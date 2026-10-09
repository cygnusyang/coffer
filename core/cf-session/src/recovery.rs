//! 离线恢复码 DEK 封装通道（FR-17.2，docs/31 v2.5.0 §1–§3 的 impl 层）。
//!
//! ## 通道概览（docs/31 §2）
//!
//! ```text
//! generate_recovery_code():                     // 只生成、不落盘（§2.4）
//!   128-bit CSPRNG（getrandom）→ BIP39-12 编码 → code（12 英文词）
//!
//! enable_recovery_code(password, code):         // 解锁态调用（§3.1）
//!   recover_dek(password)                       // 主密码校验 + 解出 DEK（错 → 1002）
//!   → code 解码 → K_recovery = HKDF(熵, uuid, "cf/recovery/v1")
//!   → AES-256-GCM seal(K_recovery, aad=uuid‖b"wrapped_dek_recovery", DEK)
//!   → 原子重写 header.json（recovery_wrap 启用态；旧槽位覆盖，不可回滚）
//!
//! reset_password_with_recovery_code(new_password, code):  // 锁定态调用（§3.4）
//!   recovery_wrap 缺失 → 4003（RecoveryUnavailable，defensive 门）
//!   → 新密码强度门禁（1010，先于 1002）
//!   → code 解码 → K_recovery 派生 → AES-256-GCM open → DEK
//!   → repack_dek_with_new_password(header, DEK, new_password)  // 不写盘
//!   → write_header 原子重写
//!   不 finish_unlock（§3.4 D-9）：重置后保持锁定，由 Swift 决定是否用
//!   新密码解锁；本函数只重写 header，不打开 db.sqlite。
//! ```
//!
//! ## 关键裁定落点
//!
//! - **D-2**：不触发 format_version 2——启用 = 填充 header v1 既有可选字段
//!   `recovery_wrap`（`#[serde(default)]`，M-FORMAT 已合入）。
//! - **AAD**：`vault_uuid_bytes(16) ‖ b"wrapped_dek_recovery"`（沿用
//!   docs/07 §2.2 的 `uuid ‖ purpose` 规则），防跨库重放。
//! - **D-4**：K_recovery = HKDF-SHA256(ikm=恢复码熵, salt=vault_uuid,
//!   "cf/recovery/v1")（`cf-crypto::subkeys::derive_recovery_key`）。
//! - **D-5**：恢复码错误 / wrap 损坏 / header 损坏 → 统一 1002（FR-1.4
//!   不可区分纪律）；recovery_wrap 缺失 → 4003（RecoveryUnavailable，
//!   defensive，UI 已有 has_recovery_wrap 门）。
//! - **D-10**：恢复码明文永不落盘——磁盘仅 header wrap 密文；code 仅内存。
//! - **密封算法**：AES-256-GCM（nonce 12B，docs/31 §1.2 D-4），与主库
//!   XChaCha20-Poly1305 并存，均经 cf-crypto aead 单入口
//!   （`aes_gcm_seal` / `aes_gcm_open`）。
//!
//! ## 本模块职责边界
//!
//! impl 层（镜像 unlock_bio / unlock_mcp 的 `_impl` 风格）：不持会话门禁、
//! 不写审计（审计与 backoff 接线由 P1c facade 层 vault.rs 承接，
//! docs/31 §3.6）。

use std::path::Path;

use cf_crypto::aead::{aes_gcm_open, aes_gcm_seal, SessionKey};
use cf_crypto::subkeys::derive_recovery_key;
use cf_domain::CfError;
use zeroize::{Zeroize, Zeroizing};

use crate::change_password::repack_dek_with_new_password;
use crate::unlock::{b64_decode, b64_encode, format_err, header_aad, recover_dek};
use crate::SessionResult;

/// `wrapped_dek_recovery` 的 AAD 用途标签（docs/31 §1.2：
/// `vault_uuid_bytes ‖ purpose` 规则下与主密码 wrapped_dek 区分）。
pub(crate) const AAD_PURPOSE_WRAPPED_DEK_RECOVERY: &[u8] = b"wrapped_dek_recovery";

/// 恢复码熵长度（128-bit，16 字节，docs/31 §2.1；BIP39-12 对应
/// 12 词 = 128-bit 熵 + 4-bit 校验和）。
const RECOVERY_ENTROPY_LEN: usize = 16;

/// 是否已启用恢复码封装（docs/31 §3.1 门）。
///
/// 委托给 header 层的既有判定（`header.recovery_wrap` 存在且 `available`），
/// 供 UI / P1c facade 在调用 enable / reset 前做前置门；impl 层自身在
/// reset 内也做同款 defensive 检查（4003）。
#[must_use]
pub(crate) fn has_recovery_wrap(header: &cf_format::Header) -> bool {
    header.has_recovery_wrap()
}

/// 生成一个新的 BIP39-12 恢复码（docs/31 §2.4：只返回 code，**无任何落盘**）。
///
/// 128-bit 熵经 `getrandom`（仓库既有 CSPRNG，cf-crypto aead 的 nonce
/// 同源）生成，BIP39 英文词表 12 词编码（含 4-bit 校验和，`Mnemonic`
/// 因 `zeroize` feature 在 Drop 时清零词索引）。code 由调用方持有
/// （Swift 侧会话局部，展示后由 UI 置空——明文不落盘的承诺不含内存
/// 强零化，docs/31 §2.3）。
///
/// # 错误
///
/// 随机源不可用 / 编码失败 → [`CfError::KdfError`]（1007，绝不降级弱随机）。
pub(crate) fn generate_recovery_code() -> SessionResult<String> {
    let mut entropy = Zeroizing::new([0u8; RECOVERY_ENTROPY_LEN]);
    // 自由函数不入参解引用自动转换，需显式 `&mut *`（Zeroizing → [u8;16] → [u8]）
    getrandom::fill(&mut *entropy).map_err(|_| CfError::KdfError)?;
    let mnemonic = bip39::Mnemonic::from_entropy(&*entropy).map_err(|_| CfError::KdfError)?;
    // entropy 由 Zeroizing 持有，离开作用域自动清零（词索引在 Mnemonic 内，
    // 同样因 zeroize feature 于 Drop 清零）
    Ok(mnemonic.to_string())
}

/// 启用恢复码封装（docs/31 §3.1 的 impl 层，镜像
/// [`crate::unlock_bio::enable_biometric_impl`]）。
///
/// 传主密码而非 DEK：`recover_dek` 同时完成主密码校验（错 → 1002）与
/// DEK 解出；失败发生在任何文件写入之前，header 保证未变。code 解码
/// → K_recovery 派生 → AES-256-GCM 封装 DEK → 原子重写 header。
///
/// **覆盖语义（docs/31 §3.1）**：已启用时再次启用直接用新 code 覆盖
/// 旧槽位（旧恢复码立即失效，**不可回滚**）；沿用旧 code 重置将失败（1002）。
///
/// # 错误
///
/// - 主密码错误 / 库数据异常 → [`CfError::UnlockFailed`]（1002，recover_dek 内）；
/// - code 无效（词表 / 校验和错误）→ [`CfError::UnlockFailed`]（1002，
///   与主密码错不可区分，FR-1.4）；
/// - `vault_uuid` 非 UUID 文本 → [`CfError::Corrupted`]；
/// - 随机源 / KDF / AEAD 失败 → [`CfError::KdfError`]（1007）；
/// - header 写失败 → [`CfError::Io`] / [`CfError::Corrupted`]（磁盘原样）。
///
/// 返回新 header 供调用方（P1c facade）更新内存副本。
pub(crate) fn enable_recovery_code_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
    password: &str,
    code: &str,
) -> SessionResult<cf_format::Header> {
    // D-6（bio 同款）：传主密码而非 DEK——recover_dek 同时完成主密码校验
    // （错 → 1002）与 DEK 解出；失败发生在任何文件写入之前，header 未变。
    let dek = recover_dek(vault_dir, header, password)?;

    // code 解码 → 熵（无效 code → 1002，与主密码错不可区分）
    let mnemonic = bip39::Mnemonic::parse(code).map_err(|_| CfError::UnlockFailed)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());

    // K_recovery = HKDF(熵, uuid, "cf/recovery/v1") → AES-256-GCM 封装 DEK
    //（AAD 钉库，docs/31 §1.2）
    let uuid = uuid::Uuid::parse_str(&header.vault_uuid)
        .map_err(|_| CfError::Corrupted("vault_uuid is not a valid uuid".into()))?;
    let uuid_b = *uuid.as_bytes();
    let k_recovery =
        derive_recovery_key(entropy.as_slice(), &uuid_b).map_err(|_| CfError::KdfError)?;
    let k_recovery_key = SessionKey::new(k_recovery);
    let wrapped = aes_gcm_seal(
        &k_recovery_key,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK_RECOVERY),
        dek.as_bytes(),
    )
    .map_err(|_| CfError::KdfError)?;
    // k_recovery_key / dek / entropy 在此离开作用域，ZeroizeOnDrop 自动清零

    let mut new_header = header.clone();
    new_header.recovery_wrap = Some(cf_format::RecoveryWrap {
        available: true,
        wrapped_dek_b64: b64_encode(&wrapped),
    });
    new_header.modified_at = crate::unix_now()?;

    // 原子替换（cf-format::write_header：临时文件 + rename）；失败则磁盘
    // header 保持原样（enable 前的主密码校验已通过，不产生半启用态）。
    cf_format::write_header(vault_dir, &new_header).map_err(format_err)?;
    Ok(new_header)
}

/// 恢复码通道的 DEK 解出（docs/31 §3.4 前半段，镜像
/// [`crate::unlock_bio::recover_dek_bio`] 的纯解封风格）。
///
/// `code` 解码 → 熵 → K_recovery 派生 → open(K_recovery,
/// aad=uuid‖"wrapped_dek_recovery", wrapped_dek_b64)。本函数不校验
/// `recovery_wrap` 是否启用——由调用方（reset 的后半段）先做 4003 门，
/// 镜像 unlock_store_with_bio 的「4001 检查 + 纯解封」拆分。
///
/// 全部失败统一 1002（D-5）：恢复码错误 / wrap 损坏 / 跨库搬运 /
/// header 损坏不可区分（FR-1.4）。`plain`（DEK 原始 Vec）在拷贝进
/// SessionKey 后显式清零，不留副本。
pub(crate) fn recover_dek_recovery(
    header: &cf_format::Header,
    wrapped_b64: &str,
    code: &str,
) -> SessionResult<SessionKey> {
    const UNLOCK_FAILED: CfError = CfError::UnlockFailed;

    let mnemonic = bip39::Mnemonic::parse(code).map_err(|_| UNLOCK_FAILED)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid).map_err(|_| UNLOCK_FAILED)?;
    let uuid_b = *uuid.as_bytes();

    let k_recovery = derive_recovery_key(entropy.as_slice(), &uuid_b).map_err(|_| UNLOCK_FAILED)?;
    let k_recovery_key = SessionKey::new(k_recovery);

    let mut combined = b64_decode(wrapped_b64).map_err(|_| UNLOCK_FAILED)?;
    let open_result = aes_gcm_open(
        &k_recovery_key,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK_RECOVERY),
        &combined,
    );
    combined.zeroize();
    let mut plain = open_result.map_err(|_| UNLOCK_FAILED)?;
    let dek = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| {
        // reviewer L-1：长度不符路径也不留明文副本（本模块「不留副本」纪律）。
        plain.zeroize();
        UNLOCK_FAILED
    })?;
    plain.zeroize();
    Ok(SessionKey::new(dek))
}

/// 用恢复码重置主密码（FR-17.2，docs/31 §3.4 的 impl 层，镜像
/// [`crate::unlock_bio::reset_password_with_bio_impl`]）。
///
/// 从**锁定态**执行：恢复码经 [`recover_dek_recovery`] 解出 DEK（无需
/// 旧主密码——这正是「忘记密码时用恢复码重置」的价值，docs/31 D-7）
/// → 复用 [`repack_dek_with_new_password`] 换 KEK 重封装 → 原子重写。
/// 与 change_password / reset-with-bio 共享 repack helper，差异只在
/// DEK 获取途径（主密码 / k_bio / 恢复码）。
///
/// ## 本路径裁定（docs/31 §3.4 / §3.6）
///
/// - **不 finish_unlock**（D-9）：重置后保持锁定，由 Swift 决定是否用新
///   密码解锁；本函数只重写 header，不打开 db.sqlite。
/// - **免 backoff**（§3.6）：恢复码非密码 oracle（正确 code 才能解出
///   DEK），镜像 [`crate::unlock_bio::unlock_store_with_bio`] 完全豁免——
///   本函数不 acquire、不计入、不清零退避计数（facade 层同样不应 acquire）。
/// - **保留 recovery 封装**：repack 契约 ⑤ 不触碰 `recovery_wrap` 字段，
///   故重置后同一恢复码仍然可用（DEK 未变，D-9）。
/// - 写失败 → Err，header 原样（`write_header` 原子替换保证，同
///   change_password）。
///
/// # 错误（docs/31 §3.5）
///
/// - `recovery_wrap` 缺失 / 未启用 → [`CfError::RecoveryUnavailable`]
///   （4003，先于一切密钥操作）；
/// - 新密码 zxcvbn score < 3 → [`CfError::WeakPassword`]（1010，先于
///   密钥操作，保持 1010 先于 1002 的既有错误优先级）；
/// - 其余一切失败（恢复码错 / wrap 损坏 / 跨库搬运 / 库数据异常）→
///   **统一 1002**（[`CfError::UnlockFailed`]），不泄露失败原因。
///
/// 返回新 header 供调用方（P1c facade）更新内存副本；调用方负责 license
/// 门禁（§3.4 license_guard）与审计（PasswordResetByRecovery 由 facade 层
/// 接，本模块不做，docs/31 §3.6）。
pub(crate) fn reset_password_with_recovery_code_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
    new_password: &str,
    code: &str,
) -> SessionResult<cf_format::Header> {
    // D-5：header 侧「用户意图未开启」→ 4003，先于一切密钥操作
    // （镜像 unlock_store_with_bio 同款顺序：400X → 1010 → 密钥操作）
    let Some(rw) = header.recovery_wrap.as_ref() else {
        return Err(CfError::RecoveryUnavailable);
    };
    if !rw.available {
        return Err(CfError::RecoveryUnavailable);
    }

    // 新密码强度门禁（1010）——先于任何文件/密钥操作，保持 1010 先于
    // 1002 的既有错误优先级（change_password 同款；repack helper 内的
    // 门禁是幂等重复，供 reset 调用方自包含，两者不冲突）。
    if !cf_audit::meets_strength_threshold(new_password) {
        return Err(CfError::WeakPassword);
    }

    // D-7：恢复码 → 打开 wrapped_dek_recovery → DEK（恢复码错 / 密文
    // 篡改 / 跨库搬运 → 1002，recover_dek_recovery 内统一）。发生在任何
    // 文件写入之前，失败时磁盘 header 保证未变。
    let dek = recover_dek_recovery(header, &rw.wrapped_dek_b64, code)?;

    // 换 KEK 重封装（就地修改克隆；bio/mcp/recovery wraps 原样保留，
    // 见 repack helper 契约 ⑤）；失败时原 header 与磁盘均未动。
    let mut new_header = header.clone();
    repack_dek_with_new_password(&mut new_header, *dek.as_bytes(), new_password, None)?;

    // 原子替换（cf-format::write_header：临时文件 + rename）；失败则
    // 磁盘 header 保持原样，旧密码仍可解锁（原子性，同 change_password）。
    cf_format::write_header(vault_dir, &new_header).map_err(format_err)?;
    Ok(new_header)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::temp_dir;
    use crate::unlock::{create_vault_with_kdf, open_vault};

    /// 建库快速 KDF（8 MiB / 1 / 1，测试不跑全量 Argon2id）。
    fn fast_kdf() -> cf_crypto::kdf::KdfParams {
        cf_crypto::kdf::KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    const OLD_PASSWORD: &str = "correct-horse-battery-staple-42!";
    /// 换成的新强密码。
    const NEW_PASSWORD: &str = "portable-copper-drift-lantern-77#";

    /// 建库并返回 (vault_dir, 磁盘 header 快照)。impl 层直接吃 header，
    /// 不经 VaultSession（facade 是 P1c 职责）。
    fn fresh_vault(tag: &str) -> (std::path::PathBuf, cf_format::Header) {
        let base = temp_dir(tag);
        let brief = create_vault_with_kdf(&base, "恢复码库", OLD_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let header: cf_format::Header = serde_json::from_str(&text).unwrap();
        (vault_dir, header)
    }

    /// 读磁盘上的 header.json（字节级，供「header 未变」断言）。
    fn header_bytes(vault_dir: &std::path::Path) -> Vec<u8> {
        std::fs::read(vault_dir.join("header.json")).unwrap()
    }

    /// 通过 impl 层完成「生成 → 启用」并返回 (vault_dir, 启用后的 header)。
    fn enabled_vault(tag: &str) -> (std::path::PathBuf, cf_format::Header, String) {
        let (vault_dir, header) = fresh_vault(tag);
        let code = generate_recovery_code().unwrap();
        let new_header =
            enable_recovery_code_impl(&vault_dir, &header, OLD_PASSWORD, &code).unwrap();
        (vault_dir, new_header, code)
    }

    /// 生成恢复码：恰好 12 个英文小写词，且两次生成互不相同。
    #[test]
    fn 生成恢复码为12英文词且每次不同() {
        let code1 = generate_recovery_code().unwrap();
        let words: Vec<&str> = code1.split(' ').collect();
        assert_eq!(words.len(), 12, "恢复码必须是 12 个词（BIP39-12）");
        assert!(
            words
                .iter()
                .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase())),
            "恢复码词必须是 ASCII 小写英文词：{code1}"
        );

        let code2 = generate_recovery_code().unwrap();
        assert_ne!(code1, code2, "两次生成的恢复码必须不同（128-bit CSPRNG）");
    }

    /// BIP39 往返：parse(生成码) → to_string 与原始一致（编码自洽）。
    #[test]
    fn bip39往返稳定() {
        let code = generate_recovery_code().unwrap();
        let mnemonic = bip39::Mnemonic::parse(&code).unwrap();
        assert_eq!(mnemonic.to_string(), code);
        assert_eq!(mnemonic.to_entropy().len(), RECOVERY_ENTROPY_LEN);
    }

    /// 启用后：返回 header 与磁盘 header 均含可用 recovery_wrap，
    /// 且 wrapped_dek_b64 可解码、长度 ≥ RECOVERY_WRAP_CT_MIN（28）。
    #[test]
    fn 启用恢复码后header含可用封装且磁盘落盘() {
        let (vault_dir, new_header, _code) = enabled_vault("rc_enable_disk");

        assert!(new_header.has_recovery_wrap());
        let rw = new_header.recovery_wrap.as_ref().unwrap();
        assert!(rw.available);

        // 磁盘 header 同步落盘
        let disk: cf_format::Header = serde_json::from_slice(&header_bytes(&vault_dir)).unwrap();
        assert!(disk.has_recovery_wrap());
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &rw.wrapped_dek_b64,
        )
        .unwrap();
        assert!(
            decoded.len() >= cf_format::header::RECOVERY_WRAP_CT_MIN,
            "wrap 密文长度必须 ≥ 28（nonce 12 + tag 16）"
        );
    }

    /// 全流程：生成 → 启用 → 重置密码 → 旧密码失效（1002）、新密码生效；
    /// 重置后会话保持锁定（不 finish_unlock）。
    #[test]
    fn 全流程生成启用重置旧密码失效新密码生效且不自动解锁() {
        let (vault_dir, header, code) = enabled_vault("rc_full_flow");

        let new_header =
            reset_password_with_recovery_code_impl(&vault_dir, &header, NEW_PASSWORD, &code)
                .unwrap();
        assert!(new_header.has_recovery_wrap(), "重置必须保留 recovery 封装");

        // 旧密码失效（1002）、新密码生效
        let sess = open_vault(&vault_dir).unwrap();
        let err = sess.unlock(OLD_PASSWORD).unwrap_err();
        assert_eq!(err.code(), 1002, "重置后旧密码必须失效");
        assert!(sess.unlock(NEW_PASSWORD).is_ok(), "新密码必须能解锁");

        // 重置不 finish_unlock：重置后重新打开会话，初始即锁定态
        let sess2 = open_vault(&vault_dir).unwrap();
        assert!(
            !sess2.is_unlocked(),
            "重置后必须保持锁定（D-9，不自动解锁）"
        );
    }

    /// 重置后同一恢复码仍然可用（DEK 未变，repack 保留 recovery 封装）：
    /// 再用同码重置一次应成功。
    #[test]
    fn 重置后同恢复码仍可用() {
        let (vault_dir, header, code) = enabled_vault("rc_reset_again");
        let h1 = reset_password_with_recovery_code_impl(&vault_dir, &header, NEW_PASSWORD, &code)
            .unwrap();
        let h2 =
            reset_password_with_recovery_code_impl(&vault_dir, &h1, OLD_PASSWORD, &code).unwrap();
        assert!(h2.has_recovery_wrap());
        // 最后一次重置后以 OLD_PASSWORD 解锁（每次重置只换主密码，DEK 恒不变）
        let sess = open_vault(&vault_dir).unwrap();
        assert!(sess.unlock(OLD_PASSWORD).is_ok());
    }

    /// recover_dek_recovery 纯解封单元：正确 code 解出 DEK，错误 code → 1002。
    #[test]
    fn 恢复码解封单元正确码成功错码失败() {
        let (_vault_dir, header, code) = enabled_vault("rc_dek_unit");
        let rw = header.recovery_wrap.as_ref().unwrap();
        let dek = recover_dek_recovery(&header, &rw.wrapped_dek_b64, &code).unwrap();
        assert_eq!(dek.as_bytes().len(), 32);

        let wrong = generate_recovery_code().unwrap();
        assert_ne!(wrong, code);
        // SessionKey 不实现 Debug，不能 `unwrap_err()`；手动 match
        let err = match recover_dek_recovery(&header, &rw.wrapped_dek_b64, &wrong) {
            Err(e) => e,
            Ok(_) => panic!("错恢复码不应解出 DEK"),
        };
        assert_eq!(err.code(), 1002, "错恢复码必须不可区分（1002）");
    }

    /// 启用时主密码错误 → 1002，且 header 字节不变（任何失败先于写入）。
    #[test]
    fn 启用时主密码错误1002且header不变() {
        let (vault_dir, header) = fresh_vault("rc_enable_wrong_pw");
        let code = generate_recovery_code().unwrap();

        let before = header_bytes(&vault_dir);
        let err =
            enable_recovery_code_impl(&vault_dir, &header, "totally-wrong-password-99!", &code)
                .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert_eq!(header_bytes(&vault_dir), before, "header 必须未变");
    }

    /// 重置时恢复码错误 → 1002，且 header 字节不变。
    #[test]
    fn 重置时恢复码错误1002且header不变() {
        let (vault_dir, header, code) = enabled_vault("rc_reset_wrong_code");
        let wrong = generate_recovery_code().unwrap();
        assert_ne!(wrong, code);

        let before = header_bytes(&vault_dir);
        let err = reset_password_with_recovery_code_impl(&vault_dir, &header, NEW_PASSWORD, &wrong)
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert_eq!(header_bytes(&vault_dir), before, "header 必须未变");

        // 旧密码仍可解锁（错误路径未动任何密钥材料）
        let sess = open_vault(&vault_dir).unwrap();
        assert!(sess.unlock(OLD_PASSWORD).is_ok());
    }

    /// 无恢复码封装时重置 → 4003（RecoveryUnavailable），先于一切密钥操作
    /// （即使 code 无效也不解析——门禁在密钥操作之前）。
    #[test]
    fn 无恢复码封装时重置4003() {
        let (vault_dir, header) = fresh_vault("rc_no_wrap");
        let err =
            reset_password_with_recovery_code_impl(&vault_dir, &header, NEW_PASSWORD, "not-a-code")
                .unwrap_err();
        assert_eq!(err.code(), 4003);
    }

    /// 新密码过弱 → 1010，且 header 字节不变（1010 先于 1002 的既有优先级）。
    #[test]
    fn 新密码过弱1010且header不变() {
        let (vault_dir, header, code) = enabled_vault("rc_weak_new_pw");
        let before = header_bytes(&vault_dir);
        let err = reset_password_with_recovery_code_impl(&vault_dir, &header, "123456", &code)
            .unwrap_err();
        assert_eq!(err.code(), 1010);
        assert_eq!(header_bytes(&vault_dir), before, "header 必须未变");

        let sess = open_vault(&vault_dir).unwrap();
        assert!(sess.unlock(OLD_PASSWORD).is_ok());
    }

    /// 覆盖语义：重新启用直接用新 code 覆盖旧槽位——旧恢复码立即失效
    /// （1002），新恢复码生效（不可回滚，docs/31 §3.1）。
    #[test]
    fn 重新启用覆盖旧恢复码旧码失效新码生效() {
        let (vault_dir, header, old_code) = enabled_vault("rc_reenable");
        let new_code = generate_recovery_code().unwrap();
        assert_ne!(old_code, new_code);

        let h2 = enable_recovery_code_impl(&vault_dir, &header, OLD_PASSWORD, &new_code).unwrap();
        assert!(h2.has_recovery_wrap());

        // 旧码失效（1002）
        let err = reset_password_with_recovery_code_impl(&vault_dir, &h2, NEW_PASSWORD, &old_code)
            .unwrap_err();
        assert_eq!(err.code(), 1002, "旧恢复码必须立即失效");

        // 新码生效
        let h3 = reset_password_with_recovery_code_impl(&vault_dir, &h2, NEW_PASSWORD, &new_code)
            .unwrap();
        assert!(h3.has_recovery_wrap());
    }

    /// 端到端：建库 → 写入条目 → 启用恢复码 → 重置密码 → 新密码解锁并
    /// 读回条目（DEK 在重置中保持原样，条目密文可解密）。
    #[test]
    fn 端到端重置后条目仍可读() {
        use cf_domain::category::ItemCategory;
        use cf_domain::field::{Designation, FieldType};
        use cf_domain::item::{FieldDraft, ItemDraft, UrlDraft};

        let (vault_dir, header, code) = enabled_vault("rc_e2e_item");

        // 重置前先解锁并写一条（DEK 基准）
        let sess = open_vault(&vault_dir).unwrap();
        sess.unlock(OLD_PASSWORD).unwrap();
        let draft = ItemDraft {
            title: "恢复码测试".to_owned(),
            category: ItemCategory::Login,
            urls: vec![UrlDraft {
                label: None,
                url: "https://example.com".to_owned(),
                is_primary: true,
                position: 0,
            }],
            tags: Vec::new(),
            sections: Vec::new(),
            totp: None,
            fields: vec![
                FieldDraft {
                    name: "username".to_owned(),
                    value: Some("alice".to_owned()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "password".to_owned(),
                    value: Some("s3cret".to_owned()),
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
        };
        let item_id = sess.create_item(&draft).unwrap();
        sess.lock();

        // 锁定态重置密码（impl 层，与已打开会话并存——磁盘是唯一真相）
        let h2 = reset_password_with_recovery_code_impl(&vault_dir, &header, NEW_PASSWORD, &code)
            .unwrap();
        assert!(h2.has_recovery_wrap());

        // 新密码解锁并读回条目（DEK 未变 → 条目密文可解）
        let sess2 = open_vault(&vault_dir).unwrap();
        sess2.unlock(NEW_PASSWORD).unwrap();
        let item = sess2.get_item(&item_id).unwrap().expect("条目必须仍在");
        // SecretString 不实现 PartialEq / Display，只能经 expose() 取明文比较
        assert_eq!(item.title.expose(), "恢复码测试");
        assert!(
            item.fields
                .iter()
                .any(|f| f.value.as_ref().map(|v| v.expose()) == Some("s3cret")),
            "重置后条目密码字段必须可解密（DEK 未变）"
        );
    }
}
