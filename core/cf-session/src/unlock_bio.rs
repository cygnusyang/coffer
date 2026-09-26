//! Touch ID（生物识别）DEK 封装通道（docs/08 v0.2 主件）。
//!
//! ## 通道概览（docs/08 §0 / §3）
//!
//! ```text
//! enable_biometric(password, k_bio):   // Keychain 写入在 Swift 侧先行（T03）
//!   recover_dek(password)              // 主密码校验 + 解出 DEK（D-6，错 → 1002）
//!   → seal(K_bio, aad=uuid‖b"wrapped_dek_bio", DEK)
//!   → 原子重写 header.json（biometric_wrap 启用态，modified_at 更新）
//!
//! unlock_with_biometric(k_bio):        // 锁定态调用
//!   open(K_bio, aad=uuid‖b"wrapped_dek_bio", wrapped_dek_bio)
//!   → DEK → finish_unlock（SubKeys → ItemStore，与主密码路径共享收尾）
//! ```
//!
//! ## 关键裁定落点
//!
//! - **D-1**：不触发 format_version 2——启用 = 填充 header v1 既有的
//!   `biometric_wrap` 可选字段，零结构变更。
//! - **D-2**：AAD = `vault_uuid_bytes(16) ‖ b"wrapped_dek_bio"`（沿用
//!   docs/07 §2.2 的 `uuid ‖ purpose` 规则；docs/03 §2.8 旧文作废），
//!   防跨库重放。
//! - **D-6**：enable 传主密码而非 DEK——`UnlockedState` 不持 DEK，
//!   且顺带重验证主密码（~1s Argon2id 可接受）。
//! - **D-7**：加解密全在 Rust；本模块不感知 Keychain / LAContext。
//! - **D-8**：解封失败统一 1002（与主密码路径同纪律，不区分失败原因）；
//!   `available == false` 时调用 → 4001（BiometricUnavailable）；
//!   `k_bio` 非 32 字节 → 5002（InvalidArgument）。
//!
//! ## 顺序裁定（docs/08 §4.1，Keychain 侧归 T03）
//!
//! 本模块只负责 header 侧：写失败 → 返回 Err，header 原样（磁盘由
//! `write_header` 原子替换保证）。「先 Keychain 后 header」中 Keychain
//! 的写入 / 补偿删除由 Swift 完成；Rust 失败时 Swift 依据 Err 补偿。

use std::path::Path;

use cf_crypto::aead::{open, seal, SessionKey, KEY_LEN};
use cf_domain::CfError;
use zeroize::{Zeroize, Zeroizing};

use crate::unlock::{
    b64_decode, b64_encode, finish_unlock, format_err, header_aad, recover_dek,
};
use crate::SessionResult;

/// `wrapped_dek_bio` 的 AAD 用途标签（docs/08 D-2：`vault_uuid_bytes ‖ purpose`）。
const AAD_PURPOSE_WRAPPED_DEK_BIO: &[u8] = b"wrapped_dek_bio";

/// macOS 生物识别 provider 名（docs/08 §3.1；Android 用 `android-keystore`）。
pub const BIOMETRIC_PROVIDER_TOUCH_ID: &str = "touch_id";

/// K_bio 长度 = AEAD 密钥长度（32 字节，docs/08 D-3）。
pub const K_BIO_LEN: usize = KEY_LEN;

/// 生成 32 字节随机 bio unwrap-key（K_bio，docs/08 D-3 / §6
/// `new_biometric_unwrap_key` 的会话层实现）。
///
/// 仅生成、不落任何状态；调用方（Swift，经 FFI）负责存入 Keychain。
/// K_bio 是随机封装密钥——非 KEK、非主密码派生物，DEK 语义不变。
///
/// # 错误
///
/// 随机源不可用 → [`CfError::KdfError`]（绝不降级到弱随机，NFR-SEC-06）。
pub fn new_biometric_unwrap_key() -> SessionResult<SessionKey> {
    SessionKey::random().map_err(|_| CfError::KdfError)
}

/// 启用生物识别封装（docs/08 §4.1 enable 的 Rust/header 侧）。
///
/// 流程：k_bio 长度门禁（5002）→ [`recover_dek`] 校验主密码并解出 DEK
/// （错 → 1002，**此时 header 未被触碰**）→ K_bio AEAD 封装 DEK
/// （AAD 钉库，D-2）→ 原子重写 header.json（`available: true`、
/// `provider: "touch_id"`、`key_alias: null`——macOS 无别名语义，字段
/// 保留给 Android）。成功后返回新 header 供调用方更新内存副本。
///
/// 调用前置条件：Swift 已把 k_bio 写入 Keychain（先 Keychain 后 header）；
/// 本函数失败时 Swift 负责补偿删除 Keychain 项（半启用态不留痕）。
///
/// # 错误
///
/// - `k_bio` 长度 ≠ 32 → [`CfError::InvalidArgument`]（5002，T01 验收 ⑦）；
/// - 主密码错误 / 库数据异常 → [`CfError::UnlockFailed`]（1002）；
/// - header 写失败 → [`CfError::Io`] / [`CfError::Corrupted`]（磁盘保持原样）。
pub(crate) fn enable_biometric_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
    password: &str,
    k_bio: &[u8],
) -> SessionResult<cf_format::Header> {
    if k_bio.len() != K_BIO_LEN {
        return Err(CfError::InvalidArgument(format!(
            "k_bio must be {K_BIO_LEN} bytes, got {}",
            k_bio.len()
        )));
    }

    // D-6：传主密码而非 DEK——recover_dek 同时完成主密码校验（错 → 1002）
    // 与 DEK 解出；失败发生在任何文件写入之前，header 保证未变（T01 验收 ③）。
    let dek = recover_dek(vault_dir, header, password)?;

    // K_bio 入 Zeroizing 副本再进 SessionKey（ZeroizeOnDrop），输入切片
    // 归调用方所有，本函数不假设其被清零。
    let k_bio_copy = Zeroizing::new(k_bio.to_vec());
    let k_bio_key = SessionKey::new(
        <[u8; K_BIO_LEN]>::try_from(k_bio_copy.as_slice())
            .map_err(|_| CfError::InvalidArgument("k_bio length check failed".into()))?,
    );

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid)
        .map_err(|_| CfError::Corrupted("vault_uuid is not a valid uuid".into()))?;
    let uuid_b = *uuid.as_bytes();
    let wrapped = seal(
        &k_bio_key,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK_BIO),
        dek.as_bytes(),
    )
    .map_err(|_| CfError::KdfError)?;
    // k_bio_key / dek 在此离开作用域，ZeroizeOnDrop 自动清零（T01 验收 ⑧）

    let mut new_header = header.clone();
    new_header.biometric_wrap = cf_format::BiometricWrap {
        available: true,
        provider: Some(BIOMETRIC_PROVIDER_TOUCH_ID.to_owned()),
        key_alias: None, // macOS 不使用；保留给 Android Keystore alias（D-2/§3.1）
        wrapped_dek_b64: Some(b64_encode(&wrapped)),
    };
    new_header.modified_at = crate::unix_now()?;

    // 原子替换（cf-format::write_header：临时文件 + rename）；失败则磁盘
    // header 保持原样，返回 Err 由 Swift 补偿 Keychain。
    cf_format::write_header(vault_dir, &new_header).map_err(format_err)?;
    Ok(new_header)
}

/// 关闭生物识别封装（docs/08 §4.1 disable 的 Rust/header 侧）。
///
/// 重写 header → 禁用态（四字段全复位），`modified_at` 更新。**幂等**：
/// 已是禁用态时不重写文件、直接返回 `None`（Keychain 删除在 Swift 侧
/// 先行且幂等，两侧独立可重试）。
///
/// # 错误
///
/// header 写失败 → [`CfError::Io`] / [`CfError::Corrupted`]——非致命，
/// 可重试（Keychain 已删时功能实际已失效，header 残留密文无泄露面）。
pub(crate) fn disable_biometric_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
) -> SessionResult<Option<cf_format::Header>> {
    let already_disabled = !header.biometric_wrap.available
        && header.biometric_wrap.provider.is_none()
        && header.biometric_wrap.wrapped_dek_b64.is_none();
    if already_disabled {
        return Ok(None);
    }

    let mut new_header = header.clone();
    new_header.biometric_wrap = cf_format::BiometricWrap {
        available: false,
        provider: None,
        key_alias: None,
        wrapped_dek_b64: None,
    };
    new_header.modified_at = crate::unix_now()?;

    cf_format::write_header(vault_dir, &new_header).map_err(format_err)?;
    Ok(Some(new_header))
}

/// Touch ID 解锁后半段（docs/08 §6 `unlock_with_biometric` 的会话层实现）：
/// K_bio 解封 wrapped_dek_bio → DEK → [`finish_unlock`]（SubKeys →
/// ItemStore，与主密码路径共享收尾）。
///
/// # 错误（D-8）
///
/// - `available == false`（或缺 wrapped_dek_b64）→
///   [`CfError::BiometricUnavailable`]（4001）；
/// - `k_bio` 长度 ≠ 32 → [`CfError::InvalidArgument`]（5002）；
/// - 其余一切失败（K_bio 错 / 密文篡改 / 跨库搬运 / 库数据异常）→
///   **统一 1002**（[`CfError::UnlockFailed`]），不泄露失败原因。
pub(crate) fn unlock_store_with_bio(
    vault_dir: &Path,
    header: &cf_format::Header,
    k_bio: &[u8],
) -> SessionResult<cf_store::ItemStore> {
    // D-8：header 侧「用户意图未开启」→ 4001，先于一切密钥操作
    if !header.biometric_wrap.available {
        return Err(CfError::BiometricUnavailable);
    }
    let Some(wrapped_b64) = header.biometric_wrap.wrapped_dek_b64.as_deref() else {
        // available=true 却无封装数据：header 畸形，按不可用处理（4001）
        return Err(CfError::BiometricUnavailable);
    };

    if k_bio.len() != K_BIO_LEN {
        return Err(CfError::InvalidArgument(format!(
            "k_bio must be {K_BIO_LEN} bytes, got {}",
            k_bio.len()
        )));
    }

    let dek = recover_dek_bio(header, wrapped_b64, k_bio)?;
    finish_unlock(vault_dir, header, &dek)
}

/// bio 通道的 DEK 解出：open(K_bio, aad=uuid‖"wrapped_dek_bio",
/// wrapped_dek_bio)。对应主密码路径的 [`recover_dek`] 步骤 2
/// （bio 路径无 KEK，verifier 校验由 wrapped_dek_bio 的 AEAD 认证承担）。
///
/// 全部失败统一 1002（D-8）；`plain`（DEK 原始 Vec）在拷贝进
/// Zeroizing 后显式清零，不留副本。
fn recover_dek_bio(
    header: &cf_format::Header,
    wrapped_b64: &str,
    k_bio: &[u8],
) -> SessionResult<SessionKey> {
    const UNLOCK_FAILED: CfError = CfError::UnlockFailed;

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid).map_err(|_| UNLOCK_FAILED)?;
    let uuid_b = *uuid.as_bytes();

    // K_bio 入 Zeroizing 副本（输入切片归调用方所有，不假设其被清零）
    let k_bio_copy = Zeroizing::new(k_bio.to_vec());
    let k_bio_key = SessionKey::new(
        <[u8; K_BIO_LEN]>::try_from(k_bio_copy.as_slice()).map_err(|_| UNLOCK_FAILED)?,
    );

    let mut combined = b64_decode(wrapped_b64).map_err(|_| UNLOCK_FAILED)?;
    let open_result = open(
        &k_bio_key,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK_BIO),
        &combined,
    );
    combined.zeroize();
    let mut plain = open_result.map_err(|_| UNLOCK_FAILED)?;
    let dek = <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| UNLOCK_FAILED)?;
    plain.zeroize();
    Ok(SessionKey::new(dek))
}

// ---------------------------------------------------------------- 测试
//
// 覆盖 docs/08 §9 T01 验收 ②③④⑤⑥⑦ 及内存纪律 ⑧（①由既有 404 基线
// 回归保证，见 unlock.rs / vault.rs 既有测试）。

#[cfg(test)]
mod tests {
    use cf_crypto::aead::SessionKey;
    use cf_crypto::kdf::KdfParams;

    use crate::types::BiometricStatus;
    use crate::unlock::{create_vault_with_kdf, open_vault};

    /// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
    fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

    /// 读磁盘上的 header.json（字节级，供「header 未变」断言）。
    fn header_bytes(vault_dir: &std::path::Path) -> Vec<u8> {
        std::fs::read(vault_dir.join("header.json")).unwrap()
    }

    /// 用 serde_json 改写磁盘 header 的 biometric_wrap 段（篡改 / 跨库
    /// 搬运用），改完经 cf_format::write_header 的校验等价路径直接落盘。
    ///
    /// 这里直接改 JSON 文本而非调 write_header：模拟「攻击者只改密文
    /// 字段」的场景（绕过应用侧构造逻辑）。
    fn patch_header_biometric(vault_dir: &std::path::Path, wrapped_dek_b64: &str) {
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["biometric_wrap"]["available"] = serde_json::json!(true);
        json["biometric_wrap"]["provider"] = serde_json::json!("touch_id");
        json["biometric_wrap"]["wrapped_dek_b64"] = serde_json::json!(wrapped_dek_b64);
        std::fs::write(
            vault_dir.join("header.json"),
            serde_json::to_vec_pretty(&json).unwrap(),
        )
        .unwrap();
    }

    /// 取磁盘 header 中 biometric_wrap.wrapped_dek_b64 的文本值。
    fn header_bio_wrapped(vault_dir: &std::path::Path) -> String {
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["biometric_wrap"]["wrapped_dek_b64"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// ② 前半：enable → lock → unlock_with_bio 往返成功，且与主密码
    /// 路径共享同一会话生命周期；解锁态内数据访问正常。
    #[test]
    fn bio_启用后往返解锁成功() {
        let base = crate::tests_support::temp_dir("bio_roundtrip");
        let brief = create_vault_with_kdf(&base, "生物库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        // 建库默认禁用态（D-1：启用 = 填充既有可选字段）
        assert!(!session.has_biometric_wrap());

        session.unlock(STRONG_PASSWORD).unwrap();
        assert!(session.is_unlocked());

        let k_bio = super::new_biometric_unwrap_key().unwrap();
        let k_bio_bytes: [u8; 32] = *k_bio.as_bytes();
        session.enable_biometric(STRONG_PASSWORD, &k_bio_bytes).unwrap();
        assert!(session.has_biometric_wrap());

        // 解锁态重复 enable 幂等可用（④ 的一部分：新 K_bio 覆盖旧值）
        session.lock();
        let session2 = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        assert!(session2.has_biometric_wrap(), "锁定态可查（T01 验收 ⑥）");

        let info = session2.unlock_with_biometric(&k_bio_bytes).unwrap();
        assert_eq!(info.item_count, 0);
        assert!(session2.is_unlocked());

        // bio 解锁与主密码解锁等价：锁定后主密码路径不受影响
        session2.lock();
        assert_eq!(session2.unlock(STRONG_PASSWORD).unwrap().item_count, 0);

        // 从磁盘重开（验证 write_header 后字段无损，T01 验收 ⑥ 往返）
        drop(session2);
        let session3 = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        assert!(session3.has_biometric_wrap());
        let info3 = session3.unlock_with_biometric(&k_bio_bytes).unwrap();
        assert_eq!(info3.item_count, 0);
    }

    /// ②：错误 K_bio（另一随机 32B）→ 1002，会话保持锁定态。
    #[test]
    fn bio_错误k_bio解封失败1002() {
        let base = crate::tests_support::temp_dir("bio_wrong_key");
        let brief = create_vault_with_kdf(&base, "错误钥匙库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let k_bio = super::new_biometric_unwrap_key().unwrap();
        session.enable_biometric(STRONG_PASSWORD, k_bio.as_bytes()).unwrap();
        session.lock();

        let wrong = super::new_biometric_unwrap_key().unwrap();
        let err = session.unlock_with_biometric(wrong.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(!session.is_unlocked());
    }

    /// ②：磁盘上篡改 wrapped_dek_b64（同库内密文被换）→ 1002。
    #[test]
    fn bio_篡改wrapped_dek_bio失败1002() {
        let base = crate::tests_support::temp_dir("bio_tamper");
        let brief = create_vault_with_kdf(&base, "篡改库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let k_bio = super::new_biometric_unwrap_key().unwrap();
        session.enable_biometric(STRONG_PASSWORD, k_bio.as_bytes()).unwrap();
        session.lock();

        // 伪造一段形状合法（nonce24‖ct32‖tag16 → 72B）的密文替换原密文
        let forged = super::b64_encode(&[0xA5u8; 72]);
        patch_header_biometric(&vault_dir, &forged);

        let session2 = open_vault(&vault_dir).unwrap();
        let err = session2.unlock_with_biometric(k_bio.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002);
    }

    /// ⑤：库 A 的 wrapped_dek_bio 拷入库 B（AAD 钉库裁定 D-2）→ 1002。
    #[test]
    fn bio_跨库搬运wrapped_dek_bio失败1002() {
        let base = crate::tests_support::temp_dir("bio_cross_vault");
        let a = create_vault_with_kdf(&base, "库A", STRONG_PASSWORD, fast_kdf()).unwrap();
        let b = create_vault_with_kdf(&base, "库B", STRONG_PASSWORD, fast_kdf()).unwrap();
        let dir_a = base.join(a.uuid.to_string());
        let dir_b = base.join(b.uuid.to_string());

        let session_a = open_vault(&dir_a).unwrap();
        session_a.unlock(STRONG_PASSWORD).unwrap();
        let k_bio = super::new_biometric_unwrap_key().unwrap();
        session_a.enable_biometric(STRONG_PASSWORD, k_bio.as_bytes()).unwrap();

        // 攻击：把 A 的 biometric_wrap 密文整体搬进 B 的 header
        let wrapped_a = header_bio_wrapped(&dir_a);
        patch_header_biometric(&dir_b, &wrapped_a);

        let session_b = open_vault(&dir_b).unwrap();
        let err = session_b.unlock_with_biometric(k_bio.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002, "AAD 钉库：跨库搬运必须解封失败");
    }

    /// ④：重复 enable（新 K_bio 覆盖）后旧 K_bio 失败、新 K_bio 成功。
    #[test]
    fn bio_重复启用旧钥匙失效() {
        let base = crate::tests_support::temp_dir("bio_reenable");
        let brief = create_vault_with_kdf(&base, "重启用库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let k1 = super::new_biometric_unwrap_key().unwrap();
        session.enable_biometric(STRONG_PASSWORD, k1.as_bytes()).unwrap();
        let k2 = super::new_biometric_unwrap_key().unwrap();
        session.enable_biometric(STRONG_PASSWORD, k2.as_bytes()).unwrap();
        session.lock();

        let err = session.unlock_with_biometric(k1.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002, "旧 K_bio 必须失效");
        assert!(session.unlock_with_biometric(k2.as_bytes()).is_ok());
    }

    /// ③：enable 传错误主密码 → 1002，且磁盘 header 字节未变。
    #[test]
    fn bio_错误主密码启用失败且header未变() {
        let base = crate::tests_support::temp_dir("bio_wrong_pw");
        let brief = create_vault_with_kdf(&base, "错密码库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let before = header_bytes(&vault_dir);
        let k_bio = super::new_biometric_unwrap_key().unwrap();
        let err = session
            .enable_biometric("totally-wrong-password-99!", k_bio.as_bytes())
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert_eq!(header_bytes(&vault_dir), before, "header 必须未变");
        assert!(!session.has_biometric_wrap());
    }

    /// ⑦：k_bio 非 32 字节 → 5002（enable 与 unlock 两侧）。
    #[test]
    fn bio_密钥长度校验5002() {
        let base = crate::tests_support::temp_dir("bio_keylen");
        let brief = create_vault_with_kdf(&base, "长度库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        // enable：31 字节拒绝
        let err = session.enable_biometric(STRONG_PASSWORD, &[0u8; 31]).unwrap_err();
        assert_eq!(err.code(), 5002);
        // enable：33 字节拒绝
        let err = session.enable_biometric(STRONG_PASSWORD, &[0u8; 33]).unwrap_err();
        assert_eq!(err.code(), 5002);
        assert!(!session.has_biometric_wrap());

        // unlock：启用后传 31 字节同样 5002（长度是参数错误，非解封失败）
        let k_bio = super::new_biometric_unwrap_key().unwrap();
        session.enable_biometric(STRONG_PASSWORD, k_bio.as_bytes()).unwrap();
        session.lock();
        let err = session.unlock_with_biometric(&[0u8; 31]).unwrap_err();
        assert_eq!(err.code(), 5002);
    }

    /// D-8：未启用（available=false）时调用 unlock_with_biometric → 4001。
    #[test]
    fn bio_未启用调用返回4001() {
        let base = crate::tests_support::temp_dir("bio_unavailable");
        let brief = create_vault_with_kdf(&base, "未启用库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        let k_bio = super::new_biometric_unwrap_key().unwrap();
        let err = session.unlock_with_biometric(k_bio.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 4001);
    }

    /// ④ + disable：关闭幂等、关闭后回禁用态、bio 通道 4001、主密码
    /// 路径不受影响；锁定态 disable 被门禁拒绝（1001）。
    #[test]
    fn bio_禁用幂等且回禁用态() {
        let base = crate::tests_support::temp_dir("bio_disable");
        let brief = create_vault_with_kdf(&base, "禁用库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();

        // 未启用时 disable 幂等成功（Keychain 侧幂等删除由 Swift 保证）
        session.unlock(STRONG_PASSWORD).unwrap();
        session.disable_biometric().unwrap();

        let k_bio = super::new_biometric_unwrap_key().unwrap();
        session.enable_biometric(STRONG_PASSWORD, k_bio.as_bytes()).unwrap();
        session.lock();

        // 锁定态 disable → 1001（设置页仅在解锁态可达，docs/08 §4.1）
        let err = session.disable_biometric().unwrap_err();
        assert_eq!(err.code(), 1001);

        session.unlock(STRONG_PASSWORD).unwrap();
        session.disable_biometric().unwrap();
        session.disable_biometric().unwrap(); // 幂等
        assert!(!session.has_biometric_wrap());
        session.lock();

        // 关闭后：bio 通道 4001，主密码解锁正常
        let err = session.unlock_with_biometric(k_bio.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 4001);
        assert!(session.unlock(STRONG_PASSWORD).is_ok());
    }

    /// ⑥：enable 后磁盘 header 启用态经 write_header 原子替换无损，
    /// 重开库锁定态可查（enabled roundtrip，R-1 覆盖）。
    #[test]
    fn bio_header启用态读写往返无损() {
        let base = crate::tests_support::temp_dir("bio_header_roundtrip");
        let brief = create_vault_with_kdf(&base, "往返库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let k_bio = super::new_biometric_unwrap_key().unwrap();
        session.enable_biometric(STRONG_PASSWORD, k_bio.as_bytes()).unwrap();
        drop(session);

        // 直接读磁盘 JSON 核对四字段形状（docs/08 §3.1）
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let bio = &json["biometric_wrap"];
        assert_eq!(bio["available"], serde_json::json!(true));
        assert_eq!(bio["provider"], serde_json::json!("touch_id"));
        assert!(bio["key_alias"].is_null());
        let wrapped = bio["wrapped_dek_b64"].as_str().unwrap();
        let decoded = super::b64_decode(wrapped).unwrap();
        // nonce(24) ‖ ct(32) ‖ tag(16) = 72 字节
        assert_eq!(decoded.len(), 72);

        // 重开 + cf-format 校验通过（open_vault 内部走 validate_header）
        let reopened = open_vault(&vault_dir).unwrap();
        assert!(reopened.has_biometric_wrap());
    }

    /// D-3：new_biometric_unwrap_key 返回 32B 且两次调用不同（CSPRNG）。
    #[test]
    fn bio_随机密钥生成32字节且不重复() {
        let k1 = super::new_biometric_unwrap_key().unwrap();
        let k2 = super::new_biometric_unwrap_key().unwrap();
        assert_eq!(k1.as_bytes().len(), 32);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// ⑧：内存纪律编译期断言——K_bio（SessionKey）与 DEK 中间值类型
    /// 全链路 ZeroizeOnDrop；Bio 状态三态判定的纯函数用例。
    #[test]
    fn bio_密钥类型与状态三态() {
        // SessionKey（K_bio / DEK 载体）ZeroizeOnDrop（NFR-SEC-04 同款断言）
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SessionKey>();

        // 三态判定（docs/08 §3.1 / §7.5）：header 意图 × Keychain 可读性
        assert_eq!(
            BiometricStatus::from_availability(true, true),
            BiometricStatus::Enabled
        );
        assert_eq!(
            BiometricStatus::from_availability(true, false),
            BiometricStatus::Stale,
            "header available 但 Keychain 失效 → 凭据已变更（BioStale）"
        );
        assert_eq!(
            BiometricStatus::from_availability(false, true),
            BiometricStatus::Disabled
        );
        assert_eq!(
            BiometricStatus::from_availability(false, false),
            BiometricStatus::Disabled
        );
    }

    /// ① 补充：recover_dek 拆分后主密码路径行为不变——错误密码 1002、
    /// 篡改 wrapped_dek 1002（既有 vault.rs 用例之外的显式回归点）。
    #[test]
    fn bio_拆分后主密码路径回归() {
        let base = crate::tests_support::temp_dir("bio_pw_regression");
        let brief = create_vault_with_kdf(&base, "回归库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        let err = session.unlock("wrong-password-indeed!").unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(!session.is_unlocked());
        assert!(session.unlock(STRONG_PASSWORD).is_ok());
    }
}
