//! MCP 解锁托管 DEK 封装通道（docs/29 §2/§4.3-G2，镜像 unlock_bio 通道）。
//!
//! ## 通道概览（docs/29 §2）
//!
//! ```text
//! derive_mcp_key(password):              // 会话层：recover_dek → HKDF(DEK, uuid, "cf/mcp/v1")
//!   recover_dek(password)                // 主密码校验 + 解出 DEK（错 → 1002）
//!   → derive_mcp_key(DEK, uuid)          // 确定性派生（cf-crypto，docs/29 §3）
//!   → mcp_key（32B，交调用方存 Keychain）
//!
//! enable_mcp_escrow(password, mcp_key):  // Keychain 写入在 Swift 侧先行（§5.2）
//!   mcp_key 长度门禁（≠32 → 5002）
//!   → recover_dek(password)              // 主密码校验 + 解出 DEK（错 → 1002，header 未动）
//!   → seal(mcp_key, aad=uuid‖b"wrapped_dek_mcp", DEK)
//!   → 原子重写 header.json（mcp_wrap 启用态，modified_at 更新）
//!
//! unlock_with_mcp_key(mcp_key):          // 锁定态调用（CLI 侧，docs/29 §6）
//!   open(mcp_key, aad=uuid‖b"wrapped_dek_mcp", wrapped_dek_mcp)
//!   → DEK → finish_unlock（SubKeys → ItemStore，与主密码/bio 路径共享收尾）
//! ```
//!
//! ## 与 unlock_bio 的关键差异（docs/29 §2 表格）
//!
//! - **封装钥**：bio 用随机 K_bio；MCP 用 **DEK 派生**的确定性 mcp_key
//!   （`cf-crypto::subkeys::derive_mcp_key`）。因此重启用幂等（重派生同一
//!   密钥，覆盖 header 密文即可），无「旧钥作废」语义。
//! - **吊销**：删除 Keychain 条目即独立吊销（CLI 无法再解封）；换主密码
//!   （重封装 D-2，DEK 不变）**不自动吊销**（docs/29 §5.3 落档语义）。
//! - **解封失败纪律**：本通道全部失败归一为 [`CfError::UnlockFailed`]
//!   （1002，fail-closed）——**不含** bio 的 4001 分支：MCP 无专用
//!   「未启用」错误变体（cf-domain 不在本组闭集），且 CLI 取密流程
//!   （docs/30 §1.3）仅在 Keychain 条目存在时调本通道，任何解锁失败
//!   都走「报错退出 1」（fail-closed），不需要区分未启用与密钥错。
//!
//! ## 关键裁定落点
//!
//! - **D-1**：不触发 format_version 2——启用 = 填充 header v1 既有的
//!   `mcp_wrap` 可选字段（`#[serde(default)]`，G1b 已合入），零结构变更。
//! - **AAD**：`vault_uuid_bytes(16) ‖ b"wrapped_dek_mcp"`（沿用
//!   docs/07 §2.2 的 `uuid ‖ purpose` 规则），防跨库重放。
//! - **D-6 同款**：enable 传主密码而非 DEK——顺带重验证主密码
//!   （~1s Argon2id 可接受），header 在密钥操作完成前不动。
//! - **内存纪律**：mcp_key / DEK 中间值全程 `SessionKey` /
//!   `Zeroizing`（NFR-SEC-04），与本通道参照的 unlock_bio 同款。

use std::path::Path;

use cf_crypto::aead::{open, seal, SessionKey, KEY_LEN};
use cf_domain::CfError;
use zeroize::{Zeroize, Zeroizing};

use crate::unlock::{b64_decode, b64_encode, finish_unlock, format_err, header_aad, recover_dek};
use crate::SessionResult;

/// `wrapped_dek_mcp` 的 AAD 用途标签（docs/29 §2：`vault_uuid_bytes ‖ purpose`）。
const AAD_PURPOSE_WRAPPED_DEK_MCP: &[u8] = b"wrapped_dek_mcp";

/// MCP 托管 provider 名（docs/29 §5.1，macOS = 数据保护 Keychain）。
pub const MCP_PROVIDER: &str = "macos-keychain";

/// MCP 托管 Keychain service 名（docs/29 §5.1 D-2 冻结：`cn.coffer.mcp-escrow`）。
pub const MCP_KEYCHAIN_SERVICE: &str = "cn.coffer.mcp-escrow";

/// mcp_key 长度 = HKDF 输出长度（32 字节，docs/29 §3.1）。
pub const MCP_KEY_LEN: usize = KEY_LEN;

/// 派生 MCP 托管密钥（docs/29 §5.2 流程 ① 的会话层实现）：
/// `recover_dek` 校验主密码并解出 DEK（错 → 1002）→
/// `cf_crypto::subkeys::derive_mcp_key(DEK, vault_uuid)` → 32 字节 mcp_key。
///
/// mcp_key 是 **DEK 派生的确定性密钥**（docs/29 §2）：换主密码不改变
/// DEK → mcp_key 不变 → `wrapped_dek_mcp` 不失效（§5.3 吊销语义）。
/// 调用方（Swift，经 FFI）负责把 mcp_key 存入 Keychain（先 Keychain 后
/// header 顺序裁定，docs/29 §5.2）。
///
/// # 错误
///
/// - 主密码错误 / 库数据异常 → [`CfError::UnlockFailed`]（1002）；
/// - 派生失败（理论不失败）→ [`CfError::KdfError`]（1007）。
pub(crate) fn derive_mcp_key_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
    password: &str,
) -> SessionResult<SessionKey> {
    let dek = recover_dek(vault_dir, header, password)?;

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid)
        .map_err(|_| CfError::Corrupted("vault_uuid is not a valid uuid".into()))?;
    let uuid_b = *uuid.as_bytes();
    let mcp_key = cf_crypto::subkeys::derive_mcp_key(dek.as_bytes(), &uuid_b)
        .map_err(|_| CfError::KdfError)?;
    // dek 在此离开作用域，ZeroizeOnDrop 自动清零
    Ok(SessionKey::new(mcp_key))
}

/// 启用 MCP 托管（docs/29 §5.2 enable 的 Rust/header 侧）。
///
/// 流程：mcp_key 长度门禁（5002）→ [`recover_dek`] 校验主密码并解出 DEK
/// （错 → 1002，**此时 header 未被触碰**）→ mcp_key AEAD 封装 DEK
/// （AAD 钉库）→ 原子重写 header.json（`mcp_wrap` 启用态，modified_at
/// 更新）。成功后返回新 header 供调用方更新内存副本。
///
/// 调用前置条件：Swift 已把 mcp_key 写入 Keychain（先 Keychain 后 header）；
/// 本函数失败时 Swift 负责补偿删除 Keychain 项（半启用态不留痕）。
///
/// # 错误
///
/// - `mcp_key` 长度 ≠ 32 → [`CfError::InvalidArgument`]（5002）；
/// - 主密码错误 / 库数据异常 → [`CfError::UnlockFailed`]（1002）；
/// - header 写失败 → [`CfError::Io`] / [`CfError::Corrupted`]（磁盘保持原样）。
pub(crate) fn enable_mcp_escrow_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
    password: &str,
    mcp_key: &[u8],
) -> SessionResult<cf_format::Header> {
    if mcp_key.len() != MCP_KEY_LEN {
        return Err(CfError::InvalidArgument(format!(
            "mcp_key must be {MCP_KEY_LEN} bytes, got {}",
            mcp_key.len()
        )));
    }

    // 传主密码而非 DEK：recover_dek 同时完成主密码校验（错 → 1002）与
    // DEK 解出；失败发生在任何文件写入之前，header 保证未变。
    let dek = recover_dek(vault_dir, header, password)?;

    // mcp_key 入 Zeroizing 副本再进 SessionKey（ZeroizeOnDrop），输入
    // 切片归调用方所有，本函数不假设其被清零。
    let mcp_key_copy = Zeroizing::new(mcp_key.to_vec());
    let mcp_key_session = SessionKey::new(
        <[u8; MCP_KEY_LEN]>::try_from(mcp_key_copy.as_slice())
            .map_err(|_| CfError::InvalidArgument("mcp_key length check failed".into()))?,
    );

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid)
        .map_err(|_| CfError::Corrupted("vault_uuid is not a valid uuid".into()))?;
    let uuid_b = *uuid.as_bytes();
    let wrapped = seal(
        &mcp_key_session,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK_MCP),
        dek.as_bytes(),
    )
    .map_err(|_| CfError::KdfError)?;
    // mcp_key_session / dek 在此离开作用域，ZeroizeOnDrop 自动清零

    let mut new_header = header.clone();
    new_header.mcp_wrap = cf_format::McpWrap {
        available: true,
        provider: Some(MCP_PROVIDER.to_owned()),
        key_alias: Some(MCP_KEYCHAIN_SERVICE.to_owned()),
        wrapped_dek_b64: Some(b64_encode(&wrapped)),
    };
    new_header.modified_at = crate::unix_now()?;

    // 原子替换（cf-format::write_header：临时文件 + rename）；失败则磁盘
    // header 保持原样，返回 Err 由 Swift 补偿 Keychain。
    cf_format::write_header(vault_dir, &new_header).map_err(format_err)?;
    Ok(new_header)
}

/// 关闭 MCP 托管（docs/29 §5.2 disable 的 Rust/header 侧）。
///
/// 重写 header → 禁用态（mcp_wrap 回落 [`cf_format::McpWrap::default()`]），
/// `modified_at` 更新。**幂等**：已是禁用态时不重写文件、直接返回 `None`
/// （Keychain 删除在 Swift 侧先行且幂等，两侧独立可重试）。
///
/// # 错误
///
/// header 写失败 → [`CfError::Io`] / [`CfError::Corrupted`]——非致命，
/// 可重试（Keychain 已删时功能实际已失效，header 残留密文无泄露面）。
pub(crate) fn disable_mcp_escrow_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
) -> SessionResult<Option<cf_format::Header>> {
    if header.mcp_wrap == cf_format::McpWrap::default() {
        return Ok(None);
    }

    let mut new_header = header.clone();
    new_header.mcp_wrap = cf_format::McpWrap::default();
    new_header.modified_at = crate::unix_now()?;

    cf_format::write_header(vault_dir, &new_header).map_err(format_err)?;
    Ok(Some(new_header))
}

/// MCP 托管解锁后半段（docs/29 §6.2 `unlock_store_with_mcp_key` 的会话层
/// 实现）：mcp_key 解封 wrapped_dek_mcp → DEK → [`finish_unlock`]（SubKeys
/// → ItemStore，与主密码/bio 路径共享收尾）。
///
/// # 错误（fail-closed，见模块文档差异说明）
///
/// - `available == false`（或缺 wrapped_dek_b64）→ 1002
///   （[`CfError::UnlockFailed`]）；
/// - `mcp_key` 长度 ≠ 32 → [`CfError::InvalidArgument`]（5002）；
/// - 其余一切失败（mcp_key 错 / 密文篡改 / 跨库搬运 / 库数据异常）→
///   **统一 1002**，不泄露失败原因。
///
/// 返回已打开的 [`cf_store::ItemStore`]：DEK 已转入 `SubKeys`，会话不持 DEK。
pub(crate) fn unlock_store_with_mcp_key(
    vault_dir: &Path,
    header: &cf_format::Header,
    mcp_key: &[u8],
) -> SessionResult<cf_store::ItemStore> {
    const UNLOCK_FAILED: CfError = CfError::UnlockFailed;

    // 用户意图未开启（available=false）或畸形（缺密文）→ 1002，
    // fail-closed（不泄露托管是否启用）
    if !header.mcp_wrap.available {
        return Err(UNLOCK_FAILED);
    }
    let Some(wrapped_b64) = header.mcp_wrap.wrapped_dek_b64.as_deref() else {
        return Err(UNLOCK_FAILED);
    };

    if mcp_key.len() != MCP_KEY_LEN {
        return Err(CfError::InvalidArgument(format!(
            "mcp_key must be {MCP_KEY_LEN} bytes, got {}",
            mcp_key.len()
        )));
    }

    let dek = recover_dek_mcp(header, wrapped_b64, mcp_key)?;
    finish_unlock(vault_dir, header, &dek)
}

/// MCP 通道的 DEK 解出：open(mcp_key, aad=uuid‖"wrapped_dek_mcp",
/// wrapped_dek_mcp)。对应主密码路径的 [`recover_dek`] 步骤 2
/// （MCP 路径无 KEK，verifier 校验由 wrapped_dek_mcp 的 AEAD 认证承担）。
///
/// 全部失败统一 1002（fail-closed）；`plain`（DEK 原始 Vec）在拷贝进
/// Zeroizing 后显式清零，不留副本。
fn recover_dek_mcp(
    header: &cf_format::Header,
    wrapped_b64: &str,
    mcp_key: &[u8],
) -> SessionResult<SessionKey> {
    const UNLOCK_FAILED: CfError = CfError::UnlockFailed;

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid).map_err(|_| UNLOCK_FAILED)?;
    let uuid_b = *uuid.as_bytes();

    // mcp_key 入 Zeroizing 副本（输入切片归调用方所有，不假设其被清零）
    let mcp_key_copy = Zeroizing::new(mcp_key.to_vec());
    let mcp_key_session = SessionKey::new(
        <[u8; MCP_KEY_LEN]>::try_from(mcp_key_copy.as_slice()).map_err(|_| UNLOCK_FAILED)?,
    );

    let mut combined = b64_decode(wrapped_b64).map_err(|_| UNLOCK_FAILED)?;
    let open_result = open(
        &mcp_key_session,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK_MCP),
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
// 覆盖 docs/30 §1.2 判据（托管生命周期 roundtrip）在 Rust 侧的条目，
// 以及 docs/29 §5.3 的吊销语义：enable → unlock 往返、错误密钥 fail-closed、
// disable 后解锁失败、换主密码不吊销、AAD 篡改拒绝、派生确定性。

#[cfg(test)]
mod tests {
    use cf_crypto::aead::SessionKey;
    use cf_crypto::kdf::KdfParams;

    use crate::unlock::{create_vault_with_kdf, open_vault};

    /// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
    fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

    /// 换密用的新强密码（zxcvbn score ≥ 3，可过强度门禁）。
    const NEW_PASSWORD: &str = "portable-copper-drift-lantern-77#";

    /// 读磁盘上的 header.json（字节级，供「header 未变」断言）。
    fn header_bytes(vault_dir: &std::path::Path) -> Vec<u8> {
        std::fs::read(vault_dir.join("header.json")).unwrap()
    }

    /// 用 serde_json 改写磁盘 header 的 mcp_wrap 段（篡改 / 跨库搬运用）。
    ///
    /// 直接改 JSON 文本而非调 write_header：模拟「攻击者只改密文字段」
    /// 的场景（绕过应用侧构造逻辑）。
    fn patch_header_mcp(vault_dir: &std::path::Path, wrapped_dek_b64: &str) {
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["mcp_wrap"]["available"] = serde_json::json!(true);
        json["mcp_wrap"]["provider"] = serde_json::json!(super::MCP_PROVIDER);
        json["mcp_wrap"]["key_alias"] = serde_json::json!(super::MCP_KEYCHAIN_SERVICE);
        json["mcp_wrap"]["wrapped_dek_b64"] = serde_json::json!(wrapped_dek_b64);
        std::fs::write(
            vault_dir.join("header.json"),
            serde_json::to_vec_pretty(&json).unwrap(),
        )
        .unwrap();
    }

    /// 取磁盘 header 中 mcp_wrap.wrapped_dek_b64 的文本值。
    fn header_mcp_wrapped(vault_dir: &std::path::Path) -> String {
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["mcp_wrap"]["wrapped_dek_b64"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// roundtrip：enable → lock → unlock_with_mcp_key 往返成功，且与主
    /// 密码路径共享同一会话生命周期；解锁态内数据访问正常。
    #[test]
    fn mcp_启用后往返解锁成功() {
        let base = crate::tests_support::temp_dir("mcp_roundtrip");
        let brief = create_vault_with_kdf(&base, "托管库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        // 建库默认禁用态（G1b：mcp_wrap = McpWrap::default()）
        assert!(!session.has_mcp_wrap());

        session.unlock(STRONG_PASSWORD).unwrap();
        assert!(session.is_unlocked());

        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        assert!(session.has_mcp_wrap());

        // 锁定态可查（header 意图），unlock 走 mcp_key
        session.lock();
        let session2 = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        assert!(session2.has_mcp_wrap(), "锁定态可查");

        let info = session2.unlock_with_mcp_key(mcp_key.as_bytes()).unwrap();
        assert_eq!(info.item_count, 0);
        assert!(session2.is_unlocked());

        // mcp 解锁与主密码解锁等价：锁定后主密码路径不受影响
        session2.lock();
        assert_eq!(session2.unlock(STRONG_PASSWORD).unwrap().item_count, 0);

        // 从磁盘重开（验证 write_header 后字段无损）
        drop(session2);
        let session3 = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        assert!(session3.has_mcp_wrap());
        let info3 = session3.unlock_with_mcp_key(mcp_key.as_bytes()).unwrap();
        assert_eq!(info3.item_count, 0);
    }

    /// 错误 mcp_key（另一 32B）→ 1002，会话保持锁定态（fail-closed）。
    #[test]
    fn mcp_错误mcp_key解封失败1002() {
        let base = crate::tests_support::temp_dir("mcp_wrong_key");
        let brief = create_vault_with_kdf(&base, "错钥库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        session.lock();

        // 另一 32B 密钥（形状合法但内容错）→ 解封失败 1002
        let wrong = SessionKey::new([0xABu8; 32]);
        let err = session.unlock_with_mcp_key(wrong.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(!session.is_unlocked());
    }

    /// 磁盘上篡改 wrapped_dek_mcp（同库内密文被换）→ 1002（AAD/密文篡改）。
    #[test]
    fn mcp_篡改wrapped_dek_mcp失败1002() {
        let base = crate::tests_support::temp_dir("mcp_tamper");
        let brief = create_vault_with_kdf(&base, "篡改库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        session.lock();

        // 伪造一段形状合法（nonce24‖ct32‖tag16 → 72B）的密文替换原密文
        let forged = super::b64_encode(&[0xA5u8; 72]);
        patch_header_mcp(&vault_dir, &forged);

        let session2 = open_vault(&vault_dir).unwrap();
        let err = session2
            .unlock_with_mcp_key(mcp_key.as_bytes())
            .unwrap_err();
        assert_eq!(err.code(), 1002);
    }

    /// 库 A 的 wrapped_dek_mcp 拷入库 B（AAD 钉库）→ 1002。
    #[test]
    fn mcp_跨库搬运wrapped_dek_mcp失败1002() {
        let base = crate::tests_support::temp_dir("mcp_cross_vault");
        let a = create_vault_with_kdf(&base, "库A", STRONG_PASSWORD, fast_kdf()).unwrap();
        let b = create_vault_with_kdf(&base, "库B", STRONG_PASSWORD, fast_kdf()).unwrap();
        let dir_a = base.join(a.uuid.to_string());
        let dir_b = base.join(b.uuid.to_string());

        let session_a = open_vault(&dir_a).unwrap();
        session_a.unlock(STRONG_PASSWORD).unwrap();
        let mcp_key_a = session_a.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session_a
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key_a.as_bytes())
            .unwrap();

        // 攻击：把 A 的 mcp_wrap 密文整体搬进 B 的 header（同一 mcp_key
        // 解封，仅 AAD 的 vault_uuid 不同 → 必须失败）
        let wrapped_a = header_mcp_wrapped(&dir_a);
        patch_header_mcp(&dir_b, &wrapped_a);

        let session_b = open_vault(&dir_b).unwrap();
        let err = session_b
            .unlock_with_mcp_key(mcp_key_a.as_bytes())
            .unwrap_err();
        assert_eq!(err.code(), 1002, "AAD 钉库：跨库搬运必须解封失败");
    }

    /// 重复 enable：确定性派生 → 同一 mcp_key，重启用幂等覆盖（重新 seal，
    /// 新 nonce 换新密文），原 mcp_key 仍可解锁（docs/29 §2 差异表格）。
    #[test]
    fn mcp_重复启用幂等覆盖() {
        let base = crate::tests_support::temp_dir("mcp_reenable");
        let brief = create_vault_with_kdf(&base, "重启用库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        let wrapped1 = header_mcp_wrapped(&vault_dir);
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        let wrapped2 = header_mcp_wrapped(&vault_dir);
        assert_ne!(wrapped1, wrapped2, "重启用须重新 seal（新 nonce）");

        session.lock();
        assert!(
            session.unlock_with_mcp_key(mcp_key.as_bytes()).is_ok(),
            "确定性 mcp_key 重启用后原钥仍可解锁"
        );
    }

    /// enable 传错误主密码 → 1002，且磁盘 header 字节未变。
    #[test]
    fn mcp_错误主密码启用失败且header未变() {
        let base = crate::tests_support::temp_dir("mcp_wrong_pw");
        let brief = create_vault_with_kdf(&base, "错密码库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let before = header_bytes(&vault_dir);
        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        let err = session
            .enable_mcp_escrow("totally-wrong-password-99!", mcp_key.as_bytes())
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert_eq!(header_bytes(&vault_dir), before, "header 必须未变");
        assert!(!session.has_mcp_wrap());
    }

    /// mcp_key 非 32 字节 → 5002（enable 与 unlock 两侧）。
    #[test]
    fn mcp_密钥长度校验5002() {
        let base = crate::tests_support::temp_dir("mcp_keylen");
        let brief = create_vault_with_kdf(&base, "长度库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        // enable：31 字节拒绝
        let err = session
            .enable_mcp_escrow(STRONG_PASSWORD, &[0u8; 31])
            .unwrap_err();
        assert_eq!(err.code(), 5002);
        // enable：33 字节拒绝
        let err = session
            .enable_mcp_escrow(STRONG_PASSWORD, &[0u8; 33])
            .unwrap_err();
        assert_eq!(err.code(), 5002);
        assert!(!session.has_mcp_wrap());

        // unlock：启用后传 31 字节同样 5002（长度是参数错误，非解封失败）
        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        session.lock();
        let err = session.unlock_with_mcp_key(&[0u8; 31]).unwrap_err();
        assert_eq!(err.code(), 5002);
    }

    /// 未启用（available=false）时调用 unlock_with_mcp_key → 1002
    /// （fail-closed，不泄露托管是否启用）。
    #[test]
    fn mcp_未启用调用返回1002() {
        let base = crate::tests_support::temp_dir("mcp_unavailable");
        let brief = create_vault_with_kdf(&base, "未启用库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        // derive 需解锁态（escrow 管理流，设置页仅解锁态可达）：
        // 先解锁取 mcp_key，再锁定回到「未启用托管」态
        session.unlock(STRONG_PASSWORD).unwrap();
        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session.lock();
        assert!(!session.has_mcp_wrap());

        let err = session.unlock_with_mcp_key(mcp_key.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002);
    }

    /// disable 幂等、关闭后回禁用态、mcp 通道 1002、主密码路径不受影响；
    /// 锁定态 disable 被门禁拒绝（1001）。
    #[test]
    fn mcp_禁用幂等且回禁用态() {
        let base = crate::tests_support::temp_dir("mcp_disable");
        let brief = create_vault_with_kdf(&base, "禁用库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();

        // 未启用时 disable 幂等成功（Keychain 侧幂等删除由 Swift 保证）
        session.unlock(STRONG_PASSWORD).unwrap();
        session.disable_mcp_escrow().unwrap();

        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        session.lock();

        // 锁定态 disable → 1001（设置页仅在解锁态可达，docs/29 §5.2）
        let err = session.disable_mcp_escrow().unwrap_err();
        assert_eq!(err.code(), 1001);

        session.unlock(STRONG_PASSWORD).unwrap();
        session.disable_mcp_escrow().unwrap();
        session.disable_mcp_escrow().unwrap(); // 幂等
        assert!(!session.has_mcp_wrap());
        session.lock();

        // 关闭后：mcp 通道 1002（fail-closed），主密码解锁正常
        let err = session.unlock_with_mcp_key(mcp_key.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(session.unlock(STRONG_PASSWORD).is_ok());
    }

    /// enable 后磁盘 header 启用态经 write_header 原子替换无损，重开库
    /// 锁定态可查（enabled roundtrip）。
    #[test]
    fn mcp_header启用态读写往返无损() {
        let base = crate::tests_support::temp_dir("mcp_header_roundtrip");
        let brief = create_vault_with_kdf(&base, "往返库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        drop(session);

        // 直接读磁盘 JSON 核对字段形状（docs/29 §5.1）
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let mcp = &json["mcp_wrap"];
        assert_eq!(mcp["available"], serde_json::json!(true));
        assert_eq!(mcp["provider"], serde_json::json!(super::MCP_PROVIDER));
        assert_eq!(
            mcp["key_alias"],
            serde_json::json!(super::MCP_KEYCHAIN_SERVICE)
        );
        let wrapped = mcp["wrapped_dek_b64"].as_str().unwrap();
        let decoded = super::b64_decode(wrapped).unwrap();
        // nonce(24) ‖ ct(32) ‖ tag(16) = 72 字节
        assert_eq!(decoded.len(), 72);

        // 重开 + cf-format 校验通过（open_vault 内部走 validate_header）
        let reopened = open_vault(&vault_dir).unwrap();
        assert!(reopened.has_mcp_wrap());
    }

    /// 换主密码不吊销托管（docs/29 §5.3 落档语义，docs/30 §1.1 第 4 条）：
    /// DEK 不变 → 派生 mcp_key 不变 → 原 mcp_key 仍可解锁。
    #[test]
    fn mcp_换主密码不吊销托管() {
        let base = crate::tests_support::temp_dir("mcp_change_pw");
        let brief =
            create_vault_with_kdf(&base, "换密托管库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();

        // 换主密码（只重封装 DEK，DEK 不变 → mcp_key 不变）
        session
            .change_password(STRONG_PASSWORD, NEW_PASSWORD, None)
            .unwrap();
        session.lock();

        // 新密码生效（换密成功）……
        assert!(session.unlock(NEW_PASSWORD).is_ok());
        session.lock();

        // ……且原 mcp_key 仍可解锁（托管未被吊销）
        assert!(
            session.unlock_with_mcp_key(mcp_key.as_bytes()).is_ok(),
            "换主密码不得吊销 MCP 托管（DEK 不变）"
        );
        assert!(session.has_mcp_wrap(), "换密后 mcp_wrap 应保留");
    }

    /// 派生确定性：同密码两次派生逐字节相等；不同库派生互异。
    #[test]
    fn mcp_派生确定性且跨库不同() {
        let base = crate::tests_support::temp_dir("mcp_derive");
        let a = create_vault_with_kdf(&base, "库A", STRONG_PASSWORD, fast_kdf()).unwrap();
        let dir_a = base.join(a.uuid.to_string());
        let session_a = open_vault(&dir_a).unwrap();
        session_a.unlock(STRONG_PASSWORD).unwrap();

        let k1 = session_a.derive_mcp_key(STRONG_PASSWORD).unwrap();
        let k2 = session_a.derive_mcp_key(STRONG_PASSWORD).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes(), "同库同密码派生必须确定");

        let b = create_vault_with_kdf(&base, "库B", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session_b = open_vault(&base.join(b.uuid.to_string())).unwrap();
        session_b.unlock(STRONG_PASSWORD).unwrap();
        let kb = session_b.derive_mcp_key(STRONG_PASSWORD).unwrap();
        assert_ne!(k1.as_bytes(), kb.as_bytes(), "不同库派生必须互异");
        assert_eq!(k1.as_bytes().len(), super::MCP_KEY_LEN);
    }

    /// 内存纪律：mcp_key（SessionKey）ZeroizeOnDrop 编译期断言。
    #[test]
    fn mcp_密钥类型_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SessionKey>();
    }
}
