//! header.json 的结构定义与校验。
//!
//! 对应 `docs/03-详细设计.md` §1.3（字段表）与 §1.2（工作目录结构）。
//!
//! # 本模块的职责边界
//!
//! - **只描述与校验结构**，不解密 `wrapped_dek` / `verifier`（那是
//!   `cf-crypto` 与解锁流程的职责）。
//! - 反序列化**不开启 `deny_unknown_fields`**：未来版本新增可选字段时，
//!   旧 App 必须能忽略未知字段打开库（`docs/04-系统设计.md` §6.1）。
//! - 参数随库文件走：KDF 参数存于 header 内，旧库用自带参数即可打开
//!   （`docs/03-详细设计.md` §2.3）。

use base64::Engine as _;
use cf_crypto::kdf::KdfParams;
use serde::{Deserialize, Serialize};

use crate::error::CfFormatError;

// ---------------------------------------------------------------- 常量

/// 当前支持的容器格式版本（`header.json` 的 `format_version`）。
///
/// 对应 `docs/03-详细设计.md` §1.3 与 `docs/04-系统设计.md` §5.4：
/// **仅在容器结构发生不兼容变更时递增**，与 App 版本无关。
pub const FORMAT_VERSION: u16 = 1;

/// KDF 算法常量，header 中必须与此一致。
pub const KDF_ALGO: &str = "argon2id";

/// Argon2 版本号常量（0x13 = 19）。
pub const ARGON2_VERSION: u32 = 19;

/// 字段级 AEAD 算法常量。
pub const AEAD_ALGO: &str = "xchacha20poly1305";

/// XChaCha20 nonce 长度（192-bit），与 `cf-crypto::aead::NONCE_LEN` 一致。
pub const NONCE_LEN: usize = 24;

/// `wrapped_dek.ct_b64` 解码后的最小长度：32 字节 DEK + 16 字节 Poly1305 tag。
pub const WRAPPED_DEK_CT_MIN: usize = 48;

/// `verifier.ct_b64` 解码后的最小长度：16 字节明文常量 + 16 字节 tag。
pub const VERIFIER_CT_MIN: usize = 32;

/// `recovery_wrap.wrapped_dek_b64` 解码后的最小长度：12 字节 nonce + 16 字节 tag。
/// 与既有 wrap 字段同思路，但恢复码路径采用 AES-256-GCM（docs/31 §1.2 D-4）。
pub const RECOVERY_WRAP_CT_MIN: usize = 28;

/// 盐长度（字节），直接引用 `cf-crypto` 的常量，避免两处定义漂移。
pub const SALT_LEN: usize = cf_crypto::SALT_LEN;

// ---------------------------------------------------------------- 结构

/// header.json 的顶层结构（形状对照 `docs/03-详细设计.md` §1.3）。
///
/// 字段顺序即序列化顺序（serde 默认按声明顺序），因此序列化是确定性的。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// 容器格式版本。用于格式迁移（`docs/04-系统设计.md` §7）。
    pub format_version: u16,
    /// 库 UUID（**UUIDv7 文本**）。同时作为 KEK/DEK 的 AAD 成分，防跨库替换。
    pub vault_uuid: String,
    /// 库显示名（锁定时明文展示，威胁模型已声明此泄露项）。
    pub display_name: String,
    /// 创建时间（Unix 秒 UTC）。
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）。
    pub modified_at: i64,
    /// KDF 参数段。
    pub kdf: KdfSection,
    /// AEAD 算法段。
    pub aead: AeadSection,
    /// 信封加密的 DEK（见 `docs/03-详细设计.md` §2.7）。
    pub wrapped_dek: WrappedKey,
    /// 解锁校验常量（见 §2.6）。
    pub verifier: VerifierSection,
    /// 生物识别封装（M1 恒为 `available: false`，仅元数据）。
    pub biometric_wrap: BiometricWrap,
    /// MCP 托管封装（可选字段，旧库无 → 回落 [`McpWrap::default()`]，
    /// `#[serde(default)]`，docs/29 §4.3 G1b）。
    #[serde(default)]
    pub mcp_wrap: McpWrap,
    /// 离线恢复码封装（可选字段，旧库无 → `None`；`#[serde(default)]`，
    /// docs/31 §1.1 FR-17.2）。
    #[serde(default)]
    pub recovery_wrap: Option<RecoveryWrap>,
    /// 功能开关。
    pub flags: HeaderFlags,
}

/// KDF 参数段（`header.json` 的 `kdf` 字段）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfSection {
    /// 算法名，必须为 [`KDF_ALGO`]。
    pub algo: String,
    /// Argon2 版本号，必须为 [`ARGON2_VERSION`]。
    pub argon2_version: u32,
    /// 内存开销（KiB）。参数随库文件走，见模块文档。
    pub m_cost_kib: u32,
    /// 迭代次数。
    pub t_cost: u32,
    /// 并行度。
    pub p_cost: u32,
    /// base64（标准）编码的 32 字节盐。
    pub salt_b64: String,
}

/// AEAD 算法段（`header.json` 的 `aead` 字段）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadSection {
    /// 算法名，必须为 [`AEAD_ALGO`]。
    pub algo: String,
}

/// 通用「nonce ‖ 密文」段（`wrapped_dek` 使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    /// base64 编码的 24 字节 nonce。
    pub nonce_b64: String,
    /// base64 编码的密文（≥ [`WRAPPED_DEK_CT_MIN`] 字节）。
    pub ct_b64: String,
}

/// verifier 段（`header.json` 的 `verifier` 字段）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierSection {
    /// base64 编码的 24 字节 nonce。
    pub nonce_b64: String,
    /// base64 编码的密文（≥ [`VERIFIER_CT_MIN`] 字节）。
    pub ct_b64: String,
}

/// 生物识别封装段（`header.json` 的 `biometric_wrap` 字段）。
///
/// M1 恒为 `available: false`；后续版本启用生物识别后由平台层填充。
/// `wrapped_dek_b64` 为 base64 编码的密文（≥ [`WRAPPED_DEK_CT_MIN`] 字节）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BiometricWrap {
    /// 当前是否启用了生物识别封装。M1 恒为 `false`。
    pub available: bool,
    /// 平台密钥库提供者名（如 `android-keystore` / `macos-keychain`）。
    pub provider: Option<String>,
    /// 平台密钥库中的密钥别名。
    pub key_alias: Option<String>,
    /// 用平台密钥封装的 DEK（base64）。
    pub wrapped_dek_b64: Option<String>,
}

/// MCP 托管封装段（`header.json` 的 `mcp_wrap` 字段）。
///
/// 镜像 [`BiometricWrap`] 的形状（docs/29 §2「镜像 bio 通道」），承载
/// `AEAD(mcp_key, DEK)` 的封装密文（sealed 后 base64）与 available 标志。
/// `mcp_key` 为 DEK 派生（HKDF，见 `cf-crypto::subkeys::derive_mcp_key`），
/// 非随机；删除 Keychain 条目即独立吊销（docs/29 §2）。
///
/// 旧库无此字段：Header 上 `#[serde(default)]` + 本结构 `#[derive(Default)]`
/// 保证反序列化回落为默认值，双向兼容（docs/29 §4.3 G1b）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct McpWrap {
    /// 当前是否启用了 MCP 托管。旧库默认 `false`。
    pub available: bool,
    /// 平台密钥库提供者名（如 `macos-keychain`）。
    pub provider: Option<String>,
    /// 平台密钥库中的服务标识（如 `cn.coffer.mcp-escrow`）。
    pub key_alias: Option<String>,
    /// 用 mcp_key 封装的 DEK（base64，≥ [`WRAPPED_DEK_CT_MIN`] 字节）。
    pub wrapped_dek_b64: Option<String>,
}

/// 恢复码封装段（`header.json` 的 `recovery_wrap` 字段）。
///
/// 承载离线恢复码封装的 DEK 密文（docs/31 §1.1，FR-17.2），格式为
/// `b64( nonce(12B) ‖ ciphertext(DEK) )`；密钥 `K_recovery` 由恢复码经
/// HKDF 派生（`cf-crypto` subkeys，docs/31 §1.2 D-4）。盐**隐含**——以
/// `vault_uuid` 充当 HKDF salt，不设独立 salt 字段（docs/31 D-2）。
///
/// 旧库无此字段：Header 上 `#[serde(default)]` + `Option` 保证反序列化
/// 回落为 `None`，双向兼容（docs/31 D-1，不 bump FORMAT_VERSION）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RecoveryWrap {
    /// 当前是否启用了恢复码封装。旧库 / 未配置默认 `false`。
    pub available: bool,
    /// 用 `K_recovery` 封装的 DEK（base64，`b64(nonce(12B) ‖ ct(DEK))`，
    /// 解码后 ≥ [`RECOVERY_WRAP_CT_MIN`] 字节）。
    pub wrapped_dek_b64: String,
}

/// 功能开关段（`header.json` 的 `flags` 字段）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderFlags {
    /// 是否启用排序键（HMAC 摘要）。M1 恒为 `false`。
    pub sort_key_enabled: bool,
    /// 是否把附件内联进数据库。M1 恒为 `false`（附件走独立文件）。
    pub attachments_inline: bool,
}

// ---------------------------------------------------------------- 只读辅助

impl Header {
    /// 是否已配置恢复码封装：`recovery_wrap` 非空且 `available == true`。
    ///
    /// `available == false` 的残留封装等价于未配置（与 `None` 同义，
    /// docs/31 §1.1/§1.3）。供 session 层 `has_recovery_wrap` facade
    /// （docs/31 §3.3）与 UI 决定是否展示「忘记密码 → 恢复码重置」入口。
    #[must_use]
    pub fn has_recovery_wrap(&self) -> bool {
        matches!(&self.recovery_wrap, Some(w) if w.available)
    }
}

// ---------------------------------------------------------------- 校验

/// 校验 header 的内容合法性。
///
/// # 为什么解锁流程必须调用
///
/// header.json 是「半可信」输入（`docs/04-系统设计.md` §4.3）：可能被篡改。
/// 若不校验 KDF 参数区间，攻击者把 `m_cost_kib` 改成 2 TiB 会在解锁时导致
/// OOM（见 §4.3 举例）。本函数在进入 KDF / AEAD 之前完成全部边界校验。
///
/// # 检查项
///
/// - `format_version` 必须等于 [`FORMAT_VERSION`]
/// - `kdf.algo` / `aead.algo` / `argon2_version` 必须等于常量
/// - KDF 参数区间（引用 `cf-crypto::kdf::KdfParams` 的 MIN/MAX，单一事实源）
/// - 各 base64 字段可解码且长度满足要求（盐 32B、nonce 24B、密文下限）
/// - `vault_uuid` 形状为 UUID 文本（轻量格式检查；深度校验归 `cf-domain`）
pub fn validate_header(h: &Header) -> Result<(), CfFormatError> {
    // 1. 版本 —— 旧版本走迁移流程，不由本函数处理
    if h.format_version != FORMAT_VERSION {
        return Err(CfFormatError::InvalidHeader(format!(
            "format_version 应为 {FORMAT_VERSION}，实际为 {}",
            h.format_version
        )));
    }

    // 2. UUID 形状（36 字符 + 连字符位置）。完整 UUID 语义校验归 cf-domain
    if !is_uuid_text_like(&h.vault_uuid) {
        return Err(CfFormatError::InvalidHeader(format!(
            "vault_uuid 不是合法的 UUID 文本：{:?}",
            h.vault_uuid
        )));
    }

    // 3. KDF 算法与参数区间（防 OOM）
    if h.kdf.algo != KDF_ALGO {
        return Err(CfFormatError::InvalidHeader(format!(
            "kdf.algo 应为 {KDF_ALGO}，实际为 {}",
            h.kdf.algo
        )));
    }
    if h.kdf.argon2_version != ARGON2_VERSION {
        return Err(CfFormatError::InvalidHeader(format!(
            "kdf.argon2_version 应为 {ARGON2_VERSION}，实际为 {}",
            h.kdf.argon2_version
        )));
    }
    KdfParams::new(h.kdf.m_cost_kib, h.kdf.t_cost, h.kdf.p_cost)
        .map_err(|e| CfFormatError::InvalidHeader(format!("KDF 参数非法：{e}")))?;

    // 4. AEAD 算法
    if h.aead.algo != AEAD_ALGO {
        return Err(CfFormatError::InvalidHeader(format!(
            "aead.algo 应为 {AEAD_ALGO}，实际为 {}",
            h.aead.algo
        )));
    }

    // 5. 盐长度
    let salt = decode_b64(&h.kdf.salt_b64, "kdf.salt_b64")?;
    if salt.len() != SALT_LEN {
        return Err(CfFormatError::InvalidHeader(format!(
            "kdf.salt_b64 解码后应为 {SALT_LEN} 字节，实际为 {}",
            salt.len()
        )));
    }

    // 6. wrapped_dek：nonce 24B + 密文 ≥ 48B
    let wn = decode_b64(&h.wrapped_dek.nonce_b64, "wrapped_dek.nonce_b64")?;
    if wn.len() != NONCE_LEN {
        return Err(CfFormatError::InvalidHeader(format!(
            "wrapped_dek.nonce_b64 解码后应为 {NONCE_LEN} 字节，实际为 {}",
            wn.len()
        )));
    }
    let wct = decode_b64(&h.wrapped_dek.ct_b64, "wrapped_dek.ct_b64")?;
    if wct.len() < WRAPPED_DEK_CT_MIN {
        return Err(CfFormatError::InvalidHeader(format!(
            "wrapped_dek.ct_b64 解码后应 ≥ {WRAPPED_DEK_CT_MIN} 字节，实际为 {}",
            wct.len()
        )));
    }

    // 7. verifier：nonce 24B + 密文 ≥ 32B
    let vn = decode_b64(&h.verifier.nonce_b64, "verifier.nonce_b64")?;
    if vn.len() != NONCE_LEN {
        return Err(CfFormatError::InvalidHeader(format!(
            "verifier.nonce_b64 解码后应为 {NONCE_LEN} 字节，实际为 {}",
            vn.len()
        )));
    }
    let vct = decode_b64(&h.verifier.ct_b64, "verifier.ct_b64")?;
    if vct.len() < VERIFIER_CT_MIN {
        return Err(CfFormatError::InvalidHeader(format!(
            "verifier.ct_b64 解码后应 ≥ {VERIFIER_CT_MIN} 字节，实际为 {}",
            vct.len()
        )));
    }

    // 8. biometric_wrap：若提供了 wrapped_dek_b64，也需可解码且长度足够。
    //    注意：M1 不启用生物识别，available=true 仅是未来版本的前向预留，
    //    本校验只保证「若声称有封装，则封装数据形状合法」。
    if let Some(wrapped) = &h.biometric_wrap.wrapped_dek_b64 {
        let b = decode_b64(wrapped, "biometric_wrap.wrapped_dek_b64")?;
        if b.len() < WRAPPED_DEK_CT_MIN {
            return Err(CfFormatError::InvalidHeader(format!(
                "biometric_wrap.wrapped_dek_b64 解码后应 ≥ {WRAPPED_DEK_CT_MIN} 字节，实际为 {}",
                b.len()
            )));
        }
    }

    // 9. mcp_wrap：与 biometric_wrap 同款校验——若提供了 wrapped_dek_b64，
    //    也需可解码且长度足够（docs/29 §2「镜像 bio 通道」）。available=true
    //    不强制密文存在（stale 态合法，docs/29 §2 表格），与 8 保持一致。
    if let Some(wrapped) = &h.mcp_wrap.wrapped_dek_b64 {
        let b = decode_b64(wrapped, "mcp_wrap.wrapped_dek_b64")?;
        if b.len() < WRAPPED_DEK_CT_MIN {
            return Err(CfFormatError::InvalidHeader(format!(
                "mcp_wrap.wrapped_dek_b64 解码后应 ≥ {WRAPPED_DEK_CT_MIN} 字节，实际为 {}",
                b.len()
            )));
        }
    }

    // 10. recovery_wrap：`available==true` 时 wrapped_dek_b64 非空且可解码为
    //     ≥ 28 字节（12B nonce + 16B tag，docs/31 §1.3）。`available==false`
    //     等价 None（残留封装不校验密文形状，与 biometric/mcp 的 available
    //     语义一致）。解码失败 → 读路径 1005 Corrupted（InvalidHeader）。
    if let Some(rw) = &h.recovery_wrap {
        if rw.available {
            if rw.wrapped_dek_b64.is_empty() {
                return Err(CfFormatError::InvalidHeader(
                    "recovery_wrap.available==true 但 wrapped_dek_b64 为空".to_string(),
                ));
            }
            let b = decode_b64(&rw.wrapped_dek_b64, "recovery_wrap.wrapped_dek_b64")?;
            if b.len() < RECOVERY_WRAP_CT_MIN {
                return Err(CfFormatError::InvalidHeader(format!(
                    "recovery_wrap.wrapped_dek_b64 解码后应 ≥ {RECOVERY_WRAP_CT_MIN} 字节，实际为 {}",
                    b.len()
                )));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------- 内部工具

/// 解码标准 base64，失败时返回带字段名上下文的 [`CfFormatError::InvalidHeader`]。
fn decode_b64(s: &str, field: &str) -> Result<Vec<u8>, CfFormatError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| CfFormatError::InvalidHeader(format!("{field} 不是合法 base64：{e}")))
}

/// 轻量 UUID 文本形状检查：36 字符，连字符位于 8/13/18/23 位。
///
/// 只做结构层面的快速失败；完整的 UUIDv7 语义校验归 `cf-domain` 的 `VaultId`。
fn is_uuid_text_like(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for &pos in &[8usize, 13, 18, 23] {
        if bytes[pos] != b'-' {
            return false;
        }
    }
    // 其余位置为十六进制字符（0-9 / a-f / A-F）
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{b64, sample_header};

    /// 黄金往返：构造 Header → 序列化 JSON → 回读，逐字段相等。
    #[test]
    fn golden_roundtrip() {
        let h = sample_header();
        let json = serde_json::to_vec(&h).expect("序列化成功");
        let back: Header = serde_json::from_slice(&json).expect("反序列化成功");
        assert_eq!(h, back);
    }

    /// 手写 fixture 解析：形状严格对照 docs/03 §1.3 的示例 JSON。
    #[test]
    fn hand_written_fixture_parses() {
        let fixture = r#"{
          "format_version": 1,
          "vault_uuid": "01932b3c-4d5e-7f80-9abc-def012345678",
          "display_name": "我的密码库",
          "created_at": 1790000000,
          "modified_at": 1790000000,
          "kdf": {
            "algo": "argon2id",
            "argon2_version": 19,
            "m_cost_kib": 262144,
            "t_cost": 3,
            "p_cost": 4,
            "salt_b64": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
          },
          "aead": { "algo": "xchacha20poly1305" },
          "wrapped_dek": {
            "nonce_b64": "ERERERERERERERERERERERERERERERER",
            "ct_b64": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"
          },
          "verifier": {
            "nonce_b64": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz",
            "ct_b64": "REREREREREREREREREREREREREREREREREREREREREQ="
          },
          "biometric_wrap": {
            "available": false,
            "provider": null,
            "key_alias": null,
            "wrapped_dek_b64": null
          },
          "flags": {
            "sort_key_enabled": false,
            "attachments_inline": false
          }
        }"#;

        let header: Header = serde_json::from_str(fixture).expect("fixture 应可解析");
        assert_eq!(header, sample_header(), "fixture 形状应与 §1.3 示例一致");
        validate_header(&header).expect("fixture 应通过校验");
    }

    /// 未知字段必须被忽略（向前兼容，04 §6.1）—— header 反序列化不得
    /// deny_unknown_fields。未来版本新增可选字段时，旧 App 仍能打开。
    #[test]
    fn unknown_fields_are_ignored() {
        let h = sample_header();
        let mut json = serde_json::to_value(&h).expect("序列化成功");
        json.as_object_mut()
            .expect("object")
            .insert("future_field".into(), serde_json::json!({"x": 1}));
        let text = serde_json::to_string(&json).expect("序列化成功");

        let back: Header = serde_json::from_str(&text).expect("未知字段应被忽略");
        assert_eq!(back, h);
    }

    // ---------- mcp_wrap（G1b escrow-format，docs/29 §4.3） ----------

    /// 旧库 JSON（无 `mcp_wrap` 字段）必须反序列化成功，且字段回落为
    /// [`McpWrap::default()`] —— `#[serde(default)]` 兼容判据。
    #[test]
    fn old_json_without_mcp_wrap_uses_default() {
        let h = sample_header();
        let mut json = serde_json::to_value(&h).expect("序列化成功");
        json.as_object_mut().expect("object").remove("mcp_wrap");
        let text = serde_json::to_string(&json).expect("序列化成功");

        let back: Header = serde_json::from_str(&text).expect("旧库 JSON 应可反序列化");
        assert_eq!(back.mcp_wrap, McpWrap::default());
    }

    /// `mcp_wrap: {}` 部分 JSON（内部字段全缺）也应反序列化成功并回落 Default。
    #[test]
    fn partial_mcp_wrap_object_uses_default() {
        let h = sample_header();
        let mut json = serde_json::to_value(&h).expect("序列化成功");
        json.as_object_mut()
            .expect("object")
            .insert("mcp_wrap".into(), serde_json::json!({}));
        let text = serde_json::to_string(&json).expect("序列化成功");

        let back: Header = serde_json::from_str(&text).expect("空对象 mcp_wrap 应可反序列化");
        assert_eq!(back.mcp_wrap, McpWrap::default());
    }

    /// mcp_wrap 携带合法封装数据（≥ 48B 密文）→ 校验通过（与 biometric_wrap 同款）。
    #[test]
    fn mcp_wrap_valid_wrapped_dek_passes() {
        let mut h = sample_header();
        h.mcp_wrap = McpWrap {
            available: true,
            provider: Some("macos-keychain".to_string()),
            key_alias: Some("cn.coffer.mcp-escrow".to_string()),
            wrapped_dek_b64: Some(b64(&[0x55u8; WRAPPED_DEK_CT_MIN])),
        };
        validate_header(&h).expect("合法 mcp_wrap 应通过校验");
    }

    /// mcp_wrap 密文长度不足（< 48 字节）→ 拒绝。
    #[test]
    fn mcp_wrap_too_short_rejected() {
        let mut h = sample_header();
        h.mcp_wrap.wrapped_dek_b64 = Some(b64(&[0x01u8; WRAPPED_DEK_CT_MIN - 1]));
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// mcp_wrap 密文非 base64 → 拒绝。
    #[test]
    fn mcp_wrap_invalid_base64_rejected() {
        let mut h = sample_header();
        h.mcp_wrap.wrapped_dek_b64 = Some("!!!not-base64!!!".to_string());
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    // ---------- recovery_wrap（FR-17.2，docs/31 §1.1/§1.3） ----------

    /// 恢复码封装往返：带 recovery_wrap 的 Header 序列化 → 反序列化
    /// 逐字段相等，且 `has_recovery_wrap()` 为 true。
    #[test]
    fn recovery_wrap_roundtrip() {
        let mut h = sample_header();
        h.recovery_wrap = Some(RecoveryWrap {
            available: true,
            wrapped_dek_b64: b64(&[0x55u8; RECOVERY_WRAP_CT_MIN]),
        });
        let json = serde_json::to_vec(&h).expect("序列化成功");
        let back: Header = serde_json::from_slice(&json).expect("反序列化成功");
        assert_eq!(back, h);
        assert!(back.has_recovery_wrap());
    }

    /// 旧库 JSON（无 `recovery_wrap` 字段）必须反序列化成功，且字段回落为
    /// `None`、`has_recovery_wrap()` 为 false —— `#[serde(default)]` 兼容判据。
    #[test]
    fn old_json_without_recovery_wrap_is_none() {
        let h = sample_header();
        let mut json = serde_json::to_value(&h).expect("序列化成功");
        json.as_object_mut()
            .expect("object")
            .remove("recovery_wrap");
        let text = serde_json::to_string(&json).expect("序列化成功");

        let back: Header = serde_json::from_str(&text).expect("旧库 JSON 应可反序列化");
        assert_eq!(back.recovery_wrap, None);
        assert!(!back.has_recovery_wrap());
    }

    /// `recovery_wrap: null` 显式空值也应回落为 None。
    #[test]
    fn null_recovery_wrap_is_none() {
        let h = sample_header();
        let mut json = serde_json::to_value(&h).expect("序列化成功");
        json.as_object_mut()
            .expect("object")
            .insert("recovery_wrap".into(), serde_json::Value::Null);
        let text = serde_json::to_string(&json).expect("序列化成功");

        let back: Header = serde_json::from_str(&text).expect("null recovery_wrap 应可反序列化");
        assert_eq!(back.recovery_wrap, None);
    }

    /// `recovery_wrap: {}` 部分 JSON（内部字段全缺）也应反序列化成功并回落默认。
    #[test]
    fn partial_recovery_wrap_object_uses_default() {
        let h = sample_header();
        let mut json = serde_json::to_value(&h).expect("序列化成功");
        json.as_object_mut()
            .expect("object")
            .insert("recovery_wrap".into(), serde_json::json!({}));
        let text = serde_json::to_string(&json).expect("序列化成功");

        let back: Header = serde_json::from_str(&text).expect("空对象 recovery_wrap 应可反序列化");
        assert_eq!(back.recovery_wrap, Some(RecoveryWrap::default()));
        assert!(!back.has_recovery_wrap());
    }

    /// recovery_wrap `available==true` + 合法 b64（≥ 28B）→ 校验通过。
    #[test]
    fn recovery_wrap_available_valid_passes() {
        let mut h = sample_header();
        h.recovery_wrap = Some(RecoveryWrap {
            available: true,
            wrapped_dek_b64: b64(&[0x55u8; RECOVERY_WRAP_CT_MIN]),
        });
        validate_header(&h).expect("合法 recovery_wrap 应通过校验");
        assert!(h.has_recovery_wrap());
    }

    /// recovery_wrap `available==true` 但 wrapped_dek_b64 为空 → 拒绝。
    #[test]
    fn recovery_wrap_available_empty_b64_rejected() {
        let mut h = sample_header();
        h.recovery_wrap = Some(RecoveryWrap {
            available: true,
            wrapped_dek_b64: String::new(),
        });
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// recovery_wrap 密文长度不足（< 28 字节）→ 拒绝。
    #[test]
    fn recovery_wrap_too_short_rejected() {
        let mut h = sample_header();
        h.recovery_wrap = Some(RecoveryWrap {
            available: true,
            wrapped_dek_b64: b64(&[0x01u8; RECOVERY_WRAP_CT_MIN - 1]),
        });
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// recovery_wrap 密文非 base64 → 拒绝。
    #[test]
    fn recovery_wrap_invalid_base64_rejected() {
        let mut h = sample_header();
        h.recovery_wrap = Some(RecoveryWrap {
            available: true,
            wrapped_dek_b64: "!!!not-base64!!!".to_string(),
        });
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// recovery_wrap `available==false` 等价 None：即使 wrapped_dek_b64 填了
    /// 内容也不校验密文形状（残留封装合法），`has_recovery_wrap()` 为 false。
    #[test]
    fn recovery_wrap_available_false_is_none() {
        let mut h = sample_header();
        h.recovery_wrap = Some(RecoveryWrap {
            available: false,
            wrapped_dek_b64: b64(&[0x01u8; RECOVERY_WRAP_CT_MIN - 1]), // 形状非法但被忽略
        });
        validate_header(&h).expect("available==false 的 recovery_wrap 应通过校验");
        assert!(!h.has_recovery_wrap());
    }

    // ---------- 负路径 ----------

    /// 盐长度不符（16 字节而非 32 字节）→ 拒绝。
    #[test]
    fn salt_wrong_length_rejected() {
        let mut h = sample_header();
        h.kdf.salt_b64 = b64(&[0x01u8; 16]);
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// wrapped_dek 密文长度不足（< 48 字节）→ 拒绝。
    #[test]
    fn wrapped_dek_too_short_rejected() {
        let mut h = sample_header();
        h.wrapped_dek.ct_b64 = b64(&[0x01u8; WRAPPED_DEK_CT_MIN - 1]);
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// verifier 密文长度不足（< 32 字节）→ 拒绝。
    #[test]
    fn verifier_too_short_rejected() {
        let mut h = sample_header();
        h.verifier.ct_b64 = b64(&[0x01u8; VERIFIER_CT_MIN - 1]);
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// 非 base64 的盐 → 拒绝。
    #[test]
    fn invalid_base64_rejected() {
        let mut h = sample_header();
        h.kdf.salt_b64 = "!!!not-base64!!!".to_string();
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// m_cost_kib 超上限（防 OOM，04 §4.3）→ 拒绝。
    #[test]
    fn m_cost_above_max_rejected() {
        let mut h = sample_header();
        h.kdf.m_cost_kib = cf_crypto::kdf::MAX_M_COST_KIB + 1;
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// m_cost_kib 低于下限 → 拒绝（引用 cf-crypto 的区间）。
    #[test]
    fn m_cost_below_min_rejected() {
        let mut h = sample_header();
        h.kdf.m_cost_kib = cf_crypto::kdf::MIN_M_COST_KIB - 1;
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// KDF 算法名不符 → 拒绝。
    #[test]
    fn wrong_kdf_algo_rejected() {
        let mut h = sample_header();
        h.kdf.algo = "pbkdf2".to_string();
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// AEAD 算法名不符 → 拒绝。
    #[test]
    fn wrong_aead_algo_rejected() {
        let mut h = sample_header();
        h.aead.algo = "aes-gcm".to_string();
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// vault_uuid 不是 UUID 文本形状 → 拒绝。
    #[test]
    fn malformed_uuid_rejected() {
        let mut h = sample_header();
        h.vault_uuid = "not-a-uuid".to_string();
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// format_version 与当前不一致（经 validate_header 直接调用）→ 拒绝。
    #[test]
    fn wrong_format_version_rejected() {
        let mut h = sample_header();
        h.format_version = 99;
        assert!(matches!(
            validate_header(&h),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }
}
