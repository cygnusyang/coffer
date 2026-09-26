//! 跨模块共享的测试工具（仅测试构建时编译）。
//!
//! `cargo test` 会以 lib target 编译 `#[cfg(test)]` 模块，各模块的测试
//! 需要共用「构造合法 Header / 临时目录 / 测试密钥」等工具，抽到此处
//! 避免在 header.rs / container.rs / manifest.rs 里各写一份。

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use cf_crypto::aead::SessionKey;

use crate::header::{
    AeadSection, BiometricWrap, Header, HeaderFlags, KdfSection, VerifierSection, WrappedKey,
    AEAD_ALGO, ARGON2_VERSION, FORMAT_VERSION, KDF_ALGO, NONCE_LEN, SALT_LEN, VERIFIER_CT_MIN,
    WRAPPED_DEK_CT_MIN,
};

/// 构造一个满足全部校验的最小合法 header（形状对照 `docs/03-详细设计.md` §1.3）。
pub(crate) fn sample_header() -> Header {
    Header {
        format_version: FORMAT_VERSION,
        vault_uuid: "01932b3c-4d5e-7f80-9abc-def012345678".to_string(),
        display_name: "我的密码库".to_string(),
        created_at: 1_790_000_000,
        modified_at: 1_790_000_000,
        kdf: KdfSection {
            algo: KDF_ALGO.to_string(),
            argon2_version: ARGON2_VERSION,
            m_cost_kib: 262_144,
            t_cost: 3,
            p_cost: 4,
            salt_b64: b64(&[0x42u8; SALT_LEN]),
        },
        aead: AeadSection {
            algo: AEAD_ALGO.to_string(),
        },
        wrapped_dek: WrappedKey {
            nonce_b64: b64(&[0x11u8; NONCE_LEN]),
            ct_b64: b64(&[0x22u8; WRAPPED_DEK_CT_MIN]),
        },
        verifier: VerifierSection {
            nonce_b64: b64(&[0x33u8; NONCE_LEN]),
            ct_b64: b64(&[0x44u8; VERIFIER_CT_MIN]),
        },
        biometric_wrap: BiometricWrap {
            available: false,
            provider: None,
            key_alias: None,
            wrapped_dek_b64: None,
        },
        flags: HeaderFlags {
            sort_key_enabled: false,
            attachments_inline: false,
        },
    }
}

/// 标准 base64 编码。
pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 测试用会话密钥 A。
pub(crate) fn test_key() -> SessionKey {
    SessionKey::new([0x42u8; 32])
}

/// 测试用会话密钥 B（与 A 不同）。
pub(crate) fn other_key() -> SessionKey {
    SessionKey::new([0x43u8; 32])
}

/// 创建唯一临时目录（不引入 tempfile 依赖，用 pid + 纳秒时间戳保证唯一）。
pub(crate) fn temp_vault_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时钟在 1970 之后")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cf-format-{name}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("创建临时目录成功");
    dir
}
