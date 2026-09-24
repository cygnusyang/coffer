//! 字段级 AEAD 封装（XChaCha20-Poly1305）。
//!
//! 对应 `docs/03-详细设计.md` §2.5。本模块是整个项目**唯一**的
//! AEAD 入口：上层不得直接使用 `chacha20poly1305` crate。
//!
//! ## 存储格式
//!
//! ```text
//! sealed = nonce(24) ‖ ciphertext(=plaintext_len) ‖ tag(16)
//! ```
//!
//! Nonce 每次加密由 CSPRNG 全新随机生成。XChaCha20 的 192-bit nonce
//! 空间允许直接随机而无需计数器管理（设计 §2.5「Nonce 策略」），
//! 这是选择 XChaCha20 而非 AES-GCM 的核心理由。
//!
//! ## AAD 构造规则（防跨行跨列密文搬运）
//!
//! ```text
//! aad = record_uuid_bytes(16) ‖ 0x00 ‖ column_name_utf8
//! ```
//!
//! 把 A 条目密文复制到 B 条目同列 → UUID 不匹配 → 解密失败；
//! 复制到 B 条目其他列 → 列名不匹配 → 同样失败。
//! 用 [`build_field_aad`] 构造，上层无需手拼。
//!
//! ## 错误信息纪律
//!
//! 解密失败**统一**返回 [`CfCryptoError::AeadOpenFailed`]，
//! 不区分「tag 校验失败」与「AAD 不匹配」——这与解锁错误不区分
//! 「密码错误」/「数据损坏」是同一条信息泄露纪律（设计 §4.2）。

use crate::error::CfCryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AEAD 密钥长度（256-bit）。
pub const KEY_LEN: usize = 32;

/// XChaCha20 nonce 长度（192-bit）。
pub const NONCE_LEN: usize = 24;

/// Poly1305 认证标签长度（128-bit）。
pub const TAG_LEN: usize = 16;

/// `sealed` 数据的最小长度：`nonce + tag`（空明文也有 tag）。
pub const SEALED_MIN_LEN: usize = NONCE_LEN + TAG_LEN;

/// 32 字节对称密钥，`Drop` 时自动清零（NFR-SEC-04）。
///
/// 上层（如 `cf-session`）从 KDF / HKDF 派生后以此类型持有，
/// 由类型系统保证密钥材料不会在作用域结束后残留内存。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey([u8; KEY_LEN]);

impl SessionKey {
    /// 从 32 字节材料构造密钥。
    #[must_use]
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// 密钥字节（只读视图，仅用于派生下一层子密钥）。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// 加密并封装为 `nonce ‖ ct ‖ tag` 格式。
///
/// # 参数
///
/// - `key`：会话密钥
/// - `aad`：附加认证数据（字段加密请用 [`build_field_aad`] 构造）
/// - `plaintext`：明文
///
/// # 错误
///
/// 随机源不可用时返回 [`CfCryptoError::RandomUnavailable`]——
/// 绝不降级到弱随机（NFR-SEC-06）。
pub fn seal(
    key: &SessionKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CfCryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| CfCryptoError::RandomUnavailable(e.to_string()))?;

    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CfCryptoError::AeadSealFailed)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// 解密 `nonce ‖ ct ‖ tag` 格式的密文。
///
/// # 错误
///
/// - 长度不足（< 40 字节）：[`CfCryptoError::InvalidLength`]（在解析
///   nonce 边界之前就能判定，属于格式错误而非认证失败）
/// - 认证失败（tag / AAD / 密文任一不匹配）：统一返回
///   [`CfCryptoError::AeadOpenFailed`]，**不透出具体原因**
pub fn open(key: &SessionKey, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CfCryptoError> {
    if sealed.len() < SEALED_MIN_LEN {
        return Err(CfCryptoError::InvalidLength(format!(
            "sealed data length {}, minimum {}",
            sealed.len(),
            SEALED_MIN_LEN
        )));
    }

    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| CfCryptoError::InvalidLength("nonce segment".into()))?;
    let nonce = XNonce::from(nonce_arr);

    cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CfCryptoError::AeadOpenFailed)
}

/// 构造字段级 AAD：`record_uuid(16) ‖ 0x00 ‖ column_name`。
///
/// 见模块文档「AAD 构造规则」。
#[must_use]
pub fn build_field_aad(record_uuid: &[u8; 16], column: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(record_uuid.len() + 1 + column.len());
    aad.extend_from_slice(record_uuid);
    aad.push(0x00);
    aad.extend_from_slice(column.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SessionKey {
        SessionKey::new([0x42u8; KEY_LEN])
    }

    /// 加解密往返：明文完整还原
    #[test]
    fn seal_open_roundtrip() {
        let key = test_key();
        let aad = build_field_aad(&[0x01u8; 16], "enc_title");
        let plaintext = b"GitHub login title";

        let sealed = seal(&key, &aad, plaintext).unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

        let opened = open(&key, &aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    /// 空明文也必须能往返（tag 仍存在）
    #[test]
    fn empty_plaintext_roundtrip() {
        let key = test_key();
        let aad = b"lv/verifier/v1";

        let sealed = seal(&key, aad, b"").unwrap();
        assert_eq!(sealed.len(), SEALED_MIN_LEN);

        let opened = open(&key, aad, &sealed).unwrap();
        assert!(opened.is_empty());
    }

    /// 每次加密 nonce 不同 → 同一明文产生不同密文（IND-CPA 语义）
    #[test]
    fn nonce_is_random_per_seal() {
        let key = test_key();
        let aad = b"aad";
        let pt = b"same plaintext";

        let s1 = seal(&key, aad, pt).unwrap();
        let s2 = seal(&key, aad, pt).unwrap();

        assert_ne!(s1, s2, "nonce 复用会导致密文相同——这是致命错误");
        assert_ne!(&s1[..NONCE_LEN], &s2[..NONCE_LEN]);
    }

    /// AAD 不匹配 → 解密失败（防跨列搬运）
    #[test]
    fn wrong_aad_fails_to_open() {
        let key = test_key();
        let aad_title = build_field_aad(&[0x01u8; 16], "enc_title");
        let aad_value = build_field_aad(&[0x01u8; 16], "enc_value");

        let sealed = seal(&key, &aad_title, b"secret").unwrap();
        assert_eq!(open(&key, &aad_value, &sealed), Err(CfCryptoError::AeadOpenFailed));
    }

    /// UUID 不匹配 → 解密失败（防跨行搬运）
    #[test]
    fn wrong_uuid_fails_to_open() {
        let key = test_key();
        let aad_a = build_field_aad(&[0x01u8; 16], "enc_title");
        let aad_b = build_field_aad(&[0x02u8; 16], "enc_title");

        let sealed = seal(&key, &aad_a, b"secret").unwrap();
        assert_eq!(open(&key, &aad_b, &sealed), Err(CfCryptoError::AeadOpenFailed));
    }

    /// 密文被篡改 → 解密失败（认证标签校验）
    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let key = test_key();
        let aad = b"aad";

        let mut sealed = seal(&key, aad, b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;

        assert_eq!(open(&key, aad, &sealed), Err(CfCryptoError::AeadOpenFailed));
    }

    /// 错误密钥 → 解密失败
    #[test]
    fn wrong_key_fails_to_open() {
        let key = test_key();
        let wrong_key = SessionKey::new([0x43u8; KEY_LEN]);
        let aad = b"aad";

        let sealed = seal(&key, aad, b"secret").unwrap();
        assert_eq!(open(&wrong_key, aad, &sealed), Err(CfCryptoError::AeadOpenFailed));
    }

    /// 长度不足的 sealed 数据 → InvalidLength（格式错误，先于认证失败判定）
    #[test]
    fn too_short_sealed_reports_invalid_length() {
        let key = test_key();
        let short = vec![0u8; SEALED_MIN_LEN - 1];

        assert!(matches!(
            open(&key, b"aad", &short),
            Err(CfCryptoError::InvalidLength(_))
        ));
    }

    /// AAD 构造格式：uuid ‖ 0x00 ‖ column
    #[test]
    fn build_field_aad_format() {
        let uuid = [0xABu8; 16];
        let aad = build_field_aad(&uuid, "enc_title");

        assert_eq!(aad.len(), 16 + 1 + "enc_title".len());
        assert_eq!(&aad[..16], &uuid[..]);
        assert_eq!(aad[16], 0x00);
        assert_eq!(&aad[17..], b"enc_title");
    }

    /// 错误 Display 不泄露细节
    #[test]
    fn error_display_does_not_leak() {
        let msg = format!("{}", CfCryptoError::AeadOpenFailed);
        assert!(!msg.contains("tag") && !msg.contains("aad"), "错误信息不应包含失败原因细节");
    }
}
