//! OPVault 密码学原语（docs/22 §2.2.4 / docs/24 §1.2 布局，T02）。
//!
//! 只做**纯密码学**，不碰文件系统与领域概念。上层（`cf-importer`）负责
//! 读取 `profile.js` / `band_*.js` 并调用本模块。
//!
//! ## 对应设计文档
//!
//! - `docs/03-详细设计.md` §6.3（密钥派生链基线）
//! - `docs/24-opvault布局交叉验证报告.md` §1.2 / §1.3（**仲裁事实源**：
//!   opdata01 带头布局、前置随机 CBC 填充、密钥链澄清）
//! - `docs/22-v0.7实现方案.md` §2.2.1（r1.3，双解码路径）
//!
//! ## 双解码路径（核心）
//!
//! | 对象 | 布局 | 解码 |
//! | --- | --- | --- |
//! | opdata01（`d`/`o`/`masterKey`/`overviewKey`） | `[magic "opdata01":8]‖[plen:8 LE]‖[IV:16]‖[ct]‖[MAC:32]` | [`opdata_decrypt`]：先验 MAC（覆盖 `[0:末尾-32]` 全量）→ AES-256-CBC 解密 → **取末 plen 字节**（前置随机填充，非 PKCS#7） |
//! | item keys `k`（无头） | `[IV:16]‖[ct]‖[MAC:32]` | [`item_keys_decrypt`]：独立路径，解密后 `[crypto:32]‖[mac:32]` |
//!
//! ## 密钥链
//!
//! 密码编码 = **UTF-8 原始字节**，**勿追加 NUL**（docs/24 §1.3：NUL 结尾
//! 只是 CommonCrypto 的 C 字符串表示，NUL 本身不进 PBKDF2 输入）。
//!
//! ```text
//! PBKDF2-HMAC-SHA512(password, salt=profile.salt(16B), iterations, dkLen=64)
//!   → derived[0:32] 加密钥 / derived[32:64] MAC 钥
//! → opdata01 解密 masterKey（明文 256B）→ SHA-512 劈分 → master 加密/MAC 钥
//! → opdata01 解密 overviewKey（明文 64B）→ SHA-512 劈分 → overview 加密/MAC 钥
//! → 每条目 k → [item crypto:32]‖[item mac:32]
//! ```
//!
//! ## 硬性约束
//!
//! - 不吞错误：所有失败显式映射为 [`OpvaultCryptoError`]，不静默降级
//! - 认证失败与格式错误**可区分**，但密码错误与数据损坏**不可区分**
//!   （[`OpvaultCryptoError::AuthFailed`] 统一承载，对齐
//!   `docs/04-系统设计.md` §4.2 信息泄露纪律）
//! - 密钥类型实现 `Zeroize` + `ZeroizeOnDrop`

use aes::Aes256;
use base64::Engine as _;
use cbc::Decryptor;
use cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------- 常量

/// opdata01 魔数（ASCII）。
pub const OPDATA_MAGIC: &[u8; 8] = b"opdata01";

/// AES 块大小（字节）。
pub const BLOCK_LEN: usize = 16;

/// IV 长度（字节）。
pub const IV_LEN: usize = 16;

/// HMAC-SHA256 输出长度（字节）。
pub const HMAC_LEN: usize = 32;

/// masterKey 明文长度（字节，docs/24 §1.3 实证）。
pub const MASTER_KEY_PLAIN_LEN: usize = 256;

/// overviewKey 明文长度（字节，docs/24 §1.3 实证）。
pub const OVERVIEW_KEY_PLAIN_LEN: usize = 64;

/// item keys 解密后的长度（字节）：`[crypto:32]‖[mac:32]`。
pub const ITEM_KEYS_PLAIN_LEN: usize = 64;

/// PBKDF2 输出长度（字节）：前 32 加密钥 / 后 32 MAC 钥。
pub const DERIVED_LEN: usize = 64;

/// PBKDF2-HMAC-SHA512 迭代次数**上界**（资源耗尽防线，dev-review HIGH-1）。
///
/// 真实 1Password opvault 用 10^5（vendor 样本 40000）；10^7 留足 100 倍
/// 余量仍远低于可被滥用的量级。恶意 `profile.js` 填数十亿 iterations 会让
/// 导入挂起 CPU 耗尽——超上界在派生前即拒绝（对齐
/// `cf_crypto::kdf::MAX_M_COST_KIB` 上界先例）。
pub const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

/// opdata01 头部长度（魔数 8 + 明文长 8 + IV 16）。
const OPDATA_HEADER_LEN: usize = OPDATA_MAGIC.len() + 8 + IV_LEN;

/// item keys `k` 的最小长度（IV 16 + 至少 1 块 + MAC 32）。
const ITEM_KEYS_MIN_LEN: usize = IV_LEN + BLOCK_LEN + HMAC_LEN;

// ---------------------------------------------------------------- 错误

/// OPVault 密码学原语的错误类型。
///
/// 上层（`cf-importer`）映射到 `CfError` 既有变体（错误码零新增）：
/// - 结构预检失败 → 2001 `ImportUnknownFormat`
/// - 密码错误 / 密钥链校验失败 / 解析失败 → 2002 `ImportFailed`
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OpvaultCryptoError {
    /// 数据格式非法（魔数不符 / 长度越界 / 填充畸形等）。
    #[error("OPVault 数据格式非法：{0}")]
    Malformed(String),

    /// 认证失败：MAC 校验未通过。
    ///
    /// 信息泄露纪律：**不区分**「密码错误」与「数据损坏」——
    /// 两者统一返回本错误（对齐 `docs/04-系统设计.md` §4.2，
    /// 与解锁失败不区分密码错误/数据损坏同源）。
    #[error("OPVault 密码错误或数据损坏")]
    AuthFailed,

    /// base64 解码失败。
    #[error("OPVault base64 解码失败：{0}")]
    Decode(String),

    /// 输入长度不合法（盐 / IV / 密钥 / 明文长度等）。
    #[error("OPVault 输入长度不合法：{0}")]
    InvalidLength(String),

    /// KDF 参数非法（iterations 为零等）。
    #[error("OPVault KDF 参数非法：{0}")]
    InvalidParams(String),
}

// ---------------------------------------------------------------- 密钥类型

/// PBKDF2 派生结果：前 32 字节加密钥 / 后 32 字节 MAC 钥。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    /// 派生加密钥（`derived[0:32]`）。
    pub enc: [u8; 32],
    /// 派生 MAC 钥（`derived[32:64]`）。
    pub mac: [u8; 32],
}

/// SHA-512 劈分结果：前 32 字节加密钥 / 后 32 字节 MAC 钥。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SplitKeys {
    /// 加密钥（SHA-512 前 32 字节）。
    pub enc: [u8; 32],
    /// MAC 钥（SHA-512 后 32 字节）。
    pub mac: [u8; 32],
}

/// 保险库密钥组（masterKey / overviewKey 各自劈分后的四把子钥）。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct OpvaultKeys {
    /// master 加密钥（解条目 `k`）。
    pub master_enc: [u8; 32],
    /// master MAC 钥（验条目 `k`）。
    pub master_mac: [u8; 32],
    /// overview 加密钥（解 `o`）。
    pub overview_enc: [u8; 32],
    /// overview MAC 钥（验 `o`）。
    pub overview_mac: [u8; 32],
}

/// 单条目 item keys：解密 `k` 后得到的一对密钥。
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ItemKeys {
    /// item 加密钥（解 `d`）。
    pub crypto_key: [u8; 32],
    /// item MAC 钥（验 `d`）。
    pub mac_key: [u8; 32],
}

// ---------------------------------------------------------------- 派生

/// PBKDF2-HMAC-SHA512 派生（dkLen=64）。
///
/// `password` 为 **UTF-8 原始字节**，**勿追加 NUL**（docs/24 §1.3）。
///
/// # Errors
///
/// `iterations == 0` 或 `iterations > [`MAX_PBKDF2_ITERATIONS`]` →
/// [`OpvaultCryptoError::InvalidParams`]（超上界在派生前拒绝，防 CPU 耗尽）。
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<DerivedKeys, OpvaultCryptoError> {
    if iterations == 0 {
        return Err(OpvaultCryptoError::InvalidParams(
            "iterations 不能为零".into(),
        ));
    }
    if iterations > MAX_PBKDF2_ITERATIONS {
        return Err(OpvaultCryptoError::InvalidParams(format!(
            "iterations {iterations} 超过上界 {MAX_PBKDF2_ITERATIONS}"
        )));
    }
    if salt.is_empty() {
        return Err(OpvaultCryptoError::InvalidLength("salt 不能为空".into()));
    }
    let mut derived = [0u8; DERIVED_LEN];
    pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut derived);
    Ok(DerivedKeys {
        enc: split_32(&derived, 0)?,
        mac: split_32(&derived, 32)?,
    })
}

/// SHA-512 劈分：`SHA-512(plaintext)` 的前 32 字节加密钥 / 后 32 字节 MAC 钥。
///
/// 用于 masterKey（明文 256B）与 overviewKey（明文 64B）。
///
/// # Errors
///
/// 输入为空 → [`OpvaultCryptoError::InvalidLength`]。
pub fn sha512_split(plaintext: &[u8]) -> Result<SplitKeys, OpvaultCryptoError> {
    if plaintext.is_empty() {
        return Err(OpvaultCryptoError::InvalidLength(
            "SHA-512 劈分输入不能为空".into(),
        ));
    }
    let digest = Sha512::digest(plaintext);
    Ok(SplitKeys {
        enc: split_32(&digest, 0)?,
        mac: split_32(&digest, 32)?,
    })
}

// ---------------------------------------------------------------- opdata01 解码

/// 解码并校验一个 base64 opdata01（docs/24 §1.2 布局）。
///
/// 布局：`[magic "opdata01":8]‖[plaintext_len:8 LE]‖[IV:16]‖[AES-256-CBC ct]‖[HMAC-SHA256:32]`
///
/// 流程：
/// 1. 验魔数 + 读小端明文长 + 拆 IV / 密文 / MAC；
/// 2. 先验 MAC：`HMAC-SHA256(key_mac, 数据[0:末尾-32] 全量)`（Encrypt-then-MAC，
///    官方 Verify-and-only-then-Decrypt，常量时间比较）；
/// 3. AES-256-CBC 解密（**NoPadding**，不使用 PKCS#7）；
/// 4. CBC 填充为「前置随机字节」（非 PKCS#7）——**取末 `plaintext_len` 字节**
///    为明文。
///
/// # Errors
///
/// base64 / 布局 / 长度非法 → [`OpvaultCryptoError::Malformed`] /
/// [`OpvaultCryptoError::Decode`]；MAC 校验失败 → [`OpvaultCryptoError::AuthFailed`]
/// （密码错误与数据损坏不可区分）。
pub fn opdata_decrypt(
    key_enc: &[u8; 32],
    key_mac: &[u8; 32],
    b64_opdata: &str,
) -> Result<Vec<u8>, OpvaultCryptoError> {
    let data = base64_decode(b64_opdata)?;
    if data.len() < OPDATA_HEADER_LEN + BLOCK_LEN + HMAC_LEN {
        return Err(OpvaultCryptoError::Malformed(format!(
            "opdata01 过短：{} 字节（至少需 {}）",
            data.len(),
            OPDATA_HEADER_LEN + BLOCK_LEN + HMAC_LEN
        )));
    }
    if &data[..8] != OPDATA_MAGIC {
        return Err(OpvaultCryptoError::Malformed(
            "opdata01 魔数不符".into(),
        ));
    }

    let plen = u64::from_le_bytes(
        data[8..16]
            .try_into()
            .map_err(|_| OpvaultCryptoError::Malformed("明文长字段越界".into()))?,
    );

    let ct = &data[OPDATA_HEADER_LEN..data.len() - HMAC_LEN];
    verify_hmac(key_mac, &data[..data.len() - HMAC_LEN], &data[data.len() - HMAC_LEN..])?;

    let plaintext = aes_cbc_decrypt_no_padding(key_enc, &data[16..32], ct)?;

    let plen = usize::try_from(plen)
        .map_err(|_| OpvaultCryptoError::Malformed("明文长超出平台范围".into()))?;
    if plen > plaintext.len() {
        return Err(OpvaultCryptoError::Malformed(format!(
            "明文长 {plen} 超出解密缓冲区 {}",
            plaintext.len()
        )));
    }
    Ok(plaintext[plaintext.len() - plen..].to_vec())
}

/// 解码并校验一个 base64 item keys `k`（**无头**布局，docs/24 §1.2 澄清）。
///
/// 布局：`[IV:16]‖[ct]‖[HMAC-SHA256:32]`（**不是** opdata01，无魔数/长度头）。
/// 用 master 加密钥解密、master MAC 钥校验，解密后 `[crypto_key:32]‖[mac_key:32]`。
///
/// # Errors
///
/// 同 [`opdata_decrypt`]；解密结果长度 ≠ 64 → [`OpvaultCryptoError::Malformed`]。
pub fn item_keys_decrypt(
    master_enc: &[u8; 32],
    master_mac: &[u8; 32],
    b64_k: &str,
) -> Result<ItemKeys, OpvaultCryptoError> {
    let data = base64_decode(b64_k)?;
    if data.len() < ITEM_KEYS_MIN_LEN {
        return Err(OpvaultCryptoError::Malformed(format!(
            "item keys k 过短：{} 字节（至少需 {ITEM_KEYS_MIN_LEN}）",
            data.len()
        )));
    }
    let iv = &data[0..16];
    let ct = &data[16..data.len() - HMAC_LEN];
    verify_hmac(master_mac, &data[..data.len() - HMAC_LEN], &data[data.len() - HMAC_LEN..])?;

    let plaintext = aes_cbc_decrypt_no_padding(master_enc, iv, ct)?;
    if plaintext.len() != ITEM_KEYS_PLAIN_LEN {
        return Err(OpvaultCryptoError::Malformed(format!(
            "item keys 明文长度异常：{}（期望 {ITEM_KEYS_PLAIN_LEN}）",
            plaintext.len()
        )));
    }
    Ok(ItemKeys {
        crypto_key: split_32(&plaintext, 0)?,
        mac_key: split_32(&plaintext, 32)?,
    })
}

// ---------------------------------------------------------------- profile 派生链

/// 主密码 → 保险库密钥组（profile.js 派生链，docs/24 §1.3）。
///
/// 组合 [`pbkdf2_derive`] → 解 `masterKey`/`overviewKey` opdata01 →
/// [`sha512_split`] 劈分。`master_key_b64` / `overview_key_b64` 为
/// `profile.js` 中的 `masterKey` / `overviewKey` 字段（base64 opdata01）。
///
/// 明文长度校验：masterKey 必须 256B、overviewKey 必须 64B
/// （docs/24 §1.3 实证，失败快）。
///
/// # Errors
///
/// 派生 / 解码 / MAC 校验失败 → 对应 [`OpvaultCryptoError`]。
pub fn derive_vault_keys(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    master_key_b64: &str,
    overview_key_b64: &str,
) -> Result<OpvaultKeys, OpvaultCryptoError> {
    let derived = pbkdf2_derive(password, salt, iterations)?;

    let master_plain = opdata_decrypt(&derived.enc, &derived.mac, master_key_b64)?;
    if master_plain.len() != MASTER_KEY_PLAIN_LEN {
        return Err(OpvaultCryptoError::Malformed(format!(
            "masterKey 明文长度异常：{}（期望 {MASTER_KEY_PLAIN_LEN}）",
            master_plain.len()
        )));
    }
    let master = sha512_split(&master_plain)?;

    let overview_plain = opdata_decrypt(&derived.enc, &derived.mac, overview_key_b64)?;
    if overview_plain.len() != OVERVIEW_KEY_PLAIN_LEN {
        return Err(OpvaultCryptoError::Malformed(format!(
            "overviewKey 明文长度异常：{}（期望 {OVERVIEW_KEY_PLAIN_LEN}）",
            overview_plain.len()
        )));
    }
    let overview = sha512_split(&overview_plain)?;

    Ok(OpvaultKeys {
        master_enc: master.enc,
        master_mac: master.mac,
        overview_enc: overview.enc,
        overview_mac: overview.mac,
    })
}

// ---------------------------------------------------------------- 内部工具

/// base64 标准解码（OPVault 用带 padding 的标准 base64）。
fn base64_decode(s: &str) -> Result<Vec<u8>, OpvaultCryptoError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| OpvaultCryptoError::Decode(e.to_string()))
}

/// HMAC-SHA256 计算（内部 helper）。
///
/// `new_from_slice` 对 HMAC 任何密钥长度都不会失败，但按 crate 纪律
/// **不 `.expect()`**，仍显式映射错误。
fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32], OpvaultCryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| OpvaultCryptoError::InvalidLength(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// 常量时间校验 `expected == actual`（subtle，时序侧信道防护）。
fn verify_hmac(
    key: &[u8; 32],
    data: &[u8],
    expected: &[u8],
) -> Result<(), OpvaultCryptoError> {
    let actual = hmac_sha256(key, data)?;
    if actual.ct_eq(expected).into() {
        Ok(())
    } else {
        Err(OpvaultCryptoError::AuthFailed)
    }
}

/// AES-256-CBC 解密（NoPadding，不验/剥 PKCS#7）。
///
/// `ct` 长度必须是块大小的整倍数；否则视为畸形。
fn aes_cbc_decrypt_no_padding(
    key: &[u8; 32],
    iv: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, OpvaultCryptoError> {
    if ct.is_empty() || ct.len() % BLOCK_LEN != 0 {
        return Err(OpvaultCryptoError::Malformed(format!(
            "密文长度 {ct_len} 不是块大小 {BLOCK_LEN} 的整倍数",
            ct_len = ct.len()
        )));
    }
    if iv.len() != IV_LEN {
        return Err(OpvaultCryptoError::InvalidLength(format!(
            "IV 长度 {}（期望 {IV_LEN}）",
            iv.len()
        )));
    }
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| OpvaultCryptoError::InvalidLength(e.to_string()))?;
    // 就地解密到调用方缓冲（不启用 cipher 的 alloc feature；
    // NoPadding 不改长度，输出 = 整块明文）
    let mut buf = ct.to_vec();
    let decrypted = cipher
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|e| OpvaultCryptoError::Malformed(format!("CBC 解密失败：{e}")))?;
    Ok(decrypted.to_vec())
}

/// 从切片中取固定 32 字节（`offset..offset+32`）。
///
/// 越界 → [`OpvaultCryptoError::InvalidLength`]（不 panic、不 `unwrap`）。
fn split_32(buf: &[u8], offset: usize) -> Result<[u8; 32], OpvaultCryptoError> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| OpvaultCryptoError::InvalidLength("offset 溢出".into()))?;
    let Some(slice) = buf.get(offset..end) else {
        return Err(OpvaultCryptoError::InvalidLength(format!(
            "切片越界：offset={offset} len={}",
            buf.len()
        )));
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试专用：构造一个合法的 opdata01（前置随机填充 + Encrypt-then-MAC）。
    ///
    /// 用于自洽往返测试（**只测自洽**；与真实 1Password 互操作由
    /// `cf-importer/tests/opvault_import.rs` 的 vendor 样本断言覆盖）。
    fn seal_opdata(key_enc: &[u8; 32], key_mac: &[u8; 32], plaintext: &[u8]) -> String {
        use aes::Aes256;
        use cipher::{block_padding::NoPadding as NoPad, BlockModeEncrypt, KeyIvInit};
        use cbc::Encryptor;

        let mut iv = [0u8; IV_LEN];
        getrandom::fill(&mut iv).unwrap();

        // 前置随机填充：明文非块整倍 → 补 1..=15；整倍 → 补一整块 16（官方口径）
        let pad_len = if plaintext.len() % BLOCK_LEN == 0 {
            BLOCK_LEN
        } else {
            BLOCK_LEN - (plaintext.len() % BLOCK_LEN)
        };
        let mut padded = vec![0u8; pad_len];
        getrandom::fill(&mut padded).unwrap();
        padded.extend_from_slice(plaintext);
        assert_eq!(padded.len() % BLOCK_LEN, 0);

        let cipher = Encryptor::<Aes256>::new_from_slices(key_enc, &iv).unwrap();
        let mut out = vec![0u8; padded.len()];
        let ct = cipher.encrypt_padded_b2b::<NoPad>(&padded, &mut out).unwrap();

        let mut header = Vec::with_capacity(OPDATA_HEADER_LEN);
        header.extend_from_slice(OPDATA_MAGIC);
        header.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
        header.extend_from_slice(&iv);
        header.extend_from_slice(ct);

        let mac = hmac_sha256(key_mac, &header).unwrap();
        header.extend_from_slice(&mac);
        base64::engine::general_purpose::STANDARD.encode(&header)
    }

    /// 测试专用：构造 item keys `k`（无头，IV‖ct‖MAC；明文恰为 64 字节 =
    /// 4 整块，无填充）。
    fn seal_item_keys(master_enc: &[u8; 32], master_mac: &[u8; 32]) -> (String, ItemKeys) {
        use aes::Aes256;
        use cipher::{block_padding::NoPadding as NoPad, BlockModeEncrypt, KeyIvInit};
        use cbc::Encryptor;

        let crypto_key = [0x51u8; 32];
        let mac_key = [0x52u8; 32];
        let mut iv = [0u8; IV_LEN];
        getrandom::fill(&mut iv).unwrap();

        let plain = [crypto_key, mac_key].concat();
        let cipher = Encryptor::<Aes256>::new_from_slices(master_enc, &iv).unwrap();
        let mut out = vec![0u8; plain.len()];
        let ct = cipher.encrypt_padded_b2b::<NoPad>(&plain, &mut out).unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&iv);
        body.extend_from_slice(ct);
        let mac = hmac_sha256(master_mac, &body).unwrap();
        body.extend_from_slice(&mac);

        (
            base64::engine::general_purpose::STANDARD.encode(&body),
            ItemKeys {
                crypto_key,
                mac_key,
            },
        )
    }

    #[test]
    fn opdata01_往返一致() {
        let enc = [0x11u8; 32];
        let mac = [0x22u8; 32];
        for plain in [&b""[..], b"abc", b"x".repeat(31).as_slice(), b"y".repeat(64).as_slice()] {
            let sealed = seal_opdata(&enc, &mac, plain);
            let out = opdata_decrypt(&enc, &mac, &sealed).expect("往返应成功");
            assert_eq!(&out, plain);
        }
    }

    #[test]
    fn item_keys_往返一致() {
        let master_enc = [0x31u8; 32];
        let master_mac = [0x32u8; 32];
        let (sealed, expected) = seal_item_keys(&master_enc, &master_mac);
        let got = item_keys_decrypt(&master_enc, &master_mac, &sealed).expect("往返应成功");
        assert_eq!(got.crypto_key, expected.crypto_key);
        assert_eq!(got.mac_key, expected.mac_key);
    }

    #[test]
    fn opdata01_魔数不符报畸形() {
        let enc = [0x11u8; 32];
        let mac = [0x22u8; 32];
        let sealed = seal_opdata(&enc, &mac, b"hello");
        let mut data = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        data[0] = b'X';
        let bad = base64::engine::general_purpose::STANDARD.encode(&data);
        assert!(matches!(
            opdata_decrypt(&enc, &mac, &bad),
            Err(OpvaultCryptoError::Malformed(_))
        ));
    }

    #[test]
    fn opdata01_篡改密文导致mac失败() {
        let enc = [0x11u8; 32];
        let mac = [0x22u8; 32];
        let sealed = seal_opdata(&enc, &mac, b"hello world hello world");
        let mut data = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        // 翻一个密文字节（末尾 MAC 之前）
        let idx = data.len() - HMAC_LEN - 1;
        data[idx] ^= 0x01;
        let bad = base64::engine::general_purpose::STANDARD.encode(&data);
        assert_eq!(
            opdata_decrypt(&enc, &mac, &bad),
            Err(OpvaultCryptoError::AuthFailed)
        );
    }

    #[test]
    fn opdata01_篡改mac导致mac失败() {
        let enc = [0x11u8; 32];
        let mac = [0x22u8; 32];
        let sealed = seal_opdata(&enc, &mac, b"tamper the mac");
        let mut data = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        let bad = base64::engine::general_purpose::STANDARD.encode(&data);
        assert_eq!(
            opdata_decrypt(&enc, &mac, &bad),
            Err(OpvaultCryptoError::AuthFailed)
        );
    }

    #[test]
    fn opdata01_错误密钥mac失败() {
        let enc = [0x11u8; 32];
        let mac = [0x22u8; 32];
        let wrong = [0x99u8; 32];
        let sealed = seal_opdata(&enc, &mac, b"secret");
        // 真实 keychain 中 enc/mac 同源于 password，错误密码两者同时失效；
        // 而 MAC 只认证密文（magic+plen+IV+ct），不认证明文，
        // 故「仅 enc 错、mac 对」在真实密钥链中不可达，此处只验证整体换钥。
        assert_eq!(
            opdata_decrypt(&wrong, &wrong, &sealed),
            Err(OpvaultCryptoError::AuthFailed)
        );
        // 仅 mac 错：密文未变但 MAC 校验失败，必须拒绝。
        assert_eq!(
            opdata_decrypt(&enc, &wrong, &sealed),
            Err(OpvaultCryptoError::AuthFailed)
        );
    }

    #[test]
    fn 篡改item_keys导致mac失败() {
        let master_enc = [0x31u8; 32];
        let master_mac = [0x32u8; 32];
        let (sealed, _) = seal_item_keys(&master_enc, &master_mac);
        let mut data = base64::engine::general_purpose::STANDARD
            .decode(&sealed)
            .unwrap();
        let idx = data.len() - HMAC_LEN - 1;
        data[idx] ^= 0x01;
        let bad = base64::engine::general_purpose::STANDARD.encode(&data);
        assert!(matches!(
            item_keys_decrypt(&master_enc, &master_mac, &bad),
            Err(OpvaultCryptoError::AuthFailed)
        ));
    }

    #[test]
    fn 空salt被拒绝() {
        assert!(matches!(
            pbkdf2_derive(b"password", b"", 1000),
            Err(OpvaultCryptoError::InvalidLength(_))
        ));
    }

    #[test]
    fn 零迭代次数被拒绝() {
        let salt = [0x41u8; 16];
        assert!(matches!(
            pbkdf2_derive(b"password", &salt, 0),
            Err(OpvaultCryptoError::InvalidParams(_))
        ));
    }

    #[test]
    fn 超大迭代次数被拒绝() {
        let salt = [0x41u8; 16];
        // 超上界在派生前即拒绝（不实际跑 PBKDF2，瞬时返回；上界取值
        // 10^7 = 真实 1Password 10^5 的百倍余量，见 `MAX_PBKDF2_ITERATIONS`）
        assert!(matches!(
            pbkdf2_derive(b"password", &salt, MAX_PBKDF2_ITERATIONS + 1),
            Err(OpvaultCryptoError::InvalidParams(_))
        ));
    }

    #[test]
    fn pbkdf2_派生是确定性的() {
        let salt = [0x41u8; 16];
        let a = pbkdf2_derive(b"password", &salt, 1000).unwrap();
        let b = pbkdf2_derive(b"password", &salt, 1000).unwrap();
        assert_eq!(a.enc, b.enc);
        assert_eq!(a.mac, b.mac);
        // 前 32 / 后 32 不同（否则劈分无意义）
        assert_ne!(a.enc, a.mac);
    }

    #[test]
    fn sha512_劈分与直接摘要一致() {
        let plain = b"0123456789abcdef".repeat(16); // 256B
        let s = sha512_split(&plain).unwrap();
        let digest: [u8; 64] = Sha512::digest(&plain).into();
        assert_eq!(s.enc.as_slice(), &digest[0..32]);
        assert_eq!(s.mac.as_slice(), &digest[32..64]);
    }
}
