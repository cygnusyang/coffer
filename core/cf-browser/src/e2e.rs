//! E2E 加密协议（docs/31 §3.3，D-6 落地，IKpsk2 风格手工实现）。
//!
//! 原语映射（docs/31 §3.3 原语表，与扩展侧 WebCrypto 对齐）：
//!
//! | 原语 | 本模块 | WebCrypto（G-C） |
//! | --- | --- | --- |
//! | ECDH | `p256`（NIST P-256） | `subtle.deriveBits` |
//! | KDF | `hkdf` + `sha2`（HKDF-SHA256） | `subtle.deriveKey` |
//! | AEAD | `aes-gcm`（AES-256-GCM） | `subtle.encrypt/decrypt` |
//! | MAC | `hmac`（HMAC-SHA256） | `subtle.importKey/verify` |
//! | 随机 | `getrandom` CSPRNG | `crypto.getRandomValues` |
//!
//! 握手流程（docs/31 §3.3 为双方共同契约，host 全程 blind transport）：
//!
//! ```text
//! 扩展(initiator)                       broker(responder)
//!   msg1: e_init          ──►
//!   msg2: e_resp, pk_b,   ◄──        含 broker 对 (e_init‖e_resp) 的 ECDSA 签名
//!         signature                       （身份密钥绑定，防中间人）
//!   msg3: p=HMAC(PSK,okm) ──►        验证 PSK → 扩展身份确立
//!   会话密钥 okm = HKDF-SHA256(ikm = ee‖es, salt = e_init_pub‖e_resp_pub,
//!                             info = "cf/browser/session/v1", L = 64)
//!   每消息 = AES-256-GCM(enc_key, nonce, seq‖msg) + HMAC(mac_key, nonce‖ct‖tag)
//!            → 防重放（seq 单调，接收方拒绝 seq ≤ 已见最大值）
//! ```
//!
//! **密钥纪律**：每会话独立 ephemeral 密钥（前向保密 + 会话隔离）；会话密钥
//! 仅存内存（[`Session`] 实现 `ZeroizeOnDrop`），不落盘、不进日志；扩展侧
//! 会话密钥随 SW 终止销毁、broker 侧随进程被杀销毁（docs/31 §3.4）。
//!
//! **KAT 冻结向量**：`tests/e2e_kat.rs` 对 [`session_okm`]、[`derive_session_key`]、
//! [`compute_confirm`]、[`sign_handshake`]、[`verify_handshake`] 与帧格式做冻结断言，
//! 期望值由独立 Python 实现首算（`cryptography` 49；首算脚本 `/tmp/coffer-kat/kat_e2e.py`，
//! 对齐 docs/29 §3.3「独立 Python 实现首算」惯例）。

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CfBrowserError;
use crate::protocol::{
    AppMessage, HandshakeMessage, IDENTITY_KDF_INFO, PROTOCOL_VERSION, SESSION_KDF_INFO,
};

// ---------------------------------------------------------------- 长度常量

/// AES-256-GCM nonce 长度（96-bit，docs/31 §3.3 原语表）。
pub const GCM_NONCE_LEN: usize = 12;

/// AES-GCM 认证标签长度（128-bit）。
pub const GCM_TAG_LEN: usize = 16;

/// 帧 MAC 长度（HMAC-SHA256 输出）。
pub const FRAME_MAC_LEN: usize = 32;

/// 会话密钥总长（enc 32 + mac 32）。
pub const SESSION_KEY_LEN: usize = 64;

/// SEC1 非压缩公钥长度（0x04 ‖ X ‖ Y，WebCrypto `raw` 导出同款）。
pub const SEC1_PUB_LEN: usize = 65;

/// P1363 签名长度（r ‖ s 各 32 字节，WebCrypto ECDSA 输出同款）。
pub const SIG_LEN: usize = 64;

// ---------------------------------------------------------------- hex（线格式）

/// 编码为 hex（小写）。公钥/签名/令牌在线格式统一 hex，扩展侧 JS 原生可解。
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 解码 hex（小写/大写均可）。
///
/// # 错误
///
/// 非法 hex 字符 / 奇数长度 → [`CfBrowserError::MalformedMessage`]。
pub fn from_hex(s: &str) -> Result<Vec<u8>, CfBrowserError> {
    if s.len() % 2 != 0 {
        return Err(CfBrowserError::MalformedMessage("odd hex length".into()));
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = nib(pair[0]).ok_or_else(|| CfBrowserError::MalformedMessage("bad hex".into()))?;
        let lo = nib(pair[1]).ok_or_else(|| CfBrowserError::MalformedMessage("bad hex".into()))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

// ---------------------------------------------------------------- 密钥材料

/// 会话密钥材料（enc 32 + mac 32，`Drop` 时清零）。
///
/// 从 [`session_okm`] 的 64 字节 okm 切分：前 32 = AES-256-GCM 加密密钥，
/// 后 32 = HMAC-SHA256 帧 MAC 密钥（docs/31 §3.3）。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeyMaterial {
    /// AES-256-GCM 加密密钥。
    pub enc_key: [u8; 32],
    /// HMAC-SHA256 帧 MAC 密钥。
    pub mac_key: [u8; 32],
}

impl SessionKeyMaterial {
    /// 从 64 字节 okm 切分构造。
    ///
    /// # 错误
    ///
    /// `okm` 长度不为 64 → [`CfBrowserError::InvalidLength`]（密钥材料纪律，
    /// 不 `.expect()`，显式校验）。
    pub fn from_okm(okm: &[u8]) -> Result<Self, CfBrowserError> {
        if okm.len() != SESSION_KEY_LEN {
            return Err(CfBrowserError::InvalidLength(format!(
                "session okm length {}, need {SESSION_KEY_LEN}",
                okm.len()
            )));
        }
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&okm[..32]);
        mac_key.copy_from_slice(&okm[32..]);
        Ok(Self { enc_key, mac_key })
    }
}

// ---------------------------------------------------------------- 密钥派生

/// HKDF 派生 broker 确定性身份密钥（docs/31 §4.2）。
///
/// `seed = HKDF-SHA256(salt = vault_uuid, ikm = DEK, info = "cf/browser/v1", L = 32)`，
/// 镜像 `mcp_key` 派生方案（cf-crypto `derive_subkey`，docs/29 §3.1）；seed 再
/// 归约 mod P-256 阶 n 得私钥标量 → 换库即自然重配对（同 §4.2）。
pub fn derive_identity_key(
    dek: &[u8; 32],
    vault_uuid: &[u8; 16],
) -> Result<SecretKey, CfBrowserError> {
    let seed = cf_crypto::kdf::derive_subkey(dek, vault_uuid, IDENTITY_KDF_INFO)
        .map_err(|e| CfBrowserError::CryptoError(format!("identity derive: {e}")))?;
    scalar_from_seed(&seed)
}

/// 计算会话密钥 okm（64 字节）：`HKDF(ikm = ee‖es, salt = 双方公钥, info = "cf/browser/session/v1")`。
///
/// 参数为**已计算的共享秘密与双方公钥**（由握手方经 [`ecdh_shared`] 算出），
/// 保证本函数纯确定性、可被 KAT 冻结向量覆盖。
///
/// # 参数
///
/// - `ee`：`ECDH(e_init, e_resp)` 共享秘密（32 字节 x 坐标）；
/// - `es`：`ECDH(e_init, pk_b)` 共享秘密（绑定 broker 静态身份）；
/// - `e_init_pub` / `e_resp_pub`：双方 ephemeral 公钥（uncompressed SEC1 65 字节），
///   拼作 HKDF salt（即 docs/31 §3.3「双方 nonce」）。
pub fn session_okm(
    ee: &[u8; 32],
    es: &[u8; 32],
    e_init_pub: &[u8; 65],
    e_resp_pub: &[u8; 65],
) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>, CfBrowserError> {
    let mut salt = Vec::with_capacity(2 * SEC1_PUB_LEN);
    salt.extend_from_slice(e_init_pub);
    salt.extend_from_slice(e_resp_pub);
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ee);
    ikm.extend_from_slice(es);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    hk.expand(SESSION_KDF_INFO, okm.as_mut())
        .map_err(|_| CfBrowserError::CryptoError("hkdf expand".into()))?;
    Ok(okm)
}

/// 派生会话密钥材料（okm 切分，供上层直接持有）。
pub fn derive_session_key(
    ee: &[u8; 32],
    es: &[u8; 32],
    e_init_pub: &[u8; 65],
    e_resp_pub: &[u8; 65],
) -> Result<SessionKeyMaterial, CfBrowserError> {
    let okm = session_okm(ee, es, e_init_pub, e_resp_pub)?;
    SessionKeyMaterial::from_okm(okm.as_ref())
}

// ---------------------------------------------------------------- 身份/共享秘密

/// `ECDH(priv, pub)` 共享秘密（P-256 x 坐标，32 字节）。
pub fn ecdh_shared(priv_key: &SecretKey, pub_key: &PublicKey) -> Result<[u8; 32], CfBrowserError> {
    // elliptic-curve 0.14：diffie_hellman 接受 `impl Borrow<NonZeroScalar>` /
    // `impl Borrow<AffinePoint>`（官方文档示例同款转换：to_nonzero_scalar + as_affine）。
    let shared = diffie_hellman(priv_key.to_nonzero_scalar(), pub_key.as_affine());
    let bytes = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// 公钥 → uncompressed SEC1（65 字节）。
pub fn pub_to_sec1(pk: &PublicKey) -> Result<[u8; SEC1_PUB_LEN], CfBrowserError> {
    let pt = pk.to_sec1_point(false);
    let bytes = pt.as_bytes();
    if bytes.len() != SEC1_PUB_LEN {
        return Err(CfBrowserError::CryptoError(format!(
            "unexpected SEC1 length {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; SEC1_PUB_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// 从 hex 解析公钥（uncompressed SEC1 65 字节）。
///
/// # 错误
///
/// hex 非法 / 长度不符 / 非曲线上点 → [`CfBrowserError::MalformedMessage`]
/// （协议消息边界失败，归 8004）。
pub fn parse_sec1_pub(hex: &str) -> Result<PublicKey, CfBrowserError> {
    let bytes = from_hex(hex)?;
    if bytes.len() != SEC1_PUB_LEN {
        return Err(CfBrowserError::MalformedMessage(format!(
            "public key length {}, need {SEC1_PUB_LEN}",
            bytes.len()
        )));
    }
    PublicKey::from_sec1_bytes(&bytes)
        .map_err(|_| CfBrowserError::MalformedMessage("invalid public key".into()))
}

// ---------------------------------------------------------------- 签名（msg2）

/// broker 对 `e_init ‖ e_resp` 的 ECDSA-P256-SHA256 签名（P1363 r‖s 64 字节）。
///
/// RFC 6979 确定性签名（`ecdsa` crate `Signer::sign`，无需随机源）——与
/// KAT 冻结向量的可复现性一致；扩展侧 WebCrypto 验证 P1363 原始格式。
pub fn sign_handshake(
    broker_key: &SecretKey,
    e_init_pub: &[u8; 65],
    e_resp_pub: &[u8; 65],
) -> Result<[u8; SIG_LEN], CfBrowserError> {
    let msg = sig_message(e_init_pub, e_resp_pub);
    let signing = SigningKey::from(broker_key);
    let sig: Signature = signing.sign(&msg);
    let bytes = sig.to_bytes();
    if bytes.len() != SIG_LEN {
        return Err(CfBrowserError::CryptoError(format!(
            "unexpected signature length {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; SIG_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 验证 msg2 的 broker 身份签名（防中间人，docs/31 §3.3）。
///
/// # 错误
///
/// 签名格式非法 / 验证失败 → [`CfBrowserError::AuthFailed`]（信息泄露纪律，
/// 不区分「签名错」与「公钥不符」）。
pub fn verify_handshake(
    pk_b: &PublicKey,
    e_init_pub: &[u8; 65],
    e_resp_pub: &[u8; 65],
    sig: &[u8; SIG_LEN],
) -> Result<(), CfBrowserError> {
    let msg = sig_message(e_init_pub, e_resp_pub);
    let signature = Signature::from_slice(sig).map_err(|_| CfBrowserError::AuthFailed)?;
    let verifying = VerifyingKey::from(pk_b);
    verifying
        .verify(&msg, &signature)
        .map_err(|_| CfBrowserError::AuthFailed)
}

fn sig_message(e_init_pub: &[u8; 65], e_resp_pub: &[u8; 65]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(2 * SEC1_PUB_LEN);
    msg.extend_from_slice(e_init_pub);
    msg.extend_from_slice(e_resp_pub);
    msg
}

// ---------------------------------------------------------------- confirm 令牌

/// `p = HMAC-SHA256(key = PSK, msg = okm)`（docs/31 §3.3：扩展身份确立）。
pub fn compute_confirm(psk: &[u8; 32], okm: &[u8]) -> Result<[u8; 32], CfBrowserError> {
    hmac_sha256(psk, &[okm])
}

/// 常量时间校验 confirm 令牌。
///
/// # 错误
///
/// 不符 → [`CfBrowserError::AuthFailed`]（不区分「PSK 错」与「会话不符」）。
pub fn verify_confirm(
    psk: &[u8; 32],
    okm: &[u8],
    token: &[u8; 32],
) -> Result<(), CfBrowserError> {
    let expected = compute_confirm(psk, okm)?;
    if bool::from(expected.ct_eq(token)) {
        Ok(())
    } else {
        Err(CfBrowserError::AuthFailed)
    }
}

// ---------------------------------------------------------------- 每消息帧

/// AES-256-GCM 加密明文 → `ct ‖ tag`（aad 为空）。
///
/// 独立可测（KAT 帧向量走本函数），`Session::encrypt` 内部随机 nonce 后组合。
pub fn encrypt_payload(
    enc_key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CfBrowserError> {
    let cipher = Aes256Gcm::new_from_slice(enc_key)
        .map_err(|e| CfBrowserError::CryptoError(format!("aes-gcm key: {e}")))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|_| CfBrowserError::CryptoError("aes-gcm encrypt".into()))
}

/// 解密 `ct ‖ tag`（aad 为空）。
///
/// # 错误
///
/// tag 校验失败 → [`CfBrowserError::AuthFailed`]。
pub fn decrypt_payload(
    enc_key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    ct_tag: &[u8],
) -> Result<Vec<u8>, CfBrowserError> {
    let cipher = Aes256Gcm::new_from_slice(enc_key)
        .map_err(|e| CfBrowserError::CryptoError(format!("aes-gcm key: {e}")))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct_tag,
                aad: b"",
            },
        )
        .map_err(|_| CfBrowserError::AuthFailed)
}

/// 帧 MAC：`HMAC-SHA256(mac_key, nonce ‖ ct ‖ tag)`（docs/31 §3.3「+ HMAC 校验」）。
pub fn frame_mac(
    mac_key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    ct_tag: &[u8],
) -> Result<[u8; FRAME_MAC_LEN], CfBrowserError> {
    hmac_sha256(mac_key, &[nonce, ct_tag])
}

/// 常量时间校验帧 MAC。
///
/// # 错误
///
/// 不符 → [`CfBrowserError::AuthFailed`]（先于解密判定，防时序侧信道）。
pub fn verify_frame_mac(
    mac_key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    ct_tag: &[u8],
    mac: &[u8; FRAME_MAC_LEN],
) -> Result<(), CfBrowserError> {
    let expected = frame_mac(mac_key, nonce, ct_tag)?;
    if bool::from(expected.ct_eq(mac)) {
        Ok(())
    } else {
        Err(CfBrowserError::AuthFailed)
    }
}

fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> Result<[u8; 32], CfBrowserError> {
    type HmacSha256 = Hmac<Sha256>;
    // 全限定 `Mac::new_from_slice`：`aes_gcm::KeyInit` 与 `hmac::Mac` 各提供一个
    // `new_from_slice`（两 trait 均在作用域），必须消歧。
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| CfBrowserError::CryptoError("hmac key".into()))?;
    for p in parts {
        mac.update(p);
    }
    Ok(mac.finalize().into_bytes().into())
}

// ---------------------------------------------------------------- 会话

/// 已建立的 E2E 会话（docs/31 §3.4 会话生命周期）。
///
/// - 会话密钥仅存内存，`Drop` 时清零（进程/SW 终止即销毁）；
/// - 每消息 `frame = nonce(12) ‖ ct ‖ tag(16) ‖ mac(32)`，seq 单调防重放；
/// - 发送方 seq 独立计数，接收方拒绝 `seq ≤` 已见最大值（T-9）。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    outbound_seq: u64,
    inbound_last_seq: u64,
}

impl Session {
    /// 从会话密钥材料建立会话（seq 计数从 0 起）。
    #[must_use]
    pub fn new(material: SessionKeyMaterial) -> Self {
        Self {
            enc_key: material.enc_key,
            mac_key: material.mac_key,
            outbound_seq: 0,
            inbound_last_seq: 0,
        }
    }

    /// 加密一条应用消息（随机 nonce，seq 自增）。
    ///
    /// # 错误
    ///
    /// 序列化失败 / 随机源不可用 / seq 溢出 → 对应 [`CfBrowserError`]。
    pub fn encrypt(&mut self, msg: &AppMessage) -> Result<Vec<u8>, CfBrowserError> {
        let payload = serde_json::to_vec(msg)
            .map_err(|e| CfBrowserError::Serialize(e.to_string()))?;
        let seq = self
            .outbound_seq
            .checked_add(1)
            // 出站序号溢出（2^64 条消息，现实不可达）不是重放——是协议内部故障
            .ok_or_else(|| CfBrowserError::CryptoError("outbound seq overflow".into()))?;
        self.outbound_seq = seq;

        let mut plaintext = Vec::with_capacity(8 + payload.len());
        plaintext.extend_from_slice(&seq.to_le_bytes());
        plaintext.extend_from_slice(&payload);

        let mut nonce = [0u8; GCM_NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|e| CfBrowserError::RandomUnavailable(e.to_string()))?;
        let ct_tag = encrypt_payload(&self.enc_key, &nonce, &plaintext)?;
        let mac = frame_mac(&self.mac_key, &nonce, &ct_tag)?;

        let mut frame = Vec::with_capacity(GCM_NONCE_LEN + ct_tag.len() + FRAME_MAC_LEN);
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ct_tag);
        frame.extend_from_slice(&mac);
        Ok(frame)
    }

    /// 解密并校验一条帧，返回应用消息。
    ///
    /// 校验顺序：长度 → 帧 MAC（常量时间）→ GCM 解密 → seq 单调 → JSON 解析。
    ///
    /// # 错误
    ///
    /// - 长度不足 / 帧 MAC 不符 / GCM 失败 → [`CfBrowserError::AuthFailed`]（统一）
    /// - `seq <=` 已见 → [`CfBrowserError::ReplayDetected`]
    /// - payload JSON 非法 → [`CfBrowserError::MalformedMessage`]
    pub fn decrypt(&mut self, frame: &[u8]) -> Result<AppMessage, CfBrowserError> {
        let min_len = GCM_NONCE_LEN + GCM_TAG_LEN + FRAME_MAC_LEN;
        if frame.len() < min_len {
            return Err(CfBrowserError::InvalidLength(format!(
                "frame length {}, minimum {min_len}",
                frame.len()
            )));
        }
        let (nonce, rest) = frame.split_at(GCM_NONCE_LEN);
        let mac_end = rest.len() - FRAME_MAC_LEN;
        let (ct_tag, mac) = rest.split_at(mac_end);
        let nonce_arr: [u8; GCM_NONCE_LEN] = nonce.try_into().map_err(|_| {
            CfBrowserError::CryptoError("nonce segment length".into())
        })?;
        let mac_arr: [u8; FRAME_MAC_LEN] = mac.try_into().map_err(|_| {
            CfBrowserError::CryptoError("mac segment length".into())
        })?;
        verify_frame_mac(&self.mac_key, &nonce_arr, ct_tag, &mac_arr)?;

        let plaintext = decrypt_payload(&self.enc_key, &nonce_arr, ct_tag)?;
        if plaintext.len() < 8 {
            return Err(CfBrowserError::AuthFailed);
        }
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&plaintext[..8]);
        let seq = u64::from_le_bytes(seq_bytes);
        if seq <= self.inbound_last_seq {
            return Err(CfBrowserError::ReplayDetected);
        }
        self.inbound_last_seq = seq;

        serde_json::from_slice(&plaintext[8..])
            .map_err(|e| CfBrowserError::MalformedMessage(e.to_string()))
    }
}

// ---------------------------------------------------------------- 握手状态机

/// 握手状态机（initiator = 扩展侧，docs/31 §3.3）。
///
/// 构造即生成 initiator ephemeral 密钥并产出 msg1；`on_response` 校验
/// msg2 后产出 (msg3, 已建立会话)。每次握手独立 ephemeral → 前向保密。
pub struct InitiatorHandshake {
    psk: [u8; 32],
    pk_b: PublicKey,
    e_init_priv: SecretKey,
    e_init_pub: [u8; SEC1_PUB_LEN],
}

impl InitiatorHandshake {
    /// 新建 initiator 握手（随机 ephemeral）。
    ///
    /// `pk_b` 为已 pin 的 broker 静态公钥（配对流 §5.3）。
    pub fn new(
        psk: [u8; 32],
        pk_b: PublicKey,
    ) -> Result<(Self, HandshakeMessage), CfBrowserError> {
        let e_init_priv = random_secret_key()?;
        let e_init_pub = pub_to_sec1(&e_init_priv.public_key())?;
        let msg = HandshakeMessage::Init {
            version: PROTOCOL_VERSION,
            e_init: to_hex(&e_init_pub),
        };
        Ok((
            Self {
                psk,
                pk_b,
                e_init_priv,
                e_init_pub,
            },
            msg,
        ))
    }

    /// 以固定 ephemeral 私钥构造（KAT 冻结向量 / 测试注入用）。
    ///
    /// # 安全
    ///
    /// **仅测试与 KAT 使用**：固定 ephemeral 无前向保密，生产路径
    /// 必须走 [`Self::new`]。
    pub fn new_with_ephemeral(
        psk: [u8; 32],
        pk_b: PublicKey,
        e_init_priv: SecretKey,
    ) -> Result<(Self, HandshakeMessage), CfBrowserError> {
        let e_init_pub = pub_to_sec1(&e_init_priv.public_key())?;
        let msg = HandshakeMessage::Init {
            version: PROTOCOL_VERSION,
            e_init: to_hex(&e_init_pub),
        };
        Ok((
            Self {
                psk,
                pk_b,
                e_init_priv,
                e_init_pub,
            },
            msg,
        ))
    }

    /// 处理 msg2 → 产出 (msg3, 会话)。
    ///
    /// 校验顺序（docs/31 §3.2 层 ④）：version → 公钥 pin 匹配 → 签名验证 →
    /// 会话密钥派生 → confirm 令牌。
    ///
    /// # 错误
    ///
    /// 任何校验失败 → [`CfBrowserError::AuthFailed`]（握手失败 → 会话不建立）。
    pub fn on_response(
        self,
        resp: &HandshakeMessage,
    ) -> Result<(HandshakeMessage, Session), CfBrowserError> {
        let HandshakeMessage::Response {
            version,
            e_resp,
            pk_b,
            signature,
        } = resp
        else {
            return Err(CfBrowserError::MalformedMessage("expected response".into()));
        };
        if *version != PROTOCOL_VERSION {
            return Err(CfBrowserError::UnsupportedVersion(*version));
        }

        // 1. broker 公钥必须 == pinned（防中间人换钥）
        let resp_pk_b = parse_sec1_pub(pk_b)?;
        if resp_pk_b != self.pk_b {
            return Err(CfBrowserError::AuthFailed);
        }
        // 2. 验身份签名（P1363）
        let e_resp_pub = parse_sec1_pub(e_resp)?;
        let e_resp_bytes = pub_to_sec1(&e_resp_pub)?;
        let sig_bytes = parse_sig(signature)?;
        verify_handshake(&self.pk_b, &self.e_init_pub, &e_resp_bytes, &sig_bytes)?;

        // 3. 派生会话密钥（ee = e_init×e_resp，es = e_init×pk_b）
        let ee = ecdh_shared(&self.e_init_priv, &e_resp_pub)?;
        let es = ecdh_shared(&self.e_init_priv, &self.pk_b)?;
        let okm = session_okm(&ee, &es, &self.e_init_pub, &e_resp_bytes)?;
        let token = compute_confirm(&self.psk, okm.as_ref())?;
        let session = Session::new(SessionKeyMaterial::from_okm(okm.as_ref())?);

        let confirm = HandshakeMessage::Confirm {
            version: PROTOCOL_VERSION,
            p: to_hex(&token),
        };
        Ok((confirm, session))
    }
}

/// 握手状态机（responder = broker 侧）。
///
/// 构造即生成 responder ephemeral 密钥；`on_init` 处理 msg1 → 产出 msg2 与
/// 待确认态 [`PendingConfirm`]；`PendingConfirm::on_confirm` 校验 PSK 后
/// 建立会话。
pub struct ResponderHandshake {
    broker_key: SecretKey,
    pk_b: [u8; SEC1_PUB_LEN],
    psk: [u8; 32],
    e_resp_priv: SecretKey,
    e_resp_pub: [u8; SEC1_PUB_LEN],
}

impl ResponderHandshake {
    /// 新建 responder 握手（随机 ephemeral）。
    ///
    /// `broker_key` 为 broker 确定性身份私钥（[`derive_identity_key`]）。
    pub fn new(broker_key: SecretKey, psk: [u8; 32]) -> Result<Self, CfBrowserError> {
        let e_resp_priv = random_secret_key()?;
        let e_resp_pub = pub_to_sec1(&e_resp_priv.public_key())?;
        let pk_b = pub_to_sec1(&broker_key.public_key())?;
        Ok(Self {
            broker_key,
            pk_b,
            psk,
            e_resp_priv,
            e_resp_pub,
        })
    }

    /// 以固定 ephemeral 私钥构造（KAT 冻结向量 / 测试注入用）。
    ///
    /// # 安全
    ///
    /// **仅测试与 KAT 使用**（同 [`InitiatorHandshake::new_with_ephemeral`]）。
    pub fn new_with_ephemeral(
        broker_key: SecretKey,
        psk: [u8; 32],
        e_resp_priv: SecretKey,
    ) -> Result<Self, CfBrowserError> {
        let e_resp_pub = pub_to_sec1(&e_resp_priv.public_key())?;
        let pk_b = pub_to_sec1(&broker_key.public_key())?;
        Ok(Self {
            broker_key,
            pk_b,
            psk,
            e_resp_priv,
            e_resp_pub,
        })
    }

    /// 处理 msg1 → 产出 (msg2, 待确认态)。
    ///
    /// # 错误
    ///
    /// 消息非 Init / version 不符 / 公钥非法 → 对应 [`CfBrowserError`]。
    pub fn on_init(
        self,
        init: &HandshakeMessage,
    ) -> Result<(HandshakeMessage, PendingConfirm), CfBrowserError> {
        let HandshakeMessage::Init { version, e_init } = init else {
            return Err(CfBrowserError::MalformedMessage("expected init".into()));
        };
        if *version != PROTOCOL_VERSION {
            return Err(CfBrowserError::UnsupportedVersion(*version));
        }
        let e_init_pub = parse_sec1_pub(e_init)?;
        let e_init_bytes = pub_to_sec1(&e_init_pub)?;

        let ee = ecdh_shared(&self.e_resp_priv, &e_init_pub)?;
        let es = ecdh_shared(&self.broker_key, &e_init_pub)?;
        let sig = sign_handshake(&self.broker_key, &e_init_bytes, &self.e_resp_pub)?;

        let resp = HandshakeMessage::Response {
            version: PROTOCOL_VERSION,
            e_resp: to_hex(&self.e_resp_pub),
            pk_b: to_hex(&self.pk_b),
            signature: to_hex(&sig),
        };
        let pending = PendingConfirm {
            psk: self.psk,
            ee,
            es,
            e_init_pub: e_init_bytes,
            e_resp_pub: self.e_resp_pub,
        };
        Ok((resp, pending))
    }
}

/// 已收到 msg1、待 msg3 确认的中间态。
pub struct PendingConfirm {
    psk: [u8; 32],
    ee: [u8; 32],
    es: [u8; 32],
    e_init_pub: [u8; SEC1_PUB_LEN],
    e_resp_pub: [u8; SEC1_PUB_LEN],
}

impl PendingConfirm {
    /// 校验 msg3（PSK 确认）→ 建立会话。
    ///
    /// # 错误
    ///
    /// 消息非 Confirm / version 不符 / 令牌不符 → 对应 [`CfBrowserError`]
    /// （令牌不符 → [`CfBrowserError::AuthFailed`]，会话不建立）。
    pub fn on_confirm(self, confirm: &HandshakeMessage) -> Result<Session, CfBrowserError> {
        let HandshakeMessage::Confirm { version, p } = confirm else {
            return Err(CfBrowserError::MalformedMessage("expected confirm".into()));
        };
        if *version != PROTOCOL_VERSION {
            return Err(CfBrowserError::UnsupportedVersion(*version));
        }
        let token = parse_32(p)?;
        let okm = session_okm(&self.ee, &self.es, &self.e_init_pub, &self.e_resp_pub)?;
        verify_confirm(&self.psk, okm.as_ref(), &token)?;
        Ok(Session::new(SessionKeyMaterial::from_okm(okm.as_ref())?))
    }
}

fn parse_sig(s: &str) -> Result<[u8; SIG_LEN], CfBrowserError> {
    let bytes = from_hex(s)?;
    if bytes.len() != SIG_LEN {
        return Err(CfBrowserError::MalformedMessage(format!(
            "signature length {}, need {SIG_LEN}",
            bytes.len()
        )));
    }
    let mut out = [0u8; SIG_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_32(s: &str) -> Result<[u8; 32], CfBrowserError> {
    let bytes = from_hex(s)?;
    if bytes.len() != 32 {
        return Err(CfBrowserError::MalformedMessage(format!(
            "token length {}, need 32",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 生成随机 P-256 ephemeral 私钥（getrandom CSPRNG + 归约 mod n）。
///
/// 不经 `SecretKey::random`（其 `rand_core::CryptoRng` 绑定在椭圆曲线 0.14
/// 下与 `OsRng` 的 trait 归属有摩擦，且该方法已弃用）；随机源失败**绝不**
/// 降级弱随机（对齐 cf-crypto NFR-SEC-06，[`CfBrowserError::RandomUnavailable`]）。
fn random_secret_key() -> Result<SecretKey, CfBrowserError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| CfBrowserError::RandomUnavailable(e.to_string()))?;
    scalar_from_seed(&bytes)
}

/// 32 字节大端 → P-256 私钥标量（归约 mod n）。
///
/// P-256 阶 `n ≈ 2^256 - 2^224`：任意 256 位值 x 若 `x >= n`，一次减法
/// `x - n < 2^224 < n` 即得余数（无需通用大数除法）。`x == 0` 拒绝
/// （标量零非法，概率 2^-256）。
fn scalar_from_seed(seed: &[u8; 32]) -> Result<SecretKey, CfBrowserError> {
    const N_HI: u128 = 0xFFFF_FFFF_0000_0000_FFFF_FFFF_FFFF_FFFF;
    const N_LO: u128 = 0xBCE6_FAAD_A717_9E84_F3B9_CAC2_FC63_2551;

    let x_hi = u128_from_be(&seed[..16]);
    let x_lo = u128_from_be(&seed[16..]);
    let (r_hi, r_lo) = if x_hi > N_HI || (x_hi == N_HI && x_lo >= N_LO) {
        let (lo, borrow) = x_lo.overflowing_sub(N_LO);
        let hi = x_hi.overflowing_sub(N_HI).0;
        let hi = if borrow { hi.wrapping_sub(1) } else { hi };
        (hi, lo)
    } else {
        (x_hi, x_lo)
    };
    if r_hi == 0 && r_lo == 0 {
        return Err(CfBrowserError::CryptoError("identity scalar is zero".into()));
    }

    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&be_from_u128(r_hi));
    bytes[16..].copy_from_slice(&be_from_u128(r_lo));
    SecretKey::from_slice(&bytes)
        .map_err(|e| CfBrowserError::CryptoError(format!("identity key: {e}")))
}

fn u128_from_be(b: &[u8]) -> u128 {
    debug_assert_eq!(b.len(), 16);
    let mut out = 0u128;
    for byte in b {
        out = (out << 8) | u128::from(*byte);
    }
    out
}

fn be_from_u128(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

#[cfg(test)]
mod tests {
    //! 归约逻辑单元测试（KAT 冻结向量只覆盖 `seed < n` 路径，此处补 `>= n` 边界）。
    //!
    //! 注：本模块在 `#![deny(clippy::unwrap_used, clippy::expect_used)]` 之下，
    //! 用 `?` 与 `assert_*` 而非 unwrap/expect。

    use super::*;

    #[test]
    fn scalar_reduction_above_n() -> Result<(), CfBrowserError> {
        // x = 0xff..ff（> n）→ 单次减法得 x - n（Python 验证：00000000ffffffff…cdaae）
        let x = [0xffu8; 32];
        let key = scalar_from_seed(&x)?;
        let mut expected = [0u8; 32];
        expected.copy_from_slice(
            &from_hex("00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae")?,
        );
        let expected_key = SecretKey::from_slice(&expected)
            .map_err(|e| CfBrowserError::CryptoError(e.to_string()))?;
        assert_eq!(key.public_key(), expected_key.public_key());

        // 归约结果 < n：再归约幂等
        let again = scalar_from_seed(&expected)?;
        assert_eq!(again.public_key(), expected_key.public_key());
        Ok(())
    }

    #[test]
    fn scalar_reduction_of_n_is_zero_rejected() -> Result<(), CfBrowserError> {
        // x = n → x - n = 0 → 标量零非法，拒绝
        let n_bytes = from_hex(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        )?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&n_bytes);
        assert!(matches!(
            scalar_from_seed(&arr),
            Err(CfBrowserError::CryptoError(_))
        ));
        Ok(())
    }
}
