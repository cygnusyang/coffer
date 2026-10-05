//! AEAD 标准测试向量（KAT）——验证底层依赖 `chacha20poly1305` crate 的正确性。
//!
//! 职责：把权威文档的向量硬编码为期望值，用 crate 真实加解密逐字节比对，
//! 把「依赖是否正确实现了标准」变成可回归的断言（NFR-SEC-01 可验证性）。
//! 这些向量不是本项目生产数据，与本仓库其他密文无耦合。
//!
//! 向量来源（节号已对照原文核实）：
//! 1. ChaCha20-Poly1305：**RFC 8439 §2.8.2**「Example and Test Vector for
//!    AEAD_CHACHA20_POLY1305」。任务单（v1.0.0-C1）记为 §2.4.2，该节实为
//!    ChaCha20 块函数向量；AEAD 组合向量在 §2.8.2，此处按原文引证。
//! 2. XChaCha20-Poly1305：**draft-irtf-cfrg-xchacha-03 §A.1**「Example and
//!    Test Vector for AEAD_XCHACHA20_POLY1305」。任务单记为 §A.3，该节实为
//!    XChaCha20 块函数「Developer-Friendly Test Vectors」；AEAD 向量在 §A.1。
//!    draft-04 起未再发布到 ietf 存档，-03 为最新可获取版。
//!
//! 生产封装路径（cf_crypto::aead）另用 §A.1 向量走一次 `open`
//! （见 production_open_decrypts_xchacha_vector）：把向量的
//! nonce‖ct‖tag 原样喂给生产 `open`，确认封装与标准向量互操作。

use cf_crypto::aead::{open, SessionKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce,
};

/// RFC 8439 §2.8.2 / draft-irtf-cfrg-xchacha §A.1 共用密钥（0x80..=0x9f）。
const KEY: [u8; 32] = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f];

/// 两向量共用 AAD（12 字节）。
const AAD: &[u8] = b"\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7";

/// 两向量共用明文（114 字节，"Ladies and Gentlemen…"）。
const PLAINTEXT: &[u8] = b"\x4c\x61\x64\x69\x65\x73\x20\x61\x6e\x64\x20\x47\x65\x6e\x74\x6c\x65\x6d\x65\x6e\x20\x6f\x66\x20\x74\x68\x65\x20\x63\x6c\x61\x73\x73\x20\x6f\x66\x20\x27\x39\x39\x3a\x20\x49\x66\x20\x49\x20\x63\x6f\x75\x6c\x64\x20\x6f\x66\x66\x65\x72\x20\x79\x6f\x75\x20\x6f\x6e\x6c\x79\x20\x6f\x6e\x65\x20\x74\x69\x70\x20\x66\x6f\x72\x20\x74\x68\x65\x20\x66\x75\x74\x75\x72\x65\x2c\x20\x73\x75\x6e\x73\x63\x72\x65\x65\x6e\x20\x77\x6f\x75\x6c\x64\x20\x62\x65\x20\x69\x74\x2e";

/// RFC 8439 §2.8.2 nonce（12 字节）。
const RFC8439_NONCE: [u8; 12] = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];

/// RFC 8439 §2.8.2 密文（114 字节）。
const RFC8439_CIPHERTEXT: &[u8] = b"\xd3\x1a\x8d\x34\x64\x8e\x60\xdb\x7b\x86\xaf\xbc\x53\xef\x7e\xc2\xa4\xad\xed\x51\x29\x6e\x08\xfe\xa9\xe2\xb5\xa7\x36\xee\x62\xd6\x3d\xbe\xa4\x5e\x8c\xa9\x67\x12\x82\xfa\xfb\x69\xda\x92\x72\x8b\x1a\x71\xde\x0a\x9e\x06\x0b\x29\x05\xd6\xa5\xb6\x7e\xcd\x3b\x36\x92\xdd\xbd\x7f\x2d\x77\x8b\x8c\x98\x03\xae\xe3\x28\x09\x1b\x58\xfa\xb3\x24\xe4\xfa\xd6\x75\x94\x55\x85\x80\x8b\x48\x31\xd7\xbc\x3f\xf4\xde\xf0\x8e\x4b\x7a\x9d\xe5\x76\xd2\x65\x86\xce\xc6\x4b\x61\x16";

/// RFC 8439 §2.8.2 认证标签（16 字节）。
const RFC8439_TAG: &[u8] = b"\x1a\xe1\x0b\x59\x4f\x09\xe2\x6a\x7e\x90\x2e\xcb\xd0\x60\x06\x91";

/// draft-irtf-cfrg-xchacha-03 §A.1 nonce（24 字节）。
const XCHACHA_NONCE: [u8; 24] = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

/// draft-irtf-cfrg-xchacha-03 §A.1 密文（114 字节）。
const XCHACHA_CIPHERTEXT: &[u8] = b"\xbd\x6d\x17\x9d\x3e\x83\xd4\x3b\x95\x76\x57\x94\x93\xc0\xe9\x39\x57\x2a\x17\x00\x25\x2b\xfa\xcc\xbe\xd2\x90\x2c\x21\x39\x6c\xbb\x73\x1c\x7f\x1b\x0b\x4a\xa6\x44\x0b\xf3\xa8\x2f\x4e\xda\x7e\x39\xae\x64\xc6\x70\x8c\x54\xc2\x16\xcb\x96\xb7\x2e\x12\x13\xb4\x52\x2f\x8c\x9b\xa4\x0d\xb5\xd9\x45\xb1\x1b\x69\xb9\x82\xc1\xbb\x9e\x3f\x3f\xac\x2b\xc3\x69\x48\x8f\x76\xb2\x38\x35\x65\xd3\xff\xf9\x21\xf9\x66\x4c\x97\x63\x7d\xa9\x76\x88\x12\xf6\x15\xc6\x8b\x13\xb5\x2e";

/// draft-irtf-cfrg-xchacha-03 §A.1 认证标签（16 字节）。
const XCHACHA_TAG: &[u8] = b"\xc0\x87\x59\x24\xc1\xc7\x98\x79\x47\xde\xaf\xd8\x78\x0a\xcf\x49";

/// RFC 8439 §2.8.2 ChaCha20-Poly1305 向量：加密与解密双向逐字节核对。
#[test]
fn rfc8439_chacha20poly1305_vector() {
    let cipher = ChaCha20Poly1305::new_from_slice(&KEY).expect("32 字节密钥");

    // 加密侧：crate 返回 ct‖tag，须与向量逐字节一致
    let ct = cipher
        .encrypt(&Nonce::from(RFC8439_NONCE), Payload { msg: PLAINTEXT, aad: AAD })
        .expect("crate 加密失败");
    let mut expected_ct = Vec::from(RFC8439_CIPHERTEXT);
    expected_ct.extend_from_slice(RFC8439_TAG);
    assert_eq!(ct, expected_ct, "密文与 RFC 8439 §2.8.2 不符");

    // 解密侧：ct‖tag → 明文
    let pt = cipher
        .decrypt(&Nonce::from(RFC8439_NONCE), Payload { msg: &ct, aad: AAD })
        .expect("crate 解密失败");
    assert_eq!(pt, PLAINTEXT, "明文与 RFC 8439 §2.8.2 不符");
}

/// draft-irtf-cfrg-xchacha-03 §A.1 XChaCha20-Poly1305 向量（生产原语）。
#[test]
fn draft_xchacha20poly1305_vector() {
    let cipher = XChaCha20Poly1305::new_from_slice(&KEY).expect("32 字节密钥");

    let ct = cipher
        .encrypt(&XNonce::from(XCHACHA_NONCE), Payload { msg: PLAINTEXT, aad: AAD })
        .expect("crate 加密失败");
    let mut expected_ct = Vec::from(XCHACHA_CIPHERTEXT);
    expected_ct.extend_from_slice(XCHACHA_TAG);
    assert_eq!(ct, expected_ct, "密文与 draft-irtf-cfrg-xchacha §A.1 不符");

    let pt = cipher
        .decrypt(&XNonce::from(XCHACHA_NONCE), Payload { msg: &ct, aad: AAD })
        .expect("crate 解密失败");
    assert_eq!(pt, PLAINTEXT, "明文与 draft-irtf-cfrg-xchacha §A.1 不符");
}

/// 生产 `open` 路径对照 §A.1 向量：nonce‖ct‖tag 装配后原样解密。
///
/// `seal` 的 nonce 由 CSPRNG 随机生成，无法用固定向量做加密侧对照；
/// 解密侧（`open`）接受任意合法 nonce‖ct‖tag，故用标准向量直接驱动生产
/// 封装，确认 XChaCha20-Poly1305 生产路径与标准互操作。
#[test]
fn production_open_decrypts_xchacha_vector() {
    let key = SessionKey::new(KEY);
    let mut sealed = Vec::with_capacity(
        XCHACHA_NONCE.len() + XCHACHA_CIPHERTEXT.len() + XCHACHA_TAG.len(),
    );
    sealed.extend_from_slice(&XCHACHA_NONCE);
    sealed.extend_from_slice(XCHACHA_CIPHERTEXT);
    sealed.extend_from_slice(XCHACHA_TAG);

    let pt = open(&key, AAD, &sealed).expect("生产 open 应能解密标准向量");
    assert_eq!(pt, PLAINTEXT);
}
