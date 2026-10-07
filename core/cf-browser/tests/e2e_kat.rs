//! E2E KAT 冻结向量（独立 Python 首算，docs/29 §3.3「独立 Python 实现首算」惯例）。
//!
//! **首算方法**：`/tmp/coffer-kat/kat_e2e.py`（`cryptography` 49；`der_to_p1363.py`
//! 解析 DER→P1363）。Rust 侧按本文件冻结 hex 断言，实现以 Python 为基准对齐。
//! 冻结输入（docs/31 §3.3 / §4.2）：DEK = `0x42×32`、vault_uuid = `0x11×16`、
//! 固定 ephemeral `e_init_priv = 0x10..0x2f`、`e_resp_priv = 0x30..0x4f`、
//! `PSK = 0x50..0x6f`、帧 nonce = `0xa0..0xac`、seq = 1。
//!
//! 冻结帧 md5（冻结帧字节的完整性自检值）：见 [`FROZEN_FRAME`] 注释。

use cf_browser::broker::BrokerEndpoint;
use cf_browser::e2e::{
    compute_confirm, decrypt_payload, derive_identity_key, derive_session_key, ecdh_shared,
    encrypt_payload, frame_mac, from_hex, pub_to_sec1, session_okm, sign_handshake,
    verify_confirm, verify_frame_mac, verify_handshake, InitiatorHandshake, ResponderHandshake,
    Session, SessionKeyMaterial,
};
use cf_browser::error::CfBrowserError;
use cf_browser::protocol::{AppMessage, AppRequest, AppResponse, HandshakeMessage};
use p256::{PublicKey, SecretKey};

// ---------------------------------------------------------------- 冻结输入

const DEK: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const VAULT_UUID: &str = "11111111111111111111111111111111";
const E_INIT_PRIV: &str = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const E_RESP_PRIV: &str = "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f";
const PSK: &str = "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f";
const FRAME_NONCE: &str = "a0a1a2a3a4a5a6a7a8a9aaab";

// ---------------------------------------------------------------- 冻结输出

const SEED: &str = "21bf849cce3b2f62246098bae6adeab591b6ddf4bc80e8f68a71e3a407e16093";
const PK_B: &str = "047f6d0fa52e7f430c2ab0947c0271f241bb3ae2a853cb5025c8008131fcd79ee201ff4953a2842535094aaf8b98b4f7ce7e4c1fc500ba885a2bdfb39911993bf5";
const E_INIT_PUB: &str = "048e71ca9d7a62917be7f0db9896b47bf9b91c8b86628eed55d47fe750e65e5bcb75937f2ef48092880eaa8335c33f344c181e9de1797f239955a0bb2d56f84099";
const E_RESP_PUB: &str = "048ed57ec2b8f5e75e9192327b51e5661c87c8e5db0170721309a517fc6e1046b15481e8ae3b39d323778e451cb1efeb541e1325a7667edd877c68faf705007575";
const EE: &str = "127ad1f6c80cce916e0c123831003369ee321654c8841412456d23742d0e4c25";
const ES: &str = "73d838d2da5d0b3f70b60b9ea85ff71095582c21c9f2cfe942d4706029836e3c";
const OKM: &str = "37cda6c871a2141e6d20cff7214874cd5933937a2939065397cd2e40acd31ebe4ec75e27d834d2d34e4d0d2990409dcd1806ec0fcb7a4e5d591e3874959b3b44";
const ENC_KEY: &str = "37cda6c871a2141e6d20cff7214874cd5933937a2939065397cd2e40acd31ebe";
const MAC_KEY: &str = "4ec75e27d834d2d34e4d0d2990409dcd1806ec0fcb7a4e5d591e3874959b3b44";
const P_CONFIRM: &str = "b591b4c925e15a85a094c00e0d430933d3c091db476a4bd00c4dedf675c4e2c8";
const SIG: &str = "411040076db3a5c33e781153df25cebab4efc9560923556ec260dcade96c4cd38281271885aff8412010c49c331fbb5682a89249f6017aaab63004e94651123f";
const PLAINTEXT: &str = "01000000000000007b2274797065223a226765745f736563726574222c22726571756573745f6964223a312c22656e747279223a2264656d6f222c226669656c6473223a5b22757365726e616d65222c2270617373776f7264225d2c226f726967696e223a2268747470733a2f2f6578616d706c652e636f6d222c2267657374757265223a22616263313233227d";
const CT_TAG: &str = "7e789f2a03990e20a5f9f8ab5ec192565477852420534670a3c40b58139f46517fe00c7232273348124fa3e432d3215ac7f32d49bec482396c43f05caa7d0aea96af88db45423b1fb6a27c4d79316b2c74e673c52f7ccb9f5edc8c25d2392d0658d51745d76a27e5b38bd9c48d587589bd7132e060e4cd97ecc423c9487304d80c7f06bcccbf6f57bf5587f0fb5547fb5378bd4d632210e4838e0b59628e";
const MAC: &str = "f480c97f3927313bec96f92152e3836eed3faeda4233d5f8fe7e572d5f549a34";
/// 冻结完整帧 `nonce(12) ‖ ct_tag ‖ mac(32)`，md5（冻结帧字节）=
/// `ef82fd23434b8857f010e7fadb93c057`（2026-10-08 多字段 get_secret 契约重算）。
const FROZEN_FRAME: &str = "a0a1a2a3a4a5a6a7a8a9aaab7e789f2a03990e20a5f9f8ab5ec192565477852420534670a3c40b58139f46517fe00c7232273348124fa3e432d3215ac7f32d49bec482396c43f05caa7d0aea96af88db45423b1fb6a27c4d79316b2c74e673c52f7ccb9f5edc8c25d2392d0658d51745d76a27e5b38bd9c48d587589bd7132e060e4cd97ecc423c9487304d80c7f06bcccbf6f57bf5587f0fb5547fb5378bd4d632210e4838e0b59628ef480c97f3927313bec96f92152e3836eed3faeda4233d5f8fe7e572d5f549a34";

// ---------------------------------------------------------------- 工具

fn hx(s: &str) -> Vec<u8> {
    from_hex(s).expect("冻结 hex 合法")
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hx(s).try_into().expect("冻结长度正确")
}

/// AppMessage 无 PartialEq（含 SecretString 纪律），比较走序列化 JSON。
fn app_json(msg: &AppMessage) -> String {
    serde_json::to_string(msg).expect("序列化")
}

fn broker_key() -> SecretKey {
    SecretKey::from_slice(&arr::<32>(SEED)).expect("seed < n，直接构造")
}

fn broker_pub() -> PublicKey {
    PublicKey::from_sec1_bytes(&hx(PK_B)).expect("冻结公钥在曲线上")
}

/// 冻结帧对应的 GetSecret 请求（与 PLAINTEXT 内 JSON 一致，多字段契约）。
fn frozen_get_secret() -> AppMessage {
    AppMessage::Request(AppRequest::GetSecret {
        request_id: 1,
        entry: "demo".into(),
        fields: vec!["username".into(), "password".into()],
        origin: "https://example.com".into(),
        gesture: "abc123".into(),
    })
}

// ---------------------------------------------------------------- broker 身份（§4.2）

#[test]
fn identity_derivation_matches_frozen() {
    // 全路径：HKDF(DEK, vault_uuid, "cf/browser/v1") + 归约 mod n → 公钥 == 冻结 pk_b
    let dek: [u8; 32] = arr(DEK);
    let uuid: [u8; 16] = arr(VAULT_UUID);
    let key = derive_identity_key(&dek, &uuid).expect("身份派生");
    let pub_bytes = pub_to_sec1(&key.public_key()).expect("sec1");
    assert_eq!(hx(PK_B), pub_bytes);

    // 交叉验证：冻结 seed < n（broker_scalar == seed，不触发归约），
    // from_slice(seed) 直构公钥必须一致
    let seed_key = broker_key();
    assert_eq!(pub_to_sec1(&seed_key.public_key()).expect("sec1"), pub_bytes);
}

// ---------------------------------------------------------------- 会话密钥 KDF（§3.3）

#[test]
fn session_kdf_matches_frozen() {
    let e_init = SecretKey::from_slice(&arr::<32>(E_INIT_PRIV)).expect("ephemeral");
    let e_resp = SecretKey::from_slice(&arr::<32>(E_RESP_PRIV)).expect("ephemeral");
    let broker = broker_key();

    let e_init_pub = pub_to_sec1(&e_init.public_key()).expect("sec1");
    let e_resp_pub = pub_to_sec1(&e_resp.public_key()).expect("sec1");
    assert_eq!(hx(E_INIT_PUB), e_init_pub);
    assert_eq!(hx(E_RESP_PUB), e_resp_pub);

    let e_resp_pk = PublicKey::from_sec1_bytes(&e_resp_pub).expect("on curve");
    // broker 公钥直接取自 seed 私钥（与 broker_pub()/PK_B 一致，见身份派生测试）
    let broker_pk = broker.public_key();

    let ee = ecdh_shared(&e_init, &e_resp_pk).expect("ecdh");
    let es = ecdh_shared(&e_init, &broker_pk).expect("ecdh");
    assert_eq!(hx(EE), ee);
    assert_eq!(hx(ES), es);

    let okm = session_okm(&ee, &es, &e_init_pub, &e_resp_pub).expect("hkdf");
    assert_eq!(hx(OKM), okm.as_slice());

    let material = derive_session_key(&ee, &es, &e_init_pub, &e_resp_pub).expect("derive");
    assert_eq!(arr::<32>(ENC_KEY), material.enc_key);
    assert_eq!(arr::<32>(MAC_KEY), material.mac_key);
}

// ---------------------------------------------------------------- confirm 令牌

#[test]
fn confirm_token_matches_frozen() {
    let psk: [u8; 32] = arr(PSK);
    let okm: [u8; 64] = arr(OKM);
    let token = compute_confirm(&psk, &okm).expect("hmac");
    assert_eq!(hx(P_CONFIRM), token);

    verify_confirm(&psk, &okm, &token).expect("一致令牌应通过");
    let wrong = [0u8; 32];
    assert!(matches!(
        verify_confirm(&psk, &okm, &wrong),
        Err(CfBrowserError::AuthFailed)
    ));
}

// ---------------------------------------------------------------- msg2 身份签名

#[test]
fn handshake_signature_frozen_and_verifies() {
    let broker = broker_key();
    let e_init: [u8; 65] = arr(E_INIT_PUB);
    let e_resp: [u8; 65] = arr(E_RESP_PUB);
    let sig = sign_handshake(&broker, &e_init, &e_resp).expect("sign");
    // RFC 6979 确定性：与 Python 首算完全一致（低-s 归一两边相同）
    assert_eq!(hx(SIG), sig);

    let pk_b = broker_pub();
    verify_handshake(&pk_b, &e_init, &e_resp, &sig).expect("冻结签名验证通过");

    // 篡改被签消息 → 拒绝（签名绑定双方公钥）
    let mut tampered = e_init;
    tampered[10] ^= 0x01;
    assert!(matches!(
        verify_handshake(&pk_b, &tampered, &e_resp, &sig),
        Err(CfBrowserError::AuthFailed)
    ));
}

// ---------------------------------------------------------------- 每消息帧

#[test]
fn frame_primitives_match_frozen_and_session_decrypts() {
    let enc_key: [u8; 32] = arr(ENC_KEY);
    let mac_key: [u8; 32] = arr(MAC_KEY);
    let nonce: [u8; 12] = arr(FRAME_NONCE);
    let plaintext = hx(PLAINTEXT);

    let ct_tag = encrypt_payload(&enc_key, &nonce, &plaintext).expect("aes-gcm");
    assert_eq!(hx(CT_TAG), ct_tag);

    let mac = frame_mac(&mac_key, &nonce, &ct_tag).expect("hmac");
    assert_eq!(hx(MAC), mac);
    verify_frame_mac(&mac_key, &nonce, &ct_tag, &mac).expect("帧 MAC 一致");

    // 完整冻结帧
    let mut frame = Vec::new();
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ct_tag);
    frame.extend_from_slice(&mac);
    assert_eq!(hx(FROZEN_FRAME), frame);

    // 解密回明文
    let decrypted = decrypt_payload(&enc_key, &nonce, &ct_tag).expect("decrypt");
    assert_eq!(plaintext, decrypted);

    // 自锁：冻结载荷的 JSON == serde_json 对 frozen_get_secret() 的输出
    //（保证 Python 首算载荷与 Rust 序列化逐字节一致，字段序敏感）
    let frozen = app_json(&frozen_get_secret());
    assert_eq!(frozen.as_bytes(), &plaintext[8..]);

    // Session::decrypt 对冻结帧完整走通 → 反序列化为 GetSecret（seq=1 通过）
    let material = SessionKeyMaterial {
        enc_key,
        mac_key,
    };
    let mut session = Session::new(material);
    assert_eq!(
        app_json(&frozen_get_secret()),
        app_json(&session.decrypt(&frame).expect("session decrypt"))
    );

    // 重放：同一帧（seq=1 ≤ 已见）→ 拒绝
    assert!(matches!(
        session.decrypt(&frame),
        Err(CfBrowserError::ReplayDetected)
    ));
}

// ---------------------------------------------------------------- 完整握手

#[test]
fn handshake_roundtrip_fixed_ephemerals() {
    let broker = broker_key();
    let pk_b = broker.public_key();
    let psk: [u8; 32] = arr(PSK);
    let e_init_priv = SecretKey::from_slice(&arr::<32>(E_INIT_PRIV)).expect("ephemeral");
    let e_resp_priv = SecretKey::from_slice(&arr::<32>(E_RESP_PRIV)).expect("ephemeral");

    let (init, msg1) =
        InitiatorHandshake::new_with_ephemeral(psk, pk_b, e_init_priv).expect("init");
    let responder =
        ResponderHandshake::new_with_ephemeral(broker, psk, e_resp_priv).expect("responder");
    let (msg2, pending) = responder.on_init(&msg1).expect("on_init");
    let (msg3, mut session_i) = init.on_response(&msg2).expect("on_response");
    let mut session_r = pending.on_confirm(&msg3).expect("on_confirm");

    // 固定 ephemeral → msg3 confirm 令牌必须 == 冻结 p_confirm（全链路一致性）
    let HandshakeMessage::Confirm { p, .. } = &msg3 else {
        panic!("msg3 应为 Confirm");
    };
    assert_eq!(hx(P_CONFIRM), from_hex(p).expect("hex"));

    // 双向互通
    let req = AppMessage::Request(AppRequest::Lock);
    let enc = session_i.encrypt(&req).expect("i→r");
    assert_eq!(
        app_json(&req),
        app_json(&session_r.decrypt(&enc).expect("r 解密"))
    );

    let resp = AppMessage::Response(AppResponse::Locked);
    let enc = session_r.encrypt(&resp).expect("r→i");
    assert_eq!(
        app_json(&resp),
        app_json(&session_i.decrypt(&enc).expect("i 解密"))
    );
}

#[test]
fn handshake_roundtrip_random() {
    // 随机 ephemeral 全握手：断言双方派生一致并可双向互通
    let broker = broker_key();
    let psk: [u8; 32] = arr(PSK);
    let (init, msg1) = InitiatorHandshake::new(psk, broker.public_key()).expect("init");
    let responder = ResponderHandshake::new(broker, psk).expect("responder");
    let (msg2, pending) = responder.on_init(&msg1).expect("on_init");
    let (msg3, mut session_i) = init.on_response(&msg2).expect("on_response");
    let mut session_r = pending.on_confirm(&msg3).expect("on_confirm");

    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 1,
        entry: "demo".into(),
        fields: vec!["username".into(), "password".into()],
        origin: "https://example.com".into(),
        gesture: "abc123".into(),
    });
    let enc = session_i.encrypt(&req).expect("i→r");
    assert_eq!(
        app_json(&req),
        app_json(&session_r.decrypt(&enc).expect("r 解密"))
    );
}

#[test]
fn wrong_psk_rejected() {
    // broker 侧 PSK 与扩展不同 → msg3 确认失败，会话不建立
    let broker = broker_key();
    let good_psk: [u8; 32] = arr(PSK);
    let mut bad_psk = good_psk;
    bad_psk[0] ^= 0x01;

    let (init, msg1) =
        InitiatorHandshake::new(good_psk, broker.public_key()).expect("init");
    let responder = ResponderHandshake::new(broker, bad_psk).expect("responder");
    let (msg2, pending) = responder.on_init(&msg1).expect("on_init");
    let (msg3, _session_i) = init.on_response(&msg2).expect("init 侧正常");
    assert!(matches!(
        pending.on_confirm(&msg3),
        Err(CfBrowserError::AuthFailed)
    ));
}

#[test]
fn pinned_pubkey_mismatch_rejected() {
    // 扩展 pin 的公钥与实际 broker 不符（中间人换钥）→ on_response 拒绝
    let attacker = SecretKey::from_slice(&arr::<32>(E_RESP_PRIV)).expect("attacker 密钥");
    let victim = broker_key();
    let psk: [u8; 32] = arr(PSK);

    let (init, msg1) =
        InitiatorHandshake::new(psk, victim.public_key()).expect("init（pin 受害者）");
    let responder = ResponderHandshake::new(attacker, psk).expect("responder（攻击者）");
    let (msg2, _pending) = responder.on_init(&msg1).expect("on_init");
    assert!(matches!(
        init.on_response(&msg2),
        Err(CfBrowserError::AuthFailed)
    ));
}

// ---------------------------------------------------------------- BrokerEndpoint 骨架

#[test]
fn broker_endpoint_full_flow() {
    // 进程侧组合根路径：BrokerIdentity::derive → BrokerEndpoint → 握手 → 会话。
    // 扩展侧 pin 冻结 pk_b——BrokerIdentity::derive(DEK, VAULT_UUID) 恰产生该公钥
    // （见 identity_derivation_matches_frozen）。
    let identity =
        cf_browser::broker::BrokerIdentity::derive(&arr::<32>(DEK), &arr::<16>(VAULT_UUID))
            .expect("身份派生");
    let psk: [u8; 32] = arr(PSK);
    let endpoint = BrokerEndpoint::new(identity, psk);

    let (init, msg1) = InitiatorHandshake::new(psk, broker_pub()).expect("init");
    let (msg2, pending) = endpoint.on_init(&msg1).expect("on_init");
    let (msg3, mut session_i) = init.on_response(&msg2).expect("on_response");
    let mut session_r = pending.on_confirm(&msg3).expect("on_confirm");

    let req = AppMessage::Request(AppRequest::Lock);
    let enc = session_i.encrypt(&req).expect("i→r");
    assert_eq!(
        app_json(&req),
        app_json(&session_r.decrypt(&enc).expect("r 解密"))
    );
}
