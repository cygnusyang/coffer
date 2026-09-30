//! v0.5 FFI 语义测试（Passkey FR-10.2/10.5 / Bitwarden 预检 FR-10.1，
//! docs/17 r2.2 §4.3 / §5）。
//!
//! 聚焦跨 FFI 的契约与错误码，与 cf-session / cf-importer 层单测互补：
//!
//! 1. **Passkey**：锁定态 1001；条目不存在 1011；行不存在 1011；
//!    损坏行两级口径——密文短于 nonce+tag → 1005 Corrupted /
//!    AEAD 校验不过 → 1008 CryptoError（docs/17 r2.2 §5，勿按单一 1005）；
//! 2. **Bitwarden 预检**：预检无解锁门禁（预检不触密钥，与 1PUX 同语义）；
//!    计数字段 + 非 ES256 显式列表跨 FFI；非 JSON → 2001。
//!
//! 损坏行注入方式：`db.sqlite` 是明文 SQLite + 逐列 AEAD（passkeys 表
//! 的 `enc_*` BLOB 为密文列），测试用 rusqlite 直接 INSERT 畸形密文行
//! （1005 = 过短；1008 = 等长篡改），经 FFI list_passkeys 触发解密路径。
//!
//! 测试约定与 `v04_ffi_semantics.rs` 一致：每测试独立临时目录；快速
//! KDF 建库；FFI 入口一律走公开 API。错误码契约零扩展（docs/17 §5）。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_ffi::api::{CofferApp, VaultSession};
use cf_ffi::types::*;

/// 提取错误码。
fn err_code<T>(r: Result<T, cf_ffi::FfiError>) -> u16 {
    match r {
        Ok(_) => panic!("预期应返回错误，实际成功"),
        Err(e) => e.code(),
    }
}

/// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

/// 每测试独立的临时工作目录。
fn temp_base(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-ffi-v05-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &std::path::Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 建库 → 打开 → 解锁，返回 FFI 会话。
fn unlocked_session(
    base: &std::path::Path,
    name: &str,
) -> (cf_domain::vault::Vault, Arc<VaultSession>) {
    let brief = setup_vault(base, name);
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    (brief, session)
}

/// 最小合法登录条目（与 v04_ffi_semantics.rs 同款，无 TOTP）。
fn login_draft(title: &str) -> FfiItemDraft {
    FfiItemDraft {
        title: title.to_owned(),
        category: FfiItemCategory::Login,
        urls: Vec::new(),
        tags: Vec::new(),
        sections: Vec::new(),
        fields: vec![
            FfiFieldDraft {
                name: "用户名".to_owned(),
                value: Some("qa-user".to_owned()),
                field_type: FfiFieldType::Text,
                designation: Some(FfiDesignation::Username),
                section_index: None,
                position: 0,
            },
            FfiFieldDraft {
                name: "密码".to_owned(),
                value: Some("p@ssw0rd-42!".to_owned()),
                field_type: FfiFieldType::Concealed,
                designation: Some(FfiDesignation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

/// 向 db.sqlite 直接 INSERT 一条畸形密文 passkey 行（FFI 测试专用的
/// 损坏注入；`enc_rp_id` 列承载畸形密文，其余密文列给合法长度的废料）。
fn insert_corrupt_passkey_row(
    vault_dir: &std::path::Path,
    item_uuid: &str,
    passkey_uuid: &str,
    enc_rp_id: &[u8],
    created_at: i64,
) {
    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO passkeys
            (uuid, item_uuid, enc_rp_id, enc_rp_name, enc_user_name,
             enc_user_handle, enc_credential_id, enc_private_key,
             enc_public_key, algorithm, sign_count, created_at,
             last_used_at, rp_id_hmac)
         VALUES (?1, ?2, ?3, NULL, NULL, ?4, ?5, ?6, NULL, -7, 0, ?7, NULL, ?8)",
        rusqlite::params![
            passkey_uuid,
            item_uuid,
            enc_rp_id,
            vec![0u8; 40], // enc_user_handle：合法长度废料（不被 list 解密）
            vec![0u8; 40], // enc_credential_id：同上
            vec![0u8; 40], // enc_private_key：同上（本版无私钥读路径）
            created_at,
            vec![0u8; 32], // rp_id_hmac：HMAC-SHA256 长度
        ],
    )
    .unwrap();
}

// ------------------------------------------------ Passkey（FR-10.2 / 10.5）

/// 锁定态 list / remove → 1001（门禁在 Rust 侧强制，docs/17 §5）。
#[test]
fn passkey锁定态list与remove返回1001() {
    let base = temp_base("pk_locked");
    let (_brief, session) = unlocked_session(&base, "passkey锁定库");
    let item_id = session.create_item(login_draft("GitHub")).unwrap();
    session.lock();

    assert_eq!(err_code(session.list_passkeys(item_id)), 1001);
    assert_eq!(
        err_code(session.remove_passkey("01940000-0000-7000-8000-000000000000".to_owned())),
        1001
    );
}

/// list：条目不存在 → 1011（存在性门禁由会话层承担）。
#[test]
fn passkeylist条目不存在返回1011() {
    let base = temp_base("pk_no_item");
    let (_brief, session) = unlocked_session(&base, "passkey无条目库");

    assert_eq!(
        err_code(session.list_passkeys("no-such-item".to_owned())),
        1011
    );
}

/// remove：行不存在 → 1011（items 仓库「影响行数为 0 → ItemNotFound」同款）。
#[test]
fn passkeyremove行不存在返回1011() {
    let base = temp_base("pk_no_row");
    let (_brief, session) = unlocked_session(&base, "passkey无行库");

    assert_eq!(
        err_code(session.remove_passkey("01940000-0000-7000-8000-000000000000".to_owned())),
        1011
    );
}

/// 损坏行两级口径（docs/17 r2.2 §5）：密文短于 nonce+tag → 1005
/// Corrupted；等长密文 AEAD 校验不过（篡改/跨行搬运形态）→ 1008
/// CryptoError。两级都经 FFI list_passkeys 钉住。
#[test]
fn passkey损坏行两级口径1005与1008() {
    let base = temp_base("pk_corrupt");
    let (_brief, session) = unlocked_session(&base, "passkey损坏库");
    let item_id = session.create_item(login_draft("GitHub")).unwrap();
    let vault_dir = std::path::PathBuf::from(session.vault_dir());

    // 行 uuid 必须是合法 UUID：field_aad 以行 uuid 参与 AAD 构造，
    // 非法 uuid 在 AEAD 之前就报 1005，会掩盖本测试的两级口径
    // 行 1：enc_rp_id 短于 nonce+tag（XChaCha20 24B nonce + 16B tag = 40B）
    //      → 结构性损坏 1005
    insert_corrupt_passkey_row(
        &vault_dir,
        &item_id,
        "01960000-0000-7000-8000-0000000000a1",
        b"ab",
        1_000,
    );
    // 行 2：enc_rp_id 等长（40B）废料 → AEAD 校验不过 1008
    insert_corrupt_passkey_row(
        &vault_dir,
        &item_id,
        "01960000-0000-7000-8000-0000000000a2",
        &[0u8; 40],
        2_000,
    );

    // created_at 升序先命中行 1 → 1005
    assert_eq!(err_code(session.list_passkeys(item_id.clone())), 1005);

    // 移除行 1 后行 2 命中 AEAD 失败 → 1008
    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).unwrap();
    conn.execute(
        "DELETE FROM passkeys WHERE uuid = '01960000-0000-7000-8000-0000000000a1'",
        [],
    )
    .unwrap();
    assert_eq!(err_code(session.list_passkeys(item_id.clone())), 1008);

    // 清空损坏行后恢复空列表（损坏只影响解密行，不毒化会话）
    conn.execute(
        "DELETE FROM passkeys WHERE uuid = '01960000-0000-7000-8000-0000000000a2'",
        [],
    )
    .unwrap();
    assert!(session.list_passkeys(item_id).unwrap().is_empty());
}

// ------------------------------------------ Bitwarden 预检（FR-10.1）

/// 预检报告跨 FFI：计数 + 非 ES256 显式列表（index usize→u32 不跨桥）。
/// 预检无解锁门禁（预检不触密钥，与 1PUX 预检同语义）。
#[test]
fn bw预检报告跨ffi计数与非es256列表() {
    let base = temp_base("bw_precheck");
    let (_brief, session) = unlocked_session(&base, "bw预检库");

    // 1 条含密码+passkey 的条目（合法 ES256 行）+ 1 条非 ES256 行
    let json = r#"{"encrypted":false,"folders":[],"items":[
        {"id":"bw-1","type":1,"name":"Example Site",
         "login":{"username":"alice","password":"pw-1","uris":[],
           "fido2Credentials":[{
             "credentialId":"Y3JlZC1pZC0x","keyType":"public-key",
             "keyAlgorithm":"ecdsa","keyCurve":"p256","rpId":"example.com",
             "rpName":"Example","userHandle":"dXNlci0x","userName":"alice",
             "counter":3,"discoverable":true,
             "creationDate":"2026-08-01T12:30:00.000Z",
             "encryptedPrivateKey":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH1THtN9Yr04dr25YaOOECBiQSeZzztzz7gTfoKjZM0KhRANCAATJw2TFOn57PJ2qnEE5fkNqv+riQosBDzm3JeP1H9tVxVdCrzzBIu58KOXRc9gTX50LkGHG2XDfX+vgmt/Wv4dK"}]},
         "creationDate":"2026-08-01T12:00:00.000Z","revisionDate":"2026-08-15T09:00:00.000Z"},
        {"id":"bw-2","type":1,"name":"Ed25519 Site",
         "login":{"username":"bob","password":"pw-2","uris":[],
           "fido2Credentials":[{
             "credentialId":"Y3JlZC1pZC0y","keyType":"public-key",
             "keyAlgorithm":"eddsa","keyCurve":"ed25519","rpId":"ed.example.com",
             "userHandle":"dXNlci0y","userName":"bob",
             "counter":0,"discoverable":false,
             "creationDate":"2026-08-01T12:30:00.000Z",
             "encryptedPrivateKey":"AAAA"}]},
         "creationDate":"2026-08-01T12:00:00.000Z","revisionDate":"2026-08-15T09:00:00.000Z"}
    ]}"#;
    let path = base.join("bw_export.json");
    std::fs::write(&path, json).unwrap();

    // 锁定态预检可执行（预检不触密钥）——先锁再调
    session.lock();
    let report = session.precheck_bitwarden_json(path.to_string_lossy().into_owned()).unwrap();

    assert_eq!(report.total_items, 2);
    assert_eq!(report.importable_items, 2);
    assert_eq!(report.passkey_total, 2);
    assert_eq!(report.passkey_importable, 1);
    assert_eq!(report.passkey_item_count, 1);
    assert_eq!(report.items_with_password_and_passkey, 1, "FR-10.6 证据计数");
    assert_eq!(report.non_es256.len(), 1, "非 ES256 显式列表（TCB-7）");
    assert_eq!(report.non_es256[0].item_id, "bw-2");
    assert_eq!(report.non_es256[0].index, 0);
    assert!(report.bad_passkeys.is_empty());
}

/// 非 JSON 文件 → 2001（格式不识别，跨 FFI）。
#[test]
fn bw预检非json返回2001() {
    let base = temp_base("bw_not_json");
    let (_brief, session) = unlocked_session(&base, "bw坏文件库");

    let path = base.join("not_json.json");
    std::fs::write(&path, b"this is not json").unwrap();
    assert_eq!(
        err_code(session.precheck_bitwarden_json(path.to_string_lossy().into_owned())),
        2001
    );
}

// ------------------------------------------ Bitwarden 导入（FR-10.1）

/// 最小合法 Bitwarden 导出（1 条含密码 + 合法 ES256 passkey 的条目；
/// 字段形态对齐 cf-importer tests/fixtures/bitwarden 合成样本体裁，
/// 全部合成数据）。`Y3JlZC1pZC0x` = base64("cred-id-1")。
fn bw_sample_json() -> &'static str {
    r#"{"encrypted":false,"folders":[],"items":[
        {"id":"bw-item-1","type":1,"name":"Example Site",
         "login":{"uris":[{"match":null,"uri":"https://example.com/login"}],
           "username":"alice@example.com","password":"P@ssw0rd-逐字节","totp":null,
           "fido2Credentials":[{
             "credentialId":"Y3JlZC1pZC0x","keyType":"public-key",
             "keyAlgorithm":"ecdsa","keyCurve":"p256","rpId":"example.com",
             "rpName":"Example","userHandle":"dXNlci1oYW5kbGUtMQ",
             "userName":"alice@example.com","userDisplayName":"alice@example.com",
             "counter":3,"discoverable":true,
             "creationDate":"2026-08-01T12:30:00.000Z",
             "encryptedPrivateKey":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgH1THtN9Yr04dr25YaOOECBiQSeZzztzz7gTfoKjZM0KhRANCAATJw2TFOn57PJ2qnEE5fkNqv+riQosBDzm3JeP1H9tVxVdCrzzBIu58KOXRc9gTX50LkGHG2XDfX+vgmt/Wv4dK"}]},
         "creationDate":"2026-08-01T12:00:00.000Z",
         "revisionDate":"2026-08-15T09:00:00.000Z"}
    ]}"#
}

/// 导入 → list → remove 端到端回环（docs/17 §4.3 PW 验收主路径）：
/// 结果计数跨 FFI → 元数据逐字段一致（无私钥字段）→ 密码字段逐字节
/// （D-6）→ 删除后行消失（再删 → 1011）。
#[test]
fn bw导入list删除端到端回环() {
    let base = temp_base("bw_import");
    let (_brief, session) = unlocked_session(&base, "bw导入库");

    let path = base.join("bw_export.json");
    std::fs::write(&path, bw_sample_json()).unwrap();

    // 导入（1001 门禁在解锁态可达）：结果计数与报告所见即所得
    let result = session
        .import_bitwarden_json(path.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(result.imported_items, 1);
    assert_eq!(result.report.passkey_total, 1);
    assert_eq!(result.report.passkey_importable, 1);
    assert_eq!(result.report.items_with_password_and_passkey, 1, "FR-10.6 证据");
    assert!(result.report.non_es256.is_empty());
    assert!(result.report.bad_passkeys.is_empty());

    // 以标题定位新条目（导入固定「全部新建 UUIDv7」）
    let items = session.list_items(None).unwrap();
    assert_eq!(items.len(), 1);
    let item_id = items[0].uuid.clone();

    // list_passkeys：元数据逐字段一致（无私钥字段可断言——结构上不存在）
    let metas = session.list_passkeys(item_id.clone()).unwrap();
    assert_eq!(metas.len(), 1);
    let pk = &metas[0];
    assert_eq!(pk.item_uuid, item_id);
    assert_eq!(pk.rp_id, "example.com");
    assert_eq!(pk.rp_name.as_deref(), Some("Example"));
    assert_eq!(pk.user_name.as_deref(), Some("alice@example.com"));
    assert_eq!(pk.credential_id_b64, "Y3JlZC1pZC0x", "凭据 ID base64 往返");
    assert_eq!(pk.algorithm, -7, "ES256");
    assert_eq!(pk.sign_count, 3);
    assert!(pk.created_at > 0);
    assert_eq!(pk.last_used_at, None, "本版无断言路径，恒 None");

    // D-6：含 passkey 的条目照常携带密码字段入库（逐字节口径）
    let details = session.get_item(item_id.clone()).unwrap().unwrap();
    let password_field = details
        .fields
        .iter()
        .find(|f| f.field_type == FfiFieldType::Concealed)
        .unwrap();
    assert_eq!(
        session
            .get_field_value(item_id.clone(), password_field.uuid.clone())
            .unwrap()
            .as_deref(),
        Some("P@ssw0rd-逐字节")
    );

    // remove → 行消失；再删 → 1011
    session.remove_passkey(pk.passkey_uuid.clone()).unwrap();
    assert!(session.list_passkeys(item_id.clone()).unwrap().is_empty());
    assert_eq!(err_code(session.remove_passkey(pk.passkey_uuid.clone())), 1011);
}

/// 锁定态导入 → 1001（导入有解锁门禁，与预检的无门禁形成对照）。
#[test]
fn bw导入锁定态返回1001() {
    let base = temp_base("bw_import_locked");
    let (_brief, session) = unlocked_session(&base, "bw锁定导入库");

    let path = base.join("bw_export.json");
    std::fs::write(&path, bw_sample_json()).unwrap();
    session.lock();

    assert_eq!(
        err_code(session.import_bitwarden_json(path.to_string_lossy().into_owned())),
        1001
    );
    // 1001 拒绝发生在任何写路径之前：解锁后目标库仍为空
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    assert_eq!(session.list_items(None).unwrap().len(), 0, "目标库零写入");
}
