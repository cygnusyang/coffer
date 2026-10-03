//! Passkey 会话门面测试（FR-10.2 / FR-10.5，docs/17 §4.1 PK1，v0.5.0）。
//!
//! 分两层：
//! - **用例编排层**（`usecase::passkeys`，内存库 + 自备子密钥）：列出 /
//!   删除回环逐字段、1011 / 1005 负路径——`add` 无会话门面（唯一来源
//!   是导入编排 PK2，docs/17 §4.1），故种子数据经 `repos.passkeys.add`
//!   在事务内写入（内核冻结用法）；
//! - **会话门禁层**（真实建库 / 解锁，`VaultSession`）：锁定态 1001、
//!   条目不存在 1011、损坏行 1005（直连 db.sqlite 注入坏密文行——加密
//!   列对测试是不透明字节，FK 由既有条目行满足）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cf_crypto::kdf::KdfParams;
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::usecase::passkeys;
use cf_session::VaultSession;
use cf_store::{ItemRow, ItemStore, PasskeyRecord, COSE_ALG_ES256};
use rusqlite::Connection;

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG: &str = "correct-horse-battery-staple-42!";

/// 测试用快速 KDF 档位（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 内存库 + 固定子密钥（用例编排层 fixture，docs/10 §0.4）。
fn memory_store() -> ItemStore {
    let conn = Connection::open_in_memory().unwrap();
    let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    ItemStore::open(conn, subkeys).unwrap()
}

/// 直接插一个 Active 条目行（编排层测试不经过 validate）。
fn host_item(store: &ItemStore, uuid: &str) {
    store
        .repos()
        .items
        .insert(
            &ItemRow {
                uuid: uuid.to_owned(),
                category: ItemCategory::Login,
                state: ItemState::Active,
                is_favorite: false,
                fav_index: 0,
                created_at: 1_000,
                updated_at: 1_000,
                trashed_at: None,
                position: 0,
            },
            &SecretString::from_exposed("GitHub 登录"),
        )
        .unwrap();
}

fn item_uuid(seed: u8) -> String {
    uuid::Uuid::from_bytes([seed; 16]).to_string()
}

/// 合法 ES256 记录。
fn record(rp_id: &str) -> PasskeyRecord {
    PasskeyRecord {
        rp_id: rp_id.to_owned(),
        rp_name: Some("GitHub".to_owned()),
        user_name: Some("alice@example.com".to_owned()),
        user_handle: vec![0xA1, 0xB2],
        credential_id: vec![0x01, 0x02, 0x03],
        private_key_pkcs8: vec![0x30, 0x82, 0x01, 0x20],
        algorithm: COSE_ALG_ES256,
        sign_count: 3,
    }
}

/// 在事务内写一条 passkey（内核冻结用法：调用方包在 with_tx 内）。
fn seed_passkey(store: &mut ItemStore, item: &str, rp_id: &str, now: i64) -> String {
    store
        .with_tx(|repos| repos.passkeys.add(item, &record(rp_id), now))
        .unwrap()
}

/// 唯一临时目录（pid + 进程内原子计数器，测试间零共享）。
fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "cf-session-passkey-{tag}-{}-{seq}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库并解锁。
fn unlocked_vault(base: &Path, tag: &str) -> VaultSession {
    let brief = create_vault_with_kdf(base, tag, STRONG, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    session.unlock(STRONG).unwrap();
    session
}

/// 最小 Login 草稿（编排测试只关心条目行存在）。
fn minimal_draft(title: &str) -> cf_domain::item::ItemDraft {
    cf_domain::item::ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields: vec![
            cf_domain::item::FieldDraft {
                name: "用户名".to_owned(),
                value: Some("alice@example.com".to_owned()),
                field_type: cf_domain::field::FieldType::Text,
                designation: Some(cf_domain::field::Designation::Username),
                section_index: None,
                position: 0,
            },
            cf_domain::item::FieldDraft {
                name: "密码".to_owned(),
                value: Some("hunter2-secret".to_owned()),
                field_type: cf_domain::field::FieldType::Concealed,
                designation: Some(cf_domain::field::Designation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

// ------------------------------------------------ 用例编排层：列出 / 删除回环

/// 列出：逐字段相等 + created_at 升序 + 无私钥字段（FR-10.2 红线：
/// PasskeyMeta 字段集固定为 rpId / 用户名 / 创建时间 / 计数器 / 凭据 ID
/// 等元数据，编译期即不存在私钥数据源）。
#[test]
fn 列出passkey元数据逐字段相等且有序() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    let p1 = seed_passkey(&mut store, &item_uuid(1), "github.com", 2_000);
    let p2 = seed_passkey(&mut store, &item_uuid(1), "gitlab.com", 3_000);

    let metas = passkeys::list_passkeys(&store, &item_uuid(1)).unwrap();
    assert_eq!(metas.len(), 2);
    assert_eq!(metas[0].uuid, p1, "created_at 升序");
    assert_eq!(metas[1].uuid, p2);
    assert_eq!(metas[0].rp_id, "github.com");
    assert_eq!(metas[0].item_uuid, item_uuid(1));
    assert_eq!(metas[0].sign_count, 3);
    assert_eq!(metas[0].created_at, 2_000);
    assert!(metas[0].last_used_at.is_none());
}

/// FR-10.2 红线（可断言接口面）：`PasskeyMeta` 只含文档化元数据字段——
/// 以编译期穷尽构造钉住字段集，多一个私钥字段即编译失败。
#[test]
fn 元数据字段集钉住无私钥() {
    let m = cf_store::PasskeyMeta {
        uuid: "u".to_owned(),
        item_uuid: "i".to_owned(),
        rp_id: "github.com".to_owned(),
        rp_name: None,
        user_name: None,
        credential_id_b64: "AQID".to_owned(),
        algorithm: COSE_ALG_ES256,
        sign_count: 0,
        created_at: 1,
        last_used_at: None,
    };
    let cf_store::PasskeyMeta {
        uuid,
        item_uuid,
        rp_id,
        rp_name,
        user_name,
        credential_id_b64,
        algorithm: _,
        sign_count: _,
        created_at: _,
        last_used_at: _,
    } = m;
    assert_eq!(uuid, "u");
    assert_eq!(item_uuid, "i");
    assert_eq!(rp_id, "github.com");
    assert!(rp_name.is_none());
    assert!(user_name.is_none());
    assert_eq!(credential_id_b64, "AQID");
}

/// 条目不存在 → 1011。
#[test]
fn 条目不存在时列出报条目不存在() {
    let store = memory_store();
    let err = passkeys::list_passkeys(&store, &item_uuid(9)).unwrap_err();
    assert_eq!(err.code(), 1011, "条目不存在应报 ItemNotFound：{err:?}");
}

/// 删除：行消失；再次删除 → 1011。
#[test]
fn 删除passkey后行消失且再删报不存在() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    let p1 = seed_passkey(&mut store, &item_uuid(1), "github.com", 2_000);

    passkeys::remove_passkey(&mut store, &p1).unwrap();
    assert!(passkeys::list_passkeys(&store, &item_uuid(1))
        .unwrap()
        .is_empty());

    let err = passkeys::remove_passkey(&mut store, &p1).unwrap_err();
    assert_eq!(err.code(), 1011, "行不存在应报 ItemNotFound：{err:?}");
}

/// 损坏行 → 1005（Corrupted，解密失败不区分原因）。
#[test]
fn 损坏密文行报损坏() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    seed_passkey(&mut store, &item_uuid(1), "github.com", 2_000);

    store
        .connection()
        .execute("UPDATE passkeys SET enc_rp_id = x'0001020304'", [])
        .unwrap();

    let err = passkeys::list_passkeys(&store, &item_uuid(1)).unwrap_err();
    assert_eq!(err.code(), 1005, "密文损坏应报 Corrupted：{err:?}");
}

// ------------------------------------------------ 会话门禁层（真实建库 / 解锁）

/// 锁定态两方法全部 1001。
#[test]
fn 锁定态passkey操作全部拒绝() {
    let base = temp_dir("locked");
    let brief = create_vault_with_kdf(&base, "锁定passkey库", STRONG, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

    assert_eq!(session.list_passkeys("no-item").unwrap_err().code(), 1001);
    assert_eq!(session.remove_passkey("no-uuid").unwrap_err().code(), 1001);
}

/// 解锁态：条目不存在 list → 1011；passkey 行不存在 remove → 1011。
#[test]
fn 解锁态不存在路径报条目不存在() {
    let base = temp_dir("no_item");
    let session = unlocked_vault(&base, "无条目passkey库");

    let err = session
        .list_passkeys("00000000-0000-0000-0000-000000000000")
        .unwrap_err();
    assert_eq!(err.code(), 1011, "{err:?}");
    let err = session.remove_passkey("no-such-passkey").unwrap_err();
    assert_eq!(err.code(), 1011, "{err:?}");
}

/// 损坏行（会话层）：直连 db.sqlite 注入坏密文 passkey 行（FK 由既有
/// 条目满足）→ list → 1005；条目硬删 → 行级联消失；软删 → 行保留。
#[test]
fn 会话层级联与损坏行语义() {
    let base = temp_dir("cascade");
    let session = unlocked_vault(&base, "级联passkey库");
    let item_id = session.create_item(&minimal_draft("级联条目")).unwrap();
    let vault_dir = session.vault_dir().to_path_buf();
    let db_path = vault_dir.join("db.sqlite");

    // 注入坏密文行（加密列对测试是不透明字节；schema 明文可直插）
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO passkeys
                (uuid, item_uuid, enc_rp_id, enc_user_handle, enc_credential_id,
                 enc_private_key, algorithm, sign_count, created_at, rp_id_hmac)
             VALUES ('pk-inject-1', ?1, x'00', x'00', x'00', x'00', -7, 0, 1, x'00')",
            rusqlite::params![item_id],
        )
        .unwrap();
    }

    // 解锁态读该行 → 1005（坏密文）
    let err = session.list_passkeys(&item_id).unwrap_err();
    assert_eq!(err.code(), 1005, "注入的坏密文行应报 Corrupted：{err:?}");

    // 软删：行保留
    session.delete_item(&item_id, false).unwrap();
    {
        let conn = Connection::open(&db_path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM passkeys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "软删不得级联删除 passkey 行");
    }

    // 恢复 → 硬删：级联消失
    session.restore_item(&item_id).unwrap();
    session.delete_item(&item_id, true).unwrap();
    {
        let conn = Connection::open(&db_path).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM passkeys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "条目硬删必须级联删除 passkey 行");
    }
}
