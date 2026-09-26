//! cf-store T01 集成测试（docs/07 §7 T01 验收标准）。
//!
//! 验收点：
//! ① 11 表幂等建齐（重复打开不报错）、schema_version=1；
//! ② items / fields / urls / tags 仓库 CRUD 往返相等；
//! ③ **密文落盘断言**：数据库文件字节里找不到明文敏感值（含 WAL）；
//! ④ with_tx 内注入失败 → 全部回滚零残留；
//! ⑤ 错误统一为 `cf_domain::CfError`（错误码可查）。

use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::rows::{FieldRow, TagRow, UrlRow};
use cf_store::{ItemRow, ItemStore};
use rusqlite::Connection;

/// 唯一临时目录（进程内唯一即可，测试进程互不共享 id + 计数器）。
fn temp_db(tag: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "coffer-t01-{}-{}-{}",
        std::process::id(),
        tag,
        n
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("db.sqlite")
}

/// 把 WAL 合并回主文件，然后读取全部库文件字节（主文件 + wal + shm）。
fn db_files_bytes(db_path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    // checkpoint(TRUNCATE) 需要独立连接执行；主连接由 ItemStore 持有。
    // 打开只读连接执行 checkpoint；失败（无 WAL）不视为错误。
    let _ = Connection::open(db_path)
        .and_then(|c| c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);"));

    let mut out = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let p = std::path::PathBuf::from(format!("{}{}", db_path.display(), suffix));
        if p.exists() {
            out.push((suffix.to_owned(), std::fs::read(&p).unwrap()));
        }
    }
    out
}

/// 子串查找（避免引入额外依赖，仅测试用）。
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn subkeys() -> SubKeys {
    SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap()
}

/// 建一个文件库并写入一条"全副武装"的条目（字段 + URL + 标签 + TOTP）。
fn seeded_store(db_path: &std::path::Path) -> ItemStore {
    let conn = Connection::open(db_path).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();

    let item_uuid = uuid::Uuid::now_v7().to_string();
    let field_uuid = uuid::Uuid::now_v7().to_string();
    let url_uuid = uuid::Uuid::now_v7().to_string();
    let tag_uuid = uuid::Uuid::now_v7().to_string();
    let totp_uuid = uuid::Uuid::now_v7().to_string();

    store
        .with_tx(|r| {
            r.items.insert(
                &ItemRow {
                    uuid: item_uuid.clone(),
                    category: ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: true,
                    fav_index: 1,
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_000,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("绝密标题·GitHub"),
            )?;
            r.meta.add_item_count(1)?;

            r.fields.replace_fields_for_item(
                &item_uuid,
                &[FieldRow {
                    uuid: field_uuid.clone(),
                    item_uuid: item_uuid.clone(),
                    section_uuid: None,
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    name: "登录密码".into(),
                    value: Some("Tr0ub4dor&3-机密值".into()),
                    position: 0,
                }],
            )?;

            r.urls.replace_for_item(
                &item_uuid,
                &[UrlRow {
                    uuid: url_uuid,
                    item_uuid: item_uuid.clone(),
                    label: Some("主站".into()),
                    url: "https://github.com/coffer-secret-path".into(),
                    is_primary: true,
                    position: 0,
                }],
            )?;

            r.tags.replace_for_item(
                &item_uuid,
                &[TagRow { uuid: tag_uuid, item_uuid: item_uuid.clone(), name: "机密标签".into() }],
            )?;

            r.totp.insert_totp(
                &totp_uuid,
                &item_uuid,
                b"0123456789abcdef0123",
                "sha1",
                6,
                30,
                Some("GitHub"),
                Some("alice@example.com"),
            )?;
            Ok(())
        })
        .unwrap();
    store
}

/// ① 端到端：with_tx 写入 → 读回逐项相等；meta.item_count 一致
#[test]
fn 端到端写入读回逐项相等() {
    let db = temp_db("roundtrip");
    let store = seeded_store(&db);

    let r = store.repos();
    let listed = r
        .items
        .list(&cf_store::ItemListFilter {
            state: Some(ItemState::Active),
            category: Some(ItemCategory::Login),
            limit: None,
            offset: None,
        })
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].title.expose(), "绝密标题·GitHub");
    assert!(listed[0].row.is_favorite);

    let fields = r.fields.read_fields_for_item(&listed[0].row.uuid).unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].name.expose(), "登录密码");
    assert_eq!(fields[0].value.as_ref().unwrap().expose(), "Tr0ub4dor&3-机密值");

    let urls = r.urls.read_for_item(&listed[0].row.uuid).unwrap();
    assert_eq!(urls[0].url.expose(), "https://github.com/coffer-secret-path");
    assert_eq!(urls[0].label.as_ref().unwrap().expose(), "主站");

    let tags = r.tags.read_for_item(&listed[0].row.uuid).unwrap();
    assert_eq!(tags[0].name.expose(), "机密标签");

    let totp_uuid = r.totp.totp_uuids_for_item(&listed[0].row.uuid).unwrap()[0].clone();
    let secret = r.totp.totp_secret(&totp_uuid).unwrap().unwrap();
    assert_eq!(&secret[..], b"0123456789abcdef0123");
    let meta = r.totp.totp_meta(&totp_uuid).unwrap().unwrap();
    assert_eq!(meta.issuer.as_deref(), Some("GitHub"));
    assert_eq!(meta.account.as_deref(), Some("alice@example.com"));

    assert_eq!(r.meta.item_count().unwrap(), 1);
}

/// ③ 密文落盘：数据库文件（含 WAL）字节里找不到任何明文敏感值
#[test]
fn 数据库文件字节找不到明文敏感值() {
    let db = temp_db("ciphertext-on-disk");
    let store = seeded_store(&db);
    drop(store); // 确保写入已提交

    let files = db_files_bytes(&db);
    assert!(!files.is_empty(), "库文件必须存在");

    let secrets: Vec<(&str, Vec<u8>)> = vec![
        ("标题", "绝密标题·GitHub".as_bytes().to_vec()),
        ("字段名", "登录密码".as_bytes().to_vec()),
        ("字段值", "Tr0ub4dor&3-机密值".as_bytes().to_vec()),
        ("URL", b"github.com/coffer-secret-path".to_vec()),
        ("标签", "机密标签".as_bytes().to_vec()),
        ("TOTP密钥", b"0123456789abcdef0123".to_vec()),
        ("Issuer", b"GitHub".to_vec()),
        ("Account", b"alice@example.com".to_vec()),
    ];

    for (suffix, bytes) in &files {
        for (what, needle) in &secrets {
            assert!(
                !contains(bytes, needle),
                "明文 {what} 出现在库文件 {suffix} 中——密文落盘被破坏"
            );
        }
    }
}

/// ④ with_tx 注入失败 → 全部回滚（条目行数与 item_count 零残留）
#[test]
fn 事务注入失败零残留() {
    let db = temp_db("rollback");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();

    // 先写一条成功基线
    let seed_uuid = uuid::Uuid::now_v7().to_string();
    store
        .with_tx(|r| {
            r.items.insert(
                &ItemRow {
                    uuid: seed_uuid.clone(),
                    category: ItemCategory::Password,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 0,
                    updated_at: 0,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("基线条目"),
            )?;
            r.meta.add_item_count(1)?;
            Ok(())
        })
        .unwrap();

    // 注入失败：同一事务写两条（其一含字段）后返回 Err
    let ghost = uuid::Uuid::now_v7().to_string();
    let result: cf_store::CfStoreResult<()> = store.with_tx(|r| {
        r.items.insert(
            &ItemRow {
                uuid: ghost.clone(),
                category: ItemCategory::Login,
                state: ItemState::Active,
                is_favorite: false,
                fav_index: 0,
                created_at: 0,
                updated_at: 0,
                trashed_at: None,
                position: 0,
            },
            &SecretString::from_exposed("应当回滚"),
        )?;
        r.meta.add_item_count(1)?;
        Err(CfError::Validation("注入的失败".into()))
    });
    assert!(matches!(result, Err(CfError::Validation(_))));

    let r = store.repos();
    assert_eq!(r.items.count(None).unwrap(), 1, "只应剩基线条目");
    assert!(r.items.get_row(&ghost).unwrap().is_none(), "回滚后不得有残留");
    assert_eq!(r.meta.item_count().unwrap(), 1, "item_count 增量必须随事务回滚");
}

/// ① 重复打开幂等：第二次 open 不报错且数据完好
#[test]
fn 重复打开幂等且数据完好() {
    let db = temp_db("reopen");
    let store = seeded_store(&db);
    drop(store);

    let conn = Connection::open(&db).unwrap();
    let store2 = ItemStore::open(conn, subkeys()).unwrap(); // 幂等
    let r = store2.repos();
    assert_eq!(r.items.count(None).unwrap(), 1);
    assert_eq!(r.meta.get_i64(cf_store::KEY_SCHEMA_VERSION).unwrap(), Some(1));

    let listed = r
        .items
        .list(&cf_store::ItemListFilter::default())
        .unwrap();
    assert_eq!(listed[0].title.expose(), "绝密标题·GitHub");
}

/// ⑤ 错误统一：cf-store 对外错误就是 cf_domain::CfError（按码断言）
#[test]
fn 错误统一为cf_domain错误() {
    let db = temp_db("errors");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();

    // ItemNotFound（1011）
    let result = store.repos().items.soft_delete("not-a-real-uuid", 0);
    match result {
        Err(e) => assert_eq!(e.code(), 1011),
        Ok(()) => panic!("应当报 ItemNotFound"),
    }

    // Validation（1012）：重复插入
    let uuid1 = uuid::Uuid::now_v7().to_string();
    let (row, title) = (
        ItemRow {
            uuid: uuid1.clone(),
            category: ItemCategory::Login,
            state: ItemState::Active,
            is_favorite: false,
            fav_index: 0,
            created_at: 0,
            updated_at: 0,
            trashed_at: None,
            position: 0,
        },
        SecretString::from_exposed("t"),
    );
    store.with_tx(|r| r.items.insert(&row, &title)).unwrap();
    let dup = store.with_tx(|r| r.items.insert(&row, &title));
    match dup {
        Err(e) => assert_eq!(e.code(), 1012),
        Ok(()) => panic!("应当报 Validation"),
    }
}

/// 软删 → 恢复 → 收藏 → 硬删全生命周期（回收站语义）
#[test]
fn 条目全生命周期() {
    let db = temp_db("lifecycle");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();

    let uuid1 = uuid::Uuid::now_v7().to_string();
    let row = ItemRow {
        uuid: uuid1.clone(),
        category: ItemCategory::CreditCard,
        state: ItemState::Active,
        is_favorite: false,
        fav_index: 0,
        created_at: 0,
        updated_at: 0,
        trashed_at: None,
        position: 0,
    };
    store
        .with_tx(|r| {
            r.items.insert(&row, &SecretString::from_exposed("银行卡"))?;
            r.meta.add_item_count(1)?;
            Ok(())
        })
        .unwrap();

    // 回收站
    store.repos().items.soft_delete(&uuid1, 42).unwrap();
    let r = store.repos();
    let got = r.items.get_row(&uuid1).unwrap().unwrap();
    assert_eq!(got.state, ItemState::Trashed);
    let trashed = r
        .items
        .list(&cf_store::ItemListFilter { state: Some(ItemState::Trashed), ..Default::default() })
        .unwrap();
    assert_eq!(trashed.len(), 1);

    // 恢复 + 收藏
    store.repos().items.restore(&uuid1).unwrap();
    store.repos().items.set_favorite(&uuid1, true).unwrap();
    let got = store.repos().items.get_row(&uuid1).unwrap().unwrap();
    assert_eq!(got.state, ItemState::Active);
    assert!(got.is_favorite);

    // 硬删：级联清场 + 计数递减
    store
        .with_tx(|r| {
            r.items.delete_hard(&uuid1)?;
            r.meta.add_item_count(-1)?;
            Ok(())
        })
        .unwrap();
    let r = store.repos();
    assert_eq!(r.items.count(None).unwrap(), 0);
    assert_eq!(r.meta.item_count().unwrap(), 0);
}
