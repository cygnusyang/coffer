//! cf-store T01 对抗性验证（QA 独立测试，不依赖工程师自测）。
//!
//! 覆盖六条工程测试未覆盖的路径：
//! 1. 畸形库文件（截断 / 密文翻字节 / schema_version 篡改 / 密文跨行跨列搬运）
//! 2. 事务边界（with_tx 内 panic、嵌套事务、WAL 多连接并发）
//! 3. 外键与级联（PRAGMA 每连接独立性、全从表级联、FK 强制）
//! 4. item_count 漂移（绕过仓库直插后的行为）
//! 5. 加密正确性（nonce 唯一性、AAD 钉死的边界）
//! 6. schema 幂等（连续/并发 open、meta 行损坏）
//!
//! 部分用例是**行为记录**（注释标明"记录现状"）：它们断言当前实现行为，
//! 若行为本身是缺陷，缺陷报告另行输出，测试先行钉死基线。

use cf_crypto::aead::SessionKey;
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::error::RusqliteResultExt;
use cf_store::rows::{FieldRow, TagRow};
use cf_store::{ItemRow, ItemStore, MetaRepo, TotpStore, KEY_SCHEMA_VERSION};
use rusqlite::Connection;

// ---------------------------------------------------------------- helpers

fn temp_db(tag: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "coffer-qa-{}-{}-{}",
        std::process::id(),
        tag,
        n
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("db.sqlite")
}

fn subkeys() -> SubKeys {
    SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap()
}

fn item_row(uuid: &str) -> ItemRow {
    ItemRow {
        uuid: uuid.to_owned(),
        category: ItemCategory::Login,
        state: ItemState::Active,
        is_favorite: false,
        fav_index: 0,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        trashed_at: None,
        position: 0,
    }
}

/// 建一个文件库，写入 1 个条目（标题 + 1 字段）。
fn seeded_store(db_path: &std::path::Path) -> (ItemStore, String, String) {
    let conn = Connection::open(db_path).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();
    let item_uuid = uuid::Uuid::now_v7().to_string();
    let field_uuid = uuid::Uuid::now_v7().to_string();
    store
        .with_tx(|r| {
            r.items.insert(&item_row(&item_uuid), &SecretString::from_exposed("绝密标题甲"))?;
            r.fields.replace_fields_for_item(
                &item_uuid,
                &[FieldRow {
                    uuid: field_uuid.clone(),
                    item_uuid: item_uuid.clone(),
                    section_uuid: None,
                    field_type: cf_domain::field::FieldType::Concealed,
                    designation: Some(cf_domain::field::Designation::Password),
                    name: "机密字段名甲".into(),
                    value: Some("机密字段值乙".into()),
                    position: 0,
                }],
            )?;
            Ok(())
        })
        .unwrap();
    (store, item_uuid, field_uuid)
}

/// 把 WAL 合并回主文件（独立连接执行 checkpoint）。
fn checkpoint(db_path: &std::path::Path) {
    let _ = Connection::open(db_path)
        .and_then(|c| c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);"));
}

// ------------------------------------------------ 1. 对抗性路径：畸形库文件

/// 截断的 db.sqlite（< 100 字节 SQLite 头）→ 结构化错误，绝不 panic
#[test]
fn 截断库文件打开返回结构化错误() {
    let db = temp_db("truncated");
    {
        let (store, _, _) = seeded_store(&db);
        drop(store);
    }
    checkpoint(&db);

    let size = std::fs::metadata(&db).unwrap().len();
    assert!(size > 100, "种子库应远大于 SQLite 头（实际 {size} 字节）");

    let mut bytes = std::fs::read(&db).unwrap();
    bytes.truncate(40); // 破坏文件头
    std::fs::write(&db, bytes).unwrap();

    let conn = Connection::open(&db).unwrap();
    match ItemStore::open(conn, subkeys()) {
        Err(CfError::StorageError(_)) => { /* 结构化错误，符合预期 */ }
        Err(other) => panic!("期望 StorageError，实际 {other:?}"),
        Ok(_) => panic!("截断库必须拒绝打开"),
    }
}

/// 密文 BLOB 被翻转字节 → 读路径返回 CryptoError（结构化、不 panic、不静默出错数据）
#[test]
fn 密文翻转字节读取返回加密错误() {
    let db = temp_db("flip-byte");
    let (store, item_uuid, field_uuid) = seeded_store(&db);
    let conn = store.connection();

    // ① 翻转 enc_title 末字节（tag 区）
    let mut ct: Vec<u8> = conn
        .query_row(
            "SELECT enc_title FROM items WHERE uuid=?1",
            rusqlite::params![item_uuid],
            |r| r.get(0),
        )
        .unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    conn.execute(
        "UPDATE items SET enc_title=?1 WHERE uuid=?2",
        rusqlite::params![ct, item_uuid],
    )
    .unwrap();
    assert!(matches!(
        store.repos().items.get(&item_uuid),
        Err(CfError::CryptoError)
    ));

    // ② 翻转 fields.enc_value 首字节（nonce 区）
    let mut fv: Vec<u8> = conn
        .query_row(
            "SELECT enc_value FROM fields WHERE uuid=?1",
            rusqlite::params![field_uuid],
            |r| r.get(0),
        )
        .unwrap();
    fv[0] ^= 0x80;
    conn.execute(
        "UPDATE fields SET enc_value=?1 WHERE uuid=?2",
        rusqlite::params![fv, field_uuid],
    )
    .unwrap();
    assert!(matches!(
        store.repos().fields.read_fields_for_item(&item_uuid),
        Err(CfError::CryptoError)
    ));
}

/// schema_version 被改成 2（未来版本库）→ 打开返回 UnsupportedFormat(2)
#[test]
fn 高版本库打开返回不支持格式错误() {
    let db = temp_db("version-2");
    {
        let (store, _, _) = seeded_store(&db);
        drop(store);
    }
    checkpoint(&db);

    {
        let conn = Connection::open(&db).unwrap();
        MetaRepo::new(&conn)
            .set_i64(KEY_SCHEMA_VERSION, 2)
            .unwrap();
    }

    let conn = Connection::open(&db).unwrap();
    match ItemStore::open(conn, subkeys()) {
        Err(CfError::UnsupportedFormat(2)) => { /* 符合预期 */ }
        Err(other) => panic!("期望 UnsupportedFormat(2)，实际 {other:?}"),
        Ok(_) => panic!("高版本库必须拒绝打开"),
    }
}

/// 密文跨列搬运（同一行的 enc_name 密文塞进 enc_value 列）→ 解密失败
#[test]
fn 密文跨列搬运解密失败() {
    let db = temp_db("cross-column");
    let (store, item_uuid, field_uuid) = seeded_store(&db);

    store
        .connection()
        .execute(
            "UPDATE fields SET enc_value=(SELECT enc_name FROM fields WHERE uuid=?1) WHERE uuid=?1",
            rusqlite::params![field_uuid],
        )
        .unwrap();

    assert!(matches!(
        store.repos().fields.read_fields_for_item(&item_uuid),
        Err(CfError::CryptoError)
    ));
}

/// 同一明文两次写入 → 密文不同（nonce 唯一性，存储层验证）
#[test]
fn 同明文两次写入密文不同() {
    let db = temp_db("nonce-unique");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();

    let a = uuid::Uuid::now_v7().to_string();
    let b = uuid::Uuid::now_v7().to_string();
    store
        .with_tx(|r| {
            r.items.insert(&item_row(&a), &SecretString::from_exposed("相同标题"))?;
            r.items.insert(&item_row(&b), &SecretString::from_exposed("相同标题"))?;
            Ok(())
        })
        .unwrap();

    let ca: Vec<u8> = store
        .connection()
        .query_row("SELECT enc_title FROM items WHERE uuid=?1", rusqlite::params![a], |r| r.get(0))
        .unwrap();
    let cb: Vec<u8> = store
        .connection()
        .query_row("SELECT enc_title FROM items WHERE uuid=?1", rusqlite::params![b], |r| r.get(0))
        .unwrap();
    assert_ne!(ca, cb, "同明文密文相同 ⇒ nonce 复用，致命");
    assert_ne!(&ca[..24], &cb[..24], "nonce 段必须不同");
}

// ------------------------------------------------ 2. 事务边界

/// with_tx 闭包 panic（非 Err）→ unwind 期间 Transaction drop 回滚，
/// 连接恢复 autocommit、无残留行、可继续使用
#[test]
fn with_tx内panic后连接恢复可用() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (v INTEGER NOT NULL);").unwrap();

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result: cf_store::CfStoreResult<()> = cf_store::tx::with_tx(&mut conn, |tx| {
            tx.execute("INSERT INTO t (v) VALUES (1)", []).store()?;
            panic!("注入的 panic");
        });
        let _ = result; // 正常情况下不会走到这里
    }));
    assert!(panicked.is_err(), "闭包应当 panic");

    assert!(conn.is_autocommit(), "panic 后事务必须已回滚（autocommit 恢复）");
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0, "panic 不得留下已写入的行");

    // 连接仍然可用：再次写入成功
    cf_store::tx::with_tx(&mut conn, |tx| {
        tx.execute("INSERT INTO t (v) VALUES (2)", []).store()?;
        Ok(())
    })
    .unwrap();
}

/// 嵌套事务：事务内再 BEGIN → 立即结构化报错，不死锁不挂起
#[test]
fn 嵌套事务被拒绝而非死锁() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (v INTEGER NOT NULL);").unwrap();

    let result: cf_store::CfStoreResult<()> = cf_store::tx::with_tx(&mut conn, |tx| {
        tx.execute_batch("BEGIN").store()?; // 嵌套 BEGIN
        Ok(())
    });

    match result {
        Err(CfError::StorageError(msg)) => {
            assert!(
                msg.contains("transaction"),
                "错误信息应指向嵌套事务：{msg}"
            );
        }
        other => panic!("期望 StorageError（嵌套事务拒绝），实际 {other:?}"),
    }
    // 外层连接状态完好
    assert!(conn.is_autocommit(), "失败后连接应回到 autocommit");
}

/// WAL 多连接并发：独立连接可读已提交数据；写事务进行中读方看到旧快照；
/// 提交后读方看到新数据
#[test]
fn 多连接并发读写快照隔离() {
    let db = temp_db("wal-concurrent");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();

    let mode: String = store
        .connection()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal", "文件库必须是 WAL 模式");

    let a = uuid::Uuid::now_v7().to_string();
    store
        .with_tx(|r| r.items.insert(&item_row(&a), &SecretString::from_exposed("第一条")).map(|_| ()))
        .unwrap();

    let reader = Connection::open(&db).unwrap();
    let n: i64 = reader.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1, "独立连接必须读到已提交数据");

    // 未提交写入对读方不可见（WAL 快照隔离）
    let b = uuid::Uuid::now_v7().to_string();
    store
        .with_tx(|r| {
            r.items.insert(&item_row(&b), &SecretString::from_exposed("第二条"))?;
            let n2: i64 = reader.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0)).unwrap();
            assert_eq!(n2, 1, "未提交写入对其他连接不可见");
            Ok(())
        })
        .unwrap();

    let n3: i64 = reader.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0)).unwrap();
    assert_eq!(n3, 2, "提交后读方必须看到新数据");
}

// ------------------------------------------------ 3. 外键与级联

/// 硬删级联清除全部从表
#[test]
fn 硬删级联清除全部从表() {
    let db = temp_db("cascade-all");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();
    let item_uuid = uuid::Uuid::now_v7().to_string();

    // sections / fields / urls / tags / attachments(inline) / history / totp / passkeys
    let children: &[(&str, &str)] = &[
        ("sections", "INSERT INTO sections (uuid, item_uuid, enc_title) VALUES ('s1', ?1, x'00')"),
        ("fields", "INSERT INTO fields (uuid, item_uuid, field_type, enc_name) VALUES ('f1', ?1, 'text', x'00')"),
        ("urls", "INSERT INTO urls (uuid, item_uuid, enc_url) VALUES ('u1', ?1, x'00')"),
        ("tags", "INSERT INTO tags (uuid, item_uuid, enc_name) VALUES ('t1', ?1, x'00')"),
        ("attachments", "INSERT INTO attachments (uuid, item_uuid, enc_filename, storage, inline_data, size_bytes, content_mac, created_at) VALUES ('a1', ?1, x'00', 'inline', x'00', 1, 'mac', 0)"),
        ("history", "INSERT INTO history (uuid, item_uuid, version, created_at, enc_snapshot) VALUES ('h1', ?1, 1, 0, x'00')"),
        ("totp", "INSERT INTO totp (uuid, item_uuid, enc_secret, created_at) VALUES ('o1', ?1, x'00', 0)"),
        ("passkeys", "INSERT INTO passkeys (uuid, item_uuid, enc_rp_id, enc_user_handle, enc_credential_id, enc_private_key, algorithm, created_at) VALUES ('p1', ?1, x'00', x'00', x'00', x'00', -7, 0)"),
    ];

    {
        let conn = store.connection();
        conn.execute(
            "INSERT INTO items (uuid, category, created_at, updated_at, enc_title)
             VALUES (?1, 'login', 0, 0, x'00')",
            rusqlite::params![item_uuid],
        )
        .unwrap();
        for (table, sql) in children {
            conn.execute(sql, rusqlite::params![item_uuid])
                .unwrap_or_else(|e| panic!("预备 {table} 行失败：{e}"));
        }
    }

    store
        .with_tx(|r| r.items.delete_hard(&item_uuid))
        .unwrap();

    let conn = store.connection();
    for (table, _) in children {
        let n: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE item_uuid=?1"),
                rusqlite::params![item_uuid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "{table} 必须随条目级联删除");
    }
}

/// FK 强制：外连接经 ItemStore::open 初始化后，引用不存在条目的从表行被拒
#[test]
fn 外键强制引用存在() {
    let db = temp_db("fk-enforce");
    let conn = Connection::open(&db).unwrap();
    let store = ItemStore::open(conn, subkeys()).unwrap();

    let result = store.connection().execute(
        "INSERT INTO fields (uuid, item_uuid, field_type, enc_name)
         VALUES ('f1', 'ghost-item', 'text', x'00')",
        [],
    );
    match result {
        Err(e) => assert!(
            e.to_string().contains("FOREIGN KEY"),
            "应为外键约束错误：{e}"
        ),
        Ok(_) => panic!("外键开启时引用不存在条目必须被拒"),
    }
}

/// FK 默认值验证：rusqlite bundled SQLite 以
/// `-DSQLITE_DEFAULT_FOREIGN_KEYS=1` 编译 ⇒ 任何连接（含未跑
/// schema::init 的裸连接）FK 都默认开启，级联在裸连接上同样生效。
/// （风险提示：若未来脱离 bundled 特性编译，该默认值会翻转为 OFF——
/// schema::init 的 PRAGMA_BATCH 是唯一显式保障，不可移除。）
#[test]
fn 裸连接外键默认开启且级联生效() {
    let db = temp_db("fk-per-conn");
    let (store, item_uuid, _) = seeded_store(&db);

    let fk: i64 = store
        .connection()
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1, "经 init 的连接 FK 必须开启");

    // 裸连接（不经 init）：bundled SQLite 默认 FK=ON
    let raw = Connection::open(&db).unwrap();
    let fk_raw: i64 = raw.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
    assert_eq!(fk_raw, 1, "bundled 编译默认开启 FK（-DSQLITE_DEFAULT_FOREIGN_KEYS=1）");

    // 裸连接删除条目：级联同样生效
    raw.execute("DELETE FROM items WHERE uuid=?1", rusqlite::params![item_uuid])
        .unwrap();
    let orphan: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM fields WHERE item_uuid=?1",
            rusqlite::params![item_uuid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphan, 0, "FK=ON 的裸连接删除必须级联");
}

/// TotpStore 兼容门面路径外键同样默认开启：引用不存在条目被拒
#[test]
fn totp兼容路径外键强制引用存在() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE items (uuid TEXT PRIMARY KEY);").unwrap();
    let store = TotpStore::new(conn, SessionKey::new([0x55u8; 32])).unwrap();

    let result = store.insert_totp(
        &uuid::Uuid::now_v7().to_string(),
        &uuid::Uuid::from_bytes([0xEE; 16]).to_string(), // 合法 UUID 但 items 表中不存在
        b"0123456789",
        "sha1",
        6,
        30,
        None,
        None,
    );
    match result {
        Err(CfError::StorageError(msg)) => assert!(
            msg.contains("FOREIGN KEY"),
            "应为外键约束错误：{msg}"
        ),
        other => panic!("兼容路径 FK 应强制引用存在，实际 {other:?}"),
    }
}

// ------------------------------------------------ 4. item_count 一致性

/// 绕过仓库直插条目 → item_count 与实际行数出现漂移；
/// 后续 add_item_count 基于错误基线继续计数（漂移保留但不放大）
#[test]
fn 绕过仓库直插导致计数漂移且不自愈() {
    let db = temp_db("count-drift");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();

    // SQL 直插（绕过仓库与 add_item_count）
    let ghost = uuid::Uuid::now_v7().to_string();
    store
        .connection()
        .execute(
            "INSERT INTO items (uuid, category, created_at, updated_at, enc_title)
             VALUES (?1, 'login', 0, 0, x'00')",
            rusqlite::params![ghost],
        )
        .unwrap();

    let r = store.repos();
    assert_eq!(r.meta.item_count().unwrap(), 0, "无人维护 ⇒ 计数仍为 0");
    assert_eq!(r.items.count(None).unwrap(), 1, "实际行数为 1 ⇒ 漂移已产生");

    // 后续正常操作：仓库插入真实条目 + add_item_count(+1)
    // → meta=1、实际行数=2：漂移被保留（不放大也不自愈）
    let real = uuid::Uuid::now_v7().to_string();
    store
        .with_tx(|r| {
            r.items.insert(&item_row(&real), &SecretString::from_exposed("正常条目"))?;
            r.meta.add_item_count(1)?;
            Ok(())
        })
        .unwrap();
    let r = store.repos();
    assert_eq!(r.meta.item_count().unwrap(), 1);
    assert_eq!(r.items.count(None).unwrap(), 2, "漂移被保留（既不放大也不自愈）");
}

// ------------------------------------------------ 5. 加密正确性：AAD 钉死的边界

/// totp enc_secret 的 AAD 钉死在 **totp 行** uuid（O-1 修复，2026-09-23：
/// 原钉死在条目 uuid 上，同条目内跨记录搬运密文仍可解密——QA 对抗性
/// 验证发现的不一致）：
/// 同一条目下两条 totp 记录互换密文 → 解密失败（行级钉死）
#[test]
fn totp密文同条目跨记录搬运解密失败() {
    let db = temp_db("totp-same-item");
    let conn = Connection::open(&db).unwrap();
    let mut store = ItemStore::open(conn, subkeys()).unwrap();
    let item_uuid = uuid::Uuid::now_v7().to_string();
    let t1 = uuid::Uuid::now_v7().to_string();
    let t2 = uuid::Uuid::now_v7().to_string();

    store
        .with_tx(|r| {
            r.items.insert(&item_row(&item_uuid), &SecretString::from_exposed("t"))?;
            r.totp.insert_totp(&t1, &item_uuid, b"secret-AAAA", "sha1", 6, 30, None, None)?;
            r.totp.insert_totp(&t2, &item_uuid, b"secret-BBBB", "sha1", 6, 30, None, None)?;
            Ok(())
        })
        .unwrap();

    // 把 t1 的 enc_secret 搬到 t2（同 item，不同 totp 行）
    store
        .connection()
        .execute(
            "UPDATE totp SET enc_secret=(SELECT enc_secret FROM totp WHERE uuid=?1) WHERE uuid=?2",
            rusqlite::params![t1, t2],
        )
        .unwrap();

    assert!(
        matches!(store.repos().totp.totp_secret(&t2), Err(CfError::CryptoError)),
        "AAD 钉死 totp 行 uuid ⇒ 同条目内跨记录搬运必须解密失败（O-1 修复，2026-09-23）"
    );
}

/// AAD 带表名命名空间（O-1 修复，2026-09-23）：攻击者把 fields.enc_name
/// 密文写进一条 uuid 文本相同的 tags 行 → 解密失败
/// （原行为：AAD = uuid‖0‖列名 无表名，重放解密成功——QA 对抗性验证发现）
#[test]
fn 跨表密文重放解密失败() {
    let db = temp_db("cross-table-replay");
    let (mut store, item2, field_uuid) = {
        let (mut store, _, field_uuid) = seeded_store(&db);
        // 再建第二个条目作为重放目标
        let item2 = uuid::Uuid::now_v7().to_string();
        store
            .with_tx(|r| r.items.insert(&item_row(&item2), &SecretString::from_exposed("目标条目")).map(|_| ()))
            .unwrap();
        (store, item2, field_uuid)
    };

    // 取字段行 F 的 enc_name 密文
    let enc_name: Vec<u8> = store
        .connection()
        .query_row(
            "SELECT enc_name FROM fields WHERE uuid=?1",
            rusqlite::params![field_uuid],
            |r| r.get(0),
        )
        .unwrap();

    // 攻击者：在 tags 表造一行，uuid 文本 = 字段行 uuid，密文 = 字段密文
    store
        .with_tx(|r| {
            r.tags.replace_for_item(
                &item2,
                &[TagRow { uuid: field_uuid.clone(), item_uuid: item2.clone(), name: String::new() }],
            )
        })
        .unwrap();
    store
        .connection()
        .execute(
            "UPDATE tags SET enc_name=?1 WHERE uuid=?2",
            rusqlite::params![enc_name, field_uuid],
        )
        .unwrap();

    assert!(
        matches!(store.repos().tags.read_for_item(&item2), Err(CfError::CryptoError)),
        "AAD 带表名命名空间 ⇒ 跨表重放即使 uuid 文本相同也必须解密失败（O-1 修复，2026-09-23）"
    );
}

// ------------------------------------------------ 6. schema 幂等与 meta 损坏

/// 连续 open 同一库 10 次：全部成功、数据完好、版本不变
#[test]
fn 连续十次打开幂等() {
    let db = temp_db("reopen-10");
    {
        let (store, _, _) = seeded_store(&db);
        drop(store);
    }

    for i in 0..10 {
        let conn = Connection::open(&db).unwrap();
        let store = ItemStore::open(conn, subkeys())
            .unwrap_or_else(|e| panic!("第 {} 次 open 失败：{e}", i + 1));
        let r = store.repos();
        assert_eq!(r.items.count(None).unwrap(), 1, "第 {} 次：数据完好", i + 1);
        assert_eq!(
            r.meta.get_i64(KEY_SCHEMA_VERSION).unwrap(),
            Some(1),
            "第 {} 次：版本不变", i + 1
        );
        drop(store);
    }
}

/// 并发 open 同一库（两个线程同时初始化 schema）：都能成功
#[test]
fn 并发打开同一库都能成功() {
    let db = temp_db("concurrent-open");
    {
        let conn = Connection::open(&db).unwrap();
        ItemStore::open(conn, subkeys()).unwrap();
    }

    let d1 = db.clone();
    let d2 = db.clone();
    let h1 = std::thread::spawn(move || {
        let c = Connection::open(&d1).unwrap();
        ItemStore::open(c, subkeys())
    });
    let h2 = std::thread::spawn(move || {
        let c = Connection::open(&d2).unwrap();
        ItemStore::open(c, subkeys())
    });
    h1.join().unwrap().unwrap_or_else(|e| panic!("并发 open 线程1 失败：{e}"));
    h2.join().unwrap().unwrap_or_else(|e| panic!("并发 open 线程2 失败：{e}"));
}

/// schema_version 值被损坏成非 8 字节 BLOB：
/// verify() 与 init() 均（O-2 修复，2026-09-23：原 init 走 None 分支
/// 静默重写为 1，与 verify 报 Corrupted 语义不一致）报 Corrupted
#[test]
fn 损坏的版本值init与verify均报损坏() {
    let mut conn = Connection::open_in_memory().unwrap();
    cf_store::schema::init(&mut conn).unwrap();
    conn.execute(
        "UPDATE meta SET value=x'0102' WHERE key='schema_version'",
        [],
    )
    .unwrap();
    assert!(matches!(
        cf_store::schema::verify(&conn),
        Err(CfError::Corrupted(_))
    ));

    // init（即 ItemStore::open 路径）：损坏值 → Corrupted，绝不静默重写
    conn.execute("UPDATE meta SET value=x'0102' WHERE key='schema_version'", []).unwrap();
    match cf_store::schema::init(&mut conn) {
        Err(CfError::Corrupted(_)) => { /* O-2 修复后语义 */ }
        other => panic!("init 对损坏版本值必须报 Corrupted（O-2），实际 {other:?}"),
    }
    // 且未发生静默重写：原损坏值原样保留
    let raw: Vec<u8> = conn
        .query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(raw, vec![0x01, 0x02], "损坏值必须原样保留，不得被重写");
}

/// 负数版本值 → UnsupportedFormat（u16 溢出折叠为 65535，记录现状）
#[test]
fn 负数版本值报不支持格式错误() {
    let mut conn = Connection::open_in_memory().unwrap();
    cf_store::schema::init(&mut conn).unwrap();
    MetaRepo::new(&conn).set_i64(KEY_SCHEMA_VERSION, -5).unwrap();

    match cf_store::schema::init(&mut conn) {
        Err(CfError::UnsupportedFormat(65_535)) => { /* 记录现状：负数折叠为 u16::MAX */ }
        other => panic!("期望 UnsupportedFormat(65535)，实际 {other:?}"),
    }
}

/// vault_display_name 被写入非法 UTF-8 → lossy 转换不 panic（记录现状）
#[test]
fn 损坏的display_name不panic() {
    let mut conn = Connection::open_in_memory().unwrap();
    cf_store::schema::init(&mut conn).unwrap();
    let meta = MetaRepo::new(&conn);
    meta.set(cf_store::KEY_ITEM_COUNT, b"\xff\xfe\xfa").unwrap(); // 顺带：i64 读损坏值 → None
    assert_eq!(meta.get_i64(cf_store::KEY_ITEM_COUNT).unwrap(), None);

    meta.set("vault_display_name", &[0xFF, 0xFE]).unwrap();
    let name = meta.vault_display_name().unwrap();
    assert!(name.is_some(), "lossy 转换不报错不 panic（记录现状）");
}
