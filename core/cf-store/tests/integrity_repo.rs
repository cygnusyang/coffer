//! NFR-REL-02/03 完整性校验集成测试（docs/09 §2 v0.2-T04，docs/10 §11.5）。
//!
//! 对码 docs/10-v0.2验收用例.md §11.5 TC-MAC 组（门禁）：
//!
//! | 用例 | 本文件测试名 |
//! | --- | --- |
//! | TC-MAC-01 | [`tc_mac_01_bump后verify往返_写条目触发基线重算`] |
//! | TC-MAC-02 | [`tc_mac_02_篡改record_count行检出`] |
//! | TC-MAC-03 | [`tc_mac_03_篡改root_mac单字节检出`] |
//! | TC-MAC-04 | [`tc_mac_04_删行自举`] |
//! | TC-MAC-05 | [`tc_mac_05_旧count_mac对回写检出`] |
//! | TC-MAC-07 | [`tc_mac_07_mac算法与派生已知答案`] |
//! | TC-MAC-08 | [`tc_mac_08_事务失败回滚后基线无半更新`] |
//!
//! TC-MAC-06（解锁端到端 1002）落 `cf-session/tests/integrity_unlock.rs`；
//! TC-MAC-09（备份回环）落 `cf-exporter/tests/backup_loopback.rs`（另人）。
//!
//! 防回滚语义边界（docs/10 §11.5 TC-MAC-05 备注）：本组断言的是
//! **行级篡改/删除可检出**；攻击者整库快照替换（连带 meta 与业务行
//! 一起回退到自洽旧态）超出单库 MAC 能力，属既定边界。

use cf_crypto::aead::SessionKey;
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::{ItemRow, ItemStore, MetaRepo, KEY_RECORD_COUNT, KEY_ROOT_MAC};
use rusqlite::Connection;

/// 唯一临时目录（与 integration.rs 同模式）。
fn temp_db(tag: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "coffer-t04-mac-{}-{}-{}",
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

/// 完整性校验用的固定测试密钥（非生产密钥；TC-MAC-07 KAT 与此绑定）。
fn root_mac_test_key() -> SessionKey {
    SessionKey::new([0x5au8; 32])
}

fn open_store(db_path: &std::path::Path) -> ItemStore {
    let conn = Connection::open(db_path).unwrap();
    ItemStore::open(conn, subkeys()).unwrap()
}

/// 经 with_tx 写入一条最小条目（自动触发 bump，NFR-REL-01 写路径纪律）。
/// 条目 uuid 用 UUIDv7（items.insert 会解析 uuid 构造 AAD）。
fn insert_item_via_tx(store: &mut ItemStore) {
    let item_uuid = uuid::Uuid::now_v7().to_string();
    store
        .with_tx(|r| {
            r.items.insert(
                &ItemRow {
                    uuid: item_uuid,
                    category: ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_000,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("完整性测试条目"),
            )?;
            r.meta.add_item_count(1)?;
            Ok(())
        })
        .unwrap();
}

fn meta_of(store: &ItemStore) -> MetaRepo<'_> {
    MetaRepo::new(store.connection())
}

fn record_count_of(store: &ItemStore) -> i64 {
    meta_of(store).get_i64(KEY_RECORD_COUNT).unwrap().unwrap()
}

fn root_mac_b64_of(store: &ItemStore) -> String {
    let blob = meta_of(store).get(KEY_ROOT_MAC).unwrap().unwrap();
    String::from_utf8(blob).unwrap()
}

/// TC-MAC-01：bump → verify 往返——写条目触发基线重算，verify 通过。
#[test]
fn tc_mac_01_bump后verify往返_写条目触发基线重算() {
    let db = temp_db("mac01");
    let mut store = open_store(&db);

    // 新库首次 verify：两行缺失 → 自举（旧库兼容语义）
    meta_of(&store)
        .verify_integrity(&store.subkeys().root_mac_key)
        .unwrap();
    assert_eq!(record_count_of(&store), 0);

    // 写入两条目（with_tx 自动 bump）→ verify 通过且计数一致
    insert_item_via_tx(&mut store);
    insert_item_via_tx(&mut store);
    meta_of(&store)
        .verify_integrity(&store.subkeys().root_mac_key)
        .unwrap();
    assert_eq!(record_count_of(&store), 2, "record_count 与 items 行数一致");
}

/// TC-MAC-02：直改 meta `record_count` 行 → verify 失败（防删除，负路径）。
#[test]
fn tc_mac_02_篡改record_count行检出() {
    let db = temp_db("mac02");
    let mut store = open_store(&db);
    insert_item_via_tx(&mut store);

    // count 0→2：与 MAC 绑定，单侧篡改不可通过
    store
        .connection()
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = 'record_count'",
            [2_i64.to_le_bytes().as_slice()],
        )
        .unwrap();
    let result = meta_of(&store).verify_integrity(&store.subkeys().root_mac_key);
    assert!(
        matches!(result, Err(CfError::Corrupted(_))),
        "篡改 record_count 必须检出"
    );
}

/// TC-MAC-03：翻转 `root_mac` BLOB 任一字节 → verify 失败（负路径）。
#[test]
fn tc_mac_03_篡改root_mac单字节检出() {
    let db = temp_db("mac03");
    let mut store = open_store(&db);
    insert_item_via_tx(&mut store);

    // 解码 base64 → 翻转首字节 → 重新编码回写（值域仍合法，仅内容变）
    use base64::Engine as _;
    let mut mac = base64::engine::general_purpose::STANDARD
        .decode(root_mac_b64_of(&store))
        .unwrap();
    mac[0] ^= 0xff;
    let tampered = base64::engine::general_purpose::STANDARD.encode(&mac);
    store
        .connection()
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = 'root_mac'",
            [tampered.as_bytes()],
        )
        .unwrap();

    let result = meta_of(&store).verify_integrity(&store.subkeys().root_mac_key);
    assert!(
        matches!(result, Err(CfError::Corrupted(_))),
        "MAC 单字节翻转必须检出"
    );
}

/// TC-MAC-04：删 `root_mac` / `record_count` 任一行 → 自举成功不报错
/// （旧库兼容，与 FR-8.5「缺行视为合法初态」同语义）。
#[test]
fn tc_mac_04_删行自举() {
    // ① 删 record_count 行
    let db = temp_db("mac04a");
    let mut store = open_store(&db);
    insert_item_via_tx(&mut store);
    store
        .connection()
        .execute("DELETE FROM meta WHERE key = 'record_count'", [])
        .unwrap();
    meta_of(&store)
        .verify_integrity(&store.subkeys().root_mac_key)
        .unwrap();
    assert_eq!(record_count_of(&store), 1, "自举按 COUNT(*) 重建");

    // ② 删 root_mac 行
    let db = temp_db("mac04b");
    let mut store = open_store(&db);
    insert_item_via_tx(&mut store);
    store
        .connection()
        .execute("DELETE FROM meta WHERE key = 'root_mac'", [])
        .unwrap();
    meta_of(&store)
        .verify_integrity(&store.subkeys().root_mac_key)
        .unwrap();
    assert!(!root_mac_b64_of(&store).is_empty(), "自举重建 MAC");
}

/// TC-MAC-05：用**旧** (count, MAC) 整对回写 → verify 失败——单独回滚
/// count 或 MAC 均不可通过，须 count↔MAC 联动绑定（行级防回滚）。
#[test]
fn tc_mac_05_旧count_mac对回写检出() {
    let db = temp_db("mac05");
    let mut store = open_store(&db);
    insert_item_via_tx(&mut store);
    insert_item_via_tx(&mut store);

    // 备份当前 (count=2, MAC) 旧对
    let old_count = record_count_of(&store);
    let old_mac = root_mac_b64_of(&store);
    assert_eq!(old_count, 2);

    // 再写 1 条 → 新基线 (3, MAC')
    insert_item_via_tx(&mut store);

    let conn = store.connection();
    let expect = |store: &ItemStore| {
        meta_of(store)
            .verify_integrity(&store.subkeys().root_mac_key)
            .is_err()
    };

    // ① 旧 count 整对回写：实际行数 3 ≠ 记录 2 → 检出
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'record_count'",
        [old_count.to_le_bytes().as_slice()],
    )
    .unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'root_mac'",
        [old_mac.as_bytes()],
    )
    .unwrap();
    assert!(expect(&store), "旧 (count, MAC) 整对回写必须检出");

    // ② 只回滚 MAC、保留新 count：MAC 与当前基线不符 → 检出
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'record_count'",
        [3_i64.to_le_bytes().as_slice()],
    )
    .unwrap();
    assert!(expect(&store), "单独回滚 MAC 必须检出");
}

/// TC-MAC-07：MAC 算法已知答案——固定密钥材料 + 固定输入向量与硬编码
/// 期望值比对（公式：HMAC-SHA256(root_mac_key, LE(count) ‖ LE(1))，
/// schema_version 取 cf_format::FORMAT_VERSION = 1，i64 小端；期望值由
/// 独立 Python 实现首算，2026-09-29）。
#[test]
fn tc_mac_07_mac算法与派生已知答案() {
    use base64::Engine as _;

    let db = temp_db("mac07");
    let store = open_store(&db);
    let meta = meta_of(&store);

    // count = 0（空库基线）
    meta.bump_integrity(&root_mac_test_key()).unwrap();
    let mac0 = base64::engine::general_purpose::STANDARD
        .decode(root_mac_b64_of(&store))
        .unwrap();
    assert_eq!(
        hex(&mac0),
        "db84c0afa2cc7bff8ed82e51599a67c688d45a85786b495bbd234e877fe76a6e",
        "HMAC(key=0x5a×32, LE(0)‖LE(1)) 已知答案"
    );

    // count = 3：插入 3 行后重算（第 9 把子密钥派生 + MAC 算法联动钉死）
    for i in 0..3 {
        store
            .connection()
            .execute(
                "INSERT INTO items (uuid, category, enc_title, created_at, updated_at)
                 VALUES (?1, 'login', x'00', 1, 1)",
                [format!("kat-{i}")],
            )
            .unwrap();
    }
    meta.bump_integrity(&root_mac_test_key()).unwrap();
    let mac3 = base64::engine::general_purpose::STANDARD
        .decode(root_mac_b64_of(&store))
        .unwrap();
    assert_eq!(
        hex(&mac3),
        "3fc87e00b10d922d805ea4ae1e1259e83a92216e2f141a8bf1a685a495547324",
        "HMAC(key=0x5a×32, LE(3)‖LE(1)) 已知答案"
    );

    // 交叉验证：SubKeys 派生 KAT（cf-crypto 冻结值，密钥材料 0x42/0x11）
    let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    assert_eq!(
        hex(keys.root_mac_key.as_bytes()),
        "bc8a85137b183970571d9a8a07d33c84dae8116350fa0d1204e70ecda0a25e2b",
        "root_mac_key 派生已知答案（cf/root-mac/v1）"
    );
}

/// TC-MAC-08：with_tx 内注入 Err → ROLLBACK → count 与 MAC 均无半更新
/// （对齐 TC-HIS-11 事务纪律）。
#[test]
fn tc_mac_08_事务失败回滚后基线无半更新() {
    let db = temp_db("mac08");
    let mut store = open_store(&db);
    insert_item_via_tx(&mut store);
    let count_before = record_count_of(&store);
    let mac_before = root_mac_b64_of(&store);

    // 事务内插入成功但闭包最终返回 Err → 整体回滚（含自动 bump）
    let result: cf_store::CfStoreResult<()> = store.with_tx(|r| {
        r.items.insert(
            &ItemRow {
                uuid: uuid::Uuid::now_v7().to_string(),
                category: ItemCategory::Login,
                state: ItemState::Active,
                is_favorite: false,
                fav_index: 0,
                created_at: 1_700_000_000,
                updated_at: 1_700_000_000,
                trashed_at: None,
                position: 0,
            },
            &SecretString::from_exposed("将被回滚"),
        )?;
        r.meta.add_item_count(1)?;
        Err(CfError::Validation("注入的失败".into()))
    });
    assert!(matches!(result, Err(CfError::Validation(_))));

    assert_eq!(record_count_of(&store), count_before, "count 无半更新");
    assert_eq!(root_mac_b64_of(&store), mac_before, "MAC 无半更新");
    meta_of(&store)
        .verify_integrity(&store.subkeys().root_mac_key)
        .unwrap();
}

/// 字节 → hex 文本（仅测试用）。
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
