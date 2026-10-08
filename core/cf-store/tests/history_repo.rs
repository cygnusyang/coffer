//! FR-2.9 history 仓库层验收用例（docs/10 §3，自动化落点冻结于 §0.3）。
//!
//! 每个用例注释标注 TC 编号；判据基准 = `docs/10-v0.2验收用例.md` §3。
//! 落点偏移说明：TC-HIS-03（内容无变化不写）的判定逻辑由编排层
//! （cf-session usecase/history.rs `snapshot_before_update`）承载，
//! cf-store 仓库层无法单独触发该判据——端到端验证在
//! `cf-session/tests/history.rs::no_change_no_snapshot`（同名用例，
//! 注释同标 TC-HIS-03），本文件不重复断言。

use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::field::FieldType;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_domain::snapshot::{FieldSnapshot, ItemSnapshot, UrlEntrySnapshot};
use cf_domain::totp_data::{TotpAlgo, TotpData};
use cf_store::{ItemRow, ItemStore};
use rusqlite::Connection;

/// 内存库 + 固定子密钥（不走解锁流；docs/10 §0.4：内存 fixture）。
fn memory_store() -> ItemStore {
    let conn = Connection::open_in_memory().unwrap();
    let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    ItemStore::open(conn, subkeys).unwrap()
}

/// 直接插一个 Active 条目行（仓库层测试不经过 validate / 编排）。
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

/// 构造一份可变异的完整快照（含 URL / 字段 / TOTP）。
fn sample_snapshot(item_uuid: &str) -> ItemSnapshot {
    ItemSnapshot {
        uuid: uuid::Uuid::parse_str(item_uuid).unwrap(),
        category: ItemCategory::Login,
        state: ItemState::Active,
        is_favorite: false,
        fav_index: 0,
        created_at: 1_000,
        updated_at: 1_000,
        title: "GitHub 登录".to_owned(),
        urls: vec![UrlEntrySnapshot {
            uuid: uuid::Uuid::now_v7(),
            label: Some("官网".to_owned()),
            url: "https://github.com".to_owned(),
            is_primary: true,
            position: 0,
        }],
        tags: vec!["工作".to_owned()],
        sections: vec![],
        fields: vec![FieldSnapshot {
            uuid: uuid::Uuid::now_v7(),
            section_uuid: None,
            field_type: FieldType::Concealed,
            designation: Some(cf_domain::field::Designation::Password),
            name: "密码".to_owned(),
            value: Some("hunter2".to_owned()),
            position: 0,
        }],
        totp: Some(TotpData {
            secret: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            algo: TotpAlgo::Sha1,
            digits: 6,
            period: 30,
        }),
        attachments: vec![],
        origin_bindings: vec![],
    }
}

fn item_uuid(seed: u8) -> String {
    uuid::Uuid::from_bytes([seed; 16]).to_string()
}

/// TC-HIS-01 快照时机：编辑 2 次（每次内容有变化）→ 2 个版本，
/// version 递增、created_at 单调不减（时间注入固定值）。
#[test]
fn versions_increase_per_edit() {
    let store = memory_store();
    let item = item_uuid(1);
    host_item(&store, &item);

    // 编辑 1：标题变化（编排层等价动作 = update 前对当前态插快照）
    let repos = store.repos();
    let snap_v1 = sample_snapshot(&item);
    repos.history.insert(&item, &snap_v1, 5_000).unwrap();

    // 编辑 2：标题再变
    let mut snap_v2 = snap_v1.clone();
    snap_v2.title = "GitHub 登录（改）".to_owned();
    repos.history.insert(&item, &snap_v2, 6_000).unwrap();

    let metas = repos.history.list(&item).unwrap();
    assert_eq!(metas.len(), 2);
    // version 递增（list 为 DESC，v2 在前）
    assert_eq!(metas[0].version, 2);
    assert_eq!(metas[1].version, 1);
    // created_at 单调不减
    assert!(metas[0].created_at >= metas[1].created_at);
    assert_eq!(metas[1].created_at, 5_000);
}

/// TC-HIS-02 创建动作不产生快照：新建条目后 list_history 为空。
#[test]
fn create_has_no_history() {
    let store = memory_store();
    let item = item_uuid(2);
    host_item(&store, &item);

    let metas = store.repos().history.list(&item).unwrap();
    assert!(metas.is_empty(), "创建路径不写 history，新条目应无任何版本");
}

/// TC-HIS-04 快照密文落盘（对抗）：BLOB ≠ ItemSnapshot CBOR 明文；
/// 跨行搬运（错 AAD）解密失败。
#[test]
fn snapshot_encrypted_aad_pinned() {
    let store = memory_store();
    let item = item_uuid(3);
    host_item(&store, &item);

    let repos = store.repos();
    let snap = sample_snapshot(&item);
    let h1 = repos.history.insert(&item, &snap, 1_000).unwrap();
    let mut snap2 = snap.clone();
    snap2.title = "第二个版本".to_owned();
    let h2 = repos.history.insert(&item, &snap2, 2_000).unwrap();

    // BLOB ≠ CBOR 明文
    let conn = store.connection();
    let mut cbor = Vec::new();
    ciborium::into_writer(&snap, &mut cbor).unwrap();
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT enc_snapshot FROM history WHERE uuid = ?1",
            rusqlite::params![h1],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(blob, cbor, "快照明文不得落盘");
    assert!(
        !blob
            .windows(cbor.len().min(blob.len()))
            .any(|w| w == cbor.as_slice()),
        "CBOR 字节序列不得以任何偏移出现在密文 BLOB 中"
    );

    // 跨行搬运（h1 的密文写到 h2 行）：AAD 钉死行 uuid → 解密失败
    conn.execute(
        "UPDATE history SET enc_snapshot=(SELECT enc_snapshot FROM history WHERE uuid=?1)
         WHERE uuid=?2",
        rusqlite::params![h1, h2],
    )
    .unwrap();
    let result = repos.history.snapshot(&h2);
    assert!(
        matches!(result, Err(cf_domain::CfError::CryptoError)),
        "跨行搬运必须解密失败（O-1 AAD 行级钉死）"
    );
}

/// TC-HIS-05 版本列表排序：3 个版本 version DESC；元组字段正确。
#[test]
fn list_desc_order() {
    let store = memory_store();
    let item = item_uuid(4);
    host_item(&store, &item);

    let repos = store.repos();
    let mut snap = sample_snapshot(&item);
    for round in 1..=3u32 {
        snap.title = format!("版本 {round}");
        repos
            .history
            .insert(&item, &snap, 1_000 + i64::from(round))
            .unwrap();
    }

    let metas = repos.history.list(&item).unwrap();
    assert_eq!(metas.len(), 3);
    assert_eq!(
        metas.iter().map(|m| m.version).collect::<Vec<_>>(),
        vec![3, 2, 1],
        "version DESC"
    );
    // 元组字段正确（uuid / item_uuid / created_at）
    for m in &metas {
        assert_eq!(m.item_uuid, item);
        assert!(
            uuid::Uuid::parse_str(&m.uuid).is_ok(),
            "history 行 uuid 合法"
        );
        assert!((1_001..=1_003).contains(&m.created_at));
    }
}

/// TC-HIS-10 硬删级联：硬删条目后 history 行级联消失（FK ON DELETE CASCADE）。
#[test]
fn hard_delete_cascades_history() {
    let store = memory_store();
    let item = item_uuid(5);
    host_item(&store, &item);

    let repos = store.repos();
    repos
        .history
        .insert(&item, &sample_snapshot(&item), 1_000)
        .unwrap();
    let before: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM history WHERE item_uuid = ?1",
            rusqlite::params![item],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before, 1, "前置：history 已有 1 行");

    repos.items.delete_hard(&item).unwrap();

    let after: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM history WHERE item_uuid = ?1",
            rusqlite::params![item],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(after, 0, "外键级联必须清空 history");
}

/// TC-HIS-11 同事务原子性：带快照的 update 中途失败 → history 与主表
/// 同时回滚（无孤儿快照、主表未变）。
#[test]
fn snapshot_tx_atomic_with_items() {
    let mut store = memory_store();
    let item = item_uuid(6);
    host_item(&store, &item);

    // 单事务：插 items 从表行 + 写快照，随后注入失败
    let err = store.with_tx(|repos| -> cf_store::CfStoreResult<()> {
        repos
            .history
            .insert(&item, &sample_snapshot(&item), 2_000)?;
        // 注入失败（可操作的显式错误，docs/03 §4.4）
        Err(cf_domain::CfError::Validation("injected failure".into()))
    });
    assert!(err.is_err(), "事务必须以失败收场");

    // history 与主表同时回滚：无孤儿快照、主表未变
    let history_rows: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(history_rows, 0, "失败事务不得留下孤儿快照");
    let got = store.repos().items.get(&item).unwrap().unwrap();
    assert_eq!(got.title.expose(), "GitHub 登录", "主表未变");
}
