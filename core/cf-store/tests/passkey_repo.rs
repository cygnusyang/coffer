//! FR-10.2 / FR-10.5 passkey 存储内核验收用例（docs/17 §4.1 PK1 测试要点
//! ①–⑥）。
//!
//! 内存库 fixture；判据 = docs/17 §4.1：逐字段往返、私钥密文落盘、
//! `rp_id_hmac` 指纹一致性、非 ES256 拒绝、条目级联、remove 无文件面。

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_store::{
    ItemRow, ItemStore, PasskeyRecord, COLUMN_PASSKEY_PRIVATE_KEY, COLUMN_PASSKEY_RP_ID,
    COSE_ALG_ES256,
};
use rusqlite::Connection;

/// 内存库 + 固定子密钥（docs/10 §0.4：内存 fixture，不走解锁流）。
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

fn item_uuid(seed: u8) -> String {
    uuid::Uuid::from_bytes([seed; 16]).to_string()
}

/// 合法 ES256 记录（PKCS#8 DER 用合成字节——解析校验在导入侧，仓库层
/// 只判定非空与算法）。
fn record(rp_id: &str) -> PasskeyRecord {
    PasskeyRecord {
        rp_id: rp_id.to_owned(),
        rp_name: Some("GitHub".to_owned()),
        user_name: Some("alice@example.com".to_owned()),
        user_handle: vec![0xA1, 0xB2, 0xC3],
        credential_id: vec![0x01, 0x02, 0x03, 0x04],
        private_key_pkcs8: vec![0x30, 0x82, 0x01, 0x20, 0xAA, 0xBB],
        algorithm: COSE_ALG_ES256,
        sign_count: 5,
    }
}

/// 在事务内 add（内核冻结用法：调用方包在 with_tx 内）。
fn add_passkey(store: &mut ItemStore, item: &str, rec: &PasskeyRecord) -> String {
    store
        .with_tx(|repos| repos.passkeys.add(item, rec, 2_000))
        .unwrap()
}

/// 读 DB 单列（BLOB）。
fn blob_column(store: &ItemStore, passkey: &str, column: &str) -> Vec<u8> {
    let sql = format!("SELECT {column} FROM passkeys WHERE uuid = ?1");
    store
        .connection()
        .query_row(&sql, rusqlite::params![passkey], |r| r.get(0))
        .unwrap()
}

/// ① add → list_for_item 逐字段相等（含 base64 凭据 ID 往返）。
#[test]
fn add_and_list_roundtrip_逐字段相等() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    let rec = record("github.com");
    let passkey = add_passkey(&mut store, &item_uuid(1), &rec);

    let metas = store.repos().passkeys.list_for_item(&item_uuid(1)).unwrap();
    assert_eq!(metas.len(), 1);
    let m = &metas[0];
    assert_eq!(m.uuid, passkey);
    assert_eq!(m.item_uuid, item_uuid(1));
    assert_eq!(m.rp_id, "github.com");
    assert_eq!(m.rp_name.as_deref(), Some("GitHub"));
    assert_eq!(m.user_name.as_deref(), Some("alice@example.com"));
    assert_eq!(m.credential_id_b64, BASE64.encode(&rec.credential_id));
    assert_eq!(m.algorithm, COSE_ALG_ES256);
    assert_eq!(m.sign_count, 5);
    assert_eq!(m.created_at, 2_000);
    assert!(m.last_used_at.is_none());
}

/// ① 可空列：None 落盘为 SQL NULL，读回 None。
#[test]
fn 可空列_none_往返为_null() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    let mut rec = record("github.com");
    rec.rp_name = None;
    rec.user_name = None;
    add_passkey(&mut store, &item_uuid(1), &rec);

    let n: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM passkeys WHERE item_uuid = ?1
             AND enc_rp_name IS NULL AND enc_user_name IS NULL",
            rusqlite::params![item_uuid(1)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);

    let m = &store.repos().passkeys.list_for_item(&item_uuid(1)).unwrap()[0];
    assert!(m.rp_name.is_none() && m.user_name.is_none());
}

/// ② 私钥密文落盘：enc_private_key ≠ PKCS#8 明文、长度符合 sealed 格式
/// （24 nonce + 明文 + 16 tag）；rp_id / user_handle / credential_id
/// 同样为密文。
#[test]
fn 落盘均为密文() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    let rec = record("github.com");
    let passkey = add_passkey(&mut store, &item_uuid(1), &rec);

    let enc_key = blob_column(&store, &passkey, COLUMN_PASSKEY_PRIVATE_KEY);
    assert_ne!(enc_key, rec.private_key_pkcs8, "私钥明文不得出现在数据库中");
    assert_eq!(enc_key.len(), 24 + rec.private_key_pkcs8.len() + 16);

    let enc_rp_id = blob_column(&store, &passkey, COLUMN_PASSKEY_RP_ID);
    assert_ne!(enc_rp_id, b"github.com", "rp_id 明文不得出现在数据库中");

    let enc_cred = blob_column(&store, &passkey, "enc_credential_id");
    assert_ne!(enc_cred, rec.credential_id, "凭据 ID 明文不得落盘");

    let enc_handle = blob_column(&store, &passkey, "enc_user_handle");
    assert_ne!(enc_handle, rec.user_handle, "user_handle 明文不得落盘");

    // rp_id_hmac 已写入且为 32 字节（HMAC-SHA256）
    let hmac_col = blob_column(&store, &passkey, "rp_id_hmac");
    assert_eq!(hmac_col.len(), 32);
}

/// ③ rp_id_hmac 指纹：同 rpId + 同子密钥 → 同指纹；跨库（不同
/// vault_uuid 派生）→ 不同指纹。
#[test]
fn rp_id_hmac_同库一致_跨库不同() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    host_item(&store, &item_uuid(2));
    let p1 = add_passkey(&mut store, &item_uuid(1), &record("github.com"));
    let p2 = add_passkey(&mut store, &item_uuid(2), &record("github.com"));

    let h1 = blob_column(&store, &p1, "rp_id_hmac");
    let h2 = blob_column(&store, &p2, "rp_id_hmac");
    assert_eq!(h1, h2, "同 rpId 同子密钥必须得到同指纹");

    // 跨库：不同 vault_uuid ⇒ passkey_idx_key 不同 ⇒ 指纹不同
    let other = SubKeys::derive(&[0x42u8; 32], &[0x22u8; 16]).unwrap();
    let mut store_b = ItemStore::open(Connection::open_in_memory().unwrap(), other).unwrap();
    host_item(&store_b, &item_uuid(1));
    let p3 = add_passkey(&mut store_b, &item_uuid(1), &record("github.com"));
    let h3 = blob_column(&store_b, &p3, "rp_id_hmac");
    assert_ne!(h1, h3, "不同子密钥必须得到不同指纹");
}

/// ④ 非 ES256 → 1012（Validation），行不落库。
#[test]
fn 非es256被拒绝() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    let mut rec = record("github.com");
    rec.algorithm = 3; // COSE ES256P256 以外的编造值

    let err = store
        .with_tx(|repos| repos.passkeys.add(&item_uuid(1), &rec, 2_000))
        .unwrap_err();
    assert!(matches!(err, cf_domain::CfError::Validation(_)));
    let n: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM passkeys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "被拒绝的记录不得部分落库");
}

/// 边界校验：空 rpId / 空凭据 ID / 空私钥 / 负 sign_count / 非法
/// item uuid → 全部 1012。
#[test]
fn 校验失败快失败() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));

    let mut rec = record("github.com");
    rec.rp_id = "  ".to_owned();
    assert!(matches!(
        store.with_tx(|repos| repos.passkeys.add(&item_uuid(1), &rec, 2_000)),
        Err(cf_domain::CfError::Validation(_))
    ));

    let mut rec = record("github.com");
    rec.credential_id.clear();
    assert!(matches!(
        store.with_tx(|repos| repos.passkeys.add(&item_uuid(1), &rec, 2_000)),
        Err(cf_domain::CfError::Validation(_))
    ));

    let mut rec = record("github.com");
    rec.private_key_pkcs8.clear();
    assert!(matches!(
        store.with_tx(|repos| repos.passkeys.add(&item_uuid(1), &rec, 2_000)),
        Err(cf_domain::CfError::Validation(_))
    ));

    let mut rec = record("github.com");
    rec.sign_count = -1;
    assert!(matches!(
        store.with_tx(|repos| repos.passkeys.add(&item_uuid(1), &rec, 2_000)),
        Err(cf_domain::CfError::Validation(_))
    ));

    assert!(matches!(
        store.with_tx(|repos| repos
            .passkeys
            .add("not-a-uuid", &record("github.com"), 2_000)),
        Err(cf_domain::CfError::Corrupted(_))
    ));
}

/// ⑤ 条目硬删 → passkey 行级联消失（FK ON DELETE CASCADE）；软删 / 恢复
/// 不动 passkey 行。
#[test]
fn 条目硬删级联_软删不动() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    add_passkey(&mut store, &item_uuid(1), &record("github.com"));

    // 软删：行仍在
    store
        .with_tx(|repos| repos.items.soft_delete(&item_uuid(1), 3_000))
        .unwrap();
    assert_eq!(
        store
            .repos()
            .passkeys
            .list_for_item(&item_uuid(1))
            .unwrap()
            .len(),
        1,
        "软删不得级联删除 passkey 行"
    );

    // 恢复 → 硬删：级联消失
    store
        .with_tx(|repos| repos.items.restore(&item_uuid(1)))
        .unwrap();
    store
        .with_tx(|repos| repos.items.delete_hard(&item_uuid(1)))
        .unwrap();
    let n: i64 = store
        .connection()
        .query_row("SELECT COUNT(*) FROM passkeys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "条目硬删必须级联删除 passkey 行");
}

/// ⑥ remove：行消失且无文件面副作用（纯 DB 行，与附件不同）；再次
/// remove → 1011（ItemNotFound）。
#[test]
fn remove_删行且无文件面() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    let passkey = add_passkey(&mut store, &item_uuid(1), &record("github.com"));

    store
        .with_tx(|repos| repos.passkeys.remove(&passkey))
        .unwrap();

    let n: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM passkeys WHERE uuid = ?1",
            rusqlite::params![passkey],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);

    // 不存在的行 → 1011
    assert!(matches!(
        store.with_tx(|repos| repos.passkeys.remove(&passkey)),
        Err(cf_domain::CfError::ItemNotFound)
    ));
}

/// 密文搬防：enc_rp_id 搬到另一 passkey 行（不同 AAD）→ 解密失败。
#[test]
fn 密文钉死在passkey行uuid上() {
    let mut store = memory_store();
    host_item(&store, &item_uuid(1));
    host_item(&store, &item_uuid(2));
    let p1 = add_passkey(&mut store, &item_uuid(1), &record("github.com"));
    let p2 = add_passkey(&mut store, &item_uuid(2), &record("gitlab.com"));

    store
        .connection()
        .execute(
            "UPDATE passkeys SET enc_rp_id=(SELECT enc_rp_id FROM passkeys WHERE uuid=?1)
             WHERE uuid=?2",
            rusqlite::params![p1, p2],
        )
        .unwrap();

    assert!(matches!(
        store.repos().passkeys.list_for_item(&item_uuid(2)),
        Err(cf_domain::CfError::CryptoError)
    ));
}

/// 错误的字段密钥：记录可见但解密必须失败（1005 族，不区分原因）。
#[test]
fn 错误密钥解密失败() {
    // 同一连接、两套子密钥（totp.rs 错误密钥用例同款：写用真钥，读用假钥）
    let mut conn = Connection::open_in_memory().unwrap();
    cf_store::schema::init(&mut conn).unwrap();

    let good = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    cf_store::ItemsRepo::new(&conn, &good)
        .insert(
            &ItemRow {
                uuid: item_uuid(1),
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

    let writer = cf_store::PasskeyRepo::new(&conn, &good);
    writer
        .add(&item_uuid(1), &record("github.com"), 2_000)
        .unwrap();

    let bad = SubKeys::derive(&[0x43u8; 32], &[0x11u8; 16]).unwrap();
    let attacker = cf_store::PasskeyRepo::new(&conn, &bad);
    assert!(matches!(
        attacker.list_for_item(&item_uuid(1)),
        Err(cf_domain::CfError::CryptoError)
    ));
}
