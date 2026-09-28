//! TCB-6 备份回环（passkey 面，docs/17 §4.4 测试 7 + 裁定 TCA-7 (a)）。
//!
//! 备份 = 工作目录 ZIP（header.json + db.sqlite），passkey 行在 db.sqlite
//! 内且已字段级加密——导出/恢复**零代码增量**，本文件补回环测试证据：
//!
//! 1. 含 passkey 的库 → `export_backup` → 删库 → `restore_backup` →
//!    解锁成功；
//! 2. **passkey 行密文逐字节一致**（含 `enc_private_key` / `rp_id_hmac`）；
//! 3. **FR-10.6 双证据**：密码字段密文逐字节一致 + 解锁后明文逐字节一致；
//! 4. passkey 元数据（解密后）逐字段一致。
//!
//! 夹具复用 `support`（不经 cf-session，同 backup_loopback.rs 口径）；
//! passkey 种子经 `repos.passkeys.add`（内核冻结用法）写入。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use cf_domain::field::Designation;
use cf_exporter::{export_backup, restore_backup};
use cf_store::ItemListFilter;

mod support;

use support::{build_vault, remove_dir_all_quiet, reopen_store, temp_dir, unlock_store, PASSWORD};

/// passkey 行的全部密文列（逐字节比对的判定集；明文列 algorithm /
/// sign_count / created_at 一并比对）。
const PASSKEY_CIPHER_COLUMNS: &[&str] = &[
    "enc_rp_id",
    "enc_rp_name",
    "enc_user_name",
    "enc_user_handle",
    "enc_credential_id",
    "enc_private_key",
    "rp_id_hmac",
];

/// 读库内全部 passkey 行：(uuid, [列 → 字节], algorithm, sign_count,
/// created_at, last_used_at)。行序按 uuid 排序，保证两侧可比。
#[allow(clippy::type_complexity)]
fn read_passkey_rows(
    db: &std::path::Path,
) -> Vec<(String, Vec<(String, Vec<u8>)>, i64, i64, i64, Option<i64>)> {
    let conn = rusqlite::Connection::open(db).expect("打开 db 成功");
    let mut stmt = conn
        .prepare("SELECT uuid, algorithm, sign_count, created_at, last_used_at FROM passkeys ORDER BY uuid")
        .expect("查询 passkeys 成功");
    let mut rows = stmt.query([]).expect("遍历 passkeys 成功");
    let mut out = Vec::new();
    while let Some(row) = rows.next().expect("读行成功") {
        let uuid: String = row.get(0).expect("读 uuid 成功");
        let mut blobs = Vec::new();
        for col in PASSKEY_CIPHER_COLUMNS {
            let v: Option<Vec<u8>> = conn
                .query_row(
                    &format!("SELECT {col} FROM passkeys WHERE uuid = ?1"),
                    rusqlite::params![uuid],
                    |r| r.get(0),
                )
                .expect("读列成功");
            blobs.push((col.to_string(), v.unwrap_or_default()));
        }
        out.push((
            uuid,
            blobs,
            row.get(1).expect("读 algorithm 成功"),
            row.get(2).expect("读 sign_count 成功"),
            row.get(3).expect("读 created_at 成功"),
            row.get(4).expect("读 last_used_at 成功"),
        ));
    }
    out
}

/// 读指定字段行的 `enc_value` 密文字节（FR-10.6 密文证据）。
fn read_field_enc_value(db: &std::path::Path, field_uuid: &str) -> Vec<u8> {
    let conn = rusqlite::Connection::open(db).expect("打开 db 成功");
    conn.query_row(
        "SELECT enc_value FROM fields WHERE uuid = ?1",
        rusqlite::params![field_uuid],
        |r| r.get(0),
    )
    .expect("读字段密文成功")
}

/// 取某标题条目上指定 designation 字段的 (uuid, 解密后明文值)。
fn password_field_of(store: &cf_store::ItemStore, title: &str) -> (String, String) {
    let repos = store.repos();
    let items = repos
        .items
        .list(&ItemListFilter::default())
        .expect("列条目成功");
    let item = items
        .iter()
        .find(|i| i.title.expose() == title)
        .unwrap_or_else(|| panic!("条目 {title} 应存在"));
    let fields = repos
        .fields
        .read_fields_for_item(&item.row.uuid)
        .expect("读字段成功");
    let f = fields
        .iter()
        .find(|f| f.designation.as_ref() == Some(&Designation::Password))
        .expect("密码字段应存在");
    (
        f.uuid.clone(),
        f.value
            .as_ref()
            .map(|v| v.expose().to_owned())
            .unwrap_or_default(),
    )
}

/// TCB-6：含 passkey 库的备份回环——密文逐字节 + FR-10.6 双证据。
#[test]
fn tcb_6_备份回环_passkey密文与密码逐字节一致() {
    let base = temp_dir("tcb6_passkey");
    let (vault_dir, vault_uuid) = build_vault(&base);
    let src_db = vault_dir.join("db.sqlite");

    // ---- 种子：GitHub 条目挂 2 个 passkey（不同 rpId），公式条目挂 1 个 ----
    let mut store = reopen_store(&vault_dir, &vault_uuid);
    let (passkey_uuids, gh_field) = {
        let gh_item = {
            let repos = store.repos();
            repos
                .items
                .list(&ItemListFilter::default())
                .expect("列条目成功")
                .into_iter()
                .find(|i| i.title.expose() == "GitHub 登录")
                .expect("GitHub 登录应存在")
                .row
                .uuid
        };
        let gh_field_before = password_field_of(&store, "GitHub 登录");
        let rec = |rp_id: &str| cf_store::PasskeyRecord {
            rp_id: rp_id.to_owned(),
            rp_name: Some(rp_id.to_uppercase()),
            user_name: Some("octocat".to_owned()),
            user_handle: vec![0xA1, 0xB2, 0xC3],
            credential_id: vec![0x01, 0x02, 0x03, 0x04, rp_id.len() as u8],
            private_key_pkcs8: vec![0x30, 0x82, 0x01, 0x20, 0xEE],
            algorithm: cf_store::COSE_ALG_ES256,
            sign_count: 7,
        };
        let mut seeds = Vec::new();
        store
            .with_tx(|repos| {
                for rp in ["github.com", "gitlab.com"] {
                    seeds.push(repos.passkeys.add(&gh_item, &rec(rp), 1_700_000_100)?);
                }
                Ok(())
            })
            .expect("种子 passkey 写入成功");
        (seeds, gh_field_before)
    };
    assert_eq!(passkey_uuids.len(), 2);
    drop(store); // 连接关闭（WAL 合并），随后导出

    // ---- 导出前证据：源库密文 + 解锁态元数据 ----
    let src_rows = read_passkey_rows(&src_db);
    assert_eq!(src_rows.len(), 2, "源库应有 2 条 passkey 种子");
    let src_gh_enc = read_field_enc_value(&src_db, &gh_field.0);

    let out_path = base.join("tcb6.coffer");
    let result = export_backup(&vault_dir, &out_path).expect("导出成功");
    assert!(result.verified, "导出后自动结构校验应通过");

    // ---- 模拟灾难：删除工作目录 ----
    remove_dir_all_quiet(&vault_dir);
    assert!(!vault_dir.exists());

    // ---- 恢复 + 解锁 ----
    let target_base = temp_dir("tcb6_restore");
    let restored = restore_backup(&out_path, &target_base).expect("恢复成功");
    let (header, store) = unlock_store(&restored, PASSWORD).expect("恢复库应可解锁");
    assert_eq!(header.vault_uuid, vault_uuid);
    let restored_db = restored.join("db.sqlite");

    // ---- 证据 1：passkey 行密文逐字节一致（含私钥密文与 rp_id_hmac） ----
    let restored_rows = read_passkey_rows(&restored_db);
    assert_eq!(restored_rows.len(), src_rows.len(), "passkey 行数一致");
    for (i, src) in src_rows.iter().enumerate() {
        let dst = &restored_rows[i];
        assert_eq!(src.0, dst.0, "行 uuid 一致（ORDER BY uuid 后同位）");
        for ((col, src_bytes), (_, dst_bytes)) in src.1.iter().zip(dst.1.iter()) {
            assert_eq!(
                src_bytes, dst_bytes,
                "passkey 行 {} 的 {col} 密文必须逐字节一致",
                src.0
            );
        }
        assert_eq!(src.2, dst.2, "algorithm 一致");
        assert_eq!(src.3, dst.3, "sign_count 一致");
        assert_eq!(src.4, dst.4, "created_at 一致");
        assert_eq!(src.5, dst.5, "last_used_at 一致");
    }
    // enc_private_key 确实非空（密文比对不是恒等式假绿）
    let pk_col = src_rows[0]
        .1
        .iter()
        .find(|(c, _)| c == "enc_private_key")
        .expect("enc_private_key 应在判定集内");
    assert!(!pk_col.1.is_empty(), "私钥密文非空");

    // ---- 证据 2（FR-10.6 密文面）：密码字段密文逐字节一致 ----
    assert_eq!(
        src_gh_enc,
        read_field_enc_value(&restored_db, &gh_field.0),
        "密码字段密文必须逐字节一致"
    );

    // ---- 证据 3（FR-10.6 明文面 + 元数据）：解锁态解密比对 ----
    let repos = store.repos();
    let metas = repos
        .passkeys
        .list_for_item(
            &repos
                .items
                .list(&ItemListFilter::default())
                .expect("列条目成功")
                .into_iter()
                .find(|i| i.title.expose() == "GitHub 登录")
                .expect("GitHub 登录应恢复")
                .row
                .uuid,
        )
        .expect("列 passkey 成功");
    assert_eq!(metas.len(), 2);
    assert_eq!(metas[0].uuid, passkey_uuids[0]);
    assert_eq!(metas[1].uuid, passkey_uuids[1]);
    assert_eq!(metas[0].rp_id, "github.com");
    assert_eq!(metas[1].rp_id, "gitlab.com");
    assert_eq!(metas[0].user_name.as_deref(), Some("octocat"));
    assert_eq!(metas[0].sign_count, 7);
    assert_eq!(metas[0].created_at, 1_700_000_100);
    assert!(metas[0].last_used_at.is_none());

    let (_, gh_plain) = password_field_of(&store, "GitHub 登录");
    assert_eq!(
        gh_plain, gh_field.1,
        "恢复后密码明文必须逐字节一致（FR-10.6 明文面）"
    );

    drop(store);
    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}
