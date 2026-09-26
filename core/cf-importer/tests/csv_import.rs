//! T03 集成测试：CSV 导入端到端（解析 → 映射 → ItemStore 落库 → 读回）。
//!
//! 样本：`tests/fixtures/csv/`（仓库根目录，docs/07 §7 T03 文件清单）。
//! 断言依据：docs/07-macOS纵切设计.md §3 与 §7 T03 验收标准。

use std::path::PathBuf;

use cf_crypto::subkeys::SubKeys;
use cf_domain::field::Designation;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_importer::{precheck_csv, import_csv, import_csv_with_options, CsvImportResult, ImportOptions};
use cf_store::{ItemListFilter, ItemRow, ItemStore};

/// 仓库根 tests/fixtures/csv 下的样本路径。
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/csv")
        .join(name)
}

/// 内存库 + 固定子密钥的 ItemStore 门面（不依赖 cf-session）。
fn store() -> ItemStore {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    ItemStore::open(conn, keys).unwrap()
}

fn insert_one(store: &mut ItemStore, title: &str) -> String {
    store
        .with_tx(|repos| {
            let uuid = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: uuid.clone(),
                    category: cf_domain::category::ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_000,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed(title),
            )?;
            repos.meta.add_item_count(1)?;
            Ok(uuid)
        })
        .unwrap()
}

/// 验收 ③：9 列映射往返——CSV → ImportModel → 写库 → 读回逐字段相等
#[test]
fn 九列映射往返逐字段相等() {
    let mut st = store();
    let result: CsvImportResult = import_csv(&fixture("good_basic.csv"), &mut st).unwrap();
    assert_eq!(result.imported_rows, 3);

    let repos = st.repos();
    assert_eq!(repos.items.count(None).unwrap(), 3);
    assert_eq!(repos.meta.item_count().unwrap(), 3, "meta.item_count 同事务增量");

    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    let github = all
        .iter()
        .find(|i| i.title.expose() == "GitHub")
        .expect("应存在标题为 GitHub 的条目");
    let uuid = &github.row.uuid;

    // items 行级字段
    assert_eq!(github.row.category, cf_domain::category::ItemCategory::Login);
    assert_eq!(github.row.state, ItemState::Active);
    assert!(github.row.is_favorite, "Favorite status = true");

    // urls：主 URL
    let urls = repos.urls.read_for_item(uuid).unwrap();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].url.expose(), "https://github.com");
    assert!(urls[0].is_primary);

    // fields：Username / Password / Notes，逐字段相等
    let fields = repos.fields.read_fields_for_item(uuid).unwrap();
    let get = |d: &Designation| -> String {
        fields
            .iter()
            .find(|f| f.designation.as_ref() == Some(d))
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(get(&Designation::Username), "octocat");
    assert_eq!(get(&Designation::Password), "s3cret!");
    assert_eq!(get(&Designation::NotesPlain), "Main account");

    // tags
    let tags = repos.tags.read_for_item(uuid).unwrap();
    let mut names: Vec<String> = tags.iter().map(|t| t.name.expose().to_owned()).collect();
    names.sort();
    assert_eq!(names, vec!["dev", "重要"]);

    // totp：secret 字节、digits、period、issuer、account
    let totp_uuids = repos.totp.totp_uuids_for_item(uuid).unwrap();
    assert_eq!(totp_uuids.len(), 1);
    let meta = repos.totp.totp_meta(&totp_uuids[0]).unwrap().unwrap();
    assert_eq!(meta.algo, "sha1");
    assert_eq!(meta.digits, 6);
    assert_eq!(meta.period, 30);
    assert_eq!(meta.issuer.as_deref(), Some("GitHub"));
    assert_eq!(meta.account.as_deref(), Some("octocat"));
    let secret = repos.totp.totp_secret(&totp_uuids[0]).unwrap().unwrap();
    // base32("JBSWY3DPEHPK3PXP") = "Hello!" + DEADBEEF
    assert_eq!(
        &secret[..],
        &[0x48u8, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]
    );

    // 第二条：无 username/password，仅标题 + URL；字段应为空集
    let bare = all.iter().find(|i| i.title.expose() == "Bare").unwrap();
    let bare_urls = repos.urls.read_for_item(&bare.row.uuid).unwrap();
    assert_eq!(bare_urls.len(), 1);
    assert_eq!(bare_urls[0].url.expose(), "https://example.com");
    let bare_fields = repos.fields.read_fields_for_item(&bare.row.uuid).unwrap();
    assert!(bare_fields.is_empty(), "全空列不产生字段");

    // 第三条：仅密码
    let min_title = all.iter().find(|i| i.title.expose() == "MinTitle").unwrap();
    let min_fields = repos
        .fields
        .read_fields_for_item(&min_title.row.uuid)
        .unwrap();
    assert_eq!(min_fields.len(), 1);
    assert_eq!(
        min_fields[0].value.as_ref().unwrap().expose(),
        "p@ss",
        "Password 列落 Concealed 字段"
    );
}

/// 验收 ①：RFC 4180 边界——BOM + CRLF + 引号内逗号
#[test]
fn bom与crlf与引号内逗号() {
    let mut st = store();
    let report = precheck_csv(&fixture("bom_crlf.csv")).unwrap();
    assert_eq!(report.total_rows, 1);
    assert_eq!(report.valid_rows, 1);
    assert!(report.warnings.is_empty());

    import_csv(&fixture("bom_crlf.csv"), &mut st).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].title.expose(), "CrlfItem", "BOM 不得残留在表头/标题");
    let username = repos
        .fields
        .read_fields_for_item(&all[0].row.uuid)
        .unwrap()
        .into_iter()
        .find(|f| f.designation == Some(Designation::Username))
        .unwrap();
    assert_eq!(username.value.unwrap().expose(), "octo, cat", "引号内逗号保留");
}

/// 验收 ①：引号内换行 + "" 转义引号
#[test]
fn 引号内换行与转义引号往返() {
    let mut st = store();
    import_csv(&fixture("quoted_newline.csv"), &mut st).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    let notes = repos
        .fields
        .read_fields_for_item(&all[0].row.uuid)
        .unwrap()
        .into_iter()
        .find(|f| f.designation == Some(Designation::NotesPlain))
        .unwrap();
    assert_eq!(
        notes.value.unwrap().expose(),
        "line1\nline2 \"quoted\" tail"
    );
}

/// 验收 ④：公式前缀值原样入库 + warnings / formula_like_cells 命中（Password 不告警）
#[test]
fn 公式前缀原样入库且告警命中() {
    let report = precheck_csv(&fixture("formula_prefix.csv")).unwrap();
    assert_eq!(report.valid_rows, 2);

    // (行号, 列名)：Username、Notes、Tab 前缀 Username；Password 不在内
    assert_eq!(
        report.formula_like_cells,
        vec![
            (2u32, "username".to_owned()),
            (2u32, "notes".to_owned()),
            (3u32, "username".to_owned()),
        ]
    );
    assert!(report
        .warnings
        .iter()
        .all(|w| w.contains("公式前缀") || w.contains("导出")));

    let mut st = store();
    import_csv(&fixture("formula_prefix.csv"), &mut st).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    let calc = all.iter().find(|i| i.title.expose() == "Calc").unwrap();
    let fields = repos.fields.read_fields_for_item(&calc.row.uuid).unwrap();
    let username = fields
        .iter()
        .find(|f| f.designation == Some(Designation::Username))
        .unwrap();
    assert_eq!(username.value.as_ref().unwrap().expose(), "=SUM(A1)", "原值保留，不加前缀");
    let password = fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .unwrap();
    assert_eq!(password.value.as_ref().unwrap().expose(), "=p=ssw0rd");
}

/// 验收 ⑤：坏 otpauth 行不丢数据（原始值并入 Notes）+ 预检行号准确
#[test]
fn 坏otpauth不丢数据且行号准确() {
    let report = precheck_csv(&fixture("bad_otpauth.csv")).unwrap();
    assert_eq!(report.rows_with_bad_totp, vec![3, 4, 5], "文件行号：表头为第 1 行");
    assert_eq!(report.valid_rows, 4);
    assert!(report.warnings.iter().any(|w| w.contains("第 3 行")));

    let mut st = store();
    let result = import_csv(&fixture("bad_otpauth.csv"), &mut st).unwrap();
    assert_eq!(result.imported_rows, 4, "坏 otpauth 的行仍全部导入");

    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert_eq!(all.len(), 4);

    // 好 otpauth 的行有 totp 记录
    let good = all.iter().find(|i| i.title.expose() == "GoodOtp").unwrap();
    assert_eq!(repos.totp.totp_uuids_for_item(&good.row.uuid).unwrap().len(), 1);

    // 坏 otpauth 的行没有 totp 记录，但原始 URI 并入 Notes
    for title in ["BadOtpCharset", "BadOtpShort", "BadOtpDigits"] {
        let item = all.iter().find(|i| i.title.expose() == title).unwrap();
        assert!(
            repos.totp.totp_uuids_for_item(&item.row.uuid).unwrap().is_empty(),
            "{title} 不应有 totp 记录"
        );
        let notes = repos
            .fields
            .read_fields_for_item(&item.row.uuid)
            .unwrap()
            .into_iter()
            .find(|f| f.designation == Some(Designation::NotesPlain))
            .expect("坏 otpauth 必须留痕于备注");
        let value = notes.value.unwrap();
        let text = value.expose();
        assert!(text.contains("[One-time password 无法解析，已保留原始值]"), "{title} 备注缺前缀");
        assert!(text.contains("otpauth://totp/"), "{title} 备注缺原始值");
    }
}

/// 验收 ⑥：未知列并入 Notes + unmapped_columns 列出（不静默丢弃）
#[test]
fn 未知列并入备注且预检列出() {
    let report = precheck_csv(&fixture("unknown_column.csv")).unwrap();
    assert_eq!(report.unmapped_columns, vec!["Security Question"]);
    assert_eq!(report.skipped_rows, vec![3], "全空数据行跳过（EmptyExtra 行）");
    assert_eq!(report.valid_rows, 1);
    assert_eq!(report.total_rows, 2);

    let mut st = store();
    import_csv(&fixture("unknown_column.csv"), &mut st).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert_eq!(all.len(), 1);
    let notes = repos
        .fields
        .read_fields_for_item(&all[0].row.uuid)
        .unwrap()
        .into_iter()
        .find(|f| f.designation == Some(Designation::NotesPlain))
        .unwrap();
    let value = notes.value.unwrap();
    let text = value.expose();
    assert!(text.contains("note line"), "原 Notes 保留");
    assert!(text.contains("[未映射列 Security Question] What is your pet?"), "未知列值并入");
}

/// 缺失 Title：预检告警 + 导入兜底「（无标题）」+ 全空行跳过
#[test]
fn 无标题行兜底与空行跳过() {
    let report = precheck_csv(&fixture("no_title.csv")).unwrap();
    assert_eq!(report.rows_without_title, vec![2]);
    assert_eq!(report.skipped_rows, vec![3]);
    assert_eq!(report.valid_rows, 1);

    let mut st = store();
    import_csv(&fixture("no_title.csv"), &mut st).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].title.expose(), "（无标题）");
    assert_eq!(all[0].row.state, ItemState::Active);
}

/// 验收 ⑦：导入中途注入失败 → 库零变化（既有条目 + 计数全部不变）
#[test]
fn 导入中途注入失败库零变化() {
    let mut st = store();
    let existing_uuid = insert_one(&mut st, "既有条目");
    let before_count = st.repos().items.count(None).unwrap();
    let before_meta = st.repos().meta.item_count().unwrap();

    let err = import_csv_with_options(
        &fixture("good_basic.csv"),
        &mut st,
        &ImportOptions { fail_after_rows: Some(1) },
    )
    .unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportFailed(_)));

    let repos = st.repos();
    assert_eq!(repos.items.count(None).unwrap(), before_count, "条目数不变");
    assert_eq!(repos.meta.item_count().unwrap(), before_meta, "item_count 不变");
    // 既有条目仍可读（insert_one 未写字段，字段集为空且保持不变）
    assert!(repos.items.get_row(&existing_uuid).unwrap().is_some(), "既有条目必须仍在");
    assert!(repos
        .fields
        .read_fields_for_item(&existing_uuid)
        .unwrap()
        .is_empty(), "既有条目字段集不变");
    // 事务内新条目不应存在
    assert!(repos
        .items
        .list(&ItemListFilter::default())
        .unwrap()
        .iter()
        .all(|i| i.row.uuid == existing_uuid));
}

/// 验收 ⑧：无效 UTF-8（GBK 误投样本）被拒并提示转码
#[test]
fn 无效utf8文件被拒() {
    let err = precheck_csv(&fixture("invalid_utf8.csv")).unwrap_err();
    match err {
        cf_domain::CfError::ImportFailed(msg) => {
            assert!(msg.contains("UTF-8"), "应提示转码：{msg}");
        }
        other => panic!("期望 ImportFailed，实际 {other:?}"),
    }
}

/// 重名仅预检告警计数，不逐条打断；导入全部新建
#[test]
fn 重名仅告警全部新建() {
    let mut st = store();
    let report = precheck_csv(&fixture("duplicate_titles.csv")).unwrap();
    assert!(report
        .warnings
        .iter()
        .any(|w| w.contains("重复标题") && w.contains("全部新建")));
    assert_eq!(report.valid_rows, 3);

    let result = import_csv(&fixture("duplicate_titles.csv"), &mut st).unwrap();
    assert_eq!(result.imported_rows, 3);
    assert_eq!(st.repos().items.count(None).unwrap(), 3);
}

/// 归档行：Archived status = true → items.state = Archived
#[test]
fn 归档状态落库() {
    let mut st = store();
    import_csv(&fixture("archived_row.csv"), &mut st).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].row.state, ItemState::Archived);
    assert_eq!(all[0].row.trashed_at, None, "归档不是回收站");
}
