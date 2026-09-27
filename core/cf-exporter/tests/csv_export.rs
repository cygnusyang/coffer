//! FR-8.3 集成测试：明文 CSV 导出与导入回环（FR-7.6 对偶）。
//!
//! 判据基准：docs/10-v0.2验收用例.md §1.2 TC-EXP-12~18（每个测试以
//! `tc_exp_NN_` 前缀对齐用例编号）。导入导出互为对拍：9 列映射全部
//! 引用 `cf_importer::csv::mapping` 的 `HEADER_*` 常量，防漂移。
//!
//! §0.4 纪律：临时目录 / 内存 fixture、时间戳固定值、无网络、测试间
//! 零共享可变状态。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;

use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_exporter::export_csv;
use cf_importer::csv::mapping::{
    parse_otpauth, HEADER_ARCHIVED, HEADER_FAVORITE, HEADER_NOTES, HEADER_OTP, HEADER_PASSWORD,
    HEADER_TAGS, HEADER_TITLE, HEADER_USERNAME, HEADER_WEBSITE,
};
use cf_importer::{import_csv, precheck_csv};
use cf_store::rows::FieldRow;
use cf_store::{ItemListFilter, ItemRow, ItemStore};

mod support;

use support::{build_vault, remove_dir_all_quiet, temp_dir};

/// 读 CSV 原始文本。
fn read_csv(path: &Path) -> String {
    fs::read_to_string(path).expect("读 CSV 成功")
}

/// 表头行文本（由 HEADER_* 常量拼出，供逐字节比对断言）。
fn expected_header_line() -> String {
    [
        HEADER_TITLE,
        HEADER_WEBSITE,
        HEADER_USERNAME,
        HEADER_PASSWORD,
        HEADER_OTP,
        HEADER_FAVORITE,
        HEADER_ARCHIVED,
        HEADER_TAGS,
        HEADER_NOTES,
    ]
    .join(",")
}

/// TC-EXP-12 CSV 回环对拍：export → precheck + import 到新库 → 逐字段
/// 比对；表头与 HEADER_* 常量逐字节相等（跨 crate 引用防漂移）。
#[test]
fn tc_exp_12_csv_roundtrip_field_identical() {
    let base = temp_dir("csv_loopback");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("export.csv");

    let store = support_unlocked_store(&vault_dir);
    let result = export_csv(&store, &out_path).expect("导出成功");
    assert_eq!(
        result.row_count, 5,
        "GitHub 登录 + SecureNote + 信用卡 + 归档 + 公式条目"
    );

    // 表头逐字节 = HEADER_* 常量（跨 crate 防漂移）
    let raw = read_csv(&out_path);
    let first_line = raw.lines().next().expect("有表头");
    assert_eq!(first_line, expected_header_line());

    // 预检：5 行全部有效
    let report = precheck_csv(&out_path).expect("预检成功");
    assert_eq!(report.total_rows, 5);
    assert_eq!(report.valid_rows, 5);
    assert!(report.rows_without_title.is_empty());
    assert!(report.warnings.is_empty(), "正常值回环不应产生告警");

    // 导入到新库
    let mut target = support_new_store();
    let imported = import_csv(&out_path, &mut target).expect("导入成功");
    assert_eq!(imported.imported_rows, 5);

    // ---- 逐字段对拍（对无公式前缀的正常条目做全等断言） ----
    let repos = target.repos();
    let items = repos
        .items
        .list(&ItemListFilter::default())
        .expect("列条目成功");

    let gh = items
        .iter()
        .find(|i| i.title.expose() == "GitHub 登录")
        .expect("GitHub 登录应回环");
    assert_eq!(gh.row.state, ItemState::Active);
    assert!(gh.row.is_favorite, "Favorite status 回环");
    let fields = repos
        .fields
        .read_fields_for_item(&gh.row.uuid)
        .expect("读字段成功");
    let get_field = |des: &Designation| {
        fields
            .iter()
            .find(|f| f.designation.as_ref() == Some(des))
            .and_then(|f| f.value.as_ref().map(|v| v.expose().to_owned()))
            .unwrap_or_default()
    };
    assert_eq!(get_field(&Designation::Username), "octocat");
    assert_eq!(get_field(&Designation::Password), "s3cret-明文密码!");
    assert_eq!(
        get_field(&Designation::NotesPlain),
        "Main account\n第二行备注"
    );
    let urls = repos.urls.read_for_item(&gh.row.uuid).expect("读 URL 成功");
    assert_eq!(urls.len(), 1, "CSV 只回写主 URL（Website 列）");
    assert_eq!(urls[0].url.expose(), "https://github.com");
    let tags = repos.tags.read_for_item(&gh.row.uuid).expect("读标签成功");
    let mut tag_names: Vec<&str> = tags.iter().map(|t| t.name.expose()).collect();
    tag_names.sort();
    assert_eq!(tag_names, vec!["dev", "重要"]);

    // TOTP 回环（TC-EXP-14 联合覆盖）：参数与密钥逐字节回环
    let totp_uuid = repos
        .totp
        .totp_uuids_for_item(&gh.row.uuid)
        .expect("列 TOTP 成功")
        .into_iter()
        .next()
        .expect("TOTP 应回环");
    let meta = repos
        .totp
        .totp_meta(&totp_uuid)
        .expect("读 TOTP 成功")
        .expect("记录存在");
    assert_eq!(meta.algo, "sha1");
    assert_eq!(meta.digits, 6);
    assert_eq!(meta.period, 30);
    assert_eq!(meta.issuer.as_deref(), Some("GitHub"));
    assert_eq!(meta.account.as_deref(), Some("octocat"));
    let secret = repos
        .totp
        .totp_secret(&totp_uuid)
        .expect("读密钥成功")
        .expect("密钥存在");
    assert_eq!(
        secret.as_slice(),
        b"Hello!\xDE\xAD\xBE\xEF",
        "TOTP 密钥逐字节回环"
    );

    // 归档条目回环
    let arch = items
        .iter()
        .find(|i| i.title.expose() == "归档的条目")
        .expect("归档条目应回环");
    assert_eq!(arch.row.state, ItemState::Archived, "Archived status 回环");

    // 回收站条目不得出现（TC-EXP-13 联合覆盖）
    assert!(
        !items.iter().any(|i| i.title.expose() == "回收站条目"),
        "回收站条目不导出"
    );

    remove_dir_all_quiet(&base);
}

/// TC-EXP-13 范围：回收站不导出，skipped_trashed 计数正确。
#[test]
fn tc_exp_13_trashed_skipped_with_count() {
    let base = temp_dir("csv_trashed");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("export.csv");

    let store = support_unlocked_store(&vault_dir);
    let result = export_csv(&store, &out_path).expect("导出成功");
    assert_eq!(result.skipped_trashed, 1, "夹具恰有 1 条回收站条目");

    let raw = read_csv(&out_path);
    assert!(!raw.contains("回收站条目"), "回收站条目不得出现在 CSV 中");
    assert_eq!(result.row_count, 5);

    remove_dir_all_quiet(&base);
}

/// TC-EXP-14 TOTP 回写：TOTP 列为合法 otpauth:// URI，secret 可被
/// 导入侧 `parse_otpauth` 解析回原参数（密钥逐字节、issuer、account、
/// digits、period 全一致）。
#[test]
fn tc_exp_14_totp_column_is_otpauth_uri() {
    let base = temp_dir("csv_totp");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("export.csv");

    let store = support_unlocked_store(&vault_dir);
    export_csv(&store, &out_path).expect("导出成功");

    // 定位 TOTP 列单元格（第 5 列，跳过表头）
    let raw = read_csv(&out_path);
    let otp_cell = raw
        .lines()
        .skip(1)
        .find(|l| l.starts_with("GitHub 登录,"))
        .and_then(|l| l.split(',').nth(4))
        .expect("GitHub 登录行的 OTP 列");

    let data = parse_otpauth(otp_cell).expect("TOTP 列必须是可解析的 otpauth URI");
    assert_eq!(data.secret, b"Hello!\xDE\xAD\xBE\xEF", "secret 逐字节一致");
    assert_eq!(data.issuer.as_deref(), Some("GitHub"));
    assert_eq!(data.account.as_deref(), Some("octocat"));
    assert_eq!(data.digits, 6);
    assert_eq!(data.period, 30);

    remove_dir_all_quiet(&base);
}

/// TC-EXP-15 公式注入防护：Username/Notes 分别为 `=`、`+`、`-`、`@`、
/// `\t` 开头 → 各单元格带 `'` 前缀；引号/逗号/换行转义符合 RFC 4180。
#[test]
fn tc_exp_15_formula_prefix_and_rfc4180_escaping() {
    let base = temp_dir("csv_formula");
    let out_path = base.join("export.csv");

    // 专用库：5 条条目各测一种前缀字符（Username / Notes 两列都覆盖）
    let mut store = support_new_store();
    seed_formula_variants(&mut store);
    export_csv(&store, &out_path).expect("导出成功");

    let raw = read_csv(&out_path);
    for prefix in ["=", "+", "-", "@", "\t"] {
        let expected_user = format!("'{prefix}user");
        let expected_note = format!("'{prefix}note");
        assert!(
            raw.contains(&expected_user),
            "Username {prefix:?} 开头必须加前缀，实际：\n{raw}"
        );
        assert!(
            raw.contains(&expected_note),
            "Notes {prefix:?} 开头必须加前缀"
        );
    }

    // RFC 4180：内嵌换行 + 引号内逗号必须引号包裹（换行按原值保留——
    // 数据保真优先，cf-importer 的解析器兼容 \n 与 \r\n）
    assert!(
        raw.contains("\"'=note\n第二行,带逗号\""),
        "内嵌换行与逗号必须整体引号包裹，实际：\n{raw}"
    );
    // 引号内逗号：夹具 notes 含逗号形态由专条覆盖（下方 formula_item）
    assert!(
        precheck_csv(&out_path).is_ok(),
        "带前缀与引号的 CSV 必须可被导入侧解析"
    );

    // 公式条目回环后值带前缀（导出侧防护的既定语义：导入侧原值保留；
    // 标题同样被加前缀 → 回环后为 "'=user 条目"）
    let mut target = support_new_store();
    import_csv(&out_path, &mut target).expect("导入成功");
    let repos = target.repos();
    let items = repos
        .items
        .list(&ItemListFilter::default())
        .expect("列条目成功");
    let first = items
        .iter()
        .find(|i| i.title.expose() == "'=user 条目")
        .expect("公式条目应回环（标题带前缀落库）");
    let fields = repos
        .fields
        .read_fields_for_item(&first.row.uuid)
        .expect("读字段成功");
    let username = fields
        .iter()
        .find(|f| f.designation.as_ref() == Some(&Designation::Username))
        .and_then(|f| f.value.as_ref())
        .map(|v| v.expose().to_owned())
        .unwrap_or_default();
    assert_eq!(username, "'=user", "导入侧原值保留（docs/07 §3.2）");

    remove_dir_all_quiet(&base);
    drop(store);
}

/// TC-EXP-16 CSV 目标不可写 → 2003，无半个文件。
#[test]
fn tc_exp_16_csv_unwritable_target() {
    let base = temp_dir("csv_unwritable");
    let store = support_new_store();
    let out_path = base.join("no_such_dir").join("export.csv");

    let err = export_csv(&store, &out_path).expect_err("父目录不存在必须失败");
    assert_eq!(err.code(), 2003, "ExportFailed，实际 {err:?}");
    assert!(!base.join("no_such_dir").exists(), "不得创建目标父目录");

    remove_dir_all_quiet(&base);
    drop(store);
}

/// TC-EXP-17 锁定态拒绝——⏸ 未覆盖（落点在 cf-session 门禁层）。
///
/// `VaultSession::export_csv` 的 1001 门禁属于 cf-session（G3 并行
/// 开发中，cf-exporter 不得反向依赖）；`cf_exporter::export_csv` 以
/// `&ItemStore` 为入参——ItemStore 只在解锁态存在，「锁定态」在该层
/// 无对应概念。G3 合入后由其侧测试核销（docs/10 §1.2 判据不变）。
#[test]
#[ignore = "TC-EXP-17：门禁落点在 cf-session（G3），cf-exporter 侧无锁定态语义"]
fn tc_exp_17_csv_requires_unlocked_pending_g3() {
    // 占位：G3 合入后由 cf-session 侧测试核销。
}

/// TC-EXP-18 空库 CSV：成功，仅表头一行，row_count = 0。
#[test]
fn tc_exp_18_empty_vault_header_only() {
    let store = support_new_store();
    let base = temp_dir("csv_empty");
    let out_path = base.join("empty.csv");
    let result = export_csv(&store, &out_path).expect("导出成功");
    assert_eq!(result.row_count, 0);
    assert_eq!(result.skipped_trashed, 0);
    let raw = read_csv(&out_path);
    let lines: Vec<&str> = raw.trim_end().split("\r\n").collect();
    assert_eq!(lines.len(), 1, "只有表头一行");
    assert_eq!(
        lines[0],
        expected_header_line(),
        "表头逐字等于 9 个 HEADER_* 常量"
    );
    remove_dir_all_quiet(&base);
    drop(store);
}

// ------------------------------------------------------------ 夹具工具

/// 用夹具「解锁」已建库目录（模拟 cf-session 解锁后的 ItemStore）。
fn support_unlocked_store(vault_dir: &Path) -> cf_store::ItemStore {
    let (_, store) =
        support::unlock_store(vault_dir, support::PASSWORD).expect("测试夹具解锁必须成功");
    store
}

/// 新建空内存库（导入侧 / 空库导出夹具）。
fn support_new_store() -> ItemStore {
    let conn = rusqlite::Connection::open_in_memory().expect("内存库成功");
    let keys =
        cf_crypto::subkeys::SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).expect("派生子密钥成功");
    ItemStore::open(conn, keys).expect("打开成功")
}

/// 向空库写入 5 条公式变体条目（TC-EXP-15 专用）：
/// Username 与 Notes 分别以 `=` `+` `-` `@` `\t` 开头（每条同字符）。
fn seed_formula_variants(store: &mut ItemStore) {
    let now = 1_700_000_000i64;
    store
        .with_tx(|repos| {
            for (k, ch) in ["=", "+", "-", "@", "\t"].iter().enumerate() {
                let uuid = uuid::Uuid::now_v7().to_string();
                repos.items.insert(
                    &ItemRow {
                        uuid: uuid.clone(),
                        category: cf_domain::category::ItemCategory::Login,
                        state: ItemState::Active,
                        is_favorite: false,
                        fav_index: 0,
                        created_at: now,
                        updated_at: now,
                        trashed_at: None,
                        position: k as i64,
                    },
                    &SecretString::from_exposed(format!("{ch}user 条目")),
                )?;
                repos.fields.replace_fields_for_item(
                    &uuid,
                    &[
                        FieldRow {
                            uuid: uuid::Uuid::now_v7().to_string(),
                            item_uuid: uuid.clone(),
                            section_uuid: None,
                            field_type: FieldType::Text,
                            designation: Some(Designation::Username),
                            name: "用户名".into(),
                            value: Some(format!("{ch}user")),
                            position: 0,
                        },
                        FieldRow {
                            uuid: uuid::Uuid::now_v7().to_string(),
                            item_uuid: uuid.clone(),
                            section_uuid: None,
                            field_type: FieldType::Multiline,
                            designation: Some(Designation::NotesPlain),
                            name: "备注".into(),
                            // 换行 + 逗号形态一并进夹具（RFC 4180 转义面）
                            value: Some(format!("{ch}note\n第二行,带逗号")),
                            position: 1,
                        },
                    ],
                )?;
                repos.meta.add_item_count(1)?;
            }
            Ok(())
        })
        .expect("写入公式变体条目成功");
}
