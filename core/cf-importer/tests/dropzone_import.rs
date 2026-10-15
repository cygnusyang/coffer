//! #104 测试前置（RED）——v2.11.0 放置区去重分类集成测试（docs/21 §5 P-4 + docs/21a §1.4）。
//!
//! 目标契约（docs/21a §1.4，lead 冻结）：
//! ```ignore
//! cf_importer::dropzone::analyze_dropzone(path, &ItemStore) -> Result<DropzoneAnalysis, CfError>
//! cf_importer::dropzone::import_dropzone(path, &[u32], &mut ItemStore) -> Result<CsvImportResult, CfError>
//! enum DedupCategory { New, Duplicate, Conflict }
//! struct DropzoneRow { line_no, title, username, url, category, conflict_note }
//! struct DropzoneAnalysis { rows, total_rows, valid_rows, new_count, duplicate_count,
//!                           conflict_count, warnings, unmapped_columns }
//! ```
//!
//! 起草状态：**RED 基线落盘 → G1 落地主模块后 18/18 全绿（2026-10-15 live 复跑，零警告）**。
//! G1 已实现 P-2 (a) Safari 别名层（`apply_header_aliases`，analyze/import 两侧同用，mapping.rs
//! 零改动）；is_empty_vault 按 lead 裁定落 FFI 层，core 集成面不承载。两例 Safari 别名测试随
//! G1 落地转绿，含非法 OTPAuth 原值并入 NotesPlain 的「不丢数据」断言（docs/21 §5 P-2）。
//!
//! 断言口径：
//! - 去重匹配键 = (Title, Username, URL) 规范化三元组，**Password 不作键**（docs/21 §4.4）；
//! - URL 规范化 = 去协议/去路径/去尾部斜杠/host 小写（`normalize_dedup_url`，U-3 provisional 至 J-5）；
//! - 空库 flag `is_empty_vault`：lead 裁定落 FFI 层（docs/21a §1.5），core 集成面不承载该契约，
//!   此处不测（FFI 面另测）；不依赖其在 core/FFI 的具体派生与暴露位置；
//! - `line_no` 文件行号 1 起（表头 = 第 1 行），数据首行 line_no = 2；
//! - 预检→导入竞态：导入重解析，include 行号在重解析后非空行集合中缺失 → `CfError::ImportFailed`
//!   零落库（fail-closed on drift，docs/21a §1.4）。

use std::io::Write;
use std::path::PathBuf;

use cf_crypto::subkeys::SubKeys;
use cf_domain::CfError;
use cf_importer::dropzone::{analyze_dropzone, import_dropzone, DedupCategory, DropzoneRow};
use cf_importer::{import_csv, CsvImportResult};
use cf_store::{ItemListFilter, ItemStore};

/// 内存库 + 固定子密钥的 ItemStore 门面（不依赖 cf-session；同 csv_import.rs 纪律）。
fn store() -> ItemStore {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    ItemStore::open(conn, keys).unwrap()
}

/// 9 列 CSV 头（docs/07 §3.2 既有格式，种子与候选共用）。
const CSV_HEADER: &str = "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes";

/// 写临时 CSV（每测试独立 TempDir，隔离性；不落仓库 fixtures）。
fn write_csv(dir: &tempfile::TempDir, name: &str, content: &str) -> PathBuf {
    let p = dir.path().join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    p
}

/// 以 9 列 CSV 种子化库（复用既有 import_csv 单事务，读回用户名/URL 依赖其既有落库路径）。
fn seed(store: &mut ItemStore, rows: &[&str]) {
    let dir = tempfile::TempDir::new().unwrap();
    let mut csv = String::from(CSV_HEADER);
    csv.push('\n');
    csv.push_str(&rows.join("\n"));
    let path = write_csv(&dir, "seed.csv", &csv);
    import_csv(&path, store).expect("seed import must succeed");
}

/// 行分类序列（顺序 = 文件行序），便于整表断言。
fn cats(rows: &[DropzoneRow]) -> Vec<&'static str> {
    rows.iter()
        .map(|r| match &r.category {
            DedupCategory::New => "new",
            DedupCategory::Duplicate => "duplicate",
            DedupCategory::Conflict => "conflict",
        })
        .collect()
}

// ===========================================================================
// analyze_dropzone：分类判定
// ===========================================================================

/// 空库 + 全新增 → 全 New，计数一致，无重复/冲突。
#[test]
fn 空库全新增() {
    let st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "new.csv",
        &format!(
            "{CSV_HEADER}\nGitHub,https://github.com,octocat,s3cret!,,,,\n淘宝,https://taobao.com,me,pw,,,,\n"
        ),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.total_rows, 2);
    assert_eq!(a.valid_rows, 2, "非空行数 = rows.len()");
    assert_eq!(a.rows.len(), 2);
    assert_eq!(a.new_count, 2);
    assert_eq!(a.duplicate_count, 0);
    assert_eq!(a.conflict_count, 0);
    assert_eq!(cats(&a.rows), vec!["new", "new"]);
}

/// 三元组完全匹配（含密码不同）→ Duplicate——**Password 不作匹配键**（docs/21 §4.4）。
#[test]
fn 三元组匹配归重复且密码不作键() {
    let mut st = store();
    seed(&mut st, &["GitHub,https://github.com,octocat,s3cret!,,,,,"]);
    let dir = tempfile::TempDir::new().unwrap();
    // 同三元组、密码已更新（`different-password`）→ 仍归 Duplicate（元数据级去重已知限制，docs/21 §4.4）
    let path = write_csv(
        &dir,
        "dup.csv",
        &format!("{CSV_HEADER}\nGitHub,https://github.com,octocat,different-password,,,,,\n"),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.duplicate_count, 1, "同三元组不同密码必须仍归 Duplicate（密码不参与匹配）");
    assert_eq!(cats(&a.rows), vec!["duplicate"]);
}

/// URL 规范化归一：`https://GitHub.com/` 与 `https://github.com` 视为同一 → Duplicate（U-3）。
#[test]
fn url规范化归一归重复() {
    let mut st = store();
    seed(&mut st, &["GitHub,https://github.com,octocat,s3cret!,,,,,"]);
    let dir = tempfile::TempDir::new().unwrap();
    // 候选 URL 大小写/协议/尾斜杠不同——规范化后应命中库内三元组
    let path = write_csv(
        &dir,
        "norm.csv",
        &format!("{CSV_HEADER}\nGitHub,HTTPS://GitHub.COM/,octocat,newpw,,,,,\n"),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.duplicate_count, 1, "URL 规范化后一致须归 Duplicate");
}

/// Title 命中但 Username 不同 → Conflict（冲突理由非空）。
#[test]
fn title命中用户名不同归冲突() {
    let mut st = store();
    seed(&mut st, &["GitHub,https://github.com,octocat,s3cret!,,,,,"]);
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "conflict.csv",
        &format!("{CSV_HEADER}\nGitHub,https://github.com,someoneelse,xyz,,,,,\n"),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.conflict_count, 1);
    assert_eq!(cats(&a.rows), vec!["conflict"]);
    assert!(
        a.rows[0].conflict_note.as_deref().is_some_and(|n| !n.is_empty()),
        "冲突行须带冲突理由（caption2 素材）"
    );
}

/// Title 命中但 URL 不同 → Conflict。
#[test]
fn title命中url不同归冲突() {
    let mut st = store();
    seed(&mut st, &["GitHub,https://github.com,octocat,s3cret!,,,,,"]);
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "conflict2.csv",
        &format!("{CSV_HEADER}\nGitHub,https://gitlab.com,octocat,xyz,,,,,\n"),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.conflict_count, 1);
}

/// 混合分类单次分析：新增 + 重复 + 冲突 各自归位，计数与行序一致。
#[test]
fn 混合分类计数与行序() {
    let mut st = store();
    seed(&mut st, &["GitHub,https://github.com,octocat,s3cret!,,,,,"]);
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "mixed.csv",
        &format!(
            "{CSV_HEADER}\nGitHub,https://github.com,octocat,s3cret!,,,,,\n新站,https://new.example,alice,pw,,,,\nGitHub,https://gitlab.com,octocat,pw2,,,,\n"
        ),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.total_rows, 3);
    assert_eq!(a.new_count, 1);
    assert_eq!(a.duplicate_count, 1);
    assert_eq!(a.conflict_count, 1);
    assert_eq!(cats(&a.rows), vec!["duplicate", "new", "conflict"]);
    // 行元数据（非敏感）暴露给 Swift：title/username/url 应有值
    assert_eq!(a.rows[1].title, "新站");
    assert_eq!(a.rows[1].username.as_deref(), Some("alice"));
    assert_eq!(a.rows[1].url.as_deref(), Some("https://new.example"));
    // 密码不得进入行元数据：DropzoneRow 无 password 字段（R2：密码不跨 FFI）——类型层面已约束
}

/// total_rows 含全空行；valid_rows / rows 不含全空行。
#[test]
fn total含全空行valid仅非空() {
    let st = store();
    let dir = tempfile::TempDir::new().unwrap();
    // 第 2 行全空（数据行，非文件尾）
    let path = write_csv(
        &dir,
        "blank.csv",
        &format!("{CSV_HEADER}\nGitHub,https://github.com,octocat,s3cret!,,,,,\n,,,,,,,,,\n"),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.total_rows, 2, "total_rows 须含全空行");
    assert_eq!(a.valid_rows, 1, "valid_rows 仅非空行");
    assert_eq!(a.rows.len(), 1);
    assert_eq!(a.rows[0].line_no, 2, "表头=第1行，数据首行 line_no=2");
}

/// 无法识别的表头 → 整文件拒绝（既有 analyze_header 语义，CfError::ImportUnknownFormat）。
#[test]
fn 无可识别表头整文件拒绝() {
    let st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(&dir, "garbage.csv", "foo,bar\n1,2\n");
    let err = analyze_dropzone(&path, &st).unwrap_err();
    assert!(
        matches!(err, CfError::ImportUnknownFormat),
        "无可识别列须 ImportUnknownFormat，实际 {err:?}"
    );
}

/// 非 UTF-8 文件 → 解析错误（不 panic、不落库）。
#[test]
fn 非utf8报错() {
    let st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let p = dir.path().join("bad.csv");
    std::fs::write(&p, [0xffu8, 0xfe, 0x00, 0x01]).unwrap();
    let err = analyze_dropzone(&p, &st).unwrap_err();
    assert!(
        matches!(err, CfError::ImportFailed(_)) || matches!(err, CfError::ImportUnknownFormat),
        "非 UTF-8 须报错，实际 {err:?}"
    );
}

/// 文件内重名（同 CSV 内 Title 重复）→ 不拦截，进入 warnings（既有 precheck 语义，
/// docs/07 §3.2「全部新建，不做去重」；docs/21 §4.4 在冲突/备注列提示）。
#[test]
fn 文件内重名入告警() {
    let st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "duptitle.csv",
        &format!("{CSV_HEADER}\nGitHub,https://a.example,u1,pw1,,,,\nGitHub,https://b.example,u2,pw2,,,,\n"),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    assert!(
        a.warnings
            .iter()
            .any(|w| w.contains("重复标题") || w.contains("重名")),
        "文件内重名须入 warnings，实际 {warnings:?}",
        warnings = a.warnings
    );
}

// ---------------------------------------------------------------------------
// P-2（裁定 (a)，provisional 至 J-5）：Safari 列头别名映射。
// 列名 = 社区事实（Title/URL/Username/Password/Notes/OTPAuth），J-5 实样核对后可调；
// 别名映射落 dropzone 模块内新增，`mapping.rs` 零改动（docs/21a §4.1 + lead 2026-10-15 裁决）。
// ---------------------------------------------------------------------------

/// Safari 列头：URL→url 字段、OTPAuth 合法 URI→totp 表、Notes→NotesPlain；
/// Password 为既有规范列，映射不受影响。
#[test]
fn safari列别名映射url与otp() {
    let mut st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let safari = "Title,URL,Username,Password,Notes,OTPAuth\nGitHub,https://github.com,octocat,s3cret!,Main account,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n";
    let path = write_csv(&dir, "safari.csv", safari);

    // 预检：URL 别名须映射到行元数据 url 字段（否则 URL 走 unmapped 并入备注 → 此断言红）
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.rows.len(), 1);
    assert_eq!(
        a.rows[0].url.as_deref(),
        Some("https://github.com"),
        "Safari URL 列须经别名映射到 url 字段（P-2 采 (a)）"
    );

    // 导入：OTPAuth 合法 URI 须进 totp 表、Notes 须进 NotesPlain
    let all_nos: Vec<u32> = a.rows.iter().map(|r| r.line_no).collect();
    let res = import_dropzone(&path, &all_nos, &mut st).unwrap();
    assert_eq!(res.imported_rows, 1);
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    let uuid = &all[0].row.uuid;
    let totp_uuids = repos.totp.totp_uuids_for_item(uuid).unwrap();
    assert_eq!(
        totp_uuids.len(),
        1,
        "Safari OTPAuth 列合法 otpauth URI 须进 totp 表（P-2 采 (a)）"
    );
    let fields = repos.fields.read_fields_for_item(uuid).unwrap();
    let notes = fields
        .iter()
        .find(|f| f.designation.as_ref() == Some(&cf_domain::field::Designation::NotesPlain))
        .and_then(|f| f.value.as_ref())
        .map(|v| v.expose().to_owned())
        .unwrap_or_default();
    assert_eq!(notes, "Main account", "Safari Notes 列须映射 NotesPlain");
}

/// Safari OTPAuth 非法值（非 otpauth URI）→ 解析失败并入备注，行仍导入、原值不丢
/// （docs/21 §5 P-2「解析失败并入备注」「未识别列降级并入备注不丢数据」）。
/// 只断言原值出现在 NotesPlain（contains）——别名层对非法值的具体前缀选择（
/// `[One-time password 无法解析…]` vs `[未映射列 OTPAuth]`）不在此处钉死，避免过度约束 G1。
#[test]
fn safari_otpauth非法并入备注() {
    let mut st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let safari = "Title,URL,Username,Password,Notes,OTPAuth\nX,https://x.example,u1,pw1,,\"not a uri\"\n";
    let path = write_csv(&dir, "safari_bad.csv", safari);
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.rows.len(), 1, "OTPAuth 非法不得丢整行");
    assert_eq!(a.rows[0].url.as_deref(), Some("https://x.example"));

    let all_nos: Vec<u32> = a.rows.iter().map(|r| r.line_no).collect();
    let res = import_dropzone(&path, &all_nos, &mut st).unwrap();
    assert_eq!(res.imported_rows, 1, "非法 OTPAuth 行仍导入不丢数据");

    // P-2 契约：非法 OTPAuth 原值须保留（并入 NotesPlain），不得静默丢弃
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    let uuid = &all[0].row.uuid;
    let fields = repos.fields.read_fields_for_item(uuid).unwrap();
    let notes = fields
        .iter()
        .find(|f| f.designation.as_ref() == Some(&cf_domain::field::Designation::NotesPlain))
        .and_then(|f| f.value.as_ref())
        .map(|v| v.expose().to_owned())
        .unwrap_or_default();
    assert!(
        notes.contains("not a uri"),
        "非法 OTPAuth 原值须并入 NotesPlain 不丢数据，实际 notes={notes:?}"
    );
}

// ===========================================================================
// import_dropzone：选择集导入 + 单事务
// ===========================================================================

/// 选择集子集：include=[3,5]（数据第 2、4 行）→ 只落库对应行，imported_rows=2。
#[test]
fn 选择集子集导入() {
    let mut st = store();
    let dir = tempfile::TempDir::new().unwrap();
    // 数据 4 行 → line_no 2,3,4,5
    let path = write_csv(
        &dir,
        "subset.csv",
        &format!(
            "{CSV_HEADER}\nA,https://a.example,u1,pw1,,,,\nB,https://b.example,u2,pw2,,,,\nC,https://c.example,u3,pw3,,,,\nD,https://d.example,u4,pw4,,,,\n"
        ),
    );
    let res: CsvImportResult = import_dropzone(&path, &[3, 5], &mut st).unwrap();
    assert_eq!(res.imported_rows, 2, "只导入 include 集行数");

    let all = st.repos().items.list(&ItemListFilter::default()).unwrap();
    let mut titles: Vec<&str> = all.iter().map(|i| i.title.expose()).collect();
    titles.sort_unstable();
    assert_eq!(titles, vec!["B", "D"], "只落库 B(line 3) 与 D(line 5)");
}

/// 全选（含重复/冲突默认集）→ 全落库；报告所见 = 导入所得（行序一致）。
#[test]
fn 全选导入与预检行序一致() {
    let mut st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "all.csv",
        &format!("{CSV_HEADER}\nA,https://a.example,u1,pw1,,,,\nB,https://b.example,u2,pw2,,,,\n"),
    );
    let a = analyze_dropzone(&path, &st).unwrap();
    let all_nos: Vec<u32> = a.rows.iter().map(|r| r.line_no).collect();
    let res = import_dropzone(&path, &all_nos, &mut st).unwrap();
    assert_eq!(res.imported_rows, 2);
    let repos = st.repos();
    assert_eq!(repos.items.count(None).unwrap(), 2);
}

/// 空选择集 → 0 行导入（「导入 N 条」N=0 时 .disabled，core 侧亦须安全接受空集）。
#[test]
fn 空选择集零导入() {
    let mut st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "empty.csv",
        &format!("{CSV_HEADER}\nA,https://a.example,u1,pw1,,,,\n"),
    );
    let res = import_dropzone(&path, &[], &mut st).unwrap();
    assert_eq!(res.imported_rows, 0);
    assert_eq!(st.repos().items.count(None).unwrap(), 0);
}

/// fail-closed on drift：预检后文件被改（include 行号在重解析后缺失）→ Err ImportFailed + 零落库。
#[test]
fn 文件漂移单事务零落库() {
    let mut st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "drift.csv",
        &format!("{CSV_HEADER}\nA,https://a.example,u1,pw1,,,,\nB,https://b.example,u2,pw2,,,,\n"),
    );
    // 预检得行号集合
    let a = analyze_dropzone(&path, &st).unwrap();
    assert_eq!(a.rows.len(), 2);
    // 导入前文件被外部改动：删掉 line 3（B 行），仅剩 1 条非空行（line 2）
    write_csv(
        &dir,
        "drift.csv",
        &format!("{CSV_HEADER}\nA,https://a.example,u1,pw1,,,,\n"),
    );
    // include 含缺失的 line 3 → 必须 Err，且库零新增
    let err = import_dropzone(&path, &[2, 3], &mut st).unwrap_err();
    assert!(
        matches!(err, CfError::ImportFailed(_)),
        "include 行号在重解析后缺失须 ImportFailed，实际 {err:?}"
    );
    assert_eq!(
        st.repos().items.count(None).unwrap(),
        0,
        "fail-closed 零落库（单事务回滚）"
    );
}

/// 导入写库逐字段往返：URL → urls（primary）、Username/Password → fields（与既有 import_csv 同构）。
#[test]
fn 导入落库逐字段() {
    let mut st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "fields.csv",
        &format!("{CSV_HEADER}\nGitHub,https://github.com,octocat,s3cret!,,,,\n"),
    );
    let res = import_dropzone(&path, &[2], &mut st).unwrap();
    assert_eq!(res.imported_rows, 1);
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert_eq!(all.len(), 1);
    let uuid = &all[0].row.uuid;
    let urls = repos.urls.read_for_item(uuid).unwrap();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].url.expose(), "https://github.com");
    assert!(urls[0].is_primary);
    let fields = repos.fields.read_fields_for_item(uuid).unwrap();
    let get = |d: &cf_domain::field::Designation| -> String {
        fields
            .iter()
            .find(|f| f.designation.as_ref() == Some(d))
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(get(&cf_domain::field::Designation::Username), "octocat");
    assert_eq!(get(&cf_domain::field::Designation::Password), "s3cret!");
}

/// 预检（analyze）不写库：分析后库条目数不变（只读面）。
#[test]
fn 预检只读不落库() {
    let st = store();
    let dir = tempfile::TempDir::new().unwrap();
    let path = write_csv(
        &dir,
        "readonly.csv",
        &format!("{CSV_HEADER}\nA,https://a.example,u1,pw1,,,,\n"),
    );
    analyze_dropzone(&path, &st).unwrap();
    assert_eq!(st.repos().items.count(None).unwrap(), 0, "预检必须零写库");
}
