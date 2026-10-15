//! # dropzone —— 放置区导入（去重分类 + 选择集导入）
//!
//! `docs/21-密码导入放置区设计.md` §4.4 / `docs/21a-放置区导入实现方案.md` §1
//! （P-4 裁定）：去重分类在 **core** 完成，Swift 只消费分类结果与非敏感行
//! 元数据——CSV 的明文（含密码）只在 core 内存内解析与分类，**密码明文
//! 全程不跨 FFI**（R2 最强姿态）。
//!
//! ## 职责边界
//!
//! - [`analyze_dropzone`]：复用 `parse_csv` + `map_row` 同一确定性管线解析，
//!   读 store 既有 `(Title, Username, URL)` 规范化三元组，逐行分类
//!   [`DedupCategory`]（New / Duplicate / Conflict）。
//! - [`import_dropzone`]：重解析（同管线确定性）→ 行号子集校验
//!   （fail-closed on drift）→ 按行号过滤 → 走既有 [`crate::import_models`]
//!   单事务写入（all-or-nothing 逐字保留）；`write_model` 恒新建、无覆盖语义，
//!   分类只决定「哪些行进导入集」。
//! - [`normalize_dedup_url`]：URL 规范化单点函数（**provisional 至 J-5**，
//!   docs/21a §1.4 / §6 U-3）。
//! - Safari 表头别名层（P-2 裁定 (a)，provisional 至 J-5）：`URL`→url 字段、
//!   `OTPAuth`→totp 解析在**本模块内**改写为规范列名后走同一
//!   `analyze_header` / `map_row` 管线——别名与既有白名单并存，
//!   `mapping.rs` 零改动（[`apply_header_aliases`]）。
//! - [`DropzoneAnalysis`] 不含空库 flag：`is_empty_vault` 由 G2 FFI 层
//!   （`FfiDropzonePrecheck`，以库内条目计数派生）承载（docs/21a §1.5 lead 裁定）。
//!
//! ## 硬约束
//!
//! - R2：密码明文只在 core 内存；不落日志、不打印；warnings / 报告面
//!   不得含密码值（[`DropzoneRow`] 不含密码字段）。
//! - Password 永不作匹配键（docs/21 §4.4，防安全反模式）。
//! - 去重匹配键 = `(Title, Username, URL)` 三元组规范化后精确匹配；
//!   只匹配**非回收站**条目（回收站条目不参与去重，重新导入应新建活跃条目）。

use std::collections::{HashMap, HashSet};
use std::path::Path;

use cf_domain::field::Designation;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_store::{ItemListFilter, ItemStore};

use crate::csv::mapping::{self, ImportModel};
use crate::csv::parser;
use crate::{import_models, CsvImportResult, ImportOptions};

/// 规范化三元组 `(Title, Username, URL)`（URL 为 [`normalize_dedup_url`] 的 host）。
type DedupTriple = (String, Option<String>, Option<String>);

/// 库内条目按 Title 分组的 `(Username, URL)` 列表（冲突理由比对素材）。
type TitleEntries = HashMap<String, Vec<(Option<String>, Option<String>)>>;

/// 去重分类（docs/21 §4.4；每行归一类、互斥）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupCategory {
    /// 库内无此 `(Title, Username, URL)` 规范化三元组。
    New,
    /// 三元组完全匹配（含密码已更新的情形——元数据级去重已知限制）。
    Duplicate,
    /// Title 命中但 Username / URL 不一致。
    Conflict,
}

/// 一行（非空）的去重分类与非敏感行元数据（明文仅进 core 内存）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropzoneRow {
    /// 文件行号（1 起，表头 = 第 1 行）——导入选择集身份。
    pub line_no: u32,
    /// 标题（缺失 Title 的行已兜底「（无标题）」）。
    pub title: String,
    /// 用户名。
    pub username: Option<String>,
    /// 主 URL（Website 列原值）。
    pub url: Option<String>,
    /// 去重分类。
    pub category: DedupCategory,
    /// 冲突理由（「与库内同名条目用户名不同」等，caption2 展示）。
    pub conflict_note: Option<String>,
}

/// 放置区预检报告（docs/21a §1.4 契约面）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropzoneAnalysis {
    /// 非空行（顺序 = 文件行序）。
    pub rows: Vec<DropzoneRow>,
    /// 数据行总数（不含表头，**含**全空行）。
    pub total_rows: u32,
    /// 非空行数（= `rows.len()`）。
    pub valid_rows: u32,
    /// 新增行数。
    pub new_count: u32,
    /// 重复行数。
    pub duplicate_count: u32,
    /// 冲突行数。
    pub conflict_count: u32,
    /// 告警（复用既有 CSV 预检警告语义，含文件内重名）。
    pub warnings: Vec<String>,
    /// 未识别的数据列名（其非空值并入 Notes，不静默丢弃）。
    pub unmapped_columns: Vec<String>,
}

/// 预检一个放置区 CSV（只读、可反复调用），产出去重分类报告。
///
/// # Errors
///
/// 文件不存在 / 不可读 → [`CfError::Io`]；格式与上限问题 →
/// [`CfError::ImportFailed`] / [`CfError::ImportUnknownFormat`]（与
/// [`crate::precheck_csv`] 同语义）。
pub fn analyze_dropzone(path: &Path, store: &ItemStore) -> Result<DropzoneAnalysis, CfError> {
    let bytes = std::fs::read(path).map_err(|e| CfError::Io(format!("读取 CSV 失败：{e}")))?;
    let parsed = parser::parse_csv(&bytes)?;
    let (analysis, _models) = analyze_parsed(parsed, store)?;
    Ok(analysis)
}

/// 导入放置区 CSV 中被选中的行（单事务 all-or-nothing）。
///
/// `include_line_nos` 为「将导入行」的文件行号集合（来自预检报告的
/// [`DropzoneRow::line_no`]）。重解析后若任一 include 行号在非空行集合中
/// 缺失（文件在预检与导入之间被改动）→ [`CfError::ImportFailed`]，
/// fail-closed on drift，零额外数据。
///
/// # Errors
///
/// 解析 / 映射失败、行号 drift、或事务内任一行写入失败时返回，库保持
/// 导入前状态（all-or-nothing 逐字保留）。
pub fn import_dropzone(
    path: &Path,
    include_line_nos: &[u32],
    store: &mut ItemStore,
) -> Result<CsvImportResult, CfError> {
    let bytes = std::fs::read(path).map_err(|e| CfError::Io(format!("读取 CSV 失败：{e}")))?;
    let parsed = parser::parse_csv(&bytes)?;
    let header = mapping::analyze_header(&apply_header_aliases(&parsed.header))?;

    // 重解析后的非空行号集合（与预检同一「全空行跳过」语义，确定性同管线）
    let non_empty_line_nos: HashSet<u32> = parsed
        .rows
        .iter()
        .filter(|r| !r.cells.iter().all(|c| c.is_empty()))
        .map(|r| r.line_no)
        .collect();

    // fail-closed on drift（docs/21a §1.4）：任一 include 行号在重解析后的
    // 非空行集合中缺失 → 文件在预检与导入之间被改动，拒绝并回 S1 重新预检。
    let include: HashSet<u32> = include_line_nos.iter().copied().collect();
    for line_no in &include {
        if !non_empty_line_nos.contains(line_no) {
            return Err(CfError::ImportFailed(format!(
                "行号 {line_no} 在预检后文件中已不存在：文件可能在预检与导入之间被改动，请返回重新预检"
            )));
        }
    }

    // 按行号过滤出将导入行（保持文件行序），走既有 import_models 单事务
    let models: Vec<ImportModel> = parsed
        .rows
        .iter()
        .filter(|r| include.contains(&r.line_no))
        .map(|r| mapping::map_row(&header, r).0)
        .collect();

    import_models(&models, store, &ImportOptions::default())
}

/// URL 规范化（去重匹配键组成部分，docs/21 §4.4 / docs/21a §1.4）。
///
/// 规则（**provisional 至 J-5**，docs/21a §6 U-3 冻结）：去协议 → 去路径 /
/// 去尾部斜杠 → host 小写。对齐 `cf-audit/src/audit_rules.rs:470 url_host`
/// 的 host 抽取心智；J-5 实样核对后如需调整，仅改本单点函数（不跨 FFI）。
/// 非法 / 空输入返回 `None`（两侧都经本函数，保证匹配一致性）。
pub fn normalize_dedup_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    // 去协议 → 去路径（截断到首个 '/'，含尾部斜杠）→ host 小写
    let after_scheme = url.split_once("://").map_or(url, |(_, r)| r);
    let host = after_scheme.split_once('/').map_or(after_scheme, |(h, _)| h);
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Safari 表头别名（P-2 裁定 (a)，provisional 至 J-5；docs/21a §4.1）。
///
/// 列名 = 社区事实（Safari 导出：`URL` / `OTPAuth`），与本仓既有规范列白名单
/// （[`mapping::HEADER_WEBSITE`] / [`mapping::HEADER_OTP`]）**并存**——别名在
/// 本模块改写为规范列名后走同一 `analyze_header` / `map_row` 管线，
/// `mapping.rs` 零改动。大小写不敏感；非别名未知列保持原名（进 unmapped）。
const SAFARI_HEADER_ALIASES: [(&str, &str); 2] = [
    ("url", mapping::HEADER_WEBSITE),
    ("otpauth", mapping::HEADER_OTP),
];

/// 把 Safari 表头别名改写为规范列名（纯函数，返回新向量，不改原表头）。
///
/// 预检与导入**同用**本函数，保证「报告所见 = 导入所得」（别名列两侧一致）。
#[must_use]
fn apply_header_aliases(header: &[String]) -> Vec<String> {
    header
        .iter()
        .map(|raw| {
            let name = raw.trim().to_lowercase();
            SAFARI_HEADER_ALIASES
                .iter()
                .find(|(alias, _)| *alias == name.as_str())
                .map_or_else(|| raw.clone(), |(_, canonical)| (*canonical).to_owned())
        })
        .collect()
}

/// 解析 + 表头识别 + 逐行分类（同一确定性管线，报告与导入共线）。
///
/// 产出去重报告与按文件行序的 [`ImportModel`] 列表（供导入复用，保证
/// 「报告所见 = 导入所得」，docs/21a §1.2）。
fn analyze_parsed(
    parsed: parser::ParsedCsv,
    store: &ItemStore,
) -> Result<(DropzoneAnalysis, Vec<ImportModel>), CfError> {
    let header = mapping::analyze_header(&apply_header_aliases(&parsed.header))?;

    let mut analysis = DropzoneAnalysis {
        unmapped_columns: header.unmapped.iter().map(|(_, n)| n.clone()).collect(),
        ..Default::default()
    };

    let (existing, title_entries) = load_existing_triples(store)?;

    let mut models: Vec<ImportModel> = Vec::new();
    let mut title_counts: HashMap<String, u32> = HashMap::new();

    for row in &parsed.rows {
        analysis.total_rows += 1;

        // 全空行跳过（docs/07 §3.2，与既有 precheck 同一语义）
        if row.cells.iter().all(|c| c.is_empty()) {
            continue;
        }

        let (model, signals) = mapping::map_row(&header, row);
        *title_counts.entry(model.title.clone()).or_insert(0) += 1;
        analysis.valid_rows += 1;

        // 告警（镜像 precheck.rs 既有语义，见 docs/07 §3.2）
        if signals.no_title {
            analysis.warnings.push(format!(
                "第 {} 行：缺失 Title，导入时以「{}」兜底",
                row.line_no,
                mapping::FALLBACK_TITLE
            ));
        }
        if signals.bad_totp {
            // M-3 脱敏（dev-reviewer 2026-10-16）：`bad_totp_reason` 可能回显原始
            // otpauth URI / 参数片段（如「period 参数无效：{v}」），TOTP secret 同属
            // 凭据（R2 精神同等适用）——warnings 只留脱敏摘要 + 行号，不含原值。
            analysis.warnings.push(format!(
                "第 {} 行：One-time password 无法解析，原始值已并入备注，该行仍导入",
                row.line_no
            ));
        }
        for col in signals.invalid_bool_columns {
            analysis.warnings.push(format!(
                "第 {} 行：{col} 值不是 true/false，按 false 处理",
                row.line_no
            ));
        }
        if signals.ragged_extra_count > 0 {
            analysis.warnings.push(format!(
                "第 {} 行：数据比表头多 {} 列，多出的非空值已并入备注",
                row.line_no, signals.ragged_extra_count
            ));
        }
        for (line, col) in &signals.formula_cells {
            analysis.warnings.push(format!(
                "第 {line} 行：列「{col}」的值以公式前缀字符（= + - @ Tab）开头，\
                 若导出为 CSV 时将被转义（导入保留原值）"
            ));
        }

        // 去重分类（Password 不参与，R2）
        let url_norm = model.url.as_deref().and_then(normalize_dedup_url);
        let (category, conflict_note) =
            classify_dedup(&model, url_norm.as_deref(), &existing, &title_entries);

        match category {
            DedupCategory::New => analysis.new_count += 1,
            DedupCategory::Duplicate => analysis.duplicate_count += 1,
            DedupCategory::Conflict => analysis.conflict_count += 1,
        }

        analysis.rows.push(DropzoneRow {
            line_no: row.line_no,
            title: model.title.clone(),
            username: model.username.clone(),
            url: model.url.clone(),
            category,
            conflict_note,
        });
        models.push(model);
    }

    // 文件内重名：仅预检提示计数，不逐条打断（docs/07 §6.2 Q-3）
    let dup_titles = title_counts.values().filter(|&&c| c > 1).count();
    if dup_titles > 0 {
        let dup_rows: u32 = title_counts.values().filter(|&&c| c > 1).sum();
        analysis.warnings.push(format!(
            "检测到 {dup_titles} 个重复标题（涉及 {dup_rows} 行），导入将全部新建，不做去重"
        ));
    }

    Ok((analysis, models))
}

/// 读库既有 (Title, Username, URL) 规范化三元组（去重匹配与冲突理由素材）。
///
/// 只匹配**非回收站**条目（Active + Archived）：回收站条目不参与去重——
/// 重新导入时应新建一条活跃条目，而非命中已删除条目。URL 经
/// [`normalize_dedup_url`] 规范化后入库；Password 永不作为匹配键（R2）。
fn load_existing_triples(store: &ItemStore) -> Result<(HashSet<DedupTriple>, TitleEntries), CfError> {
    let repos = store.repos();
    let items = repos.items.list(&ItemListFilter::default())?;

    let mut triples: HashSet<DedupTriple> = HashSet::new();
    let mut title_entries: TitleEntries = HashMap::new();

    for item in items {
        if item.row.state == ItemState::Trashed {
            continue;
        }
        let title = item.title.expose().to_owned();

        // Login 模板单 Username 字段：取首个非空 Username-designation 值
        let fields = repos.fields.read_fields_for_item(&item.row.uuid)?;
        let username = fields
            .iter()
            .filter(|f| f.designation == Some(Designation::Username))
            .find_map(|f| {
                f.value
                    .as_ref()
                    .map(SecretString::expose)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned)
            });

        // 全部 URL（规范化后）；无 URL 时记一个 (username, None) 三元组
        let urls = repos.urls.read_for_item(&item.row.uuid)?;
        let url_hosts: Vec<Option<String>> = urls
            .iter()
            .map(|u| normalize_dedup_url(u.url.expose()))
            .collect();

        if url_hosts.is_empty() {
            triples.insert((title.clone(), username.clone(), None));
            title_entries
                .entry(title)
                .or_default()
                .push((username, None));
        } else {
            for host in url_hosts {
                triples.insert((title.clone(), username.clone(), host.clone()));
                title_entries
                    .entry(title.clone())
                    .or_default()
                    .push((username.clone(), host));
            }
        }
    }

    Ok((triples, title_entries))
}

/// 单行去重分类：三元组命中 → Duplicate；Title 命中 → Conflict；否则 New。
///
/// 冲突理由对比**首个** Title 命中条目（`title_entries` 构建顺序确定——
/// 条目按 list 序、URL 按读序，故 `.first()` 确定，笔记文案稳定）。
fn classify_dedup(
    model: &ImportModel,
    url_norm: Option<&str>,
    existing: &HashSet<DedupTriple>,
    title_entries: &TitleEntries,
) -> (DedupCategory, Option<String>) {
    let row_url = url_norm.map(str::to_owned);
    let triple = (model.title.clone(), model.username.clone(), row_url.clone());

    if existing.contains(&triple) {
        return (DedupCategory::Duplicate, None);
    }

    let Some(entries) = title_entries.get(&model.title) else {
        return (DedupCategory::New, None);
    };
    let Some((other_username, other_url)) = entries.first() else {
        // Title 命中但无可比对条目（理论不可达），仍按冲突处理
        return (DedupCategory::Conflict, Some("与库内同名条目信息不同".into()));
    };

    // 全等三元组已被上方 Duplicate 截获，此处至少一个分量不同
    let mut parts = Vec::new();
    if other_username != &model.username {
        parts.push("用户名");
    }
    if other_url != &row_url {
        parts.push("网址");
    }
    let note = if parts.is_empty() {
        "与库内同名条目信息不同".to_owned()
    } else {
        format!("与库内同名条目{}不同", parts.join("和"))
    };
    (DedupCategory::Conflict, Some(note))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use cf_crypto::subkeys::SubKeys;
    use cf_store::ItemStore;

    use super::*;
    use crate::csv::mapping::ImportModel;
    use crate::{import_models, ImportOptions};

    fn store() -> ItemStore {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        ItemStore::open(conn, keys).unwrap()
    }

    fn model(title: &str, url: Option<&str>, username: Option<&str>) -> ImportModel {
        ImportModel {
            title: title.into(),
            url: url.map(str::to_owned),
            username: username.map(str::to_owned),
            password: Some("pw".into()),
            totp: None,
            is_favorite: false,
            archived: false,
            tags: vec![],
            notes: String::new(),
        }
    }

    fn seed(store: &mut ItemStore, models: &[ImportModel]) {
        import_models(models, store, &ImportOptions::default()).unwrap();
    }

    fn write_csv(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    /// URL 规范化各态：去协议 / 去路径 / 去尾斜杠 / host 小写
    #[test]
    fn url规范化各态() {
        assert_eq!(normalize_dedup_url("https://github.com"), Some("github.com".into()));
        assert_eq!(
            normalize_dedup_url("https://GitHub.com/octocat/"),
            Some("github.com".into())
        );
        assert_eq!(
            normalize_dedup_url("http://example.com/path/to/page"),
            Some("example.com".into())
        );
        assert_eq!(normalize_dedup_url("https://example.com/"), Some("example.com".into()));
        assert_eq!(normalize_dedup_url("example.com"), Some("example.com".into()));
        assert_eq!(
            normalize_dedup_url("HTTPS://EXAMPLE.COM/"),
            Some("example.com".into())
        );
        assert_eq!(normalize_dedup_url("example.com/"), Some("example.com".into()));
        // 同一 host 的 http/https/大小写/路径差异 → 规范化后相同（参与匹配）
        assert_eq!(
            normalize_dedup_url("https://GitHub.com/octocat"),
            normalize_dedup_url("HTTP://GITHUB.COM")
        );
    }

    /// 空 / 无 host 输入 → None（不参与匹配）
    #[test]
    fn url规范化空输入() {
        assert_eq!(normalize_dedup_url(""), None);
        assert_eq!(normalize_dedup_url("   "), None);
        assert_eq!(normalize_dedup_url("https://"), None);
        assert_eq!(normalize_dedup_url("https:///"), None);
    }

    /// 三分归类：三元组命中 / 用户名不同 / URL 不同 / 全新
    #[test]
    fn 去重三分归类() {
        let mut st = store();
        // 库内已有：GitHub (octocat, https://github.com)
        seed(
            &mut st,
            &[model("GitHub", Some("https://github.com"), Some("octocat"))],
        );

        let csv = concat!(
            "Title,Website,Username,Password\n",
            "GitHub,https://github.com,octocat,pw1\n",  // 行2：三元组命中 → Duplicate
            "GitHub,https://github.com,bob,pw2\n",      // 行3：用户名不同 → Conflict
            "GitHub,https://gitlab.com,octocat,pw3\n",  // 行4：URL 不同 → Conflict
            "Example,https://example.com,alice,pw4\n",  // 行5：全新 → New
        );
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();

        assert_eq!(analysis.valid_rows, 4);
        assert_eq!(analysis.total_rows, 4);
        assert_eq!(analysis.new_count, 1);
        assert_eq!(analysis.duplicate_count, 1);
        assert_eq!(analysis.conflict_count, 2);

        assert_eq!(analysis.rows[0].category, DedupCategory::Duplicate);
        assert_eq!(analysis.rows[0].line_no, 2);
        assert_eq!(analysis.rows[1].category, DedupCategory::Conflict);
        assert_eq!(
            analysis.rows[1].conflict_note.as_deref(),
            Some("与库内同名条目用户名不同")
        );
        assert_eq!(analysis.rows[2].category, DedupCategory::Conflict);
        assert_eq!(
            analysis.rows[2].conflict_note.as_deref(),
            Some("与库内同名条目网址不同")
        );
        assert_eq!(analysis.rows[3].category, DedupCategory::New);
        assert!(analysis.rows[3].conflict_note.is_none());
        assert_eq!(analysis.rows[3].line_no, 5);
    }

    /// 冲突理由：用户名与网址均不同
    #[test]
    fn 冲突理由用户名与网址均不同() {
        let mut st = store();
        seed(
            &mut st,
            &[model("GitHub", Some("https://github.com"), Some("octocat"))],
        );
        let csv = "Title,Website,Username,Password\nGitHub,https://gitlab.com,carol,pw\n";
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(analysis.rows[0].category, DedupCategory::Conflict);
        assert_eq!(
            analysis.rows[0].conflict_note.as_deref(),
            Some("与库内同名条目用户名和网址不同")
        );
    }

    /// P-2 (a)：Safari 别名 URL→url 字段、OTPAuth→totp（别名层在 dropzone 内，
    /// mapping.rs 零改动）；别名列不进 unmapped
    #[test]
    fn safari别名映射url与otp() {
        let st = store();
        let csv = concat!(
            "Title,URL,Username,Password,Notes,OTPAuth\n",
            "GitHub,https://github.com,octocat,pw,Main account,",
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n",
        );
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(
            analysis.unmapped_columns,
            Vec::<String>::new(),
            "别名列不得进 unmapped"
        );
        assert_eq!(analysis.rows.len(), 1);
        assert_eq!(analysis.rows[0].url.as_deref(), Some("https://github.com"));
    }

    /// P-2 (a)：别名层大小写不敏感（url / OTpAUTH 均识别）
    #[test]
    fn safari别名大小写不敏感() {
        let st = store();
        let csv = "Title,url,Username,Password,OTpAUTH\nX,https://x.example,u1,pw,\n";
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(analysis.rows[0].url.as_deref(), Some("https://x.example"));
        assert_eq!(analysis.unmapped_columns, Vec::<String>::new());
    }

    /// P-2 (a)：别名与规范列并存（URL + Website 同文件）→ 重复列拒绝（fail-closed）
    #[test]
    fn 别名与规范列并存冲突拒绝() {
        let st = store();
        let csv = "Title,Website,URL,Username\nX,https://a.example,https://b.example,u1\n";
        let f = write_csv(csv);
        let err = analyze_dropzone(f.path(), &st).unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("重复列")));
    }

    /// P-2 (a)：别名「报告所见 = 导入所得」——预检 URL 别名显示 url 字段，
    /// 导入同走别名：url 落 urls 表、OTPAuth 合法 URI 落 totp 表
    #[test]
    fn safari别名预检导入一致() {
        let mut st = store();
        let csv = concat!(
            "Title,URL,Username,Password,OTPAuth\n",
            "X,https://x.example,u1,pw,",
            "otpauth://totp/X:u1?secret=JBSWY3DPEHPK3PXP&issuer=X\n",
        );
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(analysis.rows[0].url.as_deref(), Some("https://x.example"));

        let nos: Vec<u32> = analysis.rows.iter().map(|r| r.line_no).collect();
        let result = import_dropzone(f.path(), &nos, &mut st).unwrap();
        assert_eq!(result.imported_rows, 1);
        let repos = st.repos();
        let all = repos.items.list(&ItemListFilter::default()).unwrap();
        let uuid = &all[0].row.uuid;
        let urls = repos.urls.read_for_item(uuid).unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].url.expose(), "https://x.example");
        assert_eq!(repos.totp.totp_uuids_for_item(uuid).unwrap().len(), 1);
    }

    /// 文件内重名：沿用既有警告语义，导入全部新建不做去重
    #[test]
    fn 文件内重名警告() {
        let st = store();
        let csv = concat!(
            "Title,Username\n",
            "GitHub,octocat\n",
            "GitHub,bob\n",
            "GitHub,carol\n",
        );
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert!(analysis.warnings.iter().any(|w| w.contains("重复标题")));
        assert!(analysis.warnings.iter().any(|w| w.contains("涉及 3 行")));
    }

    /// 既有警告语义复用：缺 Title 兜底、坏 otpauth 并入备注、行仍有效
    ///
    /// M-3（dev-reviewer 2026-10-16 归因=生产行为按审查修正）：otpauth 解析失败
    /// 的 warnings 已脱敏——只留摘要 + 行号，不得携带原始 otpauth/secret 片段。
    #[test]
    fn 既有警告语义复用() {
        let st = store();
        let csv = concat!(
            "Title,Website,Username,Password,One-time password\n",
            ",https://example.com,alice,pw,otpauth://totp/x?secret=BAD!!\n",
        );
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert!(analysis.warnings.iter().any(|w| w.contains("缺失 Title")));
        assert!(analysis.warnings.iter().any(|w| w.contains("One-time password 无法解析")));
        assert!(
            analysis.warnings.iter().all(|w| !w.contains("BAD!!") && !w.contains("secret=")),
            "warnings 不得含原始 otpauth/secret 片段（M-3 脱敏）：{warnings:?}",
            warnings = analysis.warnings
        );
        assert_eq!(analysis.valid_rows, 1);
        assert_eq!(analysis.rows[0].title, "（无标题）");
    }

    /// M-3 脱敏：otpauth 解析失败 warnings 不得携带原始 URI/参数片段
    /// （TOTP secret 同属凭据，R2 精神同等适用）
    #[test]
    fn otpauth解析失败warnings脱敏() {
        let st = store();
        // period 参数非法 → 原 parse_otpauth 错误会回显「period 参数无效：{v}」原值
        // （mapping.rs C-4 红线不动），dropzone 侧 warnings 必须只留脱敏摘要
        let csv = concat!(
            "Title,Website,Username,Password,One-time password\n",
            "X,https://x.example,u1,pw,",
            "otpauth://totp/X:u1?secret=JBSWY3DPEHPK3PXP&period=abcSECRETMARKER\n",
        );
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        let warn = analysis
            .warnings
            .iter()
            .find(|w| w.contains("无法解析"))
            .expect("须有 OTP 解析失败告警");
        assert!(warn.contains("第 2 行"), "脱敏摘要须带行号：{warn}");
        assert!(
            !warn.contains("abcSECRETMARKER") && !warn.contains("otpauth://") && !warn.contains("secret"),
            "warnings 不得含原始 URI/参数/secret 片段：{warn}"
        );
        assert_eq!(analysis.valid_rows, 1, "解析失败不丢行，值并入备注");
    }

    /// 未识别列进报告（不静默丢弃，值并入备注）
    #[test]
    fn 未识别列进报告() {
        let st = store();
        let csv = "Title,Website,Username,Password,SecretQ\nGitHub,https://github.com,octocat,pw,yes\n";
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(analysis.unmapped_columns, vec!["SecretQ".to_owned()]);
    }

    /// URL 规范化参与匹配：协议/大小写/路径差异仍归 Duplicate
    #[test]
    fn url规范化参与匹配() {
        let mut st = store();
        seed(
            &mut st,
            &[model("GitHub", Some("https://github.com/octocat"), Some("octocat"))],
        );
        let csv = "Title,Website,Username,Password\nGitHub,HTTP://GITHUB.COM,octocat,pw\n";
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(analysis.rows[0].category, DedupCategory::Duplicate);
    }

    /// R2：密码不参与匹配；报告面（Debug 输出）不得含密码明文
    #[test]
    fn 密码不参与匹配() {
        let mut st = store();
        seed(
            &mut st,
            &[model("GitHub", Some("https://github.com"), Some("octocat"))],
        );
        let csv = "Title,Website,Username,Password\nGitHub,https://github.com,octocat,DIFFERENT_PW\n";
        let f = write_csv(csv);
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(
            analysis.rows[0].category,
            DedupCategory::Duplicate,
            "密码差异不影响三元组匹配（R2：密码不作匹配键）"
        );
        let debug_out = format!("{analysis:?}");
        assert!(!debug_out.contains("DIFFERENT_PW"), "报告面不得含密码明文");
    }

    /// 行号 drift fail-closed：include 行号在重解析后缺失 → 拒绝且零写入
    #[test]
    fn 行号drift失败关闭() {
        let mut st = store();
        let csv = "Title,Username\nGitHub,octocat\nGitLab,bob\n";
        let f = write_csv(csv);
        let err = import_dropzone(f.path(), &[2, 99], &mut st).unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("重新预检")));
        assert_eq!(st.repos().items.count(None).unwrap(), 0, "drift 拒绝必须零写入");
    }

    /// include 空集 → 导入 0 条
    #[test]
    fn include空集导入零条() {
        let mut st = store();
        let csv = "Title,Username\nGitHub,octocat\n";
        let f = write_csv(csv);
        let result = import_dropzone(f.path(), &[], &mut st).unwrap();
        assert_eq!(result.imported_rows, 0);
        assert_eq!(st.repos().items.count(None).unwrap(), 0);
    }

    /// 选择集导入：跳过重复行，只导入选中的非空行（单事务、计数正确）
    #[test]
    fn 选择集导入仅导入选中的非空行() {
        let mut st = store();
        seed(
            &mut st,
            &[model("GitHub", Some("https://github.com"), Some("octocat"))],
        );

        let csv = concat!(
            "Title,Website,Username,Password,Notes\n",
            "GitHub,https://github.com,octocat,pw1,\n",    // 行2：duplicate
            "\n",                                           // 行3：全空行
            "Example,https://example.com,alice,pw2,note\n", // 行4：new
            "GitHub,https://github.com,bob,pw3,\n",         // 行5：conflict
        );
        let f = write_csv(csv);

        // 预检：total 含全空行，valid 不含
        let analysis = analyze_dropzone(f.path(), &st).unwrap();
        assert_eq!(analysis.total_rows, 4);
        assert_eq!(analysis.valid_rows, 3);
        assert_eq!(analysis.rows.len(), 3);
        let line_nos: Vec<u32> = analysis.rows.iter().map(|r| r.line_no).collect();
        assert_eq!(line_nos, vec![2, 4, 5]);

        // 只导入行 4、5（跳过重复行 2）
        let result = import_dropzone(f.path(), &[4, 5], &mut st).unwrap();
        assert_eq!(result.imported_rows, 2);

        let repos = st.repos();
        assert_eq!(repos.items.count(None).unwrap(), 3, "原有 1 + 导入 2");
        let all = repos.items.list(&ItemListFilter::default()).unwrap();
        let titles: Vec<&str> = all.iter().map(|i| i.title.expose()).collect();
        assert!(titles.contains(&"Example"));
        assert!(titles.contains(&"GitHub"));
    }

    /// 格式拒绝：无可识别表头 → ImportUnknownFormat（与 CSV 预检同语义）
    #[test]
    fn 非csv文件拒绝() {
        let st = store();
        let f = write_csv("not,headers\n1,2\n");
        let err = analyze_dropzone(f.path(), &st).unwrap_err();
        assert!(matches!(err, CfError::ImportUnknownFormat));
    }
}
