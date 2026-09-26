//! 9 列映射（`docs/07-macOS纵切设计.md` §3.2，对齐 docs/03 §6.4.4）。
//!
//! 1Password 9 列 CSV → [`ImportModel`]（导入中间表示）：
//!
//! | CSV 列 | 映射目标 |
//! | --- | --- |
//! | Title | `items.enc_title` |
//! | Website | `urls`（is_primary=1） |
//! | Username | field(designation=Username) |
//! | Password | field(designation=Password, type=Concealed) |
//! | One-time password | otpauth URI 解析（cf-totp 边界校验）→ totp 表 |
//! | Favorite status | `items.is_favorite` |
//! | Archived status | `items.state`（仅接受 true/false） |
//! | Tags | `tags`（逗号/分号分隔） |
//! | Notes | field(designation=NotesPlain, type=Multiline) |
//!
//! ## 不静默丢弃原则
//!
//! - 未知表头的数据列：列名记入预检报告 `unmapped_columns`，
//!   非空值并入该条目 Notes（前缀「[未映射列 <名>]」）；
//! - otpauth 解析失败的单元格：原始值并入 Notes 并告警，**不丢整行**；
//! - 缺失 Title 的行：告警，导入时以「（无标题）」兜底。
//!
//! ## 公式注入（导入侧）
//!
//! 以 `= + - @ \t` 开头的 Username / Notes / 未映射列值**保留原值存储**
//! （数据完整性优先），仅产出 `(行号, 列名)` 告警素材；Password 列不告警
//! （docs/07 §3.2）。防护主战场在导出侧（v0.2 导出时加 `'` 前缀）。

use std::collections::HashMap;

use cf_domain::CfError;

use super::parser::CsvRow;

/// 表头规范名：Title。
pub const HEADER_TITLE: &str = "title";
/// 表头规范名：Website。
pub const HEADER_WEBSITE: &str = "website";
/// 表头规范名：Username。
pub const HEADER_USERNAME: &str = "username";
/// 表头规范名：Password。
pub const HEADER_PASSWORD: &str = "password";
/// 表头规范名：One-time password。
pub const HEADER_OTP: &str = "one-time password";
/// 表头规范名：Favorite status。
pub const HEADER_FAVORITE: &str = "favorite status";
/// 表头规范名：Archived status。
pub const HEADER_ARCHIVED: &str = "archived status";
/// 表头规范名：Tags。
pub const HEADER_TAGS: &str = "tags";
/// 表头规范名：Notes。
pub const HEADER_NOTES: &str = "notes";

/// 全部 9 个规范列名（表头识别白名单，大小写不敏感匹配）。
const CANONICAL_HEADERS: [&str; 9] = [
    HEADER_TITLE,
    HEADER_WEBSITE,
    HEADER_USERNAME,
    HEADER_PASSWORD,
    HEADER_OTP,
    HEADER_FAVORITE,
    HEADER_ARCHIVED,
    HEADER_TAGS,
    HEADER_NOTES,
];

/// 缺失 Title 的行的兜底标题（docs/07 §3.2）。
pub const FALLBACK_TITLE: &str = "（无标题）";

/// 公式注入前缀字符（docs/07 §3.2：`= + - @ \t`）。
const FORMULA_PREFIXES: [char; 5] = ['=', '+', '-', '@', '\t'];

/// otpauth URI 解析结果（totp 表写入素材）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpauthData {
    /// Base32 解码后的共享密钥原始字节（≥ 10 字节，80-bit 下限）。
    pub secret: Vec<u8>,
    /// 验证码位数（6 或 8）。
    pub digits: u8,
    /// 时间窗口秒数（默认 30）。
    pub period: u32,
    /// 发行方（otpauth 的 issuer 参数，缺省取路径标签冒号前段）。
    pub issuer: Option<String>,
    /// 账户名（路径标签冒号后段）。
    pub account: Option<String>,
}

/// 一行 CSV 映射出的导入中间表示（ImportModel，docs/03 §6 职责边界）。
///
/// cf-importer **不直接写库**——由导入编排层（本 crate [`crate::import_models`]）
/// 在 `cf-store::ItemStore::with_tx` 单事务内写入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportModel {
    /// 条目标题（缺失 Title 的行已兜底为 [`FALLBACK_TITLE`]）。
    pub title: String,
    /// 主 URL（Website 列，非空才有）。
    pub url: Option<String>,
    /// 用户名（非空才有）。
    pub username: Option<String>,
    /// 密码（非空才有）。
    pub password: Option<String>,
    /// otpauth 解析成功的 TOTP 数据。
    pub totp: Option<OtpauthData>,
    /// 是否收藏。
    pub is_favorite: bool,
    /// 是否归档（Archived status = true）。
    pub archived: bool,
    /// 标签（逗号/分号分隔，已 trim、去空）。
    pub tags: Vec<String>,
    /// 备注（Notes 列原值 + 未映射列值 + 无法解析的 otpauth 原始值）。
    pub notes: String,
}

/// 单行映射产出的预检信号（报告素材；值本身不修改）。
#[derive(Debug, Clone, Default)]
pub struct RowMapSignals {
    /// 缺失 Title（导入时兜底）。
    pub no_title: bool,
    /// otpauth 解析失败（原始值已并入 Notes）。
    pub bad_totp: bool,
    /// otpauth 解析失败原因（用于 warnings）。
    pub bad_totp_reason: Option<String>,
    /// bool 值非法的规范列名（仅接受 true/false，按 false 处理）。
    pub invalid_bool_columns: Vec<&'static str>,
    /// 行比表头多出的单元格数（其值已并入 Notes）。
    pub ragged_extra_count: usize,
    /// 疑似公式注入单元格：(行号, 列名)。
    pub formula_cells: Vec<(u32, String)>,
}

/// 表头 → 列索引映射（分析产物，复用于全部数据行）。
#[derive(Debug, Clone)]
pub struct HeaderMap {
    /// 规范列名 → 列下标。
    idx: HashMap<&'static str, usize>,
    /// 未识别的数据列：(列下标, 原始列名 trim 后)。
    pub unmapped: Vec<(usize, String)>,
    /// 表头总列数（判断数据行是否比表头多列）。
    pub total_columns: usize,
}

impl HeaderMap {
    /// 查规范列的列下标。
    #[must_use]
    pub fn index_of(&self, canonical: &str) -> Option<usize> {
        self.idx.get(canonical).copied()
    }
}

/// 表头识别（docs/07 §3.2）。
///
/// 大小写不敏感匹配 9 个规范列名；存在重复规范列 → 整文件拒绝；
/// **一个规范列都认不出** → 整文件拒绝（`ImportUnknownFormat`，格式校验）。
/// 未识别的列记入 [`HeaderMap::unmapped`]（其值映射时并入 Notes，不丢弃）。
///
/// # Errors
///
/// 重复列名 → [`CfError::ImportFailed`]；无可识别列 →
/// [`CfError::ImportUnknownFormat`]。
pub fn analyze_header(header: &[String]) -> Result<HeaderMap, CfError> {
    let mut idx: HashMap<&'static str, usize> = HashMap::new();
    let mut unmapped: Vec<(usize, String)> = Vec::new();

    for (i, raw) in header.iter().enumerate() {
        let name = raw.trim().to_lowercase();
        let canonical = CANONICAL_HEADERS.iter().find(|c| **c == name.as_str());
        match canonical {
            Some(&c) => {
                if idx.insert(c, i).is_some() {
                    return Err(CfError::ImportFailed(format!(
                        "表头存在重复列：{c}"
                    )));
                }
            }
            None => {
                let display = if name.is_empty() { "(空列名)" } else { raw.trim() };
                unmapped.push((i, display.to_owned()));
            }
        }
    }

    if idx.is_empty() {
        return Err(CfError::ImportUnknownFormat);
    }

    Ok(HeaderMap {
        idx,
        unmapped,
        total_columns: header.len(),
    })
}

/// 值是否以公式前缀字符开头（docs/07 §3.2：`= + - @ \t`）。
#[must_use]
pub fn is_formula_like(value: &str) -> bool {
    FORMULA_PREFIXES.iter().any(|p| value.starts_with(*p))
}

/// 映射一行数据 → ([`ImportModel`], [`RowMapSignals`])。
///
/// 纯函数：不修改任何原值，只重组与打标。
#[must_use]
pub fn map_row(header: &HeaderMap, row: &CsvRow) -> (ImportModel, RowMapSignals) {
    let mut signals = RowMapSignals::default();

    // 按规范列名取单元格（行短于表头时视为空）
    let cell = |canonical: &str| -> Option<&str> {
        header
            .index_of(canonical)
            .and_then(|i| row.cells.get(i))
            .map(String::as_str)
    };
    let non_empty = |canonical: &str| -> Option<String> {
        cell(canonical)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    };

    // ---- Title（缺失 → 兜底，docs/07 §3.2） ----
    let title = match non_empty(HEADER_TITLE) {
        Some(t) => t,
        None => {
            signals.no_title = true;
            FALLBACK_TITLE.to_owned()
        }
    };

    // ---- Website → 主 URL ----
    let url = non_empty(HEADER_WEBSITE);

    // ---- Username（公式前缀检查） ----
    let username = non_empty(HEADER_USERNAME);
    if username.as_deref().is_some_and(is_formula_like) {
        signals
            .formula_cells
            .push((row.line_no, HEADER_USERNAME.to_owned()));
    }

    // ---- Password：公式前缀**不**告警（docs/07 §3.2 裁定） ----
    let password = non_empty(HEADER_PASSWORD);

    // ---- One-time password：合法 → totp；非法 → 原值并入 Notes ----
    let mut totp: Option<OtpauthData> = None;
    let mut notes_parts: Vec<String> = Vec::new();
    if let Some(raw) = non_empty(HEADER_OTP) {
        match parse_otpauth(&raw) {
            Ok(data) => totp = Some(data),
            Err(reason) => {
                signals.bad_totp = true;
                signals.bad_totp_reason = Some(reason);
                notes_parts
                    .push(format!("[One-time password 无法解析，已保留原始值] {raw}"));
            }
        }
    }

    // ---- Favorite / Archived（仅接受 true/false，非法按 false 并告警） ----
    let is_favorite = parse_bool_signal(cell(HEADER_FAVORITE), HEADER_FAVORITE, &mut signals);
    let archived = parse_bool_signal(cell(HEADER_ARCHIVED), HEADER_ARCHIVED, &mut signals);

    // ---- Tags（逗号/分号分隔，trim、去空） ----
    let tags: Vec<String> = cell(HEADER_TAGS)
        .map(|v| {
            v.split([',', ';'])
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    // ---- Notes（基础值 + 未映射列 + 多余列） ----
    let base_notes = cell(HEADER_NOTES).unwrap_or("");
    if !base_notes.is_empty() && is_formula_like(base_notes) {
        signals
            .formula_cells
            .push((row.line_no, HEADER_NOTES.to_owned()));
    }

    // 未映射列的非空值并入 Notes（列名已进 unmapped_columns，不静默丢弃）
    for (col_idx, col_name) in &header.unmapped {
        if let Some(v) = row.cells.get(*col_idx) {
            if v.is_empty() {
                continue;
            }
            if is_formula_like(v) {
                signals.formula_cells.push((row.line_no, col_name.clone()));
            }
            notes_parts.push(format!("[未映射列 {col_name}] {v}"));
        }
    }

    // 行比表头多出的单元格（畸形 CSV，值并入 Notes）
    let ragged = row.cells.len().saturating_sub(header.total_columns);
    signals.ragged_extra_count = ragged;
    for k in 0..ragged {
        let idx = header.total_columns + k;
        if let Some(v) = row.cells.get(idx) {
            if v.is_empty() {
                continue;
            }
            if is_formula_like(v) {
                signals
                    .formula_cells
                    .push((row.line_no, format!("第{}列(无表头)", idx + 1)));
            }
            notes_parts.push(format!("[未映射列 第{}列(无表头)] {v}", idx + 1));
        }
    }

    let mut notes = base_notes.to_owned();
    for part in notes_parts {
        if !notes.is_empty() {
            notes.push('\n');
        }
        notes.push_str(&part);
    }

    (
        ImportModel {
            title,
            url,
            username,
            password,
            totp,
            is_favorite,
            archived,
            tags,
            notes,
        },
        signals,
    )
}

/// bool 列解析：仅接受 `true` / `false`（大小写不敏感、可带空白），
/// 空与非法定值按 `false` 并记入告警信号。
fn parse_bool_signal(
    value: Option<&str>,
    column: &'static str,
    signals: &mut RowMapSignals,
) -> bool {
    let Some(v) = value else {
        return false;
    };
    match v.trim().to_lowercase().as_str() {
        "true" => true,
        "false" | "" => false,
        _ => {
            signals.invalid_bool_columns.push(column);
            false
        }
    }
}

/// 解析 otpauth://totp/ URI → [`OtpauthData`]。
///
/// 支持查询参数：`secret`（必需，Base32）、`issuer`、`period`（默认 30）、
/// `digits`（默认 6，仅允许 6/8）；未知参数忽略。路径标签
/// `otpauth://totp/Issuer:account` 在查询参数缺 issuer 时提供发行方。
///
/// v0.1 仅支持 totp（SHA-1）类型；`otpauth://hotp/` 等直接拒绝。
///
/// # Errors
///
/// 返回人类可读的失败原因（用于预检 warnings）。非法输入的单元格由
/// 调用方并入 Notes，**不丢弃**（docs/07 §3.2）。
///
/// # 与 cf-totp 的关系（实现备注）
///
/// `cf_totp::parse_totp_uri` 的历史缺陷（把 `?` 前路径当 secret 解码）
/// 已由 cf-totp 侧修复为标准 otpauth 解析。但本函数**不能整体切回**：
/// 导入路径还需要 `issuer` / `account` 提取（含路径标签兜底与 percent
/// 解码）与人类可读的 `String` 错误（用于预检 warnings），而
/// `TotpConfig` 不承载 issuer/account。因此本函数保留自己的参数解析，
/// 把**共享密钥的 Base32 解码委托**给 `cf_totp::base32_decode`——
/// 两条入口（解析 URI / 导入 CSV）的解码行为保证完全一致（严格
/// RFC 4648 字符集 + 规范填充校验，容忍省略填充的真实 otpauth 形式）。
pub fn parse_otpauth(uri: &str) -> Result<OtpauthData, String> {
    let uri = uri.trim();
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| "不是 otpauth:// URI".to_owned())?;
    let (type_part, tail) = rest
        .split_once('/')
        .ok_or_else(|| "otpauth URI 缺少路径".to_owned())?;
    if !type_part.eq_ignore_ascii_case("totp") {
        return Err(format!("仅支持 totp 类型（v0.1），收到 {type_part}"));
    }

    let (label, query) = match tail.split_once('?') {
        Some((l, q)) => (l, q),
        None => (tail, ""),
    };

    let mut secret: Option<String> = None;
    let mut issuer_param: Option<String> = None;
    let mut period: Option<u32> = None;
    let mut digits: Option<u8> = None;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("查询参数缺少值：{pair}"))?;
        match k {
            "secret" => secret = Some(percent_decode(v)),
            "issuer" => issuer_param = Some(percent_decode(v)),
            "period" => {
                period = Some(
                    v.parse::<u32>()
                        .map_err(|_| format!("period 参数无效：{v}"))?,
                );
            }
            "digits" => {
                let d = v
                    .parse::<u8>()
                    .map_err(|_| format!("digits 参数无效：{v}"))?;
                if d != 6 && d != 8 {
                    return Err(format!("digits 仅允许 6 或 8，收到 {d}"));
                }
                digits = Some(d);
            }
            _ => {} // 未知参数忽略（与 cf-totp 行为一致）
        }
    }

    let secret_b32 = secret.ok_or_else(|| "缺少 secret 参数".to_owned())?;

    // 路径标签 Issuer:account（查询参数的 issuer 优先）
    let mut issuer = issuer_param;
    let mut account: Option<String> = None;
    if !label.is_empty() {
        let decoded = percent_decode(label);
        match decoded.split_once(':') {
            Some((i, a)) => {
                if issuer.is_none() && !i.is_empty() {
                    issuer = Some(i.to_owned());
                }
                if !a.is_empty() {
                    account = Some(a.to_owned());
                }
            }
            None => {
                if !decoded.is_empty() {
                    account = Some(decoded);
                }
            }
        }
    }

    let period = period.unwrap_or(30);
    if period == 0 {
        return Err("period 必须为正整数".to_owned());
    }
    let digits = digits.unwrap_or(6);
    // Base32 解码委托 cf_totp（严格 RFC 4648），与 cf_totp::parse_totp_uri 同一实现
    let secret_bytes =
        cf_totp::base32_decode(&secret_b32).map_err(|e| e.to_string())?;

    // 边界校验（secret ≥ 10 字节、digits ∈ {6,8}）委托 cf-totp 门面
    cf_totp::TotpConfig::new(secret_bytes.clone(), period, digits)
        .map_err(|e| e.to_string())?;

    Ok(OtpauthData {
        secret: secret_bytes,
        digits,
        period,
        issuer,
        account,
    })
}

/// 最小 percent 解码（`%XX` → 字节）；非法序列原样保留。
/// （Base32 解码已委托 `cf_totp::base32_decode`，本模块不再保留重复实现。）
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h * 16) + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 表头识别：大小写不敏感 + 未知列入 unmapped
    #[test]
    fn 表头大小写不敏感与未知列() {
        let header: Vec<String> = [
            "TITLE",
            "website",
            " UserName ",
            "password",
            "One-Time Password",
            "favorite status",
            "ARCHIVED STATUS",
            "tags",
            "notes",
            "Custom X",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let map = analyze_header(&header).unwrap();
        assert_eq!(map.index_of(HEADER_TITLE), Some(0));
        assert_eq!(map.index_of(HEADER_OTP), Some(4));
        assert_eq!(map.unmapped, vec![(9, "Custom X".to_owned())]);
        assert_eq!(map.total_columns, 10);
    }

    /// 一个规范列都认不出 → 整文件拒绝
    #[test]
    fn 无可识别表头整文件拒绝() {
        let header: Vec<String> = ["foo", "bar"].iter().map(|s| (*s).to_owned()).collect();
        let err = analyze_header(&header).unwrap_err();
        assert!(matches!(err, CfError::ImportUnknownFormat));
    }

    /// 重复规范列 → 整文件拒绝
    #[test]
    fn 重复规范列拒绝() {
        let header: Vec<String> = ["title", "Title"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let err = analyze_header(&header).unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("重复列")));
    }

    fn header_map(headers: &[&str]) -> HeaderMap {
        let owned: Vec<String> = headers.iter().map(|s| (*s).to_owned()).collect();
        analyze_header(&owned).unwrap()
    }

    fn row(line: u32, cells: &[&str]) -> CsvRow {
        CsvRow {
            line_no: line,
            cells: cells.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// 完整 9 列映射：逐字段断言
    #[test]
    fn 九列完整映射逐字段() {
        let hm = header_map(&[
            "Title",
            "Website",
            "Username",
            "Password",
            "One-time password",
            "Favorite status",
            "Archived status",
            "Tags",
            "Notes",
        ]);
        let (m, s) = map_row(
            &hm,
            &row(
                2,
                &[
                    "GitHub",
                    "https://github.com",
                    "octocat",
                    "s3cret!",
                    "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                    "true",
                    "false",
                    "dev; 重要",
                    "Main account",
                ],
            ),
        );
        assert_eq!(m.title, "GitHub");
        assert_eq!(m.url.as_deref(), Some("https://github.com"));
        assert_eq!(m.username.as_deref(), Some("octocat"));
        assert_eq!(m.password.as_deref(), Some("s3cret!"));
        let totp = m.totp.unwrap();
        assert_eq!(
            totp.secret,
            vec![0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(totp.issuer.as_deref(), Some("GitHub"));
        assert_eq!(totp.account.as_deref(), Some("octocat"));
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.period, 30);
        assert!(m.is_favorite);
        assert!(!m.archived);
        assert_eq!(m.tags, vec!["dev", "重要"]);
        assert_eq!(m.notes, "Main account");
        assert!(!s.no_title);
        assert!(!s.bad_totp);
        assert!(s.formula_cells.is_empty());
    }

    /// 缺失 Title → 兜底标题 + 信号
    #[test]
    fn 缺失标题兜底() {
        let hm = header_map(&["Title", "Website", "Username", "Password", "One-time password", "Favorite status", "Archived status", "Tags", "Notes"]);
        let (m, s) = map_row(&hm, &row(3, &["", "https://x.example", "a", "b", "", "", "", "", ""]));
        assert_eq!(m.title, FALLBACK_TITLE);
        assert!(s.no_title);
    }

    /// 公式前缀：Username/Notes 告警，Password 不告警，原值保留
    #[test]
    fn 公式前缀告警与原值保留() {
        let hm = header_map(&["Title", "Website", "Username", "Password", "One-time password", "Favorite status", "Archived status", "Tags", "Notes"]);
        let (m, s) = map_row(
            &hm,
            &row(2, &["T", "", "=SUM(A1)", "=p=ss", "", "", "", "", "@cmd note"]),
        );
        assert_eq!(m.username.as_deref(), Some("=SUM(A1)"));
        assert_eq!(m.password.as_deref(), Some("=p=ss"));
        assert_eq!(m.notes, "@cmd note");
        let cols: Vec<&str> = s.formula_cells.iter().map(|(_, c)| c.as_str()).collect();
        assert_eq!(cols, vec![HEADER_USERNAME, HEADER_NOTES]);
    }

    /// 未知列非空值并入 Notes + 多余单元格并入 Notes
    #[test]
    fn 未知列与多余单元格并入备注() {
        let hm = header_map(&["Title", "Website", "Username", "Password", "One-time password", "Favorite status", "Archived status", "Tags", "Notes", "Secret Q"]);
        let (m, _) = map_row(
            &hm,
            &row(2, &["T", "", "", "", "", "", "", "", "base", "pet?", "extra"]),
        );
        assert_eq!(m.notes, "base\n[未映射列 Secret Q] pet?\n[未映射列 第11列(无表头)] extra");
    }

    /// 全空行不产生 title 兜底信号（跳过逻辑在预检层，此处验证映射无害）
    #[test]
    fn 空行映射() {
        let hm = header_map(&["Title", "Website", "Username", "Password", "One-time password", "Favorite status", "Archived status", "Tags", "Notes"]);
        let (m, s) = map_row(&hm, &row(2, &[""; 9]));
        assert_eq!(m.title, FALLBACK_TITLE);
        assert!(m.url.is_none());
        assert!(!m.is_favorite);
        assert!(s.no_title);
    }

    /// Tags 逗号/分号混用、去空、trim
    #[test]
    fn 标签分隔与去空() {
        let hm = header_map(&["Title", "Website", "Username", "Password", "One-time password", "Favorite status", "Archived status", "Tags", "Notes"]);
        let (m, _) = map_row(&hm, &row(2, &["T", "", "", "", "", "", "", " a;;b ,c", ""]));
        assert_eq!(m.tags, vec!["a", "b", "c"]);
    }

    /// bool 非法值按 false 处理并产生信号
    #[test]
    fn bool非法值信号() {
        let hm = header_map(&["Title", "Website", "Username", "Password", "One-time password", "Favorite status", "Archived status", "Tags", "Notes"]);
        let (_, s) = map_row(&hm, &row(4, &["T", "", "", "", "", "yes", "TRUE", "", ""]));
        assert_eq!(s.invalid_bool_columns, vec![HEADER_FAVORITE]);
        // "TRUE" 合法（大小写不敏感）
    }

    /// otpauth 合法 URI（含 issuer 参数优先、percent 解码）
    #[test]
    fn otpauth合法解析() {
        let d = parse_otpauth(
            "otpauth://totp/Label%20X:alice%40ex.com?secret=jbswy3dpehpk3pxp&issuer=My%20Bank&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(d.issuer.as_deref(), Some("My Bank"));
        assert_eq!(d.account.as_deref(), Some("alice@ex.com"));
        assert_eq!(d.digits, 8);
        assert_eq!(d.period, 60);
        assert_eq!(d.secret.len(), 10);
    }

    /// otpauth issuer 缺省时取路径标签冒号前段
    #[test]
    fn otpauth标签兜底issuer与account() {
        let d = parse_otpauth("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(d.issuer.as_deref(), Some("GitHub"));
        assert_eq!(d.account.as_deref(), Some("octocat"));
    }

    /// otpauth 非法：非 base32、secret 过短、digits 非法、缺 secret、错误类型
    #[test]
    fn otpauth非法输入逐一拒绝() {
        assert!(parse_otpauth("otpauth://totp/x?secret=NOT!!BASE32").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=AAAA").is_err(), "4 字符 = 2.5 字节 < 80 bits");
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5").is_err());
        assert!(parse_otpauth("otpauth://totp/x").is_err(), "缺 secret");
        assert!(parse_otpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err(), "v0.1 仅 totp");
        assert!(parse_otpauth("https://example.com").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
    }

    /// base32 非法字符（0/1/8/9）被拒绝——错解会产生永远错误的验证码
    #[test]
    fn base32非法字符拒绝() {
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PX0").is_err());
        assert!(parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PX1").is_err());
    }
}
