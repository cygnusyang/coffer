//! 预检报告（`docs/07-macOS纵切设计.md` §3.3 最小形态）。
//!
//! [`precheck_csv`]（只读、可反复调用）产出 [`CsvPrecheckReport`] 供 UI
//! 展示；[`analyze_csv`] 同时产出映射后的 [`ImportModel`] 列表——
//! **预检与导入复用同一条解析/映射管线**，保证报告所见即导入所得
//! （docs/07 §3.3 流程：precheck → 用户确认 → import）。
//!
//! ## 报告语义
//!
//! - `total_rows`：数据行总数（不含表头，**含**全空行）；
//! - `valid_rows`：可导入行数（不含全空行；含带告警的行——坏 otpauth、
//!   公式前缀、非法 bool 都不阻止该行导入）；
//! - 行号一律是文件行号（1 起，表头为第 1 行）；
//! - 公式注入：**不修改原值**，仅告警（docs/07 §3.2，防护主战场在导出侧）；
//! - 重名：仅 warnings 提示计数，导入固定「全部新建」，不逐条打断
//!   （docs/07 §6.2 Q-3 裁定）。

use std::collections::HashMap;
use std::path::Path;

use cf_domain::CfError;

use crate::csv::mapping::{self, ImportModel};
use crate::csv::parser;

/// 预检报告（最小形态，字段与 docs/07 §3.3 的结构体逐项一致）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsvPrecheckReport {
    /// 数据行总数（不含表头，含全空行）。
    pub total_rows: u32,
    /// 可导入行数（不含全空行；含带告警的行）。
    pub valid_rows: u32,
    /// 全空行号（文件行号，1 起、表头为第 1 行）。
    pub skipped_rows: Vec<u32>,
    /// 缺失 Title 的行号（导入时以「（无标题）」兜底）。
    pub rows_without_title: Vec<u32>,
    /// otpauth 解析失败的行号（原始值并入 Notes，行本身仍导入）。
    pub rows_with_bad_totp: Vec<u32>,
    /// 未识别的数据列名（其非空值并入 Notes，不静默丢弃）。
    pub unmapped_columns: Vec<String>,
    /// 疑似公式注入单元格：(行号, 列名)。原值保留，仅告警。
    pub formula_like_cells: Vec<(u32, String)>,
    /// 告警文本（公式注入、非法 bool、重复标题、多余列等）。
    pub warnings: Vec<String>,
}

/// 预检 + 映射的完整产物（导入编排复用，保证报告与导入一致）。
#[derive(Debug, Clone)]
pub struct CsvAnalysis {
    /// 预检报告。
    pub report: CsvPrecheckReport,
    /// 全部可导入行的中间表示（顺序 = 文件行序）。
    pub models: Vec<ImportModel>,
}

/// 读取并预检一个 CSV 文件（只读，可反复调用）。
///
/// # Errors
///
/// 文件读不出 → [`CfError::Io`]；解析/表头/上限失败 →
/// [`CfError::ImportFailed`] / [`CfError::ImportUnknownFormat`]。
pub fn read_and_analyze(path: &Path) -> Result<CsvAnalysis, CfError> {
    let bytes = std::fs::read(path).map_err(|e| CfError::Io(format!("读取 CSV 失败：{e}")))?;
    analyze_csv(&bytes)
}

/// 预检内存中的 CSV 字节流（测试与编排复用）。
///
/// # Errors
///
/// 同 [`precheck_csv`]（去掉文件读取）。
pub fn analyze_csv(bytes: &[u8]) -> Result<CsvAnalysis, CfError> {
    analyze_parsed(parser::parse_csv(bytes)?)
}

/// 对已解析的 CSV 做表头识别、逐行映射与报告汇总。
fn analyze_parsed(parsed: parser::ParsedCsv) -> Result<CsvAnalysis, CfError> {
    let header = mapping::analyze_header(&parsed.header)?;

    let mut report = CsvPrecheckReport {
        unmapped_columns: header.unmapped.iter().map(|(_, n)| n.clone()).collect(),
        ..Default::default()
    };

    let mut models: Vec<ImportModel> = Vec::new();
    let mut title_counts: HashMap<String, u32> = HashMap::new();

    for row in &parsed.rows {
        report.total_rows += 1;

        // 全空行跳过（docs/07 §3.2）
        if row.cells.iter().all(|c| c.is_empty()) {
            report.skipped_rows.push(row.line_no);
            continue;
        }

        let (model, signals) = mapping::map_row(&header, row);
        *title_counts.entry(model.title.clone()).or_insert(0) += 1;
        report.valid_rows += 1;

        if signals.no_title {
            report.rows_without_title.push(row.line_no);
            report.warnings.push(format!(
                "第 {} 行：缺失 Title，导入时以「{}」兜底",
                row.line_no,
                mapping::FALLBACK_TITLE
            ));
        }

        if signals.bad_totp {
            report.rows_with_bad_totp.push(row.line_no);
            report.warnings.push(format!(
                "第 {} 行：One-time password 无法解析（{}），原始值已并入备注，该行仍导入",
                row.line_no,
                signals.bad_totp_reason.as_deref().unwrap_or("原因未知")
            ));
        }

        for col in signals.invalid_bool_columns {
            report.warnings.push(format!(
                "第 {} 行：{col} 值不是 true/false，按 false 处理",
                row.line_no
            ));
        }

        if signals.ragged_extra_count > 0 {
            report.warnings.push(format!(
                "第 {} 行：数据比表头多 {} 列，多出的非空值已并入备注",
                row.line_no, signals.ragged_extra_count
            ));
        }

        for (line, col) in &signals.formula_cells {
            report.formula_like_cells.push((*line, col.clone()));
            report.warnings.push(format!(
                "第 {line} 行：列「{col}」的值以公式前缀字符（= + - @ Tab）开头，\
                 若导出为 CSV 时将被转义（导入保留原值）"
            ));
        }

        models.push(model);
    }

    // 重名：仅预检提示计数，不逐条打断（docs/07 §6.2 Q-3）
    let dup_titles = title_counts.values().filter(|&&c| c > 1).count();
    if dup_titles > 0 {
        let dup_rows: u32 = title_counts.values().filter(|&&c| c > 1).sum();
        report.warnings.push(format!(
            "检测到 {dup_titles} 个重复标题（涉及 {dup_rows} 行），导入将全部新建，不做去重"
        ));
    }

    Ok(CsvAnalysis { report, models })
}
