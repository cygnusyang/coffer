//! 导入后源文件删除建议（FR-7.8，`docs/01`；裁决基线 docs/09 §6 D-6）。
//!
//! ## D-6 数据驱动裁决
//!
//! FR-7.8 原措辞是导入完成后无条件强制删源；D-6（lead 采纳为实施
//! 基线）改为**数据驱动**：当且仅当预检报告已完整 surface 的导入
//! 过程**零信息损失**（无未导入项、无已导入但降级项）时，才提示
//! 可删除源文件；否则提示保留，并逐条列出降级/未导入原因。
//!
//! ## 为什么只接收预检报告、不接收导入结果
//!
//! PUX 为每条目独立事务，任一条目失败整个导入返回 `Err`（无结果
//! 可言）；CSV 为单事务 all-or-nothing。故成功路径上「实际导入数」
//! 与预检报告的 `importable_items` / `valid_rows` 必然一致，导入
//! 结果类型不携带本判断所需的额外信息——不为此编造参数。
//!
//! ## 格式裁决明细
//!
//! - 1PUX 拦截项（任一命中即不可删）：
//!   - `not_imported` 非空（Tombstone、附件内容缺失等，数据未入库）；
//!   - `unknown_categories` 非空（已降级为安全笔记，结构信息丢失）；
//!   - `unmapped_value_types` 非空（值并入备注，字段结构丢失）；
//!   - `password_history_dropped > 0`（历史条目未迁移，FR-2.9）。
//!   - `trashed_count` / `duplicate_document_ids` **不拦**：回收站
//!     按语义导入、重复 documentId 全部保留，均无信息损失。
//! - CSV 拦截项：
//!   - `rows_with_bad_totp` 非空（TOTP 未成为可用字段，原值并入备注）；
//!   - `unmapped_columns` 非空（未知列值并入备注，结构丢失）。
//!   - `formula_like_cells` **不拦**（docs/07 §3.2：原值原样导入，
//!     防护在导出侧转义）；`skipped_rows` **不拦**（全空行无数据）；
//!     `rows_without_title` **不拦**（源本无标题，兜底不构成损失）。
//! - 空导入（0 条成功 0 条失败）→ **提示保留**：删除无收益且不可
//!   恢复，且空导入可能是源文件异常的前兆，保守裁决。
//!
//! ## 已知缺口（上报项，不在本次修复）
//!
//! 1. **CSV「非法 bool 值按 false 处理」**：仅存在于 `warnings` 文本，
//!    无结构化字段（原始值被丢弃、构成信息损失但无法从报告结构化
//!    判定）；待预检报告补结构化字段后再纳入拦截条件。
//! 2. **PUX「坏 otpauth 并入 notes」（v0.3 审查 H-1 登记）**：TOTP
//!    字段解析失败时原值并入 notes（`pux/mapping.rs`），TOTP 结构
//!    丢失但 notes 保有原值，`PuxPrecheckReport` 仅 warnings 文本、
//!    无结构化字段 → 本函数**不拦截**（与缺口 1 同待遇，明确推后）；
//!    行为由测试 `pux坏otpauth并入notes不拦截缺口声明` 锁定。
//! 3. **PUX「未知 state 按 active 处理」（v0.3 审查 LOW 登记）**：
//!    原始 state 值被丢弃，极小元数据损失，同待遇推后。

use crate::precheck::CsvPrecheckReport;
use crate::pux::PuxPrecheckReport;

/// 源文件删除建议（FR-7.8 结果页素材）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDeletionAdvice {
    /// 当且仅当本次导入零信息损失时为 true（可提示删除源文件）。
    pub can_delete: bool,
    /// 阻止删除的原因（人类可读，逐条，供结果页直接展示）。
    pub blockers: Vec<String>,
    /// 已导入但降级的条目：(条目 uuid 或 CSV 行号, 降级原因)。
    ///
    /// 仅收录报告中有条目级标识的降级项；计数型损失（如密码历史
    /// 条数）无条目 uuid，只在 [`Self::blockers`] 中说明。
    pub degraded_items: Vec<(String, String)>,
}

/// 依据 1PUX 预检报告给出源文件删除建议（传入 [`crate::pux::PuxImportResult::report`]）。
pub fn advise_pux_source_deletion(report: &PuxPrecheckReport) -> SourceDeletionAdvice {
    let mut advice = SourceDeletionAdvice {
        can_delete: true,
        blockers: Vec::new(),
        degraded_items: Vec::new(),
    };

    // 空导入：0 条成功 0 条失败 → 保守裁决保留（模块注释「空导入」条目）
    if report.total_items == 0 {
        advice.can_delete = false;
        advice.blockers.push(
            "本次导入未写入任何条目（0 条成功、0 条失败），删除源文件无收益且不可恢复，建议保留"
                .into(),
        );
        return advice;
    }

    // 未导入项：数据未入库，逐条列出（标题 + uuid + 原因）
    for item in &report.not_imported {
        advice.can_delete = false;
        advice.blockers.push(format!(
            "条目「{}」（{}）未导入：{}",
            item.title, item.uuid, item.reason
        ));
    }

    // 未识别类别：已降级为安全笔记（结构信息丢失），逐条进 degraded_items，
    // blockers 聚合一条（uuid 来自报告，不猜类别名）
    for (uuid, category) in &report.unknown_categories {
        advice.can_delete = false;
        advice.degraded_items.push((
            uuid.clone(),
            format!("未识别类别 {category}，已降级导入为安全笔记（数据并入备注）"),
        ));
    }
    if !report.unknown_categories.is_empty() {
        advice.can_delete = false;
        let uuids: Vec<&str> = report
            .unknown_categories
            .iter()
            .map(|(uuid, _)| uuid.as_str())
            .collect();
        advice.blockers.push(format!(
            "{} 条未识别类别已降级为安全笔记（数据并入备注）：{}",
            report.unknown_categories.len(),
            uuids.join("、")
        ));
    }

    // 未识别的字段值类型：值并入备注、字段结构丢失（无条目级标识，仅 blockers）
    if !report.unmapped_value_types.is_empty() {
        advice.can_delete = false;
        advice.blockers.push(format!(
            "存在 {} 种未识别的字段值类型（值已并入备注、字段结构丢失）：{}",
            report.unmapped_value_types.len(),
            report.unmapped_value_types.join("、")
        ));
    }

    // 密码历史：未迁移（FR-2.9 语义不同构），源文件中仍有而库中没有
    if report.password_history_dropped > 0 {
        advice.can_delete = false;
        advice.blockers.push(format!(
            "丢弃 {} 条密码历史（cf 历史表语义不同构，FR-2.9），源文件中仍有",
            report.password_history_dropped
        ));
    }

    advice
}

/// 依据 CSV 预检报告给出源文件删除建议（传入 [`crate::precheck_csv`] 的报告）。
pub fn advise_csv_source_deletion(report: &CsvPrecheckReport) -> SourceDeletionAdvice {
    let mut advice = SourceDeletionAdvice {
        can_delete: true,
        blockers: Vec::new(),
        degraded_items: Vec::new(),
    };

    // 空导入：与 PUX 空库同裁决（保守保留）
    if report.total_rows == 0 {
        advice.can_delete = false;
        advice.blockers.push(
            "本次导入未写入任何条目（0 条成功、0 条失败），删除源文件无收益且不可恢复，建议保留"
                .into(),
        );
        return advice;
    }

    // 坏 otpauth 行：TOTP 未成为可用字段（原值并入备注），逐行进
    // degraded_items 与 blockers（行号即条目标识）
    for line in &report.rows_with_bad_totp {
        advice.can_delete = false;
        advice.degraded_items.push((
            line.to_string(),
            "One-time password 未解析为可用 TOTP 字段（原值已并入备注）".into(),
        ));
        advice.blockers.push(format!(
            "第 {line} 行：One-time password 未解析为可用 TOTP 字段（原值已并入备注）"
        ));
    }

    // 未识别列：值并入备注、结构丢失（列级信息，无条目级标识，仅 blockers）
    if !report.unmapped_columns.is_empty() {
        advice.can_delete = false;
        advice.blockers.push(format!(
            "{} 个未识别列的值已并入备注（字段结构丢失）：{}",
            report.unmapped_columns.len(),
            report.unmapped_columns.join("、")
        ));
    }

    advice
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- 1PUX 侧 ----------

    /// 全净导入（无未导入、无任何降级）→ 可删除
    #[test]
    fn pux_全净导入可删除() {
        let report = PuxPrecheckReport {
            total_items: 5,
            importable_items: 5,
            ..Default::default()
        };
        let advice = advise_pux_source_deletion(&report);
        assert!(advice.can_delete);
        assert!(advice.blockers.is_empty());
        assert!(advice.degraded_items.is_empty());
    }

    /// 含未识别类别降级 → 不可删，blockers 与 degraded_items 逐条列出
    #[test]
    fn pux_未识别类别降级不可删() {
        let report = PuxPrecheckReport {
            total_items: 3,
            importable_items: 3,
            unknown_categories: vec![
                ("SYNTH-aaa".into(), "custom.cat.x".into()),
                ("SYNTH-bbb".into(), "legacy.y".into()),
            ],
            ..Default::default()
        };
        let advice = advise_pux_source_deletion(&report);
        assert!(!advice.can_delete);
        assert!(
            advice
                .blockers
                .iter()
                .any(|b| b.contains("2 条未识别类别") && b.contains("SYNTH-aaa")),
            "blockers 应聚合列出降级条目 uuid：{:?}",
            advice.blockers
        );
        assert_eq!(advice.degraded_items.len(), 2);
        assert!(advice
            .degraded_items
            .iter()
            .any(|(uuid, reason)| uuid == "SYNTH-aaa" && reason.contains("custom.cat.x")));
    }

    /// 含未导入项（Tombstone / 附件缺失）→ 不可删，原因含标题与理由
    #[test]
    fn pux_未导入项不可删() {
        let report = PuxPrecheckReport {
            total_items: 2,
            importable_items: 1,
            not_imported: vec![crate::pux::NotImportedItem {
                uuid: "SYNTH-del".into(),
                title: "已删除条目".into(),
                reason: "Tombstone 已删除标记".into(),
            }],
            ..Default::default()
        };
        let advice = advise_pux_source_deletion(&report);
        assert!(!advice.can_delete);
        assert!(advice.blockers.iter().any(|b| b.contains("已删除条目")
            && b.contains("SYNTH-del")
            && b.contains("Tombstone")));
        assert!(advice.degraded_items.is_empty(), "未导入不是降级导入");
    }

    /// 丢弃密码历史 → 不可删
    #[test]
    fn pux_密码历史丢弃不可删() {
        let report = PuxPrecheckReport {
            total_items: 1,
            importable_items: 1,
            password_history_dropped: 4,
            ..Default::default()
        };
        let advice = advise_pux_source_deletion(&report);
        assert!(!advice.can_delete);
        assert!(advice
            .blockers
            .iter()
            .any(|b| b.contains("4") && b.contains("密码历史")));
    }

    /// 未识别的字段值类型 → 不可删（值并入备注、结构丢失）
    #[test]
    fn pux_未识别值类型不可删() {
        let report = PuxPrecheckReport {
            total_items: 1,
            importable_items: 1,
            unmapped_value_types: vec!["someCustomType".into()],
            ..Default::default()
        };
        let advice = advise_pux_source_deletion(&report);
        assert!(!advice.can_delete);
        assert!(advice.blockers.iter().any(|b| b.contains("someCustomType")));
    }

    /// 回收站条目与重复 documentId 不拦（无信息损失，裁决见模块注释）
    #[test]
    fn pux_回收站与重复文档不拦() {
        let report = PuxPrecheckReport {
            total_items: 3,
            importable_items: 3,
            trashed_count: 1,
            duplicate_document_ids: vec!["doc-1".into()],
            ..Default::default()
        };
        assert!(advise_pux_source_deletion(&report).can_delete);
    }

    /// 空库导入（0 条成功 0 条失败）→ 提示保留（裁决：删除无收益且不可恢复）
    #[test]
    fn pux_空库导入提示保留() {
        let report = PuxPrecheckReport::default();
        let advice = advise_pux_source_deletion(&report);
        assert!(!advice.can_delete);
        assert!(!advice.blockers.is_empty(), "须给出保留理由");
    }

    // ---------- CSV 侧 ----------

    /// CSV 全净导入 → 可删除
    #[test]
    fn csv_全净导入可删除() {
        let report = CsvPrecheckReport {
            total_rows: 3,
            valid_rows: 3,
            ..Default::default()
        };
        let advice = advise_csv_source_deletion(&report);
        assert!(advice.can_delete);
        assert!(advice.blockers.is_empty());
        assert!(advice.degraded_items.is_empty());
    }

    /// 含坏 otpauth 行 → 不可删（TOTP 未成为可用字段），degraded_items 按行号
    #[test]
    fn csv_坏totp行不可删() {
        let report = CsvPrecheckReport {
            total_rows: 2,
            valid_rows: 2,
            rows_with_bad_totp: vec![3, 7],
            ..Default::default()
        };
        let advice = advise_csv_source_deletion(&report);
        assert!(!advice.can_delete);
        assert_eq!(advice.degraded_items.len(), 2);
        assert!(advice
            .blockers
            .iter()
            .any(|b| b.contains("第 3 行") && b.contains("One-time password")));
    }

    /// 含未识别列 → 不可删（值并入备注、结构丢失），blocker 列出列名
    #[test]
    fn csv_未识别列不可删() {
        let report = CsvPrecheckReport {
            total_rows: 1,
            valid_rows: 1,
            unmapped_columns: vec!["Custom Field".into(), "extra".into()],
            ..Default::default()
        };
        let advice = advise_csv_source_deletion(&report);
        assert!(!advice.can_delete);
        assert!(advice
            .blockers
            .iter()
            .any(|b| b.contains("Custom Field") && b.contains("extra")));
    }

    /// 公式单元格 / 全空行 / 缺标题不拦（裁决见模块注释：均无信息损失）
    #[test]
    fn csv_公式空行缺标题不拦() {
        let report = CsvPrecheckReport {
            total_rows: 5,
            valid_rows: 3,
            skipped_rows: vec![2],
            rows_without_title: vec![4],
            formula_like_cells: vec![(5, "Notes".into())],
            ..Default::default()
        };
        assert!(advise_csv_source_deletion(&report).can_delete);
    }

    /// 空表导入 → 提示保留（与 PUX 空库同裁决）
    #[test]
    fn csv_空表导入提示保留() {
        let report = CsvPrecheckReport::default();
        let advice = advise_csv_source_deletion(&report);
        assert!(!advice.can_delete);
        assert!(!advice.blockers.is_empty());
    }

    /// 已知缺口声明锁定（v0.3 审查 H-1）：PUX 坏 otpauth 并入 notes
    /// 的信息损失目前仅存在于 `warnings` 文本、无结构化字段——本测试
    /// 锁定「warnings 有坏 otpauth 记录但 can_delete 仍为 true」的
    /// 现状，防止未来误以为已拦截；待 PuxPrecheckReport 补结构化
    /// 字段后本测试应改为拦截断言（与 CSV 非法 bool 同待遇）。
    #[test]
    fn pux坏otpauth并入notes不拦截缺口声明() {
        // 非空导入（避开空导入保守分支），正常条目 1 条；
        // 坏 otpauth 场景在报告上的唯一痕迹是 warnings 文本
        let report = PuxPrecheckReport {
            total_items: 1,
            importable_items: 1,
            warnings: vec![
                "条目 0197xxxx：otpauth 解析失败，原值已并入 notes（TOTP 结构丢失）".into(),
            ],
            ..Default::default()
        };
        let advice = advise_pux_source_deletion(&report);
        assert!(advice.can_delete, "缺口声明：warnings 文本不参与拦截");
        assert!(advice.degraded_items.is_empty());
    }
}
