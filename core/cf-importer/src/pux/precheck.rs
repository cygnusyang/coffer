//! 1PUX 预检报告（FR-7.4~7.7，`docs/09` v0.3.0 冻结字段）。
//!
//! 与 CSV 预检同纪律：**预检与导入复用同一条解析/映射管线**（报告所见
//! 即导入所得），未导入项逐条列出、不静默丢弃（FR-7.6）。报告扩展字段：
//!
//! - `attachment_count`：附件总数（FR-7.4）；
//! - `unknown_categories`：未识别 `(条目 uuid, categoryUuid)` 清单
//!   （E-4：降级条目**计入导入成功**，不在未导入清单，但预检必须
//!   surface——D-6 删源提示条件依赖它）；
//! - `trashed_count` / `password_history_dropped` / `unmapped_value_types`
//!   / `duplicate_document_ids`；
//! - `not_imported`：Tombstone、附件内容缺失等无法导入项逐条列出。

use cf_domain::CfError;

use super::mapping::{map_item, ItemMapSignals, MapOutcome, PuxItemModel};
use super::parser::PuxArchive;

/// 预检报告（docs/09 v0.3.0 冻结字段集）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PuxPrecheckReport {
    /// 条目总数（全部 vault 合计，含 Tombstone / 附件缺失等未导入项）。
    pub total_items: u32,
    /// 可导入条目数（含未知类别降级——计入导入成功，E-4）。
    pub importable_items: u32,
    /// 按类别分布（降级条目按 secure_note 计入）。
    pub category_distribution: Vec<(String, u32)>,
    /// 附件总数。
    pub attachment_count: u32,
    /// 未识别类别清单：(条目 uuid, 原始 categoryUuid)。
    pub unknown_categories: Vec<(String, String)>,
    /// 回收站条目数（state=trashed）。
    pub trashed_count: u32,
    /// 丢弃的密码历史条目总数（FR-2.9 语义不同构）。
    pub password_history_dropped: u32,
    /// 未识别的类型化 value 顶层 key（去重排序；值已保留不丢）。
    pub unmapped_value_types: Vec<String>,
    /// 出现 ≥ 2 次的 documentId（官方形态；可能互为副本，导入全部保留）。
    pub duplicate_document_ids: Vec<String>,
    /// 未导入项逐条清单（FR-7.6 不静默丢弃）。
    pub not_imported: Vec<NotImportedItem>,
    /// 告警文本（降级、未知状态、坏 otpauth、重复 documentId 等）。
    pub warnings: Vec<String>,
}

/// 一条未导入项（FR-7.6 逐条列出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotImportedItem {
    /// 1PUX 原始条目 uuid。
    pub uuid: String,
    /// 标题（缺失时为兜底标题）。
    pub title: String,
    /// 未导入原因（人类可读）。
    pub reason: String,
}

/// 预检 + 映射的完整产物（导入编排复用）。
#[derive(Debug)]
pub struct PuxAnalysis {
    /// 预检报告。
    pub report: PuxPrecheckReport,
    /// 可导入条目的中间表示（顺序 = 1PUX 文件序）。
    pub models: Vec<PuxItemModel>,
}

/// 打开并预检一个 1PUX 文件（只读、可反复调用）。
///
/// # Errors
///
/// 同 [`PuxArchive::open`] / [`PuxArchive::parse`]。
pub fn read_and_analyze(path: &std::path::Path) -> Result<PuxAnalysis, CfError> {
    let mut archive = PuxArchive::open(path)?;
    analyze(&mut archive)
}

/// 预检一个已打开的 1PUX 归档（导入编排复用，避免二次打开）。
///
/// 流程：解析 JSON → 逐条映射（未知类别降级）→ 附件条目定位
/// （定位失败的条目转入 `not_imported`）→ 汇总报告。
///
/// # Errors
///
/// 容器 / JSON 层错误向上传播（整体拒绝，不落库）。
pub fn analyze(archive: &mut PuxArchive) -> Result<PuxAnalysis, CfError> {
    let model = archive.parse()?;

    let mut models: Vec<PuxItemModel> = Vec::new();
    let mut not_imported: Vec<NotImportedItem> = Vec::new();
    let mut unknown_categories: Vec<(String, String)> = Vec::new();
    let mut unmapped_value_types: Vec<String> = Vec::new();
    let mut password_history_dropped: u32 = 0;
    let mut trashed_count: u32 = 0;
    let mut warnings: Vec<String> = Vec::new();
    let mut total_items: u32 = 0;

    for account in &model.accounts {
        for vault in &account.vaults {
            for item in &vault.items {
                total_items += 1;
                let mut signals = ItemMapSignals::default();
                match map_item(item, &mut signals)? {
                    MapOutcome::Skipped(reason) => {
                        let title = item
                            .overview
                            .as_ref()
                            .and_then(|o| o.title.clone())
                            .unwrap_or_else(|| crate::csv::mapping::FALLBACK_TITLE.to_owned());
                        not_imported.push(NotImportedItem {
                            uuid: item.uuid.clone(),
                            title,
                            reason,
                        });
                        warnings.push(format!(
                            "条目 {}（{}）：未导入——Tombstone 已删除标记",
                            item.uuid,
                            item.overview
                                .as_ref()
                                .and_then(|o| o.title.as_deref())
                                .unwrap_or("(无标题)")
                        ));
                    }
                    MapOutcome::Imported(mut m) => {
                        if signals.unknown_category {
                            unknown_categories
                                .push((m.source_uuid.clone(), item.category_uuid.clone()));
                            warnings.push(format!(
                                "条目 {}（{}）：未识别类别 {}，已降级导入为安全笔记（数据并入备注，计入导入成功）",
                                m.source_uuid, m.title, item.category_uuid
                            ));
                        }
                        if signals.unknown_state {
                            warnings.push(format!(
                                "条目 {}（{}）：state 值「{}」不在规范内，按 active 处理",
                                m.source_uuid,
                                m.title,
                                item.state.as_deref().unwrap_or("(空)")
                            ));
                        }
                        if signals.no_title {
                            warnings.push(format!(
                                "条目 {}：缺失标题，导入时以「{}」兜底",
                                m.source_uuid,
                                crate::csv::mapping::FALLBACK_TITLE
                            ));
                        }
                        if signals.bad_totp {
                            warnings.push(format!(
                                "条目 {}：TOTP URI 无法解析，原始值已并入备注，该条目仍导入",
                                m.source_uuid
                            ));
                        }
                        unmapped_value_types.extend(signals.unmapped_value_types);
                        password_history_dropped += signals.password_history_dropped;

                        // 附件条目定位：失败 → 未导入清单（FR-7.6）
                        if let Some(file) = &m.file {
                            match archive.resolve_file_entry(file) {
                                Some(entry) => {
                                    m.zip_entry = Some(entry);
                                }
                                None => {
                                    not_imported.push(NotImportedItem {
                                        uuid: m.source_uuid.clone(),
                                        title: m.title.clone(),
                                        reason: format!(
                                            "附件「{}」在 ZIP files/ 中未找到",
                                            file.filename
                                        ),
                                    });
                                    warnings.push(format!(
                                        "条目 {}（{}）：附件内容缺失，整条不导入",
                                        m.source_uuid, m.title
                                    ));
                                    continue;
                                }
                            }
                        }
                        if m.state == cf_domain::item::ItemState::Trashed {
                            trashed_count += 1;
                        }
                        models.push(*m);
                    }
                }
            }
        }
    }

    // 汇总可导入数与类别分布（附件缺失条目已转入 not_imported，
    // 分布严格按 models 统计——保证报告与落库一致，FR-7.4）
    let importable_items = models.len() as u32;
    let mut category_counts: std::collections::BTreeMap<String, u32> = Default::default();
    for m in &models {
        *category_counts
            .entry(m.category.as_str().to_owned())
            .or_insert(0) += 1;
    }

    // 重复 documentId（官方形态；导入全部保留，仅告警）
    let mut doc_counts: std::collections::BTreeMap<String, u32> = Default::default();
    for m in &models {
        if let Some(id) = m.file.as_ref().and_then(|f| f.document_id.as_deref()) {
            *doc_counts.entry(id.to_owned()).or_insert(0) += 1;
        }
    }
    let duplicate_document_ids: Vec<String> = doc_counts
        .into_iter()
        .filter(|(_, c)| *c > 1)
        .map(|(id, _)| id)
        .collect();
    for id in &duplicate_document_ids {
        warnings.push(format!(
            "documentId {id} 在多个条目中重复出现，将全部导入（可能互为副本）"
        ));
    }

    unmapped_value_types.sort();
    unmapped_value_types.dedup();
    if !unmapped_value_types.is_empty() {
        warnings.push(format!(
            "存在未识别的字段值类型（值已保留不丢弃）：{}",
            unmapped_value_types.join(", ")
        ));
    }
    if password_history_dropped > 0 {
        warnings.push(format!(
            "丢弃 {password_history_dropped} 条密码历史（cf 历史表语义不同构，FR-2.9）"
        ));
    }
    if trashed_count > 0 {
        warnings.push(format!(
            "{trashed_count} 条处于回收站（trashed），将按回收站语义导入"
        ));
    }

    let report = PuxPrecheckReport {
        total_items,
        importable_items,
        category_distribution: category_counts.into_iter().collect(),
        attachment_count: models.iter().filter(|m| m.file.is_some()).count() as u32,
        unknown_categories,
        trashed_count,
        password_history_dropped,
        unmapped_value_types,
        duplicate_document_ids,
        not_imported,
        warnings,
    };
    Ok(PuxAnalysis { report, models })
}
