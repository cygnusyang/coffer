//! Bitwarden 预检报告（docs/17 §4.2 precheck.rs）。
//!
//! 与 CSV/1PUX 预检同纪律：**预检与导入复用同一条解析/映射管线**
//! （报告所见即导入所得），坏 passkey 行逐条列出、不静默丢弃（FR-7.8 /
//! TCB-7）。报告字段：
//!
//! - `total_items` / `importable_items`：条目计数（降级 / 回收站均计入
//!   可导入）；
//! - `passkey_total` / `passkey_importable` / `passkey_item_count`：
//!   passkey 行计数（TCB-1 向导显示面）；
//! - `items_with_password_and_passkey`：「含密码且含 passkey 的条目数」
//!   ——**FR-10.6 的可测试证据**（docs/17 §4.2 D-6）；
//! - `non_es256`：非 ES256 行显式列表；`bad_passkeys`：其余坏行逐条
//!   列出（EncString 私钥 / 坏 credentialId / 缺 rpId / 负 counter）。

use std::path::Path;

use cf_domain::CfError;

use super::mapping::{map_export, BwItemModel};
use super::parser;

/// 预检报告（docs/17 §4.2 冻结语义）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BwPrecheckReport {
    /// 条目总数（含回收站 / 降级条目）。
    pub total_items: u32,
    /// 可导入条目数（降级计入导入成功，E-4 同纪律）。
    pub importable_items: u32,
    /// passkey 行总数（含不可导入行）。
    pub passkey_total: u32,
    /// 可导入 passkey 行数。
    pub passkey_importable: u32,
    /// 含 ≥ 1 条可导入 passkey 的条目数。
    pub passkey_item_count: u32,
    /// **「含密码且含 passkey 的条目数」**（FR-10.6 可测试证据，D-6）。
    pub items_with_password_and_passkey: u32,
    /// 非 ES256 passkey 行显式列表（TCB-7）。
    pub non_es256: Vec<super::mapping::BwPasskeyFailure>,
    /// 其余坏 passkey 行逐条清单（EncString / 坏 credentialId / 缺 rpId /
    /// 负 counter；导入跳过该行不丢条目）。
    pub bad_passkeys: Vec<super::mapping::BwPasskeyFailure>,
    /// 回收站条目数（deletedDate 非空）。
    pub trashed_count: u32,
    /// 丢弃的密码历史条目数（FR-2.9 语义不同构，1PUX 同裁决）。
    pub password_history_dropped: u32,
    /// 告警文本（未知 fido2 键、降级、坏 totp、Linked 字段跳过等）。
    pub warnings: Vec<String>,
}

/// 预检 + 映射的完整产物（导入编排复用，保证报告与落库一致）。
#[derive(Debug)]
pub struct BwAnalysis {
    /// 预检报告。
    pub report: BwPrecheckReport,
    /// 可导入条目的中间表示（顺序 = 导出文件序；含可导入 passkey 行）。
    pub models: Vec<BwItemModel>,
}

/// 读取并预检一个 Bitwarden JSON 文件（只读、可反复调用，TCB-1④）。
///
/// # Errors
///
/// 同 [`parser::parse_file`]。
pub fn read_and_analyze(path: &Path) -> Result<BwAnalysis, CfError> {
    let export = parser::parse_file(path)?;
    analyze(&export)
}

/// 预检内存中的 Bitwarden 导出（测试与编排复用）。
///
/// # Errors
///
/// 同 [`parser::parse`]。
pub fn analyze(export: &parser::BwExport) -> Result<BwAnalysis, CfError> {
    let mapped = map_export(export)?;

    let mut models: Vec<BwItemModel> = Vec::with_capacity(mapped.len());
    let mut warnings: Vec<String> = Vec::new();
    let mut non_es256 = Vec::new();
    let mut bad_passkeys = Vec::new();
    let mut trashed_count: u32 = 0;
    // 密码历史：FR-2.9 语义不同构 → 丢弃 + 预检计数（1PUX 同裁决）
    let password_history_dropped: usize =
        export.items.iter().map(|i| i.password_history.len()).sum();

    for (model, signals) in mapped {
        warnings.extend(signals.warnings);
        non_es256.extend(signals.non_es256);
        bad_passkeys.extend(signals.bad_passkeys);
        if model.state == cf_domain::item::ItemState::Trashed {
            trashed_count += 1;
        }
        models.push(model);
    }
    if password_history_dropped > 0 {
        warnings.push(format!(
            "丢弃 {password_history_dropped} 条密码历史（cf 历史表语义不同构，FR-2.9）"
        ));
    }

    let report = build_report(
        export.items.len(),
        &models,
        &non_es256,
        &bad_passkeys,
        &warnings,
        trashed_count,
        u32::try_from(password_history_dropped).unwrap_or(u32::MAX),
    );
    Ok(BwAnalysis { report, models })
}

/// 汇总报告计数（保持 report 与 models 严格一致——FR-7.4 同纪律）。
#[allow(clippy::too_many_arguments)]
fn build_report(
    total_items: usize,
    models: &[BwItemModel],
    non_es256: &[super::mapping::BwPasskeyFailure],
    bad_passkeys: &[super::mapping::BwPasskeyFailure],
    warnings: &[String],
    trashed_count: u32,
    password_history_dropped: u32,
) -> BwPrecheckReport {
    let passkey_total: u32 = models
        .iter()
        .map(|m| m.passkeys.len())
        .sum::<usize>()
        .checked_add(non_es256.len() + bad_passkeys.len())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(u32::MAX);
    let passkey_item_count = models.iter().filter(|m| !m.passkeys.is_empty()).count() as u32;
    let items_with_password_and_passkey = models
        .iter()
        .filter(|m| m.password.is_some() && !m.passkeys.is_empty())
        .count() as u32;

    BwPrecheckReport {
        total_items: u32::try_from(total_items).unwrap_or(u32::MAX),
        importable_items: models.len() as u32,
        passkey_total,
        passkey_importable: models
            .iter()
            .map(|m| u32::try_from(m.passkeys.len()).unwrap_or(u32::MAX))
            .sum(),
        passkey_item_count,
        items_with_password_and_passkey,
        non_es256: non_es256.to_vec(),
        bad_passkeys: bad_passkeys.to_vec(),
        trashed_count,
        password_history_dropped,
        warnings: warnings.to_vec(),
    }
}
