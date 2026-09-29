//! 导出与只读查询的会话层薄委托（v0.2.0-T06 FFI 收口配套）。
//!
//! 与 [`VaultSession::import_csv`](crate::VaultSession::import_csv) 对称：
//! 导入编排归 cf-session，导出/审计查询同样由本模块提供 `&ItemStore`
//! 访问路径，cf-ffi 由此获得能力而不必接触 `ItemStore` 内部
//! （DEK / SubKeys 依旧不跨 FFI）。
//!
//! - [`VaultSession::export_csv`]：薄委托 `cf_exporter::export_csv`
//!   （FR-8.3；明文导出的二次确认门禁在调用方 UI，见 FR-8.4——内核
//!   不提供也不应绕过该门禁，cf-exporter 模块文档同款纪律）。
//! - [`VaultSession::recent_audit_events`]：FR-12.6 审计日志只读分页
//!   查询（只读，不提供 FFI 写入通道——审计事件只由内核动作打点）。

use std::path::Path;

use crate::vault::VaultSession;
use crate::SessionResult;
use cf_domain::CfError;
use cf_store::AuditEntry;

impl VaultSession {
    /// CSV 明文导出（FR-8.3，docs/09 §2 v0.2.0 范围）。
    ///
    /// 薄委托 [`cf_exporter::export_csv`]——9 列映射与 cf-importer
    /// `HEADER_*` 常量严格对齐，公式注入防护在导出侧完成。
    /// **明文导出的二次确认（FR-8.4）是调用方 UI 门禁**：FFI/UI 侧必须
    /// 先取得用户显式确认才可调用本方法。
    ///
    /// # 错误
    ///
    /// 锁定态 → 1001；其余透传 `cf_exporter` 错误（docs/03 §12）。
    pub fn export_csv(&self, out_path: &Path) -> SessionResult<cf_exporter::CsvExportResult> {
        let guard = self.write_guard(cf_domain::license::LicensedOp::ExportData)?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        let result = cf_exporter::export_csv(&state.store, out_path);
        // FR-12.6 本地审计：CSV 导出成功事件。打点失败静默（不否定已
        // 成功的导出，与 cf-exporter stamp_* 同纪律）。
        if result.is_ok() {
            if let Ok(now) = crate::unix_now() {
                let _ =
                    state
                        .store
                        .repos()
                        .audit
                        .append(now, cf_store::AuditEvent::CsvExport, None);
            }
        }
        result
    }

    /// 本地审计日志只读分页查询（FR-12.6，docs/09 §2 v0.2.0 Could）。
    ///
    /// 按时间倒序（同秒按 id DESC）；`offset` / `limit` 语义与
    /// `cf_store::ItemListFilter` 一致：`None` 偏移视为 0、`None` 上限
    /// 不限量。事件只由内核动作打点（备份导出/恢复/CSV 导出/改主密码），
    /// 本方法不提供写入通道。
    ///
    /// # 错误
    ///
    /// 锁定态 → 1001；未知事件文本 → Corrupted（不静默跳过）。
    pub fn recent_audit_events(
        &self,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> SessionResult<Vec<AuditEntry>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        state.store.repos().audit.list_desc(offset, limit)
    }
}
