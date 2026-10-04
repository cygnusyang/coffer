//! FR-14.4 本地诊断（只读允许面，docs/22 §2.4 / §3.3；docs/23 §1.5 TC-DIAG 组）。
//!
//! [`VaultSession::diagnostic_summary`] 组合读取**非敏感**库级元数据：
//! 条目数（`meta.item_count`）、附件数（`attachments` 行数，纯计数不触
//! 解密）、库创建时间（`header.created_at`）、最后备份时间
//! （`meta.last_backup_at`）、库 UUID 前缀。
//!
//! **字段集白名单**（FR-14.4 红线，docs/23 §1.5 TC-DIAG-03）：本模块输出
//! 结构上不含标题 / 密码 / secret / 密钥材料——非仅 UI 不展示。新增字段
//! 须经 `tests/diag.rs` 白名单钉住测试（编译期穷尽构造）复核。
//!
//! 门禁归属：只读**允许面**，无 6002/6003（与 `list_items` 同类，
//! docs/22 §5）；锁定态 → 1001。

use std::path::Path;

use cf_domain::CfError;

use crate::vault::VaultSession;
use crate::SessionResult;

/// 库 UUID 前缀长度（v0.7.0-T03 冻结契约：UUID 前 8 字符 short 形态）。
///
/// 非敏感：全量 uuid 已由 [`VaultSession::vault_uuid`] 暴露（`FfiVaultInfo` /
/// `FfiVaultBrief`），前缀信息量更弱。
pub const UUID_PREFIX_LEN: usize = 8;

/// FR-14.4 本地诊断摘要（docs/22 §3.3 冻结契约）。
///
/// **字段集白名单**（FR-14.4 红线，docs/23 §1.5 TC-DIAG-03）：只含计数 /
/// 时间 / uuid 前缀类非敏感字段，结构上不存在密码明文 / 条目标题 / URL /
/// 用户名 / secret / 密钥材料读路径。新增字段须经 `tests/diag.rs` 白名单
/// 钉住测试（编译期穷尽构造）复核。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticSummary {
    /// 条目数（`meta.item_count`；已知元数据泄露项，同 [`crate::VaultInfo`]）。
    pub item_count: i64,
    /// 附件数（`attachments` 表行数；纯计数，不触附件内容解密）。
    pub attachment_count: i64,
    /// 库创建时间（`header.created_at`，Unix 秒 UTC）。
    pub vault_created_at: i64,
    /// 最后成功备份时间（`meta.last_backup_at`，Unix 秒；从未备份为 `None`）。
    pub last_backup_at: Option<i64>,
    /// 库 UUID 前 [`UUID_PREFIX_LEN`] 字符（非敏感）。
    pub vault_uuid_prefix: String,
}

impl VaultSession {
    /// FR-14.4 本地诊断摘要（只读允许面）。
    ///
    /// 组合读取非敏感元数据：条目数 / 附件数 / 库创建时间 / 最后备份时间 /
    /// 库 UUID 前缀。**字段集白名单**——不含任何敏感数据（FR-14.4 红线：
    /// 无标题 / 无密码 / 无 secret，docs/23 §1.5 TC-DIAG-03）。
    ///
    /// 门禁：只读允许面，无许可门禁（6002/6003 不适用，与 `list_items`
    /// 同类，docs/22 §5）；锁定态 → 1001。
    ///
    /// # 错误
    ///
    /// 锁定态 → 1001；附件计数 / meta 读取失败 → 存储层错误透出；
    /// 磁盘 header 不可读（外部篡改）→ 1005 / 1006（错误映射对齐
    /// [`crate::unlock::open_vault`]）。
    pub fn diagnostic_summary(&self) -> SessionResult<DiagnosticSummary> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;

        let item_count = state.store.repos().meta.item_count()?;
        let last_backup_at = state.store.repos().meta.last_backup_at()?;
        let attachment_count = attachment_count(state.store.connection())?;
        let vault_created_at = header_created_at(self.vault_dir())?;

        let uuid = self.vault_uuid().to_string();
        let prefix_len = UUID_PREFIX_LEN.min(uuid.len());
        Ok(DiagnosticSummary {
            item_count,
            attachment_count,
            vault_created_at,
            last_backup_at,
            vault_uuid_prefix: uuid[..prefix_len].to_owned(),
        })
    }
}

/// 附件数：`attachments` 表行数（纯统计，不解密任何附件内容，不读
/// `attachments/` 旁路文件）。失败 → [`CfError::StorageError`]（透出细节）。
fn attachment_count(conn: &rusqlite::Connection) -> SessionResult<i64> {
    conn.query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))
        .map_err(|e| CfError::StorageError(format!("统计附件数失败：{e}")))
}

/// 库创建时间：磁盘重读 `header.json`。
///
/// `created_at` 建库后恒定（bio enable/disable / 改主密码重写 header 均
/// 不改变它），故磁盘重读与会话内存 header 一致，且不触碰
/// `VaultSession` 私有 header 字段（模块边界解耦）。错误映射对齐
/// [`crate::unlock::open_vault`]：版本过新 / 旧库待迁移 → 1006、
/// header 损坏 → 1005。
fn header_created_at(vault_dir: &Path) -> SessionResult<i64> {
    match cf_format::open_container(vault_dir) {
        Ok(cf_format::OpenOutcome::Current(header)) => Ok(header.created_at),
        Ok(cf_format::OpenOutcome::TooNew(v)) => Err(CfError::UnsupportedFormat(v)),
        Ok(cf_format::OpenOutcome::NeedsMigration { from, .. }) => {
            Err(CfError::UnsupportedFormat(from))
        }
        Err(other) => Err(CfError::Corrupted(other.to_string())),
    }
}
