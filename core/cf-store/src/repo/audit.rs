//! audit_local 表仓库（FR-12.6 本地审计日志，docs/02 §3 / docs/03 §3.1）。
//!
//! 本地安全日志：记录解锁、导出、改密等敏感操作的时间与事件类型，
//! 供「用户否认执行过导出 / 删除」类争议提供本机证据（docs/04 §9 威胁表）。
//!
//! ## 纪律（docs/03 §3.1 DDL 头注释）
//!
//! **严禁写入任何敏感值**——`detail` 列只允许放非敏感上下文（如条目
//! UUID、目标文件名），密码 / 明文字段值 / 密钥材料一律不得入内。
//!
//! ## 事件类型
//!
//! [`AuditEvent`] 是封闭枚举，覆盖 v0.2.0 的四类动作与 v0.4.0 的跨库
//! 复制（FR-2.10 `item_copy`）；`event` 列以
//! `as_str` 文本落盘，读取时反向解析——遇到本实现不认识的文本（更高
//! 版本 App 写入）返回 [`CfError::Corrupted`]，**不静默跳过**（与
//! schema 版本校验的 O-2 纪律一致）。
//!
//! ## 已知风险（FR-2.10，设计裁决接受）
//!
//! `ItemCopy` 变体使旧版本 App 读取含 `item_copy` 事件的库时在
//! [`AuditRepo::list_desc`] 处返回 [`CfError::Corrupted`]——封闭枚举 +
//! 不静默跳过的既有纪律使然，v0.4.0 设计评审明确接受（正向版本要求）。
//!
//! 会话层埋点（unlock / 失败计数等）由 cf-session 后续接入，本仓库只
//! 提供忠实读写原语。

use rusqlite::Connection;

use crate::error::{CfError, CfStoreResult, RusqliteResultExt};

/// 审计事件类型（FR-12.6，v0.2.0 覆盖范围）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    /// 加密备份导出成功（FR-8.1）。
    BackupExport,
    /// 备份恢复完成（FR-8.1 回环）。
    BackupRestore,
    /// CSV 明文导出成功（FR-8.3）。
    CsvExport,
    /// 修改主密码成功（FR-1.8）。
    PasswordChange,
    /// 跨库复制条目成功（FR-2.10，v0.4.0）。源库与目标库各打一条，
    /// `detail` = 非敏感上下文（两端库 uuid + 条目 uuid，不含标题）。
    ItemCopy,
}

impl AuditEvent {
    /// 落盘文本（`event` 列的规范值，冻结后不得更改既有取值）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackupExport => "backup_export",
            Self::BackupRestore => "backup_restore",
            Self::CsvExport => "csv_export",
            Self::PasswordChange => "password_change",
            Self::ItemCopy => "item_copy",
        }
    }

    /// 从落盘文本解析；未知文本返回 `None`（调用方决定报错语义）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "backup_export" => Some(Self::BackupExport),
            "backup_restore" => Some(Self::BackupRestore),
            "csv_export" => Some(Self::CsvExport),
            "password_change" => Some(Self::PasswordChange),
            "item_copy" => Some(Self::ItemCopy),
            _ => None,
        }
    }
}

/// 一条审计记录（`id` 为库内自增主键）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// 行 id（自增，写入时由 SQLite 分配）。
    pub id: i64,
    /// 事件时间（Unix 秒，调用方注入）。
    pub ts: i64,
    /// 事件类型。
    pub event: AuditEvent,
    /// 非敏感上下文（如条目 UUID）；无则 `None`。
    pub detail: Option<String>,
}

/// audit_local 表仓库（借用连接，可参与事务）。
pub struct AuditRepo<'a> {
    conn: &'a Connection,
}

impl<'a> AuditRepo<'a> {
    /// 构造仓库。
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// 追加一条审计记录，返回分配的行 id。
    ///
    /// `ts` 由调用方注入（与 history 仓库同模式，时间不取自库内）；
    /// `detail` 只允许非敏感上下文（见模块文档纪律）。
    pub fn append(
        &self,
        ts: i64,
        event: AuditEvent,
        detail: Option<&str>,
    ) -> CfStoreResult<i64> {
        self.conn
            .execute(
                "INSERT INTO audit_local (ts, event, detail) VALUES (?1, ?2, ?3)",
                rusqlite::params![ts, event.as_str(), detail],
            )
            .store()?;
        Ok(self.conn.last_insert_rowid())
    }

    /// 按时间倒序分页读取（ts DESC；同秒按 id DESC，后写在前）。
    ///
    /// `offset` / `limit` 语义与 [`crate::ItemListFilter`] 一致：`None`
    /// 偏移视为 0、`None` 上限不限量（SQLite `LIMIT -1` 语义）。
    /// 遇未知事件文本报 [`CfError::Corrupted`]（不静默跳过，见模块文档）。
    pub fn list_desc(
        &self,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> CfStoreResult<Vec<AuditEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ts, event, detail FROM audit_local
                 ORDER BY ts DESC, id DESC LIMIT ?1 OFFSET ?2",
            )
            .store()?;
        let mut rows = stmt
            .query(rusqlite::params![limit.unwrap_or(-1), offset.unwrap_or(0)])
            .store()?;

        let mut out = Vec::new();
        while let Some(row) = rows.next().store()? {
            let event_text: String = row.get(2).store()?;
            let Some(event) = AuditEvent::parse(&event_text) else {
                return Err(CfError::Corrupted(format!(
                    "unknown audit event: {event_text}"
                )));
            };
            out.push(AuditEntry {
                id: row.get(0).store()?,
                ts: row.get(1).store()?,
                event,
                detail: row.get(3).store()?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn repo() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::schema::init(&mut conn).unwrap();
        conn
    }

    /// 追加 → 读取：字段往返一致（含 detail 为 NULL 的形态）
    #[test]
    fn 追加读取往返() {
        let conn = repo();
        let r = AuditRepo::new(&conn);
        let id1 = r.append(1_000, AuditEvent::BackupExport, Some("/tmp/库.coffer")).unwrap();
        let id2 = r.append(1_001, AuditEvent::PasswordChange, None).unwrap();
        assert_ne!(id1, id2, "自增 id 必须不同");

        let rows = r.list_desc(None, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].id, id1);
        assert_eq!(rows[1].ts, 1_000);
        assert_eq!(rows[1].event, AuditEvent::BackupExport);
        assert_eq!(rows[1].detail.as_deref(), Some("/tmp/库.coffer"));
        assert_eq!(rows[0].event, AuditEvent::PasswordChange);
        assert_eq!(rows[0].detail, None);
    }

    /// 倒序 + 分页：ts DESC、同秒 id DESC；limit/offset 切片正确
    #[test]
    fn 倒序分页切片() {
        let conn = repo();
        let r = AuditRepo::new(&conn);
        for i in 0..5_i64 {
            r.append(1_000 + i % 2, AuditEvent::BackupExport, Some(&i.to_string()))
                .unwrap();
        }

        let all = r.list_desc(None, None).unwrap();
        assert_eq!(all.len(), 5);
        // (ts DESC, id DESC) 的元组序：同秒内后写的 id 更大、排在前面
        let keys: Vec<(i64, i64)> = all.iter().map(|e| (e.ts, e.id)).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable_by_key(|&(ts, id)| std::cmp::Reverse((ts, id)));
        assert_eq!(keys, sorted, "必须 ts DESC, id DESC");

        // 第一页 2 条 + 第二页 2 条
        let page1 = r.list_desc(Some(0), Some(2)).unwrap();
        let page2 = r.list_desc(Some(2), Some(2)).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page1[0].id, all[0].id);
        assert_eq!(page2[0].id, all[2].id, "offset 翻页衔接");
        assert!(r.list_desc(Some(4), Some(2)).unwrap().len() == 1, "末页允许不满页");
        assert!(r.list_desc(Some(5), Some(2)).unwrap().is_empty(), "越界偏移为空");
    }

    /// 全事件类型文本往返：as_str ↔ parse 互逆
    #[test]
    fn 事件类型文本往返() {
        for event in [
            AuditEvent::BackupExport,
            AuditEvent::BackupRestore,
            AuditEvent::CsvExport,
            AuditEvent::PasswordChange,
            AuditEvent::ItemCopy,
        ] {
            assert_eq!(AuditEvent::parse(event.as_str()), Some(event));
        }
        assert_eq!(AuditEvent::parse("nope"), None);
    }

    /// 未知事件文本（更高版本写入）→ Corrupted，不静默跳过
    #[test]
    fn 未知事件文本报损坏() {
        let conn = repo();
        conn.execute(
            "INSERT INTO audit_local (ts, event) VALUES (1, 'future_event')",
            [],
        )
        .unwrap();
        let result = AuditRepo::new(&conn).list_desc(None, None);
        assert!(matches!(result, Err(CfError::Corrupted(_))));
    }

    /// 可参与事务：with_tx 内写入，提交后可读；失败回滚无残留
    #[test]
    fn 事务内写入与回滚() {
        use cf_crypto::subkeys::SubKeys;
        let conn = repo();
        let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        let mut store = crate::ItemStore::open(conn, subkeys).unwrap();

        store
            .with_tx(|repos| repos.audit.append(1, AuditEvent::CsvExport, None).map(|_| ()))
            .unwrap();
        assert_eq!(store.repos().audit.list_desc(None, None).unwrap().len(), 1);

        let err = store.with_tx(|repos| -> CfStoreResult<()> {
            repos.audit.append(2, AuditEvent::BackupRestore, None)?;
            Err(cf_domain::CfError::Validation("injected".into()))
        });
        assert!(err.is_err());
        assert_eq!(
            store.repos().audit.list_desc(None, None).unwrap().len(),
            1,
            "失败事务不得留下审计行"
        );
    }
}
