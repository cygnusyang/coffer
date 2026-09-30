//! 审计轨迹（docs/20 §4.6，AS-10）。
//!
//! 分层纪律（§2.3）：审计轨迹**不**复用 cf-audit——cf-audit 是弱/重复/陈旧密码
//! 体检（FR-6），与 AS-10「Secret 使用审计轨迹」语义不符。
//!
//! D-3 未确认：本版默认 [`NoopAudit`]（§4.6 方案 B 延迟）。JSONL（方案 A，建议）
//! 是新持久化格式（不可逆，§8 D-3），须用户确认后实现。
//!
//! 不变量：审计事件**永不携带 Secret 值**（[`AuditEvent`] 无值字段）。

use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// 操作：USE（secret 被用于运行）。
pub const OP_USE: &str = "USE";
/// 操作：ROTATE（secret 轮换）。
pub const OP_ROTATE: &str = "ROTATE";
/// 操作：GRANT（授权）。
pub const OP_GRANT: &str = "GRANT";
/// 操作：REVOKE（撤权）。
pub const OP_REVOKE: &str = "REVOKE";

/// 审计事件（无 Secret 值，§4.6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// unix 秒时间戳。
    pub ts: i64,
    /// 发起 Agent（Agent 上下文未建模，MVP 恒 `None`，docs/10 U-6 未决）。
    pub agent: Option<String>,
    /// 发起用户（MVP 恒 `None`）。
    pub user: Option<String>,
    /// Secret 标识（非明文值）。
    pub secret_id: String,
    /// 操作（[`OP_USE`] / [`OP_ROTATE`] / [`OP_GRANT`] / [`OP_REVOKE`]）。
    pub operation: String,
    /// 目标进程（run_with_secret 的命令，MVP 可选）。
    pub target_process: Option<String>,
    /// 操作结果（成功 / 失败）。
    pub result: bool,
}

impl AuditEvent {
    /// 构造 USE 事件（MVP 唯一可触达的审计面）。
    #[must_use]
    pub fn use_event(secret_id: &str, result: bool) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        Self {
            ts,
            agent: None,
            user: None,
            secret_id: secret_id.to_string(),
            operation: OP_USE.to_string(),
            target_process: None,
            result,
        }
    }
}

/// 审计错误（记录失败**不**阻断工具调用——审计是尽力而为，D-3 未定）。
#[derive(Debug, PartialEq, Eq)]
pub enum AuditError {
    /// 记录失败（含 IO 细节）。
    Io(String),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "audit io error: {m}"),
        }
    }
}

impl Error for AuditError {}

/// UsageAudit（docs/20 §4.6 冻结签名）。
pub trait UsageAudit: Send + Sync {
    /// 记录一条审计事件（`ev` 无 Secret 值）。
    fn record(&self, ev: &AuditEvent) -> Result<(), AuditError>;
}

/// 默认实现：NoopAudit（§4.6 方案 B 延迟；D-3 确认 JSONL 前不落盘）。
#[derive(Debug, Clone, Default)]
pub struct NoopAudit;

impl UsageAudit for NoopAudit {
    fn record(&self, _ev: &AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}
