//! cf-mcp 错误类型（docs/20 §3.4）。
//!
//! 错误码分两类：
//!
//! - **协议层**（JSON-RPC 2.0 / MCP 标准，冻结）：`-32700` 解析错 / `-32600`
//!   无效请求 / `-32601` 方法未找到 / `-32602` 无效参数 / `-32603` 内部错误；
//!   MCP 级 `-32000`~`-32099` 保留；
//! - **应用层**（docs/20 §3.4 新增 7xxx 段）：`7001`~`7006`。
//!
//! 7xxx 段**暂用本地常量标注**（docs/03 §12 一行登记属 docs 域，落 **G-F**，
//! docs/20 §9.1）。载荷纪律对齐 CfError（docs/03 §4.4）：错误消息**不得含
//! Secret 值或可直接降低攻击成本的信息**。

use thiserror::Error;

use crate::provider::ProviderError;

/// 7001：Provider 不可用（op 未装 / 不可执行）。
pub const CODE_PROVIDER_UNAVAILABLE: i64 = 7001;
/// 7002：需要身份（op 未登录，OP_SESSION 缺失）。
pub const CODE_AUTH_REQUIRED: i64 = 7002;
/// 7003：Secret 不存在 / 无权限。
pub const CODE_SECRET_NOT_FOUND: i64 = 7003;
/// 7004：子进程失败（含退出码）。
pub const CODE_SUBPROCESS_FAILED: i64 = 7004;
/// 7005：协议 / 参数错误。
pub const CODE_INVALID_PARAMETER: i64 = 7005;
/// 7006：内部错误（不泄露细节）。
pub const CODE_INTERNAL: i64 = 7006;

/// cf-mcp 统一错误（docs/20 §3.4 错误码表）。
///
/// `code()` 返回稳定错误码（负数 = 协议层，7xxx = 应用层），协议层用它构建
/// JSON-RPC `error.code`，UI/CLI 层用它做本地化映射（不解析消息文本）。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum McpError {
    /// -32700 解析错误（无效 JSON）。
    #[error("parse error: {0}")]
    ParseError(String),
    /// -32600 无效请求（版本错 / 结构错 / id 乱序）。
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// -32601 方法未找到。
    #[error("method not found: {0}")]
    MethodNotFound(String),
    /// -32602 无效参数。
    #[error("invalid params: {0}")]
    InvalidParams(String),
    /// -32603 内部错误（协议层兜底）。
    #[error("internal error: {0}")]
    Internal(String),
    /// 7001 Provider 不可用。
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(String),
    /// 7002 需要身份。
    #[error("authentication required: {0}")]
    AuthRequired(String),
    /// 7003 Secret 不存在 / 无权限。
    #[error("secret not found: {0}")]
    SecretNotFound(String),
    /// 7004 子进程失败。
    #[error("subprocess failed (exit {exit_code:?}): {detail}")]
    SubprocessFailed {
        /// 子进程退出码；`None` = spawn 阶段失败。
        exit_code: Option<i32>,
        /// 归一化后的失败细节（剥离敏感值）。
        detail: String,
    },
    /// 7005 协议 / 参数错误。
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    /// 7006 内部错误（兜底，不泄露细节）。
    #[error("internal error: {0}")]
    InternalError(String),
}

impl McpError {
    /// 返回 `docs/20` §3.4 错误码表中的稳定错误码。
    ///
    /// 负数 = 协议层（JSON-RPC/MCP 标准），7xxx = 应用层。**无 `_` 兜底分支**：
    /// 新增变体时编译器会强制在此补码。
    #[must_use]
    pub fn code(&self) -> i64 {
        match self {
            Self::ParseError(_) => -32700,
            Self::InvalidRequest(_) => -32600,
            Self::MethodNotFound(_) => -32601,
            Self::InvalidParams(_) => -32602,
            Self::Internal(_) => -32603,
            Self::ProviderUnavailable(_) => CODE_PROVIDER_UNAVAILABLE,
            Self::AuthRequired(_) => CODE_AUTH_REQUIRED,
            Self::SecretNotFound(_) => CODE_SECRET_NOT_FOUND,
            Self::SubprocessFailed { .. } => CODE_SUBPROCESS_FAILED,
            Self::InvalidParameter(_) => CODE_INVALID_PARAMETER,
            Self::InternalError(_) => CODE_INTERNAL,
        }
    }
}

impl From<ProviderError> for McpError {
    /// Provider 错误 → MCP 应用层错误（docs/20 §3.4 映射）。
    fn from(e: ProviderError) -> Self {
        match e {
            ProviderError::Unavailable(m) => Self::ProviderUnavailable(m),
            ProviderError::AuthRequired(m) => Self::AuthRequired(m),
            ProviderError::NotFound(m) => Self::SecretNotFound(m),
            ProviderError::SubprocessFailed { exit_code, detail } => {
                Self::SubprocessFailed { exit_code, detail }
            }
            ProviderError::InvalidParameter(m) => Self::InvalidParameter(m),
            ProviderError::Internal(m) => Self::InternalError(m),
        }
    }
}

impl From<serde_json::Error> for McpError {
    /// 序列化失败归为协议层内部错误（对本 crate 的帧类型实际不可失败）。
    fn from(e: serde_json::Error) -> Self {
        Self::Internal(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_match_section_34() {
        // 期望值逐项抄自 docs/20 §3.4 错误码表（协议层 + 7xxx 段）。
        let expected: [(McpError, i64); 11] = [
            (McpError::ParseError(String::new()), -32700),
            (McpError::InvalidRequest(String::new()), -32600),
            (McpError::MethodNotFound(String::new()), -32601),
            (McpError::InvalidParams(String::new()), -32602),
            (McpError::Internal(String::new()), -32603),
            (McpError::ProviderUnavailable(String::new()), 7001),
            (McpError::AuthRequired(String::new()), 7002),
            (McpError::SecretNotFound(String::new()), 7003),
            (
                McpError::SubprocessFailed { exit_code: None, detail: String::new() },
                7004,
            ),
            (McpError::InvalidParameter(String::new()), 7005),
            (McpError::InternalError(String::new()), 7006),
        ];
        for (err, code) in &expected {
            assert_eq!(err.code(), *code, "错误码不匹配：{err:?}");
        }
    }

    #[test]
    fn error_codes_are_unique() {
        let codes: Vec<i64> = [
            McpError::ParseError(String::new()),
            McpError::InvalidRequest(String::new()),
            McpError::MethodNotFound(String::new()),
            McpError::InvalidParams(String::new()),
            McpError::Internal(String::new()),
            McpError::ProviderUnavailable(String::new()),
            McpError::AuthRequired(String::new()),
            McpError::SecretNotFound(String::new()),
            McpError::SubprocessFailed { exit_code: None, detail: String::new() },
            McpError::InvalidParameter(String::new()),
            McpError::InternalError(String::new()),
        ]
        .iter()
        .map(McpError::code)
        .collect();

        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "错误码存在重复：{codes:?}");
    }

    #[test]
    fn provider_error_maps_to_7xxx() {
        assert_eq!(
            McpError::from(ProviderError::NotFound("x".into())).code(),
            CODE_SECRET_NOT_FOUND
        );
        assert_eq!(
            McpError::from(ProviderError::AuthRequired("x".into())).code(),
            CODE_AUTH_REQUIRED
        );
        assert_eq!(
            McpError::from(ProviderError::Unavailable("x".into())).code(),
            CODE_PROVIDER_UNAVAILABLE
        );
        assert_eq!(
            McpError::from(ProviderError::InvalidParameter("x".into())).code(),
            CODE_INVALID_PARAMETER
        );
        assert_eq!(
            McpError::from(ProviderError::Internal("x".into())).code(),
            CODE_INTERNAL
        );
        let sub = McpError::from(ProviderError::SubprocessFailed {
            exit_code: Some(1),
            detail: "boom".into(),
        });
        assert_eq!(sub.code(), CODE_SUBPROCESS_FAILED);
    }
}
