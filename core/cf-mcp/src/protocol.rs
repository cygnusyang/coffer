//! MCP / JSON-RPC 2.0 协议层（docs/20 §3）。
//!
//! ## 传输（§3.1）
//!
//! **stdio**：stdout = 协议帧，stderr = 日志（禁 stdout 打日志）。UTF-8、
//! **换行分隔的 JSON-RPC 2.0 消息**。MVP 不实现 `--uds`（D-4），本文件
//! **零网络**——无任何 TCP/UDP 代码路径（§3.1 零网络约束）。
//!
//! ## 生命周期（§3.2）
//!
//! `initialize` → `notifications/initialized` → `tools/list` → `tools/call`。
//! 通知（无 id）不产生响应；未知方法返回 `-32601`。
//!
//! ## 错误码（§3.4）
//!
//! 协议层 `-32700`~`-32603`（本文件直接使用）；应用层 7xxx 段见
//! [`crate::error`]（docs/03 §12 登记落 G-F）。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::McpError;

/// JSON-RPC 版本。
pub const JSONRPC_VERSION: &str = "2.0";

/// MCP 协议版本（2024-11-05 为 MCP 稳定版本线）。
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// MCP stdio 单行内容最大字节数（L-7，HIGH-1 同族有界读取）。
///
/// 换行分隔的 JSON-RPC 帧通常 < 1 KiB；64 KiB 对任何合法帧都宽裕，同时把
/// 恶意/失控客户端的单行内存压力钉死在上界内。内容超限 → **7005 拒收**
/// （KNOWN-ISSUES L-7 建议；[`parse_frame`] 与 [`crate::McpServer::serve_with`]
/// 双层强制，同一常量，零新增 7xxx 码）。
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// JSON-RPC 请求 id（数字 / 字符串；通知无 id，解析为 [`Option::None`]）。
///
/// [`RequestId::Null`] 仅用于**错误响应**（JSON-RPC 要求 id 存在，解析失败时
/// 用 `null`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// 数值 id。
    Number(i64),
    /// 字符串 id。
    Str(String),
    /// null（仅错误响应回显）。
    Null,
}

/// 客户端请求帧（MCP stdio 换行分隔消息）。
#[derive(Debug, Clone, Deserialize)]
pub struct RequestFrame {
    /// JSON-RPC 版本（须为 [`JSONRPC_VERSION`]）。
    pub jsonrpc: String,
    /// 请求 id；`None` = 通知。
    #[serde(default)]
    pub id: Option<RequestId>,
    /// 方法名（`initialize` / `tools/list` / `tools/call` / `ping` / 通知）。
    pub method: String,
    /// 方法参数（可选）。
    #[serde(default)]
    pub params: Option<Value>,
}

/// 响应帧（含 result 或 error，二者互斥）。
#[derive(Debug, Clone, Serialize)]
pub struct ResponseFrame {
    /// JSON-RPC 版本。
    pub jsonrpc: String,
    /// 请求 id 回显（解析失败时为 `null`）。
    pub id: Option<RequestId>,
    /// 成功结果。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// 错误对象。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

/// JSON-RPC 错误对象。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorObject {
    /// 错误码（docs/20 §3.4）。
    pub code: i64,
    /// 错误消息（**不含 Secret 值**，载荷纪律）。
    pub message: String,
}

/// 解析一行 MCP 消息为请求帧。
///
/// - 行内容超 [`MAX_LINE_BYTES`] → [`McpError::InvalidParameter`]（`7005`，
///   单行长度上界，L-7 / HIGH-1 同族有界读取）；
/// - 非 JSON → [`McpError::ParseError`]（`-32700`）；
/// - `jsonrpc` 非 `2.0` / 缺 `method` → [`McpError::InvalidRequest`]（`-32600`）；
/// - 其余结构错误 → [`McpError::InvalidRequest`]（`-32600`）。
pub fn parse_frame(line: &str) -> Result<RequestFrame, McpError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(McpError::InvalidParameter(format!(
            "single line exceeds MAX_LINE_BYTES ({MAX_LINE_BYTES} bytes)"
        )));
    }
    let value: Value = serde_json::from_str(line)
        .map_err(|e| McpError::ParseError(format!("invalid JSON: {e}")))?;
    if value.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err(McpError::InvalidRequest(
            "jsonrpc must be \"2.0\"".to_string(),
        ));
    }
    if value.get("method").is_none() {
        return Err(McpError::InvalidRequest("missing method".to_string()));
    }
    let frame: RequestFrame = serde_json::from_value(value)
        .map_err(|e| McpError::InvalidRequest(format!("malformed request: {e}")))?;
    Ok(frame)
}
