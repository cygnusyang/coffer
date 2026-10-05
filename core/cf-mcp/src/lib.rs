//! # cf-mcp —— MCP（Model Context Protocol）服务（Agent 凭据网关）
//!
//! 设计契约：`docs/20-MCP设计.md`（LV-HLD-020）。本 crate 是应用服务层新 crate
//! （lib + bin），承载：MCP 协议收发、工具分发、SecretProvider 抽象、Redactor、
//! CLI 入口（`coffer` bin 的 `mcp` 子命令，G-D）。
//!
//! ## 依赖方向（docs/20 §2.2，硬约束）
//!
//! ```text
//! cf-mcp ──► cf-domain（CfError / SecretString / item 模型）
//!         ──► serde / serde_json（协议帧）
//!         ──► zeroize（缓冲清零）
//! ```
//!
//! MVP **不依赖** cf-session / cf-store / cf-ffi；审计轨迹不复用 cf-audit
//! （§2.3 分层语义违规）；**零网络**（§3.1：MVP 只 stdio，无 TCP/UDP 代码路径）。
//!
//! ## 模块划分（docs/20 §2.4）
//!
//! - [`protocol`]：MCP/JSON-RPC 帧解析、生命周期、错误码映射
//! - [`tools`]：工具分发（MVP 四项，§3.3）
//! - [`redact`]：[`SecretRedactor`]（AS-11 输出脱敏，§3.5）
//! - [`audit`]：`UsageAudit` trait + 默认实现（§4.6）
//! - [`error`]：[`McpError`]（7xxx 段，§3.4）
//! - [`provider`]：`SecretProvider` trait + 注册表（§4.1 冻结签名）
//! - [`cli`]：`coffer mcp` 参数解析与入口（§5，G-D）
//! - [`McpServer`]：门面（`serve_stdio` / `handle_line`，§2.4 lib.rs 职责）
//! - [`mcp`]：`mcp::*` 本地门面（4 实工具 + 8 个 D-1 未确认收缩范围的兼容桩）
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`；生产代码禁 `unwrap` / `expect`
//! （测试代码经 `clippy.toml` 放行）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod audit;
pub mod cli;
pub mod error;
pub mod protocol;
pub mod provider;
pub mod redact;
pub mod tools;

use std::io::{BufRead, Write};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::audit::{NoopAudit, UsageAudit};
use crate::error::McpError;
use crate::protocol::{
    parse_frame, RequestFrame, RequestId, ResponseFrame, MAX_LINE_BYTES, JSONRPC_VERSION,
    MCP_PROTOCOL_VERSION,
};
use crate::provider::SecretProvider;
use crate::redact::SecretRedactor;
use crate::tools::ToolRegistry;

/// MCP 服务器（docs/20 §2.4 lib.rs 门面职责）。
///
/// 持有一个 [`SecretProvider`]、输出 Redactor 与 `UsageAudit`，按 §3.2 生命周期
/// 处理 stdio 换行分隔的 JSON-RPC 2.0 消息。**非 `Clone`**：持有 provider 与
/// 进程级 replay 状态（[`last_id`](Self::last_id)），一实例一连接。
pub struct McpServer {
    provider: Box<dyn SecretProvider>,
    redactor: SecretRedactor,
    audit: Box<dyn UsageAudit>,
    tools: ToolRegistry,
    /// Replay 防护（§3.6）：数值消息 id 单调递增，乱序/重号拒绝。
    last_id: Mutex<Option<i64>>,
}

impl McpServer {
    /// 以给定 provider 构造服务器（默认 NoopAudit + 默认 Redactor）。
    #[must_use]
    pub fn new(provider: Box<dyn SecretProvider>) -> Self {
        Self {
            provider,
            redactor: SecretRedactor::new(),
            audit: Box::new(NoopAudit),
            tools: ToolRegistry::new(),
            last_id: Mutex::new(None),
        }
    }

    /// 替换输出 Redactor（builder）。
    #[must_use]
    pub fn with_redactor(mut self, redactor: SecretRedactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// 替换审计实现（builder；D-3 未确认前默认为 NoopAudit）。
    #[must_use]
    pub fn with_audit(mut self, audit: Box<dyn UsageAudit>) -> Self {
        self.audit = audit;
        self
    }

    /// 处理一行 MCP 消息，返回响应帧字符串；通知返回 `None`（无响应）。
    ///
    /// 生命周期：`initialize` → `notifications/initialized` → `tools/list` →
    /// `tools/call`（§3.2）。协议错误返回 JSON-RPC error（码值 §3.4）。
    pub fn handle_line(&self, line: &str) -> Option<String> {
        match parse_frame(line) {
            Ok(req) => {
                let id = req.id.clone().unwrap_or(RequestId::Null);
                if req.id.is_none() {
                    // 通知：无响应（§3.2）；未知通知按 MCP 规范静默忽略。
                    self.handle_notification(&req);
                    return None;
                }
                if let Err(e) = self.check_replay_id(&id) {
                    return Some(self.error_frame(id, e.code(), e.to_string()));
                }
                Some(self.dispatch(&req))
            }
            Err(McpError::ParseError(msg)) => {
                // JSON-RPC：解析失败时 id 恒为 null。
                Some(self.error_frame(RequestId::Null, -32700, msg))
            }
            Err(McpError::InvalidRequest(msg)) => {
                let id = extract_id_best_effort(line);
                Some(self.error_frame(id, -32600, msg))
            }
            Err(e) => Some(self.error_frame(RequestId::Null, e.code(), e.to_string())),
        }
    }

    /// 运行 stdio 服务循环（§3.1）：stdout = 协议帧，stderr = 日志。
    ///
    /// 逐行有界读取 stdin（单行上界 [`MAX_LINE_BYTES`]，L-7），响应写 stdout
    /// 并 flush；EOF（连接关闭）返回 `Ok(())`（§5.3 干净退出码由 CLI 层映射）。
    /// 调用方禁在 stdout 打日志。IO 语义见 [`Self::serve_with`]。
    pub fn serve_stdio(&self) -> std::io::Result<()> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        self.serve_with(stdin.lock(), stdout.lock())
    }

    /// 在任意 `BufRead` / `Write` 上运行服务循环（§3.1 传输；测试面注入
    /// `Cursor`/`Vec` 代替真实 stdin/stdout）。stdio 入口见 [`Self::serve_stdio`]。
    ///
    /// 逐行**有界**读取（L-7 / HIGH-1 同族）：行内容超 [`MAX_LINE_BYTES`] →
    /// 写 7005 错误帧（§3.4，客户端可见诊断）后返回 `Err`
    /// （帧同步已不可恢复；CLI 层映射退出码 2 协议致命，§5.3）。空行跳过；
    /// 非 UTF-8 行返回 `Err`；EOF 干净返回 `Ok(())`。
    pub fn serve_with<R: BufRead, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        loop {
            match read_bounded_line(&mut reader, &mut buf, MAX_LINE_BYTES)? {
                BoundedLine::TooLong => {
                    let msg = format!(
                        "single line exceeds MAX_LINE_BYTES ({MAX_LINE_BYTES} bytes)"
                    );
                    let frame = self.error_frame(RequestId::Null, 7005, msg);
                    writeln!(writer, "{frame}")?;
                    writer.flush()?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "protocol line exceeds MAX_LINE_BYTES",
                    ));
                }
                BoundedLine::Eof => break,
                BoundedLine::Line => {}
            }
            if buf.is_empty() {
                continue; // 空行（§3.1 忽略空行）。
            }
            let line = std::str::from_utf8(&buf).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid UTF-8 in protocol line: {e}"),
                )
            })?;
            let line = line.trim_end();
            if let Some(response) = self.handle_line(line) {
                writeln!(writer, "{response}")?;
                writer.flush()?;
            }
        }
        Ok(())
    }

    /// 通知处理（MVP 子集，§3.2）。
    fn handle_notification(&self, req: &RequestFrame) {
        match req.method.as_str() {
            "notifications/initialized" => { /* 客户端完成初始化，无响应 */ }
            "notifications/cancelled" => { /* 客户端取消（可选），MVP 忽略 */ }
            _ => { /* 未知通知：MCP 规范要求静默忽略（不产生响应） */ }
        }
    }

    /// Replay 防护（§3.6）：数值 id 单调递增，乱序/重号拒绝（`-32600`）。
    /// 字符串 id 无法排序，不校验；通知（无 id）不进入本检查。
    fn check_replay_id(&self, id: &RequestId) -> Result<(), McpError> {
        if let RequestId::Number(n) = id {
            let mut last = self.last_id.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(prev) = *last {
                if *n <= prev {
                    return Err(McpError::InvalidRequest(format!(
                        "message id {n} out of order (last seen {prev})"
                    )));
                }
            }
            *last = Some(*n);
        }
        Ok(())
    }

    /// 分发请求方法。
    fn dispatch(&self, req: &RequestFrame) -> String {
        let id = req.id.clone().unwrap_or(RequestId::Null);
        match req.method.as_str() {
            "initialize" => self.result_frame(
                id,
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "coffer",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }),
            ),
            "tools/list" => self.result_frame(id, json!({ "tools": self.tools.definitions() })),
            "tools/call" => self.handle_tools_call(req),
            "ping" => self.result_frame(id, json!({})),
            other => self.error_frame(id, -32601, format!("method not found: {other}")),
        }
    }

    /// tools/call：取 name + arguments，分发到工具注册表。
    fn handle_tools_call(&self, req: &RequestFrame) -> String {
        let id = req.id.clone().unwrap_or(RequestId::Null);
        let params = req.params.clone().unwrap_or(Value::Null);
        let name = match params.get("name").and_then(Value::as_str) {
            Some(n) => n.to_string(),
            None => {
                return self.error_frame(
                    id,
                    -32602,
                    "tools/call requires a string `name`".to_string(),
                )
            }
        };
        let args = params.get("arguments").cloned().unwrap_or(Value::Null);
        match self
            .tools
            .call(&*self.provider, &self.redactor, &*self.audit, &name, &args)
        {
            Ok(result) => self.result_frame(
                id,
                json!({ "content": result.content, "isError": result.is_error }),
            ),
            Err(e) => self.error_frame(id, e.code(), e.to_string()),
        }
    }

    /// 成功响应帧。
    fn result_frame(&self, id: RequestId, result: Value) -> String {
        let frame = ResponseFrame {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(id),
            result: Some(result),
            error: None,
        };
        to_json_string(&frame)
    }

    /// 错误响应帧（码值 §3.4）。
    fn error_frame(&self, id: RequestId, code: i64, message: String) -> String {
        let frame = ResponseFrame {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(id),
            result: None,
            error: Some(crate::protocol::ErrorObject { code, message }),
        };
        to_json_string(&frame)
    }
}

/// 有界单行读取的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedLine {
    /// 读到一行（内容在 `buf`，不含换行符）。
    Line,
    /// 行内容超上界（HIGH-1 同族拒收，L-7）。
    TooLong,
    /// EOF（无更多输入），服务循环应干净结束。
    Eof,
}

/// 有界地读取一行（`\n` 或 EOF 结束），内容存入 `buf`（不含 `\n`）。
///
/// L-7 核心：无论客户端单行多长，`buf` 累积**永不超 `max` 字节**——替代
/// `BufRead::lines()` 的无界整行物化，超大单行不再造成内存压力。超限返回
/// [`BoundedLine::TooLong`] 而不继续缓冲剩余行（帧同步已不可恢复）。
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<BoundedLine> {
    buf.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(BoundedLine::Eof);
        }
        // 本块内 `\n` 的位置（含）；无则取整块。`\n` 不计入内容上界。
        let nl = available.iter().position(|&b| b == b'\n');
        let has_nl = nl.is_some();
        let take = nl.map_or(available.len(), |i| i + 1);
        let content = take - usize::from(has_nl);
        if buf.len() + content > max {
            return Ok(BoundedLine::TooLong);
        }
        buf.extend_from_slice(&available[..content]);
        reader.consume(take);
        if has_nl {
            return Ok(BoundedLine::Line);
        }
    }
}

/// 序列化不可失败（`ResponseFrame` / `Value` 无非法键类型），失败仅能是内部 bug；
/// 不 panic（禁 unwrap），退化为不泄露细节的错误帧。
fn to_json_string<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_string(v) {
        Ok(s) => s,
        Err(_) => {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}"#
                .to_string()
        }
    }
}

/// 从（可能不完整的）行中尽力提取 id（供 `-32600` 错误响应回显）。
fn extract_id_best_effort(line: &str) -> RequestId {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .and_then(|v| {
            if let Some(n) = v.as_i64() {
                Some(RequestId::Number(n))
            } else if let Some(s) = v.as_str() {
                Some(RequestId::Str(s.to_string()))
            } else if v.is_null() {
                Some(RequestId::Null)
            } else {
                None
            }
        })
        .unwrap_or(RequestId::Null)
}

// ===========================================================================
// mcp::* 本地门面（docs/20 §2.4 lib.rs）
// ===========================================================================

/// `mcp::*` 本地门面——`cf_mcp::mcp::*` 公有签名（mcp_acceptance.rs 契约面）。
///
/// 4 个 MVP 工具经 [`provider::test_seed::TestSeedProvider`]（环境变量种子，
/// 契约见 `tests/mcp_acceptance.rs` 文件头）**真实实现**；其余 8 个
/// （grant/revoke/rotate/environment/audit）属 **D-1 未确认的收缩范围**
/// （docs/20 §1.3：MVP 只 4 工具），**保持桩**返回——对应验收用例保持红灯，
/// 由 lead 在 D-1 裁定后统一收口（本门面亦随 MCP 协议面收敛，见 [`crate::tools`]
/// 只注册 4 项）。
pub mod mcp {
    use std::error::Error;

    use crate::error::McpError;
    use crate::provider::test_seed::TestSeedProvider;
    use crate::provider::{RunSpec, SecretProvider};
    use crate::tools::secret_meta_json;

    /// 本门面使用的 provider（验收种子 provider；生产路径由 McpServer / CLI 注入）。
    fn provider() -> TestSeedProvider {
        TestSeedProvider
    }

    fn boxed(e: McpError) -> Box<dyn Error> {
        Box::new(e)
    }

    /// 列出全部 secret 名（无值）。MVP 工具（docs/20 §3.3）。
    pub fn list_secret_names() -> Result<Vec<String>, Box<dyn Error>> {
        provider()
            .list_secret_names(None)
            .map_err(|e| boxed(e.into()))
    }

    /// 列出全部 secret（名称 + 元数据 JSON；无值）。MVP 工具（docs/20 §3.3）。
    pub fn list_secrets() -> Result<Vec<(String, String)>, Box<dyn Error>> {
        let metas = provider().list_secrets(None).map_err(|e| boxed(e.into()))?;
        let entries: Vec<(String, String)> = metas
            .iter()
            .map(|m| {
                let json = serde_json::to_string(&secret_meta_json(m))
                    .map_err(|e| boxed(McpError::Internal(e.to_string())));
                json.map(|j| (m.name.clone(), j))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    /// 用 secret 运行命令（AS-5 模式 B）。注入的变量名 = secret 名；非零退出码
    /// **原样返回**（不吞、不误报 Err）。MVP 工具（docs/20 §3.3）。
    pub fn run_with_secret(secret: &str, cmd: &str, args: &[&str]) -> Result<i32, Box<dyn Error>> {
        let spec = RunSpec {
            secret_ref: secret.to_string(),
            env_name: secret.to_string(),
            cmd: cmd.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            cwd: None,
        };
        provider()
            .run_with_secret(&spec)
            .map_err(|e| boxed(e.into()))
    }

    /// 获取 secret 元数据 JSON（无值）。MVP 工具（docs/20 §3.3）。
    pub fn get_secret_metadata(secret: &str) -> Result<String, Box<dyn Error>> {
        let meta = provider()
            .get_secret_metadata(secret)
            .map_err(|e| boxed(e.into()))?;
        serde_json::to_string(&secret_meta_json(&meta))
            .map_err(|e| boxed(McpError::Internal(e.to_string())))
    }

    // -----------------------------------------------------------------------
    // D-1 未确认收缩范围的兼容桩（保持红灯；docs/20 §1.3 非 MVP）
    // -----------------------------------------------------------------------

    /// 列出全部环境。**D-1 未确认收缩范围，桩**（v2.x 完整面，docs/20 §1.3）。
    pub fn list_environments() -> Result<Vec<String>, Box<dyn Error>> {
        Ok(vec![])
    }

    /// 创建环境。**D-1 未确认收缩范围，桩**（v2.x 完整面，docs/20 §1.3）。
    pub fn create_environment(_name: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// 挂载环境到路径。**D-1 未确认收缩范围，桩**（AS-5 模式 C 非 MVP，§1.3）。
    pub fn mount_environment(_env: &str, _path: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// 向当前进程注入环境。**D-1 未确认收缩范围，桩**（AS-5 模式 A 非 MVP）。
    pub fn inject_environment(_env: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// 授权 secret 给 agent。**D-1 未确认收缩范围，桩**（AS-7 权限矩阵 v2.x）。
    pub fn grant_secret(_secret: &str, _agent: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// 撤销 secret 授权。**D-1 未确认收缩范围，桩**（AS-7 权限矩阵 v2.x）。
    pub fn revoke_secret(_secret: &str, _agent: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// 轮换 secret。**D-1 未确认收缩范围，桩**（AS-9 生命周期 v2.x）。
    pub fn rotate_secret(_secret: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// 审计 secret 使用。**D-1 未确认收缩范围，桩**（AS-10 审计入口 v2.x；
    /// 真实审计在 McpServer 工具路径内记录 USE 事件，见 [`crate::tools`]）。
    pub fn audit_secret_usage(_secret: &str) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
