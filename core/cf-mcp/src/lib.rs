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
    parse_frame, RequestFrame, RequestId, ResponseFrame, JSONRPC_VERSION, MAX_LINE_BYTES,
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
                    let msg =
                        format!("single line exceeds MAX_LINE_BYTES ({MAX_LINE_BYTES} bytes)");
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
/// （grant/revoke/rotate/environment/audit）按 docs/10 AS-5/AS-7/AS-9/AS-10
/// 语义**真实实现**：以「env 种子 + 进程内状态」承载（验收契约本就为绕开
/// U-4 存储未裁定而设计，不引入任何存储 API；生产存储见 feature 门控的
/// `provider::coffer`，本门面非存储）。AS-7 `allowed_agents` / AS-9
/// `last_rotated_at` 在**本门面层**并入元数据信封（`secret_meta_json` 非冻结，
/// trait 不动，lead 裁定 2026-10-05）。
pub mod mcp {
    use std::collections::{BTreeSet, HashMap};
    use std::error::Error;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use crate::error::McpError;
    use crate::provider::test_seed::{is_known_secret, TestSeedProvider, ENV_TEST_SECRET_PREFIX};
    use crate::provider::{RunSpec, SecretProvider};
    use crate::tools::secret_meta_json;
    // MEDIUM-2 facade 轮换同源生成器（docs/27 裁定 B）：仅 coffer-store feature 下
    // 引入 cf-audit（依赖树含 cf-crypto/rand/zxcvbn，docs/20 §2.2 只下不上）；
    // slim 构建（--no-default-features）不引入，facade 保留时间 nonce 兜底。
    #[cfg(feature = "coffer-store")]
    use cf_audit::{generate_password, PasswordGenOptions};

    /// 门面进程内状态（U-4 存储模型未裁定 → 用内存态承载验收可观察副作用）。
    #[derive(Debug, Default)]
    struct FacadeState {
        /// 已创建环境名（AS-5 模式 A/C 目标源）。
        envs: BTreeSet<String>,
        /// secret → 已授权 agent 集合（AS-7 allowed_agents 生命周期）。
        grants: HashMap<String, BTreeSet<String>>,
        /// secret → 最近轮换时间（unix 秒；AS-9 last_rotated_at）。
        rotated_at: HashMap<String, i64>,
    }

    /// 门面进程态（OnceLock 惰性初始化；Mutex 串行化并行验收用例）。
    fn state() -> &'static Mutex<FacadeState> {
        static STATE: OnceLock<Mutex<FacadeState>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(FacadeState::default()))
    }

    /// 环境是否已知：创建登记命中，或 `COFFER_MCP_TEST_ENV_VARS_<ENV>` 种子在位。
    fn env_known(env: &str) -> bool {
        let s = state().lock().unwrap_or_else(|p| p.into_inner());
        if s.envs.contains(env) {
            return true;
        }
        drop(s);
        std::env::var(format!("COFFER_MCP_TEST_ENV_VARS_{env}")).is_ok()
    }

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
    ///
    /// AS-9 生命周期信封（`secret_meta_json`）之上并入门面态：AS-7
    /// `allowed_agents`（grant/revoke 结果）与 AS-9 `last_rotated_at`
    /// （rotate 结果）；无操作的字段保持信封缺省（历史值由 provider 填充）。
    pub fn get_secret_metadata(secret: &str) -> Result<String, Box<dyn Error>> {
        let meta = provider()
            .get_secret_metadata(secret)
            .map_err(|e| boxed(e.into()))?;
        let mut envelope = secret_meta_json(&meta);
        let s = state().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(agents) = s.grants.get(secret) {
            envelope["allowed_agents"] =
                Value::Array(agents.iter().map(|a| Value::String(a.clone())).collect());
        }
        if let Some(ts) = s.rotated_at.get(secret) {
            envelope["last_rotated_at"] = Value::String(ts.to_string());
        }
        drop(s);
        serde_json::to_string(&envelope).map_err(|e| boxed(McpError::Internal(e.to_string())))
    }

    // -----------------------------------------------------------------------
    // v2.x 完整面（docs/20 §1.3 非 MVP；AS-5/AS-7/AS-9/AS-10 语义实现）
    // -----------------------------------------------------------------------

    /// 列出全部环境（AS-5：已创建环境回显，无注入/挂载面副作用）。
    pub fn list_environments() -> Result<Vec<String>, Box<dyn Error>> {
        let s = state().lock().unwrap_or_else(|p| p.into_inner());
        Ok(s.envs.iter().cloned().collect())
    }

    /// 创建环境（AS-5 模式 A/C 目标源）：登记名，重名 / 空名 / 纯空白拒绝。
    pub fn create_environment(name: &str) -> Result<(), Box<dyn Error>> {
        if name.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter(
                "empty environment name".into(),
            )));
        }
        let mut s = state().lock().unwrap_or_else(|p| p.into_inner());
        if !s.envs.insert(name.to_string()) {
            return Err(boxed(McpError::InvalidParameter(format!(
                "environment already exists: {name}"
            ))));
        }
        Ok(())
    }

    /// 挂载环境到路径（AS-5 模式 C 临时挂载）：要求 env 已知，落盘真实产物
    /// （挂载点目录）。未知 env / 空 env / 空路径拒绝。
    pub fn mount_environment(env: &str, path: &str) -> Result<(), Box<dyn Error>> {
        if env.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter(
                "empty environment name".into(),
            )));
        }
        if path.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter("empty mount path".into())));
        }
        if !env_known(env) {
            return Err(boxed(McpError::SecretNotFound(format!(
                "environment not found: {env}"
            ))));
        }
        std::fs::create_dir_all(path)
            .map_err(|e| boxed(McpError::Internal(format!("mount failed: {e}"))))?;
        Ok(())
    }

    /// 向当前进程注入环境（AS-5 模式 A）：把 `COFFER_MCP_TEST_ENV_VARS_<ENV>`
    /// 种子的 `NAME=VALUE` 清单写入进程 env —— 子进程（继承 env）可见变量名与
    /// 值，Agent 只见名。未知 env（种子缺失）拒绝。
    pub fn inject_environment(env: &str) -> Result<(), Box<dyn Error>> {
        if env.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter(
                "empty environment name".into(),
            )));
        }
        let raw = std::env::var(format!("COFFER_MCP_TEST_ENV_VARS_{env}")).map_err(|_| {
            boxed(McpError::SecretNotFound(format!(
                "environment not found: {env}"
            )))
        })?;
        for pair in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').ok_or_else(|| {
                boxed(McpError::InvalidParameter(format!(
                    "malformed env var entry: {pair}"
                )))
            })?;
            let k = k.trim();
            if k.is_empty() {
                return Err(boxed(McpError::InvalidParameter(
                    "empty env var name".into(),
                )));
            }
            std::env::set_var(k, v.trim());
        }
        Ok(())
    }

    /// 授权 secret 给 agent（AS-7）：记入门面 `allowed_agents`（元数据面合并）。
    /// 空 secret / 空 agent / 未知 secret 拒绝。
    pub fn grant_secret(secret: &str, agent: &str) -> Result<(), Box<dyn Error>> {
        if secret.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter(
                "empty secret name".into(),
            )));
        }
        if agent.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter("empty agent name".into())));
        }
        if !is_known_secret(secret) {
            return Err(boxed(McpError::SecretNotFound(format!(
                "secret not found: {secret}"
            ))));
        }
        let mut s = state().lock().unwrap_or_else(|p| p.into_inner());
        s.grants
            .entry(secret.to_string())
            .or_default()
            .insert(agent.to_string());
        Ok(())
    }

    /// 撤销 secret 授权（AS-7）：从 `allowed_agents` 剔除。参数校验同
    /// [`grant_secret`]；未授权 agent 撤销为幂等 Ok。
    pub fn revoke_secret(secret: &str, agent: &str) -> Result<(), Box<dyn Error>> {
        if secret.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter(
                "empty secret name".into(),
            )));
        }
        if agent.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter("empty agent name".into())));
        }
        if !is_known_secret(secret) {
            return Err(boxed(McpError::SecretNotFound(format!(
                "secret not found: {secret}"
            ))));
        }
        let mut s = state().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(agents) = s.grants.get_mut(secret) {
            agents.remove(agent);
        }
        Ok(())
    }

    /// 轮换 secret（AS-9）：写入新值（进程 env 种子面，验收可观察——子进程注入
    /// 面读取）并登记 `last_rotated_at`。空名 / 未知 secret 拒绝。
    pub fn rotate_secret(secret: &str) -> Result<(), Box<dyn Error>> {
        if secret.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter(
                "empty secret name".into(),
            )));
        }
        if !is_known_secret(secret) {
            return Err(boxed(McpError::SecretNotFound(format!(
                "secret not found: {secret}"
            ))));
        }
        // 轮换新值（MEDIUM-2，docs/27 裁定 B）：与 provider 同源——Coffer 生成器
        // 强随机值（cf_audit `generate_password` 默认档，CSPRNG 20 位四类字符去
        // 易混淆），不再用可预测时间戳 nonce。`generate_password` 仅 coffer-store
        // feature 下可用（cf-audit 依赖树含 cf-crypto/rand/zxcvbn，docs/20 §2.2
        // 只下不上）；`--no-default-features` slim 构建下 facade 为测试种子 mock
        //（仅 mcp_acceptance 消费、不落生产），保留时间 nonce 兜底并注明。
        #[cfg(feature = "coffer-store")]
        let new_value = generate_password(&PasswordGenOptions::default()).map_err(|reason| {
            boxed(McpError::Internal(format!(
                "password generation failed: {reason}"
            )))
        })?;
        #[cfg(not(feature = "coffer-store"))]
        let new_value = {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("rotated-{nonce}")
        };
        std::env::set_var(format!("{ENV_TEST_SECRET_PREFIX}{secret}"), new_value);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut s = state().lock().unwrap_or_else(|p| p.into_inner());
        s.rotated_at.insert(secret.to_string(), now);
        Ok(())
    }

    /// 审计 secret 使用（AS-10 入口）：校验 secret 已登记（未知拒绝）。
    /// 真实 USE/ROTATE/GRANT/REVOKE 事件在 [`crate::tools`] 工具路径内记录；
    /// 本入口守「未知即拒」的验收判据。
    pub fn audit_secret_usage(secret: &str) -> Result<(), Box<dyn Error>> {
        if secret.trim().is_empty() {
            return Err(boxed(McpError::InvalidParameter(
                "empty secret name".into(),
            )));
        }
        if !is_known_secret(secret) {
            return Err(boxed(McpError::SecretNotFound(format!(
                "secret not found: {secret}"
            ))));
        }
        Ok(())
    }
}
