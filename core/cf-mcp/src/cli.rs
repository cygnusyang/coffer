//! `coffer` CLI（docs/20 §5，G-D）。
//!
//! 主职责：把 `mcp` 子命令参数（§5.2 **冻结签名**）解析成 provider 配置 + 启动
//! [`crate::McpServer::serve_stdio`]。stdout 永为协议帧（§3.1）；日志只走
//! stderr 或 `--log` 文件。退出码映射见 §5.3 与 [`exit_code`]。
//!
//! ## 子命令（docs/20 §5.1）
//!
//! - `mcp`：MCP 服务（本文主体）；
//!
//! ## provider 选择（docs/20 §4.5 / §5.2；docs/27 D-2 缺省翻转）
//!
//! - `coffer`（`CofferStoreProvider`）为**缺省 provider**（D-2 用户裁定：无
//!   `--provider` 且无 `$COFFER_MCP_PROVIDER` → `coffer`）：经 `coffer-store`
//!   feature（default feature）从 `$COFFER_VAULT_DIR` / `$COFFER_VAULT_PASSWORD`
//!   构造（§4.3 同款 env 约定；密码不经 argv/日志）；
//! - feature 关闭（`--no-default-features`）时缺省 coffer 不可用 → 回落 `op`
//!   （op 可用则 op，日志告警）；op 亦不可用 → 7001 退出 1（D-1 退出码契约
//!   不破坏，非 panic/挂死）；
//! - `op`（`OpProvider`）为可选第二 provider：`--provider op` 显式选择行为不变；
//! - feature 关闭时显式 `--provider coffer`（flag 或 env 均为显式选择）→ 同任意
//!   未知 provider → 配置错误退出 1（D-1：coffer 仅 feature 构建下可用）。
//!
//! ## 传输（docs/20 §3.1 / §3.6，v2.1.0 D-4 实现）
//!
//! 缺省 **stdio**；`--uds PATH`（或 `$COFFER_MCP_UDS`，见 [`resolve_uds_path`]）
//! 切换 UDS **本机回环**传输（[`crate::uds`] 模块，§3.6 防护全套：0600/0700
//! 权限、peer 凭据校验、会话 challenge、单调 id）。协议帧格式与退出码契约
//! 不变（§5.3 / D-1 冻结面零改动）。**零网络**：无 TCP/UDP 代码路径（§3.1；
//! AF_UNIX 本机回环不违背「不去云端」，docs/27 D-4 新口径）。
//!
//! ## 日志纪律（§3.1 / §3.5-4）
//!
//! - stdout 永为协议帧；CLI 自身日志只经 [`Logger`]（stderr 或 `--log` 文件）；
//! - 致命启动错误（解析失败 / provider 不可用 / 身份缺失）恒走 stderr（操作者
//!   必须可见）；运行时生命周期日志（启动 / 关闭）经 [`Logger`] 落 sink；
//! - `tracing::warn!` / `error!` 事件（如工具层审计失败告警，tools.rs）经
//!   [`DiagnosticSubscriber`] 订阅到**同一诊断通道**（L-5，审计失败告警不再被
//!   丢弃——stderr 或 `--log` 文件可观察）；
//! - 日志/错误载荷**不**含 Secret 值（§3.5-4 载荷纪律）。
//!
//! ## 依赖纪律（docs/20 §2.2）
//!
//! 本模块不新增第三方依赖：flag 集冻结且很小 → 参数解析手写（不引 clap）；
//! 日志走最小 [`Logger`]（stderr / `--log` 文件）；L-5 诊断订阅器为手写极简
//! `tracing::Subscriber`（[`DiagnosticSubscriber`]，复用既有 tracing crate，
//! 不引 tracing-subscriber）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::provider::op::{OpProvider, OpProviderConfig};
use crate::provider::{ProviderError, SecretProvider};
use crate::uds;
use crate::McpServer;

#[cfg(feature = "coffer-store")]
use crate::provider::coffer::CofferStoreProvider;
#[cfg(feature = "coffer-store")]
use crate::provider::escrow::{EscrowErrorKind, VaultEscrowStore};
#[cfg(feature = "coffer-store")]
use cf_domain::secret::SecretString;
#[cfg(feature = "coffer-store")]
use cf_domain::CfError;
#[cfg(feature = "coffer-store")]
use cf_session::open_vault;
#[cfg(feature = "coffer-store")]
use zeroize::Zeroize;

/// 退出码（docs/20 §5.3）。
///
/// - `0` 干净退出（连接关闭 / shutdown）
/// - `1` 配置错误（未知 flag / provider 不可用）
/// - `2` 协议致命错误
/// - `3` 身份缺失（7002）
pub mod exit_code {
    /// 干净退出（连接关闭 / shutdown）。
    pub const CLEAN: i32 = 0;
    /// 配置错误（未知 flag / provider 不可用）。
    pub const CONFIG_ERROR: i32 = 1;
    /// 协议致命错误。
    pub const PROTOCOL_FATAL: i32 = 2;
    /// 身份缺失（7002）。
    pub const IDENTITY_MISSING: i32 = 3;
}

/// CLI 参数 / 配置错误（docs/20 §5.2；§5.3 映射到退出码 1）。
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// 未知 flag / 位置参数。
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    /// flag 缺值。
    #[error("flag `{0}` requires a value")]
    MissingValue(String),
    /// `--log` 文件无法打开。
    #[error("cannot open log file `{path}`: {source}")]
    LogOpen {
        /// 日志文件路径。
        path: String,
        /// 底层 IO 错误。
        source: std::io::Error,
    },
}

/// `coffer mcp` 已解析选项（docs/20 §5.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCliOptions {
    /// provider 名（`coffer` 缺省，D-2；`op` 显式选择；`coffer` 经
    /// `coffer-store` feature 门控，缺省 `$COFFER_MCP_PROVIDER` 再内置 `coffer`）。
    pub provider: String,
    /// provider 是否由用户显式选择（`--provider` flag 或 `$COFFER_MCP_PROVIDER`
    /// 给定），而非内置缺省。feature 关闭时，缺省 coffer 回落 op；显式 coffer
    /// 则按 D-1 报 unsupported（docs/27 D-2）。
    pub provider_explicit: bool,
    /// 默认 vault（`--vault NAME`；缺省由 [`OpProviderConfig::from_env`] 读
    /// `$COFFER_OP_VAULT`，本层只收集 flag 覆盖值）。
    pub vault: Option<String>,
    /// 日志文件路径（`--log PATH`；`None` = stderr）。
    pub log_path: Option<PathBuf>,
    /// 关闭审计记录（`--no-audit`；缺省开启）。
    pub no_audit: bool,
    /// UDS 监听路径（`--uds PATH`；`None` = stdio 或回落 `$COFFER_MCP_UDS`，
    /// 见 [`resolve_uds_path`]）。v2.1.0 D-4 实现（docs/20 §3.1/§3.6）。
    pub uds: Option<PathBuf>,
}

/// 从 argv（不含子命令 `mcp`）解析 `coffer mcp` 选项（docs/20 §5.2 冻结签名）。
///
/// 缺省值：
/// - `--provider`：`$COFFER_MCP_PROVIDER`，未设 → `coffer`（D-2 缺省翻转，
///   docs/27 D-2）；`provider_explicit` 标记 flag/env 是否给定（feature 关闭时
///   缺省 coffer 回落 op，显式 coffer 按 D-1 报 unsupported）；
/// - `--vault`：不在本层解析（由 [`OpProviderConfig::from_env`] 读
///   `$COFFER_OP_VAULT`）；
/// - `--log` / `--no-audit` / `--uds`：本层直收（`--uds` 未给时回落
///   `$COFFER_MCP_UDS`，见 [`resolve_uds_path`]）。
///
/// 未知 flag / 位置参数 → [`CliError::UnknownFlag`]；值 flag 缺值 →
/// [`CliError::MissingValue`]。
pub fn parse_args(args: &[String]) -> Result<McpCliOptions, CliError> {
    let mut provider: Option<String> = None;
    let mut log_path: Option<PathBuf> = None;
    let mut vault: Option<String> = None;
    let mut no_audit = false;
    let mut uds: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--provider" => {
                provider = Some(take_value(args, &mut i, "--provider")?);
            }
            "--vault" => {
                vault = Some(take_value(args, &mut i, "--vault")?);
            }
            "--log" => {
                let path = take_value(args, &mut i, "--log")?;
                log_path = Some(PathBuf::from(path));
            }
            "--uds" => {
                // v2.1.0 D-4 实现（docs/20 §3.1/§3.6）：监听 UDS 而非 stdio。
                let path = take_value(args, &mut i, "--uds")?;
                uds = Some(PathBuf::from(path));
            }
            "--no-audit" => {
                no_audit = true;
            }
            other => return Err(CliError::UnknownFlag(other.to_string())),
        }
        i += 1;
    }

    let flag_provider = provider;
    let env_provider = std::env::var("COFFER_MCP_PROVIDER").ok();
    let provider_explicit = flag_provider.is_some() || env_provider.is_some();
    let provider = flag_provider
        .or(env_provider)
        .unwrap_or_else(|| "coffer".to_string());

    Ok(McpCliOptions {
        provider,
        provider_explicit,
        log_path,
        vault,
        no_audit,
        uds,
    })
}

/// 解析 UDS 监听路径：`--uds PATH` flag 优先；未给则回落 `$COFFER_MCP_UDS`
/// （非空；docs/20 §4.3）。`None` = stdio 传输。
fn resolve_uds_path(options: &McpCliOptions) -> Option<PathBuf> {
    if let Some(p) = &options.uds {
        return Some(p.clone());
    }
    std::env::var(uds::UDS_ENV_PATH)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
}

/// 取 flag 的下一个取值；缺值 → [`CliError::MissingValue`]。推进 `i` 越过取值。
fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, CliError> {
    let next = *i + 1;
    if next >= args.len() {
        return Err(CliError::MissingValue(flag.to_string()));
    }
    *i = next;
    Ok(args[next].clone())
}

/// `--provider coffer` 取密流程（docs/29 §6.2，D-4 冻结契约）：
/// **托管优先 → env 兜底 → 都无退出 1**。
///
/// 流程：`COFFER_VAULT_DIR` 必填（缺 → 配置错误退出 1，现状维持）→
/// `open_vault`（**锁定态**读 header，取 vault_uuid）→
/// [`VaultEscrowStore::read_mcp_key`]：
///
/// - `Ok(Some(mcp_key))` → `unlock_with_mcp_key`；失败 → **fail-closed 退出 1**
///   （提示从 App 重新启用 MCP 以重建托管，**绝不回落 env**）；
/// - `Ok(None)`（托管不存在）→ env 兜底：有 `COFFER_VAULT_PASSWORD` → 密码解锁
///   + warning `source="env-fallback"`；无 → 配置错误退出 1（提示启用托管或提供
///     `COFFER_VAULT_PASSWORD`）；
/// - `Err(..)`（读取失败：ACL / 签名 / 内容非法）→ **fail-closed 退出 1**
///   （可操作消息，不回退 env）。
///
/// **read 门（lead 裁定 2026-10-07，§5.2 意图源语义）**：仅当 header
/// `mcp_wrap.available == true`（用户经 App 显式启用托管）才读 Keychain；
/// `available == false` = 用户显式停用托管 → 语义即「托管不存在」→ **直接走
/// env 兜底，不触 Keychain read**。孤儿条目边界：header 禁用 + keychain 残留
/// → 仍走 env（`unlock_with_mcp_key` 对该态本就 1002，header 为意图源）。
///
/// **env 不覆盖托管**（D-4）：托管条目存在即不再看 env；env 仅在托管不存在
/// （`Ok(None)` / `available=false`）时兜底。mcp_key **不经 argv / 协议帧 /
/// 日志**（§3.5-4）；`[u8; 32]` 用后显式 zeroize。
///
/// 成功会话 → [`CofferStoreProvider::new`]（复用既有构造，coffer.rs:99）。
#[cfg(feature = "coffer-store")]
fn build_coffer_provider(
    vault_dir: &std::path::Path,
    escrow: &dyn VaultEscrowStore,
    env_password: Option<SecretString>,
    logger: &mut Logger,
) -> Result<CofferStoreProvider, i32> {
    let session = match open_vault(vault_dir) {
        Ok(s) => s,
        Err(e) => {
            let (msg, code) = match e {
                CfError::VaultNotFound | CfError::UnsupportedFormat(_) => (
                    format!("error: provider unavailable (7001): cannot open vault: {e}"),
                    exit_code::CONFIG_ERROR,
                ),
                other => (
                    format!("error: provider open failed: {other}"),
                    exit_code::CONFIG_ERROR,
                ),
            };
            logger.error(&msg);
            return Err(code);
        }
    };

    // read 门（lead 裁定 2026-10-07，§5.2 意图源语义）：available=false =
    // 用户显式停用托管 → 语义即「托管不存在」→ 直接 env 兜底，不触 Keychain。
    if !session.has_mcp_wrap() {
        return env_fallback_unlock(session, env_password, logger);
    }

    let vault_uuid = session.vault_uuid().to_string();
    match escrow.read_mcp_key(&vault_uuid) {
        Ok(Some(mut mcp_key)) => {
            let r = session.unlock_with_mcp_key(&mcp_key);
            mcp_key.zeroize();
            match r {
                Ok(_) => {
                    logger.info(
                        "vault unlocked via MCP keychain escrow (source=\"keychain-escrow\")",
                    );
                }
                Err(_) => {
                    // fail-closed：托管条目存在但不可用（吊销 / 损坏 / 库换过）
                    // → 报错退出 1，不静默回落 env（多凭据静默重试 = 安全反模式，
                    // 与 challenge fail-closed 先例一致，docs/30 §1.3）。
                    logger.error(
                        "error: MCP 托管条目存在但解锁失败（可能已吊销/损坏）；\
                         请从 App 重新启用 MCP 以重建托管（source=\"keychain-escrow-failed\"）",
                    );
                    return Err(exit_code::CONFIG_ERROR);
                }
            }
        }
        Ok(None) => return env_fallback_unlock(session, env_password, logger),
        Err(e) => {
            // fail-closed：读取失败不回退 env（防掩盖签名 / ACL 问题，D-4）。
            let hint = match e.kind() {
                EscrowErrorKind::AccessDenied => {
                    "；请确认 CLI 与 App 同 bundle 同身份签名（docs/29 D-6）"
                }
                EscrowErrorKind::NotFound => "；请从 App 重新启用 MCP 以重建托管",
                EscrowErrorKind::Other => "",
            };
            logger.error(&format!("error: MCP 托管读取失败：{e}{hint}"));
            return Err(exit_code::CONFIG_ERROR);
        }
    }

    Ok(CofferStoreProvider::new(session))
}

/// env 兜底解锁（docs/29 §6.2，仅托管不存在时进入）：
/// 有 `COFFER_VAULT_PASSWORD` → `unlock` + warning `source="env-fallback"`；
/// 无 → 配置错误退出 1（提示启用托管或提供 env）。解锁失败按 §5.3 映射
/// （7002 → 3 身份缺失；7001 / 其余 → 1）。
#[cfg(feature = "coffer-store")]
fn env_fallback_unlock(
    session: cf_session::VaultSession,
    env_password: Option<SecretString>,
    logger: &mut Logger,
) -> Result<CofferStoreProvider, i32> {
    let Some(password) = env_password else {
        logger.error(
            "error: 未启用 MCP 解锁托管，也未提供 $COFFER_VAULT_PASSWORD；\
             请在 App 设置页启用 MCP 托管，或设置 $COFFER_VAULT_PASSWORD（docs/20 §4.5）",
        );
        return Err(exit_code::CONFIG_ERROR);
    };
    match session.unlock(password.expose()) {
        Ok(_) => {
            logger.warn("vault unlocked via env password fallback (source=\"env-fallback\")");
            Ok(CofferStoreProvider::new(session))
        }
        Err(e) => {
            let (msg, code) = match e {
                CfError::VaultLocked | CfError::UnlockFailed => (
                    format!("error: identity missing (7002): vault unlock failed: {e}"),
                    exit_code::IDENTITY_MISSING,
                ),
                other => (
                    format!("error: provider open failed: {other}"),
                    exit_code::CONFIG_ERROR,
                ),
            };
            logger.error(&msg);
            Err(code)
        }
    }
}

/// 诊断通道写端（stdout 永为协议帧，docs/20 §3.1）。
///
/// 输出目标：`--log PATH` 文件（追加），缺省 stderr。**永不写 stdout**。
/// 文件句柄以 `Arc<Mutex<File>>` 承载——[`Logger`] 与 [`DiagnosticSubscriber`]
///（L-5）共用同一文件写端（追加模式，行写互斥）。文件写失败为尽力而为
///（日志不阻断服务）。
#[derive(Debug, Clone)]
enum LogSink {
    /// stderr（缺省）。
    Stderr,
    /// `--log PATH` 追加文件（共享句柄）。
    File(Arc<Mutex<std::fs::File>>),
}

impl LogSink {
    /// 写一行诊断日志（unix 秒前缀）。文件写失败忽略——日志是尽力而为
    /// （审计同纪律，docs/20 §4.6）。
    fn write_line(&self, level: &str, msg: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("[{ts}] [{level}] {msg}");
        match self {
            LogSink::Stderr => eprintln!("{line}"),
            LogSink::File(f) => {
                let mut f = f.lock().unwrap_or_else(|p| p.into_inner());
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

/// CLI 运行时日志接收器（stdout 永为协议帧，docs/20 §3.1）。
///
/// 输出目标：`--log PATH` 文件（追加），缺省 stderr。**永不写 stdout**。
/// `Clone`：notify.sock 监听线程经克隆句柄共享同一诊断通道（配对集成 W）。
#[derive(Debug, Clone)]
pub struct Logger {
    sink: LogSink,
}

impl Logger {
    /// 按选项构造日志器；打开 `--log` 文件失败 → [`CliError::LogOpen`]。
    pub fn new(options: &McpCliOptions) -> Result<Self, CliError> {
        let sink = match &options.log_path {
            None => LogSink::Stderr,
            Some(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| CliError::LogOpen {
                        path: path.display().to_string(),
                        source: e,
                    })?;
                LogSink::File(Arc::new(Mutex::new(file)))
            }
        };
        Ok(Self { sink })
    }

    /// 信息级日志。
    pub fn info(&mut self, msg: &str) {
        self.sink.write_line("INFO", msg);
    }

    /// 警告级日志（非致命）。
    pub fn warn(&mut self, msg: &str) {
        self.sink.write_line("WARN", msg);
    }

    /// 错误级日志（致命启动错误，操作者必须可见）。经同一诊断通道（stderr /
    /// `--log` 文件）落盘，供可测性与生产排障共用。
    pub fn error(&mut self, msg: &str) {
        self.sink.write_line("ERROR", msg);
    }

    /// 供 L-5 诊断订阅器共享诊断通道写端（stderr / `--log` 文件同一句柄）。
    fn sink_handle(&self) -> LogSink {
        self.sink.clone()
    }
}

/// L-5：把 `tracing::warn!` / `error!` 事件写入与 [`Logger`] 相同的诊断通道
/// （stderr / `--log` 文件），审计失败告警（tools.rs）不再被丢弃。
///
/// 极简手写 `tracing::Subscriber`（复用既有 tracing crate，**不引
/// tracing-subscriber**，依赖树零新增，docs/20 §2.2 / docs/28 §1.3）：
///
/// - `enabled` 只放行 WARN/ERROR 级（INFO/DEBUG 不写诊断通道）；
/// - 不追踪 span（`new_span`/`enter`/`exit` 无操作）；
/// - 事件字段 `message` 作主文案，其余以 `key=value` 平铺。
///
/// 纪律：诊断通道不得含 Secret **值**（§3.5-4 载荷纪律）——事件载荷仅含 secret
/// 引用（名），与既有 Logger 日志同界。
#[derive(Debug)]
struct DiagnosticSubscriber {
    sink: LogSink,
}

impl DiagnosticSubscriber {
    /// 以共享诊断通道写端构造订阅器。
    fn new(sink: LogSink) -> Self {
        Self { sink }
    }
}

impl tracing::Subscriber for DiagnosticSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        // 级别越低越严重：WARN(2) / ERROR(1) 放行，INFO(3) 及以下不写。
        *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(0)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = FieldCollector::default();
        event.record(&mut visitor);
        let mut message = String::from("<event>");
        let mut rest: Vec<String> = Vec::new();
        for (key, value) in visitor.fields {
            if key == "message" {
                message = value;
            } else {
                rest.push(format!("{key}={value}"));
            }
        }
        let mut line = message;
        for part in rest {
            line.push(' ');
            line.push_str(&part);
        }
        self.sink
            .write_line(event.metadata().level().as_str(), &line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}

    fn clone_span(&self, id: &tracing::span::Id) -> tracing::span::Id {
        id.clone()
    }

    fn try_close(&self, _: tracing::span::Id) -> bool {
        true
    }
    // `current_span` 不覆盖——tracing 0.1.44 不导出 `tracing::span::Current`
    // （tracing-core 内部类型），且 trait 默认实现（`Current::unknown`）语义
    // 对本订阅器（不追踪 span）正确，故省略。
}

/// 事件字段收集器（`tracing::field::Visit`）：平铺 `key=value` 对。
#[derive(Debug, Default)]
struct FieldCollector {
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for FieldCollector {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

/// 构造 `op` provider（OpProvider，docs/20 §4.5 / §5.2）：`--vault` 覆盖 env 缺省
/// （COFFER_OP_BIN / COFFER_OP_VAULT / COFFER_OP_SESSION_TOKEN，§4.3）；`op --version`
/// 启动探测失败 → 7001 → 退出 1；启动期身份检查（§5.3 退出码 3）：list 面探测，
/// 仅 `AuthRequired`（7002）阻断启动，其余探测错误非致命（协议层暴露）。
///
/// 返回 `(provider, vault_label)`；失败返回退出码（1 provider 不可用 / 3 身份缺失）。
fn build_op_provider(
    vault_override: Option<String>,
    logger: &mut Logger,
) -> Result<(Box<dyn SecretProvider>, String), i32> {
    let mut config = OpProviderConfig::from_env();
    if let Some(vault) = vault_override {
        config.default_vault = Some(vault);
    }
    let vault_hint = config.default_vault.clone();

    // 构造 provider：`op --version` 启动探测（docs/20 §4.2）；失败 → 7001 → 退出 1。
    let p = match OpProvider::new(config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: provider unavailable (7001): {e}");
            return Err(exit_code::CONFIG_ERROR);
        }
    };

    // 启动期身份检查（docs/20 §5.3 退出码 3）：轻量探测 provider 的 list 面。
    // 仅 `AuthRequired`（7002）阻断启动；其余探测错误非致命（在协议层暴露）。
    match p.list_secret_names(vault_hint.as_deref()) {
        Err(ProviderError::AuthRequired(m)) => {
            eprintln!("error: identity missing (7002): {m}");
            return Err(exit_code::IDENTITY_MISSING);
        }
        Err(e) => {
            logger.warn(&format!("provider startup probe: {e}"));
        }
        Ok(_) => {}
    }

    Ok((
        Box::new(p),
        vault_hint.unwrap_or_else(|| "default".to_string()),
    ))
}

/// `coffer` bin 入口：解析 argv → 构建 provider → 启动 stdio 服务，返回退出码。
///
/// `args` = `argv[1..]`（不含程序名），首个非 flag 参数须为子命令 `mcp`
/// （docs/20 §5.1）。退出码按 §5.3 映射：
///
/// - 致命启动错误（解析 / provider / 身份）恒写 stderr 并退出 1 或 3；
/// - 运行时生命周期日志经 [`Logger`]（stderr / `--log` 文件），服务正常结束退出 0；
/// - [`McpServer::serve_stdio`] 的 IO 失败（连接异常）→ 退出 2（协议致命）。
///
/// 本函数不 panic（生产禁 unwrap / expect）；`main.rs` 仅透传返回码。
pub fn run(args: &[String]) -> i32 {
    let Some(subcommand) = args.first() else {
        eprintln!("error: missing subcommand; expected `coffer mcp` (docs/20 §5.2)");
        return exit_code::CONFIG_ERROR;
    };
    if subcommand != "mcp" {
        eprintln!("error: unknown subcommand `{subcommand}`; expected `coffer mcp` (docs/20 §5.2)");
        return exit_code::CONFIG_ERROR;
    }

    let options = match parse_args(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            return exit_code::CONFIG_ERROR;
        }
    };

    let mut logger = match Logger::new(&options) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: {e}");
            return exit_code::CONFIG_ERROR;
        }
    };

    // L-5：订阅 `tracing::warn!` / `error!`（如工具层审计失败告警）到与 Logger
    // 同一诊断通道（stderr / `--log` 文件），告警不再被丢弃。线程本地默认订阅器
    // （stdio 服务单线程主循环），作用域 = 本 run() 生命周期。
    let _tracing_guard =
        tracing::subscriber::set_default(DiagnosticSubscriber::new(logger.sink_handle()));

    // provider 选择（docs/20 §4.5 / §5.2；docs/27 D-2 缺省翻转）：`coffer`
    //（CofferStoreProvider）为缺省；`op`（OpProvider）为可选第二 provider——
    // `--provider op` 显式选择行为不变。
    let vault_override = options.vault.clone();
    let provider: Box<dyn SecretProvider>;
    let provider_name: &str;
    let vault_label: String;
    match options.provider.as_str() {
        "op" => match build_op_provider(vault_override, &mut logger) {
            Ok((p, label)) => {
                provider = p;
                provider_name = "op";
                vault_label = label;
            }
            Err(code) => return code,
        },
        #[cfg(feature = "coffer-store")]
        "coffer" => {
            // CofferStoreProvider（docs/20 §4.5）：取密走 docs/29 §6.2 托管优先
            // 流程（D-4）。`COFFER_VAULT_DIR` 必填（缺 → 配置错误退出 1 现状
            // 维持）；`COFFER_VAULT_PASSWORD` 现为**可选**（仅托管不存在时
            // env 兜底）。escrow store = 平台默认（macOS Keychain）；mcp_key /
            // 密码经 `SecretString` / 显式 zeroize 承载，不经 argv/日志
            // （§3.5-4 载荷纪律）。
            let vault_dir = match std::env::var("COFFER_VAULT_DIR") {
                Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
                _ => {
                    logger.error(
                        "error: `--provider coffer` requires $COFFER_VAULT_DIR（库目录路径，docs/20 §4.5）",
                    );
                    return exit_code::CONFIG_ERROR;
                }
            };
            let env_password = std::env::var("COFFER_VAULT_PASSWORD")
                .ok()
                .map(SecretString::from_exposed);
            let escrow = crate::provider::escrow::platform_escrow();
            let p = match build_coffer_provider(&vault_dir, &escrow, env_password, &mut logger) {
                Ok(p) => p,
                Err(code) => return code,
            };
            provider = Box::new(p);
            provider_name = "coffer";
            vault_label = "coffer-store".to_string();
        }
        #[cfg(not(feature = "coffer-store"))]
        "coffer" if !options.provider_explicit => {
            // D-2 缺省翻转（docs/27）：feature 关闭构建下缺省 coffer 不可用 →
            // 回落 `op`（op 可用则 op）；op 亦不可用 → 7001 退出 1（D-1 退出码
            // 契约不破坏，非 panic/挂死）。显式 `--provider coffer` / env coffer
            // 走 `other` 臂按 D-1 报 unsupported。
            logger.warn(
                "provider `coffer` unavailable in this build (feature `coffer-store` off); \
                 defaulting to `op`",
            );
            match build_op_provider(vault_override, &mut logger) {
                Ok((p, label)) => {
                    provider = p;
                    provider_name = "op";
                    vault_label = label;
                }
                Err(code) => return code,
            }
        }
        other => {
            let supported = if cfg!(feature = "coffer-store") {
                "`op` / `coffer`"
            } else {
                "`op`"
            };
            eprintln!("error: unsupported provider `{other}`: 支持 {supported}（docs/20 §5.2）");
            return exit_code::CONFIG_ERROR;
        }
    }

    // audit（docs/20 §5.2 --no-audit）：D-3 未确认前审计恒 NoopAudit（§4.6 方案 B）。
    // --no-audit 与缺省（开启）在 JSONL 落定前行为相同，仅体现在日志声明。
    if options.no_audit {
        logger.info("audit: off (--no-audit)");
    } else {
        logger.info("audit: on (NoopAudit until D-3 JSONL lands)");
    }

    let server = McpServer::new(provider);

    // 传输选择（docs/20 §3.1）：`--uds PATH` / `$COFFER_MCP_UDS` → UDS 本机回环
    //（§3.6 防护全套，见 [`crate::uds::run`]）；缺省 stdio。协议帧格式与退出码
    // 契约两传输一致（D-1 冻结面零改动）。
    if let Some(path) = resolve_uds_path(&options) {
        logger.info(&format!(
            "serving on uds {} (provider={provider_name}, vault={vault_label})",
            path.display()
        ));
        return uds::run(&path, &mut logger, server);
    }

    logger.info(&format!(
        "serving on stdio (provider={provider_name}, vault={vault_label})"
    ));

    match server.serve_stdio() {
        Ok(()) => {
            logger.info("connection closed, exiting");
            exit_code::CLEAN
        }
        Err(e) => {
            eprintln!("error: stdio serve failed: {e}");
            exit_code::PROTOCOL_FATAL
        }
    }
}

// ===========================================================================
// 单元测试（纯解析面；集成面见 tests/cli.rs —— spawn `coffer` 二进制）
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditError, AuditEvent, UsageAudit};
    #[cfg(feature = "coffer-store")]
    use crate::provider::escrow::EscrowError;
    use crate::provider::test_seed::TestSeedProvider;
    use serde_json::json;
    use std::path::PathBuf;

    /// 环境变量是进程级共享状态，串行化读写（同 provider_op_list ENV_LOCK 纪律）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn arg(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parse_full_flag_set() {
        let o = parse_args(&arg(&[
            "--provider",
            "op",
            "--vault",
            "Personal",
            "--log",
            "/tmp/coffer.log",
            "--no-audit",
            "--uds",
            "/tmp/coffer.sock",
        ]))
        .expect("valid flag set must parse");
        assert_eq!(o.provider, "op");
        assert_eq!(o.vault.as_deref(), Some("Personal"));
        assert_eq!(
            o.log_path.as_deref(),
            Some(PathBuf::from("/tmp/coffer.log").as_path())
        );
        assert!(o.no_audit);
        assert_eq!(
            o.uds.as_deref(),
            Some(PathBuf::from("/tmp/coffer.sock").as_path()),
            "--uds 须解析进选项"
        );
    }

    #[test]
    fn parse_empty_args_use_builtin_defaults() {
        let _g = env_guard();
        std::env::remove_var("COFFER_MCP_PROVIDER");
        let o = parse_args(&[]).expect("empty args must parse");
        assert_eq!(
            o.provider, "coffer",
            "缺省 provider = coffer（D-2，docs/27）"
        );
        assert!(
            !o.provider_explicit,
            "无 flag 无 env → 非显式选择（内置缺省）"
        );
        assert_eq!(o.vault, None);
        assert_eq!(o.log_path, None);
        assert!(!o.no_audit, "审计缺省开启");
    }

    #[test]
    fn parse_provider_defaults_to_env_when_flag_absent() {
        let _g = env_guard();
        std::env::set_var("COFFER_MCP_PROVIDER", "op");
        let o = parse_args(&[]).expect("empty args must parse");
        assert_eq!(o.provider, "op", "--provider 缺省读 $COFFER_MCP_PROVIDER");
        assert!(o.provider_explicit, "env 给定 → 显式选择");
        std::env::remove_var("COFFER_MCP_PROVIDER");
    }

    #[test]
    fn parse_flag_overrides_env_default() {
        let _g = env_guard();
        std::env::set_var("COFFER_MCP_PROVIDER", "op");
        let o = parse_args(&arg(&["--provider", "op"])).expect("explicit --provider must parse");
        assert_eq!(o.provider, "op");
        assert!(o.provider_explicit, "flag 给定 → 显式选择");
        std::env::remove_var("COFFER_MCP_PROVIDER");
    }

    #[test]
    fn parse_env_coffer_is_explicit_not_builtin_default() {
        // D-2：env 显式 coffer ≠ 内置缺省 coffer——feature 关闭构建下前者按
        // D-1 报 unsupported，后者回落 op。语义差异由 `provider_explicit` 承载。
        let _g = env_guard();
        std::env::set_var("COFFER_MCP_PROVIDER", "coffer");
        let o = parse_args(&[]).expect("empty args must parse");
        assert_eq!(o.provider, "coffer");
        assert!(o.provider_explicit, "env coffer 是显式选择，非内置缺省");
        std::env::remove_var("COFFER_MCP_PROVIDER");
    }

    #[test]
    fn parse_rejects_unknown_flag() {
        let err = parse_args(&arg(&["--bogus"])).expect_err("unknown flag must be rejected");
        assert!(matches!(err, CliError::UnknownFlag(f) if f == "--bogus"));
    }

    #[test]
    fn parse_rejects_positional_argument() {
        // parse_args 接收的是子命令 `mcp` 之后的参数；位置参数须被拒。
        let err = parse_args(&arg(&["extra"])).expect_err("positional must be rejected");
        assert!(matches!(err, CliError::UnknownFlag(f) if f == "extra"));
    }

    #[test]
    fn parse_rejects_missing_value() {
        let err = parse_args(&arg(&["--vault"])).expect_err("missing value must be rejected");
        assert!(matches!(err, CliError::MissingValue(f) if f == "--vault"));
        let err = parse_args(&arg(&["--log"])).expect_err("missing value must be rejected");
        assert!(matches!(err, CliError::MissingValue(f) if f == "--log"));
    }

    #[test]
    fn parse_accepts_uds() {
        // v2.1.0 D-4 实现（docs/27）：--uds 激活，不再是占位未实现。
        let o = parse_args(&arg(&["--uds", "/tmp/coffer.sock"]))
            .expect("--uds must parse (v2.1.0 D-4)");
        assert_eq!(o.uds, Some(PathBuf::from("/tmp/coffer.sock")));
    }

    #[test]
    fn parse_rejects_uds_missing_value() {
        let err = parse_args(&arg(&["--uds"])).expect_err("--uds without value must be rejected");
        assert!(matches!(err, CliError::MissingValue(f) if f == "--uds"));
    }

    #[test]
    fn cli_error_messages_are_actionable() {
        // 错误消息面向调用方可操作（载荷纪律：不含敏感值）。
        let unknown = CliError::UnknownFlag("--xyz".into());
        assert_eq!(unknown.to_string(), "unknown flag: --xyz");
        let missing = CliError::MissingValue("--vault".into());
        assert_eq!(missing.to_string(), "flag `--vault` requires a value");
    }

    // -------------------------------------------------------- UDS challenge 门控

    /// stdio 路径不受 challenge 影响：无 challenge 时 tools/list 无需 initialize
    ///（§3.6：stdio 无持久 token，replay 面 = 0，不加门控）。
    #[test]
    fn stdio_tools_without_challenge_works() {
        let server = McpServer::new(Box::new(TestSeedProvider));
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}
"#;
        let mut out: Vec<u8> = Vec::new();
        server
            .serve_with(std::io::Cursor::new(input.as_bytes()), &mut out)
            .expect("stdio serve must not error");
        let response = String::from_utf8(out).expect("response must be UTF-8");
        assert!(
            response.contains("\"tools\""),
            "stdio tools/list 须正常: {response}"
        );
    }

    /// UDS challenge（docs/20 §3.6 ③）：initialize 回显错误 → 拒绝本请求，
    /// 且工具面保持关闭（-32600「not verified」）。
    #[test]
    fn uds_challenge_wrong_echo_rejects_tools() {
        let server = McpServer::new(Box::new(TestSeedProvider))
            .with_uds_challenge(uds::Challenge::from_env_value("real-challenge"));
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"{}\":\"wrong\"}}}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n",
            uds::CHALLENGE_PARAM
        );
        let mut out: Vec<u8> = Vec::new();
        server
            .serve_with(std::io::Cursor::new(input.as_bytes()), &mut out)
            .expect("serve must not error");
        let response = String::from_utf8(out).expect("response must be UTF-8");
        assert!(
            response.contains("challenge verification failed"),
            "initialize 回显错误须被拒: {response}"
        );
        assert!(
            response.contains("challenge not verified"),
            "工具面须保持关闭: {response}"
        );
    }

    /// UDS challenge：initialize 正确回显 → initialize 与 tools/list 均成功。
    #[test]
    fn uds_challenge_correct_echo_opens_tools() {
        let server = McpServer::new(Box::new(TestSeedProvider))
            .with_uds_challenge(uds::Challenge::from_env_value("real-challenge"));
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"{}\":\"real-challenge\"}}}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n",
            uds::CHALLENGE_PARAM
        );
        let mut out: Vec<u8> = Vec::new();
        server
            .serve_with(std::io::Cursor::new(input.as_bytes()), &mut out)
            .expect("serve must not error");
        let response = String::from_utf8(out).expect("response must be UTF-8");
        assert!(
            !response.contains("challenge"),
            "正确回显不得出现 challenge 错误: {response}"
        );
        assert!(
            response.contains("\"tools\""),
            "tools/list 须成功: {response}"
        );
    }

    // -------------------------------------------------------- L-5 诊断订阅

    /// 建一个 `--log` 同型临时文件 sink（tag 唯一，防并行测试互踩）。
    fn temp_log_sink(tag: &str) -> (LogSink, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "cf-mcp-diag-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .expect("temp diag log must open");
        (LogSink::File(Arc::new(Mutex::new(file))), path)
    }

    /// 恒失败的审计实现（L-5：验证审计失败告警可达诊断通道，tools.rs:250）。
    #[derive(Debug)]
    struct FailingAudit;

    impl UsageAudit for FailingAudit {
        fn record(&self, _ev: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::Io("simulated disk full".into()))
        }
    }

    #[test]
    fn tracing_warn_is_routed_to_diagnostic_sink() {
        // 与 tools.rs:250 同型事件：warn!(error = ?e, secret = %secret, "audit record failed")。
        let (sink, path) = temp_log_sink("warn");
        let guard = tracing::subscriber::set_default(DiagnosticSubscriber::new(sink));
        tracing::warn!(
            error = ?AuditError::Io("disk full".into()),
            secret = %"API_KEY",
            "audit record failed"
        );
        drop(guard);
        let content = std::fs::read_to_string(&path).expect("diag log must be readable");
        assert!(content.contains("[WARN]"), "WARN 级须写入: {content}");
        assert!(
            content.contains("audit record failed"),
            "事件 message 须为行首文案: {content}"
        );
        assert!(
            content.contains("error=Io(\"disk full\")"),
            "error 字段须平铺（Debug 表示，`?e`）: {content}"
        );
        assert!(
            content.contains("secret=API_KEY"),
            "secret 引用须平铺（无值，§3.5-4）: {content}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tracing_error_is_routed_but_debug_is_filtered() {
        // 级别过滤：ERROR/WARN 放行，DEBUG 不写诊断通道。
        let (sink, path) = temp_log_sink("levels");
        let guard = tracing::subscriber::set_default(DiagnosticSubscriber::new(sink));
        tracing::debug!("noise that must be filtered");
        tracing::error!(secret = %"API_KEY", "audit record failed");
        drop(guard);
        let content = std::fs::read_to_string(&path).expect("diag log must be readable");
        assert!(content.contains("[ERROR]"), "ERROR 级须写入: {content}");
        assert!(content.contains("audit record failed"));
        assert!(
            !content.contains("noise that must be filtered"),
            "DEBUG 级须被过滤: {content}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn audit_failure_warn_observable_through_server() {
        // L-5 端到端：真实 McpServer（TestSeedProvider + FailingAudit）走
        // run_with_secret——审计 record 失败 → tools.rs:250 warn! → 诊断通道。
        let (sink, path) = temp_log_sink("server");
        let _guard = tracing::subscriber::set_default(DiagnosticSubscriber::new(sink));
        let server = McpServer::new(Box::new(TestSeedProvider)).with_audit(Box::new(FailingAudit));
        // 注意尾随 `\n`：`read_bounded_line` 对 EOF 前的最后一段**无换行**内容
        // 判为 Eof 丢弃（帧协议逐行换行分隔，生产客户端恒带 `\n`），测试须模拟。
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secret":"ANY_SECRET","env_name":"MCP_TEST","cmd":"/bin/sh","args":["-c","true"]}}}
"#;
        let mut out: Vec<u8> = Vec::new();
        server
            .serve_with(std::io::Cursor::new(input.as_bytes()), &mut out)
            .expect("serve must not error");
        let response = String::from_utf8(out).expect("response must be UTF-8");
        // 内部 text 是 JSON 转义后的字符串（`{\"exit_code\":0}`），须二次解析。
        let frame: serde_json::Value =
            serde_json::from_str(&response).expect("response must be JSON-RPC");
        assert_eq!(
            frame["result"]["isError"],
            json!(false),
            "response: {response}"
        );
        let inner_text = frame["result"]["content"][0]["text"]
            .as_str()
            .expect("text must be a string");
        let inner: serde_json::Value =
            serde_json::from_str(inner_text).expect("inner text must be JSON");
        assert_eq!(
            inner["exit_code"],
            json!(0),
            "审计失败不阻断工具调用（尽力而为，§4.6）: {response}"
        );
        let content = std::fs::read_to_string(&path).expect("diag log must be readable");
        assert!(
            content.contains("[WARN]"),
            "审计失败告警须写入诊断通道: {content}"
        );
        assert!(
            content.contains("audit record failed"),
            "告警 message 须写入: {content}"
        );
        assert!(
            content.contains("secret=ANY_SECRET"),
            "secret 引用须平铺: {content}"
        );
        let _ = std::fs::remove_file(&path);
    }

    // -------------------------------------------------------- escrow 取密（G3a）
    //
    // docs/30 §1.3 六条 + 孤儿边界（lead 裁定 2026-10-07）+ 读失败 fail-closed。
    // mock escrow 经 trait 注入 `build_coffer_provider`（in-process，不 spawn）；
    // 日志经临时 `--log` 文件捕获（断言托管/兜底线索，载荷纪律：不泄密钥）。

    /// 快速档测试库（8 MiB KDF，几十毫秒；tests/cli.rs 同款）。
    #[cfg(feature = "coffer-store")]
    fn escrow_fast_vault(tag: &str) -> (PathBuf, String) {
        use cf_crypto::kdf::KdfParams;
        use cf_session::create_vault_with_kdf;

        const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "cf-mcp-cli-escrow-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).expect("create temp base");
        let brief = create_vault_with_kdf(
            &base,
            "测试库",
            STRONG_PASSWORD,
            KdfParams::new(8 * 1024, 1, 1).expect("8 MiB fast KDF"),
        )
        .expect("create fast vault");
        (
            base.join(brief.uuid.to_string()),
            STRONG_PASSWORD.to_string(),
        )
    }

    /// 在测试库上启用 MCP 托管（解锁态 derive → enable），返回 mcp_key 字节
    /// 副本（供 mock escrow 注入）。session 在返回前 drop（库留在磁盘）。
    #[cfg(feature = "coffer-store")]
    fn escrow_enable(vault_dir: &std::path::Path, password: &str) -> [u8; 32] {
        let session = open_vault(vault_dir).expect("open vault");
        session.unlock(password).expect("unlock vault");
        let mcp_key = session.derive_mcp_key(password).expect("derive mcp_key");
        session
            .enable_mcp_escrow(password, mcp_key.as_bytes())
            .expect("enable escrow");
        *mcp_key.as_bytes()
    }

    /// mock escrow（trait 注入，docs/30 §1.3）：可编程三态结果 + 记录调用 uuid。
    #[cfg(feature = "coffer-store")]
    struct MockEscrow {
        result: std::sync::Mutex<Result<Option<[u8; 32]>, EscrowError>>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[cfg(feature = "coffer-store")]
    impl MockEscrow {
        fn new(result: Result<Option<[u8; 32]>, EscrowError>) -> Self {
            Self {
                result: std::sync::Mutex::new(result),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn called_with(&self) -> Vec<String> {
            self.calls.lock().expect("mock calls lock").clone()
        }
    }

    #[cfg(feature = "coffer-store")]
    impl VaultEscrowStore for MockEscrow {
        fn read_mcp_key(&self, vault_uuid: &str) -> Result<Option<[u8; 32]>, EscrowError> {
            self.calls
                .lock()
                .expect("mock calls lock")
                .push(vault_uuid.to_string());
            self.result.lock().expect("mock result lock").clone()
        }
    }

    /// 测试 logger：落临时 `--log` 文件，供断言托管/兜底线索。
    #[cfg(feature = "coffer-store")]
    fn escrow_test_logger(tag: &str) -> (Logger, PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cf-mcp-cli-escrow-log-{tag}-{}-{nanos}",
            std::process::id()
        ));
        let options = McpCliOptions {
            provider: "coffer".to_string(),
            provider_explicit: false,
            vault: None,
            log_path: Some(path.clone()),
            no_audit: false,
            uds: None,
        };
        (Logger::new(&options).expect("test logger"), path)
    }

    /// 读日志文件并清理（断言后统一走此路径，避免并行测试残留）。
    #[cfg(feature = "coffer-store")]
    fn escrow_read_log(log_path: &PathBuf) -> String {
        let content = std::fs::read_to_string(log_path).expect("read log file");
        let _ = std::fs::remove_file(log_path);
        content
    }

    /// **托管优先**（docs/30 §1.3 第 1 条）：托管条目存在且可用 → 走托管
    /// mcp_key 解锁成功；read 以 vault_uuid 定位；日志 source="keychain-escrow"，
    /// 不出现 env-fallback。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_uses_escrow_first() {
        let (vault_dir, password) = escrow_fast_vault("uses-escrow-first");
        let key = escrow_enable(&vault_dir, &password);
        let escrow = MockEscrow::new(Ok(Some(key)));
        let (mut logger, log_path) = escrow_test_logger("uses-escrow-first");
        let p = build_coffer_provider(&vault_dir, &escrow, None, &mut logger)
            .expect("托管优先：有可用 mcp_key 须解锁成功");
        assert_eq!(escrow.called_with().len(), 1, "须恰好读一次 Keychain");
        assert_eq!(
            escrow.called_with()[0],
            vault_dir
                .file_name()
                .expect("vault dir file name")
                .to_str()
                .expect("utf8 path"),
            "read_mcp_key 须以 vault_uuid 定位"
        );
        let content = escrow_read_log(&log_path);
        assert!(
            content.contains("keychain-escrow"),
            "须日志托管解锁线索: {content}"
        );
        assert!(
            !content.contains("env-fallback"),
            "托管优先不得走 env 兜底: {content}"
        );
        drop(p);
    }

    /// **env 兜底**（docs/30 §1.3 第 2 条）+ **read 门**（lead 裁定 2026-10-07）：
    /// 未启用托管（available=false）→ 直接 env 兜底成功，**不触 Keychain read**
    /// （mock 即便返回 Some 也不得被读），日志 warning source="env-fallback"。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_env_fallback_when_escrow_disabled() {
        let (vault_dir, password) = escrow_fast_vault("env-fallback");
        let escrow = MockEscrow::new(Ok(Some([0x42; 32])));
        let (mut logger, log_path) = escrow_test_logger("env-fallback");
        let p = build_coffer_provider(
            &vault_dir,
            &escrow,
            Some(SecretString::from_exposed(&password)),
            &mut logger,
        )
        .expect("env 兜底：无托管 + env 正确须解锁成功");
        assert!(
            escrow.called_with().is_empty(),
            "available=false 不得触 Keychain read（read 门）"
        );
        let content = escrow_read_log(&log_path);
        assert!(
            content.contains("env-fallback"),
            "须日志 env 兜底线索: {content}"
        );
        assert!(
            !content.contains("keychain-escrow"),
            "未启用托管不得走托管解锁: {content}"
        );
        drop(p);
    }

    /// **都无退出 1**（docs/30 §1.3 第 3 条）：托管缺失 + env 缺失 → 配置错误
    /// 退出 1（fail-closed，D-1 退出码契约不破坏），消息提示启用托管或提供 env。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_no_escrow_no_env_exits_1() {
        let (vault_dir, _password) = escrow_fast_vault("no-escrow-no-env");
        let escrow = MockEscrow::new(Ok(None));
        let (mut logger, log_path) = escrow_test_logger("no-escrow-no-env");
        let code = build_coffer_provider(&vault_dir, &escrow, None, &mut logger)
            .map(|_| ())
            .expect_err("托管缺失 + env 缺失 → 配置错误退出 1");
        assert_eq!(code, exit_code::CONFIG_ERROR);
        let content = escrow_read_log(&log_path);
        assert!(
            content.contains("COFFER_VAULT_PASSWORD"),
            "须提示启用托管或提供 env，content: {content}"
        );
    }

    /// **托管 + env 并存 → 托管优先（优先级锁定）**（docs/30 §1.3 第 4 条）：
    /// env 密码故意给错，若实现误回落 env → unlock 失败退出 3；正确实现走托管
    /// → 成功（env 不覆盖托管，D-4），日志无 env-fallback。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_escrow_takes_priority_when_both() {
        let (vault_dir, password) = escrow_fast_vault("escrow-priority");
        let key = escrow_enable(&vault_dir, &password);
        let escrow = MockEscrow::new(Ok(Some(key)));
        let (mut logger, log_path) = escrow_test_logger("escrow-priority");
        let p = build_coffer_provider(
            &vault_dir,
            &escrow,
            Some(SecretString::from_exposed("definitely-wrong-password-99!")),
            &mut logger,
        )
        .expect("托管 + env 并存 → 托管优先，须解锁成功（env 不覆盖托管）");
        let content = escrow_read_log(&log_path);
        assert!(content.contains("keychain-escrow"), "须走托管: {content}");
        assert!(
            !content.contains("env-fallback"),
            "并存时不得走 env 兜底: {content}"
        );
        drop(p);
    }

    /// **回落 env 仅限条目不存在**（docs/30 §1.3 第 5 条）：启用态但 Keychain
    /// 条目被外部删除（stale header）→ mock Ok(None) → 合法回落 env（条目不
    /// 存在 = 未启用托管语义，回落仅限此分支）。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_env_fallback_only_when_item_missing() {
        let (vault_dir, password) = escrow_fast_vault("env-fallback-only-missing");
        escrow_enable(&vault_dir, &password);
        let escrow = MockEscrow::new(Ok(None));
        let (mut logger, log_path) = escrow_test_logger("env-fallback-only-missing");
        let p = build_coffer_provider(
            &vault_dir,
            &escrow,
            Some(SecretString::from_exposed(&password)),
            &mut logger,
        )
        .expect("条目不存在（Ok(None)）→ env 兜底须成功");
        assert_eq!(escrow.called_with().len(), 1, "启用态须触 read");
        let content = escrow_read_log(&log_path);
        assert!(content.contains("env-fallback"), "须走 env 兜底: {content}");
        drop(p);
    }

    /// **托管条目存在但解锁失败 = fail-closed 报错退出 1**（docs/30 §1.3 第 6
    /// 条）：mock 返回形状合法但内容错的 32B 密钥（已吊销/损坏）+ env **正确**——
    /// 若实现静默回落 env 会解锁成功；正确实现须退出 1 + 错误含「从 App 重新
    /// 启用 MCP 以重建托管」指引 + 不出现 env 兜底信号。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_escrow_unlock_failure_exits_1_no_env_fallback() {
        let (vault_dir, password) = escrow_fast_vault("escrow-unlock-failure");
        escrow_enable(&vault_dir, &password);
        let escrow = MockEscrow::new(Ok(Some([0xAB; 32])));
        let (mut logger, log_path) = escrow_test_logger("escrow-unlock-failure");
        let code = build_coffer_provider(
            &vault_dir,
            &escrow,
            Some(SecretString::from_exposed(&password)),
            &mut logger,
        )
        .map(|_| ())
        .expect_err("托管条目存在但解锁失败 → fail-closed 退出 1，不回落 env");
        assert_eq!(code, exit_code::CONFIG_ERROR);
        let content = escrow_read_log(&log_path);
        assert!(
            content.contains("请从 App 重新启用 MCP 以重建托管"),
            "须含重建指引，content: {content}"
        );
        assert!(!content.contains("env-fallback"), "不得回落 env: {content}");
    }

    /// **孤儿条目边界**（lead 裁定 2026-10-07）：header 禁用 + keychain 残留
    /// → 仍走 env 兜底，**不触 read**（header = 意图源；unlock_with_mcp_key 对
    /// 该态本就 1002）。mock 返回能解锁的 key 也不得被读。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_orphan_item_ignored_when_header_disabled() {
        let (vault_dir, password) = escrow_fast_vault("orphan-item");
        let escrow = MockEscrow::new(Ok(Some([0x42; 32])));
        let (mut logger, log_path) = escrow_test_logger("orphan-item");
        let p = build_coffer_provider(
            &vault_dir,
            &escrow,
            Some(SecretString::from_exposed(&password)),
            &mut logger,
        )
        .expect("header 禁用 + keychain 残留 → env 兜底须成功");
        assert!(
            escrow.called_with().is_empty(),
            "available=false 必须跳过 read（孤儿条目不触发托管路径）"
        );
        let content = escrow_read_log(&log_path);
        assert!(content.contains("env-fallback"), "须走 env 兜底: {content}");
        drop(p);
    }

    /// **读失败 fail-closed**（D-4，docs/29 §6.2 step 3 Err）：读取失败（ACL /
    /// 签名 / 内容非法）→ 退出 1 + 可操作消息，**不回退 env**（防掩盖签名 / ACL
    /// 问题）；env 密码正确也不得兜底。
    #[cfg(feature = "coffer-store")]
    #[test]
    fn coffer_provider_escrow_read_error_exits_1_no_env_fallback() {
        let (vault_dir, password) = escrow_fast_vault("escrow-read-error");
        escrow_enable(&vault_dir, &password);
        let escrow = MockEscrow::new(Err(EscrowError::access_denied(
            "simulated missing entitlement (-34018)",
        )));
        let (mut logger, log_path) = escrow_test_logger("escrow-read-error");
        let code = build_coffer_provider(
            &vault_dir,
            &escrow,
            Some(SecretString::from_exposed(&password)),
            &mut logger,
        )
        .map(|_| ())
        .expect_err("读取失败 → fail-closed 退出 1，不回退 env");
        assert_eq!(code, exit_code::CONFIG_ERROR);
        let content = escrow_read_log(&log_path);
        assert!(
            content.contains("MCP 托管读取失败"),
            "须含可操作错误，content: {content}"
        );
        assert!(
            !content.contains("env-fallback"),
            "读失败不得回落 env: {content}"
        );
    }
}
