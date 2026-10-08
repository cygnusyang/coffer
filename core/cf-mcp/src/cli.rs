//! `coffer` CLI（docs/20 §5，G-D；browser 子命令 G-B）。
//!
//! 主职责：把 `mcp` 子命令参数（§5.2 **冻结签名**）解析成 provider 配置 + 启动
//! [`crate::McpServer::serve_stdio`]。stdout 永为协议帧（§3.1）；日志只走
//! stderr 或 `--log` 文件。退出码映射见 §5.3 与 [`exit_code`]。
//!
//! ## 子命令（docs/31 §2.1 D-2，G-B）
//!
//! - `mcp`：MCP 服务（本文主体）；
//! - `browser-agent` / `browser-broker`：浏览器扩展 native messaging host / 长驻
//!   daemon（`mod browser`，docs/31；经 `coffer-store` feature + macOS 双门控，
//!   docs/32 §8 #1 裁决——feature 关闭时两子命令不注册，落 unknown-subcommand
//!   fail-closed）。
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
#[derive(Debug)]
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
    // 浏览器扩展子命令（G-B，docs/31 §2.1 D-2）：经 `coffer-store` feature +
    // macOS 双门控（docs/32 §8 #1 裁决：复用既有 feature，不新增 browser feature）。
    // feature 关闭（slim build）或非 macOS 时两子命令不注册 → 落入下方
    // unknown-subcommand 分支 fail-closed（cli.rs:617，退出码契约不变）。
    #[cfg(all(feature = "coffer-store", target_os = "macos"))]
    match subcommand.as_str() {
        "browser-agent" => return browser::run_agent(&args[1..]),
        "browser-broker" => return browser::run_broker(&args[1..]),
        _ => {}
    }
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
// 浏览器扩展子命令（G-B，docs/31 §2.1 D-2 / §3.2 认证链 ②③）
// ===========================================================================
// `coffer browser-agent`（native messaging host，薄中继）+ `coffer browser-broker`
//（长驻 daemon，持解锁会话）——复用嵌套 bundle coffer 二进制（D-2），分发到
// cf-browser（HostRelay / BrokerEndpoint）。经 `coffer-store` feature 门控
//（docs/32 §8 #1 裁决）+ macOS 双门控（`os::macos` SecCode / `LOCAL_PEERPID`
// 平台惯例，同 cf-uds-sys）；两门控关闭时子命令不注册 → run() 落 unknown-
// subcommand fail-closed。
//
// 生命周期（docs/31 §3.1「三段通道第 3 段」）：v2.3.0 单会话范围；broker 由
// App（G-D）解锁时 spawn、锁定时 kill（锁态镜像）。本模块只做进程/通道层：
// host 验父进程（②，8001）、broker 验 peer（③，8002）、E2E 会话编排
//（BrokerEndpoint）、app 请求分发（锁定 → broker_locked 8003；Lock → 杀进程）。
//
// ## 解锁契约（HIGH2-3 §3 冻结：stdin 私有管道为主源；env 降级仅测试门控）
//
// 生产：App 解锁后 spawn `browser-broker --uds <well-known>`，经 **stdin 私有管道**
// 按行交付 `DEK_HEX/VAULT_UUID_HEX/PSK_HEX/UNLOCKED`（4 行 key=value LF，写完
// close stdin，broker 读至 EOF + 5s 硬超时，读满零化缓冲；H-3 核销——密钥不落
// env，`ps eww` 不可读）。`COFFER_BROKER_*` env 降级为**仅**
// `COFFER_BROKER_SKIP_PEER_VERIFY=1` 且 debug 构建时回退（自动化测试夹具路径，
// 生产绝不设置；release inert）。`DEK_HEX`/`VAULT_UUID_HEX` 使 broker 派生确定性
// 身份（`BrokerIdentity::derive`，docs/31 §4.2）并建立 E2E；`UNLOCKED=1` = 已解锁
//（可服务 app 请求），缺省/0 = 锁定态（E2E 可握手，但取密/列表 → broker_locked
// 8003）。解锁态另需 `$COFFER_VAULT_DIR`（App 注入）：broker 以 stdin 交付的 DEK
// 直开 vault（`unlock_with_dek`），开库失败 fail-closed exit 1 不留 socket；
// 分发语义 = 裁定书 §3.2（见 [`handle_request`] 文档）。PSK 持久化（配对时写入
// keychain）为 G-D/G-T merge-time 集成点。
//
// ## 退出码（复用 docs/20 §5.3，映射表见 run_agent / run_broker）
//
// 0 干净（连接 EOF / Lock / 拒连为已处理事件）/ 1 配置错（缺 --uds、缺 pairing
// env、父进程拒签 8001、bind 失败）/ 2 协议致命 / 3 身份缺失（身份派生失败）。
//
// ## 日志纪律
//
// host 的 stdout 是 native messaging 协议面、broker 的 stdout 未用——两子命令
// 一切诊断只走 `--log` 文件或 stderr（与 `coffer mcp` 同款 [`Logger`]），
// 且**不产生任何通道内容日志**（盲传/解密面零落盘，docs/31 §3.1）。
#[cfg(all(feature = "coffer-store", target_os = "macos"))]
mod browser {
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use cf_browser::broker::{BrokerEndpoint, BrokerIdentity};
    use cf_browser::e2e::Session;
    use cf_browser::gesture::GestureRegistry;
    use cf_browser::host::HostRelay;
    use cf_browser::origin::{self, Origin, OriginBinding as BrowserOriginBinding};
    use cf_browser::protocol::{
        AppMessage, AppRequest, AppResponse, EntryFieldRef, EntryInfo, HandshakeMessage,
    };
    use cf_browser::CfBrowserError;

    use cf_domain::category::ItemCategory;
    use cf_domain::field::Designation;
    use cf_domain::item::{FieldDraft, ItemDraft, SectionDraft, UrlDraft};
    use cf_domain::origin::{
        OriginBinding as DomainOriginBinding, OriginBindingKind as DomainOriginBindingKind,
    };
    use cf_session::open_vault;
    use cf_session::{ItemDetails, SessionResult, VaultSession};

    use super::exit_code;
    use super::{Logger, McpCliOptions};
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
    use zeroize::Zeroize;

    // ---------------- 环境变量契约（G-B 版 broker 解锁 / host 定位） ----------------

    /// broker UDS 显式覆盖（host 定位 / broker `--uds` 传参；**非密钥**，仅路径，
    /// HIGH2-3 §3.4 末——路径 env 不构成泄露面）。缺省 = well-known 公式
    ///（[`well_known_broker_uds`]）：G-D spawn `browser-broker --uds <well-known>`
    /// 与 host 同公式，两端共享同一 socket（无 env 发现，HIGH-2 ② 核销）。
    pub const ENV_BROKER_UDS: &str = "COFFER_BROKER_UDS";
    /// broker 身份 DEK（32 字节 hex）。G-B 版 = env 注入（生产 = G-D 在 App 解锁后
    /// spawn 注入；PSK 持久化/配对流 = G-D/G-T merge-time 集成点，见模块文档）。
    const ENV_BROKER_DEK: &str = "COFFER_BROKER_DEK_HEX";
    /// broker 身份派生用 vault uuid（16 字节 hex，`BrokerIdentity::derive`）。
    const ENV_BROKER_VAULT_UUID: &str = "COFFER_BROKER_VAULT_UUID_HEX";
    /// broker 配对 PSK（32 字节 hex；配对流注入，可轮换）。
    const ENV_BROKER_PSK: &str = "COFFER_BROKER_PSK_HEX";
    /// broker 解锁会话存在标记（**显式 `=1` 才解锁**，见 [`env_flag`]；
    /// 缺省 = 锁定态 8003）。
    const ENV_BROKER_UNLOCKED: &str = "COFFER_BROKER_UNLOCKED";
    /// broker 解锁态 vault 目录（App 注入，AppModel.swift:1115；解锁态必填，
    /// 缺失 → fail-closed exit 1 不留 socket。**非密钥**，仅路径）。
    const ENV_BROKER_VAULT_DIR: &str = "COFFER_VAULT_DIR";
    /// broker 跳过 ③ 层 peer 签名验证——**仅 debug 构建**且显式 `=1` 才生效
    ///（G-B 自动化测试设置；release 编译期剔除，生产不可达，③ 层恒开——测试
    /// 进程非签名二进制无法通过自身签名链）。
    const ENV_BROKER_SKIP_PEER_VERIFY: &str = "COFFER_BROKER_SKIP_PEER_VERIFY";
    /// broker 验 peer 的 SecRequirement 覆盖——**仅 debug 构建**读取（release
    /// 恒用 [`DEFAULT_BROKER_REQUIREMENT`]，防同用户 `launchctl setenv` 放宽
    /// ③ 层到任意 Apple 签名进程）；缺省 = 自有 coffer 二进制签名锚定。
    const ENV_BROKER_REQUIREMENT: &str = "COFFER_BROKER_REQUIREMENT";

    /// broker well-known UDS 落点常量（docs/31 §4.2 / HIGH2-3-INTEGRATION §4.1；
    /// G-D Swift 侧 `BrowserBroker.wellKnownUDS` 同串，**逐字节一致**）：
    /// `<real_home>/Library/Application Support/Coffer/browser/broker.sock`。
    /// 本机 68B ≪ AF_UNIX `sun_path` 104 上限（TC-PATH 预算守卫）。
    const BROKER_UDS_SUFFIX: &str = "Library/Application Support/Coffer/browser/broker.sock";

    /// stdin 私有管道帧缓冲上限（4 KiB；超即拒，防灌，HIGH2-3 §3.1）。
    const STDIN_FRAME_LIMIT: usize = 4 * 1024;
    /// stdin 读取硬超时（5s；App 未写 stdin 而保持打开 → 超时无有效行 →
    /// fail-closed 退出 1，不留 socket，HIGH2-3 §3.3）。
    const STDIN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// stdin 帧 key（**key 大小写敏感**，顺序无关，HIGH2-3 §3.1）。
    const KEY_DEK_HEX: &str = "DEK_HEX";
    const KEY_VAULT_UUID_HEX: &str = "VAULT_UUID_HEX";
    const KEY_PSK_HEX: &str = "PSK_HEX";
    const KEY_UNLOCKED: &str = "UNLOCKED";

    /// 单帧 payload 上限（内存安全守卫：E2E 帧 ~100 字节、握手 JSON ~300 字节，
    /// 64 MiB 远够且防恶意长度前缀的分配炸弹；native messaging 理论 4 GiB 不追求）。
    const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

    /// socket 文件权限 0600（对齐 uds.rs `SOCKET_FILE_MODE`，docs/20 §3.6）。
    const SOCKET_FILE_MODE: u32 = 0o600;
    /// socket 父目录权限 0700（对齐 uds.rs `SOCKET_DIR_MODE`）。
    const SOCKET_DIR_MODE: u32 = 0o700;

    /// ② 层浏览器白名单 `(identifier, TeamID)`——公开稳定常量。P-S spike 实证
    /// DR/TeamID 锚定跨浏览器原地自更新稳定（docs/31 §3.2 ②），TeamID 非密钥。
    const BROWSER_WHITELIST: &[(&str, &str)] = &[
        ("com.google.Chrome", "EQHXZ8M8AV"),
        ("com.microsoft.edgemac", "UBF8T346G9"),
        ("org.mozilla.firefox", "43AQ936H96"),
    ];

    /// 缺省 broker 验 peer 的 SecRequirement：自有 coffer 二进制（DR/TeamID 锚定）。
    /// TeamID/identifier 为公开签名常量（escrow keychain 组
    /// `A6DS985SJJ.app.coffer.Coffer` 见 docs/31 §7），非密钥。release 恒用此值
    ///（[`ENV_BROKER_REQUIREMENT`] 覆盖仅 debug 构建读取）。
    const DEFAULT_BROKER_REQUIREMENT: &str =
        "identifier \"app.coffer.Coffer\" and anchor apple generic \
                                              and certificate leaf[subject.OU] = \"A6DS985SJJ\"";

    // ---------------- 8xxx 错误码（docs/03 §12 冻结；本模块产生 8001/8002/8003，
    // 认证链 8001/8002/8004、不可用 8003、交互/授权面 8005-8008） ----------------

    /// host 拒签：父进程非签名浏览器（docs/31 §3.2 ②，fail-closed；认证链）。
    pub const ERR_HOST_PARENT_UNVERIFIED: u16 = 8001;
    /// broker 拒连：peer host 非自有 coffer 二进制（docs/31 §3.2 ③；认证链）。
    pub const ERR_BROKER_PEER_UNVERIFIED: u16 = 8002;
    /// broker 锁定：无解锁会话（docs/31 §4.1，popup 引导打开 App 解锁）。
    ///
    /// 与 [`ERR_BROKER_UNAVAILABLE`] 同属 docs/03 §12 `BrokerUnavailable`（8003）
    /// ——「Coffer 未运行或未解锁」即本码；此常量仅用于 BrokerLocked 响应日志
    /// （响应本体是 `AppResponse::BrokerLocked` 变体，不携带码值）。
    pub const ERR_BROKER_LOCKED: u16 = 8003;
    /// broker 不可用（docs/03 §12 `BrokerUnavailable` = 8003）：该操作当前不可用。
    ///
    /// G-B 版 app 请求未接线 vault 取密/写入（vault 集成 = G-D/G-T merge-time
    /// 点）与 broker 进程不可达，均属「当前不可用」→ 本码；G-B 不产生 8006
    /// `UserDenied`（用户拒绝流程未实现，docs/03 §12 冻结语义）。
    pub const ERR_BROKER_UNAVAILABLE: u16 = 8003;
    /// 协议/服务面错误（8004，docs/03 §12 认证链「握手解密失败」同组语义扩至
    /// 请求服务失败：条目不存在 / 读取错误 / 非法 origin 无法写库等）。UI 一律
    /// 按「通道不可用，重试或重连」处理（cf-browser error.rs L92-94）。
    pub const ERR_BROKER_PROTOCOL: u16 = 8004;
    /// origin 未绑定（8005，docs/31 §5.3 / 31a §附）：`get_secret` 目标条目对
    /// 当前页 origin 无匹配绑定 → 不填充，popup 提示用户确认绑定。
    pub const ERR_BROKER_ORIGIN_NOT_BOUND: u16 = 8005;
    /// 手势令牌无效/过期/重放（8007，docs/31 §5.2 / D-7）：经
    /// [`GestureRegistry::validate_and_consume`] 单次消费校验失败。
    pub const ERR_BROKER_GESTURE_INVALID: u16 = 8007;

    /// ② 层：验父进程是否为白名单签名浏览器（docs/31 §3.2 ②，P-S spike 实证）。
    ///
    /// 经 `SecCodeCopyGuestWithAttributes(PID)` + `SecCodeCheckValidity`
    /// （security-framework 安全封装，免 entitlement / 免 TCC，P-S 实证）。
    /// fail-closed：PID 不存在 / 无签名信息 / 非白名单 → `false`。
    ///
    /// **runtime CDHash 次校验**（`kSecCodeInfoUnique` 现取，docs/31 §3.2 ②）：
    /// security-framework 不暴露该 info 字典 API（G-B 实测），本版仅实现
    /// **主锚定 = DR/TeamID 签名验证**；CDHash 次校验列为 G-R/G-E 后续（需独立
    /// sys crate 封装 `SecCodeCopySigningInformation`，report 已声明）。
    fn parent_is_trusted_browser() -> bool {
        let ppid = std::os::unix::process::parent_id();
        BROWSER_WHITELIST.iter().any(|(identifier, team_id)| {
            let requirement = format!(
                "identifier \"{identifier}\" and anchor apple generic \
                 and certificate leaf[subject.OU] = \"{team_id}\""
            );
            // `parent_id()` 返回 u32；PID 恒 < 2^31（macOS 默认上限远低于此），
            // `as i32` 无损。peer_pid（`cf-uds-sys`）为 `libc::pid_t` = i32，故
            // 验证函数统一以 i32 承载。
            verify_code_signature(ppid as i32, &requirement)
        })
    }

    /// SecCode by PID 代码签名验证（docs/31 §3.2 ②③，P-S spike 实证机制）。
    ///
    /// 任何失败（PID 不存在 / 无签名 / 签名不符 / requirement 非法）→ `false`，
    /// 绝不降级（fail-closed）。
    fn verify_code_signature(pid: i32, requirement: &str) -> bool {
        use security_framework::os::macos::code_signing::{
            Flags, GuestAttributes, SecCode, SecRequirement,
        };
        let mut attrs = GuestAttributes::new();
        attrs.set_pid(pid);
        let code = match SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE) {
            Ok(code) => code,
            Err(_) => return false,
        };
        let req: SecRequirement = match requirement.parse() {
            Ok(req) => req,
            Err(_) => return false,
        };
        code.check_validity(Flags::NONE, &req).is_ok()
    }

    /// ③ 层：验 peer host（docs/31 §3.2 ③）。
    ///
    /// `getpeereid` 同用户 + SecCode 签名（自有 coffer 二进制锚定，DR/TeamID）。
    /// [`ENV_BROKER_SKIP_PEER_VERIFY`] 在 **debug 构建**且显式 `=1` 时跳过签名校验
    ///（**仅自动化测试**；release 编译期剔除（`cfg!(debug_assertions)`），生产不可达——
    /// 同用户 `launchctl setenv` 无法影响 release broker，③ 层恒开）。
    fn peer_is_verified(stream: &UnixStream) -> bool {
        if cfg!(debug_assertions) && env_flag(ENV_BROKER_SKIP_PEER_VERIFY) {
            return true;
        }
        let peer_euid = match cf_uds_sys::peer_euid(stream) {
            Ok(u) => u,
            Err(_) => return false,
        };
        if peer_euid != cf_uds_sys::self_euid() {
            return false;
        }
        let pid = match cf_uds_sys::peer_pid(stream) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // release 编译期剔除覆盖旋钮：生产 SecRequirement 恒为默认锚定
        //（HIGH-1 修复，M-3 release-inert 原则）。
        let requirement = if cfg!(debug_assertions) {
            std::env::var(ENV_BROKER_REQUIREMENT)
                .unwrap_or_else(|_| DEFAULT_BROKER_REQUIREMENT.to_string())
        } else {
            DEFAULT_BROKER_REQUIREMENT.to_string()
        };
        verify_code_signature(pid, &requirement)
    }

    /// 读环境布尔标记（**显式 `"1"` 才为 `true`**；`"0"`/空/缺省均 `false`，
    /// 防 `=0` 误开启——HIGH-1 修复，含 [`ENV_BROKER_UNLOCKED`] 语义）。
    fn env_flag(name: &str) -> bool {
        std::env::var(name)
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
    }

    // ---------------- browser-agent：native messaging host（薄中继） ----------------

    /// `coffer browser-agent` 入口（docs/31 §3.1 第 2 段，薄中继）。
    ///
    /// 流程：② 层验父进程（8001 fail-closed）→ 定位 broker UDS → 连 broker →
    /// 中继循环（stdin 帧 → broker → stdout 帧，**零逻辑盲传**，仅经 [`HostRelay`]
    /// 做帧长校验与重组，不解密/不解析/不落盘）。
    ///
    /// 退出码（复用 docs/20 §5.3）：
    /// - `0` 干净（stdin EOF，扩展关闭端口）；
    /// - `1` 配置错：父进程非签名浏览器（8001）/ broker 不可达（8003）/
    ///   无法确定 broker socket 路径（`$COFFER_BROKER_UDS` 未设且 `$HOME` 缺失）；
    /// - `2` 协议致命：中继 IO / 帧长异常。
    ///
    /// 日志纪律：stdout 是 native messaging 协议面，一切诊断只走 `--log` / stderr。
    pub fn run_agent(args: &[String]) -> i32 {
        let log_path = match parse_agent_args(args) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: browser agent: {e}");
                return exit_code::CONFIG_ERROR;
            }
        };
        let mut logger = match build_logger(log_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: browser agent: {e}");
                return exit_code::CONFIG_ERROR;
            }
        };

        if !parent_is_trusted_browser() {
            logger.error(&format!(
                "error: browser host: parent process is not a trusted browser ({ERR_HOST_PARENT_UNVERIFIED}); refusing to relay"
            ));
            return exit_code::CONFIG_ERROR;
        }

        let Some(uds) = broker_uds_path() else {
            logger.error(
                "error: browser host: 无法确定 broker socket 路径（$COFFER_BROKER_UDS \
                 未设且 $HOME 缺失），fail-closed 退出",
            );
            return exit_code::CONFIG_ERROR;
        };

        logger.info(&format!(
            "browser host: relaying via uds {} (parent verified)",
            uds.display()
        ));
        match relay_loop(&uds) {
            Ok(()) => {
                logger.info("browser host: channel closed, exiting");
                exit_code::CLEAN
            }
            Err(e) => {
                logger.error(&format!("error: browser host: {e}"));
                exit_code::PROTOCOL_FATAL
            }
        }
    }

    /// 解析 `browser-agent` 参数：仅 `--log PATH`（可选）。未知 flag / 缺值 → Err。
    fn parse_agent_args(args: &[String]) -> Result<Option<PathBuf>, String> {
        let mut log_path = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--log" => {
                    let next = i + 1;
                    if next >= args.len() {
                        return Err("flag `--log` requires a value".into());
                    }
                    log_path = Some(PathBuf::from(&args[next]));
                    i += 2;
                }
                other => return Err(format!("unknown flag: {other}")),
            }
        }
        Ok(log_path)
    }

    /// 按 `--log` 构造 [`Logger`]（缺省 stderr；复用 `coffer mcp` 的日志纪律）。
    fn build_logger(log_path: Option<PathBuf>) -> Result<Logger, String> {
        let options = McpCliOptions {
            provider: "browser".to_string(),
            provider_explicit: false,
            vault: None,
            log_path,
            no_audit: true,
            uds: None,
        };
        Logger::new(&options).map_err(|e| e.to_string())
    }

    /// 中继主循环：stdin（native messaging）→ broker UDS → stdout（native messaging）。
    ///
    /// 盲传纪律（docs/31 §3.1）：不解密、不解析、不落盘、不缓存内容；仅经
    /// [`HostRelay::wrap`] 做帧长校验与重组。每帧 lockstep 一进一出（单会话 E2E
    /// 的请求-响应一一对应，握手三消息同样流经此中继）。
    fn relay_loop(uds: &Path) -> Result<(), String> {
        let mut broker = UnixStream::connect(uds).map_err(|e| {
            format!(
                "broker unreachable ({ERR_BROKER_UNAVAILABLE}): connect {}: {e}",
                uds.display()
            )
        })?;
        let relay = HostRelay;
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut stdin = stdin.lock();
        let mut stdout = stdout.lock();
        // while-let：stdin EOF（扩展关闭 native port）→ 干净退出。每帧 lockstep
        // 一进一出。
        while let Some(payload) =
            read_frame(&mut stdin).map_err(|e| format!("stdin read failed: {e}"))?
        {
            // 扩展 → broker：读一帧（4B LE + payload），校验重组，转发 broker。
            let framed = relay
                .wrap(&payload)
                .map_err(|e| format!("frame invalid: {e}"))?;
            broker
                .write_all(&framed)
                .map_err(|e| format!("broker write failed: {e}"))?;
            // broker → 扩展：读响应帧，原样写回 stdout（native messaging 帧）。
            let Some(resp) =
                read_frame(&mut broker).map_err(|e| format!("broker read failed: {e}"))?
            else {
                return Err("broker closed connection (channel lost)".into());
            };
            stdout
                .write_all(&resp)
                .map_err(|e| format!("stdout write failed: {e}"))?;
            stdout
                .flush()
                .map_err(|e| format!("stdout flush failed: {e}"))?;
        }
        Ok(())
    }

    // ---------------- browser-broker：长驻 daemon（持解锁会话） ----------------

    /// `coffer browser-broker` 入口（docs/31 §2.1 D-2，长驻 daemon）。
    ///
    /// 流程：解析 `--uds`（必填）/ `--log`（可选）→ **解锁契约（stdin 私有管道
    /// 必填，缺/非法 → 配置错 1，fail-closed；env 降级仅测试门控）** → 派生身份
    ///（失败 → 身份缺失 3）→ bind UDS（socket 0600 / 父目录 0700）→ accept 循环：
    /// 每连接 ③ 层验 peer（8002 拒连）→ E2E 握手（失败拒绝）→ app 请求分发
    ///（锁定 → broker_locked 8003；Lock → 响应后退出 0）。
    ///
    /// 退出码（复用 docs/20 §5.3）：
    /// - `0` 干净（连接 EOF / 收到 Lock；peer 拒连为已处理事件，daemon 继续）；
    /// - `1` 配置错：缺 `--uds` / 缺 pairing 材料（stdin 或测试降级 env）/ bind 失败；
    /// - `2` 协议致命：accept 循环致命错误；
    /// - `3` 身份缺失：broker 身份密钥派生失败。
    pub fn run_broker(args: &[String]) -> i32 {
        let (uds, log_path) = match parse_broker_args(args) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("error: browser broker: {e}");
                return exit_code::CONFIG_ERROR;
            }
        };
        let mut logger = match build_logger(log_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: browser broker: {e}");
                return exit_code::CONFIG_ERROR;
            }
        };

        // 解锁契约：pairing 材料必填（缺 → 配置错 1，fail-closed；测试断言此路径）。
        // 主源 = stdin 私有管道（HIGH2-3 §3.3）；env 降级仅 SKIP_PEER_VERIFY+debug。
        let Some(mut secrets) = resolve_broker_secrets() else {
            logger.error(
                "error: browser broker: 缺 pairing 材料（stdin 私有管道 4 行；测试降级 \
                 $COFFER_BROKER_* 仅 SKIP_PEER_VERIFY+debug 门控），fail-closed 退出",
            );
            return exit_code::CONFIG_ERROR;
        };

        let identity = match BrokerIdentity::derive(&secrets.dek, &secrets.vault_uuid) {
            Ok(id) => id,
            Err(e) => {
                logger.error(&format!(
                    "error: browser broker: 身份派生失败 ({}): {e}",
                    e.code()
                ));
                return exit_code::IDENTITY_MISSING;
            }
        };
        let endpoint = BrokerEndpoint::new(identity, secrets.psk);

        // 解锁态 → 用 stdin 交付的 DEK 开库（裁定书 §3.1：stdin → 身份 → **开库** →
        // bind）。开库失败 fail-closed exit 1（bind 尚未发生，**不留 socket**）；
        // 锁定态 → 不开库，恒 8003。开库成功后 `secrets.dek` 覆零（vault 密钥不再
        // 需要，`BrokerSecrets` 无 Debug）；`psk` 已移入 [`BrokerEndpoint`]（E2E 配对
        // 全连接期需要，非 vault 密钥，不在此零化）。
        let vault = if secrets.unlocked {
            let Some(dir) = vault_dir_from_env() else {
                logger.error(
                    "error: browser broker: 解锁态缺 $COFFER_VAULT_DIR（App 注入），\
                     fail-closed 退出",
                );
                return exit_code::CONFIG_ERROR;
            };
            let session = match open_vault(&dir) {
                Ok(s) => s,
                Err(e) => {
                    logger.error(&format!(
                        "error: browser broker: 打开 vault 失败 ({}): {e}",
                        e.code()
                    ));
                    return exit_code::CONFIG_ERROR;
                }
            };
            if let Err(e) = session.unlock_with_dek(&secrets.dek) {
                logger.error(&format!(
                    "error: browser broker: DEK 开库失败 ({}): {e}",
                    e.code()
                ));
                return exit_code::CONFIG_ERROR;
            }
            secrets.dek.zeroize();
            Some(session)
        } else {
            None
        };

        let listener = match bind_broker_socket(&uds) {
            Ok(l) => l,
            Err(e) => {
                logger.error(&format!(
                    "error: browser broker: bind `{}` failed: {e}",
                    uds.display()
                ));
                return exit_code::CONFIG_ERROR;
            }
        };
        let _guard = SocketGuard { path: uds.clone() };

        let locked = vault.as_ref().is_none_or(|v| !v.is_unlocked());
        logger.info(&format!(
            "browser broker: serving on uds {} (locked={locked})",
            uds.display()
        ));

        // 手势单次消费登记（TTL 淘汰有界，docs/31 §5.2 / D-7）：broker 级持用，
        // 跨连接共享（同一 nonce 全局只放行一次，replay 防重）。
        let mut gestures = GestureRegistry::new();
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => match serve_connection(
                    stream,
                    &endpoint,
                    vault.as_ref(),
                    &mut gestures,
                    &mut logger,
                ) {
                    // 单连接处理完毕（EOF / 拒连 / 握手失败）→ daemon 继续 accept；
                    // 仅 Lock / 致命错误返回退出码。
                    ServerResult::Continue => {}
                    ServerResult::Exit(code) => return code,
                },
                Err(e) => {
                    logger.error(&format!("error: browser broker: accept failed: {e}"));
                    return exit_code::PROTOCOL_FATAL;
                }
            }
        }
    }

    /// 解析 `browser-broker` 参数：`--uds PATH`（必填）+ `--log PATH`（可选）。
    fn parse_broker_args(args: &[String]) -> Result<(PathBuf, Option<PathBuf>), String> {
        let mut uds = None;
        let mut log_path = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--uds" => {
                    let next = i + 1;
                    if next >= args.len() {
                        return Err("flag `--uds` requires a value".into());
                    }
                    uds = Some(PathBuf::from(&args[next]));
                    i += 2;
                }
                "--log" => {
                    let next = i + 1;
                    if next >= args.len() {
                        return Err("flag `--log` requires a value".into());
                    }
                    log_path = Some(PathBuf::from(&args[next]));
                    i += 2;
                }
                other => return Err(format!("unknown flag: {other}")),
            }
        }
        let Some(uds) = uds else {
            return Err("missing `--uds PATH`（broker socket 路径必填）".into());
        };
        Ok((uds, log_path))
    }

    /// 单连接服务结果：daemon 继续 or 退出。
    enum ServerResult {
        /// 连接处理完毕（EOF / 拒连 / 握手失败），daemon 继续 accept。
        Continue,
        /// 退出 daemon（Lock 请求 → 0；内部致命 → 相应码）。
        Exit(i32),
    }

    /// 服务一个连接：③ 层验 peer → E2E 握手 → app 请求循环（docs/31 §4/§5）。
    ///
    /// `vault` = broker 持有的开库会话（锁定态 / 未解锁 = `None`，请求分发
    /// 每请求判定 8003，裁定书 §3.1）；`gestures` = broker 级手势消费登记表
    ///（跨连接共享，单次消费防重）。
    fn serve_connection(
        mut stream: UnixStream,
        endpoint: &BrokerEndpoint,
        vault: Option<&VaultSession>,
        gestures: &mut GestureRegistry,
        logger: &mut Logger,
    ) -> ServerResult {
        if !peer_is_verified(&stream) {
            logger.error(&format!(
                "error: browser broker: peer host not verified ({ERR_BROKER_PEER_UNVERIFIED}); rejecting connection"
            ));
            return ServerResult::Continue;
        }
        let mut session = match broker_handshake(&mut stream, endpoint) {
            Ok(s) => s,
            Err(e) => {
                logger.error(&format!(
                    "error: browser broker: E2E handshake failed ({}): {e}",
                    e.code()
                ));
                return ServerResult::Continue;
            }
        };
        loop {
            // read_frame 返回 Result<Option<Frame>, …>：`Ok(None)` = 连接 EOF →
            // 干净关闭。用单 match 而非 let-else（scrutinee 为 match 表达式触发
            // 解析限制「}` before `else`」）。
            let frame = match read_frame(&mut stream) {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    logger.error(&format!("error: browser broker: read failed: {e}"));
                    return ServerResult::Continue;
                }
            };
            let msg = match session.decrypt(&frame) {
                Ok(m) => m,
                Err(e) => {
                    // 认证/解密失败统一 8004（info-leak 纪律，cf-browser error.rs）；
                    // daemon 继续（单会话断开）。
                    logger.error(&format!(
                        "error: browser broker: decrypt failed ({}): {e}",
                        e.code()
                    ));
                    return ServerResult::Continue;
                }
            };

            // Lock 请求：响应后杀进程（docs/31 §4.1「lock 命令 → 杀进程」）。
            if matches!(msg, AppMessage::Request(AppRequest::Lock)) {
                let out = match session.encrypt(&AppMessage::Response(AppResponse::Locked)) {
                    Ok(o) => o,
                    Err(e) => {
                        logger.error(&format!("error: browser broker: encrypt failed: {e}"));
                        return ServerResult::Exit(exit_code::PROTOCOL_FATAL);
                    }
                };
                if let Err(e) = write_frame(&mut stream, &out) {
                    logger.error(&format!("error: browser broker: write failed: {e}"));
                }
                logger.info("browser broker: lock requested, exiting");
                return ServerResult::Exit(exit_code::CLEAN);
            }

            let response = handle_request(msg, vault, gestures);
            // BrokerLocked（8003）记 stderr（对齐 8001/8002/8003 的可观测性模式）。
            if matches!(response, AppResponse::BrokerLocked) {
                logger.error(&format!(
                    "error: browser broker: vault locked ({ERR_BROKER_LOCKED}); refusing request"
                ));
            }
            let out = match session.encrypt(&AppMessage::Response(response)) {
                Ok(o) => o,
                Err(e) => {
                    logger.error(&format!("error: browser broker: encrypt failed: {e}"));
                    return ServerResult::Exit(exit_code::PROTOCOL_FATAL);
                }
            };
            if let Err(e) = write_frame(&mut stream, &out) {
                logger.error(&format!("error: browser broker: write failed: {e}"));
                return ServerResult::Continue;
            }
        }
        ServerResult::Continue
    }

    /// app 请求分发（docs/31 §5；最小实现语义 = 裁定书 §3.2）。
    ///
    /// 锁定判定为**每请求**（`vault` 缺失或已锁 → 8003，裁定书 §3.1）：
    /// - `get_secret`：锁定→8003；手势校验失败→8007；目标条目对当前页 origin 无
    ///   绑定匹配→8005；逐 fields 取字段值 → `GetSecretResult`；
    /// - `get_entries`：锁定→8003；vault 查询按 origin 绑定过滤（无手势，lead
    ///   裁定 2026-10-08）；
    /// - `capture_save`：锁定→8003；手势→8007；按 (origin 绑定 + username) 建/改
    ///   条目并写 `origin_bindings=[绑定(origin)]` → `CaptureSaved{item_id}`；
    /// - `confirm_unbound_origin`：锁定→8003；手势→8007；**写绑定需目标条目引用
    ///   而协议未携带 entry 字段（L-4 缺口，lead 已定后续加字段）** → 本轮最小
    ///   语义 = 手势校验 + 直接确认，不写绑定。
    fn handle_request(
        msg: AppMessage,
        vault: Option<&VaultSession>,
        gestures: &mut GestureRegistry,
    ) -> AppResponse {
        let AppMessage::Request(req) = msg else {
            // 请求方向收到响应消息 = 扩展行为异常 → 协议错误（8004 语义）。
            return broker_error(
                ERR_BROKER_PROTOCOL,
                "unexpected response message from extension",
            );
        };
        match req {
            AppRequest::GetSecret {
                request_id,
                entry,
                fields,
                origin,
                gesture,
            } => {
                let Some(vault) = vault else {
                    return AppResponse::BrokerLocked;
                };
                if !vault.is_unlocked() {
                    return AppResponse::BrokerLocked;
                }
                if gestures.validate_and_consume(&gesture, now_ms()).is_err() {
                    return broker_error(ERR_BROKER_GESTURE_INVALID, "手势令牌无效或过期");
                }
                // origin 非法 → 视为无绑定可命中（fail-closed，不静默放行）。
                let Ok(o) = Origin::parse(&origin) else {
                    return broker_error(ERR_BROKER_ORIGIN_NOT_BOUND, "当前站点未绑定该条目");
                };
                let item = match vault.get_item(&entry) {
                    Ok(Some(i)) => i,
                    Ok(None) => {
                        return broker_error(ERR_BROKER_PROTOCOL, "目标条目不存在");
                    }
                    Err(e) => {
                        return broker_error(
                            ERR_BROKER_PROTOCOL,
                            format!("读取条目失败 ({}): {e}", e.code()),
                        )
                    }
                };
                let bindings: Vec<BrowserOriginBinding> =
                    item.origin_bindings.iter().map(browser_binding).collect();
                if origin::best_match(&bindings, &o).is_none() {
                    return broker_error(ERR_BROKER_ORIGIN_NOT_BOUND, "当前站点未绑定该条目");
                }
                // 逐 fields：字段名 → uuid 解析自条目详情（get_item 本就为 origin
                // 绑定取出）；权威明文值走会话按需访问器（随取随走，drop 清零）。
                let mut values = BTreeMap::new();
                for name in fields {
                    let Some(field_uuid) = item
                        .fields
                        .iter()
                        .find(|f| f.name.expose() == name.as_str())
                        .map(|f| f.uuid.clone())
                    else {
                        continue; // 字段不存在 → 不返回该键（扩展自行判断缺项）
                    };
                    match vault.get_field_value(&entry, &field_uuid) {
                        Ok(Some(v)) => {
                            values.insert(name, v);
                        }
                        Ok(None) => {} // 字段存在但无值 → 不返回该键
                        Err(e) => {
                            return broker_error(
                                ERR_BROKER_PROTOCOL,
                                format!("读取字段失败 ({}): {e}", e.code()),
                            )
                        }
                    }
                }
                AppResponse::GetSecretResult { request_id, values }
            }
            // GetEntries 不带 gesture（lead 裁定 2026-10-08，docs/31 L261 仅点名
            // 三消息带手势；get_entries 只读元数据列举不在其列）→ 无需手势校验。
            AppRequest::GetEntries { origin } => {
                let Some(vault) = vault else {
                    return AppResponse::BrokerLocked;
                };
                if !vault.is_unlocked() {
                    return AppResponse::BrokerLocked;
                }
                match vault_entries(vault, &origin) {
                    Ok(entries) => AppResponse::EntriesResult { entries },
                    Err(e) => broker_error(
                        ERR_BROKER_PROTOCOL,
                        format!("列举条目失败 ({}): {e}", e.code()),
                    ),
                }
            }
            AppRequest::CaptureSave {
                origin,
                username,
                password,
                title,
                category,
                gesture,
            } => {
                let Some(vault) = vault else {
                    return AppResponse::BrokerLocked;
                };
                if !vault.is_unlocked() {
                    return AppResponse::BrokerLocked;
                }
                if gestures.validate_and_consume(&gesture, now_ms()).is_err() {
                    return broker_error(ERR_BROKER_GESTURE_INVALID, "手势令牌无效或过期");
                }
                // 绑定 = 提交 origin 的 Exact 绑定；解析失败（非法 origin）→ 写库
                // 无意义，协议错（8004）。
                let Some(binding) = binding_for_origin(&origin) else {
                    return broker_error(ERR_BROKER_PROTOCOL, "非法 origin，无法建立绑定");
                };
                let Ok(o) = Origin::parse(&origin) else {
                    return broker_error(ERR_BROKER_PROTOCOL, "非法 origin");
                };
                // 按 (origin 绑定匹配 + username 字段值相同) 找既有条目：有 → 改，
                // 无 → 建。`origin_bindings` 恒替换为 `[绑定(origin)]`（裁定书 §3.2）。
                match find_item_by_origin_and_username(vault, &o, &username) {
                    Ok(Some(item_id)) => {
                        let item = match vault.get_item(&item_id) {
                            Ok(Some(i)) => i,
                            Ok(None) => {
                                return broker_error(ERR_BROKER_PROTOCOL, "目标条目不存在");
                            }
                            Err(e) => {
                                return broker_error(
                                    ERR_BROKER_PROTOCOL,
                                    format!("读取条目失败 ({}): {e}", e.code()),
                                )
                            }
                        };
                        // 改：合并既有字段（仅替换 username/password 值，保留其余
                        // 字段/分区/URL/标签；TOTP 由 update_item Keep 语义保留）。
                        let draft =
                            capture_merge_draft(&item, &username, &password, &title, category);
                        if let Err(e) = vault.update_item(&item_id, &draft) {
                            return broker_error(
                                ERR_BROKER_PROTOCOL,
                                format!("更新条目失败 ({}): {e}", e.code()),
                            );
                        }
                        if let Err(e) = vault.set_item_origin_bindings(&item_id, vec![binding]) {
                            return broker_error(
                                ERR_BROKER_PROTOCOL,
                                format!("写入绑定失败 ({}): {e}", e.code()),
                            );
                        }
                        AppResponse::CaptureSaved { item_id }
                    }
                    Ok(None) => {
                        let draft = capture_create_draft(&username, &password, &title, category);
                        match vault.create_item_with_origin_bindings(&draft, vec![binding]) {
                            Ok(item_id) => AppResponse::CaptureSaved { item_id },
                            Err(e) => broker_error(
                                ERR_BROKER_PROTOCOL,
                                format!("创建条目失败 ({}): {e}", e.code()),
                            ),
                        }
                    }
                    Err(e) => broker_error(
                        ERR_BROKER_PROTOCOL,
                        format!("检索既有条目失败 ({}): {e}", e.code()),
                    ),
                }
            }
            AppRequest::ConfirmUnboundOrigin { origin: _, gesture } => {
                let Some(vault) = vault else {
                    return AppResponse::BrokerLocked;
                };
                if !vault.is_unlocked() {
                    return AppResponse::BrokerLocked;
                }
                // L-4 缺口：写绑定需目标条目引用而协议未携带 entry 字段（lead 已定
                // 后续加字段）。本轮最小语义 = 手势校验 + 直接确认，不写绑定。
                if gestures.validate_and_consume(&gesture, now_ms()).is_err() {
                    return broker_error(ERR_BROKER_GESTURE_INVALID, "手势令牌无效或过期");
                }
                AppResponse::OriginConfirmed
            }
            AppRequest::Lock => {
                // Lock 在 serve_connection 单独处理（需退出信号）；此处兜底（不可达）。
                AppResponse::Locked
            }
        }
    }

    /// 统一的 8xxx 错误响应。
    fn broker_error(code: u16, message: impl Into<String>) -> AppResponse {
        AppResponse::Error {
            code,
            message: message.into(),
        }
    }

    /// 当前 Unix 毫秒（手势 TTL 校验的时钟源，docs/31 §5.2；与扩展 `Date.now()`
    /// 同向）。`SystemTime` 错误（理论不可达）→ `0`（fail-closed：任何正时间戳
    /// 手势均判过期/未来拒，不静默放行）。
    fn now_ms() -> u64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_millis() as u64,
            Err(_) => 0,
        }
    }

    /// 解锁态 vault 目录来源：`$COFFER_VAULT_DIR`（App 注入，AppModel.swift:1115）。
    /// 缺失/空 → `None`（fail-closed，调用方 exit 1 不留 socket）。
    fn vault_dir_from_env() -> Option<PathBuf> {
        std::env::var_os(ENV_BROKER_VAULT_DIR)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
    }

    /// 绑定 = 提交 origin 的 Exact 绑定（`https://host:port` 规范化后存值，
    /// [`BrowserOriginBinding::parse`] 权威解析）。返回 cf-domain 存储形态。
    fn binding_for_origin(origin: &str) -> Option<DomainOriginBinding> {
        let b = BrowserOriginBinding::parse(origin).ok()?;
        Some(domain_binding(&b))
    }

    /// cf-domain 存储绑定 → cf-browser 匹配绑定（结构同构，仅类型转换；匹配
    /// 语义以 `cf-browser::origin` 权威为准，裁定书 §3.2「勿改」）。
    fn browser_binding(b: &DomainOriginBinding) -> BrowserOriginBinding {
        let kind = match b.kind {
            DomainOriginBindingKind::Exact => cf_browser::origin::OriginBindingKind::Exact,
            DomainOriginBindingKind::Subdomain => cf_browser::origin::OriginBindingKind::Subdomain,
            DomainOriginBindingKind::Domain => cf_browser::origin::OriginBindingKind::Domain,
        };
        BrowserOriginBinding {
            kind,
            value: b.value.clone(),
        }
    }

    /// cf-browser 匹配绑定 → cf-domain 存储绑定（capture_save 写库用）。
    fn domain_binding(b: &BrowserOriginBinding) -> DomainOriginBinding {
        let kind = match b.kind {
            cf_browser::origin::OriginBindingKind::Exact => DomainOriginBindingKind::Exact,
            cf_browser::origin::OriginBindingKind::Subdomain => DomainOriginBindingKind::Subdomain,
            cf_browser::origin::OriginBindingKind::Domain => DomainOriginBindingKind::Domain,
        };
        DomainOriginBinding {
            kind,
            value: b.value.clone(),
        }
    }

    /// 按 (origin 绑定匹配 + username 字段值相同) 查找既有条目 ID（capture_save
    /// 「改」路径定位；无 → `None` 走「建」）。`username` 匹配 = designation 为
    /// Username 的字段值相等。
    fn find_item_by_origin_and_username(
        vault: &VaultSession,
        origin: &Origin,
        username: &cf_domain::secret::SecretString,
    ) -> SessionResult<Option<String>> {
        let items = vault.list_items(None)?;
        for summary in items {
            let id = summary.uuid.to_string();
            let Some(item) = vault.get_item(&id)? else {
                continue;
            };
            let bindings: Vec<BrowserOriginBinding> =
                item.origin_bindings.iter().map(browser_binding).collect();
            if origin::best_match(&bindings, origin).is_none() {
                continue;
            }
            let username_matches = item.fields.iter().any(|f| {
                f.designation == Some(Designation::Username)
                    && f.value
                        .as_ref()
                        .is_some_and(|v| v.expose() == username.expose())
            });
            if username_matches {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// `get_entries` 的 vault 实现（裁定书 §3.2）：`list_items` 全量 → 逐条目取
    /// 详情 → 按 origin 绑定 `best_match` 过滤 → 元数据投影（非机密；字段仅
    /// 名 + designation）。非法 origin → 空列表（无绑定可命中）；单条目读取失败
    /// → 跳过（元数据列举尽力而为，不整单失败）。
    fn vault_entries(vault: &VaultSession, origin: &str) -> SessionResult<Vec<EntryInfo>> {
        let Ok(o) = Origin::parse(origin) else {
            return Ok(Vec::new());
        };
        let items = vault.list_items(None)?;
        let mut out = Vec::new();
        for summary in items {
            let id = summary.uuid.to_string();
            let Ok(Some(item)) = vault.get_item(&id) else {
                continue;
            };
            let bindings: Vec<BrowserOriginBinding> =
                item.origin_bindings.iter().map(browser_binding).collect();
            if origin::best_match(&bindings, &o).is_none() {
                continue;
            }
            out.push(EntryInfo {
                entry: id,
                title: item.title.expose().to_owned(),
                category: item.category,
                fields: item
                    .fields
                    .iter()
                    .filter_map(|f| {
                        let designation = f.designation.clone()?;
                        Some(EntryFieldRef {
                            name: f.name.expose().to_owned(),
                            designation,
                        })
                    })
                    .collect(),
            });
        }
        Ok(out)
    }

    /// capture_save 建条目草稿：username + password 双字段（无手势恒拒在分发层）。
    fn capture_create_draft(
        username: &cf_domain::secret::SecretString,
        password: &cf_domain::secret::SecretString,
        title: &str,
        category: ItemCategory,
    ) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            category,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![
                FieldDraft {
                    name: "username".to_owned(),
                    value: Some(username.expose().to_owned()),
                    field_type: cf_domain::field::FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "password".to_owned(),
                    value: Some(password.expose().to_owned()),
                    field_type: cf_domain::field::FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        }
    }

    /// capture_save 改条目草稿：保留既有字段/分区/URL/标签（值 + 元数据），仅替换
    /// username / password 值 + 标题/类别——不丢既有数据；TOTP 由 update_item 的
    /// Keep 默认语义保留（draft 的 `totp` 字段在更新路径忽略）。
    fn capture_merge_draft(
        item: &ItemDetails,
        username: &cf_domain::secret::SecretString,
        password: &cf_domain::secret::SecretString,
        title: &str,
        category: ItemCategory,
    ) -> ItemDraft {
        let urls = item
            .urls
            .iter()
            .map(|u| UrlDraft {
                label: u.label.as_ref().map(|l| l.expose().to_owned()),
                url: u.url.expose().to_owned(),
                is_primary: u.is_primary,
                position: u.position as i32,
            })
            .collect();
        let tags = item.tags.iter().map(|t| t.expose().to_owned()).collect();
        let sections = item
            .sections
            .iter()
            .map(|s| SectionDraft {
                title: s.title.expose().to_owned(),
                position: s.position as i32,
            })
            .collect();
        let fields = item
            .fields
            .iter()
            .map(|f| {
                let value = if f.designation == Some(Designation::Username) {
                    Some(username.expose().to_owned())
                } else if f.designation == Some(Designation::Password) {
                    Some(password.expose().to_owned())
                } else {
                    f.value.as_ref().map(|v| v.expose().to_owned())
                };
                FieldDraft {
                    name: f.name.expose().to_owned(),
                    value,
                    field_type: f.field_type,
                    designation: f.designation.clone(),
                    section_index: f
                        .section_uuid
                        .as_ref()
                        .and_then(|suid| item.sections.iter().position(|s| s.uuid == *suid)),
                    position: f.position as i32,
                }
            })
            .collect();
        ItemDraft {
            title: title.to_owned(),
            category,
            urls,
            tags,
            sections,
            fields,
            totp: None,
        }
    }

    /// broker UDS 定位（host 侧，HIGH2-3 §4.2）：`$COFFER_BROKER_UDS` 显式覆盖；
    /// 缺省 = well-known 公式（无 env 发现，HIGH-2 ② 核销）。`$HOME` 缺失 →
    /// `None`（fail-closed，不静默用错路径）。
    fn broker_uds_path() -> Option<PathBuf> {
        match std::env::var(ENV_BROKER_UDS) {
            Ok(v) if !v.trim().is_empty() => Some(PathBuf::from(v)),
            _ => well_known_broker_uds(),
        }
    }

    /// broker well-known UDS 落点：`<real_home>/Library/Application Support/Coffer/browser/broker.sock`。
    ///
    /// `real_home`：cf-mcp 是 `forbid(unsafe_code)` crate（unsafe 面隔离在 sys
    /// crate，cf-uds-sys 先例），libc `getpwuid` 无法在此直调 → 以 `$HOME` 落地
    ///（HIGH2-3 §6「或 `$HOME` 兜底」；Design Y 非沙盒进程 `$HOME` = 真实主目录，
    /// 与 G-D Swift 侧 `BrowserStatusProbe.userHomeDirectory` 同构）。`$HOME`
    /// 缺失 → `None`（fail-closed）。
    fn well_known_broker_uds() -> Option<PathBuf> {
        let home = std::env::var("HOME")
            .ok()
            .filter(|v| !v.trim().is_empty())?;
        Some(PathBuf::from(home).join(BROKER_UDS_SUFFIX))
    }

    /// 解锁契约解析：**stdin 私有管道**（生产主源，HIGH2-3 §3.3）为主；
    /// env 降级**仅**测试门控（`COFFER_BROKER_SKIP_PEER_VERIFY=1` 且 debug 构建）——
    /// 门控激活时**只用 env**（env 不完整即 fail-closed，不静默改读 stdin，测试
    /// 语义可预期；production 绝不设置该 env）。任一材料缺失/非法 → `None`
    ///（fail-closed，调用方配置错退出 1，不留 socket）。
    fn resolve_broker_secrets() -> Option<BrokerSecrets> {
        if cfg!(debug_assertions) && env_flag(ENV_BROKER_SKIP_PEER_VERIFY) {
            return resolve_broker_secrets_from_env();
        }
        resolve_broker_secrets_from_stdin()
    }

    /// env 降级源（G-B 旧夹具路径）。**仅** `COFFER_BROKER_SKIP_PEER_VERIFY=1`
    /// 且 debug 构建可达（release 下 `cfg!(debug_assertions)` 恒定 false，恒走
    /// stdin——生产绝不设置该 env，HIGH2-3 §3.4 / M-3 并入）。
    fn resolve_broker_secrets_from_env() -> Option<BrokerSecrets> {
        let dek = parse_hex_array::<32>(std::env::var(ENV_BROKER_DEK).ok()?.as_str())?;
        let vault_uuid =
            parse_hex_array::<16>(std::env::var(ENV_BROKER_VAULT_UUID).ok()?.as_str())?;
        let psk = parse_hex_array::<32>(std::env::var(ENV_BROKER_PSK).ok()?.as_str())?;
        Some(BrokerSecrets {
            dek,
            vault_uuid,
            psk,
            unlocked: env_flag(ENV_BROKER_UNLOCKED),
        })
    }

    /// stdin 私有管道源：读至 EOF（App 已 close → 即时 EOF）+ 5s 硬超时 →
    /// 解析 → 成功/失败皆零化读取缓冲（HIGH2-3 §3.3）。
    fn resolve_broker_secrets_from_stdin() -> Option<BrokerSecrets> {
        let mut buf = read_stdin_to_eof()?;
        let parsed = parse_stdin_frame(&buf);
        buf.zeroize();
        parsed
    }

    /// 读 stdin 至 EOF，缓冲上限 [`STDIN_FRAME_LIMIT`]（4 KiB，超即拒，防灌）。
    ///
    /// 5s 硬超时（[`STDIN_READ_TIMEOUT`]）：App 未写 stdin 而保持打开 → 超时 →
    /// `None`（fail-closed 退出 1，不留 socket）。读错 / 超限 → 零化部分缓冲后
    /// `None`。
    fn read_stdin_to_eof() -> Option<Vec<u8>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf: Vec<u8> = Vec::with_capacity(STDIN_FRAME_LIMIT);
            let mut chunk = [0u8; 512];
            let mut stdin = io::stdin();
            loop {
                match stdin.read(&mut chunk) {
                    Ok(0) => break, // EOF（App 已 close → 即时）
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() > STDIN_FRAME_LIMIT {
                            buf.zeroize();
                            let _ = tx.send(Err(()));
                            return;
                        }
                    }
                    Err(_) => {
                        buf.zeroize();
                        let _ = tx.send(Err(()));
                        return;
                    }
                }
            }
            let _ = tx.send(Ok(buf));
        });
        match rx.recv_timeout(STDIN_READ_TIMEOUT) {
            Ok(Ok(buf)) => Some(buf),
            // 超时（App 未写 stdin 而保持打开）/ 读错 / 超限 → fail-closed。
            _ => None,
        }
    }

    /// 解析 stdin 帧（key=value LF，4 行，顺序无关，**key 大小写敏感**，HIGH2-3
    /// §3.1）。
    ///
    /// 空行（含末尾换行产生的空串）跳过；非空行必须含 `=` 且 key ∈ 已知集合；
    /// 未知 key / 缺必填 / hex 非法 / `UNLOCKED` 值非 `0|1` → `None`（fail-closed）。
    /// 只读解析不持有密钥材料，零化由调用方负责（[`resolve_broker_secrets_from_stdin`]）。
    fn parse_stdin_frame(buf: &[u8]) -> Option<BrokerSecrets> {
        let mut dek = None;
        let mut vault_uuid = None;
        let mut psk = None;
        let mut unlocked = false;
        for raw in buf.split(|&b| b == b'\n') {
            if raw.is_empty() {
                continue;
            }
            let line = std::str::from_utf8(raw).ok()?;
            let (key, value) = line.split_once('=')?;
            match key {
                KEY_DEK_HEX => dek = Some(parse_hex_array::<32>(value)?),
                KEY_VAULT_UUID_HEX => vault_uuid = Some(parse_hex_array::<16>(value)?),
                KEY_PSK_HEX => psk = Some(parse_hex_array::<32>(value)?),
                // 缺省/0 = 锁定态（app 请求 → broker_locked 8003）；1 = 已解锁。
                KEY_UNLOCKED => match value {
                    "1" => unlocked = true,
                    "0" => unlocked = false,
                    _ => return None, // 非法值 fail-closed
                },
                _ => return None, // 未知 key fail-closed
            }
        }
        Some(BrokerSecrets {
            dek: dek?,
            vault_uuid: vault_uuid?,
            psk: psk?,
            unlocked,
        })
    }

    /// broker 解锁材料（身份派生 + 配对 PSK + 解锁态标记）。
    struct BrokerSecrets {
        /// vault 数据加密密钥（身份派生输入，docs/31 §4.2）。
        dek: [u8; 32],
        /// vault uuid（身份派生输入）。
        vault_uuid: [u8; 16],
        /// 配对 PSK（E2E 双向认证，docs/31 §3.3）。
        psk: [u8; 32],
        /// 解锁会话存在标记（`false` = 锁定态，app 请求 → broker_locked）。
        unlocked: bool,
    }

    /// 解析 hex 字符串为定长数组（长度不符 / 非法 hex → None，fail-closed）。
    fn parse_hex_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
        cf_browser::e2e::from_hex(hex).ok()?.try_into().ok()
    }

    /// E2E 握手（responder 侧，[`BrokerEndpoint`] 编排，docs/31 §3.3）。
    /// 读 msg1 → 产 msg2 → 读 msg3 → 建会话。任何失败 → Err（统一 8004 语义）。
    fn broker_handshake(
        stream: &mut UnixStream,
        endpoint: &BrokerEndpoint,
    ) -> Result<Session, CfBrowserError> {
        let Some(frame) = read_frame(stream)
            .map_err(|e| CfBrowserError::MalformedMessage(format!("handshake read: {e}")))?
        else {
            return Err(CfBrowserError::SessionNotEstablished);
        };
        let msg1: HandshakeMessage = serde_json::from_slice(&frame)
            .map_err(|e| CfBrowserError::MalformedMessage(format!("init: {e}")))?;
        let (msg2, pending) = endpoint.on_init(&msg1)?;
        let msg2_bytes =
            serde_json::to_vec(&msg2).map_err(|e| CfBrowserError::Serialize(e.to_string()))?;
        write_frame(stream, &msg2_bytes)
            .map_err(|e| CfBrowserError::MalformedMessage(format!("write msg2: {e}")))?;
        let Some(frame3) = read_frame(stream)
            .map_err(|e| CfBrowserError::MalformedMessage(format!("confirm read: {e}")))?
        else {
            return Err(CfBrowserError::SessionNotEstablished);
        };
        let msg3: HandshakeMessage = serde_json::from_slice(&frame3)
            .map_err(|e| CfBrowserError::MalformedMessage(format!("confirm: {e}")))?;
        pending.on_confirm(&msg3)
    }

    /// bind broker UDS 监听器（socket 0600 / 父目录 0700，对齐 uds.rs 模式）。
    ///
    /// 已存在路径按类型处理：活 socket → `AddrInUse`；陈旧 socket（拒绝连接）→
    /// 删除重绑；非 socket（普通文件/目录）→ `AddrInUse`（不覆盖用户数据）。
    fn bind_broker_socket(path: &Path) -> io::Result<UnixListener> {
        ensure_broker_parent_dir(path)?;
        if path.exists() {
            let file_type = fs::metadata(path)?.file_type();
            if file_type.is_socket() {
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "uds path already in use by a live listener: {}",
                            path.display()
                        ),
                    ));
                }
                // 陈旧 socket（拒绝连接）→ 删除重绑。
                let _ = fs::remove_file(path);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "uds path `{}` exists and is not a socket; refusing to overwrite it",
                        path.display()
                    ),
                ));
            }
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_FILE_MODE))?;
        Ok(listener)
    }

    /// 父目录就绪（0700 自建；已存在**不动其权限**，对齐 uds.rs：不对既有共享/
    /// 系统目录 chmod）。
    fn ensure_broker_parent_dir(path: &Path) -> io::Result<()> {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let mut builder = fs::DirBuilder::new();
        builder.mode(SOCKET_DIR_MODE);
        builder.recursive(true);
        builder.create(&parent)
    }

    /// socket 文件清理守卫：所有退出路径删除 socket 文件（不留陈旧残留）。
    struct SocketGuard {
        path: PathBuf,
    }

    impl Drop for SocketGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    /// 读一个 native messaging 帧（4B LE 长度前缀 + payload），返回 payload。
    ///
    /// EOF（前缀不足 4 字节即断开）→ `None`（调用方按干净关闭处理）；payload
    /// 超 [`MAX_FRAME_LEN`] → `InvalidData`（内存安全守卫，防分配炸弹）。
    fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        if let Err(e) = r.read_exact(&mut len_buf) {
            return if e.kind() == io::ErrorKind::UnexpectedEof {
                Ok(None)
            } else {
                Err(e)
            };
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame payload too large: {len} bytes (max {MAX_FRAME_LEN})"),
            ));
        }
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload)?;
        Ok(Some(payload))
    }

    /// 写一个 native messaging 帧（4B LE 长度前缀 + payload），写后 flush。
    fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
        let len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame payload too large"))?;
        w.write_all(&len.to_le_bytes())?;
        w.write_all(payload)?;
        w.flush()
    }

    // ------------------------------------------------------------------
    // 单元测试（纯解析面：stdin 帧 / well-known 公式 / host UDS 解析；
    // 集成面 spawn `coffer` 二进制见 tests/browser_subcommand.rs）
    // ------------------------------------------------------------------
    #[cfg(test)]
    mod tests {
        use super::*;

        /// 环境变量是进程级共享状态，串行化读写（同 cli.rs 外层 tests 纪律）。
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        /// 确定性 4 行帧（`UNLOCKED` 取 `"1"` / `"0"` / 缺省行）。
        fn frame(unlocked_line: Option<&str>) -> String {
            format!(
                "DEK_HEX={}\nVAULT_UUID_HEX={}\nPSK_HEX={}{}\n",
                "a1".repeat(32),
                "b2".repeat(16),
                "c3".repeat(32),
                match unlocked_line {
                    Some(v) => format!("\n{v}"),
                    None => String::new(),
                }
            )
        }

        #[test]
        fn parse_stdin_frame_valid_unlocked() {
            let s = parse_stdin_frame(frame(Some("UNLOCKED=1")).as_bytes())
                .expect("4 行正确帧须解析成功");
            assert_eq!(s.dek, [0xa1; 32]);
            assert_eq!(s.vault_uuid, [0xb2; 16]);
            assert_eq!(s.psk, [0xc3; 32]);
            assert!(s.unlocked, "UNLOCKED=1 → 解锁态");
        }

        #[test]
        fn parse_stdin_frame_order_independent() {
            // 顺序无关（HIGH2-3 §3.1）：乱序 + 中间空行仍解析。
            let (dek, uuid, psk) = ("a1".repeat(32), "b2".repeat(16), "c3".repeat(32));
            let s = parse_stdin_frame(
                format!("PSK_HEX={psk}\nDEK_HEX={dek}\n\nUNLOCKED=0\nVAULT_UUID_HEX={uuid}\n")
                    .as_bytes(),
            )
            .expect("乱序帧须解析成功");
            assert_eq!(s.dek, [0xa1; 32]);
            assert_eq!(s.psk, [0xc3; 32]);
            assert!(!s.unlocked, "UNLOCKED=0 → 锁定态");
        }

        #[test]
        fn parse_stdin_frame_locked_by_default() {
            // 缺 UNLOCKED 行 → 锁定态（HIGH2-3 §3.1「缺省 = 锁定态」）。
            let s = parse_stdin_frame(frame(None).as_bytes()).expect("缺 UNLOCKED 可解析");
            assert!(!s.unlocked, "缺省 → 锁定态");
        }

        #[test]
        fn parse_stdin_frame_missing_required_is_none() {
            let missing_psk = format!(
                "DEK_HEX={}\nVAULT_UUID_HEX={}\nUNLOCKED=1\n",
                "a1".repeat(32),
                "b2".repeat(16)
            );
            assert!(
                parse_stdin_frame(missing_psk.as_bytes()).is_none(),
                "缺必填（PSK_HEX）→ fail-closed"
            );
            assert!(parse_stdin_frame(b"").is_none(), "空 stdin → fail-closed");
        }

        #[test]
        fn parse_stdin_frame_unknown_key_is_none() {
            let unknown = format!(
                "DEK_HEX={}\nVAULT_UUID_HEX={}\nPSK_HEX={}\nFOO=bar\nUNLOCKED=1\n",
                "a1".repeat(32),
                "b2".repeat(16),
                "c3".repeat(32)
            );
            assert!(
                parse_stdin_frame(unknown.as_bytes()).is_none(),
                "未知 key → fail-closed"
            );
        }

        #[test]
        fn parse_stdin_frame_invalid_hex_is_none() {
            let bad = format!(
                "DEK_HEX={}\nVAULT_UUID_HEX={}\nPSK_HEX={}\nUNLOCKED=1\n",
                "zz".repeat(32),
                "b2".repeat(16),
                "c3".repeat(32)
            );
            assert!(
                parse_stdin_frame(bad.as_bytes()).is_none(),
                "非法 hex → fail-closed"
            );
        }

        #[test]
        fn parse_stdin_frame_malformed_line_is_none() {
            // 非空行缺 `=` → 非法帧。
            let malformed = format!(
                "DEK_HEX={}\nVAULT_UUID_HEX={}\nPSK_HEX={}\nNOTAEQUAL\nUNLOCKED=1\n",
                "a1".repeat(32),
                "b2".repeat(16),
                "c3".repeat(32)
            );
            assert!(
                parse_stdin_frame(malformed.as_bytes()).is_none(),
                "缺 `=` 行 → fail-closed"
            );
        }

        #[test]
        fn parse_stdin_frame_invalid_unlocked_value_is_none() {
            let bad = format!(
                "DEK_HEX={}\nVAULT_UUID_HEX={}\nPSK_HEX={}\nUNLOCKED=2\n",
                "a1".repeat(32),
                "b2".repeat(16),
                "c3".repeat(32)
            );
            assert!(
                parse_stdin_frame(bad.as_bytes()).is_none(),
                "UNLOCKED 非法值 → fail-closed"
            );
        }

        /// TC-PATH（HIGH2-3 §7）：well-known socket 路径 ≤ 104 字节（sun_path 预算
        /// 守卫），且落点常量与 G-D Swift 侧逐字节一致（后缀断言）。
        #[test]
        fn well_known_broker_uds_within_sun_path_budget() {
            let path = well_known_broker_uds().expect("$HOME 存在时须可计算");
            let os = path.as_os_str().as_encoded_bytes();
            assert!(
                os.len() <= 104,
                "well-known socket 路径须 ≤ 104 字节（AF_UNIX sun_path）: {} ({}B)",
                path.display(),
                os.len()
            );
            assert!(
                path.ends_with(BROKER_UDS_SUFFIX),
                "落点须以常量后缀结尾: {}",
                path.display()
            );
        }

        /// TC-HOST-1（HIGH2-3 §7，自动段）：无 `COFFER_BROKER_UDS` env → 回落
        /// well-known 公式（无 env 发现，HIGH-2 ②）。可信签名浏览器父进程下的
        /// 真机连 socket 为 P-S 判据（同 host_rejects_unsigned_parent 反向）。
        #[test]
        fn broker_uds_path_falls_back_to_well_known() {
            let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            std::env::remove_var(ENV_BROKER_UDS);
            assert_eq!(
                broker_uds_path(),
                well_known_broker_uds(),
                "无 $COFFER_BROKER_UDS → well-known 公式"
            );
            std::env::remove_var(ENV_BROKER_UDS);
        }

        /// TC-HOST-2（HIGH2-3 §7，自动段）：`COFFER_BROKER_UDS` 指向显式路径 →
        /// 采用覆盖值（显式错误路径 → 调用方连失败 → 配置错 1；真机断言同
        /// TC-HOST-1）。
        #[test]
        fn broker_uds_path_honors_env_override() {
            let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let override_path = PathBuf::from("/tmp/coffer-broker-override.sock");
            std::env::set_var(ENV_BROKER_UDS, &override_path);
            assert_eq!(
                broker_uds_path(),
                Some(override_path.clone()),
                "$COFFER_BROKER_UDS 显式覆盖优先"
            );
            std::env::remove_var(ENV_BROKER_UDS);
        }

        /// HIGH-1 语义回归：`env_flag` 仅显式 `"1"` 为真，`"0"`/空/缺省均假
        ///（防 `=0` 误开启跳过/解锁旋钮）。
        #[test]
        fn env_flag_only_true_on_exact_1() {
            let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            for (value, expect) in [
                (Some("1"), true),
                (Some("0"), false),
                (Some(""), false),
                (Some("true"), false),
                (None, false),
            ] {
                match value {
                    Some(v) => std::env::set_var(ENV_BROKER_SKIP_PEER_VERIFY, v),
                    None => std::env::remove_var(ENV_BROKER_SKIP_PEER_VERIFY),
                }
                assert_eq!(
                    env_flag(ENV_BROKER_SKIP_PEER_VERIFY),
                    expect,
                    "value={value:?} 须映射到 {expect}"
                );
            }
            std::env::remove_var(ENV_BROKER_SKIP_PEER_VERIFY);
        }

        /// HIGH-1 语义回归：env 降级路径 `UNLOCKED=0`（旧夹具写法）→ 锁定态
        ///（`=0` 不再被误判为已解锁；`=1` → 解锁态）。
        #[test]
        fn env_unlocked_zero_means_locked() {
            let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            std::env::set_var(ENV_BROKER_DEK, "a1".repeat(32));
            std::env::set_var(ENV_BROKER_VAULT_UUID, "b2".repeat(16));
            std::env::set_var(ENV_BROKER_PSK, "c3".repeat(32));
            std::env::set_var(ENV_BROKER_UNLOCKED, "0");
            let locked = resolve_broker_secrets_from_env().expect("env 材料齐全可解析");
            assert!(!locked.unlocked, "UNLOCKED=0 → 锁定态（HIGH-1 语义）");
            std::env::set_var(ENV_BROKER_UNLOCKED, "1");
            let unlocked = resolve_broker_secrets_from_env().expect("env 材料齐全可解析");
            assert!(unlocked.unlocked, "UNLOCKED=1 → 解锁态");
            std::env::remove_var(ENV_BROKER_UNLOCKED);
            let default = resolve_broker_secrets_from_env().expect("env 材料齐全可解析");
            assert!(!default.unlocked, "缺 UNLOCKED → 锁定态");
            for name in [ENV_BROKER_DEK, ENV_BROKER_VAULT_UUID, ENV_BROKER_PSK] {
                std::env::remove_var(name);
            }
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
