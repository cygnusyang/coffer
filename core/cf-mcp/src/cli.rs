//! `coffer mcp` CLI（docs/20 §5，G-D）。
//!
//! 职责：把命令行参数（§5.2 **冻结签名**）解析成 provider 配置 + 启动
//! [`crate::McpServer::serve_stdio`]。stdout 永为协议帧（§3.1）；日志只走
//! stderr 或 `--log` 文件。退出码映射见 §5.3 与 [`exit_code`]。
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
//! ## 传输（D-4 暂缓）
//!
//! MVP 只支持 **stdio**。`--uds` 传入 → 配置错误（退出码 1），注明未实现
//! （docs/20 §3.1 / §8 D-4）。**零网络**：无 TCP/UDP 代码路径（§3.1）。
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
use crate::McpServer;

#[cfg(feature = "coffer-store")]
use crate::provider::coffer::CofferStoreProvider;
#[cfg(feature = "coffer-store")]
use cf_domain::secret::SecretString;

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
    /// flag 在本版未实现（D-4 暂缓）。
    #[error(
        "{0} is not implemented in this version (docs/20 D-4): only stdio transport is supported"
    )]
    Unimplemented(String),
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
}

/// 从 argv（不含子命令 `mcp`）解析 `coffer mcp` 选项（docs/20 §5.2 冻结签名）。
///
/// 缺省值：
/// - `--provider`：`$COFFER_MCP_PROVIDER`，未设 → `coffer`（D-2 缺省翻转，
///   docs/27 D-2）；`provider_explicit` 标记 flag/env 是否给定（feature 关闭时
///   缺省 coffer 回落 op，显式 coffer 按 D-1 报 unsupported）；
/// - `--vault`：不在本层解析（由 [`OpProviderConfig::from_env`] 读
///   `$COFFER_OP_VAULT`）；
/// - `--log` / `--no-audit`：本层直收。
///
/// `--uds`（D-4 暂缓）返回 [`CliError::Unimplemented`]。
///
/// 未知 flag / 位置参数 → [`CliError::UnknownFlag`]；值 flag 缺值 →
/// [`CliError::MissingValue`]。
pub fn parse_args(args: &[String]) -> Result<McpCliOptions, CliError> {
    let mut provider: Option<String> = None;
    let mut log_path: Option<PathBuf> = None;
    let mut vault: Option<String> = None;
    let mut no_audit = false;

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
                // 仍校验取值形态（缺值报 MissingValue），随后报未实现（D-4）。
                let _ = take_value(args, &mut i, "--uds")?;
                return Err(CliError::Unimplemented("--uds".to_string()));
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
    })
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

/// `--provider coffer` 的库配置：读 `$COFFER_VAULT_DIR`（库目录路径）与
/// `$COFFER_VAULT_PASSWORD`（解锁密码），供 [`CofferStoreProvider::open`] 构造
/// （docs/20 §4.5）。缺任一 → 打印可操作错误并返回退出码 1。
///
/// env 约定与 §4.3 同款（Coffer 侧定义、文档落表）：密码**不经 argv / 协议帧 /
/// 日志**，经 [`SecretString`]（ZeroizeOnDrop）承载，用后即毁。
#[cfg(feature = "coffer-store")]
fn coffer_config_from_env() -> Result<(PathBuf, SecretString), i32> {
    let vault_dir = match std::env::var("COFFER_VAULT_DIR") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => {
            eprintln!(
                "error: `--provider coffer` requires $COFFER_VAULT_DIR（库目录路径，docs/20 §4.5）"
            );
            return Err(exit_code::CONFIG_ERROR);
        }
    };
    let password = match std::env::var("COFFER_VAULT_PASSWORD") {
        Ok(v) => SecretString::from_exposed(v),
        _ => {
            eprintln!(
                "error: `--provider coffer` requires $COFFER_VAULT_PASSWORD（解锁密码，docs/20 §4.5）"
            );
            return Err(exit_code::CONFIG_ERROR);
        }
    };
    Ok((vault_dir, password))
}

/// 把 [`CofferStoreProvider::open`] 的失败映射到退出码（docs/20 §5.3）：
/// 7002（密码错误 / 锁态）→ 3 身份缺失；7001（库缺失 / 版本不受支持）→ 1；
/// 其余（7005 / 7006）→ 1。错误消息面向调用方可操作，载荷不泄露细节。
#[cfg(feature = "coffer-store")]
fn map_coffer_open_error(e: ProviderError) -> i32 {
    match e {
        ProviderError::AuthRequired(m) => {
            eprintln!("error: identity missing (7002): {m}");
            exit_code::IDENTITY_MISSING
        }
        ProviderError::Unavailable(m) => {
            eprintln!("error: provider unavailable (7001): {m}");
            exit_code::CONFIG_ERROR
        }
        other => {
            eprintln!("error: provider open failed: {other}");
            exit_code::CONFIG_ERROR
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
            // CofferStoreProvider（docs/20 §4.5）：库路径 + 解锁密码来自 env
            // （§4.3 同款 Coffer 侧约定；密码经 [`SecretString`] 承载，不经
            // argv/日志，§3.5-4 载荷纪律）。`open` 即完成开库 + 解锁：7002 →
            // 退出 3，7001 等 → 退出 1（见 [`map_coffer_open_error`]）。
            let (vault_dir, password) = match coffer_config_from_env() {
                Ok(cfg) => cfg,
                Err(code) => return code,
            };
            let p = match CofferStoreProvider::open(&vault_dir, password.expose()) {
                Ok(p) => p,
                Err(e) => return map_coffer_open_error(e),
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
        ]))
        .expect("valid flag set must parse");
        assert_eq!(o.provider, "op");
        assert_eq!(o.vault.as_deref(), Some("Personal"));
        assert_eq!(
            o.log_path.as_deref(),
            Some(PathBuf::from("/tmp/coffer.log").as_path())
        );
        assert!(o.no_audit);
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
    fn parse_rejects_uds_as_unimplemented() {
        let err = parse_args(&arg(&["--uds", "/tmp/coffer.sock"]))
            .expect_err("--uds (D-4) must be rejected as unimplemented");
        assert!(matches!(err, CliError::Unimplemented(f) if f == "--uds"));
    }

    #[test]
    fn cli_error_messages_are_actionable() {
        // 错误消息面向调用方可操作（载荷纪律：不含敏感值）。
        let unknown = CliError::UnknownFlag("--xyz".into());
        assert_eq!(unknown.to_string(), "unknown flag: --xyz");
        let missing = CliError::MissingValue("--vault".into());
        assert_eq!(missing.to_string(), "flag `--vault` requires a value");
        let uds = CliError::Unimplemented("--uds".into());
        assert!(
            uds.to_string().contains("not implemented"),
            "uds 须注明未实现: {uds}"
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
}
