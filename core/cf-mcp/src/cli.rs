//! `coffer mcp` CLI（docs/20 §5，G-D）。
//!
//! 职责：把命令行参数（§5.2 **冻结签名**）解析成 provider 配置 + 启动
//! [`crate::McpServer::serve_stdio`]。stdout 永为协议帧（§3.1）；日志只走
//! stderr 或 `--log` 文件。退出码映射见 §5.3 与 [`exit_code`]。
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
//! - 日志/错误载荷**不**含 Secret 值（§3.5-4 载荷纪律）。
//!
//! ## 依赖纪律（docs/20 §2.2）
//!
//! 本模块不新增第三方依赖：flag 集冻结且很小 → 参数解析手写（不引 clap）；
//! 日志走最小 [`Logger`]（stderr / `--log` 文件），不引 tracing-subscriber。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::provider::op::{OpProvider, OpProviderConfig};
use crate::provider::{ProviderError, SecretProvider};
use crate::McpServer;

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
    #[error("{0} is not implemented in this version (docs/20 D-4): only stdio transport is supported")]
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
    /// provider 名（MVP 恒 `op`；缺省 `$COFFER_MCP_PROVIDER`）。
    pub provider: String,
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
/// - `--provider`：`$COFFER_MCP_PROVIDER`，未设 → `op`；
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

    let provider = provider
        .or_else(|| std::env::var("COFFER_MCP_PROVIDER").ok())
        .unwrap_or_else(|| "op".to_string());

    Ok(McpCliOptions { provider, log_path, vault, no_audit })
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

/// CLI 运行时日志接收器（stdout 永为协议帧，docs/20 §3.1）。
///
/// 输出目标：`--log PATH` 文件（追加），缺省 stderr。**永不写 stdout**。
/// 文件写失败为尽力而为（日志不阻断服务，注释说明）。
#[derive(Debug)]
pub struct Logger {
    sink: LogSink,
}

#[derive(Debug)]
enum LogSink {
    /// stderr（缺省）。
    Stderr,
    /// `--log PATH` 追加文件。
    File(std::fs::File),
}

impl Logger {
    /// 按选项构造日志器；打开 `--log` 文件失败 → [`CliError::LogOpen`]。
    pub fn new(options: &McpCliOptions) -> Result<Self, CliError> {
        match &options.log_path {
            None => Ok(Self { sink: LogSink::Stderr }),
            Some(path) => {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| CliError::LogOpen {
                        path: path.display().to_string(),
                        source: e,
                    })?;
                Ok(Self { sink: LogSink::File(file) })
            }
        }
    }

    /// 信息级日志。
    pub fn info(&mut self, msg: &str) {
        self.emit("INFO", msg);
    }

    /// 警告级日志（非致命）。
    pub fn warn(&mut self, msg: &str) {
        self.emit("WARN", msg);
    }

    /// 写一行日志（unix 秒前缀）。文件写失败忽略——日志是尽力而为。
    fn emit(&mut self, level: &str, msg: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("[{ts}] [{level}] {msg}");
        match &mut self.sink {
            LogSink::Stderr => {
                eprintln!("{line}");
            }
            LogSink::File(f) => {
                // 尽力而为日志：写失败不升级为业务错误（审计同纪律，docs/20 §4.6）。
                let _ = writeln!(f, "{line}");
            }
        }
    }
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
        eprintln!(
            "error: unknown subcommand `{subcommand}`; expected `coffer mcp` (docs/20 §5.2)"
        );
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

    // provider 选择（docs/20 §5.2）：MVP 恒 `op`。
    if options.provider != "op" {
        eprintln!(
            "error: unsupported provider `{}`: MVP 仅支持 `op`（docs/20 §5.2）",
            options.provider
        );
        return exit_code::CONFIG_ERROR;
    }

    // 构造 OpProviderConfig：env 缺省（COFFER_OP_BIN / COFFER_OP_VAULT /
    // COFFER_OP_SESSION_TOKEN，§4.3）+ `--vault` 覆盖。
    let mut config = OpProviderConfig::from_env();
    if let Some(vault) = options.vault {
        config.default_vault = Some(vault);
    }
    let vault_hint = config.default_vault.clone();

    // 构造 provider：`op --version` 启动探测（docs/20 §4.2）；失败 → 7001 → 退出 1。
    let provider = match OpProvider::new(config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: provider unavailable (7001): {e}");
            return exit_code::CONFIG_ERROR;
        }
    };

    // 启动期身份检查（docs/20 §5.3 退出码 3）：轻量探测 provider 的 list 面。
    // 仅 `AuthRequired`（7002）阻断启动；其余探测错误非致命（在协议层暴露）。
    match provider.list_secret_names(vault_hint.as_deref()) {
        Err(ProviderError::AuthRequired(m)) => {
            eprintln!("error: identity missing (7002): {m}");
            return exit_code::IDENTITY_MISSING;
        }
        Err(e) => {
            logger.warn(&format!("provider startup probe: {e}"));
        }
        Ok(_) => {}
    }

    // audit（docs/20 §5.2 --no-audit）：D-3 未确认前审计恒 NoopAudit（§4.6 方案 B）。
    // --no-audit 与缺省（开启）在 JSONL 落定前行为相同，仅体现在日志声明。
    if options.no_audit {
        logger.info("audit: off (--no-audit)");
    } else {
        logger.info("audit: on (NoopAudit until D-3 JSONL lands)");
    }

    let server = McpServer::new(Box::new(provider));
    logger.info(&format!(
        "serving on stdio (provider=op, vault={})",
        vault_hint.as_deref().unwrap_or("default")
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
        assert_eq!(o.log_path.as_deref(), Some(PathBuf::from("/tmp/coffer.log").as_path()));
        assert!(o.no_audit);
    }

    #[test]
    fn parse_empty_args_use_builtin_defaults() {
        let _g = env_guard();
        std::env::remove_var("COFFER_MCP_PROVIDER");
        let o = parse_args(&[]).expect("empty args must parse");
        assert_eq!(o.provider, "op", "缺省 provider = op（docs/20 §5.2）");
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
        std::env::remove_var("COFFER_MCP_PROVIDER");
    }

    #[test]
    fn parse_flag_overrides_env_default() {
        let _g = env_guard();
        std::env::set_var("COFFER_MCP_PROVIDER", "op");
        let o = parse_args(&arg(&["--provider", "op"]))
            .expect("explicit --provider must parse");
        assert_eq!(o.provider, "op");
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
}
