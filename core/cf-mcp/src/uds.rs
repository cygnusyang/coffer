//! UDS 传输（docs/20 §3.1 / §3.6，v2.1.0 D-4 实现）。
//!
//! `coffer mcp --uds PATH`：监听 Unix domain socket（AF_UNIX 本机回环）而非
//! stdio，协议帧格式与 stdio 完全一致（换行分隔 JSON-RPC 2.0），区别只在传输层。
//! 退出码契约复用 stdio（0 干净 / 1 配置错 / 2 协议致命 / 3 身份缺失，docs/27 D-1）。
//!
//! ## §3.6 防护全套
//!
//! | 判据 | 落点 |
//! | --- | --- |
//! | ① 单次 connect 生命周期 | [`run`] 只 accept 一次；断连/EOF → 干净退出 0 |
//! | ② peer 凭据校验（`getpeereid` / `LOCAL_PEERPID` 须为 spawn 方） | [`peer_is_authorized`] + `cf-uds-sys`（macOS；连接方 PID 须等于 `$COFFER_MCP_UDS_PEER_PID`，且同用户） |
//! | ③ 会话随机 challenge（env 下发，`initialize` 回显） | [`Challenge`]（HMAC-SHA256 指纹）+ McpServer 门控（`_coffer_uds_challenge` 参数） |
//! | ④ 消息 id 单调递增 | 复用 [`crate::McpServer`] 的 `check_replay_id`（stdio 同规则） |
//!
//! ## 权限（docs/20 §3.1）
//!
//! socket 文件 **0600**、父目录 **0700**（`SOCKET_FILE_MODE` / `SOCKET_DIR_MODE`）。
//!
//! ## env 握手契约（spawn 时经 env 下发，docs/20 §3.6 ②③ / §4.3）
//!
//! - `$COFFER_MCP_UDS`：非空则监听该路径（空 = stdio；docs/20 §4.3）；
//! - `$COFFER_MCP_UDS_PEER_PID`：spawn 方 PID（macOS 必填，fail-closed）；
//! - `$COFFER_MCP_UDS_CHALLENGE`：会话随机 challenge（必填，fail-closed）；
//!
//! 缺任一（macOS 下）→ 配置错误退出 1（fail-closed：无握手材料不提供服务）。
//! 非 macOS 无 `LOCAL_PEERPID`，peer PID 检查跳过；challenge 仍全平台生效。

use std::fs;
use std::io::BufReader;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::cli::{exit_code, Logger};
use crate::McpServer;

/// `--uds` 路径环境变量（docs/20 §4.3：非空则监听该 UDS 路径，空 = stdio）。
pub const UDS_ENV_PATH: &str = "COFFER_MCP_UDS";
/// spawn 方 PID 环境变量（docs/20 §3.6 ②：spawn 时经 env 下发）。
pub const UDS_ENV_PEER_PID: &str = "COFFER_MCP_UDS_PEER_PID";
/// 会话随机 challenge 环境变量（docs/20 §3.6 ③：spawn 时经 env 下发，`initialize` 回显）。
pub const UDS_ENV_CHALLENGE: &str = "COFFER_MCP_UDS_CHALLENGE";
/// `initialize` 请求中回显 challenge 的参数名（UDS 专属约定，与 MCP 标准参数并存）。
pub const CHALLENGE_PARAM: &str = "_coffer_uds_challenge";
/// socket 文件权限（docs/20 §3.1：0600）。
const SOCKET_FILE_MODE: u32 = 0o600;
/// 父目录权限（docs/20 §3.1：0700）。
const SOCKET_DIR_MODE: u32 = 0o700;
/// macOS `sockaddr_un.sun_path` 可用上限：`char[104]` 须给 NUL 留位，std 的
/// `UnixListener::bind` 对 `len >= SUN_LEN` 报「must be shorter than SUN_LEN」，
/// 故可用路径最长 103 字节——超长在 bind 前报可操作错误。
const MAX_SUN_PATH: usize = 103;
/// challenge 指纹的固定 HMAC 密钥（域分离常量；秘密是 challenge 本身）。
const CHALLENGE_HMAC_KEY: &[u8] = b"coffer-uds-challenge-v1";

type HmacSha256 = Hmac<Sha256>;

/// 会话 challenge（docs/20 §3.6 ③）：只持 HMAC-SHA256 指纹，不存明文。
#[derive(Debug, Clone)]
pub struct Challenge {
    fingerprint: [u8; 32],
}

impl Challenge {
    /// 由 env 下发的原始 challenge 构造（指纹 = HMAC-SHA256，常量时间比对）。
    #[must_use]
    pub fn from_env_value(raw: &str) -> Self {
        Self {
            fingerprint: hmac_fingerprint(raw.as_bytes()),
        }
    }

    /// 常量时间校验回显（`initialize` 的 [`CHALLENGE_PARAM`] 参数）。
    #[must_use]
    pub fn verify(&self, echo: &str) -> bool {
        let mut mac = match HmacSha256::new_from_slice(CHALLENGE_HMAC_KEY) {
            Ok(m) => m,
            // 定长固定密钥不可能超 HMAC 块长；防御性兜底直接判失败。
            Err(_) => return false,
        };
        mac.update(echo.as_bytes());
        mac.verify_slice(&self.fingerprint).is_ok()
    }
}

/// HMAC-SHA256 指纹（固定密钥，域分离）。
fn hmac_fingerprint(data: &[u8]) -> [u8; 32] {
    let mut mac = match HmacSha256::new_from_slice(CHALLENGE_HMAC_KEY) {
        Ok(m) => m,
        // 定长固定密钥不可能超 HMAC 块长；防御性兜底返回全零（verify 恒失败）。
        Err(_) => return [0u8; 32],
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// 运行 UDS 服务（docs/20 §3.1/§3.6）：权限、env 握手、bind、单次 connect、
/// peer 校验、challenge 门控 + 复用 [`McpServer::serve_with`] 协议循环。
///
/// 返回退出码（§5.3 复用 stdio）：0 干净 / 1 配置错（路径超长、bind 失败、握手
/// env 缺失、权限设置失败）/ 2 协议致命（serve 帧同步不可恢复）。peer 拒绝不是
/// 服务错误——记 warn 后干净退出 0（连接生命周期完成）。
pub fn run(path: &Path, logger: &mut Logger, server: McpServer) -> i32 {
    // sun_path 长度（macOS 上限，须 < 104 给 NUL 留位）——bind 前即给可操作错误。
    if path.as_os_str().as_bytes().len() > MAX_SUN_PATH {
        eprintln!(
            "error: uds path too long (max {MAX_SUN_PATH} bytes on macOS): {}",
            path.display()
        );
        return exit_code::CONFIG_ERROR;
    }
    // 父目录就绪并 0700（docs/20 §3.1）。
    if let Err(e) = ensure_parent_dir(path) {
        eprintln!(
            "error: uds parent dir for `{}` cannot be prepared: {e}",
            path.display()
        );
        return exit_code::CONFIG_ERROR;
    }
    // 会话 challenge（fail-closed：--uds 下 env 未下发 → 配置错误 1）。
    let challenge = match std::env::var(UDS_ENV_CHALLENGE) {
        Ok(v) if !v.is_empty() => Challenge::from_env_value(&v),
        _ => {
            eprintln!(
                "error: `--uds` requires ${UDS_ENV_CHALLENGE}（会话 challenge，spawn 时经 env 下发，docs/20 §3.6 ③）"
            );
            return exit_code::CONFIG_ERROR;
        }
    };
    // spawn 方 PID（macOS 才校验；非 macOS 跳过 peer 检查，challenge 仍生效）。
    let spawner_pid = std::env::var(UDS_ENV_PEER_PID)
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    #[cfg(target_os = "macos")]
    if spawner_pid.is_none() {
        eprintln!(
            "error: `--uds` requires ${UDS_ENV_PEER_PID}（spawn 方 PID，spawn 时经 env 下发，docs/20 §3.6 ②）"
        );
        return exit_code::CONFIG_ERROR;
    }

    // bind（陈旧 socket 探测后重绑）+ socket 文件 0600。
    let listener = match bind(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: uds bind `{}` failed: {e}", path.display());
            return exit_code::CONFIG_ERROR;
        }
    };
    if let Err(e) = fs::set_permissions(path, PermissionsExt::from_mode(SOCKET_FILE_MODE)) {
        eprintln!(
            "error: cannot set 0600 on uds socket `{}`: {e}",
            path.display()
        );
        return exit_code::CONFIG_ERROR;
    }
    // 所有退出路径（含提前返回）都删除 socket 文件。
    let _guard = SocketGuard {
        path: path.to_path_buf(),
    };

    logger.info(&format!(
        "listening on uds {} (single-connect lifecycle)",
        path.display()
    ));

    // ① 单次 connect 生命周期（§3.6）。
    let (stream, _addr) = match listener.accept() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: uds accept failed: {e}");
            return exit_code::PROTOCOL_FATAL;
        }
    };

    // ② peer 凭据校验（连接方 PID 须为 spawn 方，且同用户；否则拒）。
    if let Some(expected) = spawner_pid {
        if !peer_is_authorized(&stream, expected) {
            logger.warn(&format!(
                "uds: rejecting connection from non-spawner (peer not authorized, expected pid {expected})"
            ));
            return exit_code::CLEAN;
        }
    }

    // ③ challenge 门控 + 服务（④ 单调 id 由 McpServer 复用）。
    let server = server.with_uds_challenge(challenge);
    let reader = match stream.try_clone() {
        Ok(r) => BufReader::new(r),
        Err(e) => {
            eprintln!("error: uds stream clone failed: {e}");
            return exit_code::PROTOCOL_FATAL;
        }
    };
    logger.info("uds: connection accepted, serving");
    match server.serve_with(reader, stream) {
        Ok(()) => {
            logger.info("uds: connection closed, exiting");
            exit_code::CLEAN
        }
        Err(e) => {
            eprintln!("error: uds serve failed: {e}");
            exit_code::PROTOCOL_FATAL
        }
    }
}

/// peer 凭据校验（docs/20 §3.6 ②）：连接方 PID 须为 spawn 方（Darwin
/// `LOCAL_PEERPID`，经 `cf-uds-sys`），且同用户（`getpeereid` euid == 本进程
/// euid）。任一 syscall 失败 / 不匹配 → 拒（fail-closed）。
#[cfg(target_os = "macos")]
fn peer_is_authorized(stream: &UnixStream, expected_pid: u32) -> bool {
    let pid_ok = cf_uds_sys::peer_pid(stream)
        .map(|p| p as u32 == expected_pid)
        .unwrap_or(false);
    let euid_ok = cf_uds_sys::peer_euid(stream)
        .map(|e| e == cf_uds_sys::self_euid())
        .unwrap_or(false);
    pid_ok && euid_ok
}

/// 非 macOS：无 `LOCAL_PEERPID` / `getpeereid`，peer 检查跳过（challenge ③仍
/// 全平台生效，docs/20 §3.6 ③）。
#[cfg(not(target_os = "macos"))]
fn peer_is_authorized(_stream: &UnixStream, _expected_pid: u32) -> bool {
    true
}

/// bind UDS 监听器（docs/20 §3.1）。`path` 已存在时按文件类型处理：
///
/// - socket 文件：探测是否存活——活监听者（能连上）→ `AddrInUse` 报错；
///   陈旧残留（拒绝连接，如上次进程崩溃留下的）→ 删除后重绑；
/// - **非 socket**（普通文件/目录）：**不删除用户数据**，直接 `AddrInUse` 报错
///   （可操作消息，fail-closed）。
fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if path.exists() {
        let file_type = fs::metadata(path)
            .map_err(|e| {
                io_error_ctx(e.kind(), format!("stat uds path `{}`: {e}", path.display()))
            })?
            .file_type();
        if file_type.is_socket() {
            if UnixStream::connect(path).is_ok() {
                return Err(io_error_ctx(
                    std::io::ErrorKind::AddrInUse,
                    format!(
                        "uds path already in use by a live listener: {}",
                        path.display()
                    ),
                ));
            }
            // 陈旧 socket（拒绝连接）→ 删除重绑。
            let _ = fs::remove_file(path);
        } else {
            return Err(io_error_ctx(
                std::io::ErrorKind::AddrInUse,
                format!(
                    "uds path `{}` exists and is not a socket; refusing to overwrite it",
                    path.display()
                ),
            ));
        }
    }
    UnixListener::bind(path)
}

/// 带上下文信息的 IO 错误（避免裸 `io::Error::new` 丢路径）。
fn io_error_ctx(kind: std::io::ErrorKind, msg: String) -> std::io::Error {
    std::io::Error::new(kind, msg)
}

/// 父目录就绪（docs/20 §3.1）：不存在则以 0700 创建；已存在则**不动其权限**
/// （`DirBuilder::mode` 只作用于本次创建的目录，绝不对既有的共享/系统目录
/// 如 `/tmp` 做 chmod——那既可能 EPERM 也可能破坏其他用户的目录语义）。
fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut builder = fs::DirBuilder::new();
    builder.mode(SOCKET_DIR_MODE);
    builder.recursive(true);
    builder.create(&parent)
}

/// socket 文件清理守卫：所有退出路径都删除 socket 文件（不留陈旧残留）。
struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::McpCliOptions;
    use crate::provider::test_seed::TestSeedProvider;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream as Conn};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// 环境变量是进程级共享状态，串行化读写（同 provider_op_list ENV_LOCK 纪律）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 唯一临时 socket 路径（父目录不存在——由 run 创建并 0700）。
    ///
    /// 唯一后缀截断到低 8 位十六进制：路径总长须 < 104（macOS `sun_path` 上限，
    /// `MAX_SUN_PATH`），不随 `temp_dir` 长度/tag 长度变化而越界。
    fn uds_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let suffix = format!("{:08x}", nanos & 0xffff_ffff);
        std::env::temp_dir()
            .join(format!("cf-uds-{tag}-{}-{suffix}", std::process::id()))
            .join("coffer.sock")
    }

    /// 默认选项的 Logger（stderr sink，无 --log 文件）。
    fn default_logger() -> Logger {
        Logger::new(&McpCliOptions {
            provider: "op".to_string(),
            provider_explicit: true,
            vault: None,
            log_path: None,
            no_audit: false,
            uds: None,
        })
        .expect("default logger must construct")
    }

    /// 等待 socket 文件出现（run 线程 bind 后连接，避免竞态）。
    fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
        let deadline = SystemTime::now() + timeout;
        while SystemTime::now() < deadline {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// 轮询直到连接成功（陈旧 socket 重绑场景：文件 exists 但连不上，须等重绑）。
    fn connect_with_retry(path: &Path, timeout: Duration) -> Option<Conn> {
        let deadline = SystemTime::now() + timeout;
        while SystemTime::now() < deadline {
            if let Ok(c) = Conn::connect(path) {
                return Some(c);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// 轮询直到 socket 文件出现且权限 == 期望（`bind` 先以 umask 默认建文件、
    /// `run` 随后 set_permissions 0600——存在短暂窗口，测试须等收敛到 0600）。
    fn wait_for_socket_mode(path: &Path, expected: u32, timeout: Duration) -> bool {
        let deadline = SystemTime::now() + timeout;
        while SystemTime::now() < deadline {
            if let Ok(meta) = fs::metadata(path) {
                if (meta.permissions().mode() & 0o777) == expected {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn challenge_verify_mismatch_fails() {
        let ch = Challenge::from_env_value("secret-challenge");
        assert!(
            !ch.verify("wrong-echo"),
            "错误回显必须判定失败（HMAC 指纹不匹配）"
        );
    }

    #[test]
    fn challenge_verify_match_succeeds() {
        let ch = Challenge::from_env_value("secret-challenge");
        assert!(
            ch.verify("secret-challenge"),
            "正确回显必须通过（HMAC 指纹匹配）"
        );
    }

    #[test]
    fn challenge_does_not_store_plaintext() {
        // 指纹化：Challenge 不保留原始 challenge 明文（内存不留可回放的会话密钥）。
        let ch = Challenge::from_env_value("top-secret-value");
        let debug = format!("{ch:?}");
        assert!(
            !debug.contains("top-secret-value"),
            "Debug 表示不得泄露明文: {debug}"
        );
    }

    /// 端到端：完整握手（initialize 回显 challenge → tools/list）→ 干净退出 0，
    /// 权限 0600/0700、socket 文件清理、peer PID == spawn 方（本进程）。
    #[test]
    fn uds_run_full_handshake_single_connect() {
        let _g = env_guard();
        let path = uds_path("full");
        std::env::set_var(UDS_ENV_CHALLENGE, "unit-challenge");
        std::env::set_var(UDS_ENV_PEER_PID, std::process::id().to_string());

        let server = McpServer::new(Box::new(TestSeedProvider));
        let mut logger = default_logger();
        let path_for_thread = path.clone();
        let handle = std::thread::spawn(move || run(&path_for_thread, &mut logger, server));

        assert!(
            wait_for_socket_mode(&path, SOCKET_FILE_MODE, Duration::from_secs(5)),
            "socket 文件须在超时内出现且权限收敛到 0600"
        );

        let mut conn = Conn::connect(&path).expect("client must connect");
        // initialize + challenge 回显。
        writeln!(
            conn,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","clientInfo":{{"name":"test"}},"{CHALLENGE_PARAM}":"unit-challenge"}}}}"#
        )
        .expect("write initialize");
        // tools/list（id 单调递增）。
        writeln!(conn, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#)
            .expect("write tools/list");
        conn.flush().expect("flush");
        conn.shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");

        let mut responses = String::new();
        conn.read_to_string(&mut responses).expect("read responses");
        assert!(
            responses.contains("\"isError\":false") || responses.contains("\"result\""),
            "initialize + tools/list 均须成功响应: {responses}"
        );
        assert!(
            !responses.contains("challenge"),
            "成功路径不得出现 challenge 错误: {responses}"
        );

        drop(conn);
        let code = handle.join().expect("run thread must not panic");
        assert_eq!(code, exit_code::CLEAN, "完整握手后须干净退出 0");
        assert!(!path.exists(), "退出后 socket 文件须清理");

        // 父目录 0700（docs/20 §3.1；父目录由 run 创建）。
        let dir_mode = fs::metadata(path.parent().expect("parent"))
            .expect("parent dir must exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, SOCKET_DIR_MODE, "父目录须 0700");

        std::env::remove_var(UDS_ENV_CHALLENGE);
        std::env::remove_var(UDS_ENV_PEER_PID);
    }

    /// 非 spawn 方 PID → 拒（连接被丢弃，客户端读 EOF），进程干净退出 0。
    #[test]
    #[cfg(target_os = "macos")]
    fn uds_rejects_non_spawner_peer() {
        let _g = env_guard();
        let path = uds_path("peer");
        std::env::set_var(UDS_ENV_CHALLENGE, "unit-challenge");
        std::env::set_var(UDS_ENV_PEER_PID, "999999999"); // 非本进程 PID。

        let server = McpServer::new(Box::new(TestSeedProvider));
        let mut logger = default_logger();
        let path_for_thread = path.clone();
        let handle = std::thread::spawn(move || run(&path_for_thread, &mut logger, server));

        assert!(wait_for_socket(&path, Duration::from_secs(5)));
        let mut conn = Conn::connect(&path).expect("client must connect");
        writeln!(
            conn,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"{CHALLENGE_PARAM}":"unit-challenge"}}}}"#
        )
        .expect("write initialize");
        conn.flush().expect("flush");
        drop(conn);

        let code = handle.join().expect("run thread must not panic");
        assert_eq!(
            code,
            exit_code::CLEAN,
            "拒绝非 spawn 方是干净退出（连接生命周期完成），非错误"
        );
        assert!(!path.exists(), "退出后 socket 文件须清理");
        std::env::remove_var(UDS_ENV_CHALLENGE);
        std::env::remove_var(UDS_ENV_PEER_PID);
    }

    /// env 握手材料缺失 → fail-closed：不 bind、配置错误退出 1。
    #[test]
    fn uds_missing_challenge_env_is_config_error() {
        let _g = env_guard();
        std::env::remove_var(UDS_ENV_CHALLENGE);
        let path = uds_path("nochallenge");
        let server = McpServer::new(Box::new(TestSeedProvider));
        let mut logger = default_logger();
        let code = run(&path, &mut logger, server);
        assert_eq!(code, exit_code::CONFIG_ERROR, "challenge env 缺失须退出 1");
        assert!(!path.exists(), "fail-closed 不得创建 socket 文件");
    }

    /// 客户端 tools/call 前未 initialize 回显 challenge → 工具面拒绝（McpServer
    /// 门控在 transport 之上，此处经真实 serve 验证）。
    #[test]
    fn uds_tools_before_challenge_rejected() {
        let _g = env_guard();
        let path = uds_path("gate");
        std::env::set_var(UDS_ENV_CHALLENGE, "unit-challenge");
        std::env::set_var(UDS_ENV_PEER_PID, std::process::id().to_string());

        let server = McpServer::new(Box::new(TestSeedProvider));
        let mut logger = default_logger();
        let path_for_thread = path.clone();
        let handle = std::thread::spawn(move || run(&path_for_thread, &mut logger, server));

        assert!(wait_for_socket(&path, Duration::from_secs(5)));
        let mut conn = Conn::connect(&path).expect("client must connect");
        writeln!(conn, r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}"#)
            .expect("write tools/list before initialize");
        conn.flush().expect("flush");
        conn.shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        let mut responses = String::new();
        conn.read_to_string(&mut responses).expect("read responses");
        assert!(
            responses.contains("challenge not verified"),
            "未回显 challenge 的工具面须被拒: {responses}"
        );
        drop(conn);
        let code = handle.join().expect("run thread must not panic");
        assert_eq!(code, exit_code::CLEAN);
        std::env::remove_var(UDS_ENV_CHALLENGE);
        std::env::remove_var(UDS_ENV_PEER_PID);
    }

    /// 陈旧 socket 残留（上次进程崩溃留下的 socket 文件、无监听者）→ 探测后
    /// 重绑成功。
    #[test]
    fn uds_stale_socket_is_rebound() {
        let _g = env_guard();
        let path = uds_path("stale");
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        // 制造真实陈旧 socket：bind 后 drop 监听器——socket 文件残留、无监听者。
        {
            let listener = UnixListener::bind(&path).expect("bind stale socket");
            drop(listener);
        }
        assert!(path.exists(), "陈旧 socket 文件须残留");

        std::env::set_var(UDS_ENV_CHALLENGE, "unit-challenge");
        std::env::set_var(UDS_ENV_PEER_PID, std::process::id().to_string());
        let server = McpServer::new(Box::new(TestSeedProvider));
        let mut logger = default_logger();
        let path_for_thread = path.clone();
        let handle = std::thread::spawn(move || run(&path_for_thread, &mut logger, server));

        // 陈旧 socket 连不上（ECONNREFUSED）→ 轮询直到重绑后可连。
        let conn = connect_with_retry(&path, Duration::from_secs(5))
            .expect("must connect to rebound socket");
        conn.shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        drop(conn);
        let code = handle.join().expect("run thread must not panic");
        assert_eq!(code, exit_code::CLEAN, "陈旧 socket 重绑后正常服务");
        std::env::remove_var(UDS_ENV_CHALLENGE);
        std::env::remove_var(UDS_ENV_PEER_PID);
    }

    /// 非 socket（普通文件）占据路径 → 拒绝覆盖（不删用户数据），退出 1。
    #[test]
    fn uds_refuses_non_socket_at_path() {
        let _g = env_guard();
        let path = uds_path("refuse");
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        fs::write(&path, b"important user data").expect("write marker file");

        std::env::set_var(UDS_ENV_CHALLENGE, "unit-challenge");
        std::env::set_var(UDS_ENV_PEER_PID, std::process::id().to_string());
        let server = McpServer::new(Box::new(TestSeedProvider));
        let mut logger = default_logger();
        let code = run(&path, &mut logger, server);
        assert_eq!(
            code,
            exit_code::CONFIG_ERROR,
            "非 socket 占据路径 → 配置错误退出 1"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("file must be readable"),
            "important user data",
            "不得删除/覆盖用户数据"
        );
        std::env::remove_var(UDS_ENV_CHALLENGE);
        std::env::remove_var(UDS_ENV_PEER_PID);
    }
}
