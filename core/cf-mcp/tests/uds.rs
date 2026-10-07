//! `coffer mcp --uds` UDS 传输集成测试（docs/20 §3.1/§3.6，v2.1.0 D-4 实现）。
//!
//! spawn 编译产物 `coffer` 二进制，以 fake `op` fixture 驱动 OpProvider
//! （tests/cli.rs 同款），`--uds PATH` + env 握手材料（spawn 方 PID = 本进程、
//! 会话 challenge）起服务，以 UnixStream 客户端走完整 MCP 生命周期：
//!
//! - 完整握手（initialize 回显 challenge → tools/list → run_with_secret）→
//!   EOF → 干净退出 0；socket 文件清理；权限 0600/0700；
//! - challenge 回显错误 → initialize 拒绝 + 工具面关闭；
//! - 非 spawn 方 PID → 连接被丢弃（客户端 EOF）、进程干净退出；
//! - 退出码契约复用 stdio（docs/27 D-1：0 干净 / 1 配置错 / 2 协议致命）。
//!
//! 子进程 env 用 `Command::env` 逐子进程下发，无跨用例污染（进程级环境变量
//! 隔离，同 tests/cli.rs 纪律）。

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

/// 编译产物 `coffer` 二进制绝对路径（cargo 在集成测试构建期注入）。
fn coffer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_coffer")
}

/// fake `op` 脚本绝对路径。
fn fake_op() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/op/op")
}

/// 会话 challenge（spawn 时经 env 下发，docs/20 §3.6 ③）。
const CHALLENGE: &str = "integration-challenge";
/// challenge 在 initialize 参数中的回显键（与 uds.rs CHALLENGE_PARAM 同值）。
const CHALLENGE_PARAM: &str = "_coffer_uds_challenge";

/// 每用例独立 socket 路径（父目录由服务端自建，tag 唯一防并行撞名）。
///
/// 唯一后缀截断到低 8 位十六进制：路径总长须 < 104（macOS `sun_path` 上限，
/// 见 uds.rs `MAX_SUN_PATH`），不随 `temp_dir` 长度/tag 长度变化而越界。
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

/// 以 fake op + env 握手材料 spawn `coffer mcp --provider op --uds PATH`。
fn spawn_uds(path: &Path) -> Child {
    Command::new(coffer_bin())
        .args(["mcp", "--provider", "op", "--uds"])
        .arg(path)
        .env("COFFER_OP_BIN", fake_op())
        .env("COFFER_MCP_UDS_PEER_PID", std::process::id().to_string())
        .env("COFFER_MCP_UDS_CHALLENGE", CHALLENGE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn coffer with --uds")
}

/// 等待 socket 文件出现（bind 后 accept 前，避免客户端连早于监听）。
fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    let deadline = SystemTime::now() + timeout;
    while SystemTime::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// 轮询直到 socket 文件权限收敛到期望（`bind` 先以 umask 默认建文件、服务端
/// 随后 set_permissions 0600——存在短暂窗口，须等收敛而非只等文件出现）。
fn wait_for_socket_mode(path: &Path, expected: u32, timeout: Duration) -> bool {
    let deadline = SystemTime::now() + timeout;
    while SystemTime::now() < deadline {
        if let Ok(meta) = std::fs::metadata(path) {
            if (meta.permissions().mode() & 0o777) == expected {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// 写一行协议帧到连接。
fn send_line(conn: &mut UnixStream, line: &str) {
    writeln!(conn, "{line}").expect("write frame to uds");
    conn.flush().expect("flush uds");
}

/// shutdown 写侧后读完全部响应（服务端 EOF → 退出 → 连接关闭）。
fn drain(conn: &mut UnixStream) -> String {
    conn.shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    let mut out = String::new();
    conn.read_to_string(&mut out).expect("read responses");
    out
}

/// 等子进程退出，返回 (退出码, stderr)。
fn finish(child: &mut Child) -> (Option<i32>, String) {
    let status = child.wait().expect("wait for coffer to exit");
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        e.read_to_string(&mut stderr).expect("read stderr");
    }
    (status.code(), stderr)
}

// ===========================================================================
// 用例
// ===========================================================================

/// 完整生命周期：initialize（回显 challenge）→ tools/list → run_with_secret
///（fake op 注入值验证）→ EOF → 干净退出 0；socket 清理；权限 0600/0700。
#[test]
fn uds_full_handshake_and_tools_roundtrip() {
    let path = uds_path("full");
    let mut child = spawn_uds(&path);
    assert!(
        wait_for_socket(&path, Duration::from_secs(10)),
        "socket 文件须在超时内出现: {}",
        path.display()
    );

    // 权限（docs/20 §3.1）：socket 文件须收敛到 0600。
    assert!(
        wait_for_socket_mode(&path, 0o600, Duration::from_secs(5)),
        "socket 文件须在超时内收敛到 0600"
    );

    let mut conn = UnixStream::connect(&path).expect("client must connect");
    send_line(
        &mut conn,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","clientInfo":{{"name":"uds-it"}},"{CHALLENGE_PARAM}":"{CHALLENGE}"}}}}"#
        ),
    );
    send_line(
        &mut conn,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );
    // 模式 B：fake op 注入 MY_KEY 到子进程 env，子进程校验值后退出 0。
    send_line(
        &mut conn,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secret":"op://Personal/OPENAI_API_KEY/password","env_name":"MY_KEY","cmd":"sh","args":["-c","test \"$MY_KEY\" = \"fixture-secret-value-openai\""]}}}"#,
    );

    let responses = drain(&mut conn);
    drop(conn);

    // initialize + tools/list 成功、工具调用子进程退出 0。
    assert!(
        responses.contains("\"serverInfo\"") && responses.contains("\"protocolVersion\""),
        "initialize 须成功返回: {responses}"
    );
    assert!(
        responses.contains("\"tools\"") && responses.contains("list_secret_names"),
        "tools/list 须列出工具: {responses}"
    );
    // 逐帧解析（同 cli.rs run_with_secret 判据）：id==3 的 tools/call 结果，取其
    // 内层 text 判定注入值校验通过（原始帧含转义 JSON，不能对整串做 contains）。
    let tool_text = responses
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v.get("id") == Some(&Value::from(3)))
        .and_then(|v| v["result"]["content"][0]["text"].as_str().map(String::from))
        .unwrap_or_default();
    assert!(
        tool_text.contains("\"exit_code\":0"),
        "run_with_secret 子进程须退出 0（注入值校验通过）: {tool_text}"
    );
    assert!(
        !responses.contains("challenge"),
        "成功路径不得出现 challenge 错误: {responses}"
    );

    let (code, stderr) = finish(&mut child);
    assert_eq!(
        code,
        Some(0),
        "完整握手 + EOF 须干净退出 0；stderr: {stderr}"
    );
    assert!(!path.exists(), "退出后 socket 文件须清理");

    // 父目录 0700（服务端自建）。
    let dir_mode = std::fs::metadata(path.parent().expect("parent"))
        .expect("parent dir must exist")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "父目录须 0700，实际 {dir_mode:o}");
}

/// challenge 回显错误 → initialize 被拒，工具面保持关闭（-32600「not verified」）。
#[test]
fn uds_wrong_challenge_rejected() {
    let path = uds_path("wrongch");
    let mut child = spawn_uds(&path);
    assert!(wait_for_socket(&path, Duration::from_secs(10)));

    let mut conn = UnixStream::connect(&path).expect("client must connect");
    send_line(
        &mut conn,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","{CHALLENGE_PARAM}":"wrong-echo"}}}}"#
        ),
    );
    send_line(
        &mut conn,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    );

    let responses = drain(&mut conn);
    drop(conn);
    assert!(
        responses.contains("challenge verification failed"),
        "initialize 回显错误须被拒: {responses}"
    );
    assert!(
        responses.contains("challenge not verified"),
        "工具面须保持关闭: {responses}"
    );

    let (code, stderr) = finish(&mut child);
    assert_eq!(
        code,
        Some(0),
        "challenge 拒绝是协议内响应 + EOF → 干净退出 0；stderr: {stderr}"
    );
    assert!(!path.exists(), "退出后 socket 文件须清理");
}

/// 非 spawn 方 PID → 连接被丢弃（客户端读到 EOF），进程干净退出 0。
#[test]
#[cfg(target_os = "macos")]
fn uds_non_spawner_peer_rejected() {
    let path = uds_path("peer");
    let mut child = Command::new(coffer_bin())
        .args(["mcp", "--provider", "op", "--uds"])
        .arg(&path)
        .env("COFFER_OP_BIN", fake_op())
        // 非本进程 PID → 须拒（docs/20 §3.6 ②）。
        .env("COFFER_MCP_UDS_PEER_PID", "999999999")
        .env("COFFER_MCP_UDS_CHALLENGE", CHALLENGE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn coffer with --uds");
    assert!(wait_for_socket(&path, Duration::from_secs(10)));

    let mut conn = UnixStream::connect(&path).expect("client must connect");
    send_line(
        &mut conn,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    );
    // 服务端 peer 校验失败 → 不服务、丢弃连接 → 客户端读到 EOF（空响应）。
    let mut responses = String::new();
    conn.shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");
    conn.read_to_string(&mut responses).expect("read responses");
    assert!(
        responses.is_empty(),
        "非 spawn 方不得获得任何协议响应: {responses:?}"
    );
    drop(conn);

    let (code, stderr) = finish(&mut child);
    assert_eq!(
        code,
        Some(0),
        "拒绝非 spawn 方是干净退出（连接生命周期完成），stderr: {stderr}"
    );
    assert!(!path.exists(), "退出后 socket 文件须清理");
}
