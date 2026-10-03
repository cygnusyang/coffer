//! MCP 端到端验收（docs/20 §3 / §5，G-G）。
//!
//! 直接 spawn 编译产物 `coffer` 二进制（`env!("CARGO_BIN_EXE_coffer")`），以
//! fake `op` fixture（tests/fixtures/op/op）驱动完整 stdio 生命周期。判据按
//! docs/20-MCP设计.md：
//!
//! - §3.1 传输：**stdout 永为协议帧**——首帧是 JSON-RPC 2.0（`"jsonrpc":"2.0"`），
//!   每帧换行分隔、可解析；日志只走 stderr / `--log`；
//! - §3.2 生命周期：initialize → notifications/initialized → tools/list →
//!   tools/call → EOF → 干净退出；
//! - §3.3 工具往返：返回**脱敏后的 Secret 元数据**（无明文值；明文值
//!   结构性不进帧，§3.5-1，本文件以 fixture 明文值不存在于整段 stdout 断言）；
//! - §5.2 / §5.3 CLI 签名与退出码：0 干净 EOF / 1 未知 flag、非法 `--provider`、
//!   `--uds` 未实现（D-4）/ 3 身份缺失（7002，fake op 过期会话哨兵）；
//! - §5.2 `--vault` 覆盖 env 缺省、`--no-audit` 接受、`--log` 落文件且 stderr
//!   无协议帧；
//! - 进程清理：spawn 的子进程在 drop 前 kill / wait——断言已被回收（无残留、无僵尸）。
//!
//! 与 `tests/cli.rs`（G-D 签名面）区分：本文件是**验收面**，按 docs/20 §3/§5 判据
//! 逐条断言协议帧内容与退出码语义，而非参数解析细节。
//!
//! 进程级环境变量隔离：每个子进程独立 env（`Command::env`），无跨用例污染。
//! fake op 的「未登录」哨兵 = `COFFER_FAKE_OP_EXPIRED_SESSION`（fixture 内定义）。

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// 编译产物 `coffer` 二进制绝对路径（cargo 在集成测试构建期注入）。
fn coffer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_coffer")
}

/// fake `op` 脚本绝对路径。
fn fake_op() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/op/op")
}

/// fake op 的「未登录」哨兵（tests/fixtures/op/op 内定义）。
const FAKE_OP_EXPIRED_SESSION: &str = "COFFER_FAKE_OP_EXPIRED_SESSION";

/// fake op fixture 的明文值（tests/fixtures/op/op 内定义）。验收断言：整段 stdout
/// **不得出现**这些明文（§3.5-1 结构性保证——list/meta 无值；run 值只进子进程 env）。
const PLAINTEXT_OPENAI: &str = "fixture-secret-value-openai";
const PLAINTEXT_GITHUB: &str = "fixture-secret-value-github";

/// 每用例独立临时目录（tag 必唯一，规避 BUG-12 并行撞名）。
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "coffer-mcp-acc-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 带协议交互的 `coffer mcp` 子进程句柄（stdio 双向管道）。
///
/// `Drop` 兜底清理（进程纪律）：stdin 未关先关（防阻塞），子进程未退出则
/// `kill` + `wait`——保证任何测试路径（含 panic）都不残留子进程 / 僵尸。
struct CofferChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    stderr: ChildStderr,
}

impl CofferChild {
    /// 写一行请求到 stdin。
    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        writeln!(stdin, "{line}").expect("write request to stdin");
        stdin.flush().expect("flush stdin");
    }

    /// 读一行 stdout 并解析为 JSON-RPC 2.0 帧。
    ///
    /// 判据 §3.1：stdout 永为协议帧——每行须非空、可解析、`jsonrpc` == `"2.0"`。
    fn read_frame(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read stdout frame");
        assert!(
            !line.trim().is_empty(),
            "stdout must carry a protocol frame; got empty line (child may have exited)"
        );
        let v: Value = serde_json::from_str(line.trim())
            .unwrap_or_else(|e| panic!("stdout must be pure JSON-RPC frames, got {line:?}: {e}"));
        assert_eq!(
            v["jsonrpc"],
            json!("2.0"),
            "stdout frame must be JSON-RPC 2.0"
        );
        v
    }

    /// 读 stdout 剩余全部内容（stdin 已关后调用；判据 §3.1 stdout 无日志噪声）。
    fn read_remaining_stdout(&mut self) -> String {
        let mut out = String::new();
        self.stdout
            .read_to_string(&mut out)
            .expect("read stdout to EOF");
        out
    }

    /// 关闭 stdin（EOF → serve_stdio 干净返回）。
    fn close_stdin(&mut self) {
        if let Some(stdin) = self.stdin.take() {
            drop(stdin);
        }
    }

    /// 显式终止子进程（kill + wait 回收；退出码应为 None——信号终止）。
    fn kill(&mut self) {
        self.close_stdin();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// 关闭 stdin（EOF）→ 等待退出 → 返回 `(退出码, stderr)`。
    fn finish(mut self) -> (Option<i32>, String) {
        self.close_stdin();
        let status = self.child.wait().expect("wait for coffer to exit");
        let mut stderr = String::new();
        self.stderr
            .read_to_string(&mut stderr)
            .expect("read stderr");
        (status.code(), stderr)
    }
}

impl Drop for CofferChild {
    /// 兜底清理：stdin 未关先关；子进程未退出则 kill + wait。
    /// 已 `finish` / `kill`（wait 过）时 `try_wait` 返回 `Some` → 无操作。
    fn drop(&mut self) {
        self.close_stdin();
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

/// 以 fake op + 协议管道 spawn `coffer mcp`。
fn spawn_mcp(args: &[&str], envs: &[(&str, &str)]) -> CofferChild {
    let mut cmd = Command::new(coffer_bin());
    cmd.args(args)
        .env("COFFER_OP_BIN", fake_op())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn coffer binary");
    CofferChild {
        stdin: Some(child.stdin.take().expect("stdin pipe")),
        stdout: BufReader::new(child.stdout.take().expect("stdout pipe")),
        stderr: child.stderr.take().expect("stderr pipe"),
        child,
    }
}

/// 非交互路径（无协议往返）：spawn → 立即 EOF → 返回 `(退出码, stderr)`。
fn run_coffer(args: &[&str], envs: &[(&str, &str)]) -> (Option<i32>, String) {
    let mut c = spawn_mcp(args, envs);
    c.close_stdin();
    let status = c.child.wait().expect("wait for coffer to exit");
    let mut stderr = String::new();
    c.stderr.read_to_string(&mut stderr).expect("read stderr");
    (status.code(), stderr)
}

/// pid 是否仍存活（`kill -0`；kill 工具不可用时保守判「不活」，不误报残留）。
fn pid_alive(pid: u32) -> bool {
    match Command::new("kill").arg("-0").arg(pid.to_string()).status() {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

/// 标准 initialize 请求（§3.2 生命周期首步）。
fn initialize_request() -> &'static str {
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#
}

// ===========================================================================
// §3.1 / §3.2：握手与传输纪律
// ===========================================================================

#[test]
fn initialize_handshake_first_frame_is_protocol_frame() {
    let mut c = spawn_mcp(&["mcp"], &[]);

    c.send(initialize_request());
    let init = c.read_frame();

    // 首帧即协议帧：jsonrpc 2.0（read_frame 已断言）+ initialize 结果契约（§3.2）。
    assert_eq!(init["id"], json!(1));
    assert_eq!(
        init["result"]["protocolVersion"],
        json!("2024-11-05"),
        "initialize 须回显 MCP 协议版本"
    );
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "capabilities.tools"
    );
    assert_eq!(init["result"]["serverInfo"]["name"], json!("coffer"));

    // notifications/initialized 无响应（§3.2）；随后 EOF → 干净退出 0（§5.3）。
    c.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    let (code, stderr) = c.finish();
    assert_eq!(code, Some(0), "EOF 干净退出 → §5.3 退出码 0");
    assert!(
        stderr.contains("serving on stdio"),
        "默认日志落 stderr，stderr: {stderr}"
    );
}

#[test]
fn stdout_carries_only_protocol_frames_across_lifecycle() {
    // 全生命周期逐帧断言 stdout 恒为 JSON-RPC 2.0（read_frame 内建），
    // 并核对 stdout 无日志噪声（[INFO]/[WARN] 只去 stderr/--log，§3.1）。
    let mut c = spawn_mcp(&["mcp"], &[]);

    c.send(initialize_request());
    let _ = c.read_frame();
    c.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    c.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    let _ = c.read_frame();
    c.send(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_secret_names","arguments":{}}}"#,
    );
    let _ = c.read_frame();

    c.close_stdin();
    let rest = c.read_remaining_stdout();
    assert!(
        !rest.contains("[INFO]") && !rest.contains("[WARN]"),
        "stdout 不得含日志行（§3.1），got: {rest:?}"
    );
    let (code, _stderr) = c.finish();
    assert_eq!(code, Some(0), "生命周期结束须干净退出");
}

// ===========================================================================
// §3.3：工具往返与脱敏（无明文值）
// ===========================================================================

#[test]
fn tools_list_and_call_roundtrip_redacted_metadata_no_plaintext() {
    let mut c = spawn_mcp(&["mcp"], &[]);
    c.send(initialize_request());
    let _ = c.read_frame();

    // tools/list → MVP 4 工具（§3.3），名字齐全、schema 存在。
    c.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    let list = c.read_frame();
    let tools = list["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expect in [
        "list_secret_names",
        "list_secrets",
        "run_with_secret",
        "get_secret_metadata",
    ] {
        assert!(
            names.contains(&expect),
            "工具 {expect} 须在 tools/list 中，got {names:?}"
        );
    }
    assert!(
        tools.iter().all(|t| t["inputSchema"].is_object()),
        "每个工具须带 inputSchema（§3.3）"
    );

    // tools/call list_secrets → 元数据（name/id/category/vault/updated_at），无值。
    c.send(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_secrets","arguments":{}}}"#,
    );
    let call = c.read_frame();
    assert_eq!(call["id"], json!(3));
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("content text");
    let parsed = serde_json::from_str::<Value>(text).expect("list_secrets text 须为 JSON");
    let secrets = parsed
        .get("secrets")
        .and_then(Value::as_array)
        .expect("secrets array");
    assert_eq!(
        secrets.len(),
        2,
        "fake op fixture 两条元数据，got {secrets:?}"
    );
    let first = &secrets[0];
    for key in ["name", "id", "category", "vault", "updated_at"] {
        assert!(
            first.get(key).is_some(),
            "元数据须含 {key} 键，got {first:?}"
        );
    }
    let names_in_meta: Vec<&str> = secrets.iter().filter_map(|s| s["name"].as_str()).collect();
    assert!(
        names_in_meta.contains(&"OPENAI_API_KEY") && names_in_meta.contains(&"GITHUB_TOKEN"),
        "fixture 名须出现在元数据，got {names_in_meta:?}"
    );
    assert!(
        !text.contains(PLAINTEXT_OPENAI) && !text.contains(PLAINTEXT_GITHUB),
        "list_secrets 元数据不得含明文值（§3.5-1），got {text:?}"
    );

    // tools/call run_with_secret → 值只进子进程 env（§4.4）；协议面只见退出码。
    c.send(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secret":"op://Personal/OPENAI_API_KEY/password","env_name":"OPENAI_API_KEY","cmd":"sh","args":["-c","test \"$OPENAI_API_KEY\" = \"fixture-secret-value-openai\""]}}}"#,
    );
    let run = c.read_frame();
    let run_text = run["result"]["content"][0]["text"]
        .as_str()
        .expect("run content text");
    assert!(
        run_text.contains("\"exit_code\":0"),
        "注入验证通过须退出 0，got {run_text:?}"
    );

    // 全段 stdout 无明文（§3.5-1 结构性保证）。
    c.close_stdin();
    let all_stdout = c.read_remaining_stdout();
    assert!(
        !all_stdout.contains(PLAINTEXT_OPENAI) && !all_stdout.contains(PLAINTEXT_GITHUB),
        "stdout 不得出现 fixture 明文值（§3.5-1），got: {all_stdout:?}"
    );

    let (code, _stderr) = c.finish();
    assert_eq!(code, Some(0), "生命周期结束须干净退出");
}

#[test]
fn get_secret_metadata_never_contains_secret_value() {
    // AS-14 可用不可见（usable without visible）：get_secret_metadata 只回元数据。
    let mut c = spawn_mcp(&["mcp"], &[]);
    c.send(initialize_request());
    let _ = c.read_frame();
    c.send(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_secret_metadata","arguments":{"secret":"op://Personal/OPENAI_API_KEY/password"}}}"#,
    );
    let call = c.read_frame();
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("content text");
    let meta = serde_json::from_str::<Value>(text).expect("meta 须为 JSON");
    assert_eq!(meta["name"], json!("OPENAI_API_KEY"));
    assert_eq!(meta["category"], json!("LOGIN"));
    assert!(
        !text.contains(PLAINTEXT_OPENAI),
        "元数据不得含明文（AS-14），got {text:?}"
    );
    let (code, _stderr) = c.finish();
    assert_eq!(code, Some(0));
}

// ===========================================================================
// §5.3：退出码
// ===========================================================================

#[test]
fn clean_eof_exits_0() {
    let (code, stderr) = run_coffer(&["mcp"], &[]);
    assert_eq!(code, Some(0), "干净 EOF → §5.3 退出码 0，stderr: {stderr}");
}

#[test]
fn unknown_flag_exits_1() {
    let (code, stderr) = run_coffer(&["mcp", "--bogus"], &[]);
    assert_eq!(code, Some(1), "未知 flag → §5.3 退出码 1");
    assert!(stderr.contains("unknown flag"), "stderr: {stderr}");
}

#[test]
fn illegal_provider_exits_1() {
    // 非法 `--provider`（非 `op`）→ 配置错误退出 1（§5.2 MVP 恒 `op`）。
    let (code, stderr) = run_coffer(&["mcp", "--provider", "coffer"], &[]);
    assert_eq!(code, Some(1), "非法 --provider → 退出码 1");
    assert!(stderr.contains("unsupported provider"), "stderr: {stderr}");
}

#[test]
fn uds_unimplemented_exits_1() {
    // D-4 暂缓：`--uds` 传入 → 配置错误退出 1，注明未实现（§3.1 / §5.2）。
    let (code, stderr) = run_coffer(&["mcp", "--uds", "/tmp/coffer-acc.sock"], &[]);
    assert_eq!(code, Some(1), "--uds（D-4）→ 退出码 1");
    assert!(stderr.contains("not implemented"), "stderr: {stderr}");
}

#[test]
fn identity_missing_exits_3() {
    // fake op 在 OP_SESSION == 哨兵值时按「账号未登录」失败 → 7002 → 退出码 3（§5.3）。
    let (code, stderr) = run_coffer(
        &["mcp"],
        &[("COFFER_OP_SESSION_TOKEN", FAKE_OP_EXPIRED_SESSION)],
    );
    assert_eq!(
        code,
        Some(3),
        "身份缺失（7002）→ 退出码 3，stderr: {stderr}"
    );
    assert!(
        stderr.contains("identity missing") || stderr.contains("7002"),
        "stderr: {stderr}"
    );
}

// ===========================================================================
// §5.2：--vault / --no-audit / --log
// ===========================================================================

#[test]
fn vault_flag_overrides_env_default() {
    let mut c = spawn_mcp(
        &["mcp", "--vault", "Personal"],
        &[("COFFER_OP_VAULT", "OtherVault")],
    );
    c.send(initialize_request());
    let _ = c.read_frame();
    let (code, stderr) = c.finish();
    assert_eq!(code, Some(0));
    assert!(
        stderr.contains("vault=Personal"),
        "--vault 须生效，stderr: {stderr}"
    );
    assert!(
        !stderr.contains("vault=OtherVault"),
        "env 缺省 vault 不得在 --vault 给定时生效，stderr: {stderr}"
    );
}

#[test]
fn no_audit_flag_accepted() {
    let mut c = spawn_mcp(&["mcp", "--no-audit"], &[]);
    c.send(initialize_request());
    let _ = c.read_frame();
    let (code, stderr) = c.finish();
    assert_eq!(code, Some(0), "--no-audit 为合法 flag，stderr: {stderr}");
    assert!(
        stderr.contains("audit: off"),
        "--no-audit 须在日志可见，stderr: {stderr}"
    );
}

#[test]
fn log_flag_writes_to_file_and_stderr_has_no_protocol_frames() {
    let dir = temp_dir("logfile");
    let log_path = dir.join("coffer-acc.log");

    let mut c = spawn_mcp(&["mcp", "--log", log_path.to_str().unwrap()], &[]);
    c.send(initialize_request());
    let _ = c.read_frame();
    let (code, stderr) = c.finish();
    assert_eq!(code, Some(0));

    // §3.1：--log 时日志落文件；stderr 不再含运行时日志，且不得出现协议帧标记。
    assert!(
        !stderr.contains("serving on stdio"),
        "--log 时运行时日志落文件，stderr 不应出现，stderr: {stderr}"
    );
    assert!(
        !stderr.contains("\"jsonrpc\""),
        "stderr 不得含协议帧（§3.1），stderr: {stderr}"
    );
    let content = std::fs::read_to_string(&log_path).expect("read log file");
    assert!(
        content.contains("serving on stdio"),
        "log 文件须捕获启动日志，content: {content:?}"
    );
}

// ===========================================================================
// 进程清理：子进程无残留（drop 前 kill / wait）
// ===========================================================================

#[test]
fn child_process_is_reaped_no_leftover() {
    let mut c = spawn_mcp(&["mcp"], &[]);
    let pid = c.child.id();
    c.send(initialize_request());
    let _ = c.read_frame();

    // 显式 kill + wait 回收；wait 后 try_wait 须为 Some（进程已回收，无僵尸残留）。
    c.kill();
    assert!(
        c.child.try_wait().expect("try_wait").is_some(),
        "已 wait → 进程已回收，无残留"
    );
    assert!(!pid_alive(pid), "pid {pid} 应已退出，不得残留");
}

#[test]
fn drop_cleans_up_child_without_explicit_finish() {
    // 不调 finish/kill，直接 drop：Drop 兜底须 kill + wait，无残留（进程纪律）。
    let pid = {
        let mut c = spawn_mcp(&["mcp"], &[]);
        c.send(initialize_request());
        let _ = c.read_frame();
        c.child.id()
    };
    assert!(!pid_alive(pid), "Drop 后 pid {pid} 应已退出，不得残留");
}
