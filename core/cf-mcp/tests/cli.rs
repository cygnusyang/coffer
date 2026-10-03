//! `coffer mcp` CLI 集成测试（docs/20 §5，G-D）。
//!
//! 直接 spawn 编译产物 `coffer` 二进制（`env!("CARGO_BIN_EXE_coffer")`），以
//! fake `op` fixture 驱动 OpProvider（tests/fixtures/op/op），验证：
//!
//! - 参数解析（§5.2 冻结签名）：合法 flag / 未知 flag / 缺省值（env / 内置缺省）；
//! - provider 选择与退出码映射（§5.3）：0 干净 / 1 配置错误 / 3 身份缺失；
//! - `--vault` 传递：flag 覆盖 `$COFFER_OP_VAULT` 缺省；
//! - `--log PATH` 落文件、stdout 永为协议帧（§3.1）；
//! - stdio 生命周期冒烟（initialize → tools/list → tools/call → EOF → 干净退出）。
//!
//! 进程级环境变量隔离：每个子进程独立 env（`Command::env`），无跨用例污染。
//! fake op 的「未登录」哨兵 = `COFFER_FAKE_OP_EXPIRED_SESSION`（fixture 内定义）。

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, Command, Output, Stdio};
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

/// 每用例独立临时目录（tag 必唯一，规避 BUG-12 并行撞名）。
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "coffer-mcp-cli-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 以 fake op 运行 `coffer` 并收集完整输出（stdin 立即 EOF → 干净路径退出 0）。
fn run_coffer(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(coffer_bin());
    cmd.args(args)
        .env("COFFER_OP_BIN", fake_op())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run coffer binary")
}

/// 带协议交互的子进程句柄（stdio 双向管道）。
struct McpChild {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    stderr: ChildStderr,
}

impl McpChild {
    /// 写一行请求到 stdin。
    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").expect("write request to stdin");
        self.stdin.flush().expect("flush stdin");
    }

    /// 读一行 stdout 并解析为 JSON（stdout 永为协议帧 → 恒 JSON-RPC 2.0）。
    fn read_frame(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read stdout frame");
        assert!(
            !line.trim().is_empty(),
            "stdout must carry a protocol frame; got empty line"
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

    /// 关闭 stdin（EOF）→ 等待退出 → 返回 (退出码, stderr)。
    fn finish(mut self) -> (Option<i32>, String) {
        drop(self.stdin); // EOF → serve_stdio 干净返回
        let status = self.child.wait().expect("wait for coffer to exit");
        let mut stderr = String::new();
        self.stderr
            .read_to_string(&mut stderr)
            .expect("read stderr");
        (status.code(), stderr)
    }
}

/// 以 fake op + 协议管道 spawn `coffer mcp`。
fn spawn_mcp(args: &[&str]) -> McpChild {
    let mut cmd = Command::new(coffer_bin());
    cmd.args(args)
        .env("COFFER_OP_BIN", fake_op())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn coffer binary");
    McpChild {
        stdin: child.stdin.take().expect("stdin pipe"),
        stdout: BufReader::new(child.stdout.take().expect("stdout pipe")),
        stderr: child.stderr.take().expect("stderr pipe"),
        child,
    }
}

// ===========================================================================
// 参数解析（§5.2 冻结签名）
// ===========================================================================

#[test]
fn unknown_flag_exits_1_with_message() {
    let out = run_coffer(&["mcp", "--bogus"], &[]);
    assert_eq!(out.status.code(), Some(1), "未知 flag → §5.3 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown flag: --bogus"), "stderr: {stderr}");
}

#[test]
fn missing_subcommand_exits_1() {
    let out = run_coffer(&[], &[]);
    assert_eq!(out.status.code(), Some(1), "缺子命令 → 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("missing subcommand"), "stderr: {stderr}");
}

#[test]
fn unknown_subcommand_exits_1() {
    let out = run_coffer(&["list"], &[]);
    assert_eq!(out.status.code(), Some(1), "未知子命令 → 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown subcommand"), "stderr: {stderr}");
}

#[test]
fn missing_flag_value_exits_1() {
    let out = run_coffer(&["mcp", "--vault"], &[]);
    assert_eq!(out.status.code(), Some(1), "flag 缺值 → 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires a value"), "stderr: {stderr}");
}

#[test]
fn uds_flag_reports_unimplemented_exit_1() {
    // D-4 暂缓：本版只支持 stdio；`--uds` 传入须报错退出 1 并注明未实现。
    let out = run_coffer(&["mcp", "--uds", "/tmp/coffer-test.sock"], &[]);
    assert_eq!(out.status.code(), Some(1), "--uds（D-4）→ §5.3 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not implemented"),
        "须注明未实现，stderr: {stderr}"
    );
}

// ===========================================================================
// provider 选择（§5.2 / §4.3）
// ===========================================================================

#[test]
fn provider_unavailable_exits_1() {
    let missing = std::env::temp_dir().join("definitely-not-an-op-binary-xyz");
    let out = run_coffer(&["mcp"], &[("COFFER_OP_BIN", missing.to_str().unwrap())]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "provider 不可用（7001）→ 退出码 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("provider unavailable") || stderr.contains("7001"),
        "stderr: {stderr}"
    );
}

#[test]
fn unsupported_provider_exits_1() {
    let out = run_coffer(&["mcp", "--provider", "coffer"], &[]);
    assert_eq!(out.status.code(), Some(1), "非 op provider → 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported provider"), "stderr: {stderr}");
}

#[test]
fn provider_defaults_from_env_when_flag_absent() {
    let out = run_coffer(&["mcp"], &[("COFFER_MCP_PROVIDER", "op")]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "缺省 provider=op（env）→ 干净退出"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("provider=op"), "stderr: {stderr}");
}

// ===========================================================================
// 退出码映射（§5.3）
// ===========================================================================

#[test]
fn identity_missing_exits_3() {
    // fake op 在 OP_SESSION == 哨兵值时按「账号未登录」失败 → 7002 → 退出码 3。
    let out = run_coffer(
        &["mcp"],
        &[("COFFER_OP_SESSION_TOKEN", FAKE_OP_EXPIRED_SESSION)],
    );
    assert_eq!(out.status.code(), Some(3), "身份缺失（7002）→ 退出码 3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("identity missing") || stderr.contains("7002"),
        "stderr: {stderr}"
    );
}

// ===========================================================================
// --vault 传递（§5.2）
// ===========================================================================

#[test]
fn vault_flag_is_used_for_provider() {
    let out = run_coffer(&["mcp", "--vault", "Personal"], &[]);
    assert_eq!(out.status.code(), Some(0), "合法 vault → 干净退出");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("vault=Personal"),
        "启动日志须反映 --vault，stderr: {stderr}"
    );
}

#[test]
fn vault_defaults_to_env_when_flag_absent() {
    let out = run_coffer(&["mcp"], &[("COFFER_OP_VAULT", "Personal")]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("vault=Personal"),
        "$COFFER_OP_VAULT 缺省须生效，stderr: {stderr}"
    );
}

#[test]
fn vault_flag_overrides_env_default() {
    let out = run_coffer(
        &["mcp", "--vault", "Personal"],
        &[("COFFER_OP_VAULT", "OtherVault")],
    );
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("vault=Personal"),
        "--vault 须覆盖 env 缺省，stderr: {stderr}"
    );
    assert!(
        !stderr.contains("OtherVault"),
        "env 缺省 vault 不得在 --vault 给定时生效，stderr: {stderr}"
    );
}

// ===========================================================================
// --no-audit 与 --log（§5.2 / §3.1）
// ===========================================================================

#[test]
fn no_audit_flag_is_observable() {
    let out = run_coffer(&["mcp", "--no-audit"], &[]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("audit: off"),
        "--no-audit 须在日志可见，stderr: {stderr}"
    );
}

#[test]
fn log_flag_writes_to_file_not_stderr() {
    let dir = temp_dir("logfile");
    let log_path = dir.join("coffer.log");
    let out = run_coffer(&["mcp", "--log", log_path.to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(0));
    // stdout 永为协议帧、日志只去 --log 文件（§3.1）：stderr 不应再含运行时日志。
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("serving on stdio"),
        "--log 时运行时日志落文件，stderr 不应出现，stderr: {stderr}"
    );
    let content = std::fs::read_to_string(&log_path).expect("read log file");
    assert!(
        content.contains("serving on stdio"),
        "log 文件须捕获启动日志，content: {content:?}"
    );
}

// ===========================================================================
// stdio 生命周期冒烟（§3.2 / §5.3 干净退出）
// ===========================================================================

#[test]
fn stdio_lifecycle_initialize_list_call_and_clean_exit() {
    let mut c = spawn_mcp(&["mcp"]);

    // initialize → 协议版本 + capabilities + serverInfo
    c.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#);
    let init = c.read_frame();
    assert_eq!(init["id"], json!(1));
    assert!(init["result"]["protocolVersion"].is_string());
    assert_eq!(init["result"]["serverInfo"]["name"], json!("coffer"));

    // notifications/initialized 无响应（不读帧）
    c.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);

    // tools/list → MVP 4 工具
    c.send(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    let list = c.read_frame();
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 4, "MVP 只注册 4 工具（docs/20 §3.3）");

    // tools/call list_secret_names → fake op fixture 数据
    c.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_secret_names","arguments":{}}}"#);
    let call = c.read_frame();
    assert_eq!(call["id"], json!(3));
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("content text");
    assert!(
        text.contains("OPENAI_API_KEY"),
        "fixture 名须出现在 list，got {text}"
    );

    // EOF → 干净退出 0；默认日志落 stderr
    let (code, stderr) = c.finish();
    assert_eq!(code, Some(0), "EOF 干净退出 → §5.3 退出码 0");
    assert!(
        stderr.contains("serving on stdio"),
        "默认日志落 stderr，stderr: {stderr}"
    );
}

#[test]
fn run_with_secret_works_end_to_end_through_stdio() {
    // 全栈冒烟：协议帧 → 工具分发 → OpProvider → fake op 注入值到子进程 env。
    let mut c = spawn_mcp(&["mcp"]);
    c.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#);
    let _ = c.read_frame();
    c.send(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_with_secret","arguments":{"secret":"op://Personal/OPENAI_API_KEY/password","env_name":"MY_KEY","cmd":"sh","args":["-c","test \"$MY_KEY\" = \"fixture-secret-value-openai\""]}}}"#,
    );
    let call = c.read_frame();
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .expect("content text");
    assert!(
        text.contains("\"exit_code\":0"),
        "子进程验证注入值后须退出 0，got {text}"
    );
    let (code, _stderr) = c.finish();
    assert_eq!(code, Some(0), "stdio 生命周期结束须干净退出");
}
