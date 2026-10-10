//! `coffer mcp` CLI 集成测试（docs/20 §5，G-D；docs/27 D-2 缺省翻转）。
//!
//! 直接 spawn 编译产物 `coffer` 二进制（`env!("CARGO_BIN_EXE_coffer")`），以
//! fake `op` fixture 驱动 OpProvider（tests/fixtures/op/op），验证：
//!
//! - 参数解析（§5.2 冻结签名）：合法 flag / 未知 flag / 缺省值（env / 内置缺省）；
//! - provider 选择与退出码映射（§5.3）：0 干净 / 1 配置错误 / 3 身份缺失；
//!   **缺省 provider = coffer**（D-2，docs/27）：op 路径用例显式 `--provider op`
//!   隔离「op 行为不变」的 D-1 冻结面；
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
fn uds_requires_handshake_env_exits_1() {
    // v2.1.0 D-4（docs/27）：--uds 已实现；但 spawn 方须经 env 下发会话
    // challenge（docs/20 §3.6 ③）——缺 → fail-closed 配置错误退出 1，消息可操作。
    let out = run_coffer(
        &["mcp", "--provider", "op", "--uds", "/tmp/coffer-test.sock"],
        &[],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "--uds 缺 challenge env → 退出码 1（fail-closed）"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("COFFER_MCP_UDS_CHALLENGE"),
        "须指明缺失的握手 env，stderr: {stderr}"
    );
}

// ===========================================================================
// provider 选择（§5.2 / §4.3）
// ===========================================================================

#[test]
fn provider_unavailable_exits_1() {
    // 显式 `--provider op`：缺省已翻转为 coffer（D-2），本用例专测 op 不可用面。
    let missing = std::env::temp_dir().join("definitely-not-an-op-binary-xyz");
    let out = run_coffer(
        &["mcp", "--provider", "op"],
        &[("COFFER_OP_BIN", missing.to_str().unwrap())],
    );
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
    // 注意：`coffer` 在 `coffer-store` feature 下是合法 provider（G-D），
    // 故这里用恒不存在的 `nosuch` 验证「未知 provider → 退出码 1」。
    let out = run_coffer(&["mcp", "--provider", "nosuch"], &[]);
    assert_eq!(out.status.code(), Some(1), "未知 provider → 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported provider"), "stderr: {stderr}");
}

#[test]
fn provider_defaults_from_env_when_flag_absent() {
    // env 显式选择 op（D-2 缺省已翻转 coffer；env 给定即显式，非内置缺省）。
    let out = run_coffer(&["mcp"], &[("COFFER_MCP_PROVIDER", "op")]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "env 显式 provider=op → 干净退出"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("provider=op"), "stderr: {stderr}");
}

// ===========================================================================
// CofferStoreProvider 选择（docs/20 §4.5；feature `coffer-store` 门控）
// ===========================================================================

#[cfg(not(feature = "coffer-store"))]
#[test]
fn coffer_provider_unsupported_when_feature_off() {
    // 未启用 `coffer-store`：`--provider coffer` 同任意未知 provider → 退出 1
    // （与接线前行为一致；启用后此分支不再编译，见下方 feature 用例）。
    let out = run_coffer(&["mcp", "--provider", "coffer"], &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "feature 关闭 → coffer 不可选 → 退出码 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported provider"), "stderr: {stderr}");
}

/// 建一个独立快速档测试库（cf-session 快速 KDF / cf-crypto KdfParams；与
/// provider/coffer.rs 内测同款），返回 (库目录, 解锁密码)。
#[cfg(feature = "coffer-store")]
fn create_fast_vault(tag: &str) -> (PathBuf, String) {
    use cf_crypto::kdf::KdfParams;
    use cf_session::create_vault_with_kdf;

    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(
        &base,
        "测试库",
        STRONG_PASSWORD,
        KdfParams::new(8 * 1024, 1, 1).expect("8 MiB fast KDF params"),
    )
    .expect("create fast test vault");
    let vault_dir = base.join(brief.uuid.to_string());
    (vault_dir, STRONG_PASSWORD.to_string())
}

#[cfg(feature = "coffer-store")]
#[test]
fn coffer_provider_serves_on_stdio_with_valid_vault() {
    let (vault_dir, password) = create_fast_vault("cli-coffer-serve");
    let out = run_coffer(
        &["mcp", "--provider", "coffer"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &password),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "合法库 + 正确密码 → 干净退出 0（provider 构造成功并服务）"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("provider=coffer"), "stderr: {stderr}");
    assert!(
        !stderr.contains(&password),
        "密码不得出现在日志（§3.5-4 载荷纪律），stderr: {stderr}"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn coffer_provider_missing_env_config_exits_1() {
    // 缺 $COFFER_VAULT_DIR / $COFFER_VAULT_PASSWORD → 配置错误退出 1，消息可操作。
    let out = run_coffer(&["mcp", "--provider", "coffer"], &[]);
    assert_eq!(out.status.code(), Some(1), "缺库配置 → 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("COFFER_VAULT_DIR") || stderr.contains("COFFER_VAULT_PASSWORD"),
        "错误消息须指明缺失的 env 变量，stderr: {stderr}"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn coffer_provider_vault_dir_missing_exits_1() {
    let dir = temp_dir("cli-coffer-missing");
    let missing = dir.join("no-such-vault");
    let out = run_coffer(
        &["mcp", "--provider", "coffer"],
        &[
            ("COFFER_VAULT_DIR", missing.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", "correct-horse-battery-staple-42!"),
        ],
    );
    assert_eq!(out.status.code(), Some(1), "库目录缺失（7001）→ 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("provider unavailable") || stderr.contains("7001"),
        "stderr: {stderr}"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn coffer_provider_wrong_password_exits_3() {
    let (vault_dir, _password) = create_fast_vault("cli-coffer-wrongpw");
    let out = run_coffer(
        &["mcp", "--provider", "coffer"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", "wrong-password"),
        ],
    );
    assert_eq!(out.status.code(), Some(3), "解锁失败（7002）→ 退出码 3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("identity missing") || stderr.contains("7002"),
        "stderr: {stderr}"
    );
}

// ===========================================================================
// D-2 缺省 provider = coffer（docs/27 D-2；无 --provider 且无
// $COFFER_MCP_PROVIDER → coffer；feature 关闭时回落 op / 不可用退出 1）
// ===========================================================================

#[cfg(feature = "coffer-store")]
#[test]
fn default_provider_is_coffer_missing_env_config_exits_1() {
    // 缺省（无 --provider / 无 $COFFER_MCP_PROVIDER）→ coffer：缺库配置 →
    // 配置错误退出 1，消息可操作（D-2 翻转后的缺省面）。
    let out = run_coffer(&["mcp"], &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "缺省 coffer 缺库配置 → 退出码 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("COFFER_VAULT_DIR") || stderr.contains("COFFER_VAULT_PASSWORD"),
        "缺省 coffer 路径错误消息须指明缺失 env，stderr: {stderr}"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn default_provider_serves_coffer_with_valid_vault() {
    let (vault_dir, password) = create_fast_vault("cli-default-coffer");
    let out = run_coffer(
        &["mcp"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &password),
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "缺省 coffer + 合法库 → 干净退出 0"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("provider=coffer"), "stderr: {stderr}");
}

#[cfg(not(feature = "coffer-store"))]
#[test]
fn default_provider_falls_back_to_op_when_coffer_off() {
    // feature 关闭构建下缺省 coffer 不可用 → 回落 op（op 可用则 op），日志告警。
    let out = run_coffer(&["mcp"], &[]);
    assert_eq!(out.status.code(), Some(0), "回落 op → 干净退出 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("defaulting to `op`"),
        "须日志告警回落 op，stderr: {stderr}"
    );
    assert!(
        stderr.contains("provider=op"),
        "实际 provider 须为 op: {stderr}"
    );
}

#[cfg(not(feature = "coffer-store"))]
#[test]
fn default_provider_exits_1_when_coffer_off_and_op_unavailable() {
    // op 亦不可用 → 7001 退出 1（D-1 退出码契约不破坏，非 panic/挂死）。
    let missing = std::env::temp_dir().join("definitely-not-an-op-binary-xyz");
    let out = run_coffer(&["mcp"], &[("COFFER_OP_BIN", missing.to_str().unwrap())]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "缺省 coffer 不可用 + op 不可用 → 退出码 1（7001）"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("provider unavailable") || stderr.contains("7001"),
        "stderr: {stderr}"
    );
}

#[cfg(not(feature = "coffer-store"))]
#[test]
fn explicit_env_coffer_unsupported_when_feature_off() {
    // env 显式 coffer（非内置缺省）→ 同任意未知 provider → 退出 1（D-1）。
    let out = run_coffer(&["mcp"], &[("COFFER_MCP_PROVIDER", "coffer")]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "feature 关闭 + env 显式 coffer → 退出码 1（unsupported）"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsupported provider"), "stderr: {stderr}");
}

// ===========================================================================
// 退出码映射（§5.3）
// ===========================================================================

#[test]
fn identity_missing_exits_3() {
    // fake op 在 OP_SESSION == 哨兵值时按「账号未登录」失败 → 7002 → 退出码 3。
    // 显式 `--provider op`（缺省已翻转 coffer，D-2）。
    let out = run_coffer(
        &["mcp", "--provider", "op"],
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
    // 显式 `--provider op`：`--vault` 是 op 侧参数（D-2 缺省已翻转 coffer）。
    let out = run_coffer(&["mcp", "--provider", "op", "--vault", "Personal"], &[]);
    assert_eq!(out.status.code(), Some(0), "合法 vault → 干净退出");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("vault=Personal"),
        "启动日志须反映 --vault，stderr: {stderr}"
    );
}

#[test]
fn vault_defaults_to_env_when_flag_absent() {
    let out = run_coffer(
        &["mcp", "--provider", "op"],
        &[("COFFER_OP_VAULT", "Personal")],
    );
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
        &["mcp", "--provider", "op", "--vault", "Personal"],
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
    let out = run_coffer(&["mcp", "--provider", "op", "--no-audit"], &[]);
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
    let out = run_coffer(
        &[
            "mcp",
            "--provider",
            "op",
            "--log",
            log_path.to_str().unwrap(),
        ],
        &[],
    );
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
    // 显式 `--provider op`：本用例是 D-1 冻结面冒烟（op 路径，D-2 缺省已翻转）。
    let mut c = spawn_mcp(&["mcp", "--provider", "op"]);

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
    let mut c = spawn_mcp(&["mcp", "--provider", "op"]);
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

// ------------------------------------------------------------ set-password（docs/34 §5，FR-18.2）

/// 带 stdin 载荷运行 `coffer`（写入后关闭 stdin 触发 EOF），收集完整输出。
#[cfg(feature = "coffer-store")]
fn run_coffer_with_stdin(args: &[&str], envs: &[(&str, &str)], stdin: &str) -> Output {
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
    {
        let mut si = child.stdin.take().expect("stdin pipe");
        si.write_all(stdin.as_bytes())
            .expect("write stdin payload");
    }
    child.wait_with_output().expect("collect output")
}

/// 快速档库 + 解锁会话，返回 (库目录, 解锁密码, 会话)。
#[cfg(feature = "coffer-store")]
fn fast_vault_setup(tag: &str) -> (PathBuf, String, cf_session::VaultSession) {
    let (vault_dir, pw) = create_fast_vault(tag);
    let s = cf_session::open_vault(&vault_dir).expect("open vault");
    s.unlock(&pw).expect("unlock vault");
    (vault_dir, pw, s)
}

/// 建一个带密码字段的 Login 条目，返回 uuid。
#[cfg(feature = "coffer-store")]
fn create_login_item_in(session: &cf_session::VaultSession, title: &str) -> String {
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::{FieldDraft, ItemDraft};
    let mut d = ItemDraft {
        title: title.to_string(),
        category: ItemCategory::Login,
        urls: Vec::new(),
        tags: Vec::new(),
        sections: Vec::new(),
        fields: vec![FieldDraft {
            name: "username".to_string(),
            value: Some("octocat".to_string()),
            field_type: FieldType::Text,
            designation: Some(Designation::Username),
            section_index: None,
            position: 0,
        }],
        totp: None,
    };
    d.fields.push(FieldDraft {
        name: "password".to_string(),
        value: Some("old-secret".to_string()),
        field_type: FieldType::Concealed,
        designation: Some(Designation::Password),
        section_index: None,
        position: 1,
    });
    session.create_item(&d).expect("create login item")
}

/// 重新开库，读取指定条目的密码字段值（None = 无密码字段）。
#[cfg(feature = "coffer-store")]
fn item_password_value(vault_dir: &std::path::Path, password: &str, item_id: &str) -> Option<String> {
    use cf_domain::field::Designation;
    let s = cf_session::open_vault(vault_dir).expect("reopen vault");
    s.unlock(password).expect("unlock vault");
    let d = s
        .get_item(item_id)
        .expect("get item")
        .expect("item exists");
    d.fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
}

/// 测试用新密码：强度 ≥ 强（zxcvbn ≥ 3），且与库密码 / 旧密码区分。
const NEW_PW: &str = "Correct-Horse-Battery-Staple-2026-XyZ!";

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_success_updates_item_and_appends_history() {
    use cf_domain::field::Designation;
    let (vault_dir, pw, s) = fast_vault_setup("setpw-ok");
    let id = create_login_item_in(&s, "GitHub");
    drop(s); // 先关会话再 spawn 子进程，避免句柄竞争

    let out = run_coffer_with_stdin(
        &["set-password", "GitHub"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        NEW_PW,
    );
    assert_eq!(out.status.code(), Some(0), "更新成功 → 退出码 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("已更新"), "成功消息，stdout: {stdout}");
    assert!(stdout.contains("GitHub"), "成功消息带条目名，stdout: {stdout}");
    assert!(
        !stdout.contains(NEW_PW),
        "成功消息不得含新密码，stdout: {stdout}"
    );
    assert!(
        !stderr.contains(NEW_PW),
        "stderr 不得含新密码，stderr: {stderr}"
    );

    // 落库 + 历史 append（FR-2.9）。
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let pw_field = d
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password field exists");
    assert_eq!(
        pw_field.value.as_ref().map(|v| v.expose()),
        Some(NEW_PW),
        "密码字段已更新为新值"
    );
    let hist = s.list_history(&id).expect("list history");
    assert_eq!(hist.len(), 1, "更新须 append 一条历史（FR-2.9）");
}

/// v2.5.2：`set-password <条目名> --user <用户名>` 用户名+密码一对写（AC-18.2-17）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_password_with_user_writes_username_and_password_pair() {
    use cf_domain::field::Designation;
    let (vault_dir, pw, s) = fast_vault_setup("setpw-user");
    let id = create_login_item_in(&s, "GitHub"); // octocat / old-secret
    drop(s);

    let out = run_coffer_with_stdin(
        &["set-password", "GitHub", "--user", "newuser"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        NEW_PW,
    );
    assert_eq!(out.status.code(), Some(0), "一对写成功 → 退出码 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("已更新"), "成功消息，stdout: {stdout}");
    assert!(
        stdout.contains("newuser"),
        "成功回显含用户名，stdout: {stdout}"
    );
    assert!(!stdout.contains(NEW_PW), "成功消息不得含新密码");

    // 落库读回：密码 + 用户名均为新值。
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let pw_field = d
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password field exists");
    assert_eq!(pw_field.value.as_ref().map(|v| v.expose()), Some(NEW_PW));
    let user_field = d
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Username))
        .expect("username field exists");
    assert_eq!(
        user_field.value.as_ref().map(|v| v.expose()),
        Some("newuser"),
        "用户名已更新"
    );
    let hist = s.list_history(&id).expect("list history");
    assert_eq!(hist.len(), 1, "一对写仍只 append 一条历史（FR-2.9）");
}

/// v2.5.2：`--user` 缺值 → 用法错误退出 4（AC-18.2-16）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_password_missing_user_value_exits_4() {
    use cf_domain::field::Designation;
    let (vault_dir, pw, s) = fast_vault_setup("setpw-user-missing");
    let id = create_login_item_in(&s, "GitHub");
    drop(s);

    let out = run_coffer_with_stdin(
        &["set-password", "GitHub", "--user"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        NEW_PW,
    );
    assert_eq!(
        out.status.code(),
        Some(4),
        "`--user` 缺值 → 用法错误退出 4，实际 {out:?}"
    );
    // 不写库：密码字段仍为旧值。
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let pw_field = d
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password field exists");
    assert_eq!(
        pw_field.value.as_ref().map(|v| v.expose()),
        Some("old-secret"),
        "用法错误不写库"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_not_found_exits_2_and_does_not_write() {
    let (vault_dir, pw, s) = fast_vault_setup("setpw-miss");
    let id = create_login_item_in(&s, "GitHub");
    drop(s);

    let out = run_coffer_with_stdin(
        &["set-password", "NoSuchEntry"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        NEW_PW,
    );
    assert_eq!(out.status.code(), Some(2), "未命中 → 退出码 2（docs/34 §5.2）");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NoSuchEntry") || stderr.contains("not found"),
        "错误消息须指出未命中条目，stderr: {stderr}"
    );
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id).as_deref(),
        Some("old-secret"),
        "未命中不得写库"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_ambiguous_name_exits_2_and_does_not_write() {
    let (vault_dir, pw, s) = fast_vault_setup("setpw-amb");
    let id1 = create_login_item_in(&s, "GitHub");
    let id2 = create_login_item_in(&s, "GitHub");
    drop(s);

    let out = run_coffer_with_stdin(
        &["set-password", "GitHub"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        NEW_PW,
    );
    assert_eq!(out.status.code(), Some(2), "歧义 → 退出码 2（docs/34 §5.2）");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ambiguous") || stderr.contains("歧义"),
        "错误消息须指出歧义，stderr: {stderr}"
    );
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id1).as_deref(),
        Some("old-secret"),
        "歧义不得写任一匹配条目"
    );
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id2).as_deref(),
        Some("old-secret")
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_weak_password_rejected_but_force_bypasses() {
    let (vault_dir, pw, s) = fast_vault_setup("setpw-weak");
    let id = create_login_item_in(&s, "GitHub");
    drop(s);

    // 弱密码 → 拒绝 + 不写库。
    let out = run_coffer_with_stdin(
        &["set-password", "GitHub"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        "123456",
    );
    assert_eq!(out.status.code(), Some(3), "弱密码 → 退出码 3（docs/34 §5.2）");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--force") || stderr.contains("强"),
        "错误消息须给强度引导，stderr: {stderr}"
    );
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id).as_deref(),
        Some("old-secret"),
        "弱密码不得写库"
    );

    // `--force` 绕过强度门禁（用户批准保留，docs/34 §3）。
    let out = run_coffer_with_stdin(
        &["set-password", "--force", "GitHub"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        "123456",
    );
    assert_eq!(out.status.code(), Some(0), "--force 绕过 → 退出码 0");
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id).as_deref(),
        Some("123456"),
        "--force 弱密码落库"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_no_escrow_no_env_fail_closed_exit_1() {
    // 快速库未启用 MCP 托管（escrow 不可用）+ 不提供 $COFFER_VAULT_PASSWORD →
    // fail-closed 退出 1（D-4 与 `coffer mcp` 同链），不写库。
    let (vault_dir, _pw, s) = fast_vault_setup("setpw-nounlock");
    let id = create_login_item_in(&s, "GitHub");
    drop(s);

    let out = run_coffer_with_stdin(
        &["set-password", "GitHub"],
        &[("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path"))],
        NEW_PW,
    );
    assert_eq!(out.status.code(), Some(1), "escrow+env 均无 → 退出码 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("COFFER_VAULT_PASSWORD"),
        "错误消息须指明解锁途径缺失，stderr: {stderr}"
    );
    // 会话未解锁，库内条目不可能被改——仍显式断言密码未变。
    assert_eq!(
        item_password_value(&vault_dir, &_pw, &id).as_deref(),
        Some("old-secret"),
        "fail-closed 不得写库"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_by_id_updates_item() {
    use cf_domain::field::Designation;
    let (vault_dir, pw, s) = fast_vault_setup("setpw-id");
    let id = create_login_item_in(&s, "GitHub");
    drop(s);

    let out = run_coffer_with_stdin(
        &["set-password", "--id", &id],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        NEW_PW,
    );
    assert_eq!(out.status.code(), Some(0), "--id 定位成功 → 退出码 0");
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let pw_field = d
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password field exists");
    assert_eq!(
        pw_field.value.as_ref().map(|v| v.expose()),
        Some(NEW_PW),
        "--id 更新落库"
    );
}

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_argv_and_log_never_contain_plaintext() {
    // 密码只走 stdin；argv / 进程列表 / stdout / stderr 均不得出现明文。
    // 在子进程阻塞读 stdin 时抓 `ps` argv 断言，随后喂密码完成更新。
    let (vault_dir, pw, s) = fast_vault_setup("setpw-ps");
    let _id = create_login_item_in(&s, "GitHub");
    drop(s);

    let mut cmd = Command::new(coffer_bin());
    cmd.args(["set-password", "GitHub"])
        .env("COFFER_OP_BIN", fake_op())
        .env("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path"))
        .env("COFFER_VAULT_PASSWORD", &pw)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn coffer binary");
    let pid = child.id();

    // 子进程此刻阻塞在 `read_line`（stdin 未写）→ argv 已定型且绝不含密码。
    let mut ps_line: Option<String> = None;
    for _ in 0..40 {
        let out = Command::new("ps")
            .args(["-o", "args=", "-p", &pid.to_string()])
            .output()
            .expect("run ps");
        if out.status.success() {
            ps_line = Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let ps_line = ps_line.expect("child process visible to ps");
    assert!(ps_line.contains("set-password"), "argv 含子命令，ps: {ps_line}");
    assert!(
        !ps_line.contains(NEW_PW),
        "argv 不得含新密码（进程列表可见性），ps: {ps_line}"
    );

    // 喂密码 → 更新成功；stdout / stderr 亦不得泄露明文。
    {
        let mut si = child.stdin.take().expect("stdin pipe");
        si.write_all(format!("{NEW_PW}\n").as_bytes())
            .expect("write password");
    }
    let out = child.wait_with_output().expect("collect output");
    assert_eq!(out.status.code(), Some(0), "喂密后更新成功 → 退出码 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(NEW_PW), "stdout 不得含明文，stdout: {stdout}");
    assert!(!stderr.contains(NEW_PW), "stderr 不得含明文，stderr: {stderr}");
}

#[cfg(feature = "coffer-store")]
#[test]
fn set_password_usage_errors_exit_4() {
    // 未知 flag / `--id` 格式错 → 参数/用法错误退出码 4（docs/34 §5.2，脚本可区分），
    // 无需库配置即可判定（parse 阶段失败）。
    let out = run_coffer_with_stdin(
        &["set-password", "--nope", "GitHub"],
        &[],
        NEW_PW,
    );
    assert_eq!(out.status.code(), Some(4), "未知 flag → 退出码 4");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown flag") || stderr.contains("--nope"),
        "stderr: {stderr}"
    );

    let out = run_coffer_with_stdin(&["set-password", "--id", "not-a-uuid"], &[], NEW_PW);
    assert_eq!(out.status.code(), Some(4), "--id 格式错 → 退出码 4");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("UUID") || stderr.contains("--id"),
        "stderr: {stderr}"
    );
}

/// tester gap 1：Unicode（中文 + emoji）+ ≥1KB 密码须逐字节落库（不截断）。
/// `--force` 绕强度门禁，保证仅验证传输/存储路径。
#[cfg(feature = "coffer-store")]
#[test]
fn set_password_unicode_and_large_payload_no_truncation() {
    use cf_domain::field::Designation;
    let (vault_dir, pw, s) = fast_vault_setup("setpw-unicode");
    let id = create_login_item_in(&s, "GitHub");
    drop(s);

    let big_pw = format!("{}🎉{}", "密".repeat(600), "x".repeat(200));
    assert!(big_pw.len() >= 1024, "构造载荷须 ≥1KB，实际 {}", big_pw.len());

    let out = run_coffer_with_stdin(
        &["set-password", "GitHub", "--force"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
        &big_pw,
    );
    assert_eq!(out.status.code(), Some(0), "强载荷 + --force → 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(&big_pw), "stdout 不得含明文");
    assert!(!stderr.contains(&big_pw), "stderr 不得含明文");

    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let pw_field = d
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password field exists");
    assert_eq!(
        pw_field.value.as_ref().map(|v| v.expose()),
        Some(big_pw.as_str()),
        "Unicode/≥1KB 密码须逐字节落库（不截断）"
    );
}

/// tester gap 3：两个并发子进程写同一库同一条目——库不得损坏。lead 验收口径：
/// 每个写者 `0`（成功）**或干净失败**（存储层锁争用时 SQLite `database is locked`
/// 报错并退出 1、`未写入`，属真实存储语义而非损坏）。本测试在工作区并行负载下
/// 已实证二者皆可能出现，故按口径断言：每个 ∈ {0,1}、至少一个成功、库可重开
/// 解锁、条目健康、密码字段取成功者值。
#[cfg(feature = "coffer-store")]
#[test]
fn set_password_concurrent_writers_no_corruption() {
    use cf_domain::field::Designation;
    const PW_A: &str = "Correct-Horse-Battery-Staple-2026-Alpha!";
    const PW_B: &str = "Correct-Horse-Battery-Staple-2026-Bravo!";
    let (vault_dir, pw, s) = fast_vault_setup("setpw-conc");
    let id = create_login_item_in(&s, "GitHub");
    drop(s);

    let vd = vault_dir.to_str().expect("utf8 path").to_string();
    let dir_a = vd.clone();
    let dir_b = vd.clone();
    let env_a = pw.clone();
    let env_b = pw.clone();
    let h_a = std::thread::spawn(move || {
        run_coffer_with_stdin(
            &["set-password", "GitHub"],
            &[("COFFER_VAULT_DIR", &dir_a), ("COFFER_VAULT_PASSWORD", &env_a)],
            PW_A,
        )
    });
    let h_b = std::thread::spawn(move || {
        run_coffer_with_stdin(
            &["set-password", "GitHub"],
            &[("COFFER_VAULT_DIR", &dir_b), ("COFFER_VAULT_PASSWORD", &env_b)],
            PW_B,
        )
    });
    let out_a = h_a.join().expect("thread a");
    let out_b = h_b.join().expect("thread b");
    let mut successes = 0;
    for (i, out) in [&out_a, &out_b].iter().enumerate() {
        let code = out.status.code();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            code == Some(0) || code == Some(1), // 1 = 解锁/操作失败（docs/34 §5.2）
            "并发写者 {i} 须成功(0)或干净失败(1)，code: {code:?}, stderr: {stderr}"
        );
        if code == Some(0) {
            successes += 1;
        } else {
            // 干净失败：明确「未写入」，非半写损坏。
            assert!(
                stderr.contains("未写入"),
                "失败写者 {i} 须报未写入（干净失败），stderr: {stderr}"
            );
        }
    }
    assert!(successes >= 1, "两并发写者至少一个成功");

    let s = cf_session::open_vault(&vault_dir).expect("reopen vault after concurrent writes");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let pw_field = d
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password field exists");
    let v = pw_field.value.as_ref().map(|v| v.expose());
    assert!(
        v == Some(PW_A) || v == Some(PW_B),
        "最终密码字段须为成功写者之一（库未损坏），实际: {v:?}"
    );
}

// ------------------------------------------------------------ set-env（docs/36 §4，AC-36.1）

/// 环境容器保留标签（docs/36 §2.1 / provider/coffer.rs:63 同源）。
#[cfg(feature = "coffer-store")]
const ENV_TAG: &str = "coffer:environment";

/// 建一个环境容器条目（SecureNote + `coffer:environment` 标签 + NAME/VALUE 字段对；
/// 字段形态固定 = `FieldType::Text` + designation None，docs/36 §4.3）。
#[cfg(feature = "coffer-store")]
fn create_env_container_in(
    session: &cf_session::VaultSession,
    owner: &str,
    pairs: &[(&str, &str)],
) -> String {
    use cf_domain::category::ItemCategory;
    use cf_domain::field::FieldType;
    use cf_domain::item::{FieldDraft, ItemDraft};
    let fields = pairs
        .iter()
        .enumerate()
        .map(|(i, (name, value))| FieldDraft {
            name: name.to_string(),
            value: Some(value.to_string()),
            field_type: FieldType::Text,
            designation: None,
            section_index: None,
            position: i as i32,
        })
        .collect();
    let d = ItemDraft {
        title: owner.to_string(),
        category: ItemCategory::SecureNote,
        urls: Vec::new(),
        tags: vec![ENV_TAG.to_string()],
        sections: Vec::new(),
        fields,
        totp: None,
    };
    session.create_item(&d).expect("create env container")
}

/// 重新开库解锁，按标题查环境容器（SecureNote + ENV_TAG）；None = 无。
#[cfg(feature = "coffer-store")]
fn find_env_container(
    vault_dir: &std::path::Path,
    password: &str,
    owner: &str,
) -> Option<cf_session::types::ItemDetails> {
    use cf_domain::category::ItemCategory;
    let s = cf_session::open_vault(vault_dir).expect("reopen vault");
    s.unlock(password).expect("unlock vault");
    for sum in s.list_items(None).expect("list items") {
        if sum.title != owner {
            continue;
        }
        let d = s
            .get_item(&sum.uuid.to_string())
            .expect("get item")
            .expect("item exists");
        if d.category == ItemCategory::SecureNote && d.tags.iter().any(|t| t.expose() == ENV_TAG) {
            return Some(d);
        }
    }
    None
}

/// 读条目中指定 NAME 字段的值（None = 无该字段）。
#[cfg(feature = "coffer-store")]
fn env_field_value(d: &cf_session::types::ItemDetails, name: &str) -> Option<String> {
    d.fields
        .iter()
        .find(|f| f.name.expose() == name)
        .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
}

/// 重新开库解锁并读条目（按 id）。
#[cfg(feature = "coffer-store")]
fn reopen_item(
    vault_dir: &std::path::Path,
    password: &str,
    id: &str,
) -> cf_session::types::ItemDetails {
    let s = cf_session::open_vault(vault_dir).expect("reopen vault");
    s.unlock(password).expect("unlock vault");
    s.get_item(id).expect("get item").expect("item exists")
}

/// AC-36.1-1：写入更新成功——`set-env --scope <存在容器> NAME=VALUE` → 退出 0；
/// 目标字段更新、其它字段/标签/类别逐项不变；历史 append 一条（含旧值可回滚）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_update_existing_container_field_and_preserves_others() {
    use cf_domain::field::FieldType;
    let (vault_dir, pw, s) = fast_vault_setup("setenv-update");
    let id = create_env_container_in(&s, "prod", &[("API_KEY", "old-key"), ("LOG_LEVEL", "debug")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "API_KEY=new-key"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "更新成功 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("prod"), "成功消息带容器名，stdout: {stdout}");
    assert!(stdout.contains("环境容器"), "成功消息带容器标记，stdout: {stdout}");
    assert!(!stdout.contains("new-key"), "stdout 不得含新 VALUE，stdout: {stdout}");
    assert!(!stderr.contains("new-key"), "stderr 不得含新 VALUE，stderr: {stderr}");

    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("new-key"), "目标字段已更新");
    assert_eq!(
        env_field_value(&d, "LOG_LEVEL").as_deref(),
        Some("debug"),
        "其它字段不变"
    );
    assert_eq!(d.fields.len(), 2, "只动目标字段，不增删字段");
    assert_eq!(
        d.category,
        cf_domain::category::ItemCategory::SecureNote,
        "类别不变"
    );
    assert!(d.tags.iter().any(|t| t.expose() == ENV_TAG), "coffer:environment 标签不变");
    // 命中既有字段不改 field_type / designation（docs/36 §4.3）。
    let target = d
        .fields
        .iter()
        .find(|f| f.name.expose() == "API_KEY")
        .expect("API_KEY field");
    assert_eq!(target.field_type, FieldType::Text, "命中字段不改 field_type");
    assert_eq!(target.designation, None, "命中字段不改 designation");
    // 历史 append 一条（FR-2.9）。
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    assert_eq!(
        s.list_history(&id).expect("list history").len(),
        1,
        "更新须 append 一条历史"
    );
}

/// AC-36.1-2：首写自动建容器——`set-env --scope <不存在>` → 退出 0 + 新建
/// SecureNote + `coffer:environment` 标签 + NAME 字段。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_first_write_auto_creates_container() {
    use cf_domain::category::ItemCategory;
    let (vault_dir, pw, s) = fast_vault_setup("setenv-autocreate");
    drop(s); // 库为空，无 "staging" 容器

    let out = run_coffer(
        &["set-env", "--scope", "staging", "STAGE_FLAG=on"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "首写自动建容器 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("staging"), "成功消息带容器名，stdout: {stdout}");

    let d = find_env_container(&vault_dir, &pw, "staging")
        .expect("首写须自动建环境容器（SecureNote + coffer:environment）");
    assert_eq!(d.category, ItemCategory::SecureNote, "新建条目须为 SecureNote");
    assert!(d.tags.iter().any(|t| t.expose() == ENV_TAG), "须带 coffer:environment 标签");
    assert_eq!(env_field_value(&d, "STAGE_FLAG").as_deref(), Some("on"), "NAME 字段已写入");
}

/// AC-36.1-3：同名非容器拒绝——存在同名普通条目 → 退出 2 + 不建不写
/// （标题撞车防混淆，D-36.2 硬约束）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_scope_matches_non_container_exits_2_no_write() {
    use cf_domain::category::ItemCategory;
    let (vault_dir, pw, s) = fast_vault_setup("setenv-noncont");
    let id = create_login_item_in(&s, "conflict"); // Login，非环境容器
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "conflict", "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "同名非容器 → 退出码 2，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("不是环境容器")
            || stderr.contains("not an environment container")
            || stderr.contains("环境容器"),
        "错误须说明非环境容器（中文/英文均可），stderr: {stderr}"
    );
    // 不建不写：Login 条目仍在且未改；无新建 SecureNote。
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id).as_deref(),
        Some("old-secret"),
        "非容器条目不得被写"
    );
    assert!(
        find_env_container(&vault_dir, &pw, "conflict").is_none(),
        "不得自动建容器（标题撞车防混淆）"
    );
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    let items = s.list_items(None).expect("list items");
    assert_eq!(items.len(), 1, "不得新增条目");
    assert_eq!(items[0].category, ItemCategory::Login, "原条目类别不变");
}

/// AC-36.1-4：歧义——同名多容器 → 退出 2 + 提示 `--id`，任一匹配容器不写。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_ambiguous_scope_exits_2_hints_id() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-amb");
    let id1 = create_env_container_in(&s, "dup", &[("A", "1")]);
    let id2 = create_env_container_in(&s, "dup", &[("B", "2")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "dup", "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "歧义 → 退出码 2，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("歧义") || stderr.contains("ambiguous"),
        "错误须说明歧义，stderr: {stderr}"
    );
    assert!(stderr.contains("--id"), "歧义须提示 --id，stderr: {stderr}");
    for id in [&id1, &id2] {
        let d = reopen_item(&vault_dir, &pw, id);
        assert!(env_field_value(&d, "FOO").is_none(), "歧义不得写 {id}");
    }
}

/// AC-36.1-5：`--id` 兜底——`--id <容器UUID>` 更新成功。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_by_id_updates_container() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-id");
    let id = create_env_container_in(&s, "target", &[("API_KEY", "old")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--id", &id, "API_KEY=new"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "--id 定位更新成功 → 退出码 0，out: {out:?}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("new"), "--id 更新落库");
}

/// AC-36.1-5：`--id` 命中非容器 → 退出 2，不写库。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_by_id_non_container_exits_2() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-id-noncont");
    let id = create_login_item_in(&s, "GitHub"); // Login，非环境容器
    drop(s);

    let out = run_coffer(
        &["set-env", "--id", &id, "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "--id 命中非容器 → 退出码 2，out: {out:?}");
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id).as_deref(),
        Some("old-secret"),
        "非容器不得被写"
    );
}

/// AC-36.1-5：`--id` 未命中 → 退出 2（--id 无自动建语义）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_by_id_missing_exits_2() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-id-missing");
    drop(s);

    let out = run_coffer(
        &["set-env", "--id", "00000000-0000-4000-8000-000000000000", "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "--id 未命中 → 退出码 2，out: {out:?}");
    assert!(
        find_env_container(&vault_dir, &pw, "FOO").is_none(),
        "未命中不得自动建容器（--id 无自动建语义）"
    );
}

/// AC-36.1-7：`--unset` 删除字段 → 退出 0；历史 append 一条。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_unset_removes_field_and_appends_history() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-unset");
    let id = create_env_container_in(&s, "prod", &[("FOO", "v1"), ("BAR", "v2")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "--unset", "FOO"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "--unset 删除字段 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("prod"), "成功消息带容器名，stdout: {stdout}");

    let d = reopen_item(&vault_dir, &pw, &id);
    assert!(env_field_value(&d, "FOO").is_none(), "FOO 字段已删除");
    assert_eq!(env_field_value(&d, "BAR").as_deref(), Some("v2"), "其它字段保留");
    assert_eq!(d.fields.len(), 1, "仅删除目标字段");
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    assert_eq!(
        s.list_history(&id).expect("list history").len(),
        1,
        "删除须 append 一条历史"
    );
}

/// AC-36.1-7：删除不存在的 NAME = 幂等成功（退出 0，不增删字段；内容无变化不
/// append 历史——FR-2.9 update_item 内建语义）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_unset_missing_name_idempotent_success() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-unset-miss");
    let id = create_env_container_in(&s, "prod", &[("FOO", "v1")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "--unset", "NOPE"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "删除不存在的 NAME = 幂等成功，out: {out:?}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "FOO").as_deref(), Some("v1"), "既有字段不变");
    assert_eq!(d.fields.len(), 1, "不增删字段");
    // 幂等语义（docs/36 §4.3「删除缺失的 NAME = 幂等成功」+ §3「内容无变化
    // 不写」）：draft 无内容变化 → 不 update、不 append 历史。
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    assert_eq!(
        s.list_history(&id).expect("list history").len(),
        0,
        "幂等删除（无内容变化）不得 append 历史"
    );
}

/// AC-36.1-13（spawn 可测分支）：无托管（快速库未启用 escrow）+ $COFFER_VAULT_PASSWORD
/// → env 兜底解锁成功（source="env-fallback"），写入落库。
///
/// 注：escrow「启用→托管解锁成功」与「存在但解锁失败→退出 1 不回落 env」两分支须
/// MockEscrow 注入，跨 spawn 边界不可行（子进程用平台真实 Keychain，无签名身份），
/// 由 P1 的 set_env_tests.rs in-process 单测覆盖（复用 cli::unlock_vault，与 cli.rs
/// 内测同面）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_no_escrow_env_fallback_success() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-envfb");
    let id = create_env_container_in(&s, "prod", &[("API_KEY", "old")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "API_KEY=new"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "无托管 + env → env 兜底成功，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("env-fallback"), "须日志 env 兜底线索，stderr: {stderr}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("new"));
}

/// AC-36.1-13（spawn 可测分支）：无托管无 env → fail-closed 退出 1（消息提示
/// $COFFER_VAULT_PASSWORD），不写库。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_no_escrow_no_env_fail_closed_exit_1() {
    let (vault_dir, _pw, s) = fast_vault_setup("setenv-nounlock");
    let id = create_env_container_in(&s, "prod", &[("API_KEY", "old")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "API_KEY=new"],
        &[("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path"))],
    );
    assert_eq!(out.status.code(), Some(1), "escrow+env 均无 → fail-closed 退出 1，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("COFFER_VAULT_PASSWORD"),
        "错误须指明解锁途径缺失，stderr: {stderr}"
    );
    let d = reopen_item(&vault_dir, &_pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("old"), "fail-closed 不得写库");
}

/// AC-36.1-14：并发写原子性（镜像 set-password 并发口径，docs/36 §6 判据）——
/// 两进程并发 `set-env` 同容器同 NAME：每个写者退出 0 或干净失败 1、至少一个成功、
/// 库可重开解锁、容器字段健康、最终值取成功写者之一（无损坏）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_concurrent_writers_no_corruption() {
    const VAL_A: &str = "value-alpha-2026";
    const VAL_B: &str = "value-bravo-2026";
    let (vault_dir, pw, s) = fast_vault_setup("setenv-conc");
    let id = create_env_container_in(&s, "conc", &[("SHARED", "v0")]);
    drop(s);

    let vd_a = vault_dir.to_str().expect("utf8 path").to_string();
    let vd_b = vd_a.clone();
    let env_a = pw.clone();
    let env_b = pw.clone();
    let h_a = std::thread::spawn(move || {
        let pair = format!("SHARED={VAL_A}");
        run_coffer(
            &["set-env", "--scope", "conc", pair.as_str()],
            &[("COFFER_VAULT_DIR", &vd_a), ("COFFER_VAULT_PASSWORD", &env_a)],
        )
    });
    let h_b = std::thread::spawn(move || {
        let pair = format!("SHARED={VAL_B}");
        run_coffer(
            &["set-env", "--scope", "conc", pair.as_str()],
            &[("COFFER_VAULT_DIR", &vd_b), ("COFFER_VAULT_PASSWORD", &env_b)],
        )
    });
    let out_a = h_a.join().expect("thread a");
    let out_b = h_b.join().expect("thread b");
    let mut successes = 0;
    for (i, out) in [&out_a, &out_b].iter().enumerate() {
        let code = out.status.code();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            code == Some(0) || code == Some(1),
            "并发写者 {i} 须成功(0)或干净失败(1)，code: {code:?}, stderr: {stderr}"
        );
        if code == Some(0) {
            successes += 1;
        } else {
            assert!(
                stderr.contains("未写入"),
                "失败写者 {i} 须报未写入（干净失败），stderr: {stderr}"
            );
        }
    }
    assert!(successes >= 1, "两并发写者至少一个成功");

    let s = cf_session::open_vault(&vault_dir).expect("reopen vault after concurrent writes");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let v = env_field_value(&d, "SHARED");
    assert!(
        v.as_deref() == Some(VAL_A) || v.as_deref() == Some(VAL_B),
        "最终 SHARED 须为成功写者之一（库未损坏），实际: {v:?}"
    );
    assert_eq!(d.fields.len(), 1, "容器字段健康（无重复/半写）");
}

/// AC-36.1-11：值不进 argv/日志——裸 NAME 形态下值走 stdin，`ps` 进程列表 argv
/// 不含 VALUE；喂值后成功，stdout/stderr 亦不得泄露明文（内联形态是显式知情
/// 逃生口，本判据仅断言裸 NAME 形态）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_bare_name_value_not_in_argv_stdout_stderr() {
    const SECRET: &str = "ps-secret-VALUE-7f3a9c-x1";
    let (vault_dir, pw, s) = fast_vault_setup("setenv-ps");
    let id = create_env_container_in(&s, "psenv", &[("EXISTING", "keep")]);
    drop(s);

    let mut cmd = Command::new(coffer_bin());
    cmd.args(["set-env", "--scope", "psenv", "API_TOKEN"])
        .env("COFFER_OP_BIN", fake_op())
        .env("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path"))
        .env("COFFER_VAULT_PASSWORD", &pw)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn coffer binary");
    let pid = child.id();

    // 裸 NAME 形态：值走 stdin，子进程阻塞读 stdin 时 argv 已定型且绝不含值。
    let mut ps_line: Option<String> = None;
    for _ in 0..40 {
        let out = Command::new("ps")
            .args(["-o", "args=", "-p", &pid.to_string()])
            .output()
            .expect("run ps");
        if out.status.success() {
            ps_line = Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let ps_line = ps_line.expect("child process visible to ps");
    assert!(ps_line.contains("set-env"), "argv 含子命令，ps: {ps_line}");
    assert!(ps_line.contains("API_TOKEN"), "argv 含裸 NAME（NAME 非值），ps: {ps_line}");
    assert!(!ps_line.contains(SECRET), "argv 不得含 VALUE（进程列表可见性），ps: {ps_line}");

    // 喂值 → 更新成功；stdout / stderr 亦不得泄露明文。
    {
        let mut si = child.stdin.take().expect("stdin pipe");
        si.write_all(format!("{SECRET}\n").as_bytes())
            .expect("write secret");
    }
    let out = child.wait_with_output().expect("collect output");
    assert_eq!(out.status.code(), Some(0), "喂值后更新成功 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(SECRET), "stdout 不得含明文，stdout: {stdout}");
    assert!(!stderr.contains(SECRET), "stderr 不得含明文，stderr: {stderr}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_TOKEN").as_deref(), Some(SECRET), "stdin 值落库");
    assert_eq!(env_field_value(&d, "EXISTING").as_deref(), Some("keep"), "其它字段不变");
}

/// AC-36.1-12（退出码纪律，退出 4 面）：缺 `--scope` / `--scope`+`--id` 并存 /
/// `--unset` 与对并存 / 非法 NAME → 用法错误退出 4，parse 阶段即可判定
/// （无需库配置），不写库（docs/36 §4.1 / §4.5）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_usage_errors_exit_4() {
    let out = run_coffer(&["set-env", "FOO=bar"], &[]);
    assert_eq!(out.status.code(), Some(4), "缺 --scope → 退出码 4，out: {out:?}");

    let out = run_coffer(
        &["set-env", "--scope", "a", "--id", "00000000-0000-4000-8000-000000000000", "FOO=bar"],
        &[],
    );
    assert_eq!(out.status.code(), Some(4), "--scope+--id 并存 → 退出码 4，out: {out:?}");

    let out = run_coffer(&["set-env", "--scope", "a", "--unset", "FOO", "BAR=baz"], &[]);
    assert_eq!(out.status.code(), Some(4), "--unset 与对并存 → 退出码 4，out: {out:?}");

    // 非法 NAME（含 `-`）→ 退出 4 不写库（需库配置以验证「不写」）。
    let (vault_dir, pw, s) = fast_vault_setup("setenv-badname");
    let id = create_env_container_in(&s, "prod", &[("GOOD", "keep")]);
    drop(s);
    let out = run_coffer(
        &["set-env", "--scope", "prod", "BAD-NAME=x"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(4), "非法 NAME → 退出码 4，out: {out:?}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "GOOD").as_deref(), Some("keep"), "用法错误不写库");
    assert!(env_field_value(&d, "BAD-NAME").is_none(), "非法 NAME 字段未写入");
}
