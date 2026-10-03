//! OpProvider 的 run_with_secret 面测试 —— 由 fake `op` fixture 驱动。
//!
//! 覆盖 `op run --env-file` 协议路径（docs/20 §4.2）：
//! - 临时 dotenv（0600）承载 `ENV_NAME=op://…` 引用，明文不经过 cf-mcp 进程内存
//!   （§4.4 明文暴露面：值只从 fake op 直接注入目标子进程环境）；
//! - 子进程退出码原样返回（对应 mcp_acceptance 的
//!   `run_with_secret_nonzero_exit_is_returned_not_error` 契约）；
//! - op 层失败（引用解析失败 / 命令不存在 / 未登录）归一为 7xxx 错误。
//!
//! 所有 run 用例经 `RUN_LOCK` 串行化：provider 的临时 dotenv 落在共享的
//! `std::env::temp_dir()`，并行下会互相看到对方的临时文件（同 mcp_acceptance
//! 对进程级可变状态串行化的纪律）。

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_mcp::error::McpError;
use cf_mcp::provider::op::{OpProvider, OpProviderConfig};
use cf_mcp::provider::{RunSpec, SecretProvider};

/// 串行化所有会创建临时 dotenv 的 run 用例。
static RUN_LOCK: Mutex<()> = Mutex::new(());

/// fake `op` 脚本的绝对路径。
fn fake_op() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/op/op")
}

/// 指向 fake `op` 的 provider（无会话 token）。
fn provider() -> OpProvider {
    OpProvider::new(OpProviderConfig {
        op_bin: fake_op(),
        default_vault: None,
        session_token: None,
    })
    .expect("fake op must be executable")
}

/// 每用例独立临时目录（tag 必唯一，规避 BUG-12 并行撞名）。
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "coffer-mcp-op-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 构造一条指向 fixture 值 `fixture-secret-value-openai` 的 RunSpec。
fn api_key_spec() -> RunSpec {
    RunSpec {
        secret_ref: "op://Personal/OPENAI_API_KEY/password".to_string(),
        env_name: "MY_KEY".to_string(),
        cmd: "sh".to_string(),
        args: vec![],
        cwd: None,
    }
}

/// 本进程可能残留的临时 dotenv 文件（provider 用后即毁；本助手仅用于断言清理）。
fn leftover_temp_env_files() -> Vec<PathBuf> {
    let prefix = format!("coffer-mcp-env-{}", std::process::id());
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect()
}

// ===========================================================================
// 值注入与退出码
// ===========================================================================

#[test]
fn run_with_secret_injects_fixture_value_into_child() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = temp_dir("inject");
    let marker = dir.join("marker");
    let mut spec = api_key_spec();
    spec.args = vec![
        "-c".to_string(),
        format!(
            "test \"$MY_KEY\" = \"fixture-secret-value-openai\" && touch {}",
            marker.display()
        ),
    ];
    spec.cwd = Some(dir.clone());

    let code = provider()
        .run_with_secret(&spec)
        .expect("run must not error");
    assert_eq!(code, 0, "child must exit 0 when value injected");
    assert!(
        marker.exists(),
        "secret value must be injected into child env under env_name (AS-5 mode B)"
    );
}

#[test]
fn run_with_secret_propagates_child_exit_code() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.args = vec!["-c".to_string(), "exit 42".to_string()];
    let code = provider()
        .run_with_secret(&spec)
        .expect("run must not error");
    assert_eq!(code, 42, "child exit code must be propagated, got {code}");
}

#[test]
fn run_with_secret_nonzero_exit_is_returned_not_error() {
    // 契约（mcp_acceptance）：子进程失败 ≠ MCP 调用失败 —— 退出码作 i32 返回，
    // 不吞、不误报 Err（fake op 对子进程失败不打 [ERROR]，与真机一致）。
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.args = vec!["-c".to_string(), "exit 7".to_string()];
    let r = provider().run_with_secret(&spec);
    match r {
        Ok(code) => assert_eq!(code, 7, "nonzero child exit must propagate, got {code}"),
        Err(e) => panic!("child nonzero exit must NOT surface as Err, got {e:?}"),
    }
}

#[test]
fn run_with_secret_uses_cwd() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = temp_dir("cwd");
    let out = dir.join("pwd-out");
    let mut spec = api_key_spec();
    spec.args = vec!["-c".to_string(), format!("pwd > {}", out.display())];
    spec.cwd = Some(dir.clone());

    let code = provider()
        .run_with_secret(&spec)
        .expect("run must not error");
    assert_eq!(code, 0);
    let pwd = std::fs::read_to_string(&out).expect("child must write pwd to cwd");
    // macOS 上 `/var` → `/private/var` 为符号链接：`temp_dir()` 给别名路径，
    // 子进程 `pwd` 报物理路径，故两侧均取 canonicalize 后再比较。
    let expected = dir
        .canonicalize()
        .expect("temp dir must canonicalize to physical path");
    assert_eq!(
        pwd.trim(),
        expected.to_string_lossy(),
        "child process must run in the requested cwd"
    );
}

// ===========================================================================
// 参数校验（7005）
// ===========================================================================

#[test]
fn run_with_secret_rejects_empty_env_name() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.env_name.clear();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("empty env_name must be rejected");
    assert_eq!(McpError::from(err.clone()).code(), 7005);
}

#[test]
fn run_with_secret_rejects_invalid_env_name() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.env_name = "BAD NAME WITH SPACES".to_string();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("invalid env_name must be rejected");
    assert_eq!(McpError::from(err.clone()).code(), 7005);
}

#[test]
fn run_with_secret_rejects_empty_secret_ref() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.secret_ref.clear();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("empty secret_ref must be rejected");
    assert_eq!(McpError::from(err.clone()).code(), 7005);
}

#[test]
fn run_with_secret_rejects_bare_item_id() {
    // H-1（dev-reviewer）：run 面 dotenv 只承载 `op://` 引用（docs/20 §4.2）——
    // 裸 item id 会被 `op run` 当字面量注入子进程 env（静默注入错误"值"）→ 7005。
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.secret_ref = "fixture-item-api-key".to_string();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("bare item id must be rejected on run path");
    assert_eq!(McpError::from(err.clone()).code(), 7005);
}

#[test]
fn run_with_secret_rejects_empty_cmd() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.cmd.clear();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("empty cmd must be rejected");
    assert_eq!(McpError::from(err.clone()).code(), 7005);
}

#[test]
fn run_with_secret_rejects_nonexistent_cwd() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.cwd = Some(temp_dir("nonexistent-cwd").join("no-such-dir"));
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("nonexistent cwd must be rejected");
    assert_eq!(McpError::from(err.clone()).code(), 7005);
}

// ===========================================================================
// op 层失败（7003 / 7004 / 7002）
// ===========================================================================

#[test]
fn run_with_secret_rejects_unknown_secret_reference() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.secret_ref = "op://Personal/DOES_NOT_EXIST/password".to_string();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("unknown secret reference must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7003,
        "unknown reference maps to 7003 SecretNotFound, got {err:?}"
    );
}

#[test]
fn run_with_secret_rejects_unknown_vault_in_reference() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.secret_ref = "op://NoSuchVault/OPENAI_API_KEY/password".to_string();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("unknown vault in reference must be rejected");
    assert_eq!(McpError::from(err.clone()).code(), 7003);
}

#[test]
fn run_with_secret_rejects_missing_command() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut spec = api_key_spec();
    spec.cmd = "definitely-not-a-real-cmd-xyz".to_string();
    let err = provider()
        .run_with_secret(&spec)
        .expect_err("missing command must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7004,
        "missing command maps to 7004 SubprocessFailed, got {err:?}"
    );
}

#[test]
fn run_with_secret_maps_not_signed_in_to_auth_required() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let provider = OpProvider::new(OpProviderConfig {
        op_bin: fake_op(),
        default_vault: None,
        session_token: Some(cf_domain::secret::SecretString::from_exposed(
            "COFFER_FAKE_OP_EXPIRED_SESSION",
        )),
    })
    .expect("fake op must be executable");
    let err = provider
        .run_with_secret(&api_key_spec())
        .expect_err("expired session must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7002,
        "not signed in maps to 7002 AuthenticationRequired, got {err:?}"
    );
}

// ===========================================================================
// 用后即毁（临时 dotenv）
// ===========================================================================

#[test]
fn run_with_secret_removes_temp_env_file_after_run() {
    let _g = RUN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // 前置：确认无残留（防御并行污染 —— 由 RUN_LOCK 保证本进程内串行）。
    assert!(
        leftover_temp_env_files().is_empty(),
        "precondition: no leftover temp env files before run"
    );

    let code = provider()
        .run_with_secret(&api_key_spec())
        .expect("run must not error");
    assert_eq!(code, 0);

    let leftover = leftover_temp_env_files();
    assert!(
        leftover.is_empty(),
        "temp env file must be removed after run (AS-5 用后即毁), got {leftover:?}"
    );
}

/// 编译期断言：`RunSpec` 字段与 docs/20 §4.1 冻结签名一致。
#[test]
fn run_spec_fields_match_design_contract() {
    let spec = api_key_spec();
    // 各字段类型/名称即契约面：此处仅确保均可读且类型正确。
    let _: String = spec.secret_ref;
    let _: String = spec.env_name;
    let _: String = spec.cmd;
    let _: Vec<String> = spec.args;
    let _: Option<PathBuf> = spec.cwd;
}
