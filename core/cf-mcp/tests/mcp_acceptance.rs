//! cf-mcp v0.5 MCP 凭据域验收用例（草稿，指向未实现功能 —— 预期红灯）。
//!
//! 判据来源：`docs/10-Agent凭据域.md`（LV-SRS-010 r1.0，AS-1..AS-14 + §5 安全审查要点）。
//! 目标 API：`core/cf-mcp/src/lib.rs` 桩 crate（合入 95870b7）的 `cf_mcp::mcp::*` 公有签名。
//!
//! # 先红后绿约定
//! 本文件是**用例起草**：对当前桩实现应大量红灯（桩函数 `Ok(空)/Ok(0)/Ok(())` 不产生任何
//! 可观察副作用）。每一条红灯用例都通过「可观察副作用断言」而非「返回值 Ok 断言」来验证，
//! 否则会对桩实现假绿。实现完成后应逐条转绿；红不了的用例（本文件头部 `// 未覆盖` 条目）
//! 不得假装已测。
//!
//! # 范围收缩（D-1，docs/20 §1.3/§3.3 —— 暂定、用户确认中、保持可逆）
//! v0.5 工具集暂定收缩为 **4 个**：`list_secret_names` / `list_secrets` /
//! `run_with_secret` / `get_secret_metadata`；`grant/revoke/rotate/environment` 系列
//! （含 `audit_secret_usage`）顺延 v2.x。
//!
//! - **4 工具相关用例（16 条，无标记）**：实现到位后须核对转绿 —— 即 lead 指令 ①；
//! - **顺延用例（25 条，带 `D-1 未确认收缩范围` 标记）**：**保留、不删、不跳过**，
//!   作为 v2.x 回归基线 —— 即 lead 指令 ②。顺延只代表实现排期后移，不改变判据本身
//!   （docs/10 AS-* 判据仍有效），桩实现下它们仍是预期红灯。
//! - 转绿/保留的精确计数口径见文件尾注（lead 指令 ③）。
//!
//! # 测试种子契约（实现须满足，否则对应用例无法转绿）
//! cf-mcp 桩 crate 目前不持有任何存储；验收用例通过**进程环境变量**向实现注入测试数据
//! （docs/10 §4 U-4 存储模型未裁定，故不以任何具体存储 API 为前提）。实现须读取以下
//! 环境变量作为其测试数据源：
//!
//! | 环境变量 | 语义 | 被以下用例消费 |
//! | --- | --- | --- |
//! | `COFFER_MCP_TEST_HOME` | 实现应把该目录视为测试工作/库目录 | 全部种子用例 |
//! | `COFFER_MCP_TEST_SEED_NAMES` | 逗号分隔的、必须已存在的 secret 名清单 | list_secret_names / list_secrets |
//! | `COFFER_MCP_TEST_SECRET_<NAME>` | secret `<NAME>` 必须持有的值 | run_with_secret 注入 / rotate 值比对 |
//! | `COFFER_MCP_TEST_ENV_VARS_<ENV>` | `<ENV>` 环境应注入的 `NAME=VALUE` 逗号清单 | inject_environment |
//!
//! 这些环境变量**只被带 `ENV_LOCK` 的用例读写**（`std::env` 是进程级可变状态，须串行化）；
//! 每个用例用 `unique()` 后缀保证变量名互不重叠，即使异常残留也不互相污染。
//!
//! # 覆盖台账（AS-* → 用例 / 未覆盖原因）
//!
//! | docs/10 判据 | 覆盖方式 | 备注 |
//! | --- | --- | --- |
//! | AS-4 MCP 工具面 | 全部 12 个工具函数逐一正/负路径；D-1 后 4 工具为 v0.5 转绿面，其余 8 工具顺延 v2.x | 桩签名即契约面；顺延用例带 `D-1 未确认收缩范围` 标记保留 |
//! | AS-4 默认不提供 reveal/get_password/dump_vault/export_all_secrets | **未覆盖（编译期面检查）** | Rust 运行时无法断言「符号不存在」；需 trybuild/compiletest 或评审清单，另立文件 |
//! | AS-5 模式 A（env 注入，只见名不见值） | `inject_environment_applies_to_child_process` | 变量真实注入子进程 |
//! | AS-5 模式 B（run_with_secret：子进程+注入+退出码） | `run_with_secret_*` 一组 | 副作用/退出码可观察 |
//! | AS-5 模式 B「退出后销毁运行环境」 | **未覆盖（部分）** | 桩签名无运行环境句柄；销毁可观察面待定 |
//! | AS-5 模式 C（临时挂载） | `mount_environment_*` | 产物/拒绝路径 |
//! | AS-7 权限矩阵（Agent×Project×Env×Secret×Action） | `grant/revoke_secret_*` | 仅 allowed_agents 生命周期；**Agent 上下文未建模**（见下） |
//! | AS-7 权限拒绝（无授权 Agent 被拒） | **未覆盖** | `run_with_secret` 桩签名无 agent 参数（U-6/§5 未决），无法表达调用方 Agent |
//! | AS-7/§5 `grant_secret` 自授权风险 | **未覆盖** | 同上，需 Agent 上下文后另立用例 |
//! | AS-9 Secret 生命周期字段 | `get_secret_metadata_*` | 断言 AS-9 字段键齐全 |
//! | AS-10 审计（USE/ROTATE/GRANT/REVOKE、不记 Secret 值） | `audit_secret_usage_*`（弱） | 桩签名 `-> Result<()>` 无可读审计面；**内容/无值泄漏判据未覆盖**（见下） |
//! | AS-10 审计永不记录 Secret 值 | **未覆盖** | 需要审计读取面（返回条目或查询接口） |
//! | AS-11 脱敏 `sk-abc123xxxxxxxx → [COFFER_SECRET_REDACTED]` | **未覆盖** | 桩 `run_with_secret` 返回退出码、不返回 Tool Result 文本（U-7 未决）；脱敏可观察面待定 |
//! | §5 run_with_secret 隐藏边界（只对 LLM 上下文隐藏，不对子进程隐藏） | `run_with_secret_injects_secret_by_name`（隐含） | 子进程可读到值 = 边界正确；Tool Result 层脱敏见 AS-11 |
//! | §5 clientInfo 之类自称不是凭据 | **未覆盖** | 无认证面，需 Agent 上下文 |
//! | AS-13 MVP 11 项 | 视各工具实现进度而定 | 本文件按 AS-4 工具面组织 |
//! | AS-14 可用不可见（usable without visible） | 隐含于 list/get_metadata 不返回值 | `get_secret_metadata_never_contains_secret_value` 直接守卫 |
//!
//! # 测试环境纪律
//! - 隔离性：每用例独立临时目录（`temp_dir`，**带唯一 tag**，绝不裸用 pid+纳秒 —— 规避
//!   BUG-12 cf-store `attachment_repo` 并行撞名 flake，docs/KNOWN-ISSUES.md BUG-12）；进程环境
//!   可变状态统一经 `ENV_LOCK` 串行化。
//! - 确定性：无时间断言、无随机；所有值由用例自身固定。
//! - 外部网络/守护进程一律不依赖（子进程只用 `/bin/sh`，本地执行）。

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_mcp::mcp;

/// 串行化所有读写进程环境变量（`std::env`）的用例。
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// 获取环境用例串行锁，容忍中毒。
/// 本套用例刻意「在持锁状态下红掉」（断言失败即 panic），会毒化这把锁；后续用例
/// 必须能继续获取它，否则会在锁上误报 PoisonError 而掩盖真正的断言失败。
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 生成进程内唯一的标识后缀（pid + 纳秒，叠加调用方 tag —— BUG-12 安全）。
fn unique(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{tag}-{}-{nanos}", std::process::id())
}

/// 生成**可作为 shell 变量名**的唯一标识（下划线连接）。
/// `unique()` 含连字符，不能出现在子进程脚本的 `${var}` 引用里（shell 会把
/// `$A-b` 解析成 `$A - b`）——凡名称会被注入为环境变量并以变量名形式被子进程
/// 读取的用例，一律用本助手。
fn unique_var(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{tag}_{}_{nanos}", std::process::id())
}

/// 每用例独立临时目录（tag 必唯一 → 同 pid 同纳秒也不撞名，规避 BUG-12）。
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("coffer-mcp-accept-{}", unique(tag)));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 经 `run_with_secret` 跑一条 `sh -c` 脚本，返回子进程退出码。
fn run_sh(secret: &str, script: &str) -> Result<i32, Box<dyn Error>> {
    mcp::run_with_secret(secret, "sh", &["-c", script])
}

/// 经 `run_with_secret` 跑脚本并把 secret 值写入 `<dir>/out`，返回读到的内容。
/// （AS-5 模式 B：子进程被注入 secret；本助手用于 rotate 前后值比对。
/// secret 名须是 `unique_var()` 生成的合法 shell 变量名。）
fn capture_secret_via_subprocess(secret: &str, dir: &Path) -> Result<String, Box<dyn Error>> {
    let out = dir.join("out");
    // secret 名 = 注入的环境变量名（AS-5：注入 OPENAI_API_KEY 语义）→ 直接按名引用。
    let script = format!("printf %s \"${secret}\" > {}", out.display());
    run_sh(secret, &script)?;
    fs::read_to_string(&out).map_err(|e| Box::new(e) as Box<dyn Error>)
}

// ===========================================================================
// list_secret_names
// ===========================================================================

#[test]
fn list_secret_names_fresh_store_empty() {
    // 判据（AS-4/AS-13）：空库下工具可调用且返回空清单 —— 不 panic、可反序列化。
    let names = mcp::list_secret_names().expect("fresh store must be queryable");
    assert!(names.is_empty(), "fresh store must list no secrets");
}

#[test]
fn list_secret_names_returns_seeded_names() {
    // 判据（AS-4）：已登记 secret 必须出现在名单中。
    let _g = env_guard();
    let home = temp_dir("list-names");
    let a = unique("LK_A");
    let b = unique("LK_B");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var("COFFER_MCP_TEST_SEED_NAMES", format!("{a},{b}"));
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{a}"), "sk-a");
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{b}"), "sk-b");

    let names = mcp::list_secret_names().expect("list_secret_names must not error");
    // 桩实现返回空清单 → 红灯；实现须从种子（测试库）读出 {a},{b} → 绿灯。
    assert!(
        names.contains(&a),
        "seeded secret {a} must be listed, got {names:?}"
    );
    assert!(
        names.contains(&b),
        "seeded secret {b} must be listed, got {names:?}"
    );
}

// ===========================================================================
// list_secrets
// ===========================================================================

#[test]
fn list_secrets_fresh_store_empty() {
    let entries = mcp::list_secrets().expect("fresh store must be queryable");
    assert!(entries.is_empty(), "fresh store must list no secrets");
}

#[test]
fn list_secrets_pairs_name_with_metadata() {
    // 判据（AS-4/AS-9）：list_secrets 返回 (name, metadata)；metadata 必须非空。
    let _g = env_guard();
    let home = temp_dir("list-secrets");
    let a = unique("LS_A");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var("COFFER_MCP_TEST_SEED_NAMES", a.clone());
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{a}"), "sk-s");

    let entries = mcp::list_secrets().expect("list_secrets must not error");
    let got = entries
        .iter()
        .find(|(name, _)| name == &a)
        .expect("seeded secret must appear in list_secrets, got {entries:?}");
    assert!(
        !got.1.is_empty(),
        "metadata for {a} must be non-empty (AS-9 lifecycle fields)"
    );
}

// ===========================================================================
// create_environment / list_environments
// ===========================================================================

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn create_environment_then_list_contains_it() {
    // 判据（AS-4）：create_environment 后 list_environments 必须回显。
    let env_name = unique("env");
    mcp::create_environment(&env_name).expect("create_environment must not error");
    let envs = mcp::list_environments().expect("list_environments must not error");
    // 桩实现 list 恒空 → 红灯。
    assert!(
        envs.contains(&env_name),
        "created env {env_name} must be listed, got {envs:?}"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn create_environment_rejects_empty_name() {
    let r = mcp::create_environment("");
    assert!(r.is_err(), "empty env name must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn create_environment_rejects_whitespace_only_name() {
    let r = mcp::create_environment("   ");
    assert!(r.is_err(), "whitespace-only env name must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn create_environment_rejects_duplicate() {
    let env_name = unique("envdup");
    mcp::create_environment(&env_name).expect("first create must succeed");
    let second = mcp::create_environment(&env_name);
    assert!(
        second.is_err(),
        "duplicate env name must be rejected, got Ok({:?})",
        second
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn create_environment_accepts_unicode_name() {
    let env_name = format!("环境-接受-テスト-{}", unique("u"));
    mcp::create_environment(&env_name).expect("unicode env name must be accepted");
    let envs = mcp::list_environments().expect("list_environments must not error");
    // 桩实现 list 恒空 → 红灯。
    assert!(
        envs.contains(&env_name),
        "unicode env name must roundtrip, got {envs:?}"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn create_environment_long_name_boundary() {
    // 边界（长名）：要么被拒绝（Err），要么成功并可从 list 回显 —— 不允许静默成功无效果。
    let long = format!("e{}", "x".repeat(1024));
    let r = mcp::create_environment(&long);
    match r {
        Err(_) => { /* 拒绝长名 = 合法契约 */ }
        Ok(()) => {
            let envs = mcp::list_environments().expect("queryable");
            assert!(
                envs.contains(&long),
                "accepted long env name must be listed, got {envs:?}"
            );
        }
    }
}

// ===========================================================================
// mount_environment（AS-5 模式 C 临时挂载）
// ===========================================================================

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn mount_environment_creates_mount_path() {
    // 判据（AS-5 模式 C）：挂载后目标路径必须真实存在（临时凭证文件/目录）。
    // 前置（lead 裁定 2026-10-05，测试自身缺陷修正）：mount 要求 env 已存在（AS-5 模式 C），
    // 先 create_environment（合法名）再 mount —— 与 rejects_unknown_env 的未知 env 判据一致。
    let env_name = unique("mtenv");
    let dir = temp_dir("mount");
    let target = dir.join("cred");
    mcp::create_environment(&env_name).expect("create_environment must not error");
    mcp::mount_environment(&env_name, target.to_str().unwrap())
        .expect("mount_environment must not error");
    // 桩实现不产生任何产物 → 红灯。
    assert!(
        target.exists(),
        "mounted path must exist after mount_environment (AS-5 mode C)"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn mount_environment_rejects_unknown_env() {
    let dir = temp_dir("mount-unknown");
    let r = mcp::mount_environment("NO_SUCH_ENV_ACCEPT", dir.to_str().unwrap());
    assert!(r.is_err(), "mount of unknown env must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn mount_environment_rejects_empty_env() {
    let dir = temp_dir("mount-empty");
    let r = mcp::mount_environment("", dir.to_str().unwrap());
    assert!(r.is_err(), "empty env name must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn mount_environment_rejects_empty_path() {
    let r = mcp::mount_environment("any-env", "");
    assert!(r.is_err(), "empty mount path must be rejected");
}

// ===========================================================================
// inject_environment（AS-5 模式 A）
// ===========================================================================

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn inject_environment_applies_to_child_process() {
    // 判据（AS-5 模式 A）：注入后子进程可见对应变量（Agent 只见变量名，值进子进程环境）。
    let _g = env_guard();
    let home = temp_dir("inject");
    let env_name = unique("injenv");
    let var = unique_var("INJ_VAR");
    let dir = temp_dir("inject-child");
    let marker = dir.join("marker");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(
        format!("COFFER_MCP_TEST_ENV_VARS_{env_name}"),
        format!("{var}=injected-accept-value"),
    );

    mcp::inject_environment(&env_name).expect("inject_environment must not error");
    // 子进程验证变量值并落 marker —— 桩实现不注入 → 子进程读到空 → 无 marker → 红灯。
    let script = format!(
        "test \"${var}\" = \"injected-accept-value\" && touch {}",
        marker.display()
    );
    let code = run_sh("ANY_SECRET", &script).expect("child must run");
    assert_eq!(code, 0, "child must exit 0 when env injected");
    assert!(
        marker.exists(),
        "injected var must be visible to child process (AS-5 mode A)"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn inject_environment_rejects_unknown_env() {
    let r = mcp::inject_environment("NO_SUCH_ENV_ACCEPT");
    assert!(r.is_err(), "inject of unknown env must be rejected");
}

// ===========================================================================
// run_with_secret（AS-5 模式 B）
// ===========================================================================

#[test]
fn run_with_secret_executes_command_and_returns_exit_code() {
    // 判据（AS-5 模式 B）：子进程真实执行，退出码原样返回。
    // 桩实现返回 Ok(0) 且不执行子进程 → 断言 Ok(42) 失败 → 红灯。
    let code = mcp::run_with_secret("ANY_SECRET", "sh", &["-c", "exit 42"])
        .expect("run_with_secret must not error");
    assert_eq!(code, 42, "child exit code must be propagated, got {code}");
}

#[test]
fn run_with_secret_runs_side_effect() {
    // 判据：子进程确实被启动（副作用可观察）。
    let dir = temp_dir("run-effect");
    let marker = dir.join("marker");
    let script = format!("touch {}", marker.display());
    let code = mcp::run_with_secret("ANY_SECRET", "sh", &["-c", &script])
        .expect("run_with_secret must not error");
    assert_eq!(code, 0);
    // 桩实现不启动子进程 → 无 marker → 红灯。
    assert!(
        marker.exists(),
        "subprocess side-effect must be observable (stub never spawns)"
    );
}

#[test]
fn run_with_secret_injects_secret_by_name() {
    // 判据（AS-5 模式 B）：注入的变量名 = secret 名（Coffer 注入 OPENAI_API_KEY 语义），
    // 子进程按 secret 名读取到存储中的值。
    let _g = env_guard();
    let home = temp_dir("run-inject");
    let secret = unique_var("RK");
    let expected = "sk-accept-value-12345";
    let dir = temp_dir("run-inject-child");
    let marker = dir.join("marker");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), expected);

    // 子进程校验注入值并落 marker —— 桩返回 Ok(0) 但从未执行 → 无 marker → 红灯。
    let script = format!(
        "test \"${secret}\" = \"{expected}\" && touch {}",
        marker.display()
    );
    let code = run_sh(&secret, &script).expect("child must run");
    assert_eq!(code, 0);
    assert!(
        marker.exists(),
        "secret must be injected into child env under its own name (AS-5 mode B)"
    );
}

#[test]
fn run_with_secret_rejects_unknown_secret() {
    // 判据：未登记的 secret 不得被使用（默认拒绝）。
    let r = mcp::run_with_secret("NO_SUCH_SECRET_ACCEPT", "sh", &["-c", "true"]);
    assert!(r.is_err(), "unknown secret must be rejected, got Ok({r:?})");
}

#[test]
fn run_with_secret_rejects_missing_command() {
    let r = mcp::run_with_secret("ANY_SECRET", "definitely-not-a-real-cmd-xyz", &[]);
    assert!(r.is_err(), "missing command must be rejected");
}

#[test]
fn run_with_secret_rejects_empty_secret_name() {
    let r = mcp::run_with_secret("", "sh", &["-c", "true"]);
    assert!(r.is_err(), "empty secret name must be rejected");
}

#[test]
fn run_with_secret_rejects_empty_command() {
    let r = mcp::run_with_secret("ANY_SECRET", "", &[]);
    assert!(r.is_err(), "empty command must be rejected");
}

#[test]
fn run_with_secret_nonzero_exit_is_returned_not_error() {
    // 契约：子进程失败 ≠ MCP 调用失败 —— 退出码作为 i32 返回，不吞、不误报 Err。
    // 桩返回 Ok(0) → 断言 Ok(7) 失败 → 红灯。
    let r = mcp::run_with_secret("ANY_SECRET", "sh", &["-c", "exit 7"]);
    match r {
        Ok(code) => assert_eq!(code, 7, "nonzero child exit must propagate, got {code}"),
        Err(e) => panic!("child nonzero exit must NOT surface as Err, got {e:?}"),
    }
}

// ===========================================================================
// grant_secret / revoke_secret（AS-7 授权生命周期）
// ===========================================================================

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn grant_secret_records_allowed_agent_in_metadata() {
    // 判据（AS-7/AS-9）：grant 后 metadata.allowed_agents 必须包含该 agent。
    let _g = env_guard();
    let home = temp_dir("grant");
    let secret = unique("GK");
    let agent = "agent-accept-1";
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), "sk-g");

    mcp::grant_secret(&secret, agent).expect("grant_secret must not error");
    let meta = mcp::get_secret_metadata(&secret).expect("metadata must be queryable");
    // 桩返回空 metadata → 红灯。
    assert!(
        meta.contains(agent),
        "granted agent must appear in metadata.allowed_agents, got {meta:?}"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn grant_secret_rejects_unknown_secret() {
    let r = mcp::grant_secret("NO_SUCH_SECRET_ACCEPT", "agent-x");
    assert!(r.is_err(), "grant of unknown secret must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn grant_secret_rejects_empty_agent() {
    let r = mcp::grant_secret("ANY_SECRET", "");
    assert!(r.is_err(), "empty agent name must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn grant_secret_rejects_empty_secret_name() {
    let r = mcp::grant_secret("", "agent-x");
    assert!(r.is_err(), "empty secret name must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn revoke_secret_removes_allowed_agent() {
    // 判据（AS-7）：revoke 后 metadata.allowed_agents 不再包含该 agent。
    let _g = env_guard();
    let home = temp_dir("revoke");
    let secret = unique("RVK");
    let agent = "agent-accept-2";
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), "sk-r");

    mcp::grant_secret(&secret, agent).expect("grant must succeed");
    // 先断言「已授权」（桩 metadata 为空 → 在此红灯；若此处通过才谈得上撤销后的剔除）。
    let meta_after_grant = mcp::get_secret_metadata(&secret).expect("metadata");
    assert!(
        meta_after_grant.contains(agent),
        "precondition: granted agent in metadata, got {meta_after_grant:?}"
    );

    mcp::revoke_secret(&secret, agent).expect("revoke must succeed");
    let meta_after_revoke = mcp::get_secret_metadata(&secret).expect("metadata");
    assert!(
        !meta_after_revoke.contains(agent),
        "revoked agent must be removed from metadata.allowed_agents, got {meta_after_revoke:?}"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn revoke_secret_rejects_unknown_secret() {
    let r = mcp::revoke_secret("NO_SUCH_SECRET_ACCEPT", "agent-x");
    assert!(r.is_err(), "revoke of unknown secret must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn revoke_secret_rejects_empty_agent() {
    let r = mcp::revoke_secret("ANY_SECRET", "");
    assert!(r.is_err(), "empty agent name must be rejected");
}

// ===========================================================================
// rotate_secret（AS-9 生命周期）
// ===========================================================================

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn rotate_secret_changes_value() {
    // 判据（AS-9）：rotate 后 secret 值必须改变。
    let _g = env_guard();
    let home = temp_dir("rotate");
    let secret = unique_var("ROT");
    let dir = temp_dir("rotate-capture");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), "sk-old-value");

    let before = capture_secret_via_subprocess(&secret, &dir)
        .expect("must be able to observe value before rotate");
    assert_eq!(before, "sk-old-value", "seed value must be served");

    mcp::rotate_secret(&secret).expect("rotate_secret must not error");
    let after = capture_secret_via_subprocess(&secret, &dir)
        .expect("must be able to observe value after rotate");
    assert_ne!(
        before, after,
        "rotated secret value must differ from pre-rotation value"
    );
}

#[test]
#[cfg(feature = "coffer-store")]
fn rotate_secret_new_value_is_generator_strength_not_nonce() {
    // MEDIUM-2（docs/27 裁定 B）facade 侧：rotate 新值不得再是 `rotated-\d+`
    // 时间戳 nonce 形态，须为 Coffer 生成器默认档强随机值（cf_audit
    // `generate_password(PasswordGenOptions::default())`，与 provider 同源，
    // lib.rs mcp facade）。`--no-default-features` 构建下 cf-audit 不在依赖树，
    // 本判据不适用（slim 构建仅门禁验证、facade 为测试种子 mock 不落生产）。
    let _g = env_guard();
    let home = temp_dir("rotate-gen");
    let secret = unique_var("ROTG");
    let dir = temp_dir("rotate-gen-capture");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), "sk-old");

    mcp::rotate_secret(&secret).expect("rotate_secret must not error");
    let after = capture_secret_via_subprocess(&secret, &dir)
        .expect("must be able to observe value after rotate");
    assert!(
        !after.starts_with("rotated-"),
        "轮换新值不得为时间戳 nonce 形态，got: {after}"
    );
    assert!(
        after.len() >= 20,
        "长度须 ≥ 20（生成器默认档），got len={} val={after}",
        after.len()
    );
    assert!(
        after.chars().any(|c| c.is_ascii_digit()),
        "须含数字: {after}"
    );
    assert!(
        after.chars().any(|c| c.is_ascii_lowercase()),
        "须含小写: {after}"
    );
    assert!(
        after.chars().any(|c| c.is_ascii_uppercase()),
        "须含大写: {after}"
    );
    assert!(
        after.chars().any(|c| !c.is_ascii_alphanumeric()),
        "须含符号: {after}"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn rotate_secret_updates_metadata() {
    // 判据（AS-9）：rotate 后 metadata 反映最近轮换（last_rotated_at 等）。
    let _g = env_guard();
    let home = temp_dir("rotate-meta");
    let secret = unique("ROTM");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), "sk-m");

    mcp::rotate_secret(&secret).expect("rotate must not error");
    let meta = mcp::get_secret_metadata(&secret).expect("metadata");
    // 判据（AS-9）：rotate 后 last_rotated_at 须为**非空**时间戳。secret_meta_json
    // 信封恒含 `"last_rotated_at":""` 缺省（tools.rs:190）——仅判键存在是假绿
    // （变异探针实证：移除门面 rotated_at 登记后原断言仍绿），故断言非空。
    assert!(
        !meta.contains("\"last_rotated_at\":\"\""),
        "rotate 后 last_rotated_at 须非空（缺省空串 = 未登记轮换），got {meta:?}"
    );
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn rotate_secret_rejects_unknown_secret() {
    let r = mcp::rotate_secret("NO_SUCH_SECRET_ACCEPT");
    assert!(r.is_err(), "rotate of unknown secret must be rejected");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn rotate_secret_rejects_empty_name() {
    let r = mcp::rotate_secret("");
    assert!(r.is_err(), "empty secret name must be rejected");
}

// ===========================================================================
// get_secret_metadata（AS-9）
// ===========================================================================

#[test]
fn get_secret_metadata_returns_lifecycle_fields() {
    // 判据（AS-9）：metadata 必须含 id/name/type/vault/project/environment/created_at/
    // updated_at/expires_at/rotation_interval/allowed_agents/allowed_actions/
    // last_used_at/last_rotated_at 等生命周期字段。
    let _g = env_guard();
    let home = temp_dir("meta");
    let secret = unique("MET");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), "sk-meta");

    let meta = mcp::get_secret_metadata(&secret).expect("metadata must not error");
    // 桩返回空字符串 → 红灯。
    for field in [
        "id",
        "name",
        "type",
        "vault",
        "project",
        "environment",
        "created_at",
        "updated_at",
        "expires_at",
        "rotation_interval",
        "allowed_agents",
        "allowed_actions",
        "last_used_at",
        "last_rotated_at",
    ] {
        assert!(
            meta.contains(field),
            "metadata must carry AS-9 field {field:?}, got {meta:?}"
        );
    }
}

#[test]
fn get_secret_metadata_never_contains_secret_value() {
    // 判据（AS-14/AS-11）：metadata 不得泄漏明文值 —— 「可用不可见」直接守卫。
    let _g = env_guard();
    let home = temp_dir("meta-noleak");
    let secret = unique("LEAK");
    let value = "sk-super-secret-abcdef123456";
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), value);

    let meta = mcp::get_secret_metadata(&secret).expect("metadata");
    assert!(
        !meta.contains(value),
        "metadata must NEVER contain the raw secret value (AS-14 usable-not-visible)"
    );
}

#[test]
fn get_secret_metadata_rejects_unknown_secret() {
    // 桩返回 Ok("") → 红灯（未知 secret 必须 Err，而非空 metadata 冒充存在）。
    let r = mcp::get_secret_metadata("NO_SUCH_SECRET_ACCEPT");
    assert!(r.is_err(), "metadata of unknown secret must be rejected");
}

#[test]
fn get_secret_metadata_rejects_empty_name() {
    let r = mcp::get_secret_metadata("");
    assert!(r.is_err(), "empty secret name must be rejected");
}

// ===========================================================================
// audit_secret_usage（AS-10）
// ===========================================================================

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn audit_secret_usage_ok_after_use_and_rotate() {
    // 判据（AS-10）：USE / ROTATE 之后审计入口可调用、不报错。
    // 注：桩签名 `-> Result<()>` 无可读审计面 —— 本条仅守「调用不炸」；
    // AS-10 的「审计内容（operation/result）」「永不记录 Secret 值」判据
    // 因缺可观察面**未覆盖**（见文件头台账），待实现提供审计读取接口后补。
    let _g = env_guard();
    let home = temp_dir("audit");
    let secret = unique("AUD");
    std::env::set_var("COFFER_MCP_TEST_HOME", &home);
    std::env::set_var(format!("COFFER_MCP_TEST_SECRET_{secret}"), "sk-audit");

    run_sh(&secret, "true").expect("use must succeed");
    mcp::rotate_secret(&secret).expect("rotate must succeed");
    mcp::audit_secret_usage(&secret).expect("audit_secret_usage must not error");
}

#[test]
// D-1 未确认收缩范围：本用例对应工具顺延 v2.x（docs/20 §1.3/§3.3，用户确认中，保持可逆）。保留为 v2.x 回归基线，不删、不跳过。
fn audit_secret_usage_rejects_unknown_secret() {
    // 桩返回 Ok(()) → 红灯（未知 secret 审计必须 Err）。
    let r = mcp::audit_secret_usage("NO_SUCH_SECRET_ACCEPT");
    assert!(r.is_err(), "audit of unknown secret must be rejected");
}

// ===========================================================================
// 计数口径（lead 指令 ③，复跑核销时回填实际转绿/保留数）
// ===========================================================================
// 总用例 41 条 = 16 条 v0.5 转绿面（D-1 4 工具）+ 25 条 v2.x 保留基线（带
// 「D-1 未确认收缩范围」标记，不删、不跳过）。
//
// v0.5 转绿面（4 工具，16 条，无标记）：
//   list_secret_names       2   list_secrets       2
//   run_with_secret         8   get_secret_metadata 4
//
// v2.x 保留基线（25 条，带标记）：
//   create_environment / list_environments   6
//   mount_environment                        4
//   inject_environment                       2
//   grant_secret                             4
//   revoke_secret                            3
//   rotate_secret                            4
//   audit_secret_usage                       2
//
// 复跑核销表（dev-coder-mcp-core 合入后由 tester 回填）：
//   - 4 工具相关 16 条：____ 转绿 / ____ 仍红
//   - v2.x 保留基线 25 条：保留（顺延不参与 v0.5 门禁；桩实现下仍为预期红灯）
