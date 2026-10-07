//! G-B browser 子命令集成测试（docs/32 §1.2 G-B 判据，7 条）。
//!
//! spawn 编译产物 `coffer` 二进制（`env!("CARGO_BIN_EXE_coffer")`，沿用
//! tests/cli.rs 惯例），驱动 `browser-agent` / `browser-broker` 子命令。
//!
//! E2E 会话用 cf-browser 的 [`InitiatorHandshake`] + [`Session`] **真实驱动**
//!（dev-dependency）：测试作为「扩展侧」走完整 IKpsk2 风格握手 + AEAD 帧，
//! 对 broker 的请求/响应逐字节走真协议（非桩）。会话与其 UDS 连接一一对应
//!（broker 单连接单会话，docs/31 §3.1 第 3 段）。
//!
//! 判据来源（docs/32 §1.2）：
//! 1. `subcommand_dispatch` —— 子命令分发 + 未知子命令退出码 + `mcp` 回归
//! 2. `host_rejects_unsigned_parent` —— ② 层验父进程 fail-closed（8001）
//! 3. `broker_uds_bind_and_permissions` —— UDS bind + socket 0600/父目录 0700 +
//!    缺 `--uds` → 配置错 1
//! 4. `broker_rejects_unverified_host` —— ③ 层验 peer fail-closed（8002）
//! 5. `broker_locked_state` —— broker 无解锁会话 → get_secret → broker_locked（8003）
//! 6. `exit_code_contract` —— 退出码 0/1/2/3 契约
//! 7. `slim_build_subcommands_not_registered` —— `--no-default-features` 门控
//!    fail-closed（docs/32 §8 #1 裁决）
//!
//! 另含 `broker_get_entries_unlocked`（G-B「broker 需处理 GetEntries」的端到端
//! 验证：解锁态 get_entries → EntriesResult，走真 E2E 通道）。
//!
//! 平台门控：browser-* 子命令仅 `feature="coffer-store"` + macOS 构建注册
//!（cli.rs `mod browser` 双门控）。故依赖真实子命令的测试以
//! `#[cfg(feature = "coffer-store")]` 编译门控；`slim_build_subcommands_not_registered`
//! 用运行时 `cfg!` 断言两构建面行为。

use std::path::PathBuf;
use std::process::{Command, Stdio};

// 以下 import 仅 `#[cfg(feature = "coffer-store")]` 测试/helper 使用（slim 面不
// 注册 browser 子命令，无 E2E 客户端/连接）；不门控会在 `--no-default-features`
// 编译面报 unused import。
#[cfg(feature = "coffer-store")]
use std::io::{Read, Write};
#[cfg(feature = "coffer-store")]
use std::os::unix::fs::PermissionsExt;
#[cfg(feature = "coffer-store")]
use std::os::unix::net::UnixStream;
#[cfg(feature = "coffer-store")]
use std::path::Path;
#[cfg(feature = "coffer-store")]
use std::process::Child;
#[cfg(feature = "coffer-store")]
use std::time::{Duration, Instant};
#[cfg(feature = "coffer-store")]
use cf_browser::e2e::Session;
#[cfg(feature = "coffer-store")]
use cf_browser::protocol::{AppMessage, AppRequest, AppResponse, EntryFieldRef};

// ---------------- 共享：spawn 助手 / 帧读写 / socket 等待 ----------------

/// 编译产物 `coffer` 二进制路径（tests/cli.rs 同款）。
#[cfg(feature = "coffer-store")]
fn coffer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_coffer")
}

/// 独立测试目录（沿用 tests/cli.rs `temp_dir` 模式）。
///
/// **路径必须短**：broker UDS 受 macOS AF_UNIX `SUN_LEN`（104 字节）上限约束，
/// socket 落在 `<tmp>/broker/coffer.sock` 时全路径须 < 104（实测时间戳后缀
/// 16 hex + 长前缀会超限，bind 报 `path must be shorter than SUN_LEN`）。
/// 用进程内原子计数器 + pid 保证并行测试不撞目录（远短于时间戳后缀），
/// 前缀 `cfb-` 简洁。
fn temp_dir(tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("cfb-{tag}-{}-{n}", std::process::id()))
}

/// 确定性 fake pairing 材料（测试注入 broker 解锁契约）：
/// `(dek_hex, vault_uuid_hex, psk_hex)`。
///
/// **不设 cfg 门控**：`slim_build_subcommands_not_registered`（无 cfg 门控，两构建
/// 面都跑）在运行时 `cfg!` 分支里调用它——`cfg!` 是运行时求值，代码两编译面都必须
/// 存在，门控会致 slim 面 E0425。纯确定性 helper，default/slim 面共用无副作用。
fn fake_secrets() -> (String, String, String) {
    let dek = "a1".repeat(32); // 64 hex = 32 字节
    let uuid = "b2".repeat(16); // 32 hex = 16 字节
    let psk = "c3".repeat(32); // 64 hex = 32 字节
    (dek, uuid, psk)
}

/// 移除所有 `COFFER_BROKER_*` env（测试隔离：stdin 用例须确保不走 env 降级路径，
/// HIGH2-3 §3.4——env 回退仅 `COFFER_BROKER_SKIP_PEER_VERIFY=1` 且 debug 构建生效）。
#[cfg(feature = "coffer-store")]
fn clear_broker_env(cmd: &mut Command) {
    for key in [
        "COFFER_BROKER_UDS",
        "COFFER_BROKER_DEK_HEX",
        "COFFER_BROKER_VAULT_UUID_HEX",
        "COFFER_BROKER_PSK_HEX",
        "COFFER_BROKER_UNLOCKED",
        "COFFER_BROKER_SKIP_PEER_VERIFY",
        "COFFER_BROKER_REQUIREMENT",
        "COFFER_BROKER_ENTRIES_JSON",
    ] {
        cmd.env_remove(key);
    }
}

/// spawn `coffer browser-broker --uds <uds> --log <log>` + pairing env（**env 降级**）。
///
/// - `overrides`：追加/覆盖环境变量（如 `COFFER_BROKER_UNLOCKED` /
///   `COFFER_BROKER_ENTRIES_JSON`）；
/// - `omit_skip_verify`：`true` 时不设 `COFFER_BROKER_SKIP_PEER_VERIFY=1`
///   （③ 层签名校验恒开 → 伪造 peer 被拒，测 8002 用）。
///
/// env 降级仅 `cfg!(debug_assertions)` 生效（release inert）；本 helper 仅用于
/// 需要 env 注入的用例（§6-5：env 用例统一在 `COFFER_BROKER_SKIP_PEER_VERIFY=1`
/// 下运行）。
#[cfg(feature = "coffer-store")]
fn spawn_broker(uds: &Path, log: &Path, overrides: &[(&str, &str)], omit_skip_verify: bool) -> Child {
    let (dek, uuid, psk) = fake_secrets();
    let mut cmd = Command::new(coffer_bin());
    cmd.args(["browser-broker", "--uds"])
        .arg(uds)
        .args(["--log"])
        .arg(log);
    clear_broker_env(&mut cmd);
    cmd.env("COFFER_BROKER_DEK_HEX", &dek)
        .env("COFFER_BROKER_VAULT_UUID_HEX", &uuid)
        .env("COFFER_BROKER_PSK_HEX", &psk);
    if !omit_skip_verify {
        cmd.env("COFFER_BROKER_SKIP_PEER_VERIFY", "1");
    }
    for (k, v) in overrides {
        cmd.env(k, v);
    }
    cmd.stderr(Stdio::piped()).stdout(Stdio::piped());
    cmd.spawn().expect("spawn browser-broker")
}

/// 标准 4 行 stdin 帧（HIGH2-3 §3.1；`unlocked` 取 `"1"` / `"0"`）。
#[cfg(feature = "coffer-store")]
fn stdin_frame(unlocked: &str) -> String {
    let (dek, uuid, psk) = fake_secrets();
    format!(
        "DEK_HEX={dek}\nVAULT_UUID_HEX={uuid}\nPSK_HEX={psk}\nUNLOCKED={unlocked}\n"
    )
}

/// spawn `coffer browser-broker --uds <uds> --log <log>`，解锁契约经 **stdin 私有
/// 管道**交付（HIGH2-3 §3.3，生产路径）：写 `stdin_lines` 后 **close stdin**
///（App 契约：写完 close → broker 即时 EOF）。`None` = 无内容即时 close（→ EOF，
/// TC-BROKER-1）。**不设任何 `COFFER_BROKER_*` env**（清空隔离，防走 env 降级）。
#[cfg(feature = "coffer-store")]
fn spawn_broker_stdin(
    uds: &Path,
    log: &Path,
    stdin_lines: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Child {
    let mut cmd = Command::new(coffer_bin());
    cmd.args(["browser-broker", "--uds"])
        .arg(uds)
        .args(["--log"])
        .arg(log);
    clear_broker_env(&mut cmd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped()).stderr(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn browser-broker");
    let mut child_stdin = child.stdin.take().expect("stdin pipe");
    if let Some(lines) = stdin_lines {
        child_stdin
            .write_all(lines.as_bytes())
            .expect("write stdin frame");
    }
    drop(child_stdin); // close stdin（写入端）→ broker 读到 EOF
    child
}

/// 读一个 native messaging 帧（4B LE + payload），返回 payload。EOF → `None`。
#[cfg(feature = "coffer-store")]
fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if let Err(e) = r.read_exact(&mut len_buf) {
        return if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// 写一个 native messaging 帧（4B LE + payload），写后 flush。
#[cfg(feature = "coffer-store")]
fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// 轮询等待 socket 文件出现且权限收敛到 `expected_mode`（bind 先以 umask 默认建
/// 文件、随后 `set_permissions 0600`——存在短暂窗口，须等收敛；tests/uds.rs 同款）。
#[cfg(feature = "coffer-store")]
fn wait_for_socket_mode(path: &Path, expected_mode: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(meta) = std::fs::metadata(path) {
            if (meta.permissions().mode() & 0o777) == expected_mode {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// 读子进程 stderr 全文（测试断言用）。子进程可能仍存活，先尝试读再 wait。
#[cfg(feature = "coffer-store")]
fn drain_stderr(child: &mut Child) -> String {
    let mut buf = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut buf);
    }
    buf
}

/// 等待子进程退出并返回退出码（带超时，防挂死）。
#[cfg(feature = "coffer-store")]
fn wait_timeout(child: &mut Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code();
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ===========================================================================
// 判据 1：子命令分发（docs/32 §1.2-1）
// ===========================================================================

/// `browser-agent` / `browser-broker` 进入对应分支（stderr 断言分支特征），
/// 未知子命令 → 契约退出码 1，`mcp` 既有路径回归不破。
#[test]
#[cfg(feature = "coffer-store")]
fn subcommand_dispatch() {
    // browser-broker：缺 --uds → 进入浏览器分支（stderr 特征）+ 配置错 1。
    let out = Command::new(coffer_bin())
        .arg("browser-broker")
        .stderr(Stdio::piped())
        .output()
        .expect("run browser-broker");
    assert_eq!(out.status.code(), Some(1), "缺 --uds → 配置错 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("browser broker"), "进入 browser-broker 分支: {err}");
    assert!(err.contains("--uds"), "提示缺 --uds: {err}");

    // browser-agent：父进程非签名浏览器（测试进程）→ 8001 拒签（进入分支 + fail-closed）。
    let out = Command::new(coffer_bin())
        .arg("browser-agent")
        .stderr(Stdio::piped())
        .output()
        .expect("run browser-agent");
    assert_eq!(out.status.code(), Some(1), "8001 拒签 → 退出 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("8001"), "browser-agent 分支 8001 特征: {err}");
    assert!(!err.contains("unknown subcommand"), "不得落入未知子命令: {err}");

    // 未知子命令 → 契约退出码 1 + unknown-subcommand 特征（cli.rs:617 路径）。
    let out = Command::new(coffer_bin())
        .arg("bogus-subcommand")
        .stderr(Stdio::piped())
        .output()
        .expect("run bogus subcommand");
    assert_eq!(out.status.code(), Some(1), "未知子命令 → 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown subcommand"), "unknown-subcommand: {err}");

    // `coffer mcp` 既有路径回归：未知 flag → 配置错 1（mcp 分支可达）。
    let out = Command::new(coffer_bin())
        .arg("mcp")
        .arg("--bogus-flag")
        .stderr(Stdio::piped())
        .output()
        .expect("run mcp bogus flag");
    assert_eq!(out.status.code(), Some(1), "mcp 未知 flag → 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown flag"), "mcp 分支回归: {err}");
}

// ===========================================================================
// 判据 2：host 验父进程 fail-closed（docs/32 §1.2-2，8001）
// ===========================================================================

/// 父进程非签名浏览器（测试进程 = 伪造上下文）→ `browser-agent` 拒绝服务并退出，
/// stderr 断言 8001（自动段可伪造断言；签名浏览器父进程为 P-S 真机判据）。
#[test]
#[cfg(feature = "coffer-store")]
fn host_rejects_unsigned_parent() {
    let out = Command::new(coffer_bin())
        .arg("browser-agent")
        .stderr(Stdio::piped())
        .output()
        .expect("run browser-agent");
    assert_eq!(out.status.code(), Some(1), "拒签退出 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("8001"), "stderr 断言 8001: {err}");
    assert!(
        !err.contains("unknown subcommand"),
        "须进入浏览器分支（非未知子命令）: {err}"
    );
}

// ===========================================================================
// 判据 3：broker --uds 起服务 + UDS 权限（docs/32 §1.2-3）
// ===========================================================================

/// broker bind UDS：socket 0600、自建父目录 0700；缺 `--uds` → 配置错 1。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_uds_bind_and_permissions() {
    let dir = temp_dir("broker-uds");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    // socket 放 <tmp>/broker/coffer.sock：broker 自建 broker/ 子目录（0700）。
    let broker_dir = dir.join("broker");
    let uds = broker_dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let mut child = spawn_broker(&uds, &log, &[], false);
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未在超时内出现并收敛 0600: {}",
        uds.display()
    );

    // socket 0600。
    let mode = std::fs::metadata(&uds)
        .expect("socket metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "socket 权限须 0600, got {:o}", mode);
    // 自建父目录 0700。
    let dir_mode = std::fs::metadata(&broker_dir)
        .expect("broker dir metadata")
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o700, "父目录权限须 0700, got {:o}", dir_mode);

    // 停止 broker（无 Lock 通道时的生命周期由 App 侧 kill；测试 kill 收尾）。
    child.kill().expect("kill broker");
    let _ = child.wait();
    let _ = log;
}

/// 缺 `--uds` → 配置错误退出 1（判据 3 后半 + 判据 6 的「缺 UDS」）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_missing_uds_is_config_error() {
    let out = Command::new(coffer_bin())
        .arg("browser-broker")
        .stderr(Stdio::piped())
        .output()
        .expect("run browser-broker");
    assert_eq!(out.status.code(), Some(1), "缺 --uds → 配置错 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--uds"), "提示缺 --uds: {err}");
}

// ===========================================================================
// 判据 4：broker 验 peer host fail-closed（docs/32 §1.2-4，8002）
// ===========================================================================

/// 伪造 peer（测试进程 = 非嵌套 bundle coffer 二进制）连 broker → ③ 层拒连，
/// stderr 断言 8002，连接被关闭（自动段伪造断言；真机签名链为 P-S 判据）。
///
/// 解锁契约走 **stdin 私有管道**（生产路径）、**不设** `COFFER_BROKER_SKIP_PEER_VERIFY`
/// → ③ 层签名校验恒开（SKIP env 同时门控 env 降级，8002 用例须走 stdin 才能
/// 保持 ③ 层真实，HIGH2-3 §6.5）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_rejects_unverified_host() {
    let dir = temp_dir("broker-8002");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // stdin 注入配对材料（不设 COFFER_BROKER_* env）→ ③ 层签名校验恒开。
    let mut child = spawn_broker_stdin(&uds, &log, Some(&stdin_frame("1")), &[]);
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );

    // 伪造 peer：裸 UnixStream（测试进程，无 coffer 签名）。
    let mut stream = UnixStream::connect(&uds).expect("connect broker");
    // broker 验 peer 后拒连 → 读到 EOF（连接被关闭）。
    let mut probe = [0u8; 1];
    let eof = stream
        .read(&mut probe)
        .map(|n| n == 0)
        .unwrap_or_else(|e| e.kind() == std::io::ErrorKind::UnexpectedEof);
    assert!(eof, "伪造 peer 的连接应被 broker 关闭");

    // 先 kill broker 再读日志：`--log` 已指定 → 8002 落 broker.log 而非 stderr；
    // 且 daemon 存活时 stderr 管道不关，read_to_string 会永久阻塞（拒连是已处理
    // 事件，daemon 继续 accept）。
    let _ = child.kill();
    let _ = child.wait();
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(log_text.contains("8002"), "日志断言 8002: {log_text}");
}

// ===========================================================================
// HIGH-1 release-inert 行为验证（M-3）：release 构建下 ③ 层旋钮无效果
// ===========================================================================

/// release 构建（`not(debug_assertions)`）下，即使显式设置
/// `COFFER_BROKER_SKIP_PEER_VERIFY=1`（模拟 HIGH-1 攻击链：同用户
/// `launchctl setenv` → GUI App 继承 env → broker spawn 继承），broker 仍必须
/// 走 ③ 层 peer 签名校验 → 伪造 peer（裸 UnixStream，无 coffer 签名）被拒
/// （8002）。证明 M-3 旋钮 **release 编译期剔除、生产不可达**。
///
/// 编译期 `not(debug_assertions)` 门控：仅 `cargo test --release` 编译并运行；
/// debug 构建此用例不存在（debug 下 ③ 恒开的对应用例是
/// `broker_rejects_unverified_host`，无 SKIP env）。
#[test]
#[cfg(all(feature = "coffer-store", not(debug_assertions)))]
fn release_broker_skips_nothing_when_env_set() {
    let dir = temp_dir("broker-release-inert");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // stdin 交付配对材料（release 下 env 降级恒走不通）+ 显式 SKIP=1 继承链。
    let mut child = spawn_broker_stdin(
        &uds,
        &log,
        Some(&stdin_frame("1")),
        &[("COFFER_BROKER_SKIP_PEER_VERIFY", "1")],
    );
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );

    // 伪造 peer：裸 UnixStream（测试进程，无 coffer 签名）。release 下 SKIP=1
    // 必须无效，③ 层仍拒连 → EOF。
    let mut stream = UnixStream::connect(&uds).expect("connect broker");
    let mut probe = [0u8; 1];
    let eof = stream
        .read(&mut probe)
        .map(|n| n == 0)
        .unwrap_or_else(|e| e.kind() == std::io::ErrorKind::UnexpectedEof);
    assert!(eof, "release 下 SKIP=1 无效，伪造 peer 应被 ③ 层拒连");

    let _ = child.kill();
    let _ = child.wait();
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(log_text.contains("8002"), "release 下 8002 仍落日志: {log_text}");
}

// ===========================================================================
// 判据 5：broker 无解锁会话 → broker_locked（docs/32 §1.2-5，8003）
// ===========================================================================

/// broker 无解锁会话（pairing 材料齐、`COFFER_BROKER_UNLOCKED` 缺省）→
/// 走真 E2E：握手建立会话，`get_secret` → [`AppResponse::BrokerLocked`]，
/// 随后 `lock` → `Locked` 响应 + broker 干净退出 0。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_locked_state() {
    let dir = temp_dir("broker-8003");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // 锁定态：不设 COFFER_BROKER_UNLOCKED。
    let mut child = spawn_broker(&uds, &log, &[], false);
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );

    // 扩展侧：真 E2E 客户端（会话与其 UDS 流绑定）。
    let (mut session, mut stream) = e2e_client(&uds, &mut child);

    // get_secret（锁定态）→ broker_locked。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 1,
        entry: "e1".into(),
        fields: vec!["username".into(), "password".into()],
        origin: "https://github.com".into(),
        gesture: "test-gesture".into(),
    });
    write_frame(&mut stream, &session.encrypt(&req).expect("encrypt get_secret"))
        .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 broker_locked");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    assert!(
        matches!(resp, AppMessage::Response(AppResponse::BrokerLocked)),
        "锁定态 get_secret → broker_locked: {resp:?}"
    );

    // lock → Locked + broker 干净退出 0。
    let lock = session
        .encrypt(&AppMessage::Request(AppRequest::Lock))
        .expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let lock_payload = read_frame(&mut stream)
        .expect("read lock response")
        .expect("broker 须响应 Locked");
    let lock_resp: AppMessage = session.decrypt(&lock_payload).expect("decrypt lock response");
    assert!(
        matches!(lock_resp, AppMessage::Response(AppResponse::Locked)),
        "lock → Locked: {lock_resp:?}"
    );

    // broker 杀进程（docs/31 §4.1）→ 退出 0。
    let code = wait_timeout(&mut child, Duration::from_secs(10))
        .expect("broker 应在 lock 后退出（未挂死）");
    assert_eq!(code, 0, "lock → 干净退出 0");
    let _ = log;
}

// ===========================================================================
// GetEntries 端到端（G-B「broker 需处理 GetEntries」，docs/31 §5.2）
// ===========================================================================

/// 解锁态（`COFFER_BROKER_UNLOCKED=1` + 条目夹具）下 `get_entries` → 真 E2E 返回
/// `EntriesResult`（夹具条目逐字段断言）；同时断言解锁态 `get_secret` 当前为
/// G-B 版契约（8003 `BrokerUnavailable` 未接线，vault 集成 = G-D/G-T merge-time 点）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_get_entries_unlocked() {
    let dir = temp_dir("broker-entries");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // fields 结构化（lead 裁定 2026-10-08）：`Vec<EntryFieldRef{name, designation}>`，
    // designation 为 cf-domain adjacently-tagged 序列化 `{"kind": "..."}`。
    let fixture = r#"[{"entry":"e1","title":"GitHub","category":"login","fields":[{"name":"username","designation":{"kind":"username"}},{"name":"password","designation":{"kind":"password"}}]},{"entry":"e2","title":"AWS Console","category":"api_credential","fields":[{"name":"username","designation":{"kind":"username"}},{"name":"password","designation":{"kind":"password"}},{"name":"secret_key","designation":{"kind":"other","value":"secret_key"}}]}]"#;
    let mut child = spawn_broker(
        &uds,
        &log,
        &[("COFFER_BROKER_UNLOCKED", "1"), ("COFFER_BROKER_ENTRIES_JSON", fixture)],
        false,
    );
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );

    let (mut session, mut stream) = e2e_client(&uds, &mut child);

    // get_entries → EntriesResult（夹具逐字段；不带 gesture，lead 裁定）。
    let req = AppMessage::Request(AppRequest::GetEntries {
        origin: "https://github.com".into(),
    });
    write_frame(&mut stream, &session.encrypt(&req).expect("encrypt get_entries"))
        .expect("write get_entries");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 entries_result");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::EntriesResult { entries }) = resp else {
        panic!("解锁态 get_entries → EntriesResult, got: {resp:?}");
    };
    assert_eq!(entries.len(), 2, "夹具两条");
    assert_eq!(entries[0].entry, "e1");
    assert_eq!(entries[0].title, "GitHub");
    assert_eq!(entries[0].category, cf_domain::category::ItemCategory::Login);
    assert_eq!(
        entries[0].fields,
        vec![
            EntryFieldRef {
                name: "username".into(),
                designation: cf_domain::field::Designation::Username,
            },
            EntryFieldRef {
                name: "password".into(),
                designation: cf_domain::field::Designation::Password,
            },
        ]
    );
    assert_eq!(
        entries[1].category,
        cf_domain::category::ItemCategory::ApiCredential
    );

    // 解锁态 get_secret：G-B 版契约 = 8003 未接线（操作不可用，docs/03 §12
    // `BrokerUnavailable`；vault 集成 = G-D/G-T merge-time）。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 2,
        entry: "e1".into(),
        fields: vec!["password".into()],
        origin: "https://github.com".into(),
        gesture: "test-gesture".into(),
    });
    write_frame(&mut stream, &session.encrypt(&req).expect("encrypt get_secret"))
        .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::Error { code, .. }) = resp else {
        panic!("解锁态 get_secret（G-B 版）→ Error, got: {resp:?}");
    };
    assert_eq!(code, 8003, "G-B 版取密未接线 → 8003 BrokerUnavailable");

    // 收尾：lock → 干净退出 0。
    let lock = session
        .encrypt(&AppMessage::Request(AppRequest::Lock))
        .expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let _ = read_frame(&mut stream).expect("read lock response");
    let code = wait_timeout(&mut child, Duration::from_secs(10))
        .expect("broker 应在 lock 后退出（未挂死）");
    assert_eq!(code, 0, "lock → 干净退出 0");
    let _ = log;
}

// ===========================================================================
// 判据 6：退出码契约 0/1/2/3（docs/32 §1.2-6）
// ===========================================================================

/// 复用 cli::exit_code 语义的进程级断言：
/// - 1 配置错：缺 `--uds` / 缺 pairing env（fail-closed）——进程级断言；
/// - 0 干净：lock 后干净退出（broker_locked_state 覆盖，此处重申语义）；
/// - 2 协议致命 / 3 身份缺失：映射经 cli::exit_code 常量直连，浏览器面无法在本机
///   伪造触发（accept 致命 / 身份派生失败），以常量同一性断言锚定
///   （`exit_code_constants_aligned`）。
#[test]
#[cfg(feature = "coffer-store")]
fn exit_code_contract() {
    let dir = temp_dir("exit-code");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");

    // 1. 缺 pairing env（fail-closed）→ 1。env 用例统一在
    //    COFFER_BROKER_SKIP_PEER_VERIFY=1 下运行（§6-5；缺 SKIP 门控 → 走 stdin
    //    源，语义不同，非本判据）。
    let (dek, uuid, psk) = fake_secrets();
    let out = Command::new(coffer_bin())
        .args(["browser-broker", "--uds"])
        .arg(&uds)
        .env("COFFER_BROKER_DEK_HEX", &dek)
        .env("COFFER_BROKER_VAULT_UUID_HEX", &uuid)
        // 故意缺 COFFER_BROKER_PSK_HEX
        .env("COFFER_BROKER_SKIP_PEER_VERIFY", "1")
        .stderr(Stdio::piped())
        .output()
        .expect("run broker missing psk");
    assert_eq!(out.status.code(), Some(1), "缺 pairing env → 配置错 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("pairing"), "提示缺 pairing: {err}");
    assert!(err.contains("COFFER_BROKER"), "提示 env 名: {err}");

    // 2. 缺 --uds（有 pairing env）→ 1。
    let out = Command::new(coffer_bin())
        .arg("browser-broker")
        .env("COFFER_BROKER_DEK_HEX", &dek)
        .env("COFFER_BROKER_VAULT_UUID_HEX", &uuid)
        .env("COFFER_BROKER_PSK_HEX", &psk)
        .env("COFFER_BROKER_SKIP_PEER_VERIFY", "1")
        .stderr(Stdio::piped())
        .output()
        .expect("run broker missing uds");
    assert_eq!(out.status.code(), Some(1), "缺 --uds → 配置错 1");

    // 3. 0 / 2 / 3 契约锚定：见 `exit_code_constants_aligned`。
    let _ = dir;
}

/// 浏览器面退出码与 cli::exit_code 常量同一性（2 协议致命 / 3 身份缺失的契约
/// 锚定：browser 模块不发明新码，直用既有四常量）。
#[test]
#[cfg(feature = "coffer-store")]
fn exit_code_constants_aligned() {
    assert_eq!(cf_mcp::cli::exit_code::CLEAN, 0);
    assert_eq!(cf_mcp::cli::exit_code::CONFIG_ERROR, 1);
    assert_eq!(cf_mcp::cli::exit_code::PROTOCOL_FATAL, 2);
    assert_eq!(cf_mcp::cli::exit_code::IDENTITY_MISSING, 3);
}

// ===========================================================================
// 判据 7：slim build 门控 fail-closed（docs/32 §8 #1 裁决）
// ===========================================================================

/// `--no-default-features`（feature="coffer-store" 关闭）下 browser-* 不注册
/// → 走既有 unknown-subcommand 分支（cli.rs:617）退出码契约 fail-closed；
/// default 面两子命令注册、行为正常。运行时 `cfg!` 覆盖两构建面。
#[test]
fn slim_build_subcommands_not_registered() {
    let dir = temp_dir("slim-gate");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");

    if cfg!(feature = "coffer-store") {
        // default 面：browser-broker 注册（缺 PSK → 配置错 1 + 分支特征，非未知子命令）。
        // env 用例统一在 COFFER_BROKER_SKIP_PEER_VERIFY=1 下运行（§6-5）。
        let (dek, uuid, _psk) = fake_secrets();
        let out = Command::new(env!("CARGO_BIN_EXE_coffer"))
            .args(["browser-broker", "--uds"])
            .arg(&uds)
            .env("COFFER_BROKER_DEK_HEX", &dek)
            .env("COFFER_BROKER_VAULT_UUID_HEX", &uuid)
            // 缺 PSK → fail-closed 配置错 1（证明进入浏览器分支）
            .env("COFFER_BROKER_SKIP_PEER_VERIFY", "1")
            .stderr(Stdio::piped())
            .output()
            .expect("run broker");
        assert_eq!(out.status.code(), Some(1));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("browser broker"), "default 面注册: {err}");
        assert!(!err.contains("unknown subcommand"), "不得走未知子命令: {err}");
    } else {
        // slim（no-default）：两子命令不注册 → unknown-subcommand fail-closed 退出 1。
        for sub in ["browser-agent", "browser-broker"] {
            let out = Command::new(env!("CARGO_BIN_EXE_coffer"))
                .arg(sub)
                .stderr(Stdio::piped())
                .output()
                .expect("run slim subcommand");
            assert_eq!(out.status.code(), Some(1), "slim 面 `{sub}` → 配置错 1");
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(err.contains("unknown subcommand"), "slim 面未知子命令: {err}");
        }
    }
    let _ = dir;
}

// ===========================================================================
// HIGH2-3 stdin 私有管道判据（TC-BROKER-1/2/3/4，docs/31 r0.7 冻结协议）
// ===========================================================================

/// TC-BROKER-1（HIGH2-3 §7）：无 stdin 内容 spawn `browser-broker --uds` → exit 1，
/// **无 socket 残留**（fail-closed 不留 socket；stdin 读取先于 bind，顺序敏感 §6.3）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_no_stdin_fails_closed_no_socket() {
    let dir = temp_dir("broker-no-stdin");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // 无 stdin 内容（pipe 即 close → 即时 EOF）：缺配对材料 → fail-closed 1。
    let mut child = spawn_broker_stdin(&uds, &log, None, &[]);
    let code = wait_timeout(&mut child, Duration::from_secs(15))
        .expect("broker 应在缺 stdin 材料时退出（未挂死）");
    assert_eq!(code, 1, "缺 stdin 配对材料 → 配置错 1");

    // 诊断走 `--log` 文件（broker 缺省日志纪律），断言缺 pairing 特征。
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(log_text.contains("pairing"), "日志提示缺 pairing: {log_text}");
    assert!(
        !uds.exists(),
        "fail-closed 不得留 socket: {}",
        uds.display()
    );
}

/// TC-BROKER-2（HIGH2-3 §7）：stdin 4 行正确 → broker 绑定 UDS、日志 `locked=false`
///（UNLOCKED=1 解锁态，可服务 app 请求）。well-known 落点公式本身由 TC-PATH /
/// TC-HOST-1 单元测试覆盖；此处绑临时路径避免污染真实主目录（App 生产经
/// `--uds <well-known>` 传参，HIGH2-3 §4.1）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_stdin_valid_binds_and_locked_false() {
    let dir = temp_dir("broker-stdin-ok");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let mut child = spawn_broker_stdin(&uds, &log, Some(&stdin_frame("1")), &[]);
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );
    let mode = std::fs::metadata(&uds)
        .expect("socket metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "socket 权限须 0600, got {:o}", mode);

    // 日志 locked=false（解锁态）。
    let _ = child.kill();
    let _ = child.wait();
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        log_text.contains("locked=false"),
        "日志断言 locked=false: {log_text}"
    );
}

/// TC-BROKER-3（HIGH2-3 §7）：stdin 含非法 hex / 未知 key / 超 4 KiB 缓冲 → exit 1
///（fail-closed 配置错），无 socket 残留。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_stdin_invalid_fails_closed() {
    let dir = temp_dir("broker-stdin-bad");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let log = dir.join("broker.log");

    let (dek, uuid, psk) = fake_secrets();
    // (a) 非法 hex（DEK_HEX 全 z，非 hex 字符）→ 1。
    let bad_hex = format!(
        "DEK_HEX={}\nVAULT_UUID_HEX={uuid}\nPSK_HEX={psk}\nUNLOCKED=1\n",
        "zz".repeat(32)
    );
    // (b) 未知 key（`FOO=bar`，key 大小写敏感白名单外）→ 1。
    let unknown_key = format!(
        "DEK_HEX={dek}\nVAULT_UUID_HEX={uuid}\nPSK_HEX={psk}\nFOO=bar\nUNLOCKED=1\n"
    );
    // (c) 超 4 KiB 缓冲（防灌，HIGH2-3 §3.1）→ 1。
    let oversized = stdin_frame("1") + &"x".repeat(5 * 1024);

    for (tag, frame) in [("bad-hex", bad_hex), ("unknown-key", unknown_key), ("oversized", oversized)] {
        let uds = dir.join(format!("{tag}.sock"));
        let mut child = spawn_broker_stdin(&uds, &log, Some(&frame), &[]);
        let code = wait_timeout(&mut child, Duration::from_secs(15))
            .unwrap_or_else(|| panic!("[{tag}] broker 应 fail-closed 退出（未挂死）"));
        assert_eq!(code, 1, "[{tag}] 非法 stdin → 配置错 1");
        assert!(
            !uds.exists(),
            "[{tag}] fail-closed 不得留 socket: {}",
            uds.display()
        );
    }
}

/// TC-BROKER-4（HIGH2-3 §7，HIGH-3 核销）：`ps eww <broker_pid>` 不含
/// `COFFER_BROKER_*`、无密钥材料——密钥经 stdin 私有管道交付，绝不落 env / argv /
/// 日志（`ps eww` 同用户可读 env，即 HIGH-3 泄露面）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_stdin_secrets_not_in_ps_env() {
    let dir = temp_dir("broker-psenv");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let mut child = spawn_broker_stdin(&uds, &log, Some(&stdin_frame("1")), &[]);
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );

    // ps eww <pid>（macOS BSD 语法）：显示进程 env（同用户可读）。
    let out = Command::new("ps")
        .arg("eww")
        .arg(child.id().to_string())
        .output()
        .expect("run ps eww");
    let ps = String::from_utf8_lossy(&out.stdout);
    assert!(
        !ps.contains("COFFER_BROKER"),
        "ps env 不得含 COFFER_BROKER_*: {ps}"
    );
    let (dek, uuid, psk) = fake_secrets();
    for material in [&dek, &uuid, &psk] {
        assert!(
            !ps.contains(material.as_str()),
            "ps env 不得含密钥材料（HIGH-3）: {ps}"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = log;
}

// ===========================================================================
// E2E 客户端助手（扩展侧：InitiatorHandshake + Session，真协议）
// ===========================================================================

/// 建立到 broker 的真 E2E 会话：连接 UDS → IKpsk2 三消息握手（pin broker 公钥，
/// 从同一 fake pairing 材料派生）→ 返回 `(Session, UnixStream)`——会话与其 UDS
/// 流绑定，调用方用同一流收发后续 AEAD 帧（broker 单连接单会话）。
///
/// 握手失败时把 broker stderr 并入 panic 消息（中途异常诊断）。
#[cfg(feature = "coffer-store")]
fn e2e_client(uds: &Path, child: &mut Child) -> (Session, UnixStream) {
    use cf_browser::broker::BrokerIdentity;
    use cf_browser::e2e::InitiatorHandshake;
    use cf_browser::protocol::HandshakeMessage;

    let (dek, uuid, psk) = fake_secrets();
    let dek_arr: [u8; 32] = cf_browser::e2e::from_hex(&dek)
        .expect("dek hex")
        .try_into()
        .expect("dek len");
    let uuid_arr: [u8; 16] = cf_browser::e2e::from_hex(&uuid)
        .expect("uuid hex")
        .try_into()
        .expect("uuid len");
    let psk_arr: [u8; 32] = cf_browser::e2e::from_hex(&psk)
        .expect("psk hex")
        .try_into()
        .expect("psk len");

    // pin broker 静态公钥（同源派生，BrokerIdentity::derive 确定性）。
    let identity = BrokerIdentity::derive(&dek_arr, &uuid_arr).expect("derive identity");
    let pk_b = identity.public_key();

    let mut stream = UnixStream::connect(uds).expect("connect broker uds");

    // msg1 → msg2 → msg3。
    let (handshake, msg1) = InitiatorHandshake::new(psk_arr, pk_b).expect("initiator");
    write_frame(&mut stream, &serde_json::to_vec(&msg1).expect("msg1 json")).expect("write msg1");
    let msg2_payload = read_frame(&mut stream)
        .expect("read msg2")
        .unwrap_or_else(|| panic!("broker 未响应 msg2（stderr: {}）", drain_stderr(child)));
    let msg2: HandshakeMessage = serde_json::from_slice(&msg2_payload).expect("parse msg2");
    let (msg3, session) = handshake.on_response(&msg2).expect("on_response");
    write_frame(&mut stream, &serde_json::to_vec(&msg3).expect("msg3 json")).expect("write msg3");

    (session, stream)
}
