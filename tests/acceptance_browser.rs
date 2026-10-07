//! tests/acceptance_browser.rs —— v2.3.0 浏览器链验收冒烟（docs/32 §1.6 G-T）。
//!
//! 独立二进制：由 `tools/run_browser_smoke.sh` 用 rustc 链 cf-browser rlib 编译并运行
//! （非 cargo 测试目标；顶层 tests/ 无 workspace）。对 G-B 版 broker（env 注入 seam，
//! `COFFER_BROKER_*`）断言 G-T 验收面：
//!
//!   1. `agent_outer_gate_fail_closed` —— ② 层验父进程**先于 broker**：真 broker 已监听，
//!      `browser-agent`（父进程 = 测试进程，非签名浏览器）→ 8001 拒绝且不触碰 broker
//!      （broker 保持存活接受连接）。全链外门禁 fail-closed 的进程级断言。
//!   2. `broker_get_entries_e2e_roundtrip` —— 解锁态 get_entries → EntriesResult
//!      （fixture 逐字段断言）→ lock → 干净退出 0。走真 E2E（cf-browser InitiatorHandshake
//!      + Session，扩展侧身份）。
//!   3. `broker_locked_get_secret_8003` —— 锁定态 get_secret → BrokerLocked（8003 语义）。
//!   4. `wire_and_logs_no_plaintext` —— 握手/应用帧为 E2E 密文 + hex；broker/agent 日志
//!      与链路上不得出现明文值/明文 JSON（docs/31 §3.3 明文暴露面 + §3.4 不落日志）。
//!
//! 诚实边界（docs/32 §7）：
//!   - **② 层真机面**：`parent_is_trusted_browser()` 无 env 跳过 seam（cli.rs:904），
//!     真 `扩展→browser-agent→UDS→broker` 全链须真签名浏览器父进程 → P-S / 真机清单项
//!     （§2-2）；本文件只做外门禁 fail-closed 的进程级断言（自动面）。
//!   - **broker vault 接线（merge-time）**：G-B 版 broker `get_secret` 未接线（解锁态 →
//!     8003 BrokerUnavailable），origin 绑定 8005 / 手势 8007 / capture_save 判据在
//!     vault 接线后启用（docs/32 §7 挂起项），本文件不冒充覆盖。
//!
//! 用法：`acceptance_browser <coffer-bin> <tmp-dir>`（由 run_browser_smoke.sh 调用）。
//! 退出码：0 = 全部通过；非 0 = 失败。

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use cf_browser::broker::BrokerIdentity;
use cf_browser::e2e::{InitiatorHandshake, Session};
use cf_browser::protocol::{AppMessage, AppRequest, AppResponse, HandshakeMessage};

// ---------------- 断言计数 harness（对齐 McpStatusTests/BrowserStatusTests 风格） ----------------

struct Harness {
    passed: usize,
    failed: usize,
}

impl Harness {
    fn check(&mut self, cond: bool, name: &str) {
        if cond {
            self.passed += 1;
            println!("  ✓ {name}");
        } else {
            self.failed += 1;
            println!("  ✗ {name}");
        }
    }
    fn summary(&self) -> bool {
        println!(
            "\n{} —— {} 项断言 {} 项通过",
            if self.failed == 0 { "ACCEPTANCE-BROWSER OK" } else { "ACCEPTANCE-BROWSER FAILED" },
            self.passed + self.failed,
            self.passed
        );
        self.failed == 0
    }
}

// ---------------- 共享助手（模式对齐 core/cf-mcp/tests/browser_subcommand.rs） ----------------

/// 确定性 fake pairing 材料（broker 解锁契约 env）：`(dek_hex, uuid_hex, psk_hex)`。
fn fake_secrets() -> (String, String, String) {
    ( "a1".repeat(32), "b2".repeat(16), "c3".repeat(32) )
}

/// 短唯一测试目录（SUN_LEN 104 约束：UDS 全路径须短）。
fn temp_dir(root: &Path, tag: &str) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    root.join(format!("{tag}-{n}"))
}

/// spawn `coffer browser-broker --uds <uds> --log <log>` + pairing env。
fn spawn_broker(bin: &Path, uds: &Path, log: &Path, overrides: &[(&str, &str)]) -> Child {
    let (dek, uuid, psk) = fake_secrets();
    let mut cmd = Command::new(bin);
    cmd.args(["browser-broker", "--uds"]).arg(uds).args(["--log"]).arg(log);
    cmd.env("COFFER_BROKER_DEK_HEX", &dek)
        .env("COFFER_BROKER_VAULT_UUID_HEX", &uuid)
        .env("COFFER_BROKER_PSK_HEX", &psk)
        // ③ 层 peer 校验：自动化测试跳过（生产装配绝不设置，G-B 注释同款）。
        .env("COFFER_BROKER_SKIP_PEER_VERIFY", "1");
    for (k, v) in overrides {
        cmd.env(k, v);
    }
    cmd.stderr(Stdio::piped()).stdout(Stdio::null());
    cmd.spawn().expect("spawn browser-broker")
}

/// 读一个 native messaging 帧（4B LE + payload）。EOF → None。
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
fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// 轮询等待 socket 出现且权限收敛 0600。
fn wait_for_socket_mode(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(meta) = std::fs::metadata(path) {
            if (meta.permissions().mode() & 0o777) == 0o600 {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// 等待子进程退出并返回退出码（带超时，防挂死）。
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

/// 扩展侧：建到 broker 的真 E2E 会话（IKpsk2 三消息握手，pin 同源派生 broker 公钥）。
fn e2e_client(uds: &Path) -> (Session, UnixStream) {
    let (dek, uuid, psk) = fake_secrets();
    let dek_arr: [u8; 32] = cf_browser::e2e::from_hex(&dek).expect("dek hex").try_into().expect("dek len");
    let uuid_arr: [u8; 16] = cf_browser::e2e::from_hex(&uuid).expect("uuid hex").try_into().expect("uuid len");
    let psk_arr: [u8; 32] = cf_browser::e2e::from_hex(&psk).expect("psk hex").try_into().expect("psk len");

    let identity = BrokerIdentity::derive(&dek_arr, &uuid_arr).expect("derive identity");
    let pk_b = identity.public_key();

    let mut stream = UnixStream::connect(uds).expect("connect broker uds");

    let (handshake, msg1) = InitiatorHandshake::new(psk_arr, pk_b).expect("initiator");
    write_frame(&mut stream, &serde_json::to_vec(&msg1).expect("msg1 json")).expect("write msg1");
    let msg2_payload = read_frame(&mut stream).expect("read msg2").expect("broker 未响应 msg2");
    let msg2: HandshakeMessage = serde_json::from_slice(&msg2_payload).expect("parse msg2");
    let (msg3, session) = handshake.on_response(&msg2).expect("on_response");
    write_frame(&mut stream, &serde_json::to_vec(&msg3).expect("msg3 json")).expect("write msg3");

    (session, stream)
}

/// get_entries fixture（fields 结构化，designation adjacently-tagged，docs/31 §5.2 契约）。
const ENTRIES_FIXTURE: &str = r#"[{"entry":"e1","title":"GitHub","category":"login","fields":[{"name":"username","designation":{"kind":"username"}},{"name":"password","designation":{"kind":"password"}}]},{"entry":"e2","title":"AWS Console","category":"api_credential","fields":[{"name":"username","designation":{"kind":"username"}},{"name":"password","designation":{"kind":"password"}},{"name":"secret_key","designation":{"kind":"other","value":"secret_key"}}]}]"#;

// ---------------- 判据 1：② 层外门禁 fail-closed 先于 broker ----------------

/// 真 broker 已监听；`browser-agent`（父进程 = 测试进程，非签名浏览器）→ 8001 拒绝，
/// 且不触碰 broker（broker 保持存活）。全链外门禁（docs/31 §3.2 ②）的进程级断言。
fn agent_outer_gate_fail_closed(h: &mut Harness, bin: &Path, root: &Path) {
    let dir = temp_dir(root, "gate");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let broker_log = dir.join("broker.log");
    let agent_log = dir.join("agent.log");

    let mut broker = spawn_broker(bin, &uds, &broker_log, &[]);
    assert!(
        wait_for_socket_mode(&uds, Duration::from_secs(10)),
        "broker socket 未就绪: {}",
        uds.display()
    );

    // 父进程 = 本测试进程（非签名浏览器）→ ② 层拒签，先于 env/连接 broker。
    let out = Command::new(bin)
        .arg("browser-agent")
        .args(["--log"]).arg(&agent_log)
        .env("COFFER_BROKER_UDS", &uds)
        .stderr(Stdio::piped())
        .output()
        .expect("run browser-agent");
    h.check(out.status.code() == Some(1), "browser-agent（非签名父进程）→ 退出 1（8001 fail-closed）");
    // `--log` 已给 → 8001 落 agent.log（logger.error 走日志面，stdout/stderr 仅原生协议面）。
    let agent_log_text = std::fs::read_to_string(&agent_log).unwrap_or_default();
    h.check(agent_log_text.contains("8001"), "agent.log 断言 8001（父进程未验证）");
    let err = String::from_utf8_lossy(&out.stderr);
    h.check(!err.contains("unknown subcommand"), "进入浏览器分支（非未知子命令）");
    h.check(!agent_log_text.contains("relaying via uds"), "② 层拒签先于接触 broker（未进入中继）");

    // broker 未被触碰：agent 拒签退出后 broker 仍存活（accept 循环继续）。
    // try_wait 返回 None = 进程仍在运行。
    h.check(
        broker.try_wait().expect("try_wait").is_none(),
        "broker 未被 agent 拒签波及（仍存活，accept 循环继续）",
    );

    let _ = broker.kill();
    let _ = broker.wait();
    let _ = broker_log;
}

// ---------------- 判据 2：解锁态 get_entries → EntriesResult（真 E2E） ----------------

fn broker_get_entries_e2e_roundtrip(h: &mut Harness, bin: &Path, root: &Path) {
    let dir = temp_dir(root, "entries");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let mut broker = spawn_broker(
        bin, &uds, &log,
        &[("COFFER_BROKER_UNLOCKED", "1"), ("COFFER_BROKER_ENTRIES_JSON", ENTRIES_FIXTURE)],
    );
    assert!(
        wait_for_socket_mode(&uds, Duration::from_secs(10)),
        "broker socket 未就绪: {}",
        uds.display()
    );

    let (mut session, mut stream) = e2e_client(&uds);

    let req = AppMessage::Request(AppRequest::GetEntries { origin: "https://github.com".into() });
    write_frame(&mut stream, &session.encrypt(&req).expect("encrypt get_entries")).expect("write get_entries");
    let resp_payload = read_frame(&mut stream).expect("read response").expect("broker 须响应 entries_result");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::EntriesResult { entries }) = resp else {
        h.check(false, "解锁态 get_entries → EntriesResult");
        let _ = broker.kill();
        return;
    };
    h.check(entries.len() == 2, "get_entries → 夹具两条");
    h.check(entries[0].entry == "e1" && entries[0].title == "GitHub", "e1 条目名/title 正确");
    h.check(
        entries[0].fields.len() == 2
            && entries[0].fields[0].name == "username"
            && entries[0].fields[1].name == "password",
        "e1 字段引用（username/password）正确",
    );
    h.check(
        entries[1].fields.iter().any(|f| f.name == "secret_key"),
        "e2 other 型字段（secret_key）在场",
    );

    // lock → Locked → 干净退出 0。
    let lock = session.encrypt(&AppMessage::Request(AppRequest::Lock)).expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let _ = read_frame(&mut stream).expect("read lock response");
    let code = wait_timeout(&mut broker, Duration::from_secs(10)).expect("broker 未挂死");
    h.check(code == 0, "lock → broker 干净退出 0");
    let _ = log;
}

// ---------------- 判据 3：锁定态 get_secret → broker_locked（8003） ----------------

fn broker_locked_get_secret_8003(h: &mut Harness, bin: &Path, root: &Path) {
    let dir = temp_dir(root, "locked");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // 锁定态：不设 COFFER_BROKER_UNLOCKED。
    let mut broker = spawn_broker(bin, &uds, &log, &[]);
    assert!(
        wait_for_socket_mode(&uds, Duration::from_secs(10)),
        "broker socket 未就绪: {}",
        uds.display()
    );

    let (mut session, mut stream) = e2e_client(&uds);

    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 1,
        entry: "e1".into(),
        fields: vec!["password".into()],
        origin: "https://github.com".into(),
        gesture: "test-gesture".into(),
    });
    write_frame(&mut stream, &session.encrypt(&req).expect("encrypt get_secret")).expect("write get_secret");
    let resp_payload = read_frame(&mut stream).expect("read response").expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    h.check(
        matches!(resp, AppMessage::Response(AppResponse::BrokerLocked)),
        "锁定态 get_secret → broker_locked（8003 语义）",
    );

    let lock = session.encrypt(&AppMessage::Request(AppRequest::Lock)).expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let _ = read_frame(&mut stream).expect("read lock response");
    let code = wait_timeout(&mut broker, Duration::from_secs(10)).expect("broker 未挂死");
    h.check(code == 0, "lock → broker 干净退出 0");
    let _ = log;
}

// ---------------- 判据 4：链路与日志无明文值 ----------------

/// 握手 + get_entries 往返期间，捕获我实际写入链路的协议行（msg1 e_init hex、
/// msg3 p hex、get_entries 密文帧 b64、唯一 origin 标记），断言无一出现在 broker 日志
/// （docs/31 §3.3 明文暴露面 + §3.4 不落盘/不进日志；协议行 = 密钥材料面）。
fn wire_and_logs_no_plaintext(h: &mut Harness, bin: &Path, root: &Path) {
    let dir = temp_dir(root, "nopk");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let mut broker = spawn_broker(
        bin, &uds, &log,
        &[("COFFER_BROKER_UNLOCKED", "1"), ("COFFER_BROKER_ENTRIES_JSON", ENTRIES_FIXTURE)],
    );
    assert!(
        wait_for_socket_mode(&uds, Duration::from_secs(10)),
        "broker socket 未就绪: {}",
        uds.display()
    );

    // 唯一 origin 标记：若出现在日志 = 明文泄漏（正常路径无此串）。
    let origin = "https://plaintext-leak-marker.invalid";
    let mut sent_lines: Vec<String> = Vec::new(); // 捕获我写入的协议行

    let (dek, uuid, psk) = fake_secrets();
    let dek_arr: [u8; 32] = cf_browser::e2e::from_hex(&dek).unwrap().try_into().unwrap();
    let uuid_arr: [u8; 16] = cf_browser::e2e::from_hex(&uuid).unwrap().try_into().unwrap();
    let psk_arr: [u8; 32] = cf_browser::e2e::from_hex(&psk).unwrap().try_into().unwrap();
    let identity = BrokerIdentity::derive(&dek_arr, &uuid_arr).unwrap();

    let mut stream = UnixStream::connect(&uds).expect("connect broker uds");
    let (handshake, msg1) = InitiatorHandshake::new(psk_arr, identity.public_key()).unwrap();
    let msg1_json = serde_json::to_vec(&msg1).unwrap();
    sent_lines.push(String::from_utf8_lossy(&msg1_json).into_owned());
    write_frame(&mut stream, &msg1_json).unwrap();
    let msg2: HandshakeMessage = serde_json::from_slice(&read_frame(&mut stream).unwrap().unwrap()).unwrap();
    let (msg3, mut session) = handshake.on_response(&msg2).unwrap();
    let msg3_json = serde_json::to_vec(&msg3).unwrap();
    sent_lines.push(String::from_utf8_lossy(&msg3_json).into_owned());
    write_frame(&mut stream, &msg3_json).unwrap();

    let req = AppMessage::Request(AppRequest::GetEntries { origin: origin.into() });
    let frame = session.encrypt(&req).unwrap();
    // 密文帧 b64 本身不应被 broker 日志捕获（帧 = nonce‖ct‖tag‖mac）。
    sent_lines.push(cf_browser::e2e::to_hex(&frame));
    write_frame(&mut stream, &frame).unwrap();
    let _ = read_frame(&mut stream).unwrap().unwrap();
    drop(stream);

    let _ = broker.kill();
    let _ = broker.wait();
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();

    let leaked = sent_lines.iter().filter(|l| !l.is_empty() && log_text.contains(l.as_str())).count();
    h.check(leaked == 0, "broker 日志不含我写入的任何协议行（握手 hex / 密文帧 b64）");
    h.check(!log_text.contains(origin), "broker 日志不含 get_entries 请求 origin 明文");
    h.check(!log_text.contains("session key") && !log_text.contains("enc_key"), "broker 日志不落会话密钥材料");
}

// ---------------- main ----------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 3, "用法: acceptance_browser <coffer-bin> <tmp-dir>");
    let bin = PathBuf::from(&args[1]);
    let root = PathBuf::from(&args[2]);
    assert!(bin.is_file(), "coffer 二进制不存在: {}", bin.display());

    let mut h = Harness { passed: 0, failed: 0 };
    println!("==> acceptance-browser: 断言 v2.3.0 浏览器链验收面（G-B 版 broker）");

    agent_outer_gate_fail_closed(&mut h, &bin, &root);
    broker_get_entries_e2e_roundtrip(&mut h, &bin, &root);
    broker_locked_get_secret_8003(&mut h, &bin, &root);
    wire_and_logs_no_plaintext(&mut h, &bin, &root);

    std::process::exit(if h.summary() { 0 } else { 1 });
}
