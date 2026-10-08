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
//! **构建面拆分（M-3 release-inert）**：走 env 降级夹具的用例（
//! `broker_uds_bind_and_permissions` / `broker_locked_state` /
//! `broker_get_entries_unlocked` 及新增 vault 用例）与配套 helper（`spawn_broker` /
//! `e2e_client` / `read_frame` / `write_frame` / `drain_stderr`）+ E2E 协议 import
//! 均 `#[cfg(debug_assertions)]` 门控——env 降级仅 debug 生效，release 下 broker 走
//! stdin fail-closed（语义由 `release_broker_skips_nothing_when_env_set` +
//! TC-BROKER-1 覆盖），对应用例仅 debug 全量跑、release 不编译。docs/32 判据锚点
//! （§1.2-3/5 等）在 debug 门禁口径核销，计数不变。
//!
//! **merge-time 组 E（broker-wiring，裁定书 §3.1/§3.2）**：解锁态 broker 以
//! stdin 交付的 DEK 直开 vault（`$COFFER_VAULT_DIR`），`get_secret` /
//! `capture_save` / `get_entries` 落真实 vault 查询与写入。新增用例
//! `broker_unlocked_get_secret_e2e` / `broker_capture_save_creates_item_with_binding`
//! / `broker_capture_save_updates_existing_item`（debug env 夹具 + 真库真 DEK，
//! 断言手势/8005/字段取值/绑定落库）。`get_entries` 旧 `COFFER_BROKER_ENTRIES_JSON`
//! 夹具已随 vault 化移除。
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
// E2E 协议类型（Session / AppMessage 等）仅被 debug 门控的 E2E 用例与
// `e2e_client` 使用（release 下 env 降级剔除、无 E2E 用例）——随 debug 归位，
// 否则 release 编译面报 unused import。
#[cfg(all(feature = "coffer-store", debug_assertions))]
use cf_browser::e2e::Session;
#[cfg(all(feature = "coffer-store", debug_assertions))]
use cf_browser::protocol::{AppMessage, AppRequest, AppResponse, EntryFieldRef};
// vault 建库 / 开库（TC-BROKER-2 与解锁态用例共用；`create_broker_vault` 在
// debug + release 双构建面都被 `broker_stdin_valid_binds_and_locked_false` 使用，
// 故仅 feature 门控、不 debug 归位）。
#[cfg(feature = "coffer-store")]
use cf_crypto::kdf::KdfParams;
#[cfg(feature = "coffer-store")]
use cf_session::{create_vault_with_kdf, open_vault, VaultSession};
// 种子条目 / 断言用域模型（仅解锁态 debug 用例使用）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
use cf_domain::category::ItemCategory;
#[cfg(all(feature = "coffer-store", debug_assertions))]
use cf_domain::field::{Designation, FieldType};
#[cfg(all(feature = "coffer-store", debug_assertions))]
use cf_domain::item::{FieldDraft, ItemDraft};
#[cfg(all(feature = "coffer-store", debug_assertions))]
use cf_domain::origin::{OriginBinding as DomainBinding, OriginBindingKind};

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
    ] {
        cmd.env_remove(key);
    }
    // `COFFER_VAULT_DIR` 故意**不在**清除列表：解锁态用例需经 `spawn_broker` /
    // `spawn_broker_stdin` 的 extra_env 注入真实库路径，清除会干扰注入。
}

/// spawn `coffer browser-broker --uds <uds> --log <log>` + pairing env（**env 降级**）。
///
/// - `overrides`：追加/覆盖环境变量（如 `COFFER_BROKER_UNLOCKED` /
///   `COFFER_BROKER_DEK_HEX` / `COFFER_VAULT_DIR`）；
/// - `omit_skip_verify`：`true` 时不设 `COFFER_BROKER_SKIP_PEER_VERIFY=1`
///   （③ 层签名校验恒开 → 伪造 peer 被拒，测 8002 用）。
///
/// env 降级仅 `cfg!(debug_assertions)` 生效（release inert）；本 helper 仅用于
/// 需要 env 注入的用例（§6-5：env 用例统一在 `COFFER_BROKER_SKIP_PEER_VERIFY=1`
/// 下运行）。**debug-only 门控**：调用方均 `debug_assertions` 门控（锁定态 /
/// 解锁态 vault 用例）——release 下 env 降级编译期剔除、本 helper 无调用方
/// 成 dead code，故随测试一并 debug 归位（release 走 stdin 语义由
/// `release_broker_skips_nothing_when_env_set` + TC-BROKER-1 覆盖）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn spawn_broker(
    uds: &Path,
    log: &Path,
    overrides: &[(&str, &str)],
    omit_skip_verify: bool,
) -> Child {
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
/// 用确定性 fake 材料（身份派生 / E2E 配对，与 [`e2e_client`] 同源）。
#[cfg(feature = "coffer-store")]
fn stdin_frame(unlocked: &str) -> String {
    let (dek, uuid, psk) = fake_secrets();
    stdin_frame_with(unlocked, &dek, &uuid, &psk)
}

/// 显式材料的 4 行 stdin 帧（解锁态用例：DEK/UUID 须为真实 vault 的，broker 以
/// DEK 直开 `$COFFER_VAULT_DIR`；PSK 仍为确定性 fake，仅 E2E 配对用）。
#[cfg(feature = "coffer-store")]
fn stdin_frame_with(unlocked: &str, dek: &str, uuid: &str, psk: &str) -> String {
    format!("DEK_HEX={dek}\nVAULT_UUID_HEX={uuid}\nPSK_HEX={psk}\nUNLOCKED={unlocked}\n")
}

/// 建一个独立快速档测试库（8 MiB KDF，与 tests/cli.rs 同款），开锁后以
/// `set_dek_retention(true)` 保留 DEK 并导出 hex，返回 `(vault_dir, dek_hex,
/// uuid_hex)`。会话随即 drop（建库/种子后测试进程不再持有库，broker 子进程
/// 以 DEK 独立直开——避免 SQLite 双进程写锁纠缠）。
#[cfg(feature = "coffer-store")]
fn create_broker_vault(tag: &str) -> (PathBuf, String, String) {
    const P1: &str = "correct-horse-battery-staple-42!";
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(
        &base,
        "broker测试库",
        P1,
        KdfParams::new(8 * 1024, 1, 1).expect("8 MiB fast KDF params"),
    )
    .expect("create broker test vault");
    let vault_dir = base.join(brief.uuid.to_string());
    let session = open_vault(&vault_dir).expect("open broker test vault");
    session.set_dek_retention(true);
    session.unlock(P1).expect("unlock broker test vault");
    let dek = session.export_dek().expect("export broker test vault DEK");
    let dek_hex: String = dek.iter().map(|b| format!("{b:02x}")).collect();
    drop(session);
    // UUID 须无连字符（32 hex，`parse_hex_array::<16>` / `from_hex` 只认裸 hex；
    // `Uuid::to_string()` 是带连字符 36 字符，直用会「缺 pairing 材料」）。
    (vault_dir, dek_hex, brief.uuid.simple().to_string())
}

/// 重开库 + 主密码解锁（测试进程侧种子/断言用；与 broker 的 DEK 直开不同路径，
/// 同库不同会话互不干扰）。
#[cfg(feature = "coffer-store")]
fn open_broker_vault(vault_dir: &Path) -> VaultSession {
    const P1: &str = "correct-horse-battery-staple-42!";
    let session = open_vault(vault_dir).expect("reopen broker test vault");
    session
        .unlock(P1)
        .expect("unlock broker test vault (password)");
    session
}

/// 最小 Login 种子草稿（username + password 字段，designation 对齐扩展填充角色）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn broker_login_draft(title: &str, username: &str, password: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields: vec![
            FieldDraft {
                name: "username".to_owned(),
                value: Some(username.to_owned()),
                field_type: FieldType::Text,
                designation: Some(Designation::Username),
                section_index: None,
                position: 0,
            },
            FieldDraft {
                name: "password".to_owned(),
                value: Some(password.to_owned()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

/// 种子/断言用 cf-domain 存储形态绑定。
///
/// **值经 cf-browser 权威解析规范化**（与 broker `binding_for_origin` 同源，
/// 裁定书 §3.2「勿改」匹配语义）：HTTPS 默认端口显式化（`https://github.com`
/// → `https://github.com:443`）。测试种子/断言须与 broker 实际落库形态一致，
/// 否则 `best_match` 不命中（8005 / 空列表 / capture 误新建）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn broker_domain_binding(kind: OriginBindingKind, value: &str) -> DomainBinding {
    let normalized = cf_browser::origin::OriginBinding::parse(value)
        .expect("canonical origin for seed/assert")
        .value;
    DomainBinding {
        kind,
        value: normalized,
    }
}

/// 合法手势（base64(nonce 16 ‖ issuedAtMs 8 BE)，对齐 G-C 线格式）：nonce 用
/// pid + 进程内递增计数器保证同进程多手势不重放撞车；`issuedAtMs` = 当前毫秒。
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn fresh_gesture() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut raw = [0u8; 24];
    raw[..8].copy_from_slice(&(std::process::id() as u64).to_be_bytes());
    raw[8..16].copy_from_slice(&seq.to_be_bytes());
    raw[16..].copy_from_slice(&now.to_be_bytes());
    base64_encode_24(&raw)
}

/// base64 编码恰 24 字节（手势净长）→ 32 字符、无填充（对齐 gesture.rs 解码面）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn base64_encode_24(raw: &[u8; 24]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(32);
    for chunk in raw.chunks_exact(3) {
        out.push(TABLE[(chunk[0] >> 2) as usize] as char);
        out.push(TABLE[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize] as char);
        out.push(TABLE[(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6)) as usize] as char);
        out.push(TABLE[(chunk[2] & 0x3f) as usize] as char);
    }
    out
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
    cmd.stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped());
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
///
/// 仅被 debug 门控的 E2E 用例（`broker_locked_state` / `broker_get_entries_unlocked`）
/// 及 `e2e_client` 使用——release 下无调用方，随 debug 归位（防 dead code）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
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
///
/// 仅被 debug 门控的 E2E 用例及 `e2e_client` 使用（同 `read_frame`），随 debug 归位。
#[cfg(all(feature = "coffer-store", debug_assertions))]
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
///
/// 仅被 `e2e_client` 握手诊断使用（debug 门控），随 debug 归位（防 dead code）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
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
    assert!(
        err.contains("browser broker"),
        "进入 browser-broker 分支: {err}"
    );
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
    assert!(
        !err.contains("unknown subcommand"),
        "不得落入未知子命令: {err}"
    );

    // 未知子命令 → 契约退出码 1 + unknown-subcommand 特征（cli.rs:617 路径）。
    let out = Command::new(coffer_bin())
        .arg("bogus-subcommand")
        .stderr(Stdio::piped())
        .output()
        .expect("run bogus subcommand");
    assert_eq!(out.status.code(), Some(1), "未知子命令 → 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unknown subcommand"),
        "unknown-subcommand: {err}"
    );

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
///
/// **debug-only 门控**：走 `spawn_broker` env 降级（仅 debug 生效）；release 下
/// env 降级编译期剔除 → broker 走空 stdin fail-closed（exit 1 无 socket），本用例
/// 语义不成立。release 对应用例 = `release_broker_skips_nothing_when_env_set`
/// （③ 层 seam 编译期剔除）。判据 docs/32 §1.2-3 在 debug 门禁口径核销，计数不变。
#[test]
#[cfg(all(feature = "coffer-store", debug_assertions))]
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
    assert_eq!(
        dir_mode & 0o777,
        0o700,
        "父目录权限须 0700, got {:o}",
        dir_mode
    );

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
///
/// **锁定态帧（UNLOCKED=0）**：③ 层验 peer 与解锁态正交（同
/// `release_broker_skips_nothing_when_env_set` 注释）；组 E 后解锁态开库为硬前提
/// （UNLOCKED=1 缺 `$COFFER_VAULT_DIR` → fail-closed exit 1，见
/// `broker_unlocked_missing_vault_dir_fails_closed`），本用例仅专注 ③ 层。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_rejects_unverified_host() {
    let dir = temp_dir("broker-8002");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // stdin 注入配对材料（不设 COFFER_BROKER_* env）→ ③ 层签名校验恒开；锁定态。
    let mut child = spawn_broker_stdin(&uds, &log, Some(&stdin_frame("0")), &[]);
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
    // 用锁定态帧（UNLOCKED=0）：③ 层拒连与解锁态正交，且免真实 vault（解锁态
    // 需 `$COFFER_VAULT_DIR`，release 本用例专注 M-3 旋钮 inert 语义）。
    let mut child = spawn_broker_stdin(
        &uds,
        &log,
        Some(&stdin_frame("0")),
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
    assert!(
        log_text.contains("8002"),
        "release 下 8002 仍落日志: {log_text}"
    );
}

// ===========================================================================
// 判据 5：broker 无解锁会话 → broker_locked（docs/32 §1.2-5，8003）
// ===========================================================================

/// broker 无解锁会话（pairing 材料齐、`COFFER_BROKER_UNLOCKED` 缺省）→
/// 走真 E2E：握手建立会话，`get_secret` → [`AppResponse::BrokerLocked`]，
/// 随后 `lock` → `Locked` 响应 + broker 干净退出 0。
///
/// **debug-only 门控**（同 `broker_uds_bind_and_permissions`）：pairing 材料经
/// `spawn_broker` env 降级注入（仅 debug 生效）；release 下 env 降级剔除 → 空
/// stdin fail-closed，本用例语义不成立。判据 docs/32 §1.2-5 在 debug 门禁口径核销。
#[test]
#[cfg(all(feature = "coffer-store", debug_assertions))]
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
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
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
    let lock_resp: AppMessage = session
        .decrypt(&lock_payload)
        .expect("decrypt lock response");
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
// 解锁态 vault 接线（merge-time 组 E，裁定书 §3.1/§3.2）：get_entries /
// get_secret / capture_save 落真实 vault。走 env 降级夹具（debug-only），
// DEK/UUID 为真实建库导出值，broker 以 DEK 直开 `$COFFER_VAULT_DIR`。
// ===========================================================================

/// 解锁态 `get_entries` → 真 E2E 返回 `EntriesResult`（vault 查询 + origin 绑定
/// 过滤；不带 gesture，lead 裁定 2026-10-08）。种子两条目：GitHub（github 绑定）
/// 与 AWS（aws 绑定）；`get_entries(github)` 只回 GitHub，`get_entries(example.com)`
/// 空列表（无绑定）。
#[test]
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn broker_get_entries_unlocked() {
    let dir = temp_dir("broker-entries");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let (vault_dir, dek, uuid) = create_broker_vault("broker-entries");
    let (_, _, psk) = fake_secrets();
    let seed = open_broker_vault(&vault_dir);
    let id_github = seed
        .create_item_with_origin_bindings(
            &broker_login_draft("GitHub", "alice", "ghp_secret"),
            vec![broker_domain_binding(
                OriginBindingKind::Exact,
                "https://github.com",
            )],
        )
        .expect("seed github item");
    let _id_aws = seed
        .create_item_with_origin_bindings(
            &broker_login_draft("AWS Console", "bob", "awspw"),
            vec![broker_domain_binding(
                OriginBindingKind::Exact,
                "https://console.aws.amazon.com",
            )],
        )
        .expect("seed aws item");
    drop(seed);

    let vault_str = vault_dir.to_str().expect("utf8 vault dir");
    let mut child = spawn_broker(
        &uds,
        &log,
        &[
            ("COFFER_BROKER_UNLOCKED", "1"),
            ("COFFER_BROKER_DEK_HEX", &dek),
            ("COFFER_BROKER_VAULT_UUID_HEX", &uuid),
            ("COFFER_VAULT_DIR", vault_str),
        ],
        false,
    );
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );

    let (mut session, mut stream) = e2e_client_with(&uds, &mut child, &dek, &uuid, &psk);

    // get_entries(github) → 仅 GitHub 条目（origin 过滤）。
    let req = AppMessage::Request(AppRequest::GetEntries {
        origin: "https://github.com".into(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_entries"),
    )
    .expect("write get_entries");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 entries_result");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::EntriesResult { entries }) = resp else {
        panic!("解锁态 get_entries → EntriesResult, got: {resp:?}");
    };
    assert_eq!(entries.len(), 1, "origin 过滤后仅 GitHub: {entries:?}");
    assert_eq!(entries[0].entry, id_github, "条目 ID 回传");
    assert_eq!(entries[0].title, "GitHub");
    assert_eq!(entries[0].category, ItemCategory::Login);
    assert_eq!(
        entries[0].fields,
        vec![
            EntryFieldRef {
                name: "username".into(),
                designation: Designation::Username,
            },
            EntryFieldRef {
                name: "password".into(),
                designation: Designation::Password,
            },
        ]
    );

    // get_entries(example.com) → 空（无绑定命中）。
    let req = AppMessage::Request(AppRequest::GetEntries {
        origin: "https://example.com".into(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_entries"),
    )
    .expect("write get_entries");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 entries_result");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::EntriesResult { entries }) = resp else {
        panic!("解锁态 get_entries → EntriesResult, got: {resp:?}");
    };
    assert!(entries.is_empty(), "example.com 无绑定 → 空列表");

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

/// 解锁态 `get_secret` 全链路（裁定书 §3.2 表）：
/// 1. 手势无效 → 8007；2. origin 未绑定 → 8005；3. 条目不存在 → 8004；
/// 4. 合法手势 + 绑定 + 多字段 → `GetSecretResult`（username/password 值）；
/// 5. 同手势重放（replay）→ 8007（单次消费，D-7）。
///    locked → 8003 由 `broker_locked_state`（锁定态启动）覆盖。
#[test]
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn broker_unlocked_get_secret_e2e() {
    let dir = temp_dir("broker-getsecret");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let (vault_dir, dek, uuid) = create_broker_vault("broker-getsecret");
    let (_, _, psk) = fake_secrets();
    let seed = open_broker_vault(&vault_dir);
    let id_github = seed
        .create_item_with_origin_bindings(
            &broker_login_draft("GitHub", "alice", "ghp_secret"),
            vec![broker_domain_binding(
                OriginBindingKind::Exact,
                "https://github.com",
            )],
        )
        .expect("seed github item");
    let id_unbound = seed
        .create_item_with_origin_bindings(&broker_login_draft("Unbound", "mallory", "x"), vec![])
        .expect("seed unbound item");
    drop(seed);

    let vault_str = vault_dir.to_str().expect("utf8 vault dir");
    let mut child = spawn_broker(
        &uds,
        &log,
        &[
            ("COFFER_BROKER_UNLOCKED", "1"),
            ("COFFER_BROKER_DEK_HEX", &dek),
            ("COFFER_BROKER_VAULT_UUID_HEX", &uuid),
            ("COFFER_VAULT_DIR", vault_str),
        ],
        false,
    );
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );
    let (mut session, mut stream) = e2e_client_with(&uds, &mut child, &dek, &uuid, &psk);

    // 1. gesture 畸形 → 8007。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 1,
        entry: id_github.clone(),
        fields: vec!["password".into()],
        origin: "https://github.com".into(),
        gesture: "not-a-gesture".into(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
    .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::Error { code, .. }) = resp else {
        panic!("畸形手势 → Error, got: {resp:?}");
    };
    assert_eq!(code, 8007, "畸形手势 → 8007");

    // 2. origin 未绑定 → 8005（对已绑定条目用未绑定 origin）。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 2,
        entry: id_github.clone(),
        fields: vec!["password".into()],
        origin: "https://example.com".into(),
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
    .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::Error { code, .. }) = resp else {
        panic!("origin 未绑定 → Error, got: {resp:?}");
    };
    assert_eq!(code, 8005, "origin 未绑定 → 8005");

    // 2b. 条目本身无任何绑定 → 8005。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 3,
        entry: id_unbound.clone(),
        fields: vec!["password".into()],
        origin: "https://example.com".into(),
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
    .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::Error { code, .. }) = resp else {
        panic!("无绑定条目 → Error, got: {resp:?}");
    };
    assert_eq!(code, 8005, "无绑定条目 → 8005");

    // 3. 目标条目不存在 → 8004。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 4,
        entry: "no-such-item".into(),
        fields: vec!["password".into()],
        origin: "https://github.com".into(),
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
    .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::Error { code, .. }) = resp else {
        panic!("条目不存在 → Error, got: {resp:?}");
    };
    assert_eq!(code, 8004, "条目不存在 → 8004");

    // 4. 合法手势 + 绑定 + 多字段 → GetSecretResult。
    let good_gesture = fresh_gesture();
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 5,
        entry: id_github.clone(),
        fields: vec!["username".into(), "password".into()],
        origin: "https://github.com".into(),
        gesture: good_gesture.clone(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
    .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 get_secret_result");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::GetSecretResult { request_id, values }) = resp else {
        panic!("合法 get_secret → GetSecretResult, got: {resp:?}");
    };
    assert_eq!(request_id, 5, "request_id 原样回传");
    assert_eq!(values.len(), 2, "多字段一次返回");
    assert_eq!(
        values.get("username").map(|v| v.expose()),
        Some("alice"),
        "username 值"
    );
    assert_eq!(
        values.get("password").map(|v| v.expose()),
        Some("ghp_secret"),
        "password 值"
    );

    // 5. 同手势重放（同一 nonce 二次消费）→ 8007（单次，D-7）。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 6,
        entry: id_github,
        fields: vec!["password".into()],
        origin: "https://github.com".into(),
        gesture: good_gesture,
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
    .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::Error { code, .. }) = resp else {
        panic!("重放手势 → Error, got: {resp:?}");
    };
    assert_eq!(code, 8007, "重放手势 → 8007（单次消费）");

    // 6. ConfirmUnboundOrigin（L-4 缺口 = 不写绑定，最小语义）：
    //    a. 坏手势 → 8007；b. 好手势 → OriginConfirmed。
    let req = AppMessage::Request(AppRequest::ConfirmUnboundOrigin {
        origin: "https://example.com".into(),
        gesture: "not-a-gesture".into(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt confirm"),
    )
    .expect("write confirm");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::Error { code, .. }) = resp else {
        panic!("confirm 坏手势 → Error, got: {resp:?}");
    };
    assert_eq!(code, 8007, "confirm 坏手势 → 8007");

    let req = AppMessage::Request(AppRequest::ConfirmUnboundOrigin {
        origin: "https://example.com".into(),
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt confirm"),
    )
    .expect("write confirm");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    assert!(
        matches!(resp, AppMessage::Response(AppResponse::OriginConfirmed)),
        "confirm 好手势 → OriginConfirmed, got: {resp:?}"
    );

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

/// 解锁态 `capture_save` **建**条目（裁定书 §3.2）：无既有 (origin+username) 匹配
/// → 建新条目 + `origin_bindings=[绑定(origin)]` 落库。收尾后重开库断言绑定与
/// username/password 字段（绑定落库断言）。
#[test]
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn broker_capture_save_creates_item_with_binding() {
    let dir = temp_dir("broker-capture-create");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let (vault_dir, dek, uuid) = create_broker_vault("broker-capture-create");
    let (_, _, psk) = fake_secrets();
    let vault_str = vault_dir.to_str().expect("utf8 vault dir");
    let mut child = spawn_broker(
        &uds,
        &log,
        &[
            ("COFFER_BROKER_UNLOCKED", "1"),
            ("COFFER_BROKER_DEK_HEX", &dek),
            ("COFFER_BROKER_VAULT_UUID_HEX", &uuid),
            ("COFFER_VAULT_DIR", vault_str),
        ],
        false,
    );
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );
    let (mut session, mut stream) = e2e_client_with(&uds, &mut child, &dek, &uuid, &psk);

    // capture_save 新（github, alice, pw1）→ CaptureSaved。
    let req = AppMessage::Request(AppRequest::CaptureSave {
        origin: "https://github.com".into(),
        username: cf_domain::secret::SecretString::from_exposed("alice"),
        password: cf_domain::secret::SecretString::from_exposed("pw1"),
        title: "GitHub".into(),
        category: ItemCategory::Login,
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt capture_save"),
    )
    .expect("write capture_save");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 capture_saved");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::CaptureSaved { item_id }) = resp else {
        panic!("capture_save 建 → CaptureSaved, got: {resp:?}");
    };
    assert!(!item_id.is_empty(), "返回新条目标识");

    // 收尾 lock → 干净退出 0（先于重开库断言，broker 释放 vault 文件句柄）。
    let lock = session
        .encrypt(&AppMessage::Request(AppRequest::Lock))
        .expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let _ = read_frame(&mut stream).expect("read lock response");
    let code = wait_timeout(&mut child, Duration::from_secs(10))
        .expect("broker 应在 lock 后退出（未挂死）");
    assert_eq!(code, 0, "lock → 干净退出 0");

    // 绑定落库断言：重开库，条目存在 + origin_bindings=[Exact github] + 字段值。
    let verify = open_broker_vault(&vault_dir);
    let item = verify
        .get_item(&item_id)
        .expect("get_item")
        .expect("新建条目存在");
    assert_eq!(
        item.origin_bindings,
        vec![broker_domain_binding(
            OriginBindingKind::Exact,
            "https://github.com"
        )],
        "绑定落库断言"
    );
    let title = item.title.expose().to_owned();
    assert_eq!(title, "GitHub");
    let pw_field = item
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password 字段存在");
    assert_eq!(pw_field.value.as_ref().map(|v| v.expose()), Some("pw1"));
    let _ = log;
}

/// 解锁态 `capture_save` **改**既有条目（裁定书 §3.2）：按 (origin 绑定 +
/// username) 命中既有条目 → 改（密码更新 + `origin_bindings` 替换为
/// `[绑定(origin)]`）→ 返回**同一** item_id。随后经 broker `get_secret` 断言新
/// 密码可取（绑定仍在，取密全链路回环）；重开库断言绑定未丢。
#[test]
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn broker_capture_save_updates_existing_item() {
    let dir = temp_dir("broker-capture-update");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let (vault_dir, dek, uuid) = create_broker_vault("broker-capture-update");
    let (_, _, psk) = fake_secrets();
    // 种子：既有 GitHub login（alice / oldpw + github 绑定）。
    let seed = open_broker_vault(&vault_dir);
    let id = seed
        .create_item_with_origin_bindings(
            &broker_login_draft("GitHub", "alice", "oldpw"),
            vec![broker_domain_binding(
                OriginBindingKind::Exact,
                "https://github.com",
            )],
        )
        .expect("seed github item");
    drop(seed);

    let vault_str = vault_dir.to_str().expect("utf8 vault dir");
    let mut child = spawn_broker(
        &uds,
        &log,
        &[
            ("COFFER_BROKER_UNLOCKED", "1"),
            ("COFFER_BROKER_DEK_HEX", &dek),
            ("COFFER_BROKER_VAULT_UUID_HEX", &uuid),
            ("COFFER_VAULT_DIR", vault_str),
        ],
        false,
    );
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );
    let (mut session, mut stream) = e2e_client_with(&uds, &mut child, &dek, &uuid, &psk);

    // capture_save（github, alice, newpw）→ 命中既有 → 同一 item_id（改）。
    let req = AppMessage::Request(AppRequest::CaptureSave {
        origin: "https://github.com".into(),
        username: cf_domain::secret::SecretString::from_exposed("alice"),
        password: cf_domain::secret::SecretString::from_exposed("newpw"),
        title: "GitHub".into(),
        category: ItemCategory::Login,
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt capture_save"),
    )
    .expect("write capture_save");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 capture_saved");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::CaptureSaved { item_id }) = resp else {
        panic!("capture_save 改 → CaptureSaved, got: {resp:?}");
    };
    assert_eq!(item_id, id, "命中既有条目 → 返回同一 item_id（改而非建）");

    // 经 broker get_secret 断言新密码可取 + 绑定仍在（全链路回环）。
    let req = AppMessage::Request(AppRequest::GetSecret {
        request_id: 7,
        entry: item_id.clone(),
        fields: vec!["password".into()],
        origin: "https://github.com".into(),
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt get_secret"),
    )
    .expect("write get_secret");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 get_secret_result");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::GetSecretResult { values, .. }) = resp else {
        panic!("更新后 get_secret → GetSecretResult, got: {resp:?}");
    };
    assert_eq!(
        values.get("password").map(|v| v.expose()),
        Some("newpw"),
        "capture_save 改后密码已更新"
    );

    // 收尾 lock → 干净退出 0。
    let lock = session
        .encrypt(&AppMessage::Request(AppRequest::Lock))
        .expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let _ = read_frame(&mut stream).expect("read lock response");
    let code = wait_timeout(&mut child, Duration::from_secs(10))
        .expect("broker 应在 lock 后退出（未挂死）");
    assert_eq!(code, 0, "lock → 干净退出 0");

    // 绑定落库断言：重开库，条目 origin_bindings 仍在。
    let verify = open_broker_vault(&vault_dir);
    let item = verify
        .get_item(&item_id)
        .expect("get_item")
        .expect("条目存在");
    assert_eq!(
        item.origin_bindings,
        vec![broker_domain_binding(
            OriginBindingKind::Exact,
            "https://github.com"
        )],
        "改后绑定仍落库"
    );
    let _ = log;
}

/// L-5 并集语义（lead 裁定 2026-10-08）：命中既有条目时绑定取**并集**——当前
/// origin 的 Exact 绑定缺则追加、既有绑定全保留（幂等，同 kind+value 不重复加）；
/// 替换语义会把条目已绑定的他源绑定在从当前 origin 捕获时静默丢弃。
///
/// 两阶段：
/// 1. 种子条目预绑 `[Domain github.com]`（B，裸 host，`best_match` 按 host 命中
///    A=`https://github.com`）→ 从 A capture → 并集 `{B, Exact A}` 落库（A 追加、
///    B 保留、无重复）；
/// 2. 再从已绑 A capture → 绑定不变（幂等，无重复追加），密码逐次更新。
#[test]
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn broker_capture_save_merges_origin_bindings_union() {
    let dir = temp_dir("broker-capture-union");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let (vault_dir, dek, uuid) = create_broker_vault("broker-capture-union");
    let (_, _, psk) = fake_secrets();
    // 种子：既有 GitHub login（alice / oldpw）仅绑 Domain github.com（B）。
    let b_domain = broker_domain_binding(OriginBindingKind::Domain, "github.com");
    let seed = open_broker_vault(&vault_dir);
    let id = seed
        .create_item_with_origin_bindings(
            &broker_login_draft("GitHub", "alice", "oldpw"),
            vec![b_domain.clone()],
        )
        .expect("seed github item with domain binding");
    drop(seed);

    let vault_str = vault_dir.to_str().expect("utf8 vault dir");
    // 期望并集 = {Domain github.com, Exact https://github.com:443}。
    let expected_union = vec![
        b_domain.clone(),
        broker_domain_binding(OriginBindingKind::Exact, "https://github.com"),
    ];
    let spawn_unlocked = |uds: &Path, log: &Path| {
        spawn_broker(
            uds,
            log,
            &[
                ("COFFER_BROKER_UNLOCKED", "1"),
                ("COFFER_BROKER_DEK_HEX", &dek),
                ("COFFER_BROKER_VAULT_UUID_HEX", &uuid),
                ("COFFER_VAULT_DIR", vault_str),
            ],
            false,
        )
    };

    // 阶段 1：从 A capture（alice/newpw）→ 命中既有 → 并集 {A,B}、无重复。
    let mut child = spawn_unlocked(&uds, &log);
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );
    let (mut session, mut stream) = e2e_client_with(&uds, &mut child, &dek, &uuid, &psk);
    let req = AppMessage::Request(AppRequest::CaptureSave {
        origin: "https://github.com".into(),
        username: cf_domain::secret::SecretString::from_exposed("alice"),
        password: cf_domain::secret::SecretString::from_exposed("newpw"),
        title: "GitHub".into(),
        category: ItemCategory::Login,
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt capture_save"),
    )
    .expect("write capture_save");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 capture_saved");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::CaptureSaved { item_id }) = resp else {
        panic!("capture_save 并集 → CaptureSaved, got: {resp:?}");
    };
    assert_eq!(item_id, id, "命中既有 → 同一 item_id");
    let lock = session
        .encrypt(&AppMessage::Request(AppRequest::Lock))
        .expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let _ = read_frame(&mut stream).expect("read lock response");
    let code = wait_timeout(&mut child, Duration::from_secs(10))
        .expect("broker 应在 lock 后退出（未挂死）");
    assert_eq!(code, 0, "lock → 干净退出 0");

    // 阶段 1 落库断言：并集 {A,B}，A 追加、B 保留、无重复。
    let verify = open_broker_vault(&vault_dir);
    let item = verify
        .get_item(&item_id)
        .expect("get_item")
        .expect("条目存在");
    assert_eq!(
        item.origin_bindings, expected_union,
        "并集落库：A 追加、B 保留、无重复"
    );
    drop(verify);

    // 阶段 2：从已绑 A 再 capture（alice/newerpw）→ 绑定不变（幂等）。
    let mut child = spawn_unlocked(&uds, &log);
    assert!(
        wait_for_socket_mode(&uds, 0o600, Duration::from_secs(10)),
        "socket 未就绪: {}",
        uds.display()
    );
    let (mut session, mut stream) = e2e_client_with(&uds, &mut child, &dek, &uuid, &psk);
    let req = AppMessage::Request(AppRequest::CaptureSave {
        origin: "https://github.com".into(),
        username: cf_domain::secret::SecretString::from_exposed("alice"),
        password: cf_domain::secret::SecretString::from_exposed("newerpw"),
        title: "GitHub".into(),
        category: ItemCategory::Login,
        gesture: fresh_gesture(),
    });
    write_frame(
        &mut stream,
        &session.encrypt(&req).expect("encrypt capture_save"),
    )
    .expect("write capture_save");
    let resp_payload = read_frame(&mut stream)
        .expect("read response")
        .expect("broker 须响应 capture_saved");
    let resp: AppMessage = session.decrypt(&resp_payload).expect("decrypt response");
    let AppMessage::Response(AppResponse::CaptureSaved { item_id: id2 }) = resp else {
        panic!("capture_save 幂等 → CaptureSaved, got: {resp:?}");
    };
    assert_eq!(id2, id, "幂等 capture → 同一 item_id");
    let lock = session
        .encrypt(&AppMessage::Request(AppRequest::Lock))
        .expect("encrypt lock");
    write_frame(&mut stream, &lock).expect("write lock");
    let _ = read_frame(&mut stream).expect("read lock response");
    let code = wait_timeout(&mut child, Duration::from_secs(10))
        .expect("broker 应在 lock 后退出（未挂死）");
    assert_eq!(code, 0, "lock → 干净退出 0");

    // 阶段 2 落库断言：绑定不变（幂等，无重复追加）+ 密码已更新。
    let verify = open_broker_vault(&vault_dir);
    let item = verify
        .get_item(&item_id)
        .expect("get_item")
        .expect("条目存在");
    assert_eq!(
        item.origin_bindings, expected_union,
        "幂等：绑定保持不变、无重复追加"
    );
    let pw_field = item
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("password 字段存在");
    assert_eq!(
        pw_field.value.as_ref().map(|v| v.expose()),
        Some("newerpw"),
        "逐次 capture 密码已更新"
    );
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
        assert!(
            !err.contains("unknown subcommand"),
            "不得走未知子命令: {err}"
        );
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
            assert!(
                err.contains("unknown subcommand"),
                "slim 面未知子命令: {err}"
            );
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
    assert!(
        log_text.contains("pairing"),
        "日志提示缺 pairing: {log_text}"
    );
    assert!(
        !uds.exists(),
        "fail-closed 不得留 socket: {}",
        uds.display()
    );
}

/// TC-BROKER-2（HIGH2-3 §7）：stdin 4 行正确 + 真实 vault 的 DEK/UUID →
/// broker 以 DEK 直开库（`$COFFER_VAULT_DIR`）并绑定 UDS，日志 `locked=false`
///（UNLOCKED=1 解锁态，可服务 app 请求）。well-known 落点公式本身由 TC-PATH /
/// TC-HOST-1 单元测试覆盖；此处绑临时路径避免污染真实主目录（App 生产经
/// `--uds <well-known>` 传参，HIGH2-3 §4.1）。
///
/// 组 E 后解锁态开库为硬前提（裁定书 §3.1）：UNLOCKED=1 缺 `$COFFER_VAULT_DIR`
/// → fail-closed exit 1（见 `broker_unlocked_missing_vault_dir_fails_closed`）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_stdin_valid_binds_and_locked_false() {
    let dir = temp_dir("broker-stdin-ok");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let (vault_dir, dek, uuid) = create_broker_vault("broker-stdin-ok");
    let (_, _, psk) = fake_secrets();
    let vault_str = vault_dir.to_str().expect("utf8 vault dir");
    let mut child = spawn_broker_stdin(
        &uds,
        &log,
        Some(&stdin_frame_with("1", &dek, &uuid, &psk)),
        &[("COFFER_VAULT_DIR", vault_str)],
    );
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

    // 日志 locked=false（解锁态 + 开库成功）。
    let _ = child.kill();
    let _ = child.wait();
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        log_text.contains("locked=false"),
        "日志断言 locked=false: {log_text}"
    );
}

/// 组 E fail-closed 判据（裁定书 §3.1）：UNLOCKED=1 解锁态缺 `$COFFER_VAULT_DIR`
/// → 配置错 1 + **不留 socket**（开库先于 bind，fail-closed 语义延续 TC-BROKER-1）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_unlocked_missing_vault_dir_fails_closed() {
    let dir = temp_dir("broker-missing-vault-dir");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    // UNLOCKED=1 但不设 COFFER_VAULT_DIR → exit 1 + 无 socket。
    let mut child = spawn_broker_stdin(&uds, &log, Some(&stdin_frame("1")), &[]);
    let code = wait_timeout(&mut child, Duration::from_secs(15))
        .expect("broker 应在缺 COFFER_VAULT_DIR 时退出（未挂死）");
    assert_eq!(code, 1, "解锁态缺 COFFER_VAULT_DIR → 配置错 1");
    assert!(
        !uds.exists(),
        "fail-closed 不得留 socket: {}",
        uds.display()
    );
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        log_text.contains("COFFER_VAULT_DIR"),
        "日志提示缺 COFFER_VAULT_DIR: {log_text}"
    );
}

/// 组 E fail-closed 判据（裁定书 §3.1/R2）：UNLOCKED=1 + `$COFFER_VAULT_DIR` 指向
/// 存在库但 DEK 错 → 开库失败（1002，`verify_integrity` 归一）→ exit 1 + 不留
/// socket（无半开状态）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_unlocked_wrong_dek_fails_closed() {
    let dir = temp_dir("broker-wrong-dek");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let (vault_dir, _, uuid) = create_broker_vault("broker-wrong-dek");
    // 用 fake DEK（`a1`×32，与真实库 DEK 不同）→ unlock_with_dek 1002 fail-closed。
    let (wrong_dek, _, psk) = fake_secrets();
    let vault_str = vault_dir.to_str().expect("utf8 vault dir");
    let mut child = spawn_broker_stdin(
        &uds,
        &log,
        Some(&stdin_frame_with("1", &wrong_dek, &uuid, &psk)),
        &[("COFFER_VAULT_DIR", vault_str)],
    );
    let code = wait_timeout(&mut child, Duration::from_secs(15))
        .expect("broker 应因 DEK 错退出（未挂死）");
    assert_eq!(code, 1, "DEK 错 → 配置错 1（fail-closed）");
    assert!(!uds.exists(), "开库失败不得留 socket: {}", uds.display());
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
    let unknown_key =
        format!("DEK_HEX={dek}\nVAULT_UUID_HEX={uuid}\nPSK_HEX={psk}\nFOO=bar\nUNLOCKED=1\n");
    // (c) 超 4 KiB 缓冲（防灌，HIGH2-3 §3.1）→ 1。
    let oversized = stdin_frame("1") + &"x".repeat(5 * 1024);

    for (tag, frame) in [
        ("bad-hex", bad_hex),
        ("unknown-key", unknown_key),
        ("oversized", oversized),
    ] {
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
///
/// **锁定态帧（UNLOCKED=0）**：ps-env 泄露面与解锁态正交（组 E 后解锁态开库为硬
/// 前提，UNLOCKED=1 缺 `$COFFER_VAULT_DIR` → fail-closed exit 1，socket 不出现）。
#[test]
#[cfg(feature = "coffer-store")]
fn broker_stdin_secrets_not_in_ps_env() {
    let dir = temp_dir("broker-psenv");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let uds = dir.join("coffer.sock");
    let log = dir.join("broker.log");

    let mut child = spawn_broker_stdin(&uds, &log, Some(&stdin_frame("0")), &[]);
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
/// 从**同一 fake pairing 材料**派生）→ 返回 `(Session, UnixStream)`——会话与其
/// UDS 流绑定，调用方用同一流收发后续 AEAD 帧（broker 单连接单会话）。
///
/// 锁定态用例的快捷入口（材料 = [`fake_secrets`]）；解锁态用例须用
/// [`e2e_client_with`] 传真实 vault 的 DEK/UUID（broker 身份派生 + 开库同源）。
///
/// 握手失败时把 broker stderr 并入 panic 消息（中途异常诊断）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn e2e_client(uds: &Path, child: &mut Child) -> (Session, UnixStream) {
    let (dek, uuid, psk) = fake_secrets();
    e2e_client_with(uds, child, &dek, &uuid, &psk)
}

/// [`e2e_client`] 的显式材料变体：`dek_hex` / `uuid_hex` / `psk_hex` 全部传入
///（解锁态用例：dek/uuid = 真实 vault 的，psk = 确定性 fake，与 broker 启动参数
/// 完全一致）。
#[cfg(all(feature = "coffer-store", debug_assertions))]
fn e2e_client_with(
    uds: &Path,
    child: &mut Child,
    dek_hex: &str,
    uuid_hex: &str,
    psk_hex: &str,
) -> (Session, UnixStream) {
    use cf_browser::broker::BrokerIdentity;
    use cf_browser::e2e::InitiatorHandshake;
    use cf_browser::protocol::HandshakeMessage;

    let dek_arr: [u8; 32] = cf_browser::e2e::from_hex(dek_hex)
        .expect("dek hex")
        .try_into()
        .expect("dek len");
    let uuid_arr: [u8; 16] = cf_browser::e2e::from_hex(uuid_hex)
        .expect("uuid hex")
        .try_into()
        .expect("uuid len");
    let psk_arr: [u8; 32] = cf_browser::e2e::from_hex(psk_hex)
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
