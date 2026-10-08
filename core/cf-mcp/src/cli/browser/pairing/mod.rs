//! broker 配对面（docs/31 §2.3/§2.4 配对集成 W + D-B broker 公钥自报）。
//!
//! notify.sock 反向通道：broker 监听、App 客户端持长连。帧协议与 broker.sock 同款
//! （4B LE 长度前缀 + JSON，复用 cli.rs mod browser 的 [`read_frame`]/[`write_frame`]，
//! 零新编解码）。App 连接鉴权：`peer_pid == getppid()`（broker 父进程 = App）且同
//! euid → 否则拒连（fail-closed，docs/31 §2.3）。
//!
//! 配对流分连接：批准后扩展关连接重开 E2E（docs/31 §2.4 裁定 ④，broker 不续接）；
//! 多浏览器同时配对回拒不排队（裁定 ①，单会话范围内 pending 决策通道串行消费）。
//!
//! 密钥纪律：PSK 永不进 notify 帧——broker 从 stdin `PSK_HEX=` 既有注入取用
//! （决策①，broker 不自行生成）；仅批准后经 `pair_result` 一次性明文下发扩展
//! （docs/31 §6.4 显式接受残余）。

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    bind_broker_socket, env_flag, read_frame, write_frame, Logger, ServerResult, SocketGuard,
    ENV_BROKER_SKIP_PEER_VERIFY,
};

/// 配对请求挂起超时（docs/31 §2.4 裁定 ③：120s）。
const PAIR_TIMEOUT: Duration = Duration::from_secs(120);

/// `pair_cancel.reason`：扩展断连（App 关框）。
const CANCEL_REASON_DISCONNECT: &str = "disconnect";
/// `pair_cancel.reason`：等待决策超时（App 关框）。
const CANCEL_REASON_TIMEOUT: &str = "timeout";

/// `pair_result.reason`：App 拒绝配对。
const RESULT_REASON_REJECTED: &str = "rejected";
/// `pair_result.reason`：等待决策超时。
const RESULT_REASON_TIMEOUT: &str = "timeout";
/// `pair_result.reason`：App 未连接 notify.sock（决策⑥，App 未启动/离线）。
const RESULT_REASON_APP_UNAVAILABLE: &str = "app_unavailable";

// ---------------- notify.sock 帧（broker↔App，4B LE + JSON，docs/31 §2.3） ----------------

/// notify.sock 帧：broker→App 配对请求（docs/31 §2.3；含 broker 自报 pk_b，D-B）。
#[derive(Debug, Serialize)]
struct NotifyPairRequest {
    #[serde(rename = "type")]
    r#type: &'static str,
    request_id: u64,
    browser: String,
    extension_id: String,
    /// 请求到达时刻（unix 毫秒）。
    requested_at: u64,
    /// broker 静态公钥（uncompressed SEC1 65 字节，hex；D-B 启动自报）。
    pk_b: String,
}

/// notify.sock 帧：broker→App 配对取消（docs/31 §2.3；扩展断连/超时 → App 关框）。
#[derive(Debug, Serialize)]
struct NotifyPairCancel {
    #[serde(rename = "type")]
    r#type: &'static str,
    request_id: u64,
    reason: String,
}

/// notify.sock 帧：App→broker 配对决策（docs/31 §2.3；批准时 App 原样转发 pk_b，D-B）。
///
/// `pk_b` 为 `Option`：§2.3 严格 schema 不含该字段（V 组 Swift 可能按 §2.3 实现），
/// 缺失时 broker 回落自身身份公钥（D-B 构造性恒等，见 [`serve_pair_request`]）。
#[derive(Debug, Deserialize)]
struct NotifyPairDecision {
    #[serde(rename = "type")]
    r#type: String,
    request_id: u64,
    approved: bool,
    #[serde(default)]
    pk_b: Option<String>,
}

/// broker → 扩展配对结果帧（broker.sock，pre-E2E 控制帧，docs/31 §2.4 step 3）。
///
/// 批准 → `{type:"pair_result", request_id, approved:true, psk, pk_b}`；
/// 拒绝/超时/App 离线 → `{type:"pair_result", request_id, approved:false, reason}`。
#[derive(Debug, Serialize)]
pub struct PairResult {
    #[serde(rename = "type")]
    r#type: &'static str,
    request_id: u64,
    approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    psk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pk_b: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl PairResult {
    /// 批准结果：一次性下发 PSK（hex）+ broker 公钥（hex）（docs/31 §6.4 残余）。
    fn approved(request_id: u64, psk_hex: &str, pk_b_hex: &str) -> Self {
        Self {
            r#type: "pair_result",
            request_id,
            approved: true,
            psk: Some(psk_hex.to_string()),
            pk_b: Some(pk_b_hex.to_string()),
            reason: None,
        }
    }

    /// 拒绝结果（`rejected` | `timeout` | `app_unavailable`）。
    fn rejected(request_id: u64, reason: &str) -> Self {
        Self {
            r#type: "pair_result",
            request_id,
            approved: false,
            psk: None,
            pk_b: None,
            reason: Some(reason.to_string()),
        }
    }
}

/// 扩展 → broker 配对请求首帧（broker.sock，pre-E2E 控制帧，docs/31 §2.4）。
#[derive(Debug, Deserialize)]
struct ExtensionPairRequest {
    #[serde(rename = "type")]
    r#type: String,
    browser: String,
    extension_id: String,
}

impl ExtensionPairRequest {
    /// 解析扩展配对请求首帧（type 恒 `"pair_request"`，serve_connection 已按 type 分支）。
    fn parse(frame: &[u8]) -> Result<Self, String> {
        let req: Self =
            serde_json::from_slice(frame).map_err(|e| format!("pair_request 帧非法: {e}"))?;
        if req.r#type != "pair_request" {
            return Err(format!("type 非 pair_request: {}", req.r#type));
        }
        if req.browser.is_empty() || req.extension_id.is_empty() {
            return Err("browser/extension_id 缺省".into());
        }
        Ok(req)
    }
}

// ---------------- 配对状态（跨线程共享） ----------------

/// 配对状态句柄（`run_broker` 持有，克隆进 notify 线程；`serve_connection` 经引用使用）。
///
/// notify 线程：accept → 鉴权 → 持连接读决策 → 注入 [`PairingInner::decision_tx`]；
/// `serve_connection`：写 `pair_request`（经 [`PairingInner::app`]）→ 从
/// [`PairingInner::decision_rx`] 收决策。两方向并发安全（读/写不同线程，std
/// `UnixStream` 语义允许），决策通道串行消费（单会话范围，docs/31 §3.1）。
#[derive(Clone)]
pub struct PairingHandle {
    inner: Arc<PairingInner>,
}

struct PairingInner {
    /// 单调 request_id 分配器（broker 侧分配，docs/31 §2.4 step 1）。
    next_request_id: AtomicU64,
    /// broker 自报 pk_b（SEC1 65 字节，hex；启动时由身份派生一次，D-B）。
    pk_b: String,
    /// 配对 PSK（hex；stdin `PSK_HEX=` 既有注入，broker 不自行生成，决策①）。
    psk_hex: String,
    /// 配对请求挂起超时（默认 [`PAIR_TIMEOUT`]；测试注入短超时）。
    pair_timeout: Duration,
    /// App 连接（notify.sock 已鉴权；None = App 未连/离线）。
    app: Mutex<Option<UnixStream>>,
    /// 决策通道接收端（`serve_connection` 串行消费；notify 线程经发送端注入）。
    /// `Mutex` 包裹：`Receiver` 非 `Sync`（`Arc<PairingInner>` 须 `Send` 才能跨线程），
    /// 单会话下无实际竞争（仅 `serve_connection` 串行 recv，notify 线程只用发送端）。
    decision_rx: Mutex<mpsc::Receiver<NotifyPairDecision>>,
    /// 决策通道发送端（notify 线程持有）。
    decision_tx: mpsc::Sender<NotifyPairDecision>,
}

impl PairingHandle {
    /// 新建（`run_broker` 调用；`pair_timeout` 取 [`PAIR_TIMEOUT`]）。
    pub fn new(pk_b: String, psk_hex: String) -> Self {
        Self::with_timeout(pk_b, psk_hex, PAIR_TIMEOUT)
    }

    /// 以指定挂起超时新建（测试注入短超时走超时路径）。
    fn with_timeout(pk_b: String, psk_hex: String, pair_timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            inner: Arc::new(PairingInner {
                next_request_id: AtomicU64::new(1),
                pk_b,
                psk_hex,
                pair_timeout,
                app: Mutex::new(None),
                decision_rx: Mutex::new(rx),
                decision_tx: tx,
            }),
        }
    }

    /// App 是否已连接 notify.sock。
    fn app_connected(&self) -> bool {
        self.inner
            .app
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    /// 分配单调 request_id。
    fn alloc_request_id(&self) -> u64 {
        self.inner.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// 组装并写 `pair_request` 帧至 App（未连/写失败 → Err，fail-closed）。
    fn send_pair_request(
        &self,
        browser: &str,
        extension_id: &str,
        request_id: u64,
    ) -> io::Result<()> {
        let frame = NotifyPairRequest {
            r#type: "pair_request",
            request_id,
            browser: browser.to_string(),
            extension_id: extension_id.to_string(),
            requested_at: unix_ms(),
            pk_b: self.inner.pk_b.clone(),
        };
        let bytes = serde_json::to_vec(&frame).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("serialize pair_request: {e}"),
            )
        })?;
        self.write_to_app(&bytes)
    }

    /// 组装并写 `pair_cancel` 帧至 App（App 可能已离线，失败静默——关框为尽力而为）。
    fn send_pair_cancel(&self, request_id: u64, reason: &str) {
        let frame = NotifyPairCancel {
            r#type: "pair_cancel",
            request_id,
            reason: reason.to_string(),
        };
        if let Ok(bytes) = serde_json::to_vec(&frame) {
            let _ = self.write_to_app(&bytes);
        }
    }

    /// 写原始帧至 App 连接（未连 → [`io::ErrorKind::NotConnected`]）。
    fn write_to_app(&self, bytes: &[u8]) -> io::Result<()> {
        let mut app = self
            .inner
            .app
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let Some(stream) = app.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "App 未连接 notify.sock",
            ));
        };
        write_frame(stream, bytes)
    }

    /// 等待当前配对请求的决策（挂起超时 [`PairingInner::pair_timeout`] → None）。
    ///
    /// 过期决策（request_id 不符）跳过；决策通道断开（notify 线程退出）→ None。
    /// 锁持有整个等待窗口（无竞争者——仅本线程 recv；notify 线程只用发送端）。
    fn wait_for_decision(&self, request_id: u64) -> Option<NotifyPairDecision> {
        let deadline = Instant::now() + self.inner.pair_timeout;
        let rx = self
            .inner
            .decision_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            match rx.recv_timeout(deadline - now) {
                Ok(d) if d.request_id == request_id => return Some(d),
                Ok(_) => continue, // 过期决策，跳过
                Err(_) => return None, // Timeout | 通道断开
            }
        }
    }
}

// ---------------- notify.sock 监听（App 连接面） ----------------

/// 校验 notify.sock 连接方 = App（broker 父进程，docs/31 §2.3）。
///
/// `peer_pid(stream) == getppid()` 且同 euid（cf-uds-sys）。测试门控：debug 构建且
/// `ENV_BROKER_SKIP_PEER_VERIFY=1` → 跳过（mock App 客户端在测试进程内，peer_pid 非
/// 测试进程父进程；release 编译期剔除，生产不可达）。
fn peer_is_app(stream: &UnixStream) -> bool {
    if cfg!(debug_assertions) && env_flag(ENV_BROKER_SKIP_PEER_VERIFY) {
        return true;
    }
    let peer_euid = match cf_uds_sys::peer_euid(stream) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if peer_euid != cf_uds_sys::self_euid() {
        return false;
    }
    let pid = match cf_uds_sys::peer_pid(stream) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // broker 由 App spawn，父进程 PID = App 进程 PID。`parent_id()` 为 u32、
    // `peer_pid` 为 i32（libc::pid_t）；PID 恒 < 2^31（macOS 默认上限远低于此），
    // `as i32` 无损（同 cli.rs `parent_is_trusted_browser` 注释）。
    pid == std::os::unix::process::parent_id() as i32
}

/// 绑定 notify.sock（复用 broker.sock 的 bind 逻辑：0600 / 父目录 0700 + 陈旧 socket
/// 处理；同目录同公式，docs/31 §6.1 决策⑤）。绑定失败 → Err（调用方 fail-closed）。
pub fn bind_notify_socket(path: &Path) -> io::Result<UnixListener> {
    bind_broker_socket(path)
}

/// notify.sock 监听线程：accept → 鉴权（[`peer_is_app`]）→ 持连接读决策 → 注入
/// 决策通道；App 断连 → 清理连接态继续 accept。
///
/// 同一时间只接受一个 App 连接（父进程唯一）；鉴权失败/多余连接 → 拒连继续
/// （fail-closed，不接受伪装 App）。正常不返回；单次 IO 错误仅记录继续——notify 面
/// 损坏不应拖垮已建立的 E2E 会话（daemon 主循环负责 broker.sock 面）。
pub fn run_notify_listener(
    listener: UnixListener,
    path: PathBuf,
    handle: &PairingHandle,
    mut logger: Logger,
) {
    let _guard = SocketGuard { path };
    loop {
        let (stream, _addr) = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                logger.error(&format!("notify.sock: accept 失败: {e}"));
                continue;
            }
        };
        if !peer_is_app(&stream) {
            logger.error("notify.sock: 连接鉴权失败（peer_pid != getppid 或非同用户），拒连");
            continue;
        }
        let mut app = handle
            .inner
            .app
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if app.is_some() {
            logger.error("notify.sock: 已有 App 连接，拒绝额外连接");
            continue;
        }
        let read_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                logger.error(&format!("notify.sock: try_clone 失败: {e}"));
                continue;
            }
        };
        *app = Some(read_stream);
        drop(app);
        logger.info("notify.sock: App 已连接");

        let mut stream = stream;
        // 读决策循环（App 断连 → EOF → 清理连接态）。
        loop {
            match read_frame(&mut stream) {
                Ok(Some(frame)) => {
                    match serde_json::from_slice::<NotifyPairDecision>(&frame) {
                        Ok(d) if d.r#type == "pair_decision" => {
                            let _ = handle.inner.decision_tx.send(d);
                        }
                        Ok(d) => logger.warn(&format!("notify.sock: 未知帧类型: {}", d.r#type)),
                        Err(e) => logger.error(&format!("notify.sock: 决策帧非法: {e}")),
                    }
                }
                Ok(None) => break, // EOF：App 断连
                Err(e) => {
                    logger.error(&format!("notify.sock: 读失败: {e}"));
                    break;
                }
            }
        }
        *handle
            .inner
            .app
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        logger.info("notify.sock: App 连接断开");
    }
}

// ---------------- 配对流编排（serve_connection 首帧 type="pair_request" 分支） ----------------

/// 处理扩展配对请求（docs/31 §2.4 状态机）。
///
/// 1. 解析扩展请求（browser/extension_id）；
/// 2. 分配 request_id，组装 `pair_request`（含 broker 自报 pk_b，D-B）经 notify.sock 写 App；
/// 3. 阻塞等待 `pair_decision`（挂起超时 [`PAIR_TIMEOUT`]）；
/// 4. 批准 → `pair_result{approved:true, psk, pk_b}` 写回扩展；拒绝/超时/App 离线 →
///    `pair_result{approved:false, reason:"rejected|timeout|app_unavailable"}`；
/// 5. 扩展断连（写 `pair_result` 失败）→ 经 notify.sock 发 `pair_cancel{disconnect}`。
///
/// 批准后扩展关连接重开 E2E（分连接语义，docs/31 §2.4 裁定 ④，broker 不续接）。
pub fn serve_pair_request(
    stream: &mut UnixStream,
    handle: &PairingHandle,
    raw_frame: &[u8],
    logger: &mut Logger,
) -> ServerResult {
    let req = match ExtensionPairRequest::parse(raw_frame) {
        Ok(r) => r,
        Err(e) => {
            logger.error(&format!("pairing: 扩展配对请求帧非法: {e}"));
            return ServerResult::Continue;
        }
    };
    let request_id = handle.alloc_request_id();

    // App 未连 notify.sock（决策⑥ 语义：App 未启动/离线）→ 立即 app_unavailable。
    if !handle.app_connected() {
        logger.error("pairing: App 未连接 notify.sock，配对不可用");
        return finish(
            stream,
            &PairResult::rejected(request_id, RESULT_REASON_APP_UNAVAILABLE),
            handle,
            request_id,
            logger,
        );
    }
    if let Err(e) = handle.send_pair_request(&req.browser, &req.extension_id, request_id) {
        logger.error(&format!("pairing: 写 pair_request 至 App 失败: {e}"));
        return finish(
            stream,
            &PairResult::rejected(request_id, RESULT_REASON_APP_UNAVAILABLE),
            handle,
            request_id,
            logger,
        );
    }

    let result = match handle.wait_for_decision(request_id) {
        Some(decision) if decision.approved => match decision.pk_b.as_deref() {
            // 批准：校验 App 原样转发的 pk_b 与 broker 自报身份一致（D-B 构造性
            // 保证）；不一致 → fail-closed 拒绝（不向扩展下发失配公钥）。
            Some(pk) if pk != handle.inner.pk_b => {
                logger.error("pairing: pair_decision.pk_b 与 broker 身份不一致，拒绝");
                PairResult::rejected(request_id, RESULT_REASON_REJECTED)
            }
            pk => {
                // pk 缺失（§2.3 严格 schema）→ 回落 broker 自身身份公钥。
                let pk_b = pk.unwrap_or(&handle.inner.pk_b);
                logger.info("pairing: App 已批准配对");
                PairResult::approved(request_id, &handle.inner.psk_hex, pk_b)
            }
        },
        Some(_) => {
            logger.info("pairing: App 拒绝配对");
            PairResult::rejected(request_id, RESULT_REASON_REJECTED)
        }
        None => {
            // 超时：通知 App 关框 + 回扩展 timeout。
            logger.error("pairing: 配对等待决策超时");
            handle.send_pair_cancel(request_id, CANCEL_REASON_TIMEOUT);
            PairResult::rejected(request_id, RESULT_REASON_TIMEOUT)
        }
    };
    finish(stream, &result, handle, request_id, logger)
}

/// 写 `pair_result` 帧回扩展；扩展断连（写失败）→ 经 notify.sock 发
/// `pair_cancel{reason:"disconnect"}`（App 关框，docs/31 §2.4）。
fn finish(
    stream: &mut UnixStream,
    result: &PairResult,
    handle: &PairingHandle,
    request_id: u64,
    logger: &mut Logger,
) -> ServerResult {
    let bytes = match serde_json::to_vec(result) {
        Ok(b) => b,
        Err(e) => {
            logger.error(&format!("pairing: 序列化 pair_result 失败: {e}"));
            return ServerResult::Continue;
        }
    };
    match write_frame(stream, &bytes) {
        Ok(()) => {
            // 成功写回也落日志（B-2 观测闭环：与写失败/超时形成三分支，真机断点
            // 定位不再靠猜——见到本行 = broker 已把决策交给 host 链路）。
            logger.info(&format!("pairing: pair_result 已写回扩展（approved={}）", result.approved));
            ServerResult::Continue
        }
        Err(e) => {
            logger.error(&format!(
                "pairing: 写 pair_result 至扩展失败（扩展断连）: {e}"
            ));
            handle.send_pair_cancel(request_id, CANCEL_REASON_DISCONNECT);
            ServerResult::Continue
        }
    }
}

/// 当前 unix 时间（毫秒；时钟异常 → 0，时间仅作弹框参考非安全判据）。
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ------------------------------------------------------------------
// 单元测试（帧编解码 + mock App 客户端走 notify.sock 往返配对流）

// ------------------------------------------------------------------
// 单元测试（帧编解码 + mock App 客户端走 notify.sock 往返配对流）
// ------------------------------------------------------------------
#[cfg(test)]
mod tests;
