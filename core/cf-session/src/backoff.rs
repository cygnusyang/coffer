//! 解锁暴力退避（FR-12.5 / docs/09 §2 v0.2.0 Must，T05）。
//!
//! ## 定位与存储裁决
//!
//! **内存级，不落盘**：退避定位是「在线路径防自动化脚本摩擦」，非安全
//! 边界——进程重启计数清零是**接受限制**（见 docs/09 冻结裁决）。
//!
//! ## 退避曲线
//!
//! 连续失败 `n` 次（`unlock`、`enable_biometric` 与 `change_password`
//! 共享同一计数器——后两者经 `recover_dek` 验主密码，同为密码 oracle）：
//!
//! - `n < BACKOFF_THRESHOLD`（前 2 次）：无延迟；
//! - `n >= BACKOFF_THRESHOLD`：延迟 `min(2^(n-3), BACKOFF_CAP_SECS)` 秒，
//!   即第 3 次起 1s → 2s → 4s → … 封顶 60s；
//! - 成功（主密码校验通过）清零。
//!
//! ## 时钟注入
//!
//! 判定用 [`MonotonicClock`]（单调时钟）而非墙钟 `unix_now()`——退避
//! 窗口与墙钟无关，测试经 `FakeClock` 注入（`with_clock`，仅测试可见）。

use std::sync::Arc;
use std::time::{Duration, Instant};

/// 退避起始阈值：失败次数 n 达到 3 才开始延迟（前 2 次不惩罚）。
pub(crate) const BACKOFF_THRESHOLD: u32 = 3;

/// 延迟封顶（秒）：`min(2^(n-3), 60)` 的上界。
pub(crate) const BACKOFF_CAP_SECS: u64 = 60;

/// 单调时钟抽象（FR-12.5）：生产用 [`SystemClock`]，测试注入 FakeClock。
pub(crate) trait MonotonicClock: Send + Sync {
    /// 当前时刻（单调，不受系统墙钟调整影响）。
    fn now(&self) -> Instant;
}

/// 生产实现：`std::time::Instant`。
pub(crate) struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// 测试用可控时钟：从构造时刻起算，经 [`FakeClock::advance`] 手动推进。
#[cfg(test)]
pub(crate) struct FakeClock {
    current: std::sync::Mutex<Instant>,
}

#[cfg(test)]
impl FakeClock {
    /// 以当前真实时刻为起点构造。
    pub(crate) fn new() -> Self {
        Self {
            current: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// 手动推进时钟（测试注入时间，与 idle 判定的平台喂时同模式）。
    pub(crate) fn advance(&self, d: Duration) {
        let mut guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard += d;
    }
}

#[cfg(test)]
impl MonotonicClock for FakeClock {
    fn now(&self) -> Instant {
        *self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 解锁失败退避计数器（FR-12.5）：内存级，随会话生命周期存在。
pub(crate) struct UnlockBackoff {
    /// 连续失败次数（成功清零）。
    failures: u32,
    /// 门禁截止时刻；`None` = 无门禁。
    blocked_until: Option<Instant>,
    /// KDF 在途标志（门禁判定 TOCTOU 修复）：`try_acquire` 放行即置位，
    /// `on_failure` / `on_success` / `release` 清除——秒级 KDF 期间并发
    /// 的第二次密码尝试被拒，消除「gate 判定与失败计数非同一临界区」
    /// 形成的并行猜测 / KDF DoS 窗口。
    in_flight: bool,
    /// 单调时钟（生产 SystemClock / 测试 FakeClock）。
    clock: Arc<dyn MonotonicClock>,
}

impl UnlockBackoff {
    /// 生产构造（系统单调时钟）。
    pub(crate) fn new() -> Self {
        Self {
            failures: 0,
            blocked_until: None,
            in_flight: false,
            clock: Arc::new(SystemClock),
        }
    }

    /// 测试构造（注入时钟）。
    #[cfg(test)]
    pub(crate) fn with_clock(clock: Arc<dyn MonotonicClock>) -> Self {
        Self {
            failures: 0,
            blocked_until: None,
            in_flight: false,
            clock,
        }
    }

    /// 门禁判定：`Err(剩余等待)` = 退避期内拒绝（调用方**不得执行 KDF**，
    /// 兼防 KDF DoS）；`Ok(())` = 放行。
    pub(crate) fn gate(&self) -> Result<(), Duration> {
        match self.blocked_until {
            Some(until) => {
                let now = self.clock.now();
                match until.checked_duration_since(now) {
                    Some(remaining) if !remaining.is_zero() => Err(remaining),
                    _ => Ok(()),
                }
            }
            None => Ok(()),
        }
    }

    /// 门禁判定 + 在途预占（同一临界区，MEDIUM-2 修复）：gate 放行即置
    /// `in_flight`，调用方随后执行 KDF；失败 / 成功 / 非密码错误分别经
    /// [`Self::on_failure`] / [`Self::on_success`] / [`Self::release`]
    /// 清除。并发窗口内的第二次获取返回 `Err`，调用方一律按 1002 拒绝
    /// （维持 FR-1.4 不可区分性）。
    ///
    /// `Err(remaining)` 两种含义：门禁期内（remaining = 剩余等待）或已
    /// 有尝试在途（remaining = `Duration::ZERO` 占位，语义不外泄）。
    pub(crate) fn try_acquire(&mut self) -> Result<(), Duration> {
        self.gate()?;
        if self.in_flight {
            return Err(Duration::ZERO);
        }
        self.in_flight = true;
        Ok(())
    }

    /// 释放预占（不触碰计数与门禁）：非密码错误路径专用（如弱密码
    /// 1010、KDF 参数越界 5002、写失败——这些不是密码尝试，不得计入
    /// 失败，但必须释放预占，否则后续合法尝试被永久拒绝）。
    pub(crate) fn release(&mut self) {
        self.in_flight = false;
    }

    /// 距门禁解除的剩余秒数（向上取整；无门禁返回 0）。
    /// UI 旁路：错误呈现维持 1002 不可区分性（FR-1.4），等待时间只经
    /// 此方法单独获取。
    pub(crate) fn remaining_secs(&self) -> u64 {
        match self.gate() {
            Err(remaining) => remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0),
            Ok(()) => 0,
        }
    }

    /// 记录一次失败：计数 +1；达到 [`BACKOFF_THRESHOLD`] 起设置门禁
    /// `min(2^(n-3), 60)` 秒（从当前时刻起算）。
    pub(crate) fn on_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.in_flight = false;
        if self.failures >= BACKOFF_THRESHOLD {
            // 指数位移防溢出：2^63 已远超 60s 封顶，之后恒取 cap
            let exp = u64::from(self.failures - BACKOFF_THRESHOLD).min(63);
            let delay = Duration::from_secs(BACKOFF_CAP_SECS.min(1u64 << exp));
            self.blocked_until = Some(self.clock.now() + delay);
        }
    }

    /// 记录一次成功（主密码校验通过）：清零计数与门禁。
    pub(crate) fn on_success(&mut self) {
        self.failures = 0;
        self.blocked_until = None;
        self.in_flight = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 注入 FakeClock 的计数器（时间从 0 推进，完全可控）。
    fn backoff() -> (UnlockBackoff, Arc<FakeClock>) {
        let clock = Arc::new(FakeClock::new());
        (UnlockBackoff::with_clock(clock.clone()), clock)
    }

    /// FR-12.5 曲线：前 2 次失败无门禁
    #[test]
    fn 前两次失败无门禁() {
        let (mut b, _clock) = backoff();
        b.on_failure();
        assert!(b.gate().is_ok(), "第 1 次失败不应有延迟");
        b.on_failure();
        assert!(b.gate().is_ok(), "第 2 次失败不应有延迟");
        assert_eq!(b.remaining_secs(), 0);
    }

    /// FR-12.5 曲线：第 3 次起 1s / 2s / 4s 指数递增
    #[test]
    fn 第三次起指数递增() {
        let (mut b, clock) = backoff();

        b.on_failure();
        b.on_failure();
        b.on_failure(); // n = 3
        let remaining = b.gate().unwrap_err();
        assert_eq!(remaining.as_secs(), 1, "第 3 次失败应延迟 1s");

        clock.advance(Duration::from_secs(1));
        assert!(b.gate().is_ok(), "等待 1s 后门禁应解除");

        b.on_failure(); // n = 4
        assert_eq!(b.gate().unwrap_err().as_secs(), 2, "第 4 次失败应延迟 2s");

        clock.advance(Duration::from_secs(2));
        b.on_failure(); // n = 5
        assert_eq!(b.gate().unwrap_err().as_secs(), 4, "第 5 次失败应延迟 4s");
    }

    /// FR-12.5 曲线：延迟封顶 60s
    #[test]
    fn 延迟封顶六十秒() {
        let (mut b, _clock) = backoff();
        // 连续失败到远超封顶点位（n=9 时 2^6 = 64 > 60），中途不推进时钟
        for _ in 0..20 {
            b.on_failure();
        }
        assert_eq!(b.gate().unwrap_err().as_secs(), BACKOFF_CAP_SECS, "应封顶 60s");
    }

    /// FR-12.5：成功解锁清零——门禁解除、计数重置（下次失败重新从 n=1 起算）
    #[test]
    fn 成功后清零重新计数() {
        let (mut b, _clock) = backoff();
        for _ in 0..5 {
            b.on_failure();
        }
        assert!(b.gate().is_err());

        b.on_success();
        assert!(b.gate().is_ok(), "成功后门禁应清除");
        assert_eq!(b.remaining_secs(), 0);

        // 重新计数：前 2 次仍无延迟
        b.on_failure();
        b.on_failure();
        assert!(b.gate().is_ok());
    }

    /// 门禁期内 gate 返回剩余等待时间（向上取整）
    #[test]
    fn 门禁期返回剩余等待秒数() {
        let (mut b, _clock) = backoff();
        for _ in 0..4 {
            b.on_failure(); // n = 4 → 2s
        }
        assert_eq!(b.remaining_secs(), 2);
    }

    /// 门禁解除后再 gate 恒 Ok（blocked_until 过期不重复触发）
    #[test]
    fn 门禁过期后放行() {
        let (mut b, clock) = backoff();
        for _ in 0..3 {
            b.on_failure(); // 1s
        }
        clock.advance(Duration::from_secs(1));
        assert!(b.gate().is_ok());
        clock.advance(Duration::from_secs(60));
        assert!(b.gate().is_ok(), "过期门禁不应随时间重新激活");
    }

    // ------------------------------------------ 在途预占（MEDIUM-2 修复）

    /// MEDIUM-2 串行可复现语义断言：try_acquire 预占期间第二次获取被拒
    /// （并发窗口内第二调用被拒的内核语义），release 后可再获取。
    #[test]
    fn 预占期间再次获取被拒() {
        let (mut b, _clock) = backoff();
        assert!(b.try_acquire().is_ok(), "首次获取应放行并预占");
        assert!(
            b.try_acquire().is_err(),
            "在途（KDF 模拟窗口）期间第二次获取应被拒"
        );
        b.release();
        assert!(b.try_acquire().is_ok(), "release 后应可再次获取");
    }

    /// 失败 / 成功路径释放预占；release 不触碰计数与门禁（非密码错误
    /// 路径专用，与 on_failure 的「计数 +1」语义解耦）
    #[test]
    fn 失败与成功释放预占且release不动计数() {
        let (mut b, _clock) = backoff();
        assert!(b.try_acquire().is_ok());
        b.on_failure();
        assert!(b.try_acquire().is_ok(), "on_failure 应释放预占");
        b.on_success();
        assert!(b.try_acquire().is_ok(), "on_success 应释放预占");
        // release 只清预占：此后 2 次失败仍无门禁（计数未被 release 触碰）
        b.release();
        b.on_failure();
        b.on_failure();
        assert!(b.gate().is_ok(), "release 不得影响失败计数");
    }

    /// 门禁优先于预占判定：门禁期内 try_acquire 直接拒绝且**不置位**
    /// 预占（期满后无需 release 即可获取）
    #[test]
    fn 门禁期内获取被拒且不置位预占() {
        let (mut b, clock) = backoff();
        for _ in 0..3 {
            b.on_failure(); // 1s 门禁
        }
        assert!(b.try_acquire().is_err(), "门禁期内获取应被拒");
        clock.advance(Duration::from_secs(1));
        assert!(b.try_acquire().is_ok(), "期满后获取应放行");
    }

    /// 预占不影响 remaining_secs 旁路：UI 倒计时只反映门禁，不暴露在途
    #[test]
    fn 预占不影响剩余秒数旁路() {
        let (mut b, _clock) = backoff();
        assert!(b.try_acquire().is_ok());
        assert_eq!(b.remaining_secs(), 0, "在途预占不是门禁，旁路应为 0");
    }
}
