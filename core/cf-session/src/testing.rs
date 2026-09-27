//! 测试支持工具（公开，仅供测试代码使用）：性能预算校准。
//!
//! 生产代码**不得**调用本模块（校准结果依赖运行时机器状态）。

use std::time::{Duration, Instant};

use cf_crypto::aead::{open, seal, SessionKey};

/// 生成一个与机器吞吐成比例的性能测试预算。
///
/// # 为什么需要校准（2026-09-28 实测记录）
///
/// 性能基线（如「1000 条搜索 < 200ms」，docs/07 §7 T02 / docs/09 §3.3/
/// §3.6 / docs/10 §0.5）的本意是**相对不劣化**：算法复杂度不得比既定
/// 基线差一个量级。但绝对毫秒数在一台被热限流（内核 `idle_inject`
/// 持续注入）或高负载的机器上会整体膨胀 10–50 倍，导致与算法无关的
/// 环境性误报。
///
/// 校准方法：先实测 N 次 AEAD open 的吞吐（本仓库最热的基础操作，
/// 健康开发机参考值 ≈ 1000 次 / 3ms），按实测值等比放大名义预算。
/// 健康机器上校准因子为 1，阈值即文档基线原值；劣化环境下阈值放大
/// 同倍数——环境噪声被归一，真正的算法级退化（10 倍以上）仍会被拦截。
///
/// # 示例
///
/// ```
/// use cf_session::testing::perf_budget;
/// // 名义 200ms 基线，按当前机器吞吐校准后使用
/// let budget = perf_budget(200);
/// assert!(budget.as_millis() >= 200);
/// ```
#[must_use]
pub fn perf_budget(base_ms: u64) -> Duration {
    /// 健康开发机跑 [`CALIB_OPS`] 次 AEAD open 的参考毫秒数（docs/07
    /// §7 T02 标定时的实测档位；取整到 3ms 防校准抖动误报）。
    const CALIB_OPS: usize = 1_000;
    const CALIB_REF_MS: u128 = 3;

    let key = SessionKey::new([0x42u8; 32]);
    let aad = b"cf-session perf calibration";
    let sealed = seal(&key, aad, b"calibration-payload-0123456789")
        .unwrap_or_else(|e| panic!("AEAD seal 失败：{e}"));

    let start = Instant::now();
    for _ in 0..CALIB_OPS {
        let _ = open(&key, aad, &sealed);
    }
    let calib_ms = start.elapsed().as_millis().max(1);
    let factor = (calib_ms / CALIB_REF_MS).max(1);
    Duration::from_millis(base_ms * factor as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 校准预算不小于名义值（因子下界为 1）。
    #[test]
    fn budget_at_least_nominal() {
        assert!(perf_budget(200).as_millis() >= 200);
    }
}
