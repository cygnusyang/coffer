//! 空闲自动锁定判定（docs/07 §2.2 / docs/03 §11.2）。
//!
//! **时间注入的纯函数**：平台层（Swift 侧定时器 / 事件监听）负责取当前
//! 时间并调用 [`VaultSession`](crate::VaultSession) 的驱动方法；本模块
//! 只做判定逻辑，全部可测试、无 IO、无时钟读取。

/// 空闲超时判定（纯函数，时间由平台注入）。
///
/// # 规则
///
/// - `now - last_activity >= timeout_secs` → 已超时（应自动锁定）；
/// - `timeout_secs <= 0` → 视为**禁用**自动锁定，永不超时（用户可关闭）；
/// - `now < last_activity` → 时钟回拨 / 乱序喂时间，**不**判定超时
///   （宁可多留一会，不因时间戳异常而误锁）。
///
/// # 参数
///
/// - `last_activity`：最后一次活动的 Unix 秒
/// - `now`：当前 Unix 秒（平台注入）
/// - `timeout_secs`：空闲超时秒数；`<= 0` 表示禁用
#[must_use]
pub fn is_expired(last_activity: i64, now: i64, timeout_secs: i64) -> bool {
    if timeout_secs <= 0 {
        return false;
    }
    if now < last_activity {
        return false;
    }
    now - last_activity >= timeout_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 超过阈值 → 判定超时
    #[test]
    fn 超过阈值判定超时() {
        assert!(is_expired(1_000, 1_301, 300));
    }

    /// 恰好等于阈值 → 判定超时（边界含等号）
    #[test]
    fn 恰好等于阈值判定超时() {
        assert!(is_expired(1_000, 1_300, 300));
    }

    /// 差 1 秒不到阈值 → 不超时（边界下界）
    #[test]
    fn 差一秒不超时() {
        assert!(!is_expired(1_000, 1_299, 300));
    }

    /// 刚发生活动（now == last_activity）→ 永不超时
    #[test]
    fn 零空闲不超时() {
        assert!(!is_expired(1_000, 1_000, 300));
    }

    /// timeout <= 0 → 禁用自动锁定，永不超时
    #[test]
    fn 非正超时视为禁用() {
        assert!(!is_expired(1_000, 9_999_999, 0));
        assert!(!is_expired(1_000, 9_999_999, -1));
    }

    /// 时钟回拨（now 早于 last_activity）→ 不误判超时
    #[test]
    fn 时钟回拨不误判() {
        assert!(!is_expired(2_000, 1_000, 300));
    }
}
