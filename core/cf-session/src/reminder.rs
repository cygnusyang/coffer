//! 备份提醒判定（FR-8.5，docs/09 §2.2）。
//!
//! **时间注入的纯函数**（与 [`crate::idle`] 同模式）：平台层负责取当前
//! 时间并调用 [`VaultSession`](crate::VaultSession) 的驱动方法；本模块
//! 只做判定逻辑，全部可测试、无 IO、无时钟读取。
//!
//! `last_backup_at` 由 cf-exporter 的 `export_backup` 成功路径写入源库
//! `meta.last_backup_at`（明文元数据）；从未备份过（缺行）视为
//! 「需要提醒」——新库尚未建立备份是最该提醒的状态。

/// 备份提醒判定（纯函数，时间由平台注入）。
///
/// # 规则
///
/// - `last_backup_at` 为 `None`（从未备份）→ 应提醒；
/// - `now - last_backup_at >= threshold_secs` → 应提醒；
/// - `threshold_secs <= 0` → 视为**禁用**提醒，永不提醒（用户可关闭）；
/// - `now < last_backup_at` → 时钟回拨 / 打点时间异常，**不**提醒
///   （宁可少提醒，不因时间戳异常而误报）。
///
/// # 参数
///
/// - `last_backup_at`：上次成功备份的 Unix 秒（库内 meta 读取，可为 `None`）
/// - `now`：当前 Unix 秒（平台注入）
/// - `threshold_secs`：提醒阈值秒数；`<= 0` 表示禁用
#[must_use]
pub fn should_suggest(last_backup_at: Option<i64>, now: i64, threshold_secs: i64) -> bool {
    if threshold_secs <= 0 {
        return false;
    }
    let Some(last) = last_backup_at else {
        return true;
    };
    if now < last {
        return false;
    }
    now - last >= threshold_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 从未备份 → 应提醒
    #[test]
    fn 从未备份应提醒() {
        assert!(should_suggest(None, 1_000, 7 * 86_400));
        assert!(should_suggest(None, 1_000, 1));
    }

    /// 超过阈值 → 应提醒（恰好等于阈值含等号）
    #[test]
    fn 超过阈值应提醒() {
        assert!(should_suggest(Some(1_000), 1_000 + 3 * 86_400, 3 * 86_400));
        assert!(should_suggest(
            Some(1_000),
            1_000 + 3 * 86_400 + 1,
            3 * 86_400
        ));
    }

    /// 阈值内 → 不提醒
    #[test]
    fn 阈值内不提醒() {
        assert!(!should_suggest(
            Some(1_000),
            1_000 + 3 * 86_400 - 1,
            3 * 86_400
        ));
        // 刚备份完（now == last）不提醒
        assert!(!should_suggest(Some(1_000), 1_000, 3 * 86_400));
    }

    /// threshold <= 0 → 禁用提醒，即使从未备份
    #[test]
    fn 非正阈值视为禁用() {
        assert!(!should_suggest(None, 9_999_999, 0));
        assert!(!should_suggest(Some(1), 9_999_999, -1));
    }

    /// 时钟回拨（now 早于打点时间）→ 不误报
    #[test]
    fn 时钟回拨不误报() {
        assert!(!should_suggest(Some(2_000), 1_000, 60));
    }
}
