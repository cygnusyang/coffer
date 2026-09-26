//! TOTP 领域数据（`docs/03-详细设计.md` §3.1 totp 表 / §7）。

use serde::{Deserialize, Serialize};

/// TOTP 哈希算法（RFC 6238）。
///
/// **本类型刻意独立于 `cf_totp::TotpConfig`**：领域层不得依赖基础设施
/// crate（`docs/02-概要设计.md` §2.1 单向依赖），算法计算在 `cf-session`
/// 中做领域数据 ↔ `cf-totp` 配置的转换。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgo {
    /// HMAC-SHA1（RFC 6238 默认）
    Sha1,
    /// HMAC-SHA256
    Sha256,
    /// HMAC-SHA512
    Sha512,
}

/// TOTP 配置数据。
///
/// 与 `cf-totp::TotpConfig` 字段对齐（secret / period / digits），
/// 额外带算法。校验规则（secret ≥ 10 字节、digits ∈ {6,8}、period > 0）
/// 由 [`crate::validate`] 在条目层面统一执行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpData {
    /// 共享密钥原始字节（HMAC 的 key）
    pub secret: Vec<u8>,
    /// 哈希算法
    pub algo: TotpAlgo,
    /// 口令位数，仅允许 6 或 8
    pub digits: u8,
    /// 时间步长（秒），须 > 0
    pub period: u32,
}

/// TOTP 更新三态（**更新路径专用**，docs/07 §2.2 update 语义）。
///
/// 背景与裁定：FFI 刻意不下发 TOTP secret（安全设计），编辑条目时
/// 调用方天然无法「重提交」原密钥。若 update 继续沿用 ItemDraft 的
/// `Option<TotpData>`（None = 删还是留？）会产生歧义并导致编辑静默
/// 丢失 TOTP。故更新路径改为显式三态：
///
/// - [`TotpUpdate::Keep`]：既有加密行**原样保留**（secret 不出会话层，
///   调用方无需也无法提供密钥）；
/// - [`TotpUpdate::Replace`]：删旧插新（提交新密钥）；
/// - [`TotpUpdate::Remove`]：删除既有行。
///
/// 新建路径（create）不用本类型：`ItemDraft.totp` 的
/// `Option<TotpData>`（有则写入、无则不写）语义无歧义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TotpUpdate {
    /// 保留既有 TOTP（完全不动存储行）
    Keep,
    /// 删旧插新：用新配置替换既有 TOTP
    Replace(TotpData),
    /// 移除既有 TOTP
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_algo_serde_round_trip() {
        for algo in [TotpAlgo::Sha1, TotpAlgo::Sha256, TotpAlgo::Sha512] {
            let json = serde_json::to_string(&algo).unwrap();
            let back: TotpAlgo = serde_json::from_str(&json).unwrap();
            assert_eq!(algo, back);
            // DDL 用 'sha1'|'sha256'|'sha512' 文本，序列化应为小写算法名
            assert_eq!(json, format!("\"{}\"", format!("{algo:?}").to_lowercase()));
        }
    }

    #[test]
    fn totp_data_serde_round_trip() {
        let data = TotpData {
            secret: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            algo: TotpAlgo::Sha256,
            digits: 8,
            period: 30,
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: TotpData = serde_json::from_str(&json).unwrap();
        assert_eq!(data, back);
    }
}
