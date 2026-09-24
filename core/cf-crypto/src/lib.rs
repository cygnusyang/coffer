//! # cf-crypto —— Coffer 的加密原语封装层
//!
//! 本 crate 只负责**密码学原语的安全封装**，不知道任何业务概念
//! （它不知道"条目""保险库"是什么）。所有上层逻辑依赖它，反向依赖禁止。
//!
//! ## 对应设计文档
//!
//! | 内容 | 文档位置 |
//! | --- | --- |
//! | 密钥层次（信封加密） | `docs/03-详细设计.md` §2.1 |
//! | 主密码 NFC 归一化 | `docs/03-详细设计.md` §2.2 |
//! | Argon2id 参数与标定方法 | `docs/03-详细设计.md` §2.3 |
//! | HKDF 子密钥派生 | `docs/03-详细设计.md` §2.4 |
//! | 字段级 AEAD 与 AAD 构造 | `docs/03-详细设计.md` §2.5 |
//! | verifier 设计 | `docs/03-详细设计.md` §2.6 |
//!
//! ## 硬性约束（见 `docs/02-概要设计.md` §1.2）
//!
//! 1. **不自造密码学原语** —— 只使用成熟库的高层 API，禁止手工拼装 AEAD 构造
//! 2. **密钥必须可清零** —— 所有含密钥的类型实现 `Zeroize` + `ZeroizeOnDrop`
//! 3. **错误必须显式** —— 禁止 `unwrap()` / `expect()` 兜底（测试代码除外）
//!
//! ## 编译状态
//!
//! ⚠️ **本 crate 尚未在真实 Rust 环境中编译验证。**
//!
//! 编写时开发机未安装 Rust 工具链，代码依据 `argon2` 0.6.0 与
//! `chacha20poly1305` 0.11.0 的官方文档编写，但**未经 `cargo build` 验证**。
//! 这是 M0 阶段的第一项任务，详见 `README.md`「当前状态」与
//! `docs/04-系统设计.md` §10.1。
//!
//! 已知需要校准的点集中在 `kdf.rs` 顶部的注释中。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod error;
pub mod kdf;

pub use error::LvCryptoError;
pub use kdf::{derive_key, normalize_password, KdfParams, KEY_LEN, SALT_LEN};

/// 本 crate 的实现状态。上层可据此判断可用性。
///
/// 在 M0 完成编译验证后，此常量应改为 [`ImplementationStatus::Verified`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImplementationStatus {
    /// 已实现且通过编译与测试
    Verified,
    /// 已编写但未经编译验证
    Unverified,
    /// 尚未实现
    NotImplemented,
}

/// 当前实现状态。
///
/// ⚠️ 保持为 `Unverified` 直到 M0 阶段完成 `cargo test` 为止。
/// **不要在未验证前改成 `Verified`** —— 这个常量存在的意义就是防止
/// 「看起来做过了」的假动作（见 SOUL.md 中的相关约定）。
pub const STATUS: ImplementationStatus = ImplementationStatus::Unverified;

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn status_is_honest() {
        // 这个测试的作用是：当有人把 STATUS 改成 Verified 时，
        // 强迫他同时删掉这个测试，从而留下一次显式的决策痕迹。
        assert_eq!(
            STATUS,
            ImplementationStatus::Unverified,
            "若已通过编译与测试，请更新 STATUS 并删除本测试"
        );
    }
}
