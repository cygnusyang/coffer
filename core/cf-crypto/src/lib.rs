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
//! ## 编译与测试状态
//!
//! ✅ **已通过编译与测试**（2026-09-24）
//!
//! | 项 | 结果 |
//! | --- | --- |
//! | `cargo build` | 通过，无警告 |
//! | `cargo test` | 9 个测试全部通过 |
//! | 工具链 | rustc 1.98.1 (2026-09-01)，aarch64-apple-darwin |
//!
//! 代码最初是在**没有 Rust 工具链**的机器上、依据 `argon2` 0.6.0 的官方文档
//! 写成的。装上工具链后**一次编译通过**，未出现任何 API 不匹配 —— 说明编写时
//! 对 `Params::new` 的签名、`Algorithm::Argon2id` / `Version::V0x13` 的变体名、
//! 以及 `getrandom::fill` 的跨版本改名判断都是正确的。
//!
//! ## 尚未实现的部分
//!
//! - **AEAD（XChaCha20-Poly1305）** —— 属 M1 内容，见 `docs/03-详细设计.md` §2.5
//! - **Argon2id 参数标定** —— M0 第 ③ 项，用 `examples/bench_kdf.rs` 执行
//! - **HKDF 子密钥派生** —— 属 M1 内容，见 `docs/03-详细设计.md` §2.4
//!
//! 也就是说：`STATUS` 为 `Verified` 指的是**当前已实现的 KDF 模块**，
//! 不代表整个 `cf-crypto` 完工。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod aead;
pub mod error;
pub mod kdf;

pub use aead::{build_field_aad, open, seal, SessionKey, KEY_LEN as AEAD_KEY_LEN, NONCE_LEN as AEAD_NONCE_LEN};
pub use error::CfCryptoError;
pub use kdf::{derive_key, normalize_password, KdfParams, KEY_LEN, SALT_LEN};

/// 本 crate 的实现状态。上层可据此判断可用性。
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
/// # 为什么用常量而不是写进文档
///
/// 「写了」和「能跑」是两件事。这个常量把状态变成**编译期可见的事实**，
/// 而不是散落在文档里、靠人自觉维护的说法。
///
/// # 变更记录
///
/// - **2026-09-24**：`Unverified → Verified`。在 rustc 1.98.1 上
///   `cargo build`（无警告）与 `cargo test`（9 个测试全通过）均通过。
///   按当初的约定，配套的 `status_is_honest` 测试已同步删除 ——
///   那次删除本身就是"已真正验证过"的显式痕迹。
///
/// # 注意本常量的粒度
///
/// 它描述的是 **`cf-crypto` 中已实现的部分**（当前仅 KDF 模块），
/// **不代表 AEAD 等其他 M1 内容已完成**。新增模块时请勿误用此常量，
/// 必要时为每个模块单独标注状态。
pub const STATUS: ImplementationStatus = ImplementationStatus::Verified;
