//! 本 crate 的错误类型。
//!
//! 设计原则（见 `docs/04-系统设计.md` §4.2「Information Disclosure」）：
//! **错误信息不得泄露可用于降低攻击成本的信息**。典型例子是解锁失败时
//! 不区分「密码错误」与「数据损坏」——两者必须返回同一个错误。

use thiserror::Error;

/// `cf-crypto` 的错误类型。
///
/// 错误码的对外映射见 `docs/03-详细设计.md` §12。
#[derive(Debug, Error)]
pub enum CfCryptoError {
    /// KDF 参数非法（越界、为零、组合不合法等）。
    ///
    /// 触发场景包括：解析 `header.json` 时发现参数被篡改为极端值。
    /// 必须拦截，否则会导致 OOM（见 `docs/04-系统设计.md` §4.3）。
    #[error("KDF 参数非法：{0}")]
    InvalidParams(String),

    /// KDF 计算失败。
    ///
    /// 注意：**不要把底层库的具体错误信息透出到 UI**，
    /// 它可能包含参数细节。日志中可以记录，用户界面只显示统一提示。
    #[error("密钥派生失败")]
    KdfFailed,

    /// 输入长度不合法（如盐长度不符）。
    #[error("输入长度不合法：{0}")]
    InvalidLength(String),

    /// 系统密码学随机源不可用。
    ///
    /// 这是极罕见但不可忽略的情况：`getrandom` 在熵不足时可能返回错误
    /// （见其文档「Early boot」一节）。本项目的安全完全建立在 CSPRNG 之上，
    /// 因此**绝不能**在随机源失败时降级到一个弱随机源。
    #[error("系统随机源不可用：{0}")]
    RandomUnavailable(String),
}
