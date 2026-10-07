//! 本 crate 的错误类型。
//!
//! 浏览器域错误码（8xxx）见 `docs/31a` §附「8xxx 错误码段」；登记 docs/03
//! §12 由 G-F 负责。本 crate 只产生会话/协议层错误（8004/8005/8007/8008）；
//! 8001/8002/8003/8006 是进程层错误（host/broker 进程管理），由 G-B/G-D 在
//! `coffer` bin / App 侧产生，不在本 lib 内出现——此处文档声明，不占变体。
//!
//! 信息泄露纪律（对齐 cf-crypto `error.rs` 模块级文档）：认证/解密失败
//! **统一**返回 [`CfBrowserError::AuthFailed`]，不区分「HMAC 校验失败」、
//! 「GCM 标签失败」、「confirm 令牌不符」与「握手签名不符」——任何一条
//! 都不给攻击者反馈到底哪一层被绕过（docs/31 §3.2 失败语义：握手失败
//! 会话不建立）。

use thiserror::Error;

/// `cf-browser` 的错误类型。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CfBrowserError {
    /// 协议版本不受支持。
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    /// 协议消息格式非法（JSON 解析失败 / 字段缺失 / 长度不符）。
    ///
    /// 载荷只放**不降低攻击成本**的格式细节（如缺失字段名），
    /// 不放任何密钥材料或解密中间值（cf-domain `error.rs` 载荷纪律同款）。
    #[error("malformed protocol message: {0}")]
    MalformedMessage(String),

    /// 认证/解密失败。
    ///
    /// 信息泄露纪律：**统一返回此错误，不区分失败原因**——HMAC 校验失败、
    /// GCM 标签失败、confirm 令牌不符、握手签名不符一律不可区分
    /// （与 `CfCryptoError::AeadOpenFailed` 同一条纪律，docs/04 §4.2）。
    #[error("authentication failed")]
    AuthFailed,

    /// 消息序列号重放（`seq <=` 已见最大值）。
    ///
    /// 防重放（docs/31 T-9）：seq 单调递增，收到旧 seq 一律拒绝。
    #[error("replay detected")]
    ReplayDetected,

    /// 会话未建立（在握手完成前调用了会话方法）。
    #[error("session not established")]
    SessionNotEstablished,

    /// origin 未绑定（8005，docs/31a §附）。
    #[error("origin not bound")]
    OriginNotBound,

    /// 手势令牌过期或重放（8007，docs/31 §5.2 手势令牌）。
    #[error("gesture invalid")]
    GestureInvalid,

    /// 捕获未验证（8008，docs/31 §5.1 验证提交成功）。
    #[error("capture not verified")]
    CaptureNotVerified,

    /// origin 字符串非法（格式 / scheme / host 校验失败）。
    #[error("invalid origin: {0}")]
    InvalidOrigin(String),

    /// 系统密码学随机源不可用。
    ///
    /// 极罕见但不可忽略：随机源失败时**绝不**降级到弱随机
    /// （对齐 cf-crypto NFR-SEC-06 纪律）。
    #[error("system randomness unavailable: {0}")]
    RandomUnavailable(String),

    /// 底层密码学运算失败（密钥解析 / 曲线运算 / AEAD 构造等）。
    ///
    /// 载荷只放非敏感的操作名（如 `hkdf expand`），不放中间值。
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// 输入长度非法（帧头截断 / 密钥长度不符等）。
    #[error("invalid length: {0}")]
    InvalidLength(String),

    /// 消息序列化失败。
    #[error("serialization failed: {0}")]
    Serialize(String),
}

impl CfBrowserError {
    /// 返回浏览器域错误码（8xxx）。
    ///
    /// 8004 = 会话未建立 / 协议错误（含认证失败与重放——与 8004「会话未建立」
    /// 同属协议面失败，UI 一律按「通道不可用，重试或重连」处理）；
    /// 8005 = origin 未绑定；8007 = 手势过期/重放；8008 = 捕获未验证。
    ///
    /// 8001/8002/8003/8006 为进程层错误（host 拒签 / host 未验证 /
    /// broker 不可用 / 用户拒绝），由 `coffer` bin（G-B）与 App（G-D）产生，
    /// 本 lib 不定义对应变体——见模块级文档。
    ///
    /// **无 `_` 兜底分支**：新增变体时编译器强制在此补码。
    #[must_use]
    pub fn code(&self) -> u16 {
        match self {
            Self::OriginNotBound => 8005,
            Self::GestureInvalid => 8007,
            Self::CaptureNotVerified => 8008,
            // 其余全部为协议/会话面失败，统一 8004
            Self::UnsupportedVersion(_)
            | Self::MalformedMessage(_)
            | Self::AuthFailed
            | Self::ReplayDetected
            | Self::SessionNotEstablished
            | Self::InvalidOrigin(_)
            | Self::RandomUnavailable(_)
            | Self::CryptoError(_)
            | Self::InvalidLength(_)
            | Self::Serialize(_) => 8004,
        }
    }
}
