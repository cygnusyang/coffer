//! # cf-browser
//!
//! 浏览器扩展后端（v2.3.0 波次 G-A：browser-core）——**纯 lib**，不产 bin。
//!
//! 范围（docs/31 §0 / §2.2，与扩展侧 G-C、进程侧 G-B/G-D 的分工）：
//!
//! - [`e2e`]：E2E 加密协议（docs/31 §3.3，IKpsk2 风格手工实现，映射 WebCrypto
//!   原语：P-256 ECDH + HKDF-SHA256 + AES-256-GCM + HMAC-SHA256）；
//! - [`protocol`]：协议消息集（握手三消息 + 应用请求/响应）+ native messaging
//!   帧格式（4 字节 LE 长度前缀）；
//! - [`origin`]：origin 三型绑定与匹配（docs/31 §5.3 D-3，exact/subdomain/domain，
//!   优先级 exact > subdomain > domain，**无 regex**）；
//! - [`gesture`]：手势令牌校验与单次消费（docs/31 §5.2 / D-7，base64 nonce‖ts、
//!   TTL 30 s、replay 防重，8007）；
//! - [`broker`]：broker 侧会话骨架（确定性身份密钥 + 握手端点编排）；
//! - [`host`]：host 中继盲传骨架（**零逻辑盲传**，仅帧长度校验，docs/31 §3.1）；
//! - [`error`]：本 crate 错误类型（浏览器域 8xxx，docs/31a §附）。
//!
//! **契约对齐**（G-C 扩展侧 WebCrypto，docs/31 §3.3 为共同契约）：
//! 公钥线格式 = uncompressed SEC1 65 字节 hex；签名线格式 = P1363 r‖s 64 字节
//! hex；会话密钥 = HKDF-SHA256(ikm = ee‖es, salt = e_init‖e_resp, info =
//! `cf/browser/session/v1`, L = 64)；每消息帧 = nonce(12)‖ct‖tag(16)‖mac(32)。
//!
//! **密钥纪律**（docs/31 §3.4）：每会话独立 ephemeral 密钥；会话密钥仅存内存、
//! `ZeroizeOnDrop` 清零；不落盘、不进日志。**防重放**：seq 单调，接收方拒绝
//! `seq <=` 已见最大值。**信息泄露纪律**：认证/解密失败统一 [`error::CfBrowserError::AuthFailed`]。
//!
//! **KAT**：`tests/e2e_kat.rs` 冻结向量由独立 Python 实现首算（`cryptography` 49，
//! 首算脚本 `/tmp/coffer-kat/kat_e2e.py`，对齐 docs/29 §3.3「独立 Python 首算」惯例）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod broker;
pub mod e2e;
pub mod error;
pub mod gesture;
pub mod host;
pub mod origin;
pub mod protocol;

pub use error::CfBrowserError;
