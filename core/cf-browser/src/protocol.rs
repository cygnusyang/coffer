//! 浏览器扩展协议消息集与帧格式（docs/31 §3 通道 / §5 捕获填充流）。
//!
//! 消息体全部为 JSON（扩展侧 JS 原生），经 E2E AEAD 帧（`crate::e2e`）传输；
//! 帧外再套 native messaging 的 4 字节 LE 长度前缀（`encode_frame` /
//! `decode_frame`，docs/31 §3.1 三段通道第 1 段）。字段名实现期可调整
//! （docs/31a §附），但 `type` 标签与帧格式是冻结契约（KAT 冻结向量入库）。
//!
//! 依赖方向（docs/31 §2.2）：复用 `cf-domain` 的 [`SecretString`]（内存清零、
//! Debug 打码）承载捕获/填充的敏感值与解密结果，复用 [`ItemCategory`] 承载
//! 捕获条目类别。**值只存在于 E2E 密文之内**（明文暴露面 docs/31 §0）。
//!
//! 序列化纪律：消息经 `serde_json` 序列化为 AEAD 帧的**明文载荷**后立即加密
//! （线路上是密文，docs/31 §3.3 帧格式）——这正落在 `cf-domain` [`SecretString`]
//! 「序列化仅供加密快照/加密前内存态」的许可内（其 `Serialize` 文档声明的
//! 禁止场景是**未加密**的明文传输，本通道不触犯）。含 [`SecretString`] 的变体
//! 因此**不**派生 `Clone`/`PartialEq`/`Eq`（cf-domain 刻意不实现，防明文复制）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use cf_domain::category::ItemCategory;
use cf_domain::secret::SecretString;

use crate::error::CfBrowserError;

/// 协议版本（v1 = IKpsk2 风格 P-256/AES-GCM 首版，docs/31 §3.3）。
pub const PROTOCOL_VERSION: u32 = 1;

/// 会话密钥 KDF info 字面量（docs/31 §3.3：`HKDF(ECDH(ee), "cf/browser/session/v1", 双方 nonce)`）。
pub const SESSION_KDF_INFO: &[u8] = b"cf/browser/session/v1";

/// broker 身份密钥派生 info 字面量（docs/31 §4.2：确定性派生 → P-256 密钥对）。
pub const IDENTITY_KDF_INFO: &str = "cf/browser/v1";

/// native messaging 长度前缀字节数（4 字节 LE，Chrome/Edge/Firefox macOS 一致，
/// docs/31 §3.1 / P-S spike ②）。
pub const FRAME_LEN_PREFIX: usize = 4;

// ---------------------------------------------------------------- 握手消息

/// 握手消息（IKpsk2 风格三消息，docs/31 §3.3 握手流程，host 全程 blind transport）。
///
/// 公钥/签名一律为 **uncompressed SEC1（65 字节）** 或 **P1363（r‖s 64 字节）**
/// 的 hex 小写字符串——与扩展侧 WebCrypto 的 `raw` 导出格式对齐（G-C 契约，
/// docs/31 §3.3 原语表）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandshakeMessage {
    /// msg1：扩展（initiator）→ broker（responder）。`e_init` = initiator ephemeral 公钥。
    Init {
        /// 协议版本（须等于 [`PROTOCOL_VERSION`]）。
        version: u32,
        /// initiator ephemeral 公钥（uncompressed SEC1 65 字节，hex）。
        e_init: String,
    },
    /// msg2：broker → 扩展。含 broker 对 (e_init, e_resp) 的 ECDSA 签名
    /// （身份密钥绑定，防中间人）。
    Response {
        /// 协议版本。
        version: u32,
        /// responder ephemeral 公钥（uncompressed SEC1，hex）。
        e_resp: String,
        /// broker 静态公钥（uncompressed SEC1，hex；扩展已 pin）。
        pk_b: String,
        /// ECDSA-P256-SHA256 over `e_init ‖ e_resp`（P1363 r‖s 64 字节，hex）。
        signature: String,
    },
    /// msg3：扩展 → broker。`p` = HMAC-SHA256(PSK, 会话密钥)——扩展身份确立。
    Confirm {
        /// 协议版本。
        version: u32,
        /// confirm 令牌（32 字节，hex）。
        p: String,
    },
}

// ---------------------------------------------------------------- 应用消息

/// 扩展 → broker 的应用请求（握手后经 AEAD 帧传输，docs/31 §5）。
///
/// 不派生 `Clone`/`PartialEq`/`Eq`：`CaptureSave` 承载 [`SecretString`]
/// （cf-domain 刻意不实现，防明文复制；见模块级文档序列化纪律）。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppRequest {
    /// 取密（docs/31 §5.2）：一次手势 = 一次授权填充（D-7 单次/TTL 30 s）。
    ///
    /// 填充一次登录需 username+password **多字段**（G-C 扩展侧契约 2026-10-08
    /// 对齐），故 `fields` 一次声明、`values` 一次返回（见 [`AppResponse::GetSecretResult`]）；
    /// `request_id` 关联请求/响应（扩展侧自增小整数，`< 2^53`，避免 JS Number 精度损失）。
    GetSecret {
        /// 请求关联 id（响应原样带回）。
        request_id: u64,
        /// 目标条目标识。
        entry: String,
        /// 目标字段名数组（如 `["username", "password"]`）。
        fields: Vec<String>,
        /// 当前页有效 origin（`Origin::to_string`，docs/31 §5.3 匹配输入）。
        origin: String,
        /// 手势令牌（UI 点击即生成，TTL 30 s、单次，docs/31 §5.2）。
        gesture: String,
    },
    /// 捕获保存（docs/31 §5.1）：仅用户显式接受；无用户名不 autosave。
    CaptureSave {
        /// 提交页 origin。
        origin: String,
        /// 用户名（页面自有值，E2E 通道传输）。
        username: SecretString,
        /// 密码（页面自有值，E2E 通道传输）。
        password: SecretString,
        /// 条目标题（自动生成或用户编辑）。
        title: String,
        /// 条目类别（docs/31 §5.1 建/改条目）。
        category: ItemCategory,
        /// 手势令牌。
        gesture: String,
    },
    /// 确认未绑定 origin（docs/31 §5.2：action 指向异源 / 未绑定时的用户显式确认）。
    ConfirmUnboundOrigin {
        /// 待确认的 origin。
        origin: String,
        /// 手势令牌。
        gesture: String,
    },
    /// 锁定（docs/31 §2.4：扩展侧 lock → broker 杀进程，同 App 锁定）。
    Lock,
}

/// broker → 扩展的应用响应（docs/31 §4 / §5）。
///
/// 不派生 `Clone`/`PartialEq`/`Eq`：`GetSecretResult` 承载 [`SecretString`]
/// （同 [`AppRequest`] 纪律）。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppResponse {
    /// broker 处于锁定态（docs/31 §4.1：popup 提示打开 App 解锁）。
    BrokerLocked,
    /// 取密结果：多字段、一次性（docs/31 §5.2）。
    GetSecretResult {
        /// 与请求 `get_secret.request_id` 关联。
        request_id: u64,
        /// 解密后的字段值（键 = 请求 `fields` 元素；扩展填充 DOM 随即覆盖，
        /// 值以 [`SecretString`] 承载、drop 清零——仅存在于密文之内）。
        values: BTreeMap<String, SecretString>,
    },
    /// 捕获保存成功。
    CaptureSaved {
        /// 新建/更新的条目标识。
        item_id: String,
    },
    /// 未绑定 origin 确认成功。
    OriginConfirmed,
    /// 锁定已受理。
    Locked,
    /// 错误响应（code 为浏览器域 8xxx，message 面向用户可操作）。
    Error {
        /// 浏览器域错误码（docs/31a §附 8xxx）。
        code: u16,
        /// 面向用户的可操作提示。
        message: String,
    },
}

/// 应用消息联合（请求 + 响应，供 `Session::decrypt` 反序列化）。
///
/// `#[serde(untagged)]`：type 标签在请求/响应两族间不相交，反序列化按序尝试
/// 请求再响应，确定性无歧义；序列化时透传内层带标签值（KAT 冻结契约同款）。
///
/// 不派生 `Clone`/`PartialEq`/`Eq`（沿 [`AppRequest`] / [`AppResponse`] 纪律，
/// 含 [`SecretString`] 值）。
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppMessage {
    /// 请求方向（扩展 → broker）。
    Request(AppRequest),
    /// 响应方向（broker → 扩展）。
    Response(AppResponse),
}

// ---------------------------------------------------------------- 帧（native messaging）

/// 编码一个 native messaging 帧：`payload_len(4, LE) ‖ payload`（docs/31 §3.1）。
///
/// # 错误
///
/// payload 超过 `u32::MAX` 字节返回 [`CfBrowserError::InvalidLength`]
/// （native messaging 长度前缀为 4 字节，单帧上限 4 GiB）。
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, CfBrowserError> {
    if payload.len() > u32::MAX as usize {
        return Err(CfBrowserError::InvalidLength(format!(
            "frame payload too large: {} bytes (native messaging max {})",
            payload.len(),
            u32::MAX
        )));
    }
    let mut out = Vec::with_capacity(FRAME_LEN_PREFIX + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 从缓冲解码**一个**帧，返回 `(payload, 剩余字节)`。
///
/// 输入可能粘包（一次读取含多帧）或半包（长度前缀齐全但 payload 未到齐），
/// 由调用方（G-B host 中继）按需循环消费。长度前缀截断视为格式错误。
///
/// # 错误
///
/// - 前缀不足 4 字节：[`CfBrowserError::InvalidLength`]（半包，等待更多字节）
/// - 声明的长度超出缓冲剩余：同样返回 [`CfBrowserError::InvalidLength`]，
///   此时 payload 尚未到齐，调用方应继续读取（错误语义由调用方区分重试）
pub fn decode_frame(buf: &[u8]) -> Result<(&[u8], &[u8]), CfBrowserError> {
    if buf.len() < FRAME_LEN_PREFIX {
        return Err(CfBrowserError::InvalidLength(format!(
            "frame header truncated: {} bytes, need {}",
            buf.len(),
            FRAME_LEN_PREFIX
        )));
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let total = FRAME_LEN_PREFIX
        .checked_add(len)
        .ok_or_else(|| CfBrowserError::InvalidLength("frame length overflow".into()))?;
    if buf.len() < total {
        return Err(CfBrowserError::InvalidLength(format!(
            "frame body truncated: declared {len} bytes, buffered {}",
            buf.len() - FRAME_LEN_PREFIX
        )));
    }
    Ok((&buf[FRAME_LEN_PREFIX..total], &buf[total..]))
}
