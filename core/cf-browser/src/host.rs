//! host 中继盲传骨架（docs/31 §3.1「三段通道第 2 段」）。
//!
//! host 是**零逻辑盲传**中继：仅在 native messaging 层做帧长度校验与转发，
//! **不解密、不解析、不落盘、不缓存**任何内容（blind transport 硬约束，
//! docs/31 §3.1）。host 与扩展的 native messaging 通道（stdin/stdout 4 字节
//! LE 长度前缀）由 `coffer` bin（G-B）建立，本模块只提供中继侧的**验证与
//! 转发骨架**，供 G-B 接线调用。
//!
//! # 安全边界
//!
//! - 中继只处理**帧长度**，payload 内容视为不透明字节；
//! - 对上游（扩展侧）交付的 payload 不做任何长度上限以外的假设；
//! - 转发前后**不产生**任何日志输出（通道内容不进日志，docs/31 §3.1）。

use crate::error::CfBrowserError;
use crate::protocol::{decode_frame, encode_frame, FRAME_LEN_PREFIX};

/// 单帧最大 payload 长度（native messaging 上限，4 GiB）。
const MAX_PAYLOAD_LEN: usize = u32::MAX as usize;

/// host 盲传中继骨架。
///
/// 无内部状态（转发即往返），方法均为纯函数，便于 G-B 以任意缓冲策略接线。
#[derive(Debug, Default)]
pub struct HostRelay;

impl HostRelay {
    /// 校验并转发一条扩展 → broker 的帧。
    ///
    /// 输入为缓冲中的**恰好一个**完整帧（4 字节 LE 长度前缀 + payload），
    /// 返回 `(重组后的字节串, 缓冲剩余)`——原样零改写，剩余字节供调用方
    /// 循环消费（粘包处理）。
    ///
    /// # 错误
    ///
    /// - 帧头截断（前缀不足 4 字节）或 payload 未到齐：返回
    ///   [`CfBrowserError::InvalidLength`]（半包，调用方应继续读取，
    ///   与 [`decode_frame`] 语义一致）；
    /// - payload 长度超限：同返回 [`CfBrowserError::InvalidLength`]（丢弃该帧）。
    pub fn relay_frame<'a>(&self, buf: &'a [u8]) -> Result<(Vec<u8>, &'a [u8]), CfBrowserError> {
        let (payload, rest) = decode_frame(buf)?;
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(CfBrowserError::InvalidLength(format!(
                "relay frame too large: {} bytes",
                payload.len()
            )));
        }
        let framed = encode_frame(payload)?;
        Ok((framed, rest))
    }

    /// 组装一条出站帧（broker → 扩展），与原帧严格一致（盲传）。
    ///
    /// 仅做长度前缀 + 原样复制，不触碰内容。
    ///
    /// # 错误
    ///
    /// payload 超过 `u32::MAX` 字节 → [`CfBrowserError::InvalidLength`]
    /// （超限为调用方组装错误，显式返回而非静默丢弃）。
    pub fn wrap(&self, payload: &[u8]) -> Result<Vec<u8>, CfBrowserError> {
        encode_frame(payload)
    }
}

/// 返回帧头长度（常量，供 G-B 缓冲计算复用）。
#[must_use]
pub fn frame_header_len() -> usize {
    FRAME_LEN_PREFIX
}
