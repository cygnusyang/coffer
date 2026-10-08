//! 手势令牌 `gesture`：格式解析 + TTL 窗口 + 单次消费（docs/31 §5.2 / D-7 / §6.1，8007）。
//!
//! 线格式权威 = G-C 扩展侧已冻结实现（`extension/src/protocol.ts`
//! `makeGesture`/`parseGesture`/`gestureWithinTtl`，`e2e_handshake.test.ts`
//! 「gesture: format, TTL window」跨语言对拍基准）。
//!
//! 格式（对齐 protocol.ts L258-287）：
//! `gesture = base64( 16 字节随机 nonce ‖ 8 字节大端 issuedAtMs )`，共 24 字节 → 32 字符；
//! `issuedAtMs` = 毫秒 Unix 时间戳（扩展 `Date.now()`），须 > 0 且 ≤ JS
//! `Number.MAX_SAFE_INTEGER`（`2^53-1`，对齐扩展 `parseGesture` 的 safe-integer 校验）。
//!
//! 校验（纯逻辑，无 IO/无加密随机——nonce 由扩展侧生成，broker 只校验与消费，镜像
//! `origin.rs` 先例）：
//! - **格式**：base64 严格解码 → 恰 24 字节；`issuedAtMs` 大端 u64 合法；
//! - **TTL 窗口**（对齐 `gestureWithinTtl`）：`issuedAtMs <= now && now - issuedAtMs <= TTL(30s)`；
//!   未来签发（时钟偏移/伪造）与过期均拒。
//!
//! **单次消费**（replay 防重，docs/31 D-7「单次、作废即弃」）：broker 侧持
//! [`GestureRegistry`]，同一 nonce 只放行一次；消费态与纯逻辑分离——[`Gesture::parse`]
//! 无状态，registry 内部按签发时间淘汰（TTL 30 s，有界：`max_entries` 上限 + 过期即逐出）。
//! 页面 JS 无法脚本化触发 broker 动作（docs/31 §5.2）。

use std::collections::{HashSet, VecDeque};

use crate::error::CfBrowserError;

/// TTL（毫秒），对齐扩展 `GESTURE_TTL_MS = 30_000`（docs/31 §5.2 / D-7）。
pub const GESTURE_TTL_MS: u64 = 30_000;

/// 手势 nonce 长度（16 字节），对齐扩展 `GESTURE_NONCE_LEN = 16`。
pub const GESTURE_NONCE_LEN: usize = 16;

/// 手势净长（nonce 16 + 时间戳 8 = 24 字节），对齐扩展 `GESTURE_NONCE_LEN + 8`。
const GESTURE_TOTAL_LEN: usize = GESTURE_NONCE_LEN + 8;

/// JS `Number.MAX_SAFE_INTEGER`（毫秒时间戳安全上界，对齐扩展 `parseGesture`）。
const MAX_SAFE_INTEGER_MS: u64 = (1u64 << 53) - 1;

/// registry 默认存活条目上限（有界，防攻击者灌满内存）。
const DEFAULT_MAX_ENTRIES: usize = 1024;

/// 解析后的手势令牌（nonce + 签发时间戳）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gesture {
    nonce: [u8; GESTURE_NONCE_LEN],
    issued_at_ms: u64,
}

impl Gesture {
    /// 解析并校验线格式（`base64( nonce(16) ‖ issuedAtMs(8, BE) )`）。
    ///
    /// 对齐扩展 `parseGesture`（protocol.ts L267-280）：base64 严格解码 → 恰 24 字节；
    /// `issuedAtMs` 大端 u64，`> 0` 且 `≤ 2^53-1`（safe-integer）。畸形
    /// （非 base64 / 长度错 / 时间戳坏 / 越界）→ [`CfBrowserError::GestureInvalid`]（8007）。
    pub fn parse(s: &str) -> Result<Self, CfBrowserError> {
        if s.is_empty() {
            return Err(CfBrowserError::GestureInvalid);
        }
        let bytes = decode_base64_strict(s)?;
        let mut nonce = [0u8; GESTURE_NONCE_LEN];
        nonce.copy_from_slice(&bytes[..GESTURE_NONCE_LEN]);
        let mut issued_be = [0u8; 8];
        issued_be.copy_from_slice(&bytes[GESTURE_NONCE_LEN..]);
        let issued_at_ms = u64::from_be_bytes(issued_be);
        if issued_at_ms == 0 || issued_at_ms > MAX_SAFE_INTEGER_MS {
            return Err(CfBrowserError::GestureInvalid);
        }
        Ok(Self {
            nonce,
            issued_at_ms,
        })
    }

    /// 是否落在 TTL 窗口内（TTL = [`GESTURE_TTL_MS`]，对齐扩展 `gestureWithinTtl`）。
    ///
    /// 未来签发（`issued > now`）与过期（`now - issued > TTL`）均返回 `false`。
    #[must_use]
    pub fn within_ttl(&self, now_ms: u64) -> bool {
        self.within_ttl_with(now_ms, GESTURE_TTL_MS)
    }

    /// 是否落在 `ttl_ms` 窗口内（registry 淘汰 / 单测注入短 TTL 用）。
    #[must_use]
    pub fn within_ttl_with(&self, now_ms: u64, ttl_ms: u64) -> bool {
        self.issued_at_ms <= now_ms && now_ms - self.issued_at_ms <= ttl_ms
    }

    /// 签发时间戳（毫秒 Unix 时间；registry 淘汰与测试用）。
    #[must_use]
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// nonce 字节（replay 消费态键）。
    #[must_use]
    pub fn nonce(&self) -> &[u8; GESTURE_NONCE_LEN] {
        &self.nonce
    }
}

/// 手势单次消费登记表（replay 防重，docs/31 D-7「单次、作废即弃」）。
///
/// broker 侧持用（组 E 接线）：每经校验的手势 nonce 消费后入表，同一 nonce 再次出现
/// → [`CfBrowserError::GestureInvalid`]（8007）。**有界**：
/// - **TTL 淘汰**：按签发时间升序排队，消费时逐出 `now - ttl` 之前的条目（front 出队）；
/// - **容量上限**：非过期存活条目达 `max_entries`（默认 1024）时拒绝新手势（fail-closed）。
///
/// 队列按签发时间近似升序（扩展按 UI 点击顺序发出）；乱序到达只可能**延迟**淘汰
/// （保守，安全方向），绝不提前逐出。
pub struct GestureRegistry {
    /// 已消费 nonce 集合（O(1) 重放查重）。
    seen: HashSet<[u8; GESTURE_NONCE_LEN]>,
    /// 按签发时间近似升序的待淘汰队列（nonce, issued_at_ms）。
    queue: VecDeque<([u8; GESTURE_NONCE_LEN], u64)>,
    /// 本 registry 的 TTL 窗口（默认 [`GESTURE_TTL_MS`]；单测可注入小值）。
    ttl_ms: u64,
    /// 存活条目上限。
    max_entries: usize,
}

impl GestureRegistry {
    /// 默认 registry：TTL [`GESTURE_TTL_MS`]，上限 [`DEFAULT_MAX_ENTRIES`]。
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(GESTURE_TTL_MS, DEFAULT_MAX_ENTRIES)
    }

    /// 指定 TTL 与容量上限的 registry（测试注入小 TTL 快速验证淘汰）。
    #[must_use]
    pub fn with_limits(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            seen: HashSet::new(),
            queue: VecDeque::new(),
            ttl_ms,
            max_entries,
        }
    }

    /// broker 主入口：解析 → 校验（TTL / 重放 / 容量）→ 单次消费。
    ///
    /// `now_ms` 由调用方统一提供（单调时钟来源由 broker 决定）。
    /// 任一失败 → [`CfBrowserError::GestureInvalid`]（8007，不区分格式/过期/重放——
    /// 信息泄露纪律，不给攻击者反馈被击穿的具体层）。
    pub fn validate_and_consume(&mut self, gesture: &str, now_ms: u64) -> Result<(), CfBrowserError> {
        let g = Gesture::parse(gesture)?;
        self.consume(&g, now_ms)
    }

    /// 消费一个**已解析**的手势：TTL 窗口 / 重放 / 容量校验，通过则登记 nonce。
    pub fn consume(&mut self, gesture: &Gesture, now_ms: u64) -> Result<(), CfBrowserError> {
        self.evict_expired(now_ms);
        if !gesture.within_ttl_with(now_ms, self.ttl_ms) {
            return Err(CfBrowserError::GestureInvalid);
        }
        if self.seen.contains(gesture.nonce()) {
            return Err(CfBrowserError::GestureInvalid);
        }
        if self.seen.len() >= self.max_entries {
            return Err(CfBrowserError::GestureInvalid);
        }
        let nonce = *gesture.nonce();
        self.seen.insert(nonce);
        self.queue.push_back((nonce, gesture.issued_at_ms()));
        Ok(())
    }

    /// 当前存活（未过期、未淘汰）的已消费 nonce 数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// 是否无已消费 nonce。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// 逐出 `now - ttl` 之前的条目（front 出队，队列签发时间近似升序）。
    fn evict_expired(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.ttl_ms);
        while let Some((nonce, issued_at_ms)) = self.queue.front().copied() {
            if issued_at_ms > cutoff {
                break;
            }
            self.queue.pop_front();
            self.seen.remove(&nonce);
        }
    }
}

impl Default for GestureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// base64 严格解码（标准字母表 `A-Za-z0-9+/`，恰 24 字节手势 → 恰 32 字符、无填充）。
///
/// 非标准字符 / 长度非 32 → [`CfBrowserError::GestureInvalid`]。手势净长 24 字节
/// （24 % 3 == 0）→ base64 恒 32 字符且无 `=` 填充，与扩展 `atob` 对 24 字节输入的
/// 行为一致（多余/缺失字符在 `atob` 均抛错）。
fn decode_base64_strict(s: &str) -> Result<[u8; GESTURE_TOTAL_LEN], CfBrowserError> {
    if s.len() != 32 {
        return Err(CfBrowserError::GestureInvalid);
    }
    let mut out = [0u8; GESTURE_TOTAL_LEN];
    for (chunk, target) in s
        .as_bytes()
        .chunks_exact(4)
        .zip(out.chunks_exact_mut(3))
    {
        let a = [
            decode_b64_char(chunk[0]).ok_or(CfBrowserError::GestureInvalid)?,
            decode_b64_char(chunk[1]).ok_or(CfBrowserError::GestureInvalid)?,
            decode_b64_char(chunk[2]).ok_or(CfBrowserError::GestureInvalid)?,
            decode_b64_char(chunk[3]).ok_or(CfBrowserError::GestureInvalid)?,
        ];
        target[0] = (a[0] << 2) | (a[1] >> 4);
        target[1] = (a[1] << 4) | (a[2] >> 2);
        target[2] = (a[2] << 6) | a[3];
    }
    Ok(out)
}

/// 单个 base64 字符 → 6 位值；非字母表字符 → `None`。
fn decode_b64_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! 手势纯逻辑单元测试（docs/31 §5.2 / D-7：格式 / TTL 窗口 / 单次消费 / 有界）。
    //!
    //! 注：本模块在 `#![deny(clippy::unwrap_used, clippy::expect_used)]` 之下，
    //! 用 `?` 与 `assert_*` 而非 unwrap/expect（对齐 e2e.rs 测试先例）。

    use super::*;

    /// 冻结线格式向量（扩展 `makeGesture(1_700_000_000_000)` 同构：
    /// nonce = 0x00..0x0f，issuedAtMs = 1_700_000_000_000，大端，base64 32 字符）。
    /// Python 独立首算：base64(nonce(16) ‖ struct.pack(">Q", ts))。
    const FROZEN_GESTURE: &str = "AAECAwQFBgcICQoLDA0ODwAAAYvP5WgA";
    const FROZEN_NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const FROZEN_ISSUED_MS: u64 = 1_700_000_000_000;

    /// 测试助手：编码手势（仅测试用——broker 侧不产手势，只校验与消费）。
    fn make_gesture(nonce: [u8; GESTURE_NONCE_LEN], issued_at_ms: u64) -> String {
        let mut raw = [0u8; GESTURE_TOTAL_LEN];
        raw[..GESTURE_NONCE_LEN].copy_from_slice(&nonce);
        raw[GESTURE_NONCE_LEN..].copy_from_slice(&issued_at_ms.to_be_bytes());
        let mut out = String::with_capacity(32);
        for chunk in raw.chunks_exact(3) {
            let b0 = encode_b64_char(chunk[0] >> 2);
            let b1 = encode_b64_char(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4));
            let b2 = encode_b64_char(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6));
            let b3 = encode_b64_char(chunk[2] & 0x3f);
            out.push(b0);
            out.push(b1);
            out.push(b2);
            out.push(b3);
        }
        out
    }

    /// 测试助手：base64 字符编码。
    fn encode_b64_char(v: u8) -> char {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        TABLE[v as usize] as char
    }

    fn nonce_from(n: u8) -> [u8; GESTURE_NONCE_LEN] {
        [n; GESTURE_NONCE_LEN]
    }

    #[test]
    fn parse_frozen_extension_vector_roundtrip() -> Result<(), CfBrowserError> {
        let g = Gesture::parse(FROZEN_GESTURE)?;
        assert_eq!(g.nonce(), &FROZEN_NONCE);
        assert_eq!(g.issued_at_ms(), FROZEN_ISSUED_MS);
        // 签发瞬间即在 TTL 窗口内
        assert!(g.within_ttl(FROZEN_ISSUED_MS));
        Ok(())
    }

    #[test]
    fn valid_gesture_within_ttl_passes() -> Result<(), CfBrowserError> {
        let now = 1_700_000_000_000u64;
        let s = make_gesture(nonce_from(7), now - 5_000);
        let g = Gesture::parse(&s)?;
        assert!(g.within_ttl(now));
        let mut reg = GestureRegistry::new();
        reg.validate_and_consume(&s, now)?;
        assert_eq!(reg.len(), 1);
        Ok(())
    }

    #[test]
    fn expired_gesture_outside_ttl_rejected() -> Result<(), CfBrowserError> {
        let now = 1_700_000_000_000u64;
        let s = make_gesture(nonce_from(1), now - GESTURE_TTL_MS - 1);
        let g = Gesture::parse(&s)?;
        assert!(!g.within_ttl(now));
        let mut reg = GestureRegistry::new();
        assert!(matches!(
            reg.validate_and_consume(&s, now),
            Err(CfBrowserError::GestureInvalid)
        ));
        assert!(reg.is_empty());
        Ok(())
    }

    #[test]
    fn ttl_boundary_exact_tick_passes_just_past_fails() -> Result<(), CfBrowserError> {
        let now = 1_700_000_000_000u64;
        // 恰在 TTL 上（now - TTL）：放行
        let at_edge = make_gesture(nonce_from(2), now - GESTURE_TTL_MS);
        assert!(Gesture::parse(&at_edge)?.within_ttl(now));
        // 早 1ms（now - TTL - 1）：过期拒
        let past_edge = make_gesture(nonce_from(3), now - GESTURE_TTL_MS - 1);
        assert!(!Gesture::parse(&past_edge)?.within_ttl(now));
        Ok(())
    }

    #[test]
    fn future_issued_gesture_rejected() -> Result<(), CfBrowserError> {
        let now = 1_700_000_000_000u64;
        let s = make_gesture(nonce_from(4), now + 60_000);
        let g = Gesture::parse(&s)?;
        assert!(!g.within_ttl(now));
        let mut reg = GestureRegistry::new();
        assert!(matches!(
            reg.validate_and_consume(&s, now),
            Err(CfBrowserError::GestureInvalid)
        ));
        Ok(())
    }

    #[test]
    fn replay_same_nonce_second_consumption_rejected() -> Result<(), CfBrowserError> {
        let now = 1_700_000_000_000u64;
        let s = make_gesture(nonce_from(9), now - 1_000);
        let g = Gesture::parse(&s)?;
        let mut reg = GestureRegistry::new();
        reg.consume(&g, now)?;
        // 同一 nonce 二次消费（同 TTL 内）→ 重放拒
        assert!(matches!(
            reg.consume(&g, now),
            Err(CfBrowserError::GestureInvalid)
        ));
        // validate_and_consume 入口同样拒
        assert!(matches!(
            reg.validate_and_consume(&s, now + 1_000),
            Err(CfBrowserError::GestureInvalid)
        ));
        assert_eq!(reg.len(), 1);
        Ok(())
    }

    #[test]
    fn malformed_inputs_rejected() {
        let now = 1_700_000_000_000u64;
        let mut reg = GestureRegistry::new();
        // 空串
        assert!(Gesture::parse("").is_err());
        // 非 base64 字符（长度错 + 非法字符，扩展 `"not-base64!!"` 对拍）
        assert!(Gesture::parse("not-base64!!").is_err());
        // 长度错：4 字符 → 3 字节（扩展 `parseGesture("AAAA")` → null 对拍）
        assert!(Gesture::parse("AAAA").is_err());
        // 32 字符但含非字母表字符
        let mut bad_char = String::from(FROZEN_GESTURE);
        bad_char.replace_range(10..11, "!");
        assert!(Gesture::parse(&bad_char).is_err());
        // 时间戳为 0（大端全零）
        let zero_ts = make_gesture(nonce_from(5), 0);
        assert!(Gesture::parse(&zero_ts).is_err());
        // 时间戳超 JS safe-integer（2^53）
        let huge_ts = make_gesture(nonce_from(6), 1u64 << 53);
        assert!(Gesture::parse(&huge_ts).is_err());
        // 全部经 validate_and_consume 统一 8007 拒（畸形/过期/重放不区分，信息泄露纪律）
        assert!(matches!(
            reg.validate_and_consume("", now),
            Err(CfBrowserError::GestureInvalid)
        ));
        assert!(matches!(
            reg.validate_and_consume("AAAA", now),
            Err(CfBrowserError::GestureInvalid)
        ));
    }

    #[test]
    fn ttl_eviction_is_bounded() -> Result<(), CfBrowserError> {
        // 注入短 TTL（10ms）验证淘汰：过期 nonce 在下次消费时出队，len 回落、有界
        let mut reg = GestureRegistry::with_limits(10, DEFAULT_MAX_ENTRIES);
        let t0 = 1_700_000_000_000u64;
        let g1 = Gesture::parse(&make_gesture(nonce_from(1), t0 - 1))?;
        let g2 = Gesture::parse(&make_gesture(nonce_from(2), t0 - 2))?;
        reg.consume(&g1, t0)?;
        reg.consume(&g2, t0)?;
        assert_eq!(reg.len(), 2);
        // t0+11ms：g1/g2（t0-1/t0-2 签发）均已过 10ms TTL → 消费 g3 时逐出，len 回落
        let t1 = t0 + 11;
        let g3 = Gesture::parse(&make_gesture(nonce_from(3), t1))?;
        reg.consume(&g3, t1)?;
        assert_eq!(reg.len(), 1); // g1/g2 已淘汰，仅 g3 存活
        assert!(reg.len() <= 2); // 队列恒有界（max_entries + 过期逐出）
        Ok(())
    }

    #[test]
    fn capacity_cap_rejects_when_full() -> Result<(), CfBrowserError> {
        // 容量 2，TTL 很大（不触发淘汰）→ 第 3 个不同 nonce 拒（fail-closed）
        let mut reg = GestureRegistry::with_limits(GESTURE_TTL_MS, 2);
        let now = 1_700_000_000_000u64;
        reg.consume(&Gesture::parse(&make_gesture(nonce_from(1), now - 1_000))?, now)?;
        reg.consume(&Gesture::parse(&make_gesture(nonce_from(2), now - 1_000))?, now)?;
        assert!(matches!(
            reg.consume(&Gesture::parse(&make_gesture(nonce_from(3), now - 1_000))?, now),
            Err(CfBrowserError::GestureInvalid)
        ));
        assert_eq!(reg.len(), 2);
        // 已消费 nonce 仍拒（重放优先于容量）
        assert!(matches!(
            reg.consume(&Gesture::parse(&make_gesture(nonce_from(1), now - 1_000))?, now),
            Err(CfBrowserError::GestureInvalid)
        ));
        Ok(())
    }

    #[test]
    fn registry_len_reflects_consumed_and_is_empty() -> Result<(), CfBrowserError> {
        let mut reg = GestureRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        let now = 1_700_000_000_000u64;
        reg.validate_and_consume(&make_gesture(nonce_from(42), now - 100), now)?;
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
        Ok(())
    }
}
