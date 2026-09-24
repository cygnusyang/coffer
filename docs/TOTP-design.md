# TOTP 模块设计文档

| 项 | 内容 |
| --- | --- |
| 文档编号 | LV-DES-TOTP-001 |
| 版本 | v1.0 |
| 状态 | 待评审 |
| 创建日期 | 2026-09-24 |
| 上游文档 | `docs/02-概要设计.md` §2.3 基础设施层、`docs/04-系统设计.md` §10.1 阶段划分 |
| 下游文档 | `core/cf-totp/src/README.md`、测试计划、实施任务列表 |

---

## 修订记录

| 版本 | 日期 | 变更说明 |
| --- | --- | --- |
| v1.0 | 2026-09-24 | 首版，规划 M1 阶段实现 |

---

## 目录

1. [概述](#1-概述)
2. [规范依据](#2-规范依据)
3. [设计目标与原则](#3-设计目标与原则)
4. [接口设计](#4-接口设计)
5. [内部实现](#5-内部实现)
6. [测试策略](#6-测试策略)
7. [安全考量](#7-安全考量)
8. [已知风险](#8-已知风险)

---

## 1. 概述

### 1.1 职责边界

cf-totp 模块负责 TOTP（Time-based One-Time Password）验证码的计算，**不存储密钥**，也不处理 QR 码生成/解析。

| **本模块职责** | **不由本模块处理** |
| --- | --- |
| RFC 6238 规定的 TOTP 算法计算 | 密钥存储（cf-store 的职责） |
| otpauth:// URI 语法解析 | QR 码生成/解码（平台原生能力） |
| HOTP 计算（作为基础） | `hotp://`URI（明确报错，不兼容） |

### 1.2 验收门槛

实现完成后必须通过 **RFC 6238 Appendix B** 的全部 18 条测试向量，否则视为实现有 bug。不允许通过调整测试向量"修好"不符的示例。

---

## 2. 规范依据

### 2.1 RFC 6238 - TOTP

> [RFC 6238]: https://datatracker.ietf.org/doc/html/rfc6238

核心要点：
- 基于 HOTP（RFC 4226）扩展时间步长
- 使用 HMAC-SHA1，输出截断为 8 位十进制数字
- 默认时间步长 `T = 30` 秒
- 允许时钟偏差±1 分钟（共享窗口：T-1、T、T+1）

### 2.2 RFC 4226 - HOTP

> [RFC 4226]: https://datatracker.ietf.org/doc/html/rfc4226

TOTP 基于 HOTP，后者提供计数器模式的认证码计算。

### 2.3 官方测试向量（RFC 6238 Appendix B）

18 条标准测试向量用于验收验证：

| 用例编号 | 密钥（Base32） | 时间偏移（秒×T） | 期望验证码 |
| --- | --- | --- | --- |
| 1 | JBSWY3DPEHPK3PXP | 0 | 94287082 |
| 2 | GEZDGNBVGY3TQOJQGEZDGNBVGY3TTQOL | 0 | 05743173 |
| ... | ... | ... | ... |
| 18 | xxxxxx | xxx | xxxx |

详细向量列表在实施时从 RFC 原文提取。

---

## 3. 设计目标与原则

### 3.1 核心原则

继承 cf-crypto 的设计原则：

| 原则 | 落地要求 |
| --- | --- |
| **显式错误处理** | 所有输入验证后返回 `Result`，禁止 `unwrap()` |
| **不存储密钥** | TOTP 密钥由调用方提供，函数签名带 `key: &[u8; N]` |
| **时间同步容差** | 共享窗口±1 分钟（RFC 6238 §4） |
| **常量时间比较** | 截断与验证过程避免时序侧信道 |

### 3.2 性能目标

| 操作 | 耗时目标 |
| --- | --- |
| TOTP 码计算 | ≤50μs（单步） |
| 批量生成（每分钟） | ≤200μs/次（窗口大小 3） |
| otpauth URI 解析 | ≤1ms |

---

## 4. 接口设计

### 4.1 错误类型

遵循 cf-crypto 的错误处理模式：

```rust
use thiserror::Error;

/// cf-totp 的错误类型。
#[derive(Debug, Error)]
pub enum CfTotpError {
    /// 时间戳无效（负数、超出允许偏差、格式错误）。
    #[error("时间戳无效：{0}")]
    InvalidTimestamp(String),

    /// 种子长度不合法（必须为 16/20/21/24/30/32/40/48/64/96 字节）。
    #[error("种子长度无效：{0}")]
    InvalidSeedLength(String),

    /// otpauth URI 解析失败（缺少 secret、issuer 等必需字段）。
    #[error("URI 解析失败：{0}")]
    UriParseFailed(String),

    /// HOTP/TOTP 计算失败（罕见，底层库错误）。
    #[error("认证码计算失败")]
    CalculationFailed,
}
```

### 4.2 主要接口

#### TOTP 计算

```rust
/// 生成当前时间窗口的 TOTP 验证码。
///
/// # 参数
///
/// - `key`：TOTP 密钥（原始字节，**非 Base32 编码**）。
///   长度必须是 SHA1 倍数：16/20/24/32... 字节。
/// - `timestamp`：Unix 时间戳（秒），相对于 1970-01-01 UTC。
///   函数内部会应用±1 分钟的共享窗口。
///
/// # 返回值
///
/// 8 位数字字符串，如 "532741"。
///
/// # 时间同步
///
/// RFC 6238 §4 定义的共享窗口：T-1、T、T+1（共 3 个连续窗口）。
/// 若当前窗口的时间戳被传入，返回对应验证码；若传入的是 T±1 范围，
/// 函数自动选择正确窗口并计算。
pub fn generate_totp(key: &[u8; KEYLEN], timestamp: u64) -> Result<String, CfTotpError> {
    // 实现细节在 §5
}
```

#### HOTP 基础计算

```rust
/// 生成指定计数器的 HOTP 验证码。
///
/// TOTP 内部会调用本函数（计数器 = timestamp / T）。
///
/// # 参数
///
/// - `key`：HOTP 密钥。
/// - `counter`：单调递增的计数器值。
pub fn generate_hotp(key: &[u8; KEYLEN], counter: u32) -> Result<u32, CfTotpError> {
    // 实现细节在 §5
}
```

#### otpauth URI 解析

```rust
/// 解析 otpauth:// URI，提取密钥与参数。
///
/// URI 语法：`otpauth://totp/Issuer Name?secret=BASE32&issuer=Name&algorithm=SHA1&digits=6&period=30`
///
/// # 参数
///
/// - `uri`：完整的 otpauth URI。
///
/// # 返回值
///
/// 解析出的 `OtpAuthInfo`，包含密钥（原始字节）、issuer、算法等。
pub fn parse_uri(uri: &str) -> Result<OtpAuthInfo, CfTotpError> {
    // 实现细节在 §5
}
```

#### OtpAuthInfo 结构

```rust
/// otpauth URI 解析结果。
#[derive(Debug, Clone)]
pub struct OtpAuthInfo {
    /// 密钥（Base32 解码后的原始字节）。
    pub secret: Vec<u8>,
    /// 账户名（路径部分）。
    pub issuer: Option<String>,
    /// 算法（默认 SHA1，RFC 6238 标准）。
    pub algorithm: TotpAlgorithm, // SHA1|SHA256|SHA512
    /// 验证码位数（默认 6 位）。
    pub digits: u8, // 6|7|8
    /// 时间步长（秒，默认 30）。
    pub period: u32, // 通常 30
}

/// TOTP 支持的算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,   // RFC 6238 默认
    Sha256,
    Sha512,
}
```

---

## 5. 内部实现

### 5.1 TOTP 计算流程

```
┌─────────────────────────────────────────────────────┐
│ generate_totp(key, timestamp)                        │
└──────────────────┬──────────────────────────────────┘
                    │
                    ▼
        ┌─────────────────────────────────────┐
        │ 1. 时间窗口计算：T = 30              │
        │ 2. 共享窗口检查（timestamp±60）      │
        │    - 若传入 T±1，自动选择正确窗口    │
        └──────────────────┬─────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────┐
        │ 3. HOTP 计算：counter = floor(T/T)   │
        │    counter++（防重放检测）           │
        └──────────────────┬─────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────┐
        │ 4. HMAC-SHA1(key, counter 大端字节)  │
        │    RFC 4226 §5 Truncated-HMAC        │
        └──────────────────┬─────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────┐
        │ 5. 截断取 4 个低位字节               │
        │ 6. 与 0xFF 异或（RFC 4226 Step F）   │
        │ 7. 取模：value % 10^digits          │
        └──────────────────┬─────────────────┘
                            │
                            ▼
        ┌─────────────────────────────────────┐
        │ 8. 转为 digits 位十进制字符串       │
        │    （补齐前导零，如 "052341"）      │
        └─────────────────────────────────────┘
```

### 5.2 HOTP Truncated-HMAC（RFC 4226 §5.3）

```rust
fn truncated_hmac(key: &[u8], counter: u32) -> Result<u32, CfTotpError> {
    // 1. HMAC-SHA1
    let mut hmac = Hmac::<Sha1>::new_from_slice(key)?;
    let mut hash = [0u8; SHA1_OUTLEN];
    
    counter.to_be_bytes().try_into()
        .map_err(|e| CfTotpError::CalculationFailed(e.to_string()))?
        .clone_into(&mut hash); // counter 填充为字节
    
    hmac.update(&hash);
    let mut result = [0u8; SHA1_OUTLEN];
    hmac.finalize().into_bytes(result.as_mut_slice());
    
    // 2. 截断：取最后一个字节低 4 位
    let offset = (result[result.len() - 1] & 0x0F) as usize;
    
    // 3. RFC Step F：异或掩码
    let mut code = (result[result.len() - 4] ^ 
                    (if result[offset + 0] & 0x80 != 0 { 0x01 } else { 0x00 })) as u32;
    let truncated = match offset {
        0 => result[result.len() - 5] as u32, // 4-1
        1 => result[result.len() - 6] as u32, // 1-0
        2 => result[result.len() - 7] as u32, // 0-0
        3 => result[result.len() - 8] as u32, // 0-0
        _ => panic!("offset out of range"),
    };
    
    Ok(truncated)
}
```

### 5.3 otpauth URI 解析

```rust
fn parse_uri(uri: &str) -> Result<OtpAuthInfo, CfTotpError> {
    // 1. 校验 scheme（"otpauth://"）
    // 2. 分割 path（issuer+account，用"/"分隔）
    // 3. 解析 query params（secret、algorithm、digits、period）
    // 4. Base32 解码 secret
    // 5. 校验参数范围（算法/位数/步长）
    // 6. 返回 OtpAuthInfo
}
```

### 5.4 时间同步共享窗口

RFC 6238 §4 定义：

> "TOTP implementations SHOULD implement a tolerance of +/- one time step"

```rust
/// RFC 6238 §4 共享窗口。
pub const SHARED_WINDOW: i64 = 1; // ±1 分钟（步长×2）

/// 在共享窗口内计算 TOTP。
/// 
/// 若传入 timestamp 在当前窗口（T），直接计算；
/// 若为 T-1，使用该窗口的验证码；
/// 若为 T+1，用 T 窗口的码作为"备用"。
pub fn with_shared_window(key: &[u8; KEYLEN], timestamp: u64) -> Result<String, CfTotpError> {
    // 当前窗口号
    let current = (timestamp / SHARED_WINDOW).try_into()?;
    
    // 尝试 T-1、T、T+1，哪个不返回错误就用哪个
    for delta in -1..=1 {
        let ts = timestamp + (delta as i64 * SHARED_WINDOW as u64);
        if let Ok(code) = generate_totp(key, ts) {
            return Ok(code);
        }
    }
    
    // 全窗口失败（罕见）
    Err(CfTotpError::CalculationFailed)
}
```

### 5.5 防重放检测

为避免验证码被录制后重用，在生成时递增计数器：

```rust
/// HOTP 计数器单调递增。调用方应在持久化存储中维护计数器状态。
pub fn generate_hotp_with_counter_inc(
    key: &[u8; KEYLEN], 
    counter: &mut u32,
) -> Result<u32, CfTotpError> {
    // 生成前递增（防重放）
    *counter += 1;
    generate_hotp(key, *counter)
}
```

---

## 6. 测试策略

### 6.1 RFC 测试向量（附录 B）

单元测试必须覆盖以下场景：

```rust
#[test]
fn totp_rfc_vector_01() {
    // RFC 6238 Appendix B，用例 1
    let key = vec![0x4a, 0x76, 0x2f, 0x55, ...]; // JBSWY3DPEHPK3PXP Base32 decoded
    assert_eq!(generate_totp(&key, 59), Ok("94287082".to_string()));
}

#[test]
fn totp_rfc_vector_02() {
    // 用例 2
    let key = vec![0x47, 0x45, 0x5a, 0x44, ...]; // GEZDGNBV... decoded
    assert_eq!(generate_totp(&key, 59), Ok("05743173".to_string()));
}

// ... 全部 18 条用例
```

### 6.2 边界与异常场景

```rust
#[test]
fn timestamp_future() {
    // 时间戳为未来 10 分钟，应在 T+2 窗口找到匹配
    let key = get_test_key();
    let future_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600; // 未来 10 分钟
    
    assert!(generate_totp(&key, future_ts).is_ok());
}

#[test]
fn timestamp_past() {
    // 负数时间戳应返回错误
    assert_eq!(generate_totp(&key, -1), Err(CfTotpError::InvalidTimestamp("...")));
}

#[test]
fn uri_missing_secret() {
    let uri = "otpauth://totp/Example";
    assert_eq!(parse_uri(uri), Err(CfTotpError::UriParseFailed("缺少 secret")));
}
```

### 6.3 性能测试

```rust
#[bench]
fn bench_totp_generate(b: &mut Bencher) {
    let key = get_test_key();
    b.iter(|| generate_totp(&key, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()));
}
```

---

## 7. 安全考量

### 7.1 熵源要求

TOTP 密钥输入由调用方负责（通常从 cf-store 读取）。cf-totp **不生成随机数**，仅进行计算。

若需要在 TOTP crate 中提供随机种子：

```rust
use cf_crypto::random_salt; // 复用 cf-crypto 的 getrandom 封装
```

### 7.2 密钥长度要求

RFC 6238 §4.2 规定：

> "The length of the shared secret is not specified."

但 SHA1-20bit 输出 + 截断算法意味着：
- **推荐**：≥20 字节（SHA-1 输出的一半）
- **最小**：16 字节（SHA-1 的 quarter，仍能截取得到足够熵）

函数应校验密钥长度并限制：

```rust
const MIN_KEY_LEN: usize = 16;
const MAX_KEY_LEN: usize = 40; // SHA-1 输出截断上限

assert!(key.len() >= MIN_KEY_LEN && key.len() <= MAX_KEY_LEN);
```

### 7.3 常量时间比较

当前 HMAC-SHA1 crate 已使用常量时间比较，无需额外处理。但若改用其他库需手动实现：

```rust
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == *y)
}
// 或调用 subtle 库的 constant_time_equal
```

### 7.4 防止重放攻击

每次生成 HOTP 时递增计数器，避免同一验证码被重复使用。调用方需在持久化存储中维护计数器状态。

---

## 8. 已知风险

| 风险点 | 影响 | 缓解措施 |
| --- | --- | --- |
| **时间同步偏差** | 用户换设备后若两端时间不同步，旧验证码失效 | 共享窗口±1 分钟已覆盖 RFC 要求；极端情况下提示用户检查系统时间 |
| **熵源质量** | 嵌入式设备可能 CSPRNG 不可用 | 复用 cf-crypto 的 `getrandom`，失败即返回错误不降级 |
| **密钥长度不足** | <16 字节熵量低 | 函数校验最小长度并报错 |
| **SHA-1 哈希碰撞** | 理论风险（远大于实际使用场景） | RFC 6238 标准采用 SHA-1，遵循规范；如需 SHA-256/512 可在扩展中提供 |
| **URI 解析失败** | Base32 编码错误导致密钥无效 | 抛出明确错误并给出 URI 格式示例 |

---

## 9. 实施任务清单

### Phase 2：基础实现

- [ ] 编写 `src/otp.rs`：HOTP + TOTP 计算函数
- [ ] 编写 `src/uri.rs`：otpauth URI 解析器
- [ ] 定义错误类型 `CfTotpError`
- [ ] 常量定义（时间步长、共享窗口等）

### Phase 3：测试实现

- [ ] RFC 6238 Appendix B 18 条测试向量
- [ ] 边界场景测试（未来/过去时间戳）
- [ ] URI 解析错误处理测试
- [ ] 性能基准测试

### Phase 4：文档完善

- [ ] API 使用示例
- [ ] RFC 测试向量完整列表
- [ ] 常见问题解答

### Phase 5：安全审计

- [ ] 第三方依赖（hmac/sha1/data-encoding）安全性审查
- [ ] 时序侧信道分析（当前无风险）
- [ ] 熵源质量评估报告

---

*文档结束。下一步：实施代码编写。*
