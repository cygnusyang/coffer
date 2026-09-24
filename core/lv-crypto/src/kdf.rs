//! Argon2id 密钥派生（KDF）。
//!
//! 对应设计文档：
//! - `docs/03-详细设计.md` §2.2 主密码归一化
//! - `docs/03-详细设计.md` §2.3 Argon2id 参数与标定方法
//! - `docs/01-需求分析.md` NFR-SEC-01 / NFR-SEC-02 / NFR-SEC-03
//!
//! # ⚠️ 未编译验证，且已知需校准的 API 点
//!
//! 本文件依据 `argon2` **0.6.0** 的公开文档编写（crates.io 实测版本，
//! 见 `core/Cargo.toml`），但**未经 `cargo build` 验证**。
//!
//! 已确认（来自官方文档示例）：
//! - `Argon2::hash_password_into(password, salt, &mut out)` 在 0.6 中仍存在，
//!   且官方明确推荐用它与 `hash_password`（PHC 字符串）区分开：
//!   *"Do not use this API to derive cryptographic keys: see the key derivation
//!   usage example below."*
//! - `Argon2::new_with_secret(secret, Algorithm, Version, Params)` 的签名形态
//!   印证了 `Argon2::new(Algorithm, Version, Params)` 的四段式构造。
//! - 0.6 新增了 `ParamsBuilder`。
//!
//! **待校准**：
//! 1. `Params::new(m_cost, t_cost, p_cost, output_len)` 的签名。0.5 版本中
//!    `output_len` 参数类型为 `Option<usize>`；若 0.6 改用 `ParamsBuilder`，
//!    需按 `docs.rs/argon2/0.6.0/argon2/struct.ParamsBuilder.html` 调整。
//! 2. `Params::new` 中 `m_cost` 的单位是否仍为 KiB（0.5 是）。
//! 3. `Algorithm::Argon2id` / `Version::V0x13` 的变体名是否变化。
//!
//! M0 第一项任务即编译本模块并逐条核对以上三点。

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::LvCryptoError;

// ---------------------------------------------------------------- 常量

/// 盐长度（字节）。库盐固定 32 字节，见 `docs/03-详细设计.md` §1.3。
pub const SALT_LEN: usize = 32;

/// 派生密钥长度（字节）。KEK 固定 256 bit。
pub const KEY_LEN: usize = 32;

/// `m_cost` 下限（KiB）。
pub const MIN_M_COST_KIB: u32 = 8 * 1024;

/// `m_cost` 上限（KiB）= 4 GiB。
///
/// 设上限的目的是防御 `header.json` 被篡改为极端值导致解锁时 OOM。
/// 见 `docs/04-系统设计.md` §4.3 的举例说明。
pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;

/// `t_cost` 下限。
pub const MIN_T_COST: u32 = 1;

/// `t_cost` 上限。
pub const MAX_T_COST: u32 = 100;

/// `p_cost` 下限。
pub const MIN_P_COST: u32 = 1;

/// `p_cost` 上限。
pub const MAX_P_COST: u32 = 64;

// ---------------------------------------------------------------- 参数

/// Argon2id 参数组。
///
/// 该结构会被序列化进 `header.json` 的 `kdf` 字段
/// （见 `docs/03-详细设计.md` §1.3），因此**参数随库文件走**：
/// 调整默认参数后，旧库仍能用其自带参数正常打开。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// 内存开销，单位 **KiB**。
    pub m_cost_kib: u32,
    /// 迭代次数（时间开销）。
    pub t_cost: u32,
    /// 并行度。
    ///
    /// 注意：该值会让 Argon2 实现内部启用多线程，因此
    /// **同一时刻不应并发执行多个 KDF 任务**，否则会造成 CPU 过订阅
    /// （见 `docs/02-概要设计.md` §2.2「线程模型」）。
    pub p_cost: u32,
}

impl KdfParams {
    /// 构造参数组并立即校验。
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self, LvCryptoError> {
        let p = Self {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        p.validate()?;
        Ok(p)
    }

    /// 内存开销（MiB），便于人读与日志输出。
    pub fn m_cost_mib(&self) -> f64 {
        f64::from(self.m_cost_kib) / 1024.0
    }

    /// 校验参数是否在允许区间内。
    ///
    /// **必须在解锁流程中调用**（而不仅在创建库时）：参数来自库文件，
    /// 而库文件可能被篡改。
    pub fn validate(&self) -> Result<(), LvCryptoError> {
        if self.m_cost_kib < MIN_M_COST_KIB {
            return Err(LvCryptoError::InvalidParams(format!(
                "m_cost 低于下限：{} KiB < {} KiB",
                self.m_cost_kib, MIN_M_COST_KIB
            )));
        }
        if self.m_cost_kib > MAX_M_COST_KIB {
            return Err(LvCryptoError::InvalidParams(format!(
                "m_cost 超出上限：{} KiB > {} KiB",
                self.m_cost_kib, MAX_M_COST_KIB
            )));
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            return Err(LvCryptoError::InvalidParams(format!(
                "t_cost 越界：{}（允许 {MIN_T_COST}..={MAX_T_COST}）",
                self.t_cost
            )));
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost) {
            return Err(LvCryptoError::InvalidParams(format!(
                "p_cost 越界：{}（允许 {MIN_P_COST}..={MAX_P_COST}）",
                self.p_cost
            )));
        }
        Ok(())
    }
}

/// 参数标定的候选组合（**待标定的起始值，不是最终值**）。
///
/// 依据：`docs/03-详细设计.md` §2.3 的标定流程 ——
/// 固定 `t_cost=3, p_cost=4`，让 `m_cost` 从 64 MiB 起按 2 倍递增，
/// 选取在**最低端目标设备**上耗时落在 0.5–1.0 s 的最大值。
///
/// 该区间下界的依据是 OWASP Password Storage Cheat Sheet 给出的
/// Argon2id 最低可接受配置（m=19 MiB, t=2, p=1）；本项目因缺少
/// 1Password 的 Secret Key，必须显著高于该下限
/// （见 `docs/01-需求分析.md` NFR-SEC-03）。
pub const PRESET_CANDIDATES: &[KdfParams] = &[
    KdfParams { m_cost_kib: 64 * 1024,  t_cost: 3, p_cost: 4 },   // 64 MiB
    KdfParams { m_cost_kib: 128 * 1024, t_cost: 3, p_cost: 4 },   // 128 MiB
    KdfParams { m_cost_kib: 192 * 1024, t_cost: 3, p_cost: 4 },   // 192 MiB
    KdfParams { m_cost_kib: 256 * 1024, t_cost: 3, p_cost: 4 },   // 256 MiB
    KdfParams { m_cost_kib: 384 * 1024, t_cost: 3, p_cost: 4 },   // 384 MiB
    KdfParams { m_cost_kib: 512 * 1024, t_cost: 3, p_cost: 4 },   // 512 MiB
];

// ---------------------------------------------------------------- 归一化

/// 对主密码做 Unicode **NFC** 归一化。
///
/// # 为什么必须做
///
/// 不做归一化时，同一个"看起来一样"的密码在不同输入法 / 不同平台上
/// 可能产生**不同的字节序列**，表现为「在 Android 上设的密码在 macOS 打不开」。
/// 详见 `docs/03-详细设计.md` §2.2。
///
/// # 刻意不做的三件事
///
/// - **不 trim**：前后空格是密码的一部分，用户可能有意为之
/// - **不做大小写折叠**：保持原样
/// - **不做长度截断**：不设上限
pub fn normalize_password(password: &str) -> String {
    password.nfc().collect()
}

// ---------------------------------------------------------------- 派生

/// 用 Argon2id 从主密码派生 KEK。
///
/// # 参数
///
/// - `password`：主密码原文。函数内部会做 NFC 归一化，调用方**不需要**预处理。
/// - `salt`：库盐，长度必须等于 [`SALT_LEN`]。
/// - `params`：从 `header.json` 读取的参数，函数内部会重新校验。
///
/// # 返回值
///
/// 32 字节派生密钥，包装在 [`Zeroizing`] 中，离开作用域时自动清零。
///
/// # 安全说明
///
/// 本函数**不负责**判定密码是否正确 —— 那是 `verifier` 的职责
/// （见 `docs/03-详细设计.md` §2.6）。本函数只做派生，
/// 任何密码都会成功派生出一个（很可能是错的）密钥。
pub fn derive_key(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, LvCryptoError> {
    // 1. 参数校验 —— 参数来自库文件，而库文件可能被篡改
    params.validate()?;

    // 2. 盐长度校验
    if salt.len() != SALT_LEN {
        return Err(LvCryptoError::InvalidLength(format!(
            "盐长度必须为 {SALT_LEN} 字节，实际为 {}",
            salt.len()
        )));
    }

    // 3. NFC 归一化。用 Zeroizing 包装，避免归一化后的中间值残留在内存
    let normalized: Zeroizing<String> = Zeroizing::new(normalize_password(password));

    // 4. 构造 Argon2 上下文
    let argon2_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| LvCryptoError::InvalidParams(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // 5. 派生到原始字节缓冲
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(normalized.as_bytes(), salt, out.as_mut())
        .map_err(|_| LvCryptoError::KdfFailed)?;

    Ok(out)
}

/// 测量一次 KDF 耗时。
///
/// 供 M0 阶段参数标定使用（见 `examples/bench_kdf.rs` 与
/// `docs/03-详细设计.md` §2.3）。生产代码不应调用本函数。
pub fn measure_once(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Duration, LvCryptoError> {
    let start = Instant::now();
    let _key = derive_key(password, salt, params)?;
    Ok(start.elapsed())
}

/// 生成一个密码学安全的随机盐。
///
/// 用 `getrandom` 直接取操作系统 CSPRNG（见 `docs/02-概要设计.md` §3）。
///
/// ⚠️ 待校准：`getrandom` 0.4 的 API 与 0.2/0.3 差异较大，
/// 使用前请核对 `docs.rs/getrandom/0.4.3`。
pub fn random_salt() -> Result<[u8; SALT_LEN], LvCryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| LvCryptoError::InvalidParams(format!("CSPRNG 不可用：{e}")))?;
    Ok(salt)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; SALT_LEN] {
        // 测试用固定盐，便于复现
        [0x42u8; SALT_LEN]
    }

    #[test]
    fn 派生是确定性的() {
        // 同密码 + 同盐 + 同参数 → 必须得到同一密钥
        let params = KdfParams::new(64 * 1024, 3, 4).expect("参数合法");
        let salt = test_salt();

        let k1 = derive_key("correct horse battery staple", &salt, params).expect("派生成功");
        let k2 = derive_key("correct horse battery staple", &salt, params).expect("派生成功");

        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn 不同盐产生不同密钥() {
        let params = KdfParams::new(64 * 1024, 3, 4).expect("参数合法");
        let k1 = derive_key("same password", &[0x01u8; SALT_LEN], params).expect("派生成功");
        let k2 = derive_key("same password", &[0x02u8; SALT_LEN], params).expect("派生成功");

        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn 不同密码产生不同密钥() {
        let params = KdfParams::new(64 * 1024, 3, 4).expect("参数合法");
        let salt = test_salt();
        let k1 = derive_key("password A", &salt, params).expect("派生成功");
        let k2 = derive_key("password B", &salt, params).expect("派生成功");

        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    /// 本测试覆盖 `docs/03-详细设计.md` §2.2 的核心风险：
    /// 同一个视觉等价的密码，其两种 Unicode 表示必须派生出**相同**密钥。
    ///
    /// - U+00E9 (é)              —— NFC 形式
    /// - "e" + U+0301 (组合尖音)  —— NFD 形式
    #[test]
    fn nfc_归一化使等价密码产生相同密钥() {
        let params = KdfParams::new(64 * 1024, 3, 4).expect("参数合法");
        let salt = test_salt();

        let precomposed = "caf\u{00E9}-password";   // NFC
        let decomposed = "cafe\u{0301}-password";   // NFD

        // 前提检查：两者在字节层面确实不同，否则本测试无意义
        assert_ne!(
            precomposed.as_bytes(),
            decomposed.as_bytes(),
            "测试前提不成立：两个字符串的 UTF-8 字节相同"
        );

        let k1 = derive_key(precomposed, &salt, params).expect("派生成功");
        let k2 = derive_key(decomposed, &salt, params).expect("派生成功");

        assert_eq!(
            k1.as_ref(),
            k2.as_ref(),
            "NFC 归一化未生效 —— 这正是「Android 设的密码 macOS 打不开」的成因"
        );
    }

    #[test]
    fn 参数越界被拒绝() {
        // m_cost 过大 —— 防御 header.json 被篡改为极端值
        assert!(KdfParams::new(8 * 1024 * 1024, 3, 4).is_err());
        // m_cost 过小
        assert!(KdfParams::new(1024, 3, 4).is_err());
        // t_cost 为零
        assert!(KdfParams::new(64 * 1024, 0, 4).is_err());
        // p_cost 为零
        assert!(KdfParams::new(64 * 1024, 3, 0).is_err());
    }

    #[test]
    fn 盐长度不符时拒绝() {
        let params = KdfParams::new(64 * 1024, 3, 4).expect("参数合法");
        let short_salt = [0u8; 16];

        let err = derive_key("password", &short_salt, params);
        assert!(matches!(err, Err(LvCryptoError::InvalidLength(_))));
    }

    #[test]
    fn 所有候选参数组合都合法() {
        for p in PRESET_CANDIDATES {
            p.validate()
                .unwrap_or_else(|e| panic!("候选参数 {p:?} 校验失败：{e}"));
        }
    }

    /// 冒烟测试：跑一次真实派生，确认底层库可用。
    ///
    /// 刻意用最小参数（8 MiB）以便快速执行；这不是安全性测试，
    /// 只是"能不能跑通"的检查。真正的参数标定见 examples/bench_kdf.rs。
    #[test]
    fn 最小参数下可以成功派生() {
        let params = KdfParams::new(MIN_M_COST_KIB, 1, 1).expect("参数合法");
        let salt = test_salt();

        let key = derive_key("smoke test", &salt, params).expect("派生成功");
        assert_eq!(key.len(), KEY_LEN);
        // 全零输出意味着底层实现没有真正工作
        assert_ne!(key.as_ref(), &[0u8; KEY_LEN], "派生结果全零，实现可疑");
    }
}
