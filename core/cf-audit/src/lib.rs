//! # cf-audit —— 离线安全检查
//!
//! 弱密码 / 重复密码 / 弱 URL / 陈旧密码检测，产出体检报告。
//!
//! ## 对应设计文档
//!
//! - `docs/03-详细设计.md` §8（安全检查规则集）
//! - `docs/01-需求分析.md` §5-F（FR-6 安全检查）
//!
//! ## 职责边界
//!
//! **硬约束：不得联网。** 本 crate 不得引入任何网络相关依赖
//! （CI 中有自动检查，见 `docs/04-系统设计.md` §11.1）。
//! 所依赖的 zxcvbn / passwords 均为纯本地计算，满足此约束。
//!
//! 能力缺口必须向用户明示：本模块**无法**检测「密码已在某次数据泄露中出现」，
//! 该能力需要查询在线泄露库。UI 与文档三处都要写明（FR-6.5）。
//!
//! 实现要点：重复密码检测用 HMAC 摘要比对，**不能明文比较**（§8 AUD-02）。
//!
//! ## 状态
//!
//! **部分实现**：
//!
//! - ✅ 密码强度评估（zxcvbn，FR-6.1）—— [`password_strength`]
//! - ✅ 随机密码生成（passwords，FR-3，参数化：docs/07 §2.3 `PasswordGenOptions`）—— [`generate_password`]
//! - ❌ 重复密码 / 弱 URL / 陈旧密码检测 —— 待实现（后续版本）
//!
//! 参见 `README.md`「当前状态」与 `docs/04-系统设计.md` §10.1（阶段划分）。
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`；生产代码禁 `unwrap` / `expect`
//! （测试代码经 `clippy.toml` 放行）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

/// 生成密码的最小长度（FR-3.2：长度 8–100）。
pub const MIN_PASSWORD_LEN: usize = 8;

/// 生成密码的最大长度（FR-3.2：长度 8–100，docs/07 §7 T02）。
pub const MAX_PASSWORD_LEN: usize = 100;

/// 随机密码生成参数（docs/07 §2.3 `PasswordGenOptions` 的 Rust 侧形态）。
///
/// 长度区间 `[`[`MIN_PASSWORD_LEN`]`, `[`[`MAX_PASSWORD_LEN`]`]`；至少启用
/// 一个字符集，否则 [`generate_password`] 拒绝（空字符集无法生成任何密码）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordGenOptions {
    /// 密码长度（字符数），`MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN`。
    pub length: usize,
    /// 包含数字。
    pub numbers: bool,
    /// 包含小写字母。
    pub lowercase_letters: bool,
    /// 包含大写字母。
    pub uppercase_letters: bool,
    /// 包含符号。
    pub symbols: bool,
    /// 排除易混淆字符（`iI1loO0"'`|`）。
    pub exclude_similar_characters: bool,
}

impl Default for PasswordGenOptions {
    /// 默认策略：20 位、四类字符齐全、排除易混淆字符（与参数化前的行为一致）。
    fn default() -> Self {
        Self {
            length: 20,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            exclude_similar_characters: true,
        }
    }
}

/// 密码强度评估（zxcvbn，FR-6.1）。
///
/// 返回 0–4 分（[`zxcvbn::Score`]）：zxcvbn 建议 **3 分及以上**才算
/// 可接受（`Score::Three`）；0–2 分应视为过弱并拒绝 / 要求更换。
///
/// 本函数不接收用户输入上下文（用户名、邮箱等）——zxcvbn 若拿到这些
/// 信息会给「包含个人信息的密码」更低的分数。当前按「无上下文」评估，
/// 后续如需精细化可在调用侧补充。
#[must_use]
pub fn password_strength(pw: &str) -> zxcvbn::Score {
    zxcvbn::zxcvbn(pw, &[]).score()
}

/// 判定密码是否达到建库门禁阈值（zxcvbn score ≥ 3，FR-1.3 / docs/07 §2.2）。
///
/// [`crate::password_strength`] 的布尔便捷封装，供 cf-session 建库流程
/// 直接调用（score < 3 → `CfError::WeakPassword` 硬拒绝）。
#[must_use]
pub fn meets_strength_threshold(pw: &str) -> bool {
    password_strength(pw) >= zxcvbn::Score::Three
}

/// 生成随机密码（FR-3，参数化）。
///
/// 长度与字符集由调用方通过 [`PasswordGenOptions`] 指定；strict 模式确保
/// 每个启用的字符类至少出现一次。熵源为 CSPRNG（`passwords` crate 基于
/// `getrandom`）。
///
/// # Errors
///
/// - `length` 不在 `[`[`MIN_PASSWORD_LEN`]`, `[`[`MAX_PASSWORD_LEN`]`]` 区间
///   （FR-3.2：8–100）→ 返回长度错误说明；
/// - 四个字符集全部关闭 → 返回字符集错误说明；
/// - 底层生成器失败（正常参数下不会发生）→ 透传 `passwords` 的错误文本。
pub fn generate_password(opts: &PasswordGenOptions) -> Result<String, &'static str> {
    if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&opts.length) {
        return Err("password length must be between 8 and 100");
    }
    if !(opts.numbers || opts.lowercase_letters || opts.uppercase_letters || opts.symbols) {
        return Err("at least one character class must be enabled");
    }
    passwords::PasswordGenerator::new()
        .length(opts.length)
        .numbers(opts.numbers)
        .lowercase_letters(opts.lowercase_letters)
        .uppercase_letters(opts.uppercase_letters)
        .symbols(opts.symbols)
        .exclude_similar_characters(opts.exclude_similar_characters)
        .strict(true)
        .generate_one()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-6.1：常见弱密码必须被评低分
    #[test]
    fn common_passwords_score_low() {
        for weak in ["password", "123456", "qwerty", "iloveyou"] {
            let score = password_strength(weak);
            assert!(
                score < zxcvbn::Score::Three,
                "「{weak}」被评 {score:?}，弱密码不应达到可接受分数线"
            );
        }
    }

    /// 强度评估不 panic（空串、超长输入等边界）
    #[test]
    fn password_strength_handles_edge_inputs() {
        let _ = password_strength("");
        let _ = password_strength("a");
        let _ = password_strength(&"x".repeat(10_000));
    }

    /// 建库门禁便捷封装：弱密码不过线、强随机密码过线
    #[test]
    fn meets_strength_threshold_matches_score() {
        assert!(!meets_strength_threshold("123456"));
        assert!(!meets_strength_threshold("password"));
        assert!(meets_strength_threshold("correct horse battery staple 42!"));
    }

    /// FR-3：默认参数生成的密码满足形状约束（长度 20 + 四类字符齐全）
    #[test]
    fn generated_password_shape() {
        let pw = generate_password(&PasswordGenOptions::default()).unwrap();
        assert_eq!(pw.len(), 20);
        assert!(pw.chars().any(|c| c.is_ascii_digit()), "应含数字");
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()), "应含小写");
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()), "应含大写");
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()), "应含符号");
    }

    /// 生成的随机密码强度评估应为高分区（zxcvbn 对真随机长密码评 4 分）
    #[test]
    fn generated_password_scores_strong() {
        let pw = generate_password(&PasswordGenOptions::default()).unwrap();
        let score = password_strength(&pw);
        assert!(
            score >= zxcvbn::Score::Three,
            "生成密码被评 {score:?}，真随机 20 位密码不应低于可接受线"
        );
    }

    /// FR-3.2 参数化：长度参数生效
    #[test]
    fn 长度参数生效() {
        for len in [8, 32, 100] {
            let opts = PasswordGenOptions {
                length: len,
                ..PasswordGenOptions::default()
            };
            let pw = generate_password(&opts).unwrap();
            assert_eq!(pw.len(), len, "长度 {len} 应精确生效");
        }
    }

    /// FR-3.2 参数化：长度越界（7 / 101）被拒绝
    #[test]
    fn 长度越界被拒绝() {
        let short = PasswordGenOptions {
            length: MIN_PASSWORD_LEN - 1,
            ..PasswordGenOptions::default()
        };
        assert!(generate_password(&short).is_err());
        let long = PasswordGenOptions {
            length: MAX_PASSWORD_LEN + 1,
            ..PasswordGenOptions::default()
        };
        assert!(generate_password(&long).is_err());
    }

    /// FR-3.2 参数化：字符集关闭后对应字符类不再出现
    #[test]
    fn 关闭字符集后不再出现() {
        let opts = PasswordGenOptions {
            length: 24,
            numbers: false,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: false,
            exclude_similar_characters: true,
        };
        let pw = generate_password(&opts).unwrap();
        assert_eq!(pw.len(), 24);
        assert!(!pw.chars().any(|c| c.is_ascii_digit()), "不应含数字");
        assert!(
            !pw.chars().any(|c| !c.is_ascii_alphanumeric()),
            "不应含符号"
        );
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
    }

    /// 全部字符集关闭 → 拒绝（空字符集无法生成）
    #[test]
    fn 全部字符集关闭被拒绝() {
        let opts = PasswordGenOptions {
            numbers: false,
            lowercase_letters: false,
            uppercase_letters: false,
            symbols: false,
            ..PasswordGenOptions::default()
        };
        let err = generate_password(&opts).unwrap_err();
        assert!(err.contains("character class"), "{err}");
    }

    /// 默认参数与参数化前的行为一致：长度 20、四类齐全
    #[test]
    fn 默认参数与旧无参行为一致() {
        let opts = PasswordGenOptions::default();
        assert_eq!(opts.length, 20);
        assert!(opts.numbers && opts.lowercase_letters && opts.uppercase_letters && opts.symbols);
        assert!(opts.exclude_similar_characters);
    }
}
