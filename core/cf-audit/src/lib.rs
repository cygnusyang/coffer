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
//! **部分实现**（M1 阶段冒烟）：
//!
//! - ✅ 密码强度评估（zxcvbn，FR-6.1）—— [`password_strength`]
//! - ✅ 随机密码生成（passwords，FR-3）—— [`generate_password`]
//! - ❌ 重复密码 / 弱 URL / 陈旧密码检测 —— 待实现（M1 后续）
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

/// 生成随机密码（FR-3）。
///
/// 默认策略：20 位、数字 + 大小写 + 符号四类齐全、排除易混淆字符
/// （`iI1loO0"'`|`）、strict 模式确保每类字符至少出现一次。
/// 熵源为 CSPRNG（`passwords` crate 基于 `getrandom`）。
///
/// # Errors
///
/// 参数非法时返回 `&'static str`（本函数参数固定，正常不会触发；
/// 返回类型与 `passwords` 一致，留作上层处理通道）。
pub fn generate_password() -> Result<String, &'static str> {
    passwords::PasswordGenerator::new()
        .length(20)
        .numbers(true)
        .lowercase_letters(true)
        .uppercase_letters(true)
        .symbols(true)
        .exclude_similar_characters(true)
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

    /// FR-3：生成的密码满足形状约束（长度 + 四类字符齐全）
    #[test]
    fn generated_password_shape() {
        let pw = generate_password().unwrap();
        assert_eq!(pw.len(), 20);
        assert!(pw.chars().any(|c| c.is_ascii_digit()), "应含数字");
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()), "应含小写");
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()), "应含大写");
        assert!(
            pw.chars().any(|c| !c.is_ascii_alphanumeric()),
            "应含符号"
        );
    }

    /// 生成的随机密码强度评估应为高分区（zxcvbn 对真随机长密码评 4 分）
    #[test]
    fn generated_password_scores_strong() {
        let pw = generate_password().unwrap();
        let score = password_strength(&pw);
        assert!(
            score >= zxcvbn::Score::Three,
            "生成密码被评 {score:?}，真随机 20 位密码不应低于可接受线"
        );
    }
}
