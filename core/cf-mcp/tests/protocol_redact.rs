//! SecretRedactor 单元测试（docs/20 §3.5 输出脱敏，AS-11）。
//!
//! 判据：已知 secret 指纹（长度 ≥ 阈值 + 前缀特征，如 `sk-`）替换为
//! `[COFFER_SECRET_REDACTED]`；长度不足阈值 / 无前缀特征 / 普通文本不替换。

use cf_mcp::redact::{SecretRedactor, REDACTION_TOKEN};

#[test]
fn redacts_sk_prefixed_fingerprint() {
    // AS-11 原文样例：sk-abc123xxxxxxxx → [COFFER_SECRET_REDACTED]
    let r = SecretRedactor::new();
    assert_eq!(r.redact("sk-abc123xxxxxxxx"), REDACTION_TOKEN);
}

#[test]
fn keeps_short_tokens_below_threshold() {
    // "sk-x" 长 4 < 阈值 8，不得替换（避免误伤短引用）。
    let r = SecretRedactor::new();
    assert_eq!(r.redact("sk-x"), "sk-x");
}

#[test]
fn keeps_plain_text() {
    let r = SecretRedactor::new();
    assert_eq!(r.redact("hello world"), "hello world");
}

#[test]
fn redacts_mid_sentence() {
    let r = SecretRedactor::new();
    assert_eq!(
        r.redact("my key sk-abc123456789 is secret"),
        "my key [COFFER_SECRET_REDACTED] is secret"
    );
}

#[test]
fn boundary_at_min_len() {
    let r = SecretRedactor::new();
    // 恰好 = 阈值（8）→ 替换（规则是「长度 ≥ 阈值」，docs/20 §3.5）
    assert_eq!(r.redact("sk-12345"), REDACTION_TOKEN);
    // 差 1 → 不替换
    assert_eq!(r.redact("sk-1234"), "sk-1234");
}

#[test]
fn redacts_multiple_tokens() {
    let r = SecretRedactor::new();
    assert_eq!(
        r.redact("sk-aaaaaaaa bbb sk-cccccccc"),
        "[COFFER_SECRET_REDACTED] bbb [COFFER_SECRET_REDACTED]"
    );
}

#[test]
fn handles_empty_input() {
    let r = SecretRedactor::new();
    assert_eq!(r.redact(""), "");
}

#[test]
fn handles_token_adjacent_to_punctuation() {
    // 标点（逗号）是 token 边界，保留；token 本体替换。
    let r = SecretRedactor::new();
    assert_eq!(r.redact("prefix sk-abc123456789,"), "prefix [COFFER_SECRET_REDACTED],");
}

#[test]
fn handles_unicode_surroundings() {
    // 多字节 UTF-8 文本不影响 token 切分。
    let r = SecretRedactor::new();
    assert_eq!(
        r.redact("令牌 sk-abc123456789 结束"),
        "令牌 [COFFER_SECRET_REDACTED] 结束"
    );
}

#[test]
fn non_marker_long_token_not_redacted() {
    // 长 token 但无 sk- 前缀特征 → 不替换（防误伤普通长词）。
    let r = SecretRedactor::new();
    assert_eq!(r.redact("abcdef123456"), "abcdef123456");
}

#[test]
fn redacts_known_values_exactly() {
    // 防御面：provider 已知明文值精确替换（AS-11 补充手段）。
    let r = SecretRedactor::new();
    assert_eq!(
        r.redact_known_values("token abcdef123456 end", &["abcdef123456"]),
        "token [COFFER_SECRET_REDACTED] end"
    );
}

#[test]
fn redact_known_values_ignores_empty_and_absent() {
    let r = SecretRedactor::new();
    assert_eq!(r.redact_known_values("plain text", &[""]), "plain text");
    assert_eq!(r.redact_known_values("plain text", &["nope"]), "plain text");
}
