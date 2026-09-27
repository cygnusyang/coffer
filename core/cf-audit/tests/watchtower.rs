//! FR-6.2 / FR-6.3 Watchtower 纯函数验收契约测试（docs/10 §5，TC-WTW-01~06）。
//!
//! 自动化落点约定（docs/10 §0.3）：`cf-audit/tests/watchtower.rs`。
//! TC-WTW-07~11 为 cf-session 编排用例（`audit_orchestration.rs`），
//! 归 G3，不在本文件。
//!
//! 测试用固定 32B 密钥模拟 G3 注入的 `audit_key`（cf/audit/v1 子密钥）。

use cf_audit::{find_duplicate_groups, find_http_urls, password_fingerprint, PasswordFingerprint};

/// 测试密钥（docs/09 §3.5：真实 audit_key 由 cf-session 派生注入）。
const KEY_A: [u8; 32] = [0x2B; 32];
const KEY_B: [u8; 32] = [0x7F; 32];

fn fingerprint_entry(item_id: &str, plain: &str) -> PasswordFingerprint {
    PasswordFingerprint {
        item_id: item_id.to_string(),
        field_id: "password".to_string(),
        hmac_b64: password_fingerprint(plain, &KEY_A),
    }
}

/// TC-WTW-01：指纹确定性——同 key 同明文两次调用结果相同。
#[test]
fn fingerprint_deterministic() {
    let a = password_fingerprint("correct horse battery staple", &KEY_A);
    let b = password_fingerprint("correct horse battery staple", &KEY_A);
    assert_eq!(a, b);
}

/// TC-WTW-02：指纹 key 绑定——同明文 × 两把 key，指纹不同（防跨库比对）。
#[test]
fn fingerprint_key_bound() {
    let a = password_fingerprint("hunter2", &KEY_A);
    let b = password_fingerprint("hunter2", &KEY_B);
    assert_ne!(a, b);
}

/// TC-WTW-03：指纹不泄露明文（对抗）——b64 中不含任何明文片段；
/// HMAC-SHA256 输出长度恒定（base64 恒 44 字符 = 32 字节）。
#[test]
fn fingerprint_leaks_nothing() {
    let plains = [
        "password123",
        "correct horse battery staple",
        "hunter2",
        "",
        "0123456789",
    ];
    for plain in plains {
        let fp = password_fingerprint(plain, &KEY_A);
        assert_eq!(fp.len(), 44, "指纹长度应恒定：{plain:?}");
        // 空串是任何串的子串，跳过 contains 判定
        if !plain.is_empty() {
            assert!(!fp.contains(plain), "指纹包含明文片段：{plain:?} → {fp}");
        }
        // 明文（或其小写形态）任一 ≥4 字符滑窗都不应出现在指纹中
        let lower = plain.to_lowercase();
        if lower.len() >= 4 {
            for window in lower.as_bytes().windows(4) {
                let snippet = String::from_utf8_lossy(window);
                assert!(
                    !fp.contains(snippet.as_ref()),
                    "指纹包含明文滑窗：{snippet}"
                );
            }
        }
    }
}

/// TC-WTW-04：分组准确——5 指纹（3 同 + 2 互异）→ 恰 1 组含 3 个 item_id，
/// 且顺序稳定（两次调用结果一致）。
#[test]
fn duplicate_grouping() {
    let fps = vec![
        fingerprint_entry("a", "same-secret"),
        fingerprint_entry("b", "same-secret"),
        fingerprint_entry("d1", "other-1"),
        fingerprint_entry("c", "same-secret"),
        fingerprint_entry("d2", "other-2"),
    ];
    let groups = find_duplicate_groups(&fps);
    assert_eq!(groups.len(), 1, "恰 1 组：{groups:?}");
    assert_eq!(groups[0], vec!["a", "b", "c"]);
    let again = find_duplicate_groups(&fps);
    assert_eq!(groups, again, "输出顺序应稳定");
}

/// TC-WTW-05：空数组 / 单条 → 均返回空（≥2 才报）。
#[test]
fn empty_and_singleton() {
    assert!(find_duplicate_groups(&[]).is_empty());
    let single = vec![fingerprint_entry("only", "x")];
    assert!(find_duplicate_groups(&single).is_empty());
}

/// TC-WTW-06：弱 URL 大小写不敏感——`http://a.com`、`HTTP://B.com` 命中；
/// `https://c.com` 与空串不命中。
#[test]
fn http_url_case_insensitive() {
    let urls = vec![
        ("a".to_string(), "http://a.com".to_string()),
        ("b".to_string(), "HTTP://B.com".to_string()),
        ("c".to_string(), "https://c.com".to_string()),
        ("d".to_string(), String::new()),
    ];
    assert_eq!(
        find_http_urls(&urls),
        vec!["a".to_string(), "b".to_string()]
    );
}
