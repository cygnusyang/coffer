//! FR-6.2 / FR-6.3 Watchtower 纯函数（docs/09 §3.5，G2）。
//!
//! 本 crate 保持**纯计算层**：不依赖 `cf-store`，解密与取数由 cf-session
//! 编排（G3）；明文即用即弃，不在本层缓存（docs/09 §8 风险 7）。
//!
//! 重复密码判定用 HMAC-SHA256 指纹比对，**禁止明文比较**（docs/03 §8
//! AUD-02）。指纹密钥 `audit_key` 为 cf-session 侧派生的第 8 把子密钥
//! （HKDF label `cf/audit/v1`，docs/09 §3.5 D-5），由调用方注入。
//!
//! 弱密码复检复用 [`crate::password_strength`] 的 zxcvbn 阈值
//! （score < 3 判弱，FR-6.1）——覆盖 CSV 导入等不设强度门禁的路径
//! （docs/09 §3.5 测试要点 5）。

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hmac::digest::generic_array::GenericArray;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use zxcvbn::Score;

/// HMAC-SHA256 指纹密钥长度（`audit_key` 子密钥，docs/09 §3.5 D-5）。
pub const FINGERPRINT_KEY_LEN: usize = 32;

/// 弱密码判定阈值（zxcvbn score < 3 判弱，FR-6.1 / docs/03 §8 AUD-01）。
pub const WEAK_PASSWORD_SCORE_THRESHOLD: Score = Score::Three;

/// SHA-256 的 HMAC 分组长度（字节，RFC 2104 §2）。
const HMAC_SHA256_BLOCK_LEN: usize = 64;

type HmacSha256 = Hmac<sha2::Sha256>;

/// 单条密码的指纹条目（FR-6.2，docs/09 §3.5 冻结契约）。
///
/// `hmac_b64` 为 `HMAC-SHA256(audit_key, 明文密码)` 的 base64 编码，
/// 不泄露明文（同库同密钥下可比等值；跨库密钥不同不可比对）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordFingerprint {
    /// 所属条目 id。
    pub item_id: String,
    /// 密码字段 id。
    pub field_id: String,
    /// HMAC-SHA256 指纹（base64）。
    pub hmac_b64: String,
}

/// Watchtower 体检报告（FR-6.2 / FR-6.3 / FR-6.1 复检，docs/09 §3.5）。
///
/// 结构预留扩展（FR-6.4 / 6.5 / 6.6 不在本版，新增字段向后兼容）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchtowerReport {
    /// 共享同一密码指纹的 item_id 分组（≥2 才报）。
    pub duplicate_groups: Vec<Vec<String>>,
    /// 弱密码条目（zxcvbn score < 3，FR-6.1 复检）。
    pub weak_password_items: Vec<String>,
    /// 任一 URL 以 `http://` 开头（大小写不敏感）的条目（FR-6.3）。
    pub http_url_items: Vec<String>,
}

/// 计算明文密码的 HMAC-SHA256 指纹（FR-6.2，docs/09 §3.5 冻结契约）。
///
/// 密钥为 32 字节 `audit_key`；输出为 base64 字符串。
///
/// 实现说明：`Mac::new_from_slice` 对任意长度密钥均合法，但其
/// `InvalidLength` 错误分支在本层无法用 `Result` 表达（冻结契约返回
/// `String`）。此处按 RFC 2104 §2 将 32 字节密钥**零填充**到 HMAC 分组
/// 长度（64B）后走 infallible 的 `Mac::new`——两者逐字节等价（HMAC 对
/// 短密钥即零填充到分组长度），由 RFC 4231 测试向量与等价性测试双重
/// 验证，不可达错误分支被结构性消除。
///
/// 明文仅在本函数内流转，调用方负责即用即弃。
#[must_use]
pub fn password_fingerprint(plain: &str, key: &[u8; FINGERPRINT_KEY_LEN]) -> String {
    let mut padded = [0u8; HMAC_SHA256_BLOCK_LEN];
    padded[..key.len()].copy_from_slice(key);
    let mut mac = <HmacSha256 as KeyInit>::new(GenericArray::from_slice(&padded));
    mac.update(plain.as_bytes());
    BASE64_STANDARD.encode(mac.finalize().into_bytes())
}

/// 按 `hmac_b64` 聚合指纹，返回共享同一密码的 item_id 分组（≥2 才报）。
///
/// 输出按指纹字典序排列，组内保持输入顺序（同一 item 多个字段共用
/// 密码时去重），保证结果确定、便于测试与 UI 稳定展示。
#[must_use]
pub fn find_duplicate_groups(fps: &[PasswordFingerprint]) -> Vec<Vec<String>> {
    let mut by_fingerprint: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for fp in fps {
        by_fingerprint
            .entry(fp.hmac_b64.as_str())
            .or_default()
            .push(fp.item_id.as_str());
    }
    by_fingerprint
        .into_values()
        .filter(|ids| ids.len() >= 2)
        .map(|ids| {
            let mut group: Vec<String> = Vec::with_capacity(ids.len());
            for id in ids {
                if !group.iter().any(|seen| seen == id) {
                    group.push(id.to_string());
                }
            }
            group
        })
        .collect()
}

/// 返回任一 URL 以 `http://` 开头（大小写不敏感）的条目 id（FR-6.3）。
///
/// 输入为 `(item_id, url)` 对；输出保持输入顺序并去重。
/// 前缀比较用 `str::get` 边界安全切片，多字节字符不会 panic。
#[must_use]
pub fn find_http_urls(urls: &[(String, String)]) -> Vec<String> {
    let mut hits: Vec<String> = Vec::new();
    for (item_id, url) in urls {
        let is_http = url
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"));
        if is_http && !hits.iter().any(|seen| seen == item_id) {
            hits.push(item_id.clone());
        }
    }
    hits
}

/// 返回弱密码条目 id（zxcvbn score < 3，FR-6.1 复检，docs/09 §3.5）。
///
/// 输入为 `(item_id, 明文密码)` 对；输出保持输入顺序并去重。
/// 明文即用即弃（仅在本函数内流转）。
#[must_use]
pub fn find_weak_passwords(items: &[(String, String)]) -> Vec<String> {
    let mut weak: Vec<String> = Vec::new();
    for (item_id, password) in items {
        if crate::password_strength(password) < WEAK_PASSWORD_SCORE_THRESHOLD
            && !weak.iter().any(|seen| seen == item_id)
        {
            weak.push(item_id.clone());
        }
    }
    weak
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 Test Case 2：HMAC-SHA256(key="Jefe", data="what do ya want for nothing?")
    /// = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843。
    /// 32 字节零填充密钥路径与 RFC 标准路径等价的外部基准。
    #[test]
    fn 指纹符合rfc4231测试向量() {
        let mut key = [0u8; FINGERPRINT_KEY_LEN];
        key[..4].copy_from_slice(b"Jefe");
        let fp = password_fingerprint("what do ya want for nothing?", &key);
        assert_eq!(fp, "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM=");
    }

    /// 零填充路径与 `Mac::new_from_slice`（RFC 标准短密钥处理）逐字节等价。
    /// 本契约密钥固定 32 字节，覆盖 0..=32 的关键长度（含全零密钥）。
    #[test]
    fn 零填充密钥与标准路径等价() {
        for len in [0usize, 1, 16, 31, 32] {
            let mut key = [0u8; FINGERPRINT_KEY_LEN];
            for (i, b) in key.iter_mut().take(len).enumerate() {
                *b = (i as u8) ^ 0xA5;
            }
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key[..len]).unwrap();
            mac.update(b"correct horse battery staple");
            let expected = BASE64_STANDARD.encode(mac.finalize().into_bytes());
            assert_eq!(
                password_fingerprint("correct horse battery staple", &key),
                expected,
                "密钥长度 {len} 的零填充路径应与标准 HMAC 路径等价"
            );
        }
    }

    /// TC-WTW-01 / TC-WTW-02（实现层）：同密码同 key 同指纹；不同 key 不同指纹。
    #[test]
    fn 指纹由密钥与明文共同决定() {
        let key = [7u8; FINGERPRINT_KEY_LEN];
        assert_eq!(
            password_fingerprint("hunter2", &key),
            password_fingerprint("hunter2", &key)
        );
        let other = [8u8; FINGERPRINT_KEY_LEN];
        assert_ne!(
            password_fingerprint("hunter2", &key),
            password_fingerprint("hunter2", &other),
            "不同密钥应产出不同指纹"
        );
    }

    /// TC-WTW-03（实现层粗粒度版）：明文不出现在指纹中；滑窗对抗见
    /// tests/watchtower.rs::fingerprint_leaks_nothing。
    #[test]
    fn 指纹不泄露明文() {
        let key = [1u8; FINGERPRINT_KEY_LEN];
        let fp = password_fingerprint("password", &key);
        assert!(!fp.contains("password"));
    }

    /// TC-WTW-04（实现层）：分组——3 条同密码 + 2 条互异 → 1 组 3 条。
    #[test]
    fn 重复密码分组() {
        let key = [42u8; FINGERPRINT_KEY_LEN];
        let fp = |item: &str| PasswordFingerprint {
            item_id: item.to_string(),
            field_id: "password".to_string(),
            hmac_b64: password_fingerprint("same-secret", &key),
        };
        let distinct = PasswordFingerprint {
            item_id: "d1".to_string(),
            field_id: "password".to_string(),
            hmac_b64: password_fingerprint("other-1", &key),
        };
        let distinct2 = PasswordFingerprint {
            item_id: "d2".to_string(),
            field_id: "password".to_string(),
            hmac_b64: password_fingerprint("other-2", &key),
        };
        let fps = vec![fp("a"), fp("b"), distinct, fp("c"), distinct2];
        let groups = find_duplicate_groups(&fps);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0],
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    /// TC-WTW-05（实现层）：空输入 / 单条 → 空报告。
    #[test]
    fn 空与单条不产生分组() {
        let key = [9u8; FINGERPRINT_KEY_LEN];
        assert!(find_duplicate_groups(&[]).is_empty());
        let single = vec![PasswordFingerprint {
            item_id: "only".to_string(),
            field_id: "password".to_string(),
            hmac_b64: password_fingerprint("x", &key),
        }];
        assert!(find_duplicate_groups(&single).is_empty());
    }

    /// 同一 item 的多个字段共用密码时只报一次。
    #[test]
    fn 组内条目去重() {
        let key = [11u8; FINGERPRINT_KEY_LEN];
        let fp = |item: &str, field: &str| PasswordFingerprint {
            item_id: item.to_string(),
            field_id: field.to_string(),
            hmac_b64: password_fingerprint("dup", &key),
        };
        let groups = find_duplicate_groups(&[fp("a", "f1"), fp("a", "f2"), fp("b", "f1")]);
        assert_eq!(groups, vec![vec!["a".to_string(), "b".to_string()]]);
    }

    /// TC-WTW-06（实现层）：弱 URL——`http://`、`HTTP://` 命中；`https://`、
    /// 空 url 不命中。
    #[test]
    fn 弱url大小写不敏感命中() {
        let urls = vec![
            ("a".to_string(), "http://example.com".to_string()),
            ("b".to_string(), "HTTP://example.org".to_string()),
            ("c".to_string(), "https://example.com".to_string()),
            ("d".to_string(), String::new()),
            ("e".to_string(), "http://".to_string()),
        ];
        assert_eq!(
            find_http_urls(&urls),
            vec!["a".to_string(), "b".to_string(), "e".to_string()]
        );
    }

    /// 非 ASCII 前缀截断安全（`get` 边界切片不 panic）与去重。
    #[test]
    fn 弱url边界与去重() {
        let urls = vec![
            ("a".to_string(), "例子http://x".to_string()),
            ("b".to_string(), "http://one".to_string()),
            ("b".to_string(), "HTTP://two".to_string()),
        ];
        assert_eq!(find_http_urls(&urls), vec!["b".to_string()]);
    }

    /// 弱密码复检：zxcvbn 弱密码命中、强密码不命中；保持输入顺序并去重。
    #[test]
    fn 弱密码复检() {
        let items = vec![
            ("w1".to_string(), "123456".to_string()),
            ("s1".to_string(), "xK9#mQ2$vL8pZ4!nR7wT".to_string()),
            ("w2".to_string(), "password".to_string()),
            ("w1".to_string(), "12345678".to_string()),
        ];
        assert_eq!(
            find_weak_passwords(&items),
            vec!["w1".to_string(), "w2".to_string()]
        );
    }
}
