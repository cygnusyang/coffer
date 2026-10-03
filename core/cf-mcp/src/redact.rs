//! SecretRedactor —— 输出脱敏管道（docs/20 §3.5，AS-11 落地）。
//!
//! 规则（§3.5-2）：所有 `content[0].text` 经本管道处理——**已知 secret 指纹**
//! （长度 ≥ 阈值 + 前缀特征，如 `sk-`）替换为 [`REDACTION_TOKEN`]。
//!
//! MVP 的工具输出本身不含 Secret 明文（§3.5-1 结构性保证），本管道是纵深防御；
//! `run_with_secret` 启动的子进程自身输出**不受** Coffer 控制（§3.5-3 诚实边界）。

/// 脱敏替换令牌（docs/10 AS-11 原文样例）。
pub const REDACTION_TOKEN: &str = "[COFFER_SECRET_REDACTED]";

/// 默认指纹长度阈值（含前缀）。
pub const DEFAULT_MIN_FINGERPRINT_LEN: usize = 8;

/// 默认前缀特征（docs/20 §3.5：如 `sk-`）。
const DEFAULT_MARKERS: &[&str] = &["sk-"];

/// 输出脱敏器。
#[derive(Debug, Clone)]
pub struct SecretRedactor {
    /// 指纹最小长度（含前缀，字节）。
    min_len: usize,
    /// 前缀特征（命中即视为 secret 指纹候选）。
    markers: Vec<String>,
}

impl SecretRedactor {
    /// 默认脱敏器（阈值 8，前缀 `sk-`）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            min_len: DEFAULT_MIN_FINGERPRINT_LEN,
            markers: DEFAULT_MARKERS.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// 指纹长度阈值（含前缀）。
    #[must_use]
    pub fn min_len(&self) -> usize {
        self.min_len
    }

    /// 前缀特征清单。
    #[must_use]
    pub fn markers(&self) -> &[String] {
        &self.markers
    }

    /// 按指纹规则替换命中 token。
    ///
    /// token = 最大连续「secret 字符」段（ASCII 字母数字 + `_` + `-`）；非 secret
    /// 字符（空白、标点、多字节 UTF-8）原样保留并作为边界。命中「前缀特征 + 长度
    /// ≥ 阈值」的 token 整体替换为 [`REDACTION_TOKEN`]。
    pub fn redact(&self, input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = String::with_capacity(input.len());
        let mut i = 0;
        while i < bytes.len() {
            if !is_secret_byte(bytes[i]) {
                if bytes[i] < 0x80 {
                    // 单字节非 secret ASCII：原样复制。
                    out.push(bytes[i] as char);
                    i += 1;
                } else {
                    // 多字节 UTF-8：整体复制（secret 字符集是 ASCII，天然是边界）。
                    let ch = input[i..].chars().next().unwrap_or('\u{FFFD}');
                    out.push(ch);
                    i += ch.len_utf8();
                }
                continue;
            }
            let start = i;
            while i < bytes.len() && is_secret_byte(bytes[i]) {
                i += 1;
            }
            let token = &input[start..i];
            if self.is_fingerprint(token) {
                out.push_str(REDACTION_TOKEN);
            } else {
                out.push_str(token);
            }
        }
        out
    }

    /// 额外按已知明文值精确替换（防御面：provider 已知值指纹）。
    ///
    /// `known` 中的非空值在 `input` 中出现的每一处都替换为 [`REDACTION_TOKEN`]。
    pub fn redact_known_values(&self, input: &str, known: &[&str]) -> String {
        let mut out = input.to_string();
        for value in known {
            if value.is_empty() {
                continue;
            }
            out = out.replace(value, REDACTION_TOKEN);
        }
        out
    }

    /// token 是否命中指纹规则（前缀特征 + 长度 ≥ 阈值）。
    fn is_fingerprint(&self, token: &str) -> bool {
        token.len() >= self.min_len && self.markers.iter().any(|m| token.starts_with(m))
    }
}

impl Default for SecretRedactor {
    fn default() -> Self {
        Self::new()
    }
}

/// secret 字符（ASCII 字母数字 + `_` + `-`）。
fn is_secret_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_and_threshold_are_sane() {
        let r = SecretRedactor::new();
        assert_eq!(r.min_len(), DEFAULT_MIN_FINGERPRINT_LEN);
        assert!(r.markers().iter().any(|m| m == "sk-"));
    }
}
