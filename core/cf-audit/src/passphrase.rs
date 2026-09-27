//! FR-3.3 密码短语生成（1Password 短语生成对齐）。
//!
//! 词表为 EFF Diceware 大词表（7776 词，CC-BY 4.0），经 [`std::include_str!`]
//! 编译期嵌入 `assets/`；署名与来源见 `assets/NOTICE-eff-large-wordlist.md`。
//!
//! 随机源为 `rand` 的 `OsRng`（操作系统密码学安全随机源，FR-3.5），
//! 不自实现随机源（NFR-SEC-06）。
//!
//! ## 熵
//!
//! 短语内**不重复抽样**（见 [`generate_passphrase`]），第 k 词的熵为
//! `log2(7776 - k + 1)`；默认 5 词约 64 bit。数字后缀另加 `log2(10)`。
//!
//! 短语不落盘，词表更换对存储格式零影响（docs/09 §3.4）。
//!
//! 注意：EFF 词表含 4 个带连字符的词（`drop-down` / `felt-tip` /
//! `t-shirt` / `yo-yo`）。当分隔符恰为 `-` 时，短语中的词边界在字形上
//! 存在歧义（人工誊写仍可辨认，1Password 同样行为）；不影响熵与安全性。

use std::collections::HashSet;
use std::sync::OnceLock;

use rand::rngs::OsRng;
use rand::Rng;

/// 短语词数下限（docs/09 §3.4：3..=10）。
pub const MIN_WORD_COUNT: usize = 3;

/// 短语词数上限。默认 5 词（约 64 bit 熵 @7776 词表）。
pub const MAX_WORD_COUNT: usize = 10;

/// 分隔符最少字符数。
pub const MIN_SEPARATOR_CHARS: usize = 1;

/// 分隔符最多字符数（防注入与失控长度）。
pub const MAX_SEPARATOR_CHARS: usize = 3;

/// 编译期嵌入的 EFF 大词表（原始格式：`NNNNN<TAB>word`，未修改）。
const WORDLIST_RAW: &str = include_str!("../assets/eff_large_wordlist.txt");

/// 词表行数（EFF 大词表：6^5 = 7776 词，每词约 12.9 bit）。
const WORDLIST_LEN: usize = 7776;

/// 密码短语生成参数（docs/09 §3.4 冻结契约 + 数字后缀扩展）。
///
/// - [`word_count`](PassphraseOptions::word_count)：词数，
///   [`MIN_WORD_COUNT`]`..=`[`MAX_WORD_COUNT`]（默认 5）；
/// - [`separator`](PassphraseOptions::separator)：词间分隔符，1..=3 个
///   可打印字符（默认 `"-"`）；
/// - [`capitalize`](PassphraseOptions::capitalize)：词首大写
///   （Title Case，对齐 1Password「首字母大写」；默认 false——全小写降低转写错误）；
/// - [`number_suffix`](PassphraseOptions::number_suffix)：末尾追加随机
///   数字 0–9（默认 false）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// 词数。
    pub word_count: usize,
    /// 词间分隔符。
    pub separator: String,
    /// 词首大写（Title Case）。
    pub capitalize: bool,
    /// 末尾追加随机数字 0–9。
    pub number_suffix: bool,
}

impl Default for PassphraseOptions {
    /// 默认策略：5 词、`-` 分隔、全小写、无数字后缀。
    fn default() -> Self {
        Self {
            word_count: 5,
            separator: "-".to_string(),
            capitalize: false,
            number_suffix: false,
        }
    }
}

/// 校验通过后的词表（进程内缓存，避免每次生成重复解析嵌入资产）。
struct Wordlist {
    words: Vec<&'static str>,
}

/// 词法校验：小写字母段（可含词内连字符，如 `drop-down`）。
fn is_valid_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .split('-')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase()))
}

/// 解析并校验嵌入词表：行数精确 7776、每行 `数字编号 + 小写字母词`、无重复。
///
/// 资产在编译期固定，正常情况下校验只会在进程首次生成时执行一次并通过；
/// 失败说明嵌入资产损坏，返回面向调用方可操作的错误文本。
fn wordlist() -> Result<&'static Wordlist, &'static str> {
    static WORDLIST: OnceLock<Result<Wordlist, &'static str>> = OnceLock::new();
    WORDLIST
        .get_or_init(|| {
            let mut words: Vec<&'static str> = Vec::with_capacity(WORDLIST_LEN);
            for line in WORDLIST_RAW.lines() {
                // EFF 原始行格式：`NNNNN<TAB>word`；取最后一个空白分隔字段即词。
                let word = line
                    .split_whitespace()
                    .next_back()
                    .ok_or("embedded wordlist has a malformed line")?;
                words.push(word);
            }
            if words.len() != WORDLIST_LEN {
                return Err("embedded wordlist must contain exactly 7776 words");
            }
            let mut seen = HashSet::with_capacity(WORDLIST_LEN);
            for word in &words {
                if !is_valid_word(word) || !seen.insert(*word) {
                    return Err("embedded wordlist contains an invalid or duplicate word");
                }
            }
            Ok(Wordlist { words })
        })
        .as_ref()
        .map_err(|e| *e)
}

/// 生成密码短语（FR-3.3）。
///
/// 词表抽样为**不重复抽样**（部分 Fisher–Yates：短语内同一词至多出现一次，
/// 熵按 `7776·7775·…` 计，docs/09 §3.4 测试要点 3）。`number_suffix` 为真时
/// 在短语末尾**直接**追加一个随机数字（不加分隔符，如 `staple7`）。
///
/// # Errors
///
/// - `word_count` 不在 [`MIN_WORD_COUNT`]`..=`[`MAX_WORD_COUNT`]；
/// - `separator` 不在 [`MIN_SEPARATOR_CHARS`]`..=`[`MAX_SEPARATOR_CHARS`]
///   个字符，或含不可打印字符；
/// - 嵌入词表资产损坏（正常运行不可达，见 [`wordlist`]）。
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<String, &'static str> {
    if !(MIN_WORD_COUNT..=MAX_WORD_COUNT).contains(&opts.word_count) {
        return Err("passphrase word count must be between 3 and 10");
    }
    let sep_chars: Vec<char> = opts.separator.chars().collect();
    if !(MIN_SEPARATOR_CHARS..=MAX_SEPARATOR_CHARS).contains(&sep_chars.len()) {
        return Err("passphrase separator must be 1 to 3 characters");
    }
    if !sep_chars.iter().all(|c| is_printable(*c)) {
        return Err("passphrase separator must contain only printable characters");
    }
    let wl = wordlist()?;
    let mut rng = OsRng;
    // 不重复抽样：第 i 轮从 `[i, len)` 随机取一索引与 `i` 交换（部分
    // Fisher–Yates），每个有序不重复词序列等概率被抽中。
    let mut indices: Vec<usize> = (0..wl.words.len()).collect();
    let mut words: Vec<String> = Vec::with_capacity(opts.word_count);
    for i in 0..opts.word_count {
        let j = rng.gen_range(i..indices.len());
        indices.swap(i, j);
        let word = wl.words[indices[i]];
        words.push(if opts.capitalize {
            capitalize(word)
        } else {
            word.to_string()
        });
    }
    let mut passphrase = words.join(&opts.separator);
    if opts.number_suffix {
        let digit = b'0' + rng.gen_range(0u8..10);
        passphrase.push(digit as char);
    }
    Ok(passphrase)
}

/// 词首大写（Title Case）。词表校验保证词非空且为小写字母。
fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// 分隔符字符可打印性：ASCII 可见字符或空格（`" "` 是 1Password 常用分隔符）。
fn is_printable(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 解析嵌入词表原文为词集合（测试独立解析，避免只验证实现自身的一致性）。
    fn raw_words() -> Vec<&'static str> {
        WORDLIST_RAW
            .lines()
            .map(|line| {
                assert!(line.contains('\t'), "词表行应保留 EFF 原始格式：{line}");
                line.split('\t').next_back().unwrap()
            })
            .collect()
    }

    /// TC-PPH-02（词表资产半）：7776 词、全部为小写字母段（可含词内连字符）、
    /// 无重复（运行时校验在 `wordlist()`，此处对资产本身做一次直测）。
    #[test]
    fn 嵌入词表资产完整() {
        let words = raw_words();
        assert_eq!(words.len(), WORDLIST_LEN);
        let mut seen = HashSet::new();
        for word in words {
            assert!(is_valid_word(word), "非法词：{word}");
            assert!(seen.insert(word), "重复词：{word}");
        }
    }

    /// TC-PPH-01（实现层粗粒度版；契约测试：tests/passphrase.rs::default_shape）：
    /// 默认参数形状——5 词、`-` 分隔、全小写、无数字后缀。词内连字符
    /// （如 `drop-down`）使 `-` 分割计数有歧义，此处只断言字符类。
    #[test]
    fn 默认参数形状() {
        let p = generate_passphrase(&PassphraseOptions::default()).unwrap();
        assert!(
            p.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "默认全小写：{p}"
        );
        assert!(p.starts_with(|c: char| c.is_ascii_lowercase()));
        assert!(p.ends_with(|c: char| c.is_ascii_lowercase()));
    }

    /// TC-PPH-02（生成侧）：生成的词均在 EFF 词表内。
    #[test]
    fn 词均在词表内() {
        let valid: HashSet<&str> = raw_words().into_iter().collect();
        let opts = PassphraseOptions {
            separator: ".".to_string(),
            ..PassphraseOptions::default()
        };
        for _ in 0..100 {
            let p = generate_passphrase(&opts).unwrap();
            for word in p.split('.') {
                assert!(valid.contains(word), "词「{word}」不在词表内：{p}");
            }
        }
    }

    /// TC-PPH-04 / TC-PPH-06（实现层）：词数与分隔符参数精确生效。
    #[test]
    fn 词数与分隔符参数生效() {
        for (count, sep) in [(3, "."), (7, " "), (10, "_-_")] {
            let opts = PassphraseOptions {
                word_count: count,
                separator: sep.to_string(),
                ..PassphraseOptions::default()
            };
            let p = generate_passphrase(&opts).unwrap();
            let words: Vec<&str> = p.split(sep).collect();
            assert_eq!(words.len(), count, "词数 {count} 应精确生效：{p}");
            assert!(words.iter().all(|w| !w.is_empty()));
        }
    }

    /// TC-PPH-03（实现层）：capitalize 生效——每个词首字母大写（Title Case）。
    #[test]
    fn 词首大写生效() {
        let opts = PassphraseOptions {
            capitalize: true,
            separator: ".".to_string(),
            ..PassphraseOptions::default()
        };
        let p = generate_passphrase(&opts).unwrap();
        for word in p.split('.') {
            let mut chars = word.chars();
            let first = chars.next().unwrap();
            assert!(first.is_ascii_uppercase(), "词首应大写：{word}");
            assert!(chars.all(|c| c.is_ascii_lowercase()), "其余应小写：{word}");
        }
    }

    /// number_suffix 生效：末尾追加一位数字 0–9；关闭时末字符为字母。
    #[test]
    fn 数字后缀生效() {
        let opts = PassphraseOptions {
            number_suffix: true,
            separator: ".".to_string(),
            ..PassphraseOptions::default()
        };
        for _ in 0..20 {
            let p = generate_passphrase(&opts).unwrap();
            let last = p.chars().last().unwrap();
            assert!(last.is_ascii_digit(), "末尾应为数字：{p}");
            assert_eq!(p.split('.').count(), 5, "数字直接拼接不加分隔符：{p}");
        }
        let plain = generate_passphrase(&PassphraseOptions::default()).unwrap();
        assert!(plain.chars().last().unwrap().is_ascii_lowercase());
    }

    /// TC-PPH-07（实现层，word_count=5）：短语内词不重复（不重复抽样）；
    /// word_count=10 契约版见 tests/passphrase.rs::no_repeated_words_within_phrase。
    #[test]
    fn 短语内词不重复() {
        let opts = PassphraseOptions {
            separator: ".".to_string(),
            ..PassphraseOptions::default()
        };
        for _ in 0..100 {
            let p = generate_passphrase(&opts).unwrap();
            let words: Vec<&str> = p.split('.').collect();
            let unique: HashSet<&str> = words.iter().copied().collect();
            assert_eq!(unique.len(), words.len(), "词重复：{p}");
        }
    }

    /// TC-PPH-05（实现层）：参数越界被拒绝（word_count 2 / 11；分隔符 0 / 4
    /// 字符 / 不可打印）。
    #[test]
    fn 参数越界被拒绝() {
        let few = PassphraseOptions {
            word_count: MIN_WORD_COUNT - 1,
            ..PassphraseOptions::default()
        };
        assert!(generate_passphrase(&few).is_err());
        let many = PassphraseOptions {
            word_count: MAX_WORD_COUNT + 1,
            ..PassphraseOptions::default()
        };
        assert!(generate_passphrase(&many).is_err());
        for separator in ["", "abcd", "\t"] {
            let opts = PassphraseOptions {
                separator: separator.to_string(),
                ..PassphraseOptions::default()
            };
            assert!(
                generate_passphrase(&opts).is_err(),
                "分隔符「{separator}」应被拒绝"
            );
        }
    }

    /// TC-PPH-08（实现层粗粒度版）：输出彼此不同；分布断言
    ///（覆盖度/卡方）见 tests/passphrase.rs::distribution_not_degenerate。
    #[test]
    fn 输出具有随机性() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let p = generate_passphrase(&PassphraseOptions::default()).unwrap();
            assert!(seen.insert(p), "5 词短语空间约 2^64，1000 次抽样不应碰撞");
        }
    }

    /// TC-PPH-10（实现层冒烟版 1 万次；完整 10 万次笛卡尔积契约用例
    /// fuzz_100k_no_panic 为 #[ignore]，CI 执行——避免常规跑测 60s+）。
    #[test]
    fn 一万次生成冒烟无panic() {
        let opts = PassphraseOptions::default();
        for _ in 0..10_000 {
            let _ = generate_passphrase(&opts).unwrap();
        }
    }

    /// 空格分隔符合法（1Password 常用），控制字符非法。
    #[test]
    fn 分隔符可打印性边界() {
        let space = PassphraseOptions {
            separator: " ".to_string(),
            ..PassphraseOptions::default()
        };
        assert!(generate_passphrase(&space).is_ok());
    }
}
