//! FR-3.3 密码短语生成验收契约测试（docs/10 §4，TC-PPH-01~10）。
//!
//! 自动化落点约定（docs/10 §0.3）：`cf-audit/tests/passphrase.rs`。
//! 命名与断言点对齐用例编号；实现层单元测试在 `src/passphrase.rs`
//! 内联模块（交叉引用见各内联测试注释）。
//!
//! TC-PPH-09（随机源非自实现）为审读勾稽项：实现仅使用
//! `rand::rngs::OsRng`（getrandom 根，NFR-SEC-06），无自写 RNG；
//! 核销时人工核对 `cf-audit/src/passphrase.rs` 的随机源引用。

use std::collections::{HashMap, HashSet};

use cf_audit::{generate_passphrase, PassphraseOptions, MAX_WORD_COUNT, MIN_WORD_COUNT};

/// 词表资产（测试独立读取，不经实现内部的 `include_str!` 路径）。
const WORDLIST_RAW: &str = include_str!("../assets/eff_large_wordlist.txt");

/// TC-PPH-09 审读记录（自动化半）：随机源来自 `rand::rngs::OsRng`。
///
/// 实现文件 `src/passphrase.rs` 中唯一的 RNG 构造点为 `OsRng`（操作系统
/// CSPRNG，getrandom 根），抽样仅用 `Rng::gen_range`，无任何自实现随机源。
/// 本测试文件本身不构造 RNG，判据在核销时人工勾稽（docs/10 §8）。
#[test]
fn random_source_review_note() {
    // 勾稽占位：保证该审读项在测试清单中可见、可统计。
    // 真实判据 = 代码审读（见上方模块注释与 src/passphrase.rs）。
    let src = include_str!("../src/passphrase.rs");
    assert!(src.contains("OsRng"), "实现必须使用 OsRng（NFR-SEC-06）");
    assert!(!src.contains("impl RngCore"), "禁止自实现随机源");
}

/// 从词表资产独立解析词集合（不依赖实现的解析逻辑）。
fn wordlist_words() -> Vec<&'static str> {
    WORDLIST_RAW
        .lines()
        .map(|line| line.split('\t').next_back().unwrap())
        .collect()
}

/// 词表按首字符分桶（回溯解析用，避免每次全表扫描）。
fn words_by_first_char() -> HashMap<char, Vec<&'static str>> {
    let mut buckets: HashMap<char, Vec<&'static str>> = HashMap::new();
    for word in wordlist_words() {
        buckets
            .entry(word.as_bytes()[0] as char)
            .or_default()
            .push(word);
    }
    buckets
}

/// 将短语按词表 + `-` 分隔符解析回词序列。
///
/// EFF 词表含 4 个词内连字符词（`drop-down` 等），与分隔符 `-` 存在字形
/// 歧义，故用回溯解析而非朴素 `split('-')`（判据「5 词 / 4 个分隔符 /
/// 逐词查词表」按解析出的词序列核验）。
fn parse_phrase(phrase: &str, by_char: &HashMap<char, Vec<&'static str>>) -> Option<Vec<String>> {
    fn dfs(
        rest: &str,
        by_char: &HashMap<char, Vec<&'static str>>,
        out: &mut Vec<String>,
    ) -> Option<()> {
        if rest.is_empty() {
            return Some(());
        }
        let first = rest.chars().next()?;
        for word in by_char.get(&first)? {
            if let Some(after) = rest.strip_prefix(word) {
                let mark = out.len();
                out.push((*word).to_string());
                match after.strip_prefix('-') {
                    Some(next) => {
                        if dfs(next, by_char, out).is_some() {
                            return Some(());
                        }
                    }
                    None if after.is_empty() => return Some(()),
                    None => {}
                }
                out.truncate(mark);
            }
        }
        None
    }
    let mut out = Vec::new();
    dfs(phrase, by_char, &mut out)?;
    Some(out)
}

/// 词首大写（与实现的 Title Case 语义一致）。
fn capitalize_word(word: &str) -> String {
    let mut chars = word.chars();
    let upper: String = chars.next().unwrap().to_uppercase().collect();
    upper + chars.as_str()
}

/// TC-PPH-01：默认参数形状——5 词、`-` 分隔（词间 4 个分隔符）、全小写。
///
/// 词内连字符词（如 `drop-down`）使 `matches('-')` 计数含词内连字符，
/// 故「4 个分隔符」以回溯解析出的词序列长度 = 5 核验（等价判据，
/// 见 [`parse_phrase`] 注释）。
#[test]
fn default_shape() {
    let by_char = words_by_first_char();
    for _ in 0..100 {
        let p = generate_passphrase(&PassphraseOptions::default()).unwrap();
        let words = parse_phrase(&p, &by_char).expect("默认短语必须可按词表解析");
        assert_eq!(words.len(), 5, "默认 5 词（词间恰 4 个分隔符）：{p}");
        assert!(
            p.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "全小写：{p}"
        );
    }
}

/// TC-PPH-02：词均出自词表；词表文件行数恰 7776 且无重复行/词。
#[test]
fn words_in_wordlist_and_wordlist_complete() {
    // 词表资产完整性（文件级判据）
    let lines: Vec<&str> = WORDLIST_RAW.lines().collect();
    assert_eq!(lines.len(), 7776, "EFF 大词表行数应为 7776");
    let words = wordlist_words();
    let unique_lines: HashSet<&str> = lines.iter().copied().collect();
    assert_eq!(unique_lines.len(), 7776, "词表行不得重复");
    let word_set: HashSet<&str> = words.iter().copied().collect();
    assert_eq!(word_set.len(), 7776, "词表词不得重复");

    // 生成 1000 次，逐词查词表
    let by_char = words_by_first_char();
    for _ in 0..1000 {
        let p = generate_passphrase(&PassphraseOptions::default()).unwrap();
        for word in parse_phrase(&p, &by_char).expect("短语必须可按词表解析") {
            assert!(
                word_set.contains(word.as_str()),
                "词「{word}」不在词表内：{p}"
            );
        }
    }
}

/// TC-PPH-03：capitalize 生效——每词首字母大写，其余不变。
#[test]
fn capitalize_applies() {
    let by_char = words_by_first_char();
    for _ in 0..20 {
        let p = generate_passphrase(&PassphraseOptions {
            capitalize: true,
            ..PassphraseOptions::default()
        })
        .unwrap();
        let words = parse_phrase(&p.to_lowercase(), &by_char).expect("短语必须可按词表解析");
        assert_eq!(words.len(), 5);
        let rebuilt = words
            .iter()
            .map(|w| capitalize_word(w))
            .collect::<Vec<_>>()
            .join("-");
        assert_eq!(rebuilt, p, "重建（词首大写）应与原文逐字符相等：{p}");
    }
}

/// TC-PPH-04：自定义分隔符精确出现 word_count-1 次（`.` / 3 字符 `_ab`）。
#[test]
fn custom_separator() {
    for separator in [".", "_ab"] {
        let opts = PassphraseOptions {
            separator: separator.to_string(),
            ..PassphraseOptions::default()
        };
        for _ in 0..20 {
            let p = generate_passphrase(&opts).unwrap();
            assert_eq!(
                p.matches(separator).count(),
                4,
                "分隔符「{separator}」应恰出现 word_count-1=4 次：{p}"
            );
            for word in p.split(separator) {
                assert!(!word.is_empty(), "空词：{p}");
            }
        }
    }
}

/// TC-PPH-05：参数越界拒绝——word_count=2/11；separator 空/4 字符/控制字符。
/// 返回 `Err(&'static str)` 且不 panic（签名为 Result，编译期保证）。
#[test]
fn rejects_out_of_range() {
    for word_count in [MIN_WORD_COUNT - 1, MAX_WORD_COUNT + 1] {
        let opts = PassphraseOptions {
            word_count,
            ..PassphraseOptions::default()
        };
        let err = generate_passphrase(&opts).expect_err("越界词数应被拒绝");
        assert!(!err.is_empty());
    }
    for separator in ["", "abcd", "\t", "\n"] {
        let opts = PassphraseOptions {
            separator: separator.to_string(),
            ..PassphraseOptions::default()
        };
        assert!(
            generate_passphrase(&opts).is_err(),
            "分隔符「{separator:?}」应被拒绝"
        );
    }
}

/// TC-PPH-06：边界值通过——word_count=3/10；separator 恰 1/3 字符，形状正确。
#[test]
fn boundary_values_accepted() {
    let by_char = words_by_first_char();
    for word_count in [3, 10] {
        let opts = PassphraseOptions {
            word_count,
            ..PassphraseOptions::default()
        };
        let p = generate_passphrase(&opts).unwrap();
        assert_eq!(parse_phrase(&p, &by_char).unwrap().len(), word_count);
    }
    for (separator, chars) in [(".", 1usize), ("_-_", 3)] {
        let opts = PassphraseOptions {
            separator: separator.to_string(),
            ..PassphraseOptions::default()
        };
        let p = generate_passphrase(&opts).unwrap();
        assert_eq!(p.split(separator).count(), 5, "分隔符 {chars} 字符：{p}");
    }
}

/// TC-PPH-07：word_count=10 时单次短语内词不重复（不重复抽样契约）。
#[test]
fn no_repeated_words_within_phrase() {
    let by_char = words_by_first_char();
    let opts = PassphraseOptions {
        word_count: 10,
        ..PassphraseOptions::default()
    };
    for _ in 0..20 {
        let p = generate_passphrase(&opts).unwrap();
        let words = parse_phrase(&p, &by_char).expect("短语必须可按词表解析");
        assert_eq!(words.len(), 10, "{p}");
        let unique: HashSet<&str> = words.iter().map(String::as_str).collect();
        assert_eq!(unique.len(), 10, "词重复：{p}");
    }
}

/// TC-PPH-08：熵底线（分布抽样）——10⁴ 次默认输出：
/// 首位词覆盖 ≥1000、卡方检验不拒绝均匀性（宽松 6σ 阈值）、两两无重复。
///
/// 注：实现随机源为 OsRng（CSPRNG，TC-PPH-09），不可播种；「固定 seed」
/// 以宽松统计阈值替代——阈值下非确定性不会造成测试翻车（docs/10 §9：
/// 本用例只证「非退化」，密码学均匀性由 getrandom 既有审计背书）。
#[test]
fn distribution_not_degenerate() {
    const N: usize = 10_000;
    let mut first_words: HashMap<String, usize> = HashMap::new();
    let mut outputs: HashSet<String> = HashSet::with_capacity(N);
    for _ in 0..N {
        let p = generate_passphrase(&PassphraseOptions::default()).unwrap();
        assert!(outputs.insert(p.clone()), "10⁴ 次抽样输出不应重复：{p}");
        let first = p.split('-').next().unwrap().to_string();
        *first_words.entry(first).or_default() += 1;
    }
    // 覆盖度：期望 distinct ≈ 7776·(1−e^(−N/7776)) ≈ 6000，宽松取 1000
    assert!(
        first_words.len() >= 1000,
        "首位词覆盖 {} < 1000",
        first_words.len()
    );
    // 卡方：k-1=7775 自由度，均值 7775，σ≈124.7；6σ 宽松阈值防退化 RNG
    let k = 7776.0_f64;
    let expected = N as f64 / k;
    let mut chi2 = 0.0_f64;
    for count in first_words.values() {
        let diff = *count as f64 - expected;
        chi2 += diff * diff / expected;
    }
    chi2 += (k - first_words.len() as f64) * expected; // 未出现词位贡献 (0−e)²/e = e
    let df = k - 1.0;
    assert!(
        chi2 < df + 6.0 * (2.0 * df).sqrt(),
        "卡方 {chi2} 超出宽松阈值，首位词分布疑似退化"
    );
}

/// TC-PPH-10：10 万次全参数组合（笛卡尔积）零 panic、零 Err。
/// docs/10 §0.3：`#[ignore]`，CI（`--include-ignored`）执行。
#[test]
#[ignore = "10 万次全参数组合，CI（--include-ignored）执行"]
fn fuzz_100k_no_panic() {
    let separators = [".", "-", "_ab", " "];
    let mut total = 0usize;
    for word_count in MIN_WORD_COUNT..=MAX_WORD_COUNT {
        for separator in separators {
            for capitalize in [false, true] {
                for number_suffix in [false, true] {
                    let opts = PassphraseOptions {
                        word_count,
                        separator: separator.to_string(),
                        capitalize,
                        number_suffix,
                    };
                    for _ in 0..800 {
                        // 128 组合 × 800 次 = 102_400 ≥ 10⁵
                        let p = generate_passphrase(&opts).expect("合法参数域内不应返回 Err");
                        assert!(!p.is_empty());
                        total += 1;
                    }
                }
            }
        }
    }
    assert!(total >= 100_000, "累计生成次数 {total} 不足 10 万");
}
