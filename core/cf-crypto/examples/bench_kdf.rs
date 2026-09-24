//! Argon2id 参数标定工具 —— M0 第 ③ 项
//!
//! 对应设计文档：`docs/03-详细设计.md` §2.3「Argon2id 参数与标定方法」、
//! `docs/01-需求分析.md` NFR-SEC-02。
//!
//! # 为什么需要它
//!
//! 本项目没有 1Password 的 Secret Key，因此 KDF 参数是**唯一**的
//! 离线爆破成本来源（见 NFR-SEC-03）。参数不能拍脑袋定：
//!
//! - 定低了 → 攻击者爆破成本不足
//! - 定高了 → 低端设备解锁要等好几秒，用户体验崩塌
//!
//! 所以必须在**最低端目标设备**上实测，选出落在 0.5–1.0 s 区间的最大内存参数。
//!
//! # 用法
//!
//! ```bash
//! # 完整扫描（耗时较长，用于最终标定）
//! cargo run --release --example bench_kdf
//!
//! # 快速扫描（每档只跑 1 次，用于初步摸底）
//! cargo run --release --example bench_kdf -- --quick
//!
//! # 输出 JSON，便于归档到标定报告
//! cargo run --release --example bench_kdf -- --json
//! ```
//!
//! ⚠️ **必须用 `--release`**。debug 构建下 Argon2 会慢一到两个数量级，
//! 得到的数字毫无参考价值。
//!
//! # 输出
//!
//! Markdown 表格，标注每个参数组合的实测耗时，并指出落在目标区间的组合。
//! 建议把结果连同设备型号一起归档，作为 NFR-SEC-02 的标定依据。

use std::time::Duration;

use cf_crypto::kdf::{measure_once, KdfParams, PRESET_CANDIDATES, SALT_LEN};

/// 目标区间下限（毫秒）。见 `docs/01-需求分析.md` NFR-SEC-02。
const TARGET_MIN_MS: f64 = 500.0;

/// 目标区间上限（毫秒）。
const TARGET_MAX_MS: f64 = 1000.0;

/// 单档默认重复次数（取平均值，抵消调度抖动）。
const DEFAULT_REPEATS: u32 = 3;

/// 快速模式下的重复次数。
const QUICK_REPEATS: u32 = 1;

#[derive(Debug)]
struct Measurement {
    params: KdfParams,
    samples: Vec<Duration>,
}

impl Measurement {
    fn mean_ms(&self) -> f64 {
        if self.samples.is_empty() {
            return f64::NAN;
        }
        let total: f64 = self.samples.iter().map(|d| d.as_secs_f64()).sum();
        total / self.samples.len() as f64 * 1000.0
    }

    fn min_ms(&self) -> f64 {
        self.samples
            .iter()
            .map(Duration::as_secs_f64)
            .fold(f64::INFINITY, f64::min)
            * 1000.0
    }

    fn max_ms(&self) -> f64 {
        self.samples
            .iter()
            .map(Duration::as_secs_f64)
            .fold(0.0_f64, f64::max)
            * 1000.0
    }

    /// 是否落在 NFR-SEC-02 的目标区间
    fn in_target_range(&self) -> bool {
        (TARGET_MIN_MS..=TARGET_MAX_MS).contains(&self.mean_ms())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let quick = args.iter().any(|a| a == "--quick");
    let json = args.iter().any(|a| a == "--json");
    let repeats = if quick { QUICK_REPEATS } else { DEFAULT_REPEATS };

    let salt = [0x5Au8; SALT_LEN];
    // 用一个固定的、足够长的测试密码。这里只是测耗时，
    // 密码内容不影响 KDF 的计算量（Argon2 的开销由参数决定）。
    let password = "benchmark-only-password-not-a-real-secret";

    if !json {
        eprintln!("=== Coffer Argon2id 参数标定 ===");
        eprintln!("对应 NFR-SEC-02：目标单次派生耗时 {TARGET_MIN_MS:.0}–{TARGET_MAX_MS:.0} ms");
        eprintln!("每档重复次数：{repeats}（取平均值）");
        eprintln!();
        eprintln!("⚠️  提示：请确认当前是 --release 构建。debug 构建的耗时无参考价值。");
        eprintln!("⚠️  提示：最终标定必须在【最低端目标设备】上进行，而不是在开发机上。");
        eprintln!();
    }

    let mut results: Vec<Measurement> = Vec::new();

    for params in PRESET_CANDIDATES {
        let mut samples = Vec::with_capacity(repeats as usize);

        for _ in 0..repeats {
            match measure_once(password, &salt, *params) {
                Ok(d) => samples.push(d),
                Err(e) => {
                    eprintln!(
                        "参数 m={} MiB t={} p={} 执行失败：{e}",
                        params.m_cost_mib(),
                        params.t_cost,
                        params.p_cost
                    );
                    break;
                }
            }
        }

        if !samples.is_empty() {
            let m = Measurement {
                params: *params,
                samples,
            };
            if !json {
                eprintln!(
                    "  完成 m={:>4.0} MiB  t={} p={}  平均 {:>7.1} ms",
                    m.params.m_cost_mib(),
                    m.params.t_cost,
                    m.params.p_cost,
                    m.mean_ms()
                );
            }
            results.push(m);
        }
    }

    if results.is_empty() {
        eprintln!("没有产生任何有效测量结果，标定失败。");
        std::process::exit(1);
    }

    if json {
        print_json(&results);
    } else {
        print_markdown(&results);
    }
}

fn print_markdown(results: &[Measurement]) {
    println!();
    println!("## Argon2id 标定结果");
    println!();
    println!("| m_cost (MiB) | t_cost | p_cost | 平均耗时 (ms) | 最小 (ms) | 最大 (ms) | 落在目标区间 |");
    println!("| --- | --- | --- | --- | --- | --- | --- |");

    for m in results {
        println!(
            "| {:.0} | {} | {} | {:.1} | {:.1} | {:.1} | {} |",
            m.params.m_cost_mib(),
            m.params.t_cost,
            m.params.p_cost,
            m.mean_ms(),
            m.min_ms(),
            m.max_ms(),
            if m.in_target_range() { "✅ 是" } else { "—" }
        );
    }

    println!();
    println!("### 建议");

    // 选取落在目标区间内、内存参数最大的那个
    let best = results
        .iter()
        .filter(|m| m.in_target_range())
        .max_by_key(|m| m.params.m_cost_kib);

    match best {
        Some(m) => {
            println!();
            println!(
                "**建议参数：`m_cost = {} KiB ({} MiB), t_cost = {}, p_cost = {}`** —— 实测平均 {:.1} ms，落在目标区间内且内存开销最大。",
                m.params.m_cost_kib,
                m.params.m_cost_mib(),
                m.params.t_cost,
                m.params.p_cost,
                m.mean_ms()
            );
            println!();
            println!("请把该值写入 `docs/03-详细设计.md` §2.3，并同步更新 `header.json` 的默认 `kdf` 字段。");
        }
        None => {
            let fastest = results.first();
            let slowest = results.last();
            println!();
            println!("**没有任何参数组合落在目标区间内。** 请按以下方向调整：");
            println!();
            match (fastest, slowest) {
                (Some(f), Some(s)) => {
                    if f.mean_ms() > TARGET_MAX_MS {
                        println!(
                            "- 即使最小参数（{} MiB）也要 {:.1} ms，**超出上限**。",
                            f.params.m_cost_mib(),
                            f.mean_ms()
                        );
                        println!("- 说明该设备性能不足。按 `docs/03-详细设计.md` §2.3 第 5 步：");
                        println!("  接受该值并在文档中记录降级，或降低 t_cost / p_cost 后重新扫描。");
                    } else if s.mean_ms() < TARGET_MIN_MS {
                        println!(
                            "- 即使最大参数（{} MiB）也只有 {:.1} ms，**低于下限**。",
                            s.params.m_cost_mib(),
                            s.mean_ms()
                        );
                        println!("- 说明该设备性能充裕。建议扩展 `PRESET_CANDIDATES`，");
                        println!("  继续向上测试更大的 m_cost（如 768 MiB / 1 GiB）。");
                    } else {
                        println!("- 耗时分布在目标区间两侧但未落入。建议细化候选档位。");
                    }
                }
                _ => println!("- 测量数据不足，请重新运行。"),
            }
        }
    }

    println!();
    println!("### 归档提示");
    println!();
    println!("标定结果的效力取决于**记录的完整性**。请一并记录：");
    println!();
    println!("- 执行标定的设备型号、CPU 型号、核心数、内存容量");
    println!("- 操作系统与版本");
    println!("- Rust 版本（`rustc --version`）与构建 profile");
    println!("- 本报告全文");
    println!();
    println!("没有这些上下文，日后无法判断该参数在目标设备上是否仍然成立。");
}

fn print_json(results: &[Measurement]) {
    println!("{{");
    println!("  \"target_min_ms\": {TARGET_MIN_MS},");
    println!("  \"target_max_ms\": {TARGET_MAX_MS},");
    println!("  \"measurements\": [");
    for (i, m) in results.iter().enumerate() {
        let comma = if i + 1 == results.len() { "" } else { "," };
        println!(
            "    {{ \"m_cost_kib\": {}, \"t_cost\": {}, \"p_cost\": {}, \
             \"mean_ms\": {:.3}, \"min_ms\": {:.3}, \"max_ms\": {:.3}, \
             \"in_target_range\": {} }}{comma}",
            m.params.m_cost_kib,
            m.params.t_cost,
            m.params.p_cost,
            m.mean_ms(),
            m.min_ms(),
            m.max_ms(),
            m.in_target_range()
        );
    }
    println!("  ]");
    println!("}}");
}
