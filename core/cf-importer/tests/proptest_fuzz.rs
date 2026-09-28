//! CSV / 1PUX 解析面的属性测试（模糊测试基建，docs/09 §2 v1.0.0 卡片）。
//!
//! 本机无 nightly / cargo-fuzz（环境替代方案，口径同 cf-format 的
//! `tests/proptest_header.rs`），以 proptest 承担同等判据：
//!
//! 1. **CSV 任意字节不 panic**：`analyze_csv` 对任意输入只许 Ok / Err
//!    （docs/07 §3.1 DoS 上限路径也在生成器覆盖范围内）；
//! 2. **CSV 结构化输入的报告不变量**：任意表头列名 + 任意单元格文本
//!    组成的 CSV，解析成功时报告满足 `valid_rows + 全空行 == total_rows`
//!    且映射模型数 == `valid_rows`（预检与导入复用同一条管线，
//!    docs/07 §3.3「报告即所得」的属性化表达）；
//! 3. **1PUX 任意字节不 panic**：任意字节写入临时文件后走
//!    `precheck_1pux`（坏 ZIP / 缺成员 / JSON 非法 / zip bomb 上限路径），
//!    只许 Ok / Err，不许 panic。
//!
//! CI 口径：默认测试集内直接执行（单轮 128~256 例，耗时秒级，无需
//! `#[ignore]`）。

use std::io::Write as _;

use cf_importer::{analyze_csv, pux::precheck_1pux};
use proptest::prelude::*;

/// 任意字节序列（含非法 UTF-8 / 空输入 / 截断的多字节字符）。
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..512)
}

/// 把任意文本按 CSV 语法落成一行（引号转义，允许产出解析器可拒绝的形状）。
fn csv_escape(cell: &str) -> String {
    format!("\"{}\"", cell.replace('"', "\"\""))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// 性质 1：CSV 任意字节 → analyze_csv 只许 Ok / Err，不许 panic。
    #[test]
    fn prop_csv_arbitrary_bytes_never_panics(bytes in arbitrary_bytes()) {
        let _ = analyze_csv(&bytes);
    }

    /// 性质 2：结构化 CSV（任意列名 + 任意单元格）解析成功时，
    /// 报告计数自洽：valid_rows + 全空行 == total_rows，
    /// 且映射模型数 == valid_rows（「报告即所得」不变量）。
    #[test]
    fn prop_csv_report_invariants(
        title_cell in ".*",
        url_cell in ".*",
        extra_row in ".*",
    ) {
        let csv = format!(
            "Title,URL\n{},{},\n{},\n",
            csv_escape(&title_cell),
            csv_escape(&url_cell),
            csv_escape(&extra_row),
        );
        if let Ok(analysis) = analyze_csv(csv.as_bytes()) {
            let r = &analysis.report;
            prop_assert_eq!(
                r.valid_rows + r.skipped_rows.len() as u32,
                r.total_rows,
                "valid_rows + 全空行应等于 total_rows"
            );
            prop_assert_eq!(
                analysis.models.len() as u32,
                r.valid_rows,
                "映射模型数应等于 valid_rows（报告即所得）"
            );
        }
    }

    /// 性质 3：1PUX 任意字节 → precheck_1pux 只许 Ok / Err，不许 panic。
    /// 坏字节几乎必然落在「非法 ZIP」分支，与手工对抗测试
    /// （pux_import.rs 的坏 ZIP / 缺成员 / zip bomb 用例）互补。
    #[test]
    fn prop_1pux_arbitrary_bytes_never_panics(bytes in arbitrary_bytes()) {
        let dir = tempfile::tempdir().expect("临时目录创建成功");
        let path = dir.path().join("fuzz.1pux");
        let mut f = std::fs::File::create(&path).expect("临时文件创建成功");
        f.write_all(&bytes).expect("写入成功");
        drop(f);
        let _ = precheck_1pux(&path);
    }
}
