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
//!    只许 Ok / Err，不许 panic；
//! 4. **CSV 变异计数不变量**：合法 CSV 的任意字节变异 → 解析成功时
//!    valid_rows + 全空行 == total_rows 且模型数 == valid_rows；
//! 5. **1PUX 恶意条目名**：病态 ZIP 条目名 + 恶意 fileName/documentId
//!    → precheck 不 panic，成功时报告自洽（total == importable + 未导入）；
//! 6. **CSV 确定性**：同一输入两次分析产出完全一致的报告与模型。
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

/// 病态 ZIP 条目名 / 文件名：空、绝对路径、`../` 穿越、反斜杠、超长、
/// 非 ASCII。全部为 `zip` crate 2.2 可编码的 UTF-8 名。
fn malicious_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("/".to_string()),
        Just("..".to_string()),
        Just("../".to_string()),
        Just("../../etc/passwd".to_string()),
        Just("a/../../b".to_string()),
        Just("files/../evil".to_string()),
        Just("files\\..\\evil".to_string()),
        Just("\\".to_string()),
        Just("文件/../../x.pdf".to_string()),
        proptest::collection::vec(proptest::char::range('a', 'z'), 200..512)
            .prop_map(|v| v.into_iter().collect()),
        "[a-z/.]{1,40}",
    ]
}

/// 构造一个「条目 JSON 引用恶意 fileName/documentId、ZIP 内含病态名条目」
/// 的 1PUX 文件。
///
/// `zip::ZipWriter` 拒绝某些名（如含 NUL）时返回 `None`——容器都建不起来，
/// 解析面无从谈起，该例跳过（不影响「解析路径不 panic」性质成立）。
fn malicious_1pux(
    dir: &std::path::Path,
    stem: &str,
    zip_entry_name: &str,
    file_name: &str,
    doc_id: &str,
) -> Option<std::path::PathBuf> {
    let path = dir.join(format!("{stem}.1pux"));
    let f = std::fs::File::create(&path).ok()?;
    let mut zip = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default();
    zip.start_file("export.attributes", opts).ok()?;
    zip.write_all(br#"{"version": 3}"#).ok()?;
    let data = serde_json::json!({
        "accounts": [{
            "attrs": {"name": "M"},
            "vaults": [{
                "attrs": {"uuid": "VM", "name": "v", "type": "P"},
                "items": [{
                    "uuid": "MAL1", "categoryUuid": "112", "state": "active",
                    "createdAt": 1_700_000_000i64, "updatedAt": 1_700_000_000i64,
                    "overview": {"title": "mal"},
                    "details": {"documentAttributes": {
                        "fileName": file_name, "documentId": doc_id,
                        "decryptedSize": 4
                    }}
                }]
            }]
        }]
    })
    .to_string()
    .into_bytes();
    zip.start_file("export.data", opts).ok()?;
    zip.write_all(&data).ok()?;
    zip.start_file(zip_entry_name, opts).ok()?;
    zip.write_all(b"evil").ok()?;
    zip.finish().ok()?;
    Some(path)
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

    /// 性质 4（CSV 变异计数不变量）：合法 CSV 的任意字节变异 → 解析成功时
    /// 计数自洽不变式仍成立（valid_rows + 全空行 == total_rows，
    /// 模型数 == valid_rows）。性质 2 只覆盖「结构化生成」的合法输入；
    /// 本性质把不变式推广到任意变异空间（残缺引号 / 多余逗号 / 非 UTF-8），
    /// 验证「报告即所得」不随畸形输入崩坏。
    #[test]
    fn prop_mutated_csv_preserves_count_invariants(
        title_cell in ".*",
        url_cell in ".*",
        extra_row in ".*",
        pos in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let csv = format!(
            "Title,URL\n{},{},\n{},\n",
            csv_escape(&title_cell),
            csv_escape(&url_cell),
            csv_escape(&extra_row),
        );
        let mut bytes = csv.into_bytes();
        let idx = pos % bytes.len();
        bytes[idx] = byte;

        if let Ok(analysis) = analyze_csv(&bytes) {
            let r = &analysis.report;
            prop_assert_eq!(
                r.valid_rows + r.skipped_rows.len() as u32,
                r.total_rows,
                "valid_rows + 全空行应等于 total_rows（变异空间）"
            );
            prop_assert_eq!(
                analysis.models.len() as u32,
                r.valid_rows,
                "映射模型数应等于 valid_rows（变异空间）"
            );
        }
    }

    /// 性质 5（1PUX 恶意条目名）：病态 ZIP 条目名 + 条目 JSON 的恶意
    /// fileName/documentId（`../` 穿越、绝对路径、反斜杠、空名、超长、
    /// 非 ASCII）→ `precheck_1pux` 只许 Ok / Err，不许 panic；解析成功者
    /// 报告自洽（total_items == importable + not_imported，不静默）。
    ///
    /// 附件名永不落文件系统路径（cf-store 按 uuid 命名文件），故本性质
    /// 只断言「不 panic + 报告自洽」两层，不做路径穿越语义推断。
    #[test]
    fn prop_1pux_malicious_entry_names_never_panic(
        zip_entry_name in malicious_name(),
        file_name in ".*",
        doc_id in ".*",
    ) {
        let dir = tempfile::tempdir().expect("临时目录创建成功");
        if let Some(path) =
            malicious_1pux(dir.path(), "mal", &zip_entry_name, &file_name, &doc_id)
        {
            if let Ok(report) = precheck_1pux(&path) {
                prop_assert_eq!(
                    report.total_items,
                    report.importable_items + report.not_imported.len() as u32,
                    "total_items 应等于可导入 + 未导入（报告不静默）"
                );
            }
        }
    }

    /// 性质 6：analyze_csv 是确定性函数——同一合法输入两次调用产出完全一致
    /// 的报告与模型（防报告构造中引入 HashMap 迭代序 / 时间戳等非确定来源）。
    #[test]
    fn prop_csv_analysis_is_deterministic(
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
        let a = analyze_csv(csv.as_bytes()).expect("结构化 CSV 必可解析");
        let b = analyze_csv(csv.as_bytes()).expect("结构化 CSV 必可解析");
        prop_assert_eq!(a.report, b.report, "同一输入的报告必须一致");
        prop_assert_eq!(a.models, b.models, "同一输入的模型必须一致");
    }
}
