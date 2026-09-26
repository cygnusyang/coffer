//! 自写 RFC 4180 CSV 解析器（`docs/07-macOS纵切设计.md` §3.1）。
//!
//! ## 选型说明
//!
//! 刻意**不引入 `csv` crate**（docs/07 §3.1 裁定）：格式足够简单、可精确
//! 施加 DoS 上限、避免第三方库的配置漂移。支持的 RFC 4180 语义：
//!
//! - `""` 引号转义；引号内可含逗号、换行（`\n` 与 `\r\n`，引号内的
//!   CRLF 与孤立 CR 均归一为 `\n`）；
//! - 引号只能出现在字段开头；闭合引号后只允许分隔符 / 换行 / EOF
//!   （严格模式，畸形输入报错并指明行号）；
//! - 引号外只接受 CRLF / LF 作为记录边界；**孤立 CR（裸 `\r`，老 Mac
//!   行尾）报错**——RFC 4180 不认可，静默切分会把行尾格式问题伪装成
//!   导入成功；
//! - 全列按字符串处理（前导零保留，禁止数值化，docs/07 §3.1）。
//!
//! ## DoS 上限（docs/07 §3.1 / docs/04 §4.2 D 类威胁）
//!
//! | 上限 | 值 | 超限行为 |
//! | --- | --- | --- |
//! | [`MAX_FILE_BYTES`] | 50 MB | 拒绝整个文件 |
//! | [`MAX_ROWS`] | 10 000 数据行 | 拒绝并指明行号 |
//! | [`MAX_FIELD_BYTES`] | 64 KiB | 拒绝并指明行号 |
//! | [`MAX_COLUMNS`] | 64 列 | 拒绝并指明行号 |
//!
//! ## 编码
//!
//! 仅 UTF-8（含 BOM 剥离）；无效 UTF-8 → `ImportFailed`，提示转码后重试
//! （GBK 回退推后 v0.2，docs/07 §5 C-7）。
//!
//! ## 行号约定
//!
//! 所有错误与报告中的「行号」一律是**文件行号**（1 起，表头为第 1 行），
//! 与文本编辑器显示一致，便于用户定位。引号内嵌换行会使一条记录跨多行，
//! 记录行号取其**起始行**。

#![forbid(unsafe_code)]

use cf_domain::CfError;

/// UTF-8 BOM（解析前剥离）。
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// 文件大小上限：50 MB（docs/07 §3.1）。
pub const MAX_FILE_BYTES: usize = 50 * 1024 * 1024;

/// 数据行数上限：10 000 行（不含表头）。
pub const MAX_ROWS: usize = 10_000;

/// 单字段字节上限：64 KiB。
pub const MAX_FIELD_BYTES: usize = 64 * 1024;

/// 列数上限：64 列。
pub const MAX_COLUMNS: usize = 64;

/// CSV 一条数据记录（不含表头）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvRow {
    /// 该记录在文件中的起始行号（1 起，表头为第 1 行）。
    pub line_no: u32,
    /// 各列的字符串值（原样保留，前导零不丢失）。
    pub cells: Vec<String>,
}

/// 解析结果：表头 + 数据行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCsv {
    /// 表头（原始大小写，未 trim；列名匹配由映射层负责）。
    pub header: Vec<String>,
    /// 数据行（按文件顺序）。
    pub rows: Vec<CsvRow>,
}

/// 解析 CSV 字节流（UTF-8，自动剥离 BOM）。
///
/// # Errors
///
/// - 文件超过 [`MAX_FILE_BYTES`] → [`CfError::ImportFailed`]；
/// - 无效 UTF-8 → [`CfError::ImportFailed`]（提示转码后重试）；
/// - 数据行数 / 单字段大小 / 列数超限 → [`CfError::ImportFailed`] 并指明行号；
/// - RFC 4180 畸形输入（未闭合引号、字段中间出现引号、闭合引号后
///   出现非法字符）→ [`CfError::ImportFailed`] 并指明行号；
/// - 引号外出现孤立 CR（老 Mac 行尾）→ [`CfError::ImportFailed`]，
///   提示转换行尾后重试。
pub fn parse_csv(input: &[u8]) -> Result<ParsedCsv, CfError> {
    if input.len() > MAX_FILE_BYTES {
        return Err(CfError::ImportFailed(format!(
            "文件大小 {} 字节，超过 50 MB 上限",
            input.len()
        )));
    }

    let body = input.strip_prefix(UTF8_BOM).unwrap_or(input);
    let text = String::from_utf8(body.to_vec()).map_err(|_| {
        CfError::ImportFailed("文件不是有效的 UTF-8 编码，请将导出文件转为 UTF-8 后重试".into())
    })?;

    let mut header: Option<Vec<String>> = None;
    let mut rows: Vec<CsvRow> = Vec::new();
    let mut record: Vec<Vec<u8>> = Vec::new();
    let mut field: Vec<u8> = Vec::new();
    let mut in_quotes = false;
    // 刚闭合一个引号字段：其后只允许 `,` / 换行 / EOF（严格模式）。
    let mut quote_just_closed = false;
    let mut line: u32 = 1;
    let mut record_line: u32 = 1;

    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if in_quotes {
            match b {
                b'"' => {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                        // `""` 转义为一个字面引号
                        field.push(b'"');
                        i += 1;
                    } else {
                        in_quotes = false;
                        quote_just_closed = true;
                    }
                }
                b'\r' => {
                    // 引号内的 CRLF 与孤立 CR 均归一为 LF（与下方引号外
                    // 「裸 CR 报错」的严格性独立：引号内是数据，归一即可）
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                        i += 1;
                    }
                    field.push(b'\n');
                    line += 1;
                }
                b'\n' => {
                    field.push(b'\n');
                    line += 1;
                }
                _ => field.push(b),
            }
            i += 1;
            if field.len() > MAX_FIELD_BYTES {
                return Err(CfError::ImportFailed(format!(
                    "第 {line} 行存在超过 64 KiB 的字段"
                )));
            }
            continue;
        }

        match b {
            b'"' => {
                if quote_just_closed || !field.is_empty() {
                    return Err(CfError::ImportFailed(format!(
                        "第 {line} 行：引号出现在字段中间（RFC 4180 只允许引号在字段开头）"
                    )));
                }
                in_quotes = true;
            }
            b',' => {
                record.push(std::mem::take(&mut field));
                quote_just_closed = false;
            }
            b'\r' => {
                // 裸 CR（后随非 LF）：RFC 4180 只认 CRLF / LF 为记录边界，
                // 老 Mac（Mac OS 9 及更早）行尾文件不在支持范围——静默切分
                // 会把行尾格式问题伪装成「导入成功」，故与解析器严格模式
                // 哲学一致：报错并提示可能原因。
                if i + 1 >= bytes.len() || bytes[i + 1] != b'\n' {
                    return Err(CfError::ImportFailed(format!(
                        "第 {line} 行出现孤立的 CR（\\r）：疑似老 Mac 行尾文件，\
                         请转换为 LF 或 CRLF 行尾后重试"
                    )));
                }
                i += 1; // CRLF 视为一条换行
                line += 1;
                record.push(std::mem::take(&mut field));
                push_record(&mut header, &mut rows, std::mem::take(&mut record), record_line)?;
                record_line = line;
                quote_just_closed = false;
            }
            b'\n' => {
                line += 1;
                record.push(std::mem::take(&mut field));
                push_record(&mut header, &mut rows, std::mem::take(&mut record), record_line)?;
                record_line = line;
                quote_just_closed = false;
            }
            _ => {
                if quote_just_closed {
                    return Err(CfError::ImportFailed(format!(
                        "第 {line} 行：引号闭合后出现非法字符（只允许逗号或换行）"
                    )));
                }
                field.push(b);
            }
        }
        i += 1;
        if field.len() > MAX_FIELD_BYTES {
            return Err(CfError::ImportFailed(format!(
                "第 {line} 行存在超过 64 KiB 的字段"
            )));
        }
    }

    if in_quotes {
        return Err(CfError::ImportFailed(format!(
            "第 {line} 行：引号未闭合（文件在引号字段中间结束）"
        )));
    }

    // 收尾：最后一条未以换行结束的记录
    if !record.is_empty() || !field.is_empty() {
        record.push(field);
        push_record(&mut header, &mut rows, record, record_line)?;
    }

    Ok(ParsedCsv {
        header: header.unwrap_or_default(),
        rows,
    })
}

/// 结束一条记录：字节缓冲 → 字符串 → 表头或数据行（含列数 / 行数上限检查）。
fn push_record(
    header: &mut Option<Vec<String>>,
    rows: &mut Vec<CsvRow>,
    record: Vec<Vec<u8>>,
    record_line: u32,
) -> Result<(), CfError> {
    let cells: Vec<String> = record
        .into_iter()
        .map(|f| {
            String::from_utf8(f)
                .map_err(|_| CfError::Corrupted("csv field not utf-8".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if cells.len() > MAX_COLUMNS {
        return Err(CfError::ImportFailed(format!(
            "第 {record_line} 行列数 {} 超过上限 {MAX_COLUMNS}",
            cells.len()
        )));
    }

    match header {
        None => *header = Some(cells),
        Some(_) => {
            if rows.len() >= MAX_ROWS {
                return Err(CfError::ImportFailed(format!(
                    "数据行数超过上限 {MAX_ROWS}（第 {record_line} 行起超限）"
                )));
            }
            rows.push(CsvRow {
                line_no: record_line,
                cells,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str) -> Result<ParsedCsv, CfError> {
        parse_csv(s.as_bytes())
    }

    /// 基础解析：表头 + 多行数据
    #[test]
    fn 基础解析表头与数据行() {
        let parsed = parse_str("a,b,c\n1,2,3\n4,5,6\n").unwrap();
        assert_eq!(parsed.header, vec!["a", "b", "c"]);
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[0].cells, vec!["1", "2", "3"]);
        assert_eq!(parsed.rows[0].line_no, 2);
        assert_eq!(parsed.rows[1].line_no, 3);
    }

    /// 引号内逗号不切分
    #[test]
    fn 引号内逗号不切分() {
        let parsed = parse_str("t\n\"a,b\",c\n").unwrap();
        assert_eq!(parsed.rows[0].cells, vec!["a,b", "c"]);
    }

    /// `""` 转义为字面引号
    #[test]
    fn 双引号转义() {
        let parsed = parse_str("t\n\"he said \"\"hi\"\"\",x\n").unwrap();
        assert_eq!(parsed.rows[0].cells, vec!["he said \"hi\"", "x"]);
    }

    /// 引号内嵌换行（\n 与 \r\n），记录行号取起始行
    #[test]
    fn 引号内嵌换行() {
        let parsed = parse_str("t\n\"line1\nline2\",x\n").unwrap();
        assert_eq!(parsed.rows[0].cells, vec!["line1\nline2", "x"]);
        assert_eq!(parsed.rows[0].line_no, 2);

        let parsed = parse_str("t\r\n\"line1\r\nline2\",x\r\n").unwrap();
        assert_eq!(parsed.rows[0].cells, vec!["line1\nline2", "x"]);
        assert_eq!(parsed.rows[0].line_no, 2);
    }

    /// CRLF 行尾与 LF 行尾等价
    #[test]
    fn crlf与lf等价() {
        let a = parse_str("h1,h2\n1,2\r\n3,4\r\n").unwrap();
        let b = parse_str("h1,h2\n1,2\n3,4\n").unwrap();
        assert_eq!(a, b);
    }

    /// BOM 自动剥离
    #[test]
    fn bom自动剥离() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"t\nv\n");
        let parsed = parse_csv(&bytes).unwrap();
        assert_eq!(parsed.header, vec!["t"]);
        assert_eq!(parsed.rows[0].cells, vec!["v"]);
    }

    /// 文件不以换行结束：最后一条记录仍然入账
    #[test]
    fn 无结尾换行的最后一条记录() {
        let parsed = parse_str("t\nlast").unwrap();
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].cells, vec!["last"]);
    }

    /// 前导零保留（全列按字符串处理）
    #[test]
    fn 前导零保留() {
        let parsed = parse_str("t\n00123\n").unwrap();
        assert_eq!(parsed.rows[0].cells, vec!["00123"]);
    }

    /// 未闭合引号报错并指明行号
    #[test]
    fn 未闭合引号报错() {
        let err = parse_str("t\n\"abc\n").unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("引号未闭合")));
    }

    /// 字段中间出现引号报错（RFC 4180 严格模式）
    #[test]
    fn 字段中间引号报错() {
        let err = parse_str("t\nab\"cd\n").unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("引号出现在字段中间")));
    }

    /// 闭合引号后出现非法字符报错
    #[test]
    fn 闭合引号后非法字符报错() {
        let err = parse_str("t\n\"abc\"x\n").unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("引号闭合后出现非法字符")));
    }

    /// 数据行数超过 10 000 → 拒绝并指明行号
    #[test]
    fn 行数超限拒绝并报行号() {
        let mut csv = String::from("t\n");
        for _ in 0..=MAX_ROWS {
            csv.push_str("v\n");
        }
        let err = parse_str(&csv).unwrap_err();
        // 第 1 条数据在第 2 行，第 10001 条数据在第 10002 行
        assert!(
            matches!(err, CfError::ImportFailed(ref m) if m.contains("10002")),
            "错误应指明行号：{err}"
        );
    }

    /// 单字段超过 64 KiB → 拒绝并指明行号
    #[test]
    fn 字段超限拒绝并报行号() {
        let big = "x".repeat(MAX_FIELD_BYTES + 1);
        let csv = format!("t\n{big}\n");
        let err = parse_str(&csv).unwrap_err();
        assert!(
            matches!(err, CfError::ImportFailed(ref m) if m.contains("64 KiB")),
            "错误应说明字段超限：{err}"
        );
    }

    /// 恰好 64 KiB 的字段应放行（上限是闭区间内合法）
    #[test]
    fn 字段恰好上限放行() {
        let big = "x".repeat(MAX_FIELD_BYTES);
        let parsed = parse_str(&format!("t\n{big}\n")).unwrap();
        assert_eq!(parsed.rows[0].cells[0].len(), MAX_FIELD_BYTES);
    }

    /// 列数超过 64 → 拒绝并指明行号
    #[test]
    fn 列数超限拒绝() {
        let mut csv = String::new();
        for i in 0..65 {
            if i > 0 {
                csv.push(',');
            }
            csv.push_str(&format!("c{i}"));
        }
        csv.push('\n');
        let err = parse_str(&csv).unwrap_err();
        assert!(
            matches!(err, CfError::ImportFailed(ref m) if m.contains("64")),
            "错误应说明列数超限：{err}"
        );
    }

    /// 文件超过 50 MB → 拒绝
    #[test]
    fn 文件超限拒绝() {
        let big = vec![b'a'; MAX_FILE_BYTES + 1];
        let err = parse_csv(&big).unwrap_err();
        assert!(matches!(err, CfError::ImportFailed(ref m) if m.contains("50 MB")));
    }

    /// 无效 UTF-8 → 拒绝并提示转码
    #[test]
    fn 无效utf8拒绝() {
        let bytes = b"t\n\xc4\xe3\xba\xc3\n"; // GBK 的「你好」
        let err = parse_csv(bytes).unwrap_err();
        assert!(
            matches!(err, CfError::ImportFailed(ref m) if m.contains("UTF-8")),
            "错误应提示转码：{err}"
        );
    }

    /// 空文件：表头为空、无数据行（表头识别层负责报「格式无法识别」）
    #[test]
    fn 空文件返回空结构() {
        let parsed = parse_str("").unwrap();
        assert!(parsed.header.is_empty());
        assert!(parsed.rows.is_empty());
    }

    /// 全空行（单个空字段）也入账为一行数据
    #[test]
    fn 空行入账() {
        let parsed = parse_str("t\nv\n\n").unwrap();
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.rows[1].cells, vec![""]);
    }
}
