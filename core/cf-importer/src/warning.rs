//! # warning —— 导入告警的结构化编码（码 + 参数）
//!
//! BUG-35 第一阶段：告警文本此前由 core 以**中文整句**直出，经 FFI 原样进入
//! Swift `Label(warning)`，英文界面必现中文（v2.13.0 多语言留的显式非目标）。
//! 本模块把「文案」与「数据」拆开：core 只产出**码 + 参数**，用户可见句子由
//! Swift 侧 `Support/ImportWarningText.swift` 按码本地化。
//!
//! ## 线格式（`code|param1|param2`）
//!
//! - 无参数：裸码；
//! - 有参数：码后逐参数以 `|` 分隔，参数内的 `|` 与反斜杠转义为「反斜杠 + 字符」；
//! - **不改 FFI 类型**：`warnings` 仍是 `Vec<String>`，避免 uniffi 绑定重生成；
//!   Swift 侧解码失败（未知码 / 非本格式的旧字符串）一律原样展示，向后兼容。
//!
//! ## 硬约束
//!
//! - 参数只放**非敏感数据**（行号、列名、计数、兜底标题、脱敏原因摘要）：
//!   编码结果会跨 FFI 进入 Swift 内存与 UI，密码 / TOTP secret / 原始 URI 一律
//!   不得作参数（R2；见 `dropzone.rs` M-3 脱敏注释）。
//! - 码是**契约**：与 Swift `ImportWarningText` 的 `switch` 分支一一对应，改名
//!   必须两侧同步改，否则 UI 回落成裸码字符串。

/// 分隔符（码 / 参数、参数之间）。
const SEPARATOR: char = '|';

/// 转义符：只转义自身与分隔符，其余转义序列原样保留。
const ESCAPE: char = '\\';

/// 第 N 行缺失 Title，导入时以兜底标题替代（参数：行号、兜底标题）。
pub const MISSING_TITLE: &str = "csv.missing_title";

/// 第 N 行 One-time password 无法解析，原始值并入备注、该行仍导入（参数：行号）。
pub const TOTP_UNPARSED: &str = "csv.totp_unparsed";

/// 第 N 行某列值不是 true/false，按 false 处理（参数：行号、列名）。
pub const BOOL_INVALID: &str = "csv.bool_invalid";

/// 第 N 行数据比表头多若干列，多出的非空值并入备注（参数：行号、多出列数）。
pub const EXTRA_COLUMNS: &str = "csv.extra_columns";

/// 第 N 行某列值以公式前缀字符开头，导出为 CSV 时会被转义（参数：行号、列名）。
pub const FORMULA_PREFIX: &str = "csv.formula_prefix";

/// 检测到重复标题，导入全部新建、不做去重（参数：重复标题数、涉及行数）。
pub const DUPLICATE_TITLES: &str = "csv.duplicate_titles";

/// 丢弃若干条密码历史（历史表语义不同构，FR-2.9）（参数：丢弃条数）。
///
/// 生成点在 Bitwarden / 1PUX 预检（`bitwarden/precheck.rs` / `pux/precheck.rs`）；
/// 两处同句同码，改文案只需改 Swift 模板一处。
pub const PASSWORD_HISTORY_DROPPED: &str = "csv.password_history_dropped";

/// 第 N 行 One-time password 无法解析（附脱敏原因），原始值并入备注（参数：行号、原因）。
pub const TOTP_UNPARSED_DETAIL: &str = "csv.totp_unparsed_detail";

/// 全部已知码（[decode] 的识别域，与 Swift 侧分支集合保持一致）。
pub const CODES: [&str; 8] = [
    MISSING_TITLE,
    TOTP_UNPARSED,
    BOOL_INVALID,
    EXTRA_COLUMNS,
    FORMULA_PREFIX,
    DUPLICATE_TITLES,
    PASSWORD_HISTORY_DROPPED,
    TOTP_UNPARSED_DETAIL,
];

/// 把「码 + 参数」编码成跨 FFI 的结构化字符串。
///
/// 无参数时输出裸 `code`；有参数时以 [SEPARATOR] 追加逐个参数，参数内的
/// [SEPARATOR] 与 [ESCAPE] 先行转义，保证 [decode] 可无损还原。
///
/// 参数会进入 UI 与 Swift 内存，**不得携带凭据或原始 URI**（R2）。
#[must_use]
pub fn encode(code: &str, params: &[String]) -> String {
    let mut out = String::with_capacity(code.len() + params.len() * 8);
    out.push_str(code);
    for param in params {
        out.push(SEPARATOR);
        for ch in param.chars() {
            if ch == SEPARATOR || ch == ESCAPE {
                out.push(ESCAPE);
            }
            out.push(ch);
        }
    }
    out
}

/// [encode] 的逆操作。
///
/// - Returns: `Some((code, params))` 当且仅当首字段是 [CODES] 中的已知码；
///   未知码或非本格式的字符串（如既有的中文整句告警）返回 `None`——调用方据此
///   原样展示，实现新旧告警共存。
#[must_use]
pub fn decode(raw: &str) -> Option<(String, Vec<String>)> {
    let mut fields = split_fields(raw).into_iter();
    let code = fields.next()?;
    if !CODES.contains(&code.as_str()) {
        return None;
    }
    Some((code, fields.collect()))
}

/// 按未转义的分隔符切分，并逐字段反转义。
fn split_fields(raw: &str) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in raw.chars() {
        if escaped {
            current.push(ESCAPE);
            current.push(ch);
            escaped = false;
        } else if ch == ESCAPE {
            escaped = true;
        } else if ch == SEPARATOR {
            fields.push(unescape(&current));
            current.clear();
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push(ESCAPE);
    }
    fields.push(unescape(&current));
    fields
}

/// 反转义单个字段：分隔符与转义符还原为自身；其它「反斜杠 + 字符」与孤立尾部
/// 反斜杠原样保留（non-lossy：不是本编码产生的转义不做猜测性改写）。
fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(ch) = chars.next() {
        if ch != ESCAPE {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(next @ (SEPARATOR | ESCAPE)) => out.push(next),
            Some(other) => {
                out.push(ESCAPE);
                out.push(other);
            }
            None => out.push(ESCAPE),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// 编码/解码往返：多参数逐字还原
    #[test]
    fn 编解码往返() {
        let raw = encode(MISSING_TITLE, &params(&["2", "（无标题）"]));
        assert_eq!(raw, "csv.missing_title|2|（无标题）");
        let (code, decoded) = decode(&raw).expect("已知码必须可解码");
        assert_eq!(code, MISSING_TITLE);
        assert_eq!(decoded, params(&["2", "（无标题）"]));
    }

    /// 参数内含分隔符与反斜杠：转义后仍可无损还原
    #[test]
    fn 参数含分隔符与反斜杠往返() {
        let tricky = params(&["a|b", "c\\d", "e\\|f"]);
        let raw = encode(BOOL_INVALID, &tricky);
        assert!(raw.contains("\\|"), "分隔符必须转义：{raw}");
        let (code, decoded) = decode(&raw).expect("已知码必须可解码");
        assert_eq!(code, BOOL_INVALID);
        assert_eq!(decoded, tricky);
    }

    /// 无参数：输出裸码，解码得空参数表
    #[test]
    fn 无参数编解码() {
        let raw = encode(TOTP_UNPARSED, &[]);
        assert_eq!(raw, "csv.totp_unparsed");
        let (code, decoded) = decode(&raw).expect("已知码必须可解码");
        assert_eq!(code, TOTP_UNPARSED);
        assert!(decoded.is_empty());
    }

    /// 未知码 / 既有中文整句 → None（Swift 侧据此原样展示，新旧告警共存）
    #[test]
    fn 未知码与旧整句不识别() {
        assert!(decode("csv.unknown_code|1").is_none());
        assert!(decode("第 2 行：缺失 Title，导入时以「（无标题）」兜底").is_none());
        assert!(decode("").is_none());
    }

    /// 所有码都在识别域内，且互不相同（防复制粘贴串码）
    #[test]
    fn 码表自洽() {
        for code in CODES {
            let raw = encode(code, &params(&["1"]));
            let (decoded_code, _) = decode(&raw).expect("码表内的码必须可解码");
            assert_eq!(decoded_code, code);
        }
        let unique: std::collections::HashSet<&&str> = CODES.iter().collect();
        assert_eq!(unique.len(), CODES.len(), "码必须唯一");
    }

    /// 非预期转义与孤立尾部转义符：原样保留，不吞字符（non-lossy）
    #[test]
    fn 非预期转义原样保留() {
        assert_eq!(
            decode("csv.formula_prefix|2\\"),
            Some((FORMULA_PREFIX.to_owned(), params(&["2\\"])))
        );
    }
}
