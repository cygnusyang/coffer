//! 明文 CSV 导出（FR-8.3）。
//!
//! 列与 `cf-importer` 的 9 列映射**严格对齐**：表头规范名直接引用
//! [`cf_importer::csv::mapping`] 的 `HEADER_*` 常量（跨 crate 引用防
//! 漂移，docs/09 §3.1 / 风险表 #5），公式判定复用同 crate 的
//! [`cf_importer::csv::mapping::is_formula_like`]。
//!
//! ## 范围与语义
//!
//! - 导出 **Active + Archived** 条目（updated_at 倒序，仓库层既有排序）；
//!   回收站条目不导出，计入 [`CsvExportResult::skipped_trashed`]；
//! - **公式注入防护（导出侧，docs/03 §6.4.4）**：以 `= + - @ \t` 开头的
//!   文本单元格加 `'` 前缀。导入侧按 docs/07 §3.2 裁定保留原值——因此
//!   公式形值回环后**带前缀落库**，这是既定语义而非数据丢失；
//! - TOTP 列回写 `otpauth://` URI（含 secret——文件明文属性由 FR-8.4
//!   二次确认覆盖）。一 item 多 TOTP 时仅导出第一条（CSV 单列，与
//!   1Password 语义一致）；**非 SHA-1 算法的 TOTP 不导出**——导入侧
//!   v0.1 仅支持 totp/SHA-1，回写其他算法的 URI 会被静默按 SHA-1 解析，
//!   产生永远错误的验证码，比空列更危险；
//! - RFC 4180 引号转义（`, "` 与换行触发包裹、`"` 加倍），行结尾
//!   `\r\n`。
//!
//! ## 安全边界
//!
//! 本函数产出**明文文件**（密码、TOTP secret、备注全明文）。UI 门禁
//! （FR-8.4 二次确认 + 成功页删除提示）由调用方负责，本 crate 不做也
//! 不应绕过。

use std::fs;
use std::path::Path;

use cf_domain::field::Designation;
use cf_domain::item::ItemState;
use cf_domain::CfError;
use cf_importer::csv::mapping::{
    is_formula_like, HEADER_ARCHIVED, HEADER_FAVORITE, HEADER_NOTES, HEADER_OTP, HEADER_PASSWORD,
    HEADER_TAGS, HEADER_TITLE, HEADER_USERNAME, HEADER_WEBSITE,
};
use cf_store::repo::totp::TotpMeta;
use cf_store::{ItemListFilter, ItemStore};

/// 表头行（9 列，顺序 = [`cf_importer::csv::mapping`] 映射表顺序）。
const HEADER_ROW: [&str; 9] = [
    HEADER_TITLE,
    HEADER_WEBSITE,
    HEADER_USERNAME,
    HEADER_PASSWORD,
    HEADER_OTP,
    HEADER_FAVORITE,
    HEADER_ARCHIVED,
    HEADER_TAGS,
    HEADER_NOTES,
];

/// CSV 导出结果（docs/09 §3.1 冻结契约）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsvExportResult {
    /// 实际写入的数据行数（不含表头）。
    pub row_count: usize,
    /// 因处于回收站而跳过的条目数。
    pub skipped_trashed: usize,
}

/// 明文 CSV 导出（FR-8.3）。
///
/// # 错误
///
/// 读取条目失败 → 仓库层错误原样透出（[`cf_domain::CfError`]）；
/// 写文件失败 → [`CfError::ExportFailed`]（2003，docs/09 §4：导出失败
/// （IO/打包）统一 2003，载荷保留文件系统细节）。
pub fn export_csv(store: &ItemStore, out_path: &Path) -> Result<CsvExportResult, CfError> {
    let repos = store.repos();
    let items = repos.items.list(&ItemListFilter::default())?;

    let mut body = String::new();
    let mut row_count = 0usize;
    let mut skipped_trashed = 0usize;

    for item in &items {
        if item.row.state == ItemState::Trashed {
            skipped_trashed += 1;
            continue;
        }
        let fields = repos.fields.read_fields_for_item(&item.row.uuid)?;
        // 同 designation 多字段时取第一个（与导入侧「一行一值」语义对齐）
        let find_value = |des: &Designation| {
            fields
                .iter()
                .find(|f| f.designation.as_ref() == Some(des))
                .and_then(|f| f.value.as_ref())
                .map(|v| v.expose().to_owned())
        };
        let username = find_value(&Designation::Username);
        let password = find_value(&Designation::Password);
        let notes = find_value(&Designation::NotesPlain);

        // 主 URL 优先；无 primary 时取第一条（1Password CSV 单列语义）
        let urls = repos.urls.read_for_item(&item.row.uuid)?;
        let website = urls
            .iter()
            .find(|u| u.is_primary)
            .or_else(|| urls.first())
            .map(|u| u.url.expose().to_owned());

        let tag_rows = repos.tags.read_for_item(&item.row.uuid)?;
        let mut tags: Vec<&str> = tag_rows.iter().map(|t| t.name.expose()).collect();
        tags.sort_unstable();
        let tags_str = tags.join(", ");

        let otp = build_otpauth_cell(&repos, &item.row.uuid)?;

        let row = [
            Some(item.title.expose().to_owned()),
            website,
            username,
            password,
            otp,
            None,
            None,
            (!tags_str.is_empty()).then_some(tags_str),
            notes,
        ];
        write_row(
            &mut body,
            &row,
            item.row.is_favorite,
            item.row.state == ItemState::Archived,
        );
        row_count += 1;
    }

    let mut content = String::new();
    push_line(
        &mut content,
        &HEADER_ROW.map(std::string::ToString::to_string),
    );
    content.push_str(&body);

    fs::write(out_path, content).map_err(|e| CfError::ExportFailed(format!("写 CSV 失败：{e}")))?;
    Ok(CsvExportResult {
        row_count,
        skipped_trashed,
    })
}

/// 拼一行（9 列）：favorite / archived 为布尔列，其余文本列过公式防护。
fn write_row(out: &mut String, cells: &[Option<String>; 9], favorite: bool, archived: bool) {
    let mut rendered: [String; 9] = [
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        bool_str(favorite).to_owned(),
        bool_str(archived).to_owned(),
        String::new(),
        String::new(),
    ];
    for (i, cell) in cells.iter().enumerate() {
        if let Some(v) = cell {
            rendered[i] = formula_safe(v);
        }
    }
    push_line(out, &rendered);
}

fn push_line(out: &mut String, cells: &[String]) {
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&csv_field(cell));
    }
    out.push_str("\r\n");
}

/// RFC 4180 字段渲染：含 `,` `"` CR LF 时包裹引号，内部 `"` 加倍。
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// 公式注入防护（导出侧，docs/03 §6.4.4）：`= + - @ \t` 开头加 `'`。
fn formula_safe(value: &str) -> String {
    if is_formula_like(value) {
        format!("'{value}")
    } else {
        value.to_owned()
    }
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

/// 取条目第一条 TOTP（created_at 升序）并回写 otpauth URI 单元格。
///
/// 仅 SHA-1（v0.1 全链路唯一支持算法，见模块文档）；无 TOTP / 非
/// SHA-1 → 空单元格。
fn build_otpauth_cell(
    repos: &cf_store::Repos<'_>,
    item_uuid: &str,
) -> Result<Option<String>, CfError> {
    let Some(totp_uuid) = repos
        .totp
        .totp_uuids_for_item(item_uuid)?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let Some(meta) = repos.totp.totp_meta(&totp_uuid)? else {
        return Ok(None);
    };
    if meta.algo != "sha1" {
        return Ok(None);
    }
    let Some(secret) = repos.totp.totp_secret(&totp_uuid)? else {
        return Ok(None);
    };
    Ok(Some(otpauth_uri(&meta, &secret)))
}

/// `TotpMeta` + 密钥 → `otpauth://totp/` URI。
///
/// 形状对齐 `cf_importer::csv::mapping::parse_otpauth` 的解析面：
/// 路径标签 `Issuer:account`（issuer 缺省时仅 account）、`secret`
/// （大写 Base32、省略填充——导入侧解码容忍）、`issuer` / `digits` /
/// `period` 查询参数。标签成分经 RFC 3986 percent 编码。
fn otpauth_uri(meta: &TotpMeta, secret: &[u8]) -> String {
    let issuer = meta.issuer.clone().unwrap_or_default();
    let account = meta.account.clone().unwrap_or_default();
    let label = if issuer.is_empty() {
        account
    } else {
        format!("{issuer}:{account}")
    };

    let mut uri = format!(
        "otpauth://totp/{}?secret={}",
        percent_encode(&label),
        base32_encode_upper(secret),
    );
    if !issuer.is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&percent_encode(&issuer));
    }
    uri.push_str(&format!("&digits={}&period={}", meta.digits, meta.period));
    uri
}

/// RFC 3986 percent 编码：unreserved（`A-Z a-z 0-9 - . _ ~`）之外全部转义。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// RFC 4648 Base32 编码（标准字母表、大写、省略填充）。
///
/// base32 是**编码而非密码学原语**，可安全自实现；正确性由测试与
/// `cf_totp::base32_decode` 的往返一致性钉死（tests/csv_export.rs）。
fn base32_encode_upper(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (u64::from(buf[0]) << 32)
            | (u64::from(buf[1]) << 24)
            | (u64::from(buf[2]) << 16)
            | (u64::from(buf[3]) << 8)
            | u64::from(buf[4]);
        let chars = (chunk.len() * 8).div_ceil(5); // 本组产生的字符数
        for i in 0..chars {
            let shift = 35 - 5 * i; // 40-bit 组内第 i 个 5-bit 段
            let idx = ((n >> shift) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
        // 省略填充（`=`）：cf_totp::base32_decode 容忍省略填充的 otpauth 形式
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// base32 与 cf_totp::base32_decode 往返一致（含 5 字节边界组）。
    #[test]
    fn base32与cf_totp解码往返一致() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0x00],
            vec![0xDE, 0xAD],
            b"Hello!".to_vec(),
            b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            (0u8..=255).collect(),
        ];
        for data in cases {
            let encoded = base32_encode_upper(&data);
            let decoded = cf_totp::base32_decode(&encoded)
                .unwrap_or_else(|e| panic!("cf_totp 无法解码自产 base32 {encoded:?}：{e}"));
            assert_eq!(decoded, data, "往返不一致：{encoded:?}");
        }
    }

    /// RFC 4648 测试向量（无填充）。
    #[test]
    fn base32_rfc4648_测试向量() {
        assert_eq!(base32_encode_upper(b""), "");
        assert_eq!(base32_encode_upper(b"f"), "MY");
        assert_eq!(base32_encode_upper(b"fo"), "MZXQ");
        assert_eq!(base32_encode_upper(b"foo"), "MZXW6");
        assert_eq!(base32_encode_upper(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode_upper(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode_upper(b"foobar"), "MZXW6YTBOI");
    }

    /// RFC 3986 percent 编码：unreserved 保留、其余转义、大写十六进制。
    #[test]
    fn percent编码规则() {
        assert_eq!(percent_encode("aB3-._~"), "aB3-._~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("用户"), "%E7%94%A8%E6%88%B7");
        assert_eq!(percent_encode("a:b&c=d?e#f"), "a%3Ab%26c%3Dd%3Fe%23f");
    }

    /// 公式防护：`= + - @ \t` 加前缀，普通值原样。
    #[test]
    fn 公式前缀防护() {
        assert_eq!(formula_safe("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(formula_safe("+1"), "'+1");
        assert_eq!(formula_safe("-x"), "'-x");
        assert_eq!(formula_safe("@cmd"), "'@cmd");
        assert_eq!(formula_safe("\tTab"), "'\tTab");
        assert_eq!(formula_safe("normal"), "normal");
        assert_eq!(formula_safe(""), "");
    }

    /// CSV 转义：逗号 / 引号 / 换行触发包裹，引号加倍。
    #[test]
    fn csv字段转义() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("l1\nl2"), "\"l1\nl2\"");
        assert_eq!(csv_field("l1\r\nl2"), "\"l1\r\nl2\"");
    }
}
