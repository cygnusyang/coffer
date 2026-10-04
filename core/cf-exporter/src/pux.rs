//! 1PUX 明文导出（FR-8.2，v0.7.0-T01）。
//!
//! 导出 Coffer 库为 1Password Unencrypted Export（`.1pux`）：标准 ZIP +
//! 明文 JSON（`export.attributes` / `export.data` / `files/` 附件）。
//! 主判据为 **导出 → 重新导入自回环逐字节等价**（docs/22 §2.1.6；
//! `docs/23` TC-EXP 组）。
//!
//! ## 结构（官方 1PUX v3）
//!
//! - `export.attributes`：`{"version": 3, "createdAt": <unix秒>}`
//! - `export.data`：`accounts → vaults → items` 三级；条目键 `uuid` /
//!   `categoryUuid` / `state` / `createdAt` / `updatedAt` / `favIndex` /
//!   `overview{title,urls,tags}` / `details{loginFields,notesPlain,
//!   sections,documentAttributes}`。
//! - `files/<documentId>___<fileName>`：附件明文（documentId 为新建
//!   UUIDv7；分隔符 `___` 命中导入侧前缀枚举）。
//!
//! ## 字段发射（与 cf-importer 导入侧映射互为逆运算，回环无损）
//!
//! | Coffer 字段 | 1PUX 形态 |
//! | --- | --- |
//! | designation=Username | `loginFields[{designation:"username",fieldType:"T"}]`（多余 Username 字段走普通字段） |
//! | designation=Password | `loginFields[{designation:"password",fieldType:"P"}]` |
//! | designation=Totp | `loginFields[{designation:"totp",value:{totp:"<otpauth URI>"}}]`（totp 表全量导出） |
//! | designation=NotesPlain | `details.notesPlain`（多条以 `\n` 合并，与导入侧 join 逆运算） |
//! | 其余（Email/Other/None） | `sections[].fields[]`；字段名按首个 `" / "` 拆分区/字段（与导入侧组合逆运算） |
//!
//! 字段类型码（docs/22 §2.1）：T/P/U/E/N/D/M/B；`Multiline` / `Phone` /
//! `Totp` / `Unsupported` 无 1P 承载码 → 降级 Text 并计入报告（不静默，
//! TC-EXP-14）。
//!
//! ## 边界
//!
//! - 回收站条目跳过 + 计数（TC-EXP-05）；
//! - passkey **不导出** + 计数（TC-EXP-07）；
//! - 分类反向映射复用 cf-domain §6.4.1 权威表（`opvault_code`），未命中
//!   兜底 `003`（SecureNote，TC-EXP-08）；
//! - 原子落盘：临时兄弟文件 → rename（备份包同型，FR-8.6 纪律）。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::CfError;
use cf_store::rows::FieldDecrypted;
use cf_store::{ItemListFilter, ItemStore, ItemWithTitle, Repos, TotpMeta};
use serde_json::{json, Map, Value};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// 导出结果（docs/22 §3.1 冻结契约 + 报告扩展）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuxExportResult {
    /// 实际导出条目数（不含回收站跳过）。
    pub item_count: usize,
    /// 导出附件文件数。
    pub attachment_count: usize,
    /// 因处于回收站而跳过的条目数。
    pub skipped_trashed: usize,
    /// 因不支持导出而跳过的 passkey 数（显式计数，不静默）。
    pub skipped_passkeys: usize,
    /// 降级 / 非 SHA-1 TOTP 的显式报告。
    pub report: PuxExportReport,
}

/// 导出过程中的降级报告（TC-EXP-06 / TC-EXP-14 素材，不静默）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PuxExportReport {
    /// 无 1P 承载码而降级为 Text 的字段（`条目uuid:字段名`）。
    pub degraded_fields: Vec<String>,
    /// 非 SHA-1 TOTP 导出数（跨导入方可能不支持而降级）。
    pub non_sha1_totp: usize,
}

/// 单条目发射期间的累计量。
struct Accum {
    /// 附件文件数。
    attachment_count: usize,
    /// 跳过 passkey 数。
    skipped_passkeys: usize,
    /// 降级报告。
    report: PuxExportReport,
}

/// 1PUX 明文导出（FR-8.2）。
///
/// `vault_dir` 为附件旁路文件目录（`attachments/`）的宿主目录，须与
/// 解锁保险库时的 vault 根目录一致（与导入侧 `import_1pux` 对称）。
///
/// # 错误
///
/// 读取条目失败 → 仓库层错误原样透出（[`cf_domain::CfError`]）；
/// 打包 / 写文件失败 → [`CfError::ExportFailed`]（2003，docs/09 §4）；
/// 目标父目录不存在 → [`CfError::ExportFailed`]（不建目录、不留半成品）。
pub fn export_one_pux(
    store: &ItemStore,
    vault_dir: &Path,
    out_path: &Path,
) -> Result<PuxExportResult, CfError> {
    // 父目录必须已存在（UI 侧已让用户选定目标位置；不建目录，TC-EXP-11）
    if out_path.parent().is_none_or(|p| !p.is_dir()) {
        return Err(CfError::ExportFailed(format!(
            "目标父目录不存在：{}",
            out_path
                .parent()
                .map_or_else(|| "(none)".to_owned(), |p| p.display().to_string())
        )));
    }

    let repos = store.repos();
    let items = repos.items.list(&ItemListFilter::default())?;

    let mut acc = Accum {
        attachment_count: 0,
        skipped_passkeys: 0,
        report: PuxExportReport::default(),
    };
    let mut item_jsons: Vec<Value> = Vec::new();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut item_count = 0usize;
    let mut skipped_trashed = 0usize;

    for item in &items {
        if item.row.state == ItemState::Trashed {
            skipped_trashed += 1;
            continue;
        }
        let emitted = emit_item(&repos, item, vault_dir, &mut acc)?;
        item_count += 1;
        item_jsons.push(emitted.json);
        files.extend(emitted.files);
    }

    // 临时文件 → rename：任何一步失败都清理临时文件，目标不留半截
    //（备份包同型纪律，FR-8.6）
    let tmp_path = temp_sibling_path(out_path);
    if let Err(e) = write_zip(&tmp_path, &item_jsons, &files) {
        let _ = fs::remove_file(&tmp_path);
        return Err(export_err(e));
    }
    if let Err(e) = finalize_export(&tmp_path, out_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(export_err(e));
    }

    Ok(PuxExportResult {
        item_count,
        attachment_count: acc.attachment_count,
        skipped_trashed,
        skipped_passkeys: acc.skipped_passkeys,
        report: acc.report,
    })
}

/// 单条目的发射产物：`json` 为该条目的 1PUX item 对象，
/// `files` 为「`files/` 段文件名 → 解密后内容」附件对（经调用方统一写入 ZIP）。
struct EmittedItem {
    json: Value,
    files: Vec<(String, Vec<u8>)>,
}

/// 发射单条目 JSON + 其附件文件（须在 `export_one_pux` 的循环内调用）。
fn emit_item(
    repos: &Repos<'_>,
    item: &ItemWithTitle,
    vault_dir: &Path,
    acc: &mut Accum,
) -> Result<EmittedItem, CfError> {
    let row = &item.row;
    let item_uuid = &row.uuid;

    // passkey：不导出数据，显式计数（TC-EXP-07，不静默）
    acc.skipped_passkeys += repos.passkeys.list_for_item(item_uuid)?.len();

    // ---- 字段分类 ----
    let fields = repos.fields.read_fields_for_item(item_uuid)?;
    let mut login_fields: Vec<Value> = Vec::new();
    let mut notes_parts: Vec<String> = Vec::new();
    let mut grouped: Vec<(Option<String>, Vec<Value>)> = Vec::new();

    let mut seen_username = false;
    let mut seen_password = false;
    for f in &fields {
        match &f.designation {
            Some(Designation::Username) if !seen_username => {
                seen_username = true;
                login_fields.push(login_field_json("username", f, "T"));
            }
            Some(Designation::Password) if !seen_password => {
                seen_password = true;
                login_fields.push(login_field_json("password", f, "P"));
            }
            Some(Designation::NotesPlain) => {
                if let Some(v) = &f.value {
                    notes_parts.push(v.expose().to_owned());
                }
            }
            // 防御：TOTP 走 totp 表（见下），字段形态残留仅报告不静默
            Some(Designation::Totp) => {
                acc.report
                    .degraded_fields
                    .push(format!("{item_uuid}:{}", f.name.expose()));
            }
            // 普通字段：Email / Other / None 与多余 Username/Password
            _ => push_normal_field(&mut grouped, item_uuid, f, &mut acc.report),
        }
    }

    // ---- totp 表 → loginFields（TOTP 全量导出，裁决 D） ----
    for tuuid in repos.totp.totp_uuids_for_item(item_uuid)? {
        let meta = repos.totp.totp_meta(&tuuid)?.ok_or_else(|| {
            CfError::Corrupted(format!("totp 行 {tuuid} 缺失（数据损坏）"))
        })?;
        let secret = repos.totp.totp_secret(&tuuid)?.ok_or_else(|| {
            CfError::Corrupted(format!("totp 密钥 {tuuid} 缺失（数据损坏）"))
        })?;
        if meta.algo != "sha1" {
            acc.report.non_sha1_totp += 1;
        }
        login_fields.push(json!({
            "designation": "totp",
            "name": "one-time password",
            "value": {"totp": totp_uri(&meta, &secret)}
        }));
    }

    // ---- details ----
    let mut details = Map::new();
    if !notes_parts.is_empty() {
        details.insert("notesPlain".into(), Value::String(notes_parts.join("\n")));
    }
    if !login_fields.is_empty() {
        details.insert("loginFields".into(), Value::Array(login_fields));
    }
    if !grouped.is_empty() {
        let sections: Vec<Value> = grouped
            .into_iter()
            .map(|(st, fields)| {
                let mut sec = Map::new();
                if let Some(t) = st {
                    sec.insert("title".into(), Value::String(t));
                }
                sec.insert("fields".into(), Value::Array(fields));
                Value::Object(sec)
            })
            .collect();
        details.insert("sections".into(), Value::Array(sections));
    }

    // ---- overview ----
    let urls = repos.urls.read_for_item(item_uuid)?;
    let url_values: Vec<Value> = urls
        .iter()
        .map(|u| {
            json!({
                "label": u.label.as_ref().map(|l| l.expose()),
                "url": u.url.expose()
            })
        })
        .collect();
    let tags = repos.tags.read_for_item(item_uuid)?;
    let tag_values: Vec<Value> = tags.iter().map(|t| json!(t.name.expose())).collect();
    let mut overview = Map::new();
    overview.insert("title".into(), Value::String(item.title.expose().to_owned()));
    overview.insert("urls".into(), Value::Array(url_values));
    overview.insert("tags".into(), Value::Array(tag_values));

    // ---- 附件：documentAttributes（首条）+ files/ 全部明文 ----
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let atts = repos.attachments.list_for_item(item_uuid)?;
    if let Some(first) = atts.first() {
        let doc_id = uuid::Uuid::now_v7().to_string();
        details.insert(
            "documentAttributes".into(),
            json!({
                "fileName": first.filename,
                "documentId": doc_id,
                "decryptedSize": first.size_bytes
            }),
        );
        for a in &atts {
            let content = repos.attachments.read_content(&a.uuid, vault_dir)?;
            let entry = format!("files/{doc_id}___{}", a.filename);
            files.push((entry, content));
            acc.attachment_count += 1;
        }
    }

    // ---- 条目级 ----
    let state_str = match row.state {
        ItemState::Active => "active",
        ItemState::Archived => "archived",
        // 回收站条目已在调用方跳过（TC-EXP-05）；此处仅为穷尽
        ItemState::Trashed => "trashed",
    };
    let item_json = json!({
        "uuid": row.uuid,
        "categoryUuid": category_to_1p_code(row.category),
        "state": state_str,
        "createdAt": row.created_at,
        "updatedAt": row.updated_at,
        "favIndex": row.fav_index,
        "overview": overview,
        "details": details
    });

    Ok(EmittedItem {
        json: item_json,
        files,
    })
}

/// username / password 走 designation 的 loginField（导入侧 write 恒为
/// Text/Concealed，故码固定 T/P；见模块文档）。
fn login_field_json(designation: &str, f: &FieldDecrypted, code: &str) -> Value {
    json!({
        "designation": designation,
        "name": f.name.expose(),
        "fieldType": code,
        "value": f.value.as_ref().map(|v| v.expose()),
    })
}

/// 普通字段 → sections 分组（名称按首个 `" / "` 拆分区/字段，与导入侧
/// display_name 组合互为逆运算；回环无损）。
fn push_normal_field(
    grouped: &mut Vec<(Option<String>, Vec<Value>)>,
    item_uuid: &str,
    f: &FieldDecrypted,
    report: &mut PuxExportReport,
) {
    let code = field_type_to_1p_code(f.field_type);
    let code_str = code.unwrap_or("T");
    if code.is_none() {
        report
            .degraded_fields
            .push(format!("{item_uuid}:{} ({:?}→Text)", f.name.expose(), f.field_type));
    }
    let (st, ft) = split_field_name(f.name.expose());
    let mut field_json = Map::new();
    if let Some(ft) = ft {
        field_json.insert("title".into(), Value::String(ft));
    }
    if let Some(d) = f.designation.as_ref().and_then(emit_designation) {
        field_json.insert("designation".into(), Value::String(d));
    }
    field_json.insert("fieldType".into(), Value::String(code_str.to_owned()));
    field_json.insert(
        "value".into(),
        f.value.as_ref().map_or(Value::Null, |v| Value::String(v.expose().to_owned())),
    );
    if let Some(g) = grouped.iter_mut().find(|g| g.0 == st) {
        g.1.push(Value::Object(field_json));
    } else {
        grouped.push((st, vec![Value::Object(field_json)]));
    }
}

/// designation → 1PUX 字符串；`totp`/`otp` 在分区字段上会被导入侧当
/// TOTP 解析，必须规避（防御性，正常路径不会出现）。
fn emit_designation(d: &Designation) -> Option<String> {
    let s = d.to_1p_str();
    if s == "totp" || s == "otp" {
        None
    } else {
        Some(s.to_owned())
    }
}

/// Coffer 字段类型 → 1PUX 字段类型码（docs/22 §2.1）。
///
/// `Multiline` / `Phone` / `Totp` / `Unsupported` 无承载码 → `None`，
/// 调用方降级 Text + 报告（TC-EXP-14）。
fn field_type_to_1p_code(t: FieldType) -> Option<&'static str> {
    match t {
        FieldType::Text => Some("T"),
        FieldType::Concealed => Some("P"),
        FieldType::Url => Some("U"),
        FieldType::Email => Some("E"),
        FieldType::Number => Some("N"),
        FieldType::Date => Some("D"),
        FieldType::MonthYear => Some("M"),
        FieldType::Bool => Some("B"),
        FieldType::Multiline | FieldType::Phone | FieldType::Totp | FieldType::Unsupported => None,
    }
}

/// 字段名按首个 `" / "` 拆为（分区标题, 字段标题）。
///
/// 与导入侧 `display_name` 组合互为逆运算：
///
/// - 含分隔符：`a / b / c` → `(a, "b / c")`，再组合仍为 `a / b / c`；
/// - 无分隔符：整名作字段标题、无分区标题 → 导入侧 `(None, Some(fn))`
///   组合回读整名（所有无分区字段汇聚进单个无标题分区，TC-EXP-14）。
fn split_field_name(name: &str) -> (Option<String>, Option<String>) {
    match name.split_once(" / ") {
        Some((st, ft)) => (Some(st.to_owned()), Some(ft.to_owned())),
        None => (None, Some(name.to_owned())),
    }
}

/// `TotpMeta` + 密钥 → `otpauth://totp/` URI。
///
/// 形状对齐 `cf_importer::csv::mapping::parse_otpauth` 的解析面：路径标签
/// `Issuer:account`（**逐成分** percent 编码、冒号为字面分隔符）、
/// `secret`（大写 Base32、省略填充）、`issuer` / `digits` / `period` /
/// `algorithm` 查询参数（`algorithm` 恒发射，裁决 D；导入侧未知参数忽略，
/// 回环时本仓降级 SHA-1）。
///
/// 回环无损性：parse_otpauth 先整体解码标签再按首个 `:` 切分，issuer
/// 由查询参数优先取值，故 issuer 含 `:` 也无损；account 含 `:` 时本
/// 格式固有歧义（格式限制，不在 TC-EXP 范围）。
fn totp_uri(meta: &TotpMeta, secret: &[u8]) -> String {
    let issuer = meta.issuer.clone().unwrap_or_default();
    let account = meta.account.clone().unwrap_or_default();
    let label = if issuer.is_empty() {
        percent_encode(&account)
    } else {
        format!("{}:{}", percent_encode(&issuer), percent_encode(&account))
    };
    let mut uri = format!(
        "otpauth://totp/{label}?secret={}",
        base32_encode_upper(secret),
    );
    if !issuer.is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&percent_encode(&issuer));
    }
    uri.push_str(&format!("&digits={}&period={}", meta.digits, meta.period));
    uri.push_str(&format!("&algorithm={}", meta.algo));
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
/// `cf_totp::base32_decode` 的往返一致性钉死（csv.rs 同型，docs/22 §2.1）。
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

/// Coffer 类别 → 1PUX `categoryUuid` 三位码（docs/03 §6.4.1 权威表）。
///
/// 复用 [`ItemCategory::opvault_code`]；未命中（Custom 等无 opvault 对应
/// 的类别）兜底 `003`（SecureNote）——与导入侧未知类别降级方向一致
/// （TC-EXP-08）。
#[must_use]
pub fn category_to_1p_code(category: ItemCategory) -> String {
    match category.opvault_code() {
        Some(code) => format!("{code:03}"),
        None => "003".to_owned(),
    }
}

// ------------------------------------------------------------ 落盘

/// 写标准 ZIP：`export.attributes` + `export.data` + `files/` 附件。
fn write_zip(
    tmp_path: &Path,
    items: &[Value],
    files: &[(String, Vec<u8>)],
) -> Result<(), CfError> {
    let f = fs::File::create(tmp_path)
        .map_err(|e| CfError::Io(format!("创建临时 1PUX 文件失败：{e}")))?;
    let mut zip = ZipWriter::new(f);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let attributes = json!({"version": 3, "createdAt": unix_now()?});
    zip.start_file("export.attributes", opts).map_err(zip_err)?;
    zip.write_all(attributes.to_string().as_bytes())
        .map_err(io_err)?;

    let data = json!({
        "accounts": [{
            "attrs": {"name": "Coffer", "type": "P"},
            "vaults": [{"attrs": {"name": "Vault", "type": "P"}, "items": items}]
        }]
    });
    zip.start_file("export.data", opts).map_err(zip_err)?;
    zip.write_all(data.to_string().as_bytes()).map_err(io_err)?;

    for (entry, content) in files {
        zip.start_file(entry, opts).map_err(zip_err)?;
        zip.write_all(content).map_err(io_err)?;
    }
    zip.finish().map_err(zip_err)?;
    Ok(())
}

/// 临时文件 → 目标路径（原子落定；失败由调用方清理临时文件）。
fn finalize_export(tmp_path: &Path, out_path: &Path) -> Result<(), CfError> {
    fs::rename(tmp_path, out_path)
        .map_err(|e| CfError::Io(format!("落定 1PUX 导出文件失败：{e}")))?;
    Ok(())
}

/// 导出路径的错误归一：文件系统层 [`CfError::Io`] 折叠为
/// [`CfError::ExportFailed`]（载荷细节保留；docs/09 §4 错误表）。
fn export_err(e: CfError) -> CfError {
    match e {
        CfError::Io(detail) => CfError::ExportFailed(detail),
        other => other,
    }
}

/// ZIP 元操作错误（start_file / finish）→ [`CfError::Io`]（外层折叠为
/// ExportFailed）。
fn zip_err(e: zip::result::ZipError) -> CfError {
    CfError::Io(format!("1PUX ZIP 写入失败：{e}"))
}

/// ZIP 数据写入错误（io 层）→ [`CfError::Io`]（外层折叠为 ExportFailed）。
fn io_err(e: std::io::Error) -> CfError {
    CfError::Io(format!("1PUX ZIP 数据写入失败：{e}"))
}

/// 同目录的唯一临时兄弟路径（备份包 `backup.rs` 同型实现）。
fn temp_sibling_path(out_path: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut name = out_path
        .file_name()
        .map_or_else(|| "export.1pux".to_owned(), |n| n.to_string_lossy().to_string());
    name.push_str(&format!(".tmp-{}-{seq}", std::process::id()));
    out_path.with_file_name(name)
}

/// 当前 Unix 秒；系统时钟早于 epoch 时返回错误（不猜测）。
fn unix_now() -> Result<i64, CfError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CfError::StorageError("system clock before unix epoch".into()))?
        .as_secs() as i64)
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

    /// 字段类型码：无承载码的类型必须返回 None（调用方降级 Text）。
    #[test]
    fn 字段类型码映射() {
        assert_eq!(field_type_to_1p_code(FieldType::Text), Some("T"));
        assert_eq!(field_type_to_1p_code(FieldType::Concealed), Some("P"));
        assert_eq!(field_type_to_1p_code(FieldType::Url), Some("U"));
        assert_eq!(field_type_to_1p_code(FieldType::Email), Some("E"));
        assert_eq!(field_type_to_1p_code(FieldType::Number), Some("N"));
        assert_eq!(field_type_to_1p_code(FieldType::Date), Some("D"));
        assert_eq!(field_type_to_1p_code(FieldType::MonthYear), Some("M"));
        assert_eq!(field_type_to_1p_code(FieldType::Bool), Some("B"));
        for t in [
            FieldType::Multiline,
            FieldType::Phone,
            FieldType::Totp,
            FieldType::Unsupported,
        ] {
            assert_eq!(field_type_to_1p_code(t), None, "{t:?} 无承载码");
        }
    }

    /// 字段名拆分与导入侧组合互为逆运算（回环无损）。
    #[test]
    fn 字段名拆合往返无损() {
        for name in ["a", "a / b", "a / b / c", " / b", "a / ", ""] {
            let (st, ft) = split_field_name(name);
            let rebuilt = match (st, ft) {
                (Some(st), Some(ft)) => format!("{st} / {ft}"),
                (Some(st), None) => st,
                (None, other) => other.unwrap_or_default(),
            };
            assert_eq!(rebuilt, name, "拆合必须还原：{name:?}");
        }
    }

    /// 分类反向映射：§6.4.1 权威表 + Custom 兜底 003。
    #[test]
    fn 分类码映射() {
        assert_eq!(category_to_1p_code(ItemCategory::Login), "001");
        assert_eq!(category_to_1p_code(ItemCategory::CreditCard), "002");
        assert_eq!(category_to_1p_code(ItemCategory::SecureNote), "003");
        assert_eq!(category_to_1p_code(ItemCategory::Identity), "004");
        assert_eq!(category_to_1p_code(ItemCategory::SoftwareLicense), "100");
        assert_eq!(category_to_1p_code(ItemCategory::EmailAccount), "111");
        assert_eq!(category_to_1p_code(ItemCategory::Custom), "003");
    }

    /// TOTP URI：标签 Issuer:account（percent 编码）+ algorithm 恒发射；
    /// 回环解析面形状与 `cf_importer::csv::mapping::parse_otpauth` 对齐。
    #[test]
    fn totp_uri形状() {
        // RFC 6238 20 字节测试密钥 → 已知 Base32 串
        let secret = b"12345678901234567890";
        let meta = TotpMeta {
            uuid: "t1".into(),
            item_uuid: "i1".into(),
            algo: "sha256".into(),
            digits: 8,
            period: 30,
            issuer: Some("Issuer".into()),
            account: Some("acct".into()),
            created_at: 0,
        };
        let uri = totp_uri(&meta, secret);
        assert_eq!(
            uri,
            "otpauth://totp/Issuer:acct?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Issuer&digits=8&period=30&algorithm=sha256"
        );
        let parsed = cf_importer::csv::mapping::parse_otpauth(&uri).expect("自产 URI 必须可回环解析");
        assert_eq!(parsed.secret, secret);
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period, 30);
        assert_eq!(parsed.issuer.as_deref(), Some("Issuer"));
        assert_eq!(parsed.account.as_deref(), Some("acct"));
    }

    /// 普通字段射入 sections 分组（跨分区保序）。
    #[test]
    fn 普通字段分组保序() {
        let mut grouped: Vec<(Option<String>, Vec<Value>)> = Vec::new();
        let mk = |name: &str, ft: FieldType, des: Option<Designation>| FieldDecrypted {
            uuid: "u".into(),
            item_uuid: "i".into(),
            section_uuid: None,
            field_type: ft,
            designation: des,
            name: cf_domain::secret::SecretString::from_exposed(name),
            value: Some(cf_domain::secret::SecretString::from_exposed("v")),
            position: 0,
        };
        let mut report = PuxExportReport::default();
        push_normal_field(
            &mut grouped,
            "i",
            &mk("A / x", FieldType::Text, Some(Designation::Other("phone".into()))),
            &mut report,
        );
        push_normal_field(
            &mut grouped,
            "i",
            &mk("A / y", FieldType::Multiline, None),
            &mut report,
        );
        push_normal_field(
            &mut grouped,
            "i",
            &mk("B", FieldType::Bool, Some(Designation::Email)),
            &mut report,
        );
        assert_eq!(grouped.len(), 2, "A 分区 + 无标题分区");
        assert_eq!(grouped[0].0.as_deref(), Some("A"));
        assert_eq!(grouped[0].1.len(), 2);
        assert_eq!(grouped[1].0.as_deref(), None, "无分隔符字段进无标题分区");
        assert_eq!(grouped[1].1[0]["title"], "B");
        // Multiline 无承载码 → 降级 Text + 报告
        assert_eq!(grouped[0].1[1]["fieldType"], "T");
        assert_eq!(report.degraded_fields.len(), 1);
        // Email designation 原样保留
        assert_eq!(grouped[1].1[0]["designation"], "email");
    }
}
