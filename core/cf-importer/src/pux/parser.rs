//! 1PUX ZIP 容器解析（FR-7.1）。
//!
//! 1PUX = 标准 ZIP 容器：`export.attributes`（导出元信息）、
//! `export.data`（明文 JSON，1PUX 导出**未加密**，解析全程无密钥）、
//! `files/`（附件条目）。解析路径照抄 cf-exporter/src/backup.rs 的
//! 防御习惯：坏 ZIP → [`CfError::ImportUnknownFormat`]（明确报错不猜测，
//! `03` §6.1），缺必需成员 / 超上限 → [`CfError::ImportFailed`]。
//!
//! ## DoS 上限
//!
//! 参照 CSV 导入（docs/07 §3.1）的硬上限纪律：`export.data` 明文
//! [`MAX_EXPORT_DATA_BYTES`]（64 MiB）、条目总数 [`MAX_ITEMS`]（10 万）、
//! 单条目 JSON 的 `export.attributes` 64 KiB、单个附件内容
//! [`cf_store::MAX_ATTACHMENT_BYTES`]（100 MiB，与 cf-store 落库检查同一
//! 常量，防口径漂移）。
//!
//! 附件上限在导入侧**读入时**把守（防 zip bomb）：central directory
//! 声明的大小只是读前快筛，恶意归档可声明小尺寸、解压出远超声明的
//! 数据——实际读取一律经 [`read_bounded`] 以 `max + 1` 硬限宽（`.take`），
//! 超限即整体拒绝，不把超限数据交给上层。

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use cf_domain::CfError;
use cf_store::MAX_ATTACHMENT_BYTES;
use zip::ZipArchive;

use super::model::PuxModel;

/// `export.data` 解压后明文 JSON 的大小上限（64 MiB）。
pub const MAX_EXPORT_DATA_BYTES: usize = 64 * 1024 * 1024;

/// 条目总数上限（10 万；超出按 DoS 拒绝，docs/07 §3.1 同纪律）。
pub const MAX_ITEMS: usize = 100_000;

/// `export.attributes` 的大小上限（64 KiB，其内容只有几行元信息）。
const MAX_ATTRIBUTES_BYTES: usize = 64 * 1024;

/// 已打开的 1PUX ZIP 归档（持文件句柄；附件内容在落库时按需读取）。
pub struct PuxArchive {
    archive: ZipArchive<BufReader<File>>,
}

impl PuxArchive {
    /// 打开一个 1PUX 文件。
    ///
    /// # Errors
    ///
    /// 文件不可读 → [`CfError::Io`]；不是合法 ZIP →
    /// [`CfError::ImportUnknownFormat`]。
    pub fn open(path: &Path) -> Result<Self, CfError> {
        let file = File::open(path).map_err(|e| CfError::Io(format!("打开 1PUX 失败：{e}")))?;
        let archive =
            ZipArchive::new(BufReader::new(file)).map_err(|_| CfError::ImportUnknownFormat)?;
        Ok(Self { archive })
    }

    /// 读取并解析 ZIP 内必需成员，产出顶层模型。
    ///
    /// 校验顺序：`export.attributes`（必需、JSON、含数字 `version`）→
    /// `export.data`（必需、大小上限、JSON、含 `accounts`）→ 条目总数
    /// 上限。任一失败**整体拒绝**，不落库（FR-7.1 损坏输入语义）。
    ///
    /// # Errors
    ///
    /// 缺成员 / 键缺失 / JSON 非法 / 超上限 → [`CfError::ImportFailed`]；
    /// 读条目 IO 失败 → [`CfError::Io`]。
    pub fn parse(&mut self) -> Result<PuxModel, CfError> {
        let attrs = self.read_entry_bytes("export.attributes", MAX_ATTRIBUTES_BYTES)?;
        let attrs_json: serde_json::Value = serde_json::from_slice(&attrs)
            .map_err(|_| CfError::ImportFailed("export.attributes 不是合法 JSON".into()))?;
        if attrs_json.get("version").and_then(serde_json::Value::as_i64).is_none() {
            return Err(CfError::ImportFailed(
                "export.attributes 缺少数字 version 字段".into(),
            ));
        }

        let data = self.read_entry_bytes("export.data", MAX_EXPORT_DATA_BYTES)?;
        let model: PuxModel = serde_json::from_slice(&data).map_err(|e| {
            CfError::ImportFailed(format!("export.data 解析失败（缺 accounts/attrs 或键非法）：{e}"))
        })?;

        let item_total: usize = model
            .accounts
            .iter()
            .map(|a| a.vaults.iter().map(|v| v.items.len()).sum::<usize>())
            .sum();
        if item_total > MAX_ITEMS {
            return Err(CfError::ImportFailed(format!(
                "1PUX 条目总数 {item_total} 超过上限 {MAX_ITEMS}，拒绝导入"
            )));
        }
        Ok(model)
    }

    /// 读取单个附件条目的明文内容（落库时按需调用）。
    ///
    /// 防 zip bomb（dev-review HIGH-1）：先按 central directory 声明大小
    /// 快筛，再以 [`MAX_ATTACHMENT_BYTES`] 硬限宽读取（见模块文档）。
    ///
    /// # Errors
    ///
    /// 条目不存在 / 声明或实际大小超上限 → [`CfError::ImportFailed`]；
    /// 读失败 → [`CfError::Io`]。
    pub fn read_entry_content(&mut self, entry_name: &str) -> Result<Vec<u8>, CfError> {
        let f = self
            .archive
            .by_name(entry_name)
            .map_err(|_| CfError::ImportFailed(format!("ZIP 内缺少条目 {entry_name}")))?;
        if f.size() > MAX_ATTACHMENT_BYTES as u64 {
            return Err(CfError::ImportFailed(format!(
                "ZIP 条目 {entry_name} 声明大小 {} 超过附件上限 {MAX_ATTACHMENT_BYTES}",
                f.size()
            )));
        }
        read_bounded(f, &format!("条目 {entry_name}"), MAX_ATTACHMENT_BYTES)
    }

    /// 定位 [`crate::pux::model::PuxFileRef`] 对应的 ZIP 条目名。
    ///
    /// 两段式匹配（设计裁决：分隔符不硬编码）：
    /// 1. `zip_entry_hint` **精确**命中（形态 A：`files/doc1.pdf`）；
    /// 2. 否则若有 `document_id`，按 `files/<documentId>` 前缀**枚举**
    ///    命中——要求前缀后紧跟分隔符（`/` `\` `_` `-` 之一），避免
    ///    `doc1` 误命中 `doc10`（合成样本真实存在的边界）。
    ///
    /// 未命中返回 `None`（调用方将该条目列入预检「未导入清单」，
    /// FR-7.6 不静默丢弃）。
    #[must_use]
    pub fn resolve_file_entry(&mut self, file: &super::model::PuxFileRef) -> Option<String> {
        if !file.zip_entry_hint.is_empty()
            && self.archive.by_name(&file.zip_entry_hint).is_ok()
        {
            return Some(file.zip_entry_hint.clone());
        }
        let Some(doc_id) = &file.document_id else {
            return None;
        };
        let prefix = format!("files/{doc_id}");
        let names: Vec<String> = self.archive.file_names().map(str::to_owned).collect();
        for name in &names {
            let Some(rest) = name.strip_prefix(&prefix) else {
                continue;
            };
            if rest.starts_with(['/', '\\', '_', '-']) {
                return Some(name.clone());
            }
        }
        None
    }

    /// 读取 ZIP 内指定成员的原始字节（上限内）。
    fn read_entry_bytes(&mut self, name: &str, max: usize) -> Result<Vec<u8>, CfError> {
        let f = self
            .archive
            .by_name(name)
            .map_err(|_| CfError::ImportFailed(format!("1PUX ZIP 内缺少必需成员 {name}")))?;
        if f.size() > max as u64 {
            return Err(CfError::ImportFailed(format!(
                "ZIP 成员 {name} 大小 {} 超过上限 {max}",
                f.size()
            )));
        }
        read_bounded(f, &format!("成员 {name}"), max)
    }
}

/// 真正防线：以 `max + 1` 硬限宽（`.take`）读取已打开的 ZIP 条目，
/// 实际解压字节数超过 `max` → [`CfError::ImportFailed`]，不把超限数据
/// 交给上层。central directory 声明的大小不可信（各调用方已快筛）。
fn read_bounded(f: impl Read, label: &str, max: usize) -> Result<Vec<u8>, CfError> {
    let mut limited = f.take(max as u64 + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| CfError::Io(format!("读取 ZIP {label} 失败：{e}")))?;
    if buf.len() > max {
        return Err(CfError::ImportFailed(format!(
            "ZIP {label} 实际解压后大小超过上限 {max}（声明大小不可信），拒绝导入"
        )));
    }
    Ok(buf)
}
