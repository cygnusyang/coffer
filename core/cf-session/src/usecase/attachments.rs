//! 附件会话门面（FR-9.3 / FR-9.4，docs/15 §3.1.2）。
//!
//! [`cf_store::AttachmentRepo`] 需要显式 `file_key` / `attach_mac_key` 与
//! `vault_dir`，这些只在解锁态 `UnlockedState` 内可得——门面落在
//! cf-session（镜像 [`super::items`] 与 `import_1pux` 的薄委托模式），
//! `repos()` 保持内部可达，不提升为 pub（最小暴露面，docs/15 §3.1.1）。
//!
//! ## 边界声明（docs/15 §3.1.2，冻结契约）
//!
//! - `add_attachment` 只校验条目存在（1011），**不限制条目状态**
//!   （Trashed / Archived 态在 UI 不可达，内核不强限——与
//!   `update_item` 的状态门禁不对称，属有意收窄的 v0.4 边界）；
//! - 同文件名不判重（1PUX 导入同语义）；
//! - 不做流式 / 分块传输（D-3：整块 `Vec<u8>` 是设计裁决）。
//!
//! ## 错误码（docs/15 §4，契约零扩展）
//!
//! 锁定态 1001（由 `VaultSession` 门禁承担）；条目不存在 1011；
//! 超过 [`cf_store::MAX_ATTACHMENT_BYTES`] / 附件行不存在 1012；
//! 行在文件无 / 密文损坏 1005；IO 5001——全部复用既有码。

use std::path::Path;

use cf_domain::CfError;
use cf_store::ItemStore;

use crate::SessionResult;

/// FFI 可见的附件元数据（docs/15 §3.1.2 冻结契约；镜像
/// [`cf_store::AttachmentMeta`]，时间戳恒 i64）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentInfo {
    /// 附件行 UUID（旁路文件名同名）。
    pub uuid: String,
    /// 所属条目 UUID。
    pub item_uuid: String,
    /// 文件名（解密后明文）。
    pub filename: String,
    /// 明文长度（字节）。
    pub size_bytes: i64,
    /// 创建时间（Unix 秒）。
    pub created_at: i64,
}

/// [`cf_store::AttachmentMeta`] → [`AttachmentInfo`]（字段一一镜像）。
fn to_info(meta: cf_store::AttachmentMeta) -> AttachmentInfo {
    AttachmentInfo {
        uuid: meta.uuid,
        item_uuid: meta.item_uuid,
        filename: meta.filename,
        size_bytes: meta.size_bytes,
        created_at: meta.created_at,
    }
}

/// 列出条目附件（created_at 升序，FR-9.3）。
///
/// 条目不存在 → [`CfError::ItemNotFound`]（1011）——内核
/// `list_for_item` 不查条目行，存在性门禁由会话层承担。
pub fn list_attachments(
    store: &ItemStore,
    item_id: &str,
) -> SessionResult<Vec<AttachmentInfo>> {
    let repos = store.repos();
    if repos.items.get_row(item_id)?.is_none() {
        return Err(CfError::ItemNotFound);
    }
    Ok(repos
        .attachments
        .list_for_item(item_id)?
        .into_iter()
        .map(to_info)
        .collect())
}

/// 添加附件（FR-9.1）：`filename` 为 UTF-8 明文，`content` 为明文内容。
///
/// 门面预检大小上限（超过 [`cf_store::MAX_ATTACHMENT_BYTES`] →
/// [`CfError::Validation`]，1012）——**先于任何 IO / 密码运算**快失败，
/// 内核 `add()` 有同判（双保险，docs/15 §3.1.2）。条目不存在 → 1011。
/// 事务内 INSERT 行（复用 `with_tx`），文件先行纪律（seal → tmp →
/// fsync → rename → INSERT）由 [`cf_store::AttachmentRepo::add`] 承担。
pub fn add_attachment(
    store: &mut ItemStore,
    vault_dir: &Path,
    item_id: &str,
    filename: &str,
    content: &[u8],
) -> SessionResult<AttachmentInfo> {
    if content.len() > cf_store::MAX_ATTACHMENT_BYTES {
        return Err(CfError::Validation(format!(
            "attachment exceeds limit: {} bytes",
            cf_store::MAX_ATTACHMENT_BYTES
        )));
    }
    {
        let repos = store.repos();
        if repos.items.get_row(item_id)?.is_none() {
            return Err(CfError::ItemNotFound);
        }
    }
    let meta = store.with_tx(|repos| {
        repos
            .attachments
            .add(item_id, filename.as_bytes(), content, vault_dir)
    })?;
    Ok(to_info(meta))
}

/// 读取附件明文内容（FR-9.2，一次一个、即用即弃；D-3 整块返回）。
///
/// 行不存在 → 1012（内核 `Validation`）；行在文件无 / 密文校验不过 →
/// 1005（内核 `Corrupted`）——错误码语义由内核映射，会话层直传。
pub fn read_attachment(
    store: &ItemStore,
    vault_dir: &Path,
    attachment_uuid: &str,
) -> SessionResult<Vec<u8>> {
    store
        .repos()
        .attachments
        .read_content(attachment_uuid, vault_dir)
}

/// 删除附件（FR-9.2）：内核 [`cf_store::AttachmentRepo::remove`] 的
/// 「先删行（事务）后删文件」纪律不变；旁路文件已不存在视为删除成功
/// （孤儿容忍的反向情形）。行不存在 → 1012。
pub fn remove_attachment(
    store: &mut ItemStore,
    vault_dir: &Path,
    attachment_uuid: &str,
) -> SessionResult<()> {
    store.with_tx(|repos| repos.attachments.remove(attachment_uuid, vault_dir))
}
