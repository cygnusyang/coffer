//! 仓库层（`docs/07-macOS纵切设计.md` §2.1）。
//!
//! 六个仓库文件 + [`Repos`] 聚合：
//!
//! | 文件 | 职责 |
//! | --- | --- |
//! | [`item`] | items 表 CRUD（insert / update / get / list / soft_delete / restore / set_favorite） |
//! | [`field`] | fields + sections 表：按 item 批量替换写入、按 item 读出 |
//! | [`url`] | urls 表：同批量替换模式 |
//! | [`tag`] | tags 表：同批量替换模式 |
//! | [`meta`] | meta 表键值读写（item_count、schema_version 等） |
//! | [`totp`] | TOTP 记录（原 `TotpStore` 迁入改造，`enc_issuer`/`enc_account` 加密列，C-2） |
//!
//! ## 加密密钥与 AAD 映射（全仓库层统一约定，O-1 后版本）
//!
//! AAD 统一带**表名命名空间**：`表名 ‖ 0x00 ‖ 行uuid(16) ‖ 0x00 ‖ 列名`
//! （构造见 [`field_aad`] → `cf_crypto::aead::build_table_field_aad`），
//! 密文被钉死在（表, 行, 列）三维位置上——跨表重放（即使 uuid 文本
//! 相同）也解密失败（O-1，2026-09-23，QA 对抗性验证发现）。
//!
//! | 列 | 子密钥 | 表名 | AAD record_uuid |
//! | --- | --- | --- | --- |
//! | `items.enc_title` | `item_key` | `items` | 条目 uuid |
//! | `sections.enc_title` | `item_key` | `sections` | 分区 uuid |
//! | `fields.enc_name` / `enc_value` | `field_key` | `fields` | 字段 uuid |
//! | `urls.enc_label` / `enc_url` | `field_key` | `urls` | url 行 uuid |
//! | `tags.enc_name` | `field_key` | `tags` | 标签行 uuid |
//! | `totp.enc_secret` | `field_key` | `totp` | **totp 行** uuid（O-1 统一：原钉条目 uuid，与 enc_issuer/enc_account 语义对齐） |
//! | `totp.enc_issuer` / `enc_account` | `field_key` | `totp` | totp 行 uuid |

pub mod field;
pub mod item;
pub mod meta;
pub mod tag;
pub mod totp;
pub mod url;

use cf_crypto::subkeys::SubKeys;
use rusqlite::Connection;

/// 仓库层聚合（docs/07 §2.2 中 `ItemStore` 持有的仓库集合）。
///
/// 事务内使用：[`crate::ItemStore::with_tx`] 在 `&Transaction` 上构造
/// 本聚合交给闭包；只读场景可用 [`crate::ItemStore::repos`] 直接借用连接。
pub struct Repos<'a> {
    /// items 表仓库。
    pub items: item::ItemsRepo<'a>,
    /// fields / sections 表仓库。
    pub fields: field::FieldsRepo<'a>,
    /// urls 表仓库。
    pub urls: url::UrlsRepo<'a>,
    /// tags 表仓库。
    pub tags: tag::TagsRepo<'a>,
    /// meta 表仓库。
    pub meta: meta::MetaRepo<'a>,
    /// totp 表仓库。
    pub totp: totp::TotpRepo<'a>,
}

impl<'a> Repos<'a> {
    /// 在给定连接与子密钥上构造仓库集合。
    pub fn new(conn: &'a Connection, subkeys: &'a SubKeys) -> Self {
        Self {
            items: item::ItemsRepo::new(conn, subkeys),
            fields: field::FieldsRepo::new(conn, subkeys),
            urls: url::UrlsRepo::new(conn, subkeys),
            tags: tag::TagsRepo::new(conn, subkeys),
            meta: meta::MetaRepo::new(conn),
            totp: totp::TotpRepo::new(conn, subkeys),
        }
    }
}

/// UUID（TEXT 形式）→ 16 字节（AAD 构造前置条件）。
pub(crate) fn uuid_bytes(uuid: &str) -> Result<[u8; 16], cf_domain::CfError> {
    let parsed = uuid::Uuid::parse_str(uuid)
        .map_err(|_| cf_domain::CfError::Corrupted("invalid uuid".into()))?;
    Ok(*parsed.as_bytes())
}

/// 构造字段级 AAD（全仓库层统一入口，O-1）。
///
/// 布局：`表名 ‖ 0x00 ‖ 行uuid(16) ‖ 0x00 ‖ 列名`。uuid 非法时返回
/// [`cf_domain::CfError::Corrupted`]。
pub(crate) fn field_aad(
    table: &str,
    record_uuid: &str,
    column: &str,
) -> Result<Vec<u8>, cf_domain::CfError> {
    let uuid_b = uuid_bytes(record_uuid)?;
    Ok(cf_crypto::aead::build_table_field_aad(table, &uuid_b, column))
}

/// 当前 Unix 秒。系统时钟早于 epoch 时返回错误（不猜测）。
pub(crate) fn unix_now() -> Result<i64, cf_domain::CfError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| cf_domain::CfError::StorageError("system clock before unix epoch".into()))?
        .as_secs() as i64)
}
