//! # cf-store —— 存储引擎 (SQLite + 字段级 AEAD)
//!
//! SQLite schema、加密字段读写、事务。
//!
//! ## 对应设计文档
//!
//! - `docs/03-详细设计.md` §3（存储层设计）
//! - `docs/03-详细设计.md` §2.5（字段级 AEAD 与 AAD 构造）
//! - `docs/07-macOS纵切设计.md` §2.1（T01：表与事务框架、仓库层、错误统一）
//!
//! ## 职责边界
//!
//! 负责「加密后的数据怎么落盘」，**不做字段级业务校验**（那是 `cf-domain`
//! 的职责）。所有加密操作委托 `cf-crypto::aead`。
//!
//! ## 模块划分（T01）
//!
//! - [`schema`]：docs/03 §3.1 全部 11 张表的幂等 DDL + PRAGMA + 版本记录
//! - [`tx`]：`with_tx` 事务框架（失败自动回滚，NFR-REL-01）
//! - [`repo`]：六个仓库（items / fields / urls / tags / meta / totp）
//!   与 [`Repos`] 聚合
//! - [`error`]：错误统一（C-6）——cf-store 不自持错误类型，全部用
//!   [`cf_domain::CfError`]
//! - [`ItemStore`]：仓库集合门面（持连接 + `SubKeys`），供 cf-session
//!   的解锁态持有（docs/07 §2.2 `UnlockedState.store`）
//!
//! ## 密文落盘纪律
//!
//! 敏感列（`enc_title` / `enc_name` / `enc_value` / `enc_url` /
//! `enc_label` / tags 的 `enc_name` / totp 的 `enc_secret` / `enc_issuer` /
//! `enc_account`）一律 AEAD 密文 BLOB 落盘，AAD 钉死在
//! （表名, 行 uuid, 列名）上防跨行跨列**跨表**搬运（表名命名空间，
//! O-1，2026-09-23）。集成测试断言**数据库文件字节里找不到明文敏感值**。
//!
//! ## 错误信息纪律（docs/04 §4.2）
//!
//! 错误信息不得泄露降低攻击成本的线索：解密失败统一
//! [`CfError::CryptoError`]（无载荷），SQLite 细节折叠进
//! [`CfError::StorageError`] 时不含敏感值。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod error;
pub mod repo;
pub mod schema;
pub mod tx;

use cf_crypto::subkeys::SubKeys;
use rusqlite::Connection;

pub use error::{CfStoreError, CfStoreResult};
pub use repo::item::{ItemListFilter, ItemRow, ItemWithTitle, ItemsRepo, COLUMN_ITEM_TITLE};
pub use repo::meta::{MetaRepo, KEY_ITEM_COUNT, KEY_SCHEMA_VERSION};
pub use repo::totp::{TotpMeta, TotpRepo, TotpStore, COLUMN_TOTP_ACCOUNT, COLUMN_TOTP_ISSUER, COLUMN_TOTP_SECRET};
pub use repo::Repos;

/// 仓库集合门面（docs/07 §2.2 中 `UnlockedState.store` 的落地形态）。
///
/// 持有连接与全部子密钥；读路径通过 [`ItemStore::repos`]（自动提交），
/// 写路径必须走 [`ItemStore::with_tx`]（失败自动回滚）。
pub struct ItemStore {
    conn: Connection,
    subkeys: SubKeys,
}

impl ItemStore {
    /// 打开存储并确保 schema 就绪（幂等建齐全部 11 张表）。
    pub fn open(conn: Connection, subkeys: SubKeys) -> CfStoreResult<Self> {
        let mut conn = conn;
        schema::init(&mut conn)?;
        Ok(Self { conn, subkeys })
    }

    /// 只读连接视图（供调用方做仓库层未覆盖的查询，如审计日志）。
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// 子密钥只读视图。
    #[must_use]
    pub fn subkeys(&self) -> &SubKeys {
        &self.subkeys
    }

    /// 在自有连接上构造仓库集合（自动提交模式，适合只读）。
    #[must_use]
    pub fn repos(&self) -> Repos<'_> {
        Repos::new(&self.conn, &self.subkeys)
    }

    /// 单事务内执行写入闭包；闭包返回 `Err` 时 ROLLBACK 并向上传播。
    ///
    /// 条目写入（create / update / delete）与 CSV 导入都必须走本方法
    /// （NFR-REL-01）。
    pub fn with_tx<T>(
        &mut self,
        f: impl FnOnce(&Repos<'_>) -> CfStoreResult<T>,
    ) -> CfStoreResult<T> {
        tx::with_tx(&mut self.conn, |tx| f(&Repos::new(tx, &self.subkeys)))
    }
}

/// 便捷重导出：仓库层的行结构（供上层 cf-session 编排使用）。
pub mod rows {
    pub use crate::repo::field::{FieldDecrypted, FieldRow, SectionDecrypted, SectionRow};
    pub use crate::repo::tag::{TagDecrypted, TagRow};
    pub use crate::repo::url::{UrlDecrypted, UrlRow};
}
