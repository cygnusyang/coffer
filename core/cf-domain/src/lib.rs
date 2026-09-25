//! # cf-domain —— 领域模型
//!
//! 条目 / 字段 / 保险库的领域模型，22 类条目模板与校验规则。
//!
//! ## 对应设计文档
//!
//! - `docs/03-详细设计.md` §4（领域模型）
//! - `docs/03-详细设计.md` §4.1（条目类型）
//! - `docs/03-详细设计.md` §4.2（字段类型与 designation）
//! - `docs/03-详细设计.md` §4.3（核心结构体）
//! - `docs/03-详细设计.md` §4.4 / §12（错误类型与错误码表）
//! - `docs/03-详细设计.md` §6.4.1（opvault 分类码映射）
//! - `docs/02-概要设计.md` §2.1（分层架构与单向依赖）
//!
//! ## 职责边界（硬约束）
//!
//! **纯逻辑，无 IO，无加密，无平台依赖。** 本 crate 不得依赖
//! `cf-store` / `cf-format` 等基础设施 crate，依赖方向必须单向：
//! 表示层 → 绑定层 → 应用服务层 → 领域层 → 基础设施层。
//!
//! 具体而言：
//! - 不读写文件、不连接数据库（那属于 `cf-store`）；
//! - 不做任何密码学计算（那属于 `cf-crypto` / `cf-totp`）；
//! - TOTP 只声明数据（[`totp_data::TotpData`]），算法委托在 `cf-session`；
//! - 不持有明文以外的状态 —— 明文敏感值一律用 [`secret::SecretString`]。
//!
//! ## 模块划分
//!
//! - [`category`]：条目类别枚举（22 类 + Custom 兜底）与 opvault 码映射
//! - [`field`]：字段类型与 designation 语义标识
//! - [`item`]：条目、字段、分区、URL、附件等核心结构体
//! - [`snapshot`]：条目历史版本快照（CBOR 序列化）
//! - [`vault`]：保险库元数据
//! - [`secret`]：内存安全字符串（析构清零、Debug 打码）
//! - [`totp_data`]：TOTP 领域数据（不依赖 cf-totp）
//! - [`template`]：22 类条目预设字段模板
//! - [`error`]：统一错误类型 [`CfError`]
//! - [`validate`]：条目校验规则
//!
//! ## 状态
//!
//! **已实现（M1 阶段）**。22 类条目模板按 `docs/01-需求分析.md` §5-B FR-2.1/2.2
//! 与 1Password 类别约定落地；字段映射表设计文档未给出（`03` §6.3 实际为
//! opvault 解析，非字段映射表），详见 [`template`] 模块说明。
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`；生产代码禁 `unwrap` / `expect`
//! （测试代码经 `clippy.toml` 放行）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod category;
pub mod error;
pub mod field;
pub mod item;
pub mod secret;
pub mod snapshot;
pub mod template;
pub mod totp_data;
pub mod validate;
pub mod vault;

pub use error::CfError;
pub use snapshot::{
    AttachmentMetaSnapshot, FieldSnapshot, ItemSnapshot, SectionSnapshot, UrlEntrySnapshot,
};

/// 条目 ID（UUIDv7，时间有序，利于索引）。
pub type ItemId = uuid::Uuid;
/// 字段 ID。
pub type FieldId = uuid::Uuid;
/// 分区 ID。
pub type SectionId = uuid::Uuid;
/// URL 条目 ID。
pub type UrlId = uuid::Uuid;
/// 附件 ID。
pub type AttachmentId = uuid::Uuid;
/// 保险库 ID（同时作为 KEK/DEK 的 AAD 成分，防跨库替换）。
pub type VaultId = uuid::Uuid;
