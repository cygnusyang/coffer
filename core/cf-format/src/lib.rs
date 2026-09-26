//! # cf-format —— 容器格式读写
//!
//! 负责库容器的结构层：头部读写、格式版本识别、格式迁移、完整性清单。
//!
//! ## 对应设计文档
//!
//! - `docs/03-详细设计.md` §1（容器格式规范）
//! - `docs/03-详细设计.md` §2（密钥派生——头部中的 KDF 参数部分）
//! - `docs/04-系统设计.md` §6（格式兼容与迁移策略）
//!
//! ## 职责边界
//!
//! 只处理容器结构：
//!
//! - **不管理条目内容**（那是 `cf-store` 的职责）；
//! - **不做字段级加密**（那是 `cf-crypto` 与 `cf-store` 的组合职责）——
//!   本 crate 只读写**已是密文**的 base64 BLOB；
//! - **不做历史快照的 CBOR 序列化**（归 `cf-store`）；
//! - **交换形态** `.lvvault`（ZIP 单文件）归 `cf-exporter`（M2），
//!   本 crate 只处理**工作形态的目录**。
//!
//! 关键约束：格式变更必须先写进 `docs/03-详细设计.md` §1，再改代码。
//! 只改代码不改文档，是这类项目最常见的隐患来源
//! （见 `docs/04-系统设计.md` §15.2）。
//!
//! ## 目录形态识别（无魔数）
//!
//! 识别一个目录是不是 Coffer 库，依据是 `header.json` **存在且可解析**、
//! 且 `format_version` **受支持**（见 [`container::open_container`]）。
//!
//! ## 状态
//!
//! **已实现**（M1-1，2026-09-24）：
//!
//! | 模块 | 内容 |
//! | --- | --- |
//! | [`header`] | `header.json` 结构定义与 [`header::validate_header`] 校验 |
//! | [`container`] | 版本三态打开、原子写 header、布局校验、迁移（迁移表为空） |
//! | [`manifest`] | `MANIFEST.json` 生成与校验（HMAC-SHA256） |
//!
//! 尚未实现：格式迁移（迁移表为空）、`.lvvault` 交换形态打包（M2）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

mod atomic;

pub mod container;
pub mod error;
pub mod header;
pub mod manifest;

#[cfg(test)]
mod testutil;

pub use container::{
    migrate, open_container, verify_container_layout, write_header, ContainerKind, OpenOutcome,
};
pub use error::CfFormatError;
pub use header::{
    validate_header, AeadSection, BiometricWrap, Header, HeaderFlags, KdfSection, VerifierSection,
    WrappedKey, FORMAT_VERSION,
};
pub use manifest::{verify_manifest, write_manifest, Manifest, ManifestEntry};
