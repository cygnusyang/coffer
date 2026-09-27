//! # cf-exporter —— 导出器
//!
//! 加密备份包（`.coffer`）与明文 CSV 的导出、结构校验与恢复。
//!
//! ## 对应设计文档
//!
//! - `docs/01-需求分析.md` §5-H（FR-8 数据导出与备份）
//! - `docs/03-详细设计.md` §1.4（交换形态打包格式）
//! - `docs/09-v0.2实现方案.md` §3.1（冻结接口契约）
//!
//! ## 职责边界
//!
//! - [`backup`]：FR-8.1 / FR-8.6——工作目录打包为 `.coffer`（ZIP 交换
//!   形态）、结构校验、恢复。**全程不接触密钥**：字段级 AEAD 已由
//!   `cf-store` 在落盘时完成，ZIP 仅作容器，打包/校验/恢复只搬运字节。
//! - [`csv`]：FR-8.3——明文 CSV 导出，9 列映射与 `cf-importer` 的
//!   `HEADER_*` 常量严格对齐（跨 crate 引用防漂移），支持导入回环。
//! - 1PUX 导出（FR-8.2）顺延 v0.3（docs/09 §2.1）。
//!
//! ## 关键约束
//!
//! 1. 明文导出（CSV）必须由调用方先完成二次确认（FR-8.4）——本 crate
//!    不提供也不应绕过该 UI 门禁；
//! 2. 打包前执行 `PRAGMA wal_checkpoint(TRUNCATE)` 合并 WAL，打包排除
//!    `-wal` / `-shm` 文件（docs/03 §1.4）；
//! 3. CSV 公式注入防护在**导出侧**：以 `= + - @ \t` 开头的文本单元格
//!    加 `'` 前缀（docs/03 §6.4.4）；
//! 4. 错误零扩展：只使用 [`cf_domain::CfError`] 既有 20 变体（docs/09 §4）。
//!
//! ## 已知校验边界（如实声明）
//!
//! [`backup::verify_backup`] 是**无密钥**的结构校验，能检出：ZIP 损坏、
//! `header.json` 缺失/畸形/版本过新、`db.sqlite` 缺失或 schema 损坏。
//! 它**不能**检出「换入他库 db.sqlite」这类跨库字节替换——该伪造只在
//! 解锁时被检出（字段级 AEAD 的 AAD / 子密钥派生均钉死本库
//! `vault_uuid`，他库数据在本库密钥下解密必然失败）。无密钥侧不存在
//! 可绑定 db 与 header 的公开参数，此为格式既定边界而非实现缺失。
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`；生产代码禁 `unwrap` / `expect`
//! （测试代码经 `clippy.toml` 放行）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

pub mod backup;
pub mod csv;

pub use backup::{
    export_backup, restore_backup, verify_backup, BackupExportResult, BackupVerifyReport,
};
pub use csv::{export_csv, CsvExportResult};
