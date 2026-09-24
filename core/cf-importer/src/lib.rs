//! # cf-importer —— 导入器
//!
//! 1PUX / CSV / opvault 三种格式的解析、字段映射与预检报告。
//!
//! ## 对应设计文档
//!
//! - `docs/03-详细设计.md` §6（导入器设计）
//! - `docs/03-详细设计.md` §6.4（分类码与字段映射表）
//! - `docs/01-需求分析.md` §5-G（FR-7 数据导入）
//!
//! ## 职责边界
//!
//! **不直接写库** —— 产出中间表示 `ImportModel`，由 `cf-session` 编排写入。
//!
//! 关键约束：
//! 1. 未知 `categoryUuid` 一律落入 `Custom` 并保留原始值，**不静默丢弃**；
//! 2. 解析器必须能抗畸形输入（模糊测试目标）；
//! 3. 1PUX 的 `categoryUuid` 映射表是**数据文件**而非硬编码，
//!    且必须先经真实样本校准（见 `docs/03-详细设计.md` §6.4.2）。
//!
//! 支持格式：
//! - 1PUX（JSON）—— M2 阶段
//! - CSV —— M2 阶段
//! - opvault —— 未定
//! - **KeePass KDBX**（`keepass` crate，冒烟已验证读取链路，见下方测试）
//!
//! ## 状态
//!
//! **未实现** —— 计划在 **M2** 阶段实现。
//! 参见 `README.md`「当前状态」与 `docs/04-系统设计.md` §10.1（阶段划分）。
//!
//! 本文件当前只声明模块意图，**不含任何可调用接口**（只有测试）。
//! 这样做是刻意的：宁可目录里是空的，也不要一个 `todo!()` 占位的假接口。
//!
//! 唯一例外：`#[cfg(test)]` 内已有 KeePass KDBX 解析**冒烟测试**，
//! 证明 `keepass` 依赖在 1.85 MSRV 下可编译、KDBX 保存→重开链路可用
//! （为 M2 的 KDBX 导入路径提前扫雷）。
//!
//! ## 硬性约束
//!
//! `#![forbid(unsafe_code)]`；生产代码禁 `unwrap` / `expect`
//! （测试代码经 `clippy.toml` 放行）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![warn(missing_docs)]

#[cfg(test)]
mod tests {
    /// KeePass KDBX 冒烟：构造最小内存数据库 → 保存 → 重新解析。
    ///
    /// 无真实样本时用 keepass crate 自身的 API 构造最小 KDBX 结构，
    /// 证明：
    /// 1. `keepass` 依赖在 workspace 的 MSRV（1.85）下可编译；
    /// 2. `Database::save`（KDBX4）→ `Database::open` 往返可用；
    /// 3. 条目字段（Title / UserName / Password）在往返后保持原值。
    #[test]
    fn keepass_minimal_db_roundtrip() {
        use keepass::db::{fields, GroupMut};
        use keepass::{Database, DatabaseKey};

        // ---- 构造：空库 + 一个分组 + 一个条目 ----
        let mut db = Database::new();
        let mut root = db.root_mut();

        let mut group: GroupMut<'_> = root.add_group();
        group.name = "Imported From KeePass".into();

        let mut entry = group.add_entry();
        entry.set_unprotected(fields::TITLE, "GitHub");
        entry.set_unprotected(fields::USERNAME, "octocat");
        entry.set_protected(fields::PASSWORD, "s3cret!");

        let key = DatabaseKey::new().with_password("coffer-test");

        // ---- 保存到内存缓冲 ----
        let mut buf = Vec::new();
        db.save(&mut buf, key.clone()).unwrap();
        assert!(buf.len() > 64, "KDBX 序列化输出不应为空");

        // ---- 重新解析 ----
        let mut source = &buf[..];
        let reopened = Database::open(&mut source, key).unwrap();

        let root_after = reopened.root();
        let group_after = root_after
            .group_by_name("Imported From KeePass")
            .expect("分组名应在往返后保留");
        let entry_after = group_after
            .entry_by_name("GitHub")
            .expect("条目 Title 应在往返后保留");

        assert_eq!(entry_after.get(fields::USERNAME), Some("octocat"));
        // 受保护字段（Password）同样应还原
        assert_eq!(entry_after.get(fields::PASSWORD), Some("s3cret!"));
    }
}
