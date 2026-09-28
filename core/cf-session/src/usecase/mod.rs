//! 用例编排层（docs/07 §2.2）。
//!
//! - [`items`]：条目 CRUD 编排（校验前置 → 单事务写库；update 替换前
//!   写历史快照，FR-2.9）
//! - [`search`]：条目搜索编排（方案 A：全量解密内存搜索；v0.2 扩展
//!   多字段 + 词级近似匹配，FR-11.2）
//! - [`history`]：条目历史版本编排（列表 / 回滚，FR-2.9）
//! - [`audit`]：Watchtower 安全体检编排（重复密码 / 弱密码 / 弱 URL，
//!   FR-6.2 / FR-6.3）
//! - [`health`]：五类体检报告编排（FR-6.7：6.2 重复 / 6.3 弱 URL /
//!   6.4 陈旧 / 6.5 泄露启发式 / 6.6 无 2FA，单次遍历解密取数）
//! - [`cross_copy`]：跨库复制条目编排（FR-2.10，v0.4.0：快照 → 校验 →
//!   目标库单事务写入 + 附件重密封，顺序化持锁防死锁）
//! - [`attachments`]：附件会话门面（FR-9.3 / FR-9.4，v0.4.0：列出 /
//!   添加 / 读取 / 删除，薄委托 [`cf_store::AttachmentRepo`]）

pub mod attachments;
pub mod audit;
pub mod cross_copy;
pub mod health;
pub mod history;
pub mod items;
pub mod search;
