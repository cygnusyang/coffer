//! 用例编排层（docs/07 §2.2）。
//!
//! - [`items`]：条目 CRUD 编排（校验前置 → 单事务写库）
//! - [`search`]：标题搜索编排（方案 A：全量解密内存搜索）

pub mod items;
pub mod search;
