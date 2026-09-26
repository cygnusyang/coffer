//! CSV 导入子模块（`docs/07-macOS纵切设计.md` §3）。
//!
//! - [`parser`]：自写 RFC 4180 解析器 + DoS 上限
//! - [`mapping`]：9 列映射（1Password CSV → [`ImportModel`]）与
//!   otpauth URI 解析

pub mod mapping;
pub mod parser;
