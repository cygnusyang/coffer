//! 测试支持工具（仅 `#[cfg(test)]` 编译）：临时目录。
//!
//! 性能预算校准已上移至公开的 [`crate::testing`]（集成测试
//! tests/*.rs 也需使用）。

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// 创建唯一临时目录（pid + 进程内原子计数器，不引入 tempfile 依赖）。
///
/// BUG-12 同型修复：原 pid+纳秒 在粗时钟下同 pid 同 tick 撞名；
/// 计数器按构造保证进程内唯一，跨进程由 pid 保证。
pub(crate) fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("cf-session-{tag}-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
    dir
}
