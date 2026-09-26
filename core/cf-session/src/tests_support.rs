//! 测试支持工具（仅 `#[cfg(test)]` 编译）：临时目录与测试常量。

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// 创建唯一临时目录（pid + 纳秒时间戳保证唯一，不引入 tempfile 依赖）。
pub(crate) fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cf-session-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
    dir
}
