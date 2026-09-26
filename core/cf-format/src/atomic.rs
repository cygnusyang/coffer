//! 容器内文件的原子写入（临时文件 → fsync → rename）。
//!
//! 供 [`crate::container::write_header`] 与 [`crate::manifest::write_manifest`]
//! 共用。原子性是密码库这类强一致场景的硬要求：
//! 写入中途崩溃时，rename 保证读者只会看到**旧的完整文件**或**新的完整文件**，
//! 绝不会看到半截内容（见 `docs/04-系统设计.md` §6.2「原子性」）。

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::CfFormatError;

/// 原子写入：把 `bytes` 以 `file_name` 写入 `dir` 目录。
///
/// 步骤：写临时文件 `. <file_name>.tmp` → `fsync` 文件 → `rename` 覆盖目标。
///
/// # 失败处理
///
/// rename 失败时清理临时文件（避免残留，见 §6.2 的临时文件残留清理），
/// 原目标文件保持不变。
///
/// # 前置条件
///
/// `dir` 必须已存在（容器目录由上层创建）。
pub(crate) fn atomic_write_bytes(
    dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<(), CfFormatError> {
    let tmp_path = dir.join(format!(".{file_name}.tmp"));
    let dest = dir.join(file_name);

    // 1. 写入临时文件并 fsync，确保 rename 之前数据已真正落盘
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| CfFormatError::Io(format!("创建临时文件 {file_name}.tmp 失败：{e}")))?;
        file.write_all(bytes)
            .map_err(|e| CfFormatError::Io(format!("写入临时文件 {file_name}.tmp 失败：{e}")))?;
        file.sync_all()
            .map_err(|e| CfFormatError::Io(format!("fsync 临时文件 {file_name}.tmp 失败：{e}")))?;
    }

    // 2. rename 覆盖目标。失败则清理临时文件，保留原目标
    if let Err(e) = fs::rename(&tmp_path, &dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(CfFormatError::Io(format!(
            "原子替换 {} 失败：{e}",
            dest.display()
        )));
    }

    // 3. 尽力 fsync 目录，保证 rename 本身持久化。
    //    macOS 上对目录 fsync 可能返回 EINVAL，因此失败忽略（尽力而为）。
    if let Ok(dir_file) = fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}
