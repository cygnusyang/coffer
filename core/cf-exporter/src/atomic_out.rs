//! 原子落定 helper（BUG-22）。
//!
//! 加密备份（`backup.rs`）与 1PUX（`pux.rs`）导出共用：把内容写满临时文件后
//! 落定到用户所选目标。App Sandbox 只授予保存面板所选**文件本身**的写权限
//! （`com.apple.security.files.user-selected.read-write`），同目录创建兄弟临时
//! 文件无授权 → `File::create` 得 EPERM（os error 1）→ 导出失败（BUG-22，
//! docs/01 登记）。
//!
//! ## 双策略
//!
//! 1. **同目录兄弟临时 + rename**：非沙盒进程（CLI）行为不变，原子落定
//!    （FR-8.6 纪律：任何一步失败目标不留半截文件）；
//! 2. **回退容器落定**：`create`/`rename` 得权限类错误（EPERM=1 / EACCES=13）
//!    → 在 `std::env::temp_dir()` 下唯一容器目录写临时 → 写满 → 直写目标文件
//!    （`File::create(out_path)` + `io::copy` + `sync_all`，保存面板授权的目标
//!    文件本身；`fs::copy` 不保证 fsync，须显式 sync）→ 清理容器。
//!
//! 注意：策略 2 是沙盒/只读约束下的**非原子退化**——write_fn 失败不触碰目标
//! （目标只在复制阶段才被打开截断），但复制中途失败（如目标盘满）会留下半截
//! 目标并覆盖既有文件；沙盒只授予所选文件本身，无原子替换可解（BUG-22 登记
//! 的接受限制）。
//!
//! 其余错误（write_fn 失败 / 非权限 IO）原样上抛不吞；回退也失败时返回的错误
//! 同时携带两段上下文（策略 1 首错 + 回退次错）。
//!
//! CSV 导出（`csv.rs`）直写目标文件、不落兄弟临时，不受本模块影响。

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cf_domain::CfError;

/// 权限类错误码：EPERM(1)（App Sandbox 拒绝建兄弟临时文件）与 EACCES(13)
/// （只读目录）。此二者触发回退容器落定；其余错误原样上抛（BUG-22 处置）。
fn is_permission_error(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(1 | 13))
}

/// 同目录的唯一临时兄弟路径（`.coffer` → `.coffer.tmp-<pid>-<seq>`）。
///
/// BUG-12 同型修复：进程内原子计数器（进程内唯一由构造保证，跨进程由 pid
/// 保证）。`backup.rs` 与 `pux.rs` 的复制粘贴孪生实现收敛至此。
fn temp_sibling_path(out_path: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut name = out_path
        .file_name()
        .map_or_else(|| "export".to_owned(), |n| n.to_string_lossy().to_string());
    name.push_str(&format!(".tmp-{}-{seq}", std::process::id()));
    out_path.with_file_name(name)
}

/// 写内容到目标文件（BUG-22 共享落定 helper）。
///
/// 优先同目录兄弟临时 + rename；`create`/`rename` 得权限类错误 → 回退容器
/// 落定。其余错误原样上抛。回退也失败时，返回的错误同时携带两段上下文。
///
/// `write_fn` 接收已打开的临时文件并写入全部内容（负责 ZIP finish/fsync）。
pub(crate) fn write_via_temp<F>(out_path: &Path, write_fn: F) -> Result<(), CfError>
where
    F: FnOnce(File) -> Result<(), CfError>,
{
    let sibling = temp_sibling_path(out_path);

    // 策略 1：同目录兄弟临时 + rename（原子落定；CLI 非沙盒行为不变）
    let file = match File::create(&sibling) {
        Ok(f) => f,
        Err(e) if is_permission_error(&e) => {
            // 兄弟临时都建不了（沙盒/只读目录）→ 容器 tmp 重写
            return fallback_write(
                out_path,
                write_fn,
                CfError::Io(format!("创建临时文件失败：{e}")),
            );
        }
        Err(e) => return Err(CfError::Io(format!("创建临时文件失败：{e}"))),
    };
    if let Err(e) = write_fn(file) {
        let _ = fs::remove_file(&sibling);
        return Err(e);
    }
    if let Err(e) = fs::rename(&sibling, out_path) {
        if is_permission_error(&e) {
            // 兄弟临时已写满：直接复制其内容到目标，不再重跑 write_fn。
            // （rename 阶段的 EPERM/EACCES 在正常沙盒下不可达——沙盒在建兄弟
            // 临时时即拒绝；此分支只防御目录权限中途变化等边缘情形。）
            let first = CfError::Io(format!("落定文件失败：{e}"));
            let copied = copy_to_out(&sibling, out_path);
            let _ = fs::remove_file(&sibling);
            return match copied {
                Ok(()) => Ok(()),
                Err(second) => Err(combine_err(first, second)),
            };
        }
        let _ = fs::remove_file(&sibling);
        return Err(CfError::Io(format!("落定文件失败：{e}")));
    }
    Ok(())
}

/// 策略 2（回退）：`std::env::temp_dir()` 下唯一容器目录建临时 → `write_fn`
/// 写满 → [`copy_to_out`]（保存面板授权的目标文件本身）→ 清理容器。
///
/// 任一步失败：返回合并两段上下文的错误（`first` = 策略 1 首错，`second` =
/// 回退次错）；容器目录总是被清理。
fn fallback_write<F>(out_path: &Path, write_fn: F, first: CfError) -> Result<(), CfError>
where
    F: FnOnce(File) -> Result<(), CfError>,
{
    let container = match unique_temp_dir() {
        Ok(d) => d,
        Err(e) => return Err(combine_err(first, e)),
    };
    let container_tmp = container.join("export.tmp");
    let result = (|| {
        let file = File::create(&container_tmp)
            .map_err(|e| CfError::Io(format!("容器临时文件创建失败：{e}")))?;
        write_fn(file)?;
        copy_to_out(&container_tmp, out_path)
    })();
    let _ = fs::remove_dir_all(&container);
    match result {
        Ok(()) => Ok(()),
        Err(second) => Err(combine_err(first, second)),
    }
}

/// 把已写满的临时文件复制到目标文件：`File::create(out_path)`（保存面板授权
/// 的目标文件本身）+ `io::copy` + `sync_all`。`fs::copy` 不保证 fsync，须显式
/// sync_all（BUG-22 处置裁定）。
fn copy_to_out(src: &Path, out_path: &Path) -> Result<(), CfError> {
    let mut src_file =
        File::open(src).map_err(|e| CfError::Io(format!("打开临时文件失败：{e}")))?;
    let mut dst = File::create(out_path)
        .map_err(|e| CfError::Io(format!("创建目标文件失败：{e}")))?;
    io::copy(&mut src_file, &mut dst)
        .map_err(|e| CfError::Io(format!("复制到目标文件失败：{e}")))?;
    dst.sync_all()
        .map_err(|e| CfError::Io(format!("fsync 目标文件失败：{e}")))?;
    Ok(())
}

/// 把策略 1 首错与回退次错合并为单条可操作错误（两段上下文都要能看见）。
fn combine_err(first: CfError, second: CfError) -> CfError {
    let first = io_payload(&first);
    let second = io_payload(&second);
    CfError::Io(format!("同目录原子落定失败（{first}）；回退落定也失败：{second}"))
}

/// 取 CfError 的可读载荷：`Io` 取内层消息，其余变体用 Display（避免嵌套
/// `io error:` 前缀重复）。
fn io_payload(e: &CfError) -> String {
    match e {
        CfError::Io(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `std::env::temp_dir()` 下的唯一容器目录（进程内原子序号；跨进程由 pid
/// 保证唯一——并行测试互不干扰）。调用方负责清理。
fn unique_temp_dir() -> Result<PathBuf, CfError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("coffer-export-{}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| CfError::Io(format!("创建导出容器目录失败：{e}")))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 唯一测试目录（`std::env::temp_dir()` 下，并行互不干扰）。
    fn unique_test_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "coffer-export-test-{tag}-{}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 测试用 write_fn：写入一段已知字节。
    fn write_hello(file: File) -> Result<(), CfError> {
        let mut f = file;
        f.write_all(b"hello export")
            .map_err(|e| CfError::Io(format!("测试写失败：{e}")))
    }

    /// 断言无残留回退容器目录（轮询至多 2s——同进程并行测试可能同时持有
    /// 各自的容器，直接断言会竞态假红；容器在调用返回前必被清理，轮询只会
    /// 短暂等待）。
    fn assert_no_container_leftover() {
        let prefix = format!("coffer-export-{}-", std::process::id());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let leftover: Vec<_> = fs::read_dir(std::env::temp_dir())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .filter(|n| n.to_string_lossy().starts_with(&prefix))
                .collect();
            if leftover.is_empty() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "残留回退容器目录：{leftover:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// 断言目录下无残留兄弟临时（`.tmp-` 前缀）。
    fn assert_no_sibling_leftover(dir: &Path) {
        let leftover: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftover.is_empty(), "残留兄弟临时：{leftover:?}");
    }

    #[cfg(unix)]
    fn set_mode(dir: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// 策略 1 端到端：正常路径兄弟临时 + rename 成功，目标内容正确、兄弟临时
    /// 已消失。
    #[test]
    fn 正常路径_兄弟临时加rename成功() {
        let dir = unique_test_dir("ok");
        let out = dir.join("backup.coffer");
        write_via_temp(&out, write_hello).expect("正常路径必须成功");
        assert_eq!(fs::read(&out).unwrap(), b"hello export");
        assert_no_sibling_leftover(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// write_fn 失败 → 原样上抛（不吞、不回退），兄弟临时已清理。
    #[test]
    fn write_fn失败_原样上抛且兄弟清理() {
        let dir = unique_test_dir("fnfail");
        let out = dir.join("backup.coffer");
        let err = write_via_temp(&out, |_file| Err(CfError::Validation("夹具失败".into())))
            .expect_err("write_fn 失败必须上抛");
        assert!(
            err.to_string().contains("夹具失败"),
            "write_fn 错误须原样上抛：{err}"
        );
        assert_no_sibling_leftover(&dir);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// 回退触发：只读父目录（chmod 555）造 EACCES → 兄弟临时创建即失败；
    /// 回退里 `File::create(out)` 也失败 → 错误上抛且两段上下文可见。
    #[test]
    fn 只读父目录_触发回退且两段错误可见() {
        let dir = unique_test_dir("ro");
        set_mode(&dir, 0o555);
        let out = dir.join("backup.coffer");
        let err = write_via_temp(&out, write_hello).expect_err("只读目录必须失败");
        let msg = err.to_string();
        assert!(msg.contains("创建临时文件失败"), "缺少首错上下文：{msg}");
        assert!(msg.contains("创建目标文件失败"), "缺少次错上下文：{msg}");
        assert_no_container_leftover();
        set_mode(&dir, 0o755);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// 内部函数（回退）：`fallback_write` 直测——可写目标成功、内容正确。
    #[test]
    fn fallback_write_可写目标成功() {
        let dir = unique_test_dir("fb");
        let out = dir.join("backup.coffer");
        fallback_write(&out, write_hello, CfError::Io("夹具首错".into()))
            .expect("回退到可写目标必须成功");
        assert_eq!(fs::read(&out).unwrap(), b"hello export");
        assert_no_container_leftover();
        fs::remove_dir_all(&dir).unwrap();
    }

    /// 内部函数（回退）：`fallback_write` 直测——只读目标 → 合并两段错误。
    #[test]
    fn fallback_write_只读目标_合并两段错误() {
        let dir = unique_test_dir("fbro");
        set_mode(&dir, 0o555);
        let out = dir.join("backup.coffer");
        let err = fallback_write(&out, write_hello, CfError::Io("夹具首错".into()))
            .expect_err("只读目标必须失败");
        let msg = err.to_string();
        assert!(msg.contains("夹具首错"), "缺少首错上下文：{msg}");
        assert!(msg.contains("创建目标文件失败"), "缺少次错上下文：{msg}");
        assert_no_container_leftover();
        set_mode(&dir, 0o755);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// 内部函数（回退核心落盘步）：`copy_to_out` 复制内容并 fsync 落定。
    #[test]
    fn copy_to_out_复制内容并落定() {
        let dir = unique_test_dir("copy");
        let src = dir.join("tmp.src");
        let out = dir.join("final.out");
        fs::write(&src, b"payload bytes").unwrap();
        copy_to_out(&src, &out).expect("复制必须成功");
        assert_eq!(fs::read(&out).unwrap(), b"payload bytes");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// 兄弟路径：同目标两次不同名、同目录、命名前缀正确（BUG-12 纪律）。
    #[test]
    fn temp_sibling_path_唯一且同目录() {
        let dir = unique_test_dir("sibuniq");
        let out = dir.join("backup.coffer");
        let a = temp_sibling_path(&out);
        let b = temp_sibling_path(&out);
        assert_ne!(a, b, "同目标两次必须不同名");
        assert_eq!(a.parent(), Some(dir.as_path()));
        assert_eq!(b.parent(), Some(dir.as_path()));
        assert!(
            a.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("backup.coffer.tmp-")
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
