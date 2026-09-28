//! 加密备份导出 / 结构校验 / 恢复（FR-8.1 / FR-8.6）。
//!
//! 备份格式 = docs/03-详细设计.md §1.4 的**交换形态**：标准 ZIP
//! （Deflate）单文件，扩展名 `.coffer`，内含工作目录的全部文件
//! （`header.json`、`db.sqlite`、`attachments/**`、`thumbnails/**`、
//! 可选 `MANIFEST.json`），路径相对库根。
//!
//! ## 安全性论证（docs/09 §3.1 D-1）
//!
//! 条目内容已由 `cf-store` 做字段级 AEAD 加密，ZIP 仅是容器：
//!
//! - **不使用** ZIP 自身加密（ZipCrypto 弱、AES-ZIP 兼容性差）；
//! - 打包全程**不接触任何密钥**——`header.json` 只含公开参数与密文，
//!   `db.sqlite` 敏感列全为密文 BLOB，「密钥不出会话」的约束被
//!   结构性满足；
//! - 打包前执行 `PRAGMA wal_checkpoint(TRUNCATE)` 合并 WAL 并排除
//!   `-wal` / `-shm` 文件。checkpoint 失败（如会话并发 busy）**不视为
//!   致命**（docs/09 §3.1 风险表）：WAL 未合并只意味着最新写入可能
//!   不在备份里，不产生损坏；
//! - 导出成功后给源库 `meta.last_backup_at` 打点（FR-8.5 备份提醒，
//!   docs/09 §2.2），失败不致命（见 [`stamp_last_backup`]）。
//!
//! ## 校验边界（如实声明，见 crate 级文档）
//!
//! [`verify_backup`] 是无密钥结构校验：ZIP 可解 → `header.json` 可解析
//! 且通过 [`cf_format::validate_header`] → `db.sqlite` 过
//! `cf_store::schema::verify` → 布局齐全。**跨库 db 替换不在其检出能力
//! 内**（无密钥侧不存在可绑定 db 与 header 的公开参数）；该伪造由
//! 解锁侧检出——字段 AAD 与 `SubKeys` 派生均钉死本库 `vault_uuid`，
//! 他库数据在本库密钥下解密必然失败。
//!
//! # 恢复语义
//!
//! [`restore_backup`] 解包到 `target_base_dir/<vault_uuid>/`；目标已存在
//! 同名库目录 → [`CfError::VaultExists`]。恢复后由调用方走常规
//! open_vault + unlock（主密码校验发生在解锁，FR-1.4）。

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cf_domain::CfError;
use cf_format::header::{validate_header, Header, FORMAT_VERSION};
use cf_store::repo::meta::MetaRepo;
use cf_store::{AuditEvent, AuditRepo, KEY_LAST_BACKUP_AT};
use zip::write::SimpleFileOptions;
use zip::ZipArchive;

/// 备份文件扩展名（docs/09 §3.1 D-1 落定，替换 docs/03 旧称 `.lvvault`）。
pub const BACKUP_EXTENSION: &str = "coffer";

/// 工作目录中的头部文件名（与 `cf-format` 一致）。
const HEADER_FILE: &str = "header.json";

/// 工作目录中的数据库文件名（与 `cf-format` 一致）。
const DB_FILE: &str = "db.sqlite";

/// 打包排除的 SQLite 伴生文件后缀（docs/03 §1.4）。
const EXCLUDED_SUFFIXES: [&str; 2] = ["-wal", "-shm"];

// ---------------------------------------------------------------- 导出

/// 导出结果（docs/09 §3.1 冻结契约）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupExportResult {
    /// 备份文件路径。
    pub file_path: PathBuf,
    /// 打包的文件数（不含目录条目）。
    pub file_count: usize,
    /// 备份文件字节数。
    pub size_bytes: u64,
    /// 导出后自动执行了一次结构校验（FR-8.6）且通过。
    pub verified: bool,
}

/// 导出加密备份：checkpoint WAL → 打包工作目录（排除 `-wal`/`-shm`）→
/// 结构校验。
///
/// 全程不接触密钥；调用方需自行完成 UI 二次确认（导出的是完整库，
/// 非明文但可被爆破——docs/09 §5 FFI 备注）。
///
/// # 错误
///
/// - `vault_dir` 不是合法工作目录（缺 `header.json` / `db.sqlite`）→
///   [`CfError::Validation`]；
/// - 打包 / 落盘过程中的文件系统失败 → [`CfError::ExportFailed`]（2003，
///   docs/09 §4 错误表：导出失败（IO/打包）统一 2003）；
/// - ZIP 打包或导出后自检失败 → [`CfError::ExportFailed`]。
pub fn export_backup(vault_dir: &Path, out_path: &Path) -> Result<BackupExportResult, CfError> {
    // 前置：确为工作形态库目录（存在性 + 完整性由 cf-format 判定）
    cf_format::verify_container_layout(vault_dir)
        .map_err(|e| CfError::Validation(format!("源目录不是合法库目录：{e}")))?;

    // WAL 合并：失败不致命（busy 等场景），仅可能缺失最新写入
    checkpoint_wal(&vault_dir.join(DB_FILE));

    // 收集打包文件（确定性顺序：按相对路径排序）
    let files = collect_vault_files(vault_dir).map_err(export_err)?;
    if !files
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n == HEADER_FILE))
    {
        return Err(CfError::Validation(format!(
            "源目录缺少 {HEADER_FILE}，不构成可备份的库"
        )));
    }

    // 父目录必须已存在（UI 侧已让用户选定目标位置）
    if out_path.parent().is_none_or(|p| !p.is_dir()) {
        return Err(CfError::ExportFailed(format!(
            "目标父目录不存在：{}",
            out_path
                .parent()
                .map_or_else(|| "(none)".to_owned(), |p| p.display().to_string())
        )));
    }

    // 临时文件 → fsync → rename：任何一步失败（含打包中途 IO 失败）都
    // 清理临时文件，目标路径不留半截文件（FR-8.6 / TC-EXP-10、11）
    let tmp_path = temp_sibling_path(out_path);
    let result = write_zip(vault_dir, &files, &tmp_path)
        .and_then(|()| finalize_and_verify(&tmp_path, out_path, files.len()));
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    } else {
        // 导出成功 → 给源库 meta.last_backup_at 打点（FR-8.5，docs/09 §2.2）。
        // 失败不致命（见 stamp_last_backup 文档），不影响导出结果。
        stamp_last_backup(vault_dir);
        // FR-12.6 本地审计：备份导出成功事件（同一静默纪律）。
        stamp_audit(vault_dir, AuditEvent::BackupExport, None);
    }
    result.map_err(export_err)
}

/// 导出路径的错误归一：文件系统层 [`CfError::Io`] 折叠为
/// [`CfError::ExportFailed`]（载荷细节保留；docs/09 §4 错误表）。
fn export_err(e: CfError) -> CfError {
    match e {
        CfError::Io(detail) => CfError::ExportFailed(detail),
        other => other,
    }
}

/// 导出成功后给源库 `meta.last_backup_at` 打点（FR-8.5，docs/09 §2.2）。
///
/// 打点放在**导出成功路径**（本函数）而非会话编排层：`export_backup` 是
/// CofferApp 级操作（锁定态可执行，TC-EXP-08），调用方（cf-ffi）不持有
/// 解锁态 `ItemStore`；而 meta 表是明文元数据，短连接即可写——与
/// [`checkpoint_wal`] 同一模式。任何失败静默忽略：打点缺失只导致备份
/// 提醒时间戳滞后，备份本身已成功，不得让打点失败反过来否定导出。
fn stamp_last_backup(vault_dir: &Path) {
    let Ok(conn) = rusqlite::Connection::open(vault_dir.join(DB_FILE)) else {
        return;
    };
    let _ = conn.busy_timeout(std::time::Duration::from_secs(2));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let _ = MetaRepo::new(&conn).set_i64(KEY_LAST_BACKUP_AT, now);
}

/// 成功动作的审计打点（FR-12.6 本地审计日志，docs/09 §2 Could）。
///
/// 与 [`stamp_last_backup`] 同一模式：meta/audit 均为明文表，短连接即写；
/// 任何失败静默忽略——审计记录缺失不否定已成功的动作本身。
fn stamp_audit(vault_dir: &Path, event: AuditEvent, detail: Option<&str>) {
    let Ok(conn) = rusqlite::Connection::open(vault_dir.join(DB_FILE)) else {
        return;
    };
    let _ = conn.busy_timeout(std::time::Duration::from_secs(2));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let _ = AuditRepo::new(&conn).append(now, event, detail);
}

/// checkpoint WAL（TRUNCATE）。任何失败静默忽略——见模块文档「不致命」。
fn checkpoint_wal(db_path: &Path) {
    let Ok(conn) = rusqlite::Connection::open(db_path) else {
        return;
    };
    let _ = conn.busy_timeout(std::time::Duration::from_secs(2));
    // 返回行 (busy, log, checkpointed)；busy=1 只表示有并发读阻塞，
    // 此处刻意忽略结果（WAL 文件本就不入包，合并只是尽力而为）。
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        let _busy: i64 = row.get(0)?;
        Ok(())
    });
}

/// 递归收集库目录内全部文件（相对路径、排序、排除 `-wal`/`-shm`）。
fn collect_vault_files(vault_dir: &Path) -> Result<Vec<PathBuf>, CfError> {
    let mut out = Vec::new();
    collect_recursive(vault_dir, vault_dir, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_recursive(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CfError> {
    let entries = fs::read_dir(dir).map_err(|e| CfError::Io(format!("读取目录失败：{e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| CfError::Io(format!("读取目录项失败：{e}")))?;
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(root, &path, out)?;
        } else if path.is_file() {
            let name = path
                .file_name()
                .map_or_else(std::ffi::OsString::new, |n| n.to_os_string());
            let name = name.to_string_lossy();
            if EXCLUDED_SUFFIXES.iter().any(|s| name.ends_with(s)) {
                continue;
            }
            out.push(
                path.strip_prefix(root)
                    .map_or_else(|_| path.clone(), Path::to_path_buf),
            );
        }
    }
    Ok(())
}

/// 把文件列表写入 ZIP（Deflate、UTF-8 文件名，docs/03 §1.4）。
fn write_zip(vault_dir: &Path, files: &[PathBuf], tmp_path: &Path) -> Result<(), CfError> {
    let file = File::create(tmp_path).map_err(|e| CfError::Io(format!("创建临时文件失败：{e}")))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for rel in files {
        let abs = vault_dir.join(rel);
        let bytes =
            fs::read(&abs).map_err(|e| CfError::Io(format!("读取 {} 失败：{e}", abs.display())))?;
        // ZIP 内路径统一用正斜杠（ZIP 规范），`Path` 在非 Windows 下本就是 `/`
        let zip_name = rel.to_string_lossy().replace('\\', "/");
        zip.start_file(zip_name.as_str(), options)
            .map_err(|e| CfError::ExportFailed(format!("写入 ZIP 条目失败：{e}")))?;
        zip.write_all(&bytes)
            .map_err(|e| CfError::ExportFailed(format!("写入 ZIP 内容失败：{e}")))?;
    }
    zip.finish()
        .map_err(|e| CfError::ExportFailed(format!("收尾 ZIP 失败：{e}")))?
        .sync_all()
        .map_err(|e| CfError::Io(format!("fsync 备份文件失败：{e}")))?;
    Ok(())
}

/// rename 临时文件到目标路径并执行导出后自检（FR-8.6）。
fn finalize_and_verify(
    tmp_path: &Path,
    out_path: &Path,
    file_count: usize,
) -> Result<BackupExportResult, CfError> {
    fs::rename(tmp_path, out_path).map_err(|e| CfError::Io(format!("落定备份文件失败：{e}")))?;
    // 自检失败 → 导出整体失败（不留坏包；错误语义原样透出）
    verify_backup(out_path)?;
    let size_bytes = fs::metadata(out_path)
        .map_err(|e| CfError::Io(format!("读取备份元数据失败：{e}")))?
        .len();
    Ok(BackupExportResult {
        file_path: out_path.to_path_buf(),
        file_count,
        size_bytes,
        verified: true,
    })
}

/// 同目录的唯一临时兄弟路径（`.coffer` → `.coffer.tmp-<pid>-<nanos>`）。
fn temp_sibling_path(out_path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = out_path.file_name().map_or_else(
        || "backup.coffer".to_owned(),
        |n| n.to_string_lossy().to_string(),
    );
    name.push_str(&format!(".tmp-{}-{nanos}", std::process::id()));
    out_path.with_file_name(name)
}

// ---------------------------------------------------------------- 校验

/// 校验报告（docs/09 §3.1 校验链全部通过时返回）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerifyReport {
    /// 包内 `header.json` 声明的库 UUID。
    pub vault_uuid: String,
    /// 包内声明的容器格式版本（恒为当前支持版本）。
    pub format_version: u16,
    /// 包内文件条目数（不含目录条目）。
    pub file_count: usize,
}

/// 结构校验（FR-8.6，无需密码）：ZIP 可解 → `header.json` 可解析且合法 →
/// `db.sqlite` 过 `cf_store::schema::verify`。
///
/// # 错误
///
/// - 不是 ZIP / 缺 `header.json` 或 `db.sqlite`（无法认定是 Coffer 备份）
///   → [`CfError::ImportUnknownFormat`]（2001，docs/09 §4 错误表）；
/// - `header.json` 存在但畸形 / 非法 → [`CfError::Corrupted`]；
/// - 格式版本不受当前支持 → [`CfError::UnsupportedFormat`]；
/// - `db.sqlite` schema 损坏 / 版本不符 → schema::verify 的错误原样透出。
pub fn verify_backup(backup_path: &Path) -> Result<BackupVerifyReport, CfError> {
    let mut archive = open_backup_archive(backup_path)?;
    // 先做「关键文件齐全」判断：缺 header.json / db.sqlite 的包无从认定
    // 是 Coffer 备份，报格式不识别（2001），而非更深的结构错误
    for required in [HEADER_FILE, DB_FILE] {
        if archive.by_name(required).is_err() {
            return Err(CfError::ImportUnknownFormat);
        }
    }
    let header = read_and_validate_header(&mut archive)?;
    verify_db_schema(&mut archive)?;

    let file_count = (0..archive.len())
        .filter(|i| archive.by_index(*i).map(|f| !f.is_dir()).unwrap_or(false))
        .count();

    Ok(BackupVerifyReport {
        vault_uuid: header.vault_uuid,
        format_version: header.format_version,
        file_count,
    })
}

/// 打开 .coffer 的 ZIP 归档。非 ZIP / 不可读 → [`CfError::ImportUnknownFormat`]。
fn open_backup_archive(
    backup_path: &Path,
) -> Result<ZipArchive<std::io::BufReader<File>>, CfError> {
    let file = File::open(backup_path).map_err(|e| CfError::Io(format!("打开备份失败：{e}")))?;
    ZipArchive::new(std::io::BufReader::new(file)).map_err(|_| CfError::ImportUnknownFormat)
}

/// 读出并校验包内 `header.json`。
fn read_and_validate_header(
    archive: &mut ZipArchive<std::io::BufReader<File>>,
) -> Result<Header, CfError> {
    let bytes = read_entry(archive, HEADER_FILE)?;
    let header: Header = serde_json::from_slice(&bytes)
        .map_err(|e| CfError::Corrupted(format!("{HEADER_FILE} 不是合法 header：{e}")))?;
    if header.format_version != FORMAT_VERSION {
        return Err(CfError::UnsupportedFormat(header.format_version));
    }
    validate_header(&header)
        .map_err(|e| CfError::Corrupted(format!("{HEADER_FILE} 校验失败：{e}")))?;
    Ok(header)
}

/// 读出包内单个条目的全部字节；不存在 → [`CfError::ImportUnknownFormat`]。
fn read_entry(
    archive: &mut ZipArchive<std::io::BufReader<File>>,
    name: &str,
) -> Result<Vec<u8>, CfError> {
    let mut entry = archive
        .by_name(name)
        .map_err(|_| CfError::ImportUnknownFormat)?;
    let mut buf = Vec::new();
    entry
        .read_to_end(&mut buf)
        .map_err(|e| CfError::Io(format!("读取包内 {name} 失败：{e}")))?;
    Ok(buf)
}

/// 校验包内 `db.sqlite` 的 schema 版本（落临时文件后只读打开）。
fn verify_db_schema(archive: &mut ZipArchive<std::io::BufReader<File>>) -> Result<(), CfError> {
    let bytes = read_entry(archive, DB_FILE)?;
    let dir = temp_dir_for_verify()?;
    let result = verify_db_schema_at(&dir, &bytes);
    let _ = fs::remove_dir_all(&dir);
    result
}

fn verify_db_schema_at(dir: &Path, db_bytes: &[u8]) -> Result<(), CfError> {
    let db_path = dir.join(DB_FILE);
    fs::write(&db_path, db_bytes).map_err(|e| CfError::Io(format!("写临时校验文件失败：{e}")))?;
    let conn =
        rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| CfError::Corrupted(format!("{DB_FILE} 不是可打开的 SQLite：{e}")))?;
    cf_store::schema::verify(&conn)
}

/// 校验用临时目录（进程级唯一；调用方负责清理）。
fn temp_dir_for_verify() -> Result<PathBuf, CfError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("coffer-verify-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| CfError::Io(format!("创建临时目录失败：{e}")))?;
    Ok(dir)
}

// ---------------------------------------------------------------- 恢复

/// 恢复（FR-8.1 回环）：解包到 `target_base_dir/<vault_uuid>/`。
///
/// 目标已存在同名库目录 → [`CfError::VaultExists`]（1004）。包内条目
/// 路径经 zip-slip 防护（`enclosed_name` 拒绝绝对路径与 `..` 穿越）。
/// 任一步失败 → 清理半截目录后返回错误（不留残留）。
///
/// 恢复后由调用方走常规 open_vault + unlock（主密码校验发生在解锁，
/// FR-1.4）。
///
/// # 错误
///
/// 同 [`verify_backup`] 的识别错误，外加目标已存在的
/// [`CfError::VaultExists`] 与条目路径非法的 [`CfError::Corrupted`]。
pub fn restore_backup(backup_path: &Path, target_base_dir: &Path) -> Result<PathBuf, CfError> {
    let mut archive = open_backup_archive(backup_path)?;
    let header = read_and_validate_header(&mut archive)?;

    let target = target_base_dir.join(&header.vault_uuid);
    if target.exists() {
        return Err(CfError::VaultExists);
    }
    fs::create_dir_all(&target).map_err(|e| CfError::Io(format!("创建恢复目录失败：{e}")))?;

    // 解包 + 落盘自检共享同一清理路径：任一步失败都删除半截目录
    // （调用方可见干净状态，可重试；FR-8.1 失败不留垃圾库目录）
    let outcome = extract_all(&mut archive, &target).and_then(|()| verify_extracted(&target));
    if let Err(e) = outcome {
        let _ = fs::remove_dir_all(&target);
        return Err(e);
    }
    // FR-12.6 本地审计：备份恢复成功事件（静默纪律同 stamp_last_backup——
    // 打点失败不得否定已成功的恢复）。
    stamp_audit(&target, AuditEvent::BackupRestore, None);
    Ok(target)
}

/// 对已落盘的恢复产物做无密钥自检：布局完整 + db schema 可打开。
fn verify_extracted(target: &Path) -> Result<(), CfError> {
    cf_format::verify_container_layout(target)
        .map_err(|e| CfError::Corrupted(format!("恢复产物布局不完整：{e}")))?;
    let conn = rusqlite::Connection::open_with_flags(
        target.join(DB_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| CfError::Corrupted(format!("{DB_FILE} 不是可打开的 SQLite：{e}")))?;
    cf_store::schema::verify(&conn)
}

/// 解包全部文件条目到 `target`（目录条目跳过，父目录按需创建）。
fn extract_all(
    archive: &mut ZipArchive<std::io::BufReader<File>>,
    target: &Path,
) -> Result<(), CfError> {
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| CfError::ExportFailed(format!("读取包内条目失败：{e}")))?;
        if entry.is_dir() {
            continue;
        }
        // zip-slip 防护：enclosed_name 拒绝绝对路径与 `..` 穿越
        let Some(rel) = entry.enclosed_name() else {
            return Err(CfError::Corrupted(format!(
                "包内条目路径非法：{}",
                entry.name()
            )));
        };
        let dest = target.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| CfError::Io(format!("创建恢复子目录失败：{e}")))?;
        }
        let mut out =
            File::create(&dest).map_err(|e| CfError::Io(format!("创建恢复文件失败：{e}")))?;
        std::io::copy(&mut entry, &mut out)
            .map_err(|e| CfError::Io(format!("写出恢复文件失败：{e}")))?;
        out.sync_all()
            .map_err(|e| CfError::Io(format!("fsync 恢复文件失败：{e}")))?;
    }
    Ok(())
}
