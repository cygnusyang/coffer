//! MANIFEST.json —— 目录内容清单与整体完整性校验。
//!
//! 对应 `docs/03-详细设计.md` §1.5（可选完整性清单）。
//!
//! # 用途与威胁模型
//!
//! 检测文件被**替换或删除**。`manifest_mac` 用 `HMAC-SHA256` 与从 DEK 派生的
//! `manifest_key` 计算，攻击者**无法伪造清单**（他不知道密钥），但可以整体
//! 回滚到旧版本（见 `02-概要设计.md` §8.2 的诚实声明）。
//!
//! 每个文件的 `content_mac` 用 `attach_mac_key`（子密钥之一，见
//! `docs/03-详细设计.md` §2.4）计算，因此**不泄露**「两个附件是否相同」
//! （`docs/03-详细设计.md` 修正 B）。
//!
//! # 本模块的职责边界
//!
//! - 只做「生成清单 / 校验清单」的结构层工作，**不解密**文件内容
//!   （内容已是密文 BLOB，见 §1.2 安全说明）。
//! - `manifest_key` / `attach_mac_key` 由调用方从 DEK 派生后以
//!   [`SessionKey`] 传入，本模块只借用、不持有密钥材料。

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use cf_crypto::aead::SessionKey;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atomic::atomic_write_bytes;
use crate::container::{open_container, OpenOutcome};
use crate::error::CfFormatError;

/// MANIFEST 文件名。
const MANIFEST_FILE: &str = "MANIFEST.json";

/// 不纳入清单的文件名（清单自身、自证源、运行时产物）。
///
/// 说明：
/// - `header.json` 是清单的**来源**（vault_uuid 取自它），且每次解锁 /
///   改密码都会变，纳入清单会互相失效，故排除；
/// - `db.sqlite-wal` / `db.sqlite-shm` 是运行时产物（§1.4 打包时也会排除）。
const EXCLUDED_FILE_NAMES: &[&str] = &[
    MANIFEST_FILE,
    "header.json",
    "db.sqlite-wal",
    "db.sqlite-shm",
];

/// HMAC-SHA256 的类型别名。
type HmacSha256 = Hmac<Sha256>;

/// MANIFEST.json 的顶层结构（形状对照 `docs/03-详细设计.md` §1.5）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// 库 UUID，必须与 `header.json` 的 `vault_uuid` 一致。
    pub vault_uuid: String,
    /// 清单生成时间（Unix 秒 UTC）。
    pub generated_at: i64,
    /// 文件条目数，必须等于 `files` 的长度。
    pub file_count: usize,
    /// 逐文件条目。
    pub files: Vec<ManifestEntry>,
    /// `base64(HMAC-SHA256(manifest_key, 上述各字段规范化序列化))`。
    pub manifest_mac: String,
}

/// 清单中的单个文件条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// 相对库根的路径（`/` 分隔，与 ZIP 打包路径一致）。
    pub path: String,
    /// 文件字节长度。
    pub size: u64,
    /// `base64(HMAC-SHA256(attach_mac_key, 文件内容))`。
    pub content_mac: String,
}

/// 生成并原子写入 `MANIFEST.json`。
///
/// # 流程
///
/// 1. 从 `header.json` 读取 `vault_uuid`（清单与库绑定，防跨库搬运）；
/// 2. 递归枚举库内文件，逐个计算 `content_mac`（读内容做 HMAC）；
/// 3. 对「除 `manifest_mac` 外的全部字段」做规范化序列化并计算
///    `manifest_mac`；
/// 4. 原子写入（见 [`crate::atomic::atomic_write_bytes`]）。
///
/// # 排除项
///
/// 见 [`EXCLUDED_FILE_NAMES`]；此外所有点开头的临时文件（如
/// `.MANIFEST.json.tmp`）也不纳入。
pub fn write_manifest(
    vault_dir: &Path,
    manifest_key: &SessionKey,
    attach_mac_key: &SessionKey,
) -> Result<(), CfFormatError> {
    // 1. vault_uuid 取自当前版本 header（旧库 / 新库都不生成清单）
    let vault_uuid = read_current_vault_uuid(vault_dir)?;

    // 2. 枚举文件并计算 content_mac
    let files = build_entries(vault_dir, attach_mac_key)?;
    let generated_at = unix_now();

    // 3. 计算 manifest_mac（规范化序列化除它之外的字段）
    let manifest_mac = compute_manifest_mac(manifest_key, &vault_uuid, generated_at, &files)?;

    let manifest = Manifest {
        vault_uuid,
        generated_at,
        file_count: files.len(),
        files,
        manifest_mac,
    };
    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| CfFormatError::InvalidHeader(format!("MANIFEST 序列化失败：{e}")))?;
    atomic_write_bytes(vault_dir, MANIFEST_FILE, &json)
}

/// 校验 `MANIFEST.json` 与库内容是否一致。
///
/// # 检查项（按顺序）
///
/// 1. `file_count` 与 `files` 条数一致；
/// 2. `manifest_mac` 匹配（用 `manifest_key` 重算，常量时间比较）——
///    检测清单本身被篡改 / 错钥；
/// 3. 逐个文件：存在性、大小、`content_mac`（用 `attach_mac_key` 重算）——
///    检测文件被删除 / 替换 / 错钥。
///
/// 任一不符返回 [`CfFormatError::ManifestMismatch`]。
pub fn verify_manifest(
    vault_dir: &Path,
    manifest_key: &SessionKey,
    attach_mac_key: &SessionKey,
) -> Result<(), CfFormatError> {
    let path = vault_dir.join(MANIFEST_FILE);
    let text = fs::read_to_string(&path)
        .map_err(|e| CfFormatError::Io(format!("读取 {} 失败：{e}", path.display())))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .map_err(|e| CfFormatError::ManifestMismatch(format!("MANIFEST 解析失败：{e}")))?;

    // 1. file_count 一致性
    if manifest.file_count != manifest.files.len() {
        return Err(CfFormatError::ManifestMismatch(format!(
            "file_count {} ≠ files 实际条数 {}",
            manifest.file_count,
            manifest.files.len()
        )));
    }

    // 2. manifest_mac（常量时间比较，见 verify_hmac）
    let expected_body =
        serialize_manifest_body(&manifest.vault_uuid, manifest.generated_at, &manifest.files)?;
    let stored = decode_b64_32(&manifest.manifest_mac)?;
    verify_hmac(manifest_key.as_bytes(), &expected_body, &stored)?;

    // 3. 逐文件校验
    for entry in &manifest.files {
        let full = vault_dir.join(&entry.path);
        if !full.is_file() {
            return Err(CfFormatError::ManifestMismatch(format!(
                "清单文件缺失：{}",
                entry.path
            )));
        }
        let meta = fs::metadata(&full)
            .map_err(|e| CfFormatError::Io(format!("读取 {} 元数据失败：{e}", full.display())))?;
        if meta.len() != entry.size {
            return Err(CfFormatError::ManifestMismatch(format!(
                "文件大小不符：{} 清单={} 实际={}",
                entry.path,
                entry.size,
                meta.len()
            )));
        }
        let content = fs::read(&full)
            .map_err(|e| CfFormatError::Io(format!("读取 {} 失败：{e}", full.display())))?;
        let expected = decode_b64_32(&entry.content_mac)?;
        verify_hmac(attach_mac_key.as_bytes(), &content, &expected)?;
    }
    Ok(())
}

// ---------------------------------------------------------------- 内部实现

/// 从当前版本库的 `header.json` 读取 `vault_uuid`。
fn read_current_vault_uuid(vault_dir: &Path) -> Result<String, CfFormatError> {
    match open_container(vault_dir)? {
        OpenOutcome::Current(h) => Ok(h.vault_uuid),
        OpenOutcome::NeedsMigration { from, .. } => Err(CfFormatError::InvalidHeader(format!(
            "MANIFEST 只能在当前版本库上生成：库版本 {from} 需迁移"
        ))),
        OpenOutcome::TooNew(v) => Err(CfFormatError::UnsupportedVersion(v)),
    }
}

/// 递归枚举库内应纳入清单的文件，返回相对路径列表（未排序）。
fn collect_vault_files(vault_dir: &Path) -> Result<Vec<PathBuf>, CfFormatError> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) -> Result<(), CfFormatError> {
        let entries = fs::read_dir(dir)
            .map_err(|e| CfFormatError::Io(format!("读取目录 {} 失败：{e}", dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| CfFormatError::Io(format!("读取目录项失败：{e}")))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // 排除清单自身 / 自证源 / 运行时产物 / 点开头的临时文件
            if EXCLUDED_FILE_NAMES.contains(&name_str.as_ref()) || name_str.starts_with('.') {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out)?;
            } else if path.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .map_err(|_| CfFormatError::Io("目录遍历越界（内部错误）".to_string()))?;
                out.push(rel.to_path_buf());
            }
        }
        Ok(())
    }

    let mut out = Vec::new();
    walk(vault_dir, vault_dir, &mut out)?;
    Ok(out)
}

/// 为库内每个文件构造清单条目：相对路径、字节数、content_mac。
fn build_entries(
    vault_dir: &Path,
    attach_mac_key: &SessionKey,
) -> Result<Vec<ManifestEntry>, CfFormatError> {
    let mut rel_paths = collect_vault_files(vault_dir)?;
    // 排序保证输出确定性（同一目录内容 → 同一 MANIFEST 字节序列）
    rel_paths.sort();

    let mut entries = Vec::with_capacity(rel_paths.len());
    for rel in rel_paths {
        let full = vault_dir.join(&rel);
        // 用 Zeroizing 持有读取的内容：附件内容虽为密文，仍按密钥材料
        // 同级别的内存卫生处理（防明文/半明文残留在堆上）
        let content = Zeroizing::new(
            fs::read(&full)
                .map_err(|e| CfFormatError::Io(format!("读取 {} 失败：{e}", full.display())))?,
        );
        let mac = compute_hmac(attach_mac_key.as_bytes(), &content)?;
        let path = rel.to_string_lossy().replace('\\', "/");
        entries.push(ManifestEntry {
            path,
            size: content.len() as u64,
            content_mac: base64::engine::general_purpose::STANDARD.encode(mac),
        });
    }
    Ok(entries)
}

/// 计算 `manifest_mac`：对除 `manifest_mac` 外的全部字段做规范化序列化后 HMAC。
fn compute_manifest_mac(
    manifest_key: &SessionKey,
    vault_uuid: &str,
    generated_at: i64,
    files: &[ManifestEntry],
) -> Result<String, CfFormatError> {
    let body = serialize_manifest_body(vault_uuid, generated_at, files)?;
    let mac = compute_hmac(manifest_key.as_bytes(), &body)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(mac))
}

/// `ManifestBody`：除 `manifest_mac` 外的字段，用于规范化序列化。
///
/// 字段顺序与 [`Manifest`] 中对应字段一致，保证「生成」与「校验」两次
/// 序列化得到**逐字节相同**的输入。
#[derive(Serialize)]
struct ManifestBody<'a> {
    vault_uuid: &'a str,
    generated_at: i64,
    file_count: usize,
    files: &'a [ManifestEntry],
}

/// 序列化 `manifest_mac` 的计算输入（确定性，见 [`ManifestBody`]）。
fn serialize_manifest_body(
    vault_uuid: &str,
    generated_at: i64,
    files: &[ManifestEntry],
) -> Result<Zeroizing<Vec<u8>>, CfFormatError> {
    let body = ManifestBody {
        vault_uuid,
        generated_at,
        file_count: files.len(),
        files,
    };
    serde_json::to_vec(&body)
        .map(Zeroizing::new)
        .map_err(|e| CfFormatError::InvalidHeader(format!("MANIFEST body 序列化失败：{e}")))
}

/// 计算 `HMAC-SHA256(key, data)`，返回 32 字节。
fn compute_hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], CfFormatError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| CfFormatError::InvalidHeader(format!("HMAC 密钥长度非法：{e}")))?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 常量时间校验 `HMAC-SHA256(key, data) == expected`。
///
/// 用 [`Mac::verify_slice`] 的常量时间比较，避免时序侧信道泄露 MAC 差异。
fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8; 32]) -> Result<(), CfFormatError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| CfFormatError::InvalidHeader(format!("HMAC 密钥长度非法：{e}")))?;
    mac.update(data);
    mac.verify_slice(expected)
        .map_err(|_| CfFormatError::ManifestMismatch("HMAC 校验失败".to_string()))
}

/// 解码 base64 并断言恰好 32 字节（HMAC-SHA256 输出长度）。
fn decode_b64_32(s: &str) -> Result<[u8; 32], CfFormatError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| CfFormatError::ManifestMismatch(format!("base64 解码失败：{e}")))?;
    raw.try_into()
        .map_err(|_| CfFormatError::ManifestMismatch("HMAC 长度必须为 32 字节".to_string()))
}

/// 当前 Unix 时间（秒）。系统时钟异常（早于 1970）时返回 0 并明确记录。
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::write_header;
    use crate::testutil::{other_key, sample_header, temp_vault_dir, test_key};

    use std::fs;
    use std::path::PathBuf;

    /// 搭一个合法的库目录：header.json + db.sqlite + 一个附件。
    fn seed_vault(name: &str) -> PathBuf {
        let dir = temp_vault_dir(name);
        let h = sample_header();
        write_header(&dir, &h).expect("写入 header 成功");
        fs::write(dir.join("db.sqlite"), b"sqlite-data-bytes").expect("写入 db 成功");
        fs::create_dir_all(dir.join("attachments")).expect("创建附件目录成功");
        fs::write(
            dir.join("attachments").join("0193.bin"),
            b"attachment-content",
        )
        .expect("写入附件成功");
        dir
    }

    /// MANIFEST 写 → 验往返，使用同一对密钥必须通过。
    #[test]
    fn write_then_verify_roundtrip() {
        let dir = seed_vault("roundtrip");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");
        verify_manifest(&dir, &test_key(), &test_key()).expect("校验应通过");

        // 清单应包含 db.sqlite 与 attachments/0193.bin 两个条目
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(dir.join("MANIFEST.json")).expect("读取成功"))
                .expect("解析成功");
        assert_eq!(manifest.file_count, 2);
        assert_eq!(manifest.files.len(), 2);
        let paths: Vec<&str> = manifest.files.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"db.sqlite"));
        assert!(paths.contains(&"attachments/0193.bin"));
    }

    /// 篡改 manifest_mac → 校验失败（检测清单自身被篡改）。
    #[test]
    fn tampered_manifest_mac_fails() {
        let dir = seed_vault("tamper_mac");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");

        let path = dir.join("MANIFEST.json");
        let mut manifest: Manifest =
            serde_json::from_slice(&fs::read(&path).expect("读取成功")).expect("解析成功");
        // 翻转 manifest_mac 首字符
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&manifest.manifest_mac)
            .expect("解码成功");
        bytes[0] ^= 0x01;
        manifest.manifest_mac = base64::engine::general_purpose::STANDARD.encode(bytes);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&manifest).expect("序列化成功"),
        )
        .expect("写入成功");

        assert!(matches!(
            verify_manifest(&dir, &test_key(), &test_key()),
            Err(CfFormatError::ManifestMismatch(_))
        ));
    }

    /// 篡改单个条目的 `content_mac`（并重算 `manifest_mac` 让第 2 步通过）
    /// → 第 3 步逐文件 MAC 校验失败。
    ///
    /// 这验证 `content_mac` 独立于 `manifest_mac` 起到防替换作用：
    /// 即使攻击者能重算整体清单 MAC（模拟拥有 manifest_key 的内部人），
    /// 篡改过的 content_mac 也会在逐文件校验时暴露。
    #[test]
    fn tampered_content_mac_fails() {
        let dir = seed_vault("tamper_content");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");

        let path = dir.join("MANIFEST.json");
        let mut manifest: Manifest =
            serde_json::from_slice(&fs::read(&path).expect("读取成功")).expect("解析成功");
        // 篡改第一条目的 content_mac
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&manifest.files[0].content_mac)
            .expect("解码成功");
        bytes[0] ^= 0x01;
        manifest.files[0].content_mac = base64::engine::general_purpose::STANDARD.encode(bytes);
        // 重算 manifest_mac（模拟内部人）：第 2 步会通过，失败点应在第 3 步
        manifest.manifest_mac = compute_manifest_mac(
            &test_key(),
            &manifest.vault_uuid,
            manifest.generated_at,
            &manifest.files,
        )
        .expect("重算成功");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&manifest).expect("序列化成功"),
        )
        .expect("写入成功");

        assert!(matches!(
            verify_manifest(&dir, &test_key(), &test_key()),
            Err(CfFormatError::ManifestMismatch(_))
        ));
    }

    /// 替换库内文件内容（大小不变）→ content_mac 不符 → 校验失败。
    ///
    /// 这里**不**改 MANIFEST.json，所以 manifest_mac 仍通过；
    /// 失败点正是「文件内容被替换」的检测（第 3 步）。
    #[test]
    fn replaced_file_content_fails() {
        let dir = seed_vault("replaced");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");

        // 覆盖 db.sqlite：保持字节数相同，但内容不同
        let db_path = dir.join("db.sqlite");
        let mut bytes = fs::read(&db_path).expect("读取成功");
        for b in bytes.iter_mut() {
            *b ^= 0xFF;
        }
        fs::write(&db_path, &bytes).expect("覆盖成功");

        assert!(matches!(
            verify_manifest(&dir, &test_key(), &test_key()),
            Err(CfFormatError::ManifestMismatch(_))
        ));
    }

    /// 删除清单中的文件 → 存在性校验失败。
    #[test]
    fn deleted_file_fails() {
        let dir = seed_vault("deleted");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");

        fs::remove_file(dir.join("attachments").join("0193.bin")).expect("删除成功");

        assert!(matches!(
            verify_manifest(&dir, &test_key(), &test_key()),
            Err(CfFormatError::ManifestMismatch(_))
        ));
    }

    /// 文件大小改变（截断）→ 大小校验失败。
    #[test]
    fn wrong_file_size_fails() {
        let dir = seed_vault("size");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");

        // 截断 db.sqlite，让实际大小与清单不符
        let db_path = dir.join("db.sqlite");
        let content = fs::read(&db_path).expect("读取成功");
        fs::write(&db_path, &content[..content.len() / 2]).expect("截断成功");

        assert!(matches!(
            verify_manifest(&dir, &test_key(), &test_key()),
            Err(CfFormatError::ManifestMismatch(_))
        ));
    }

    /// 错误密钥 → manifest_mac 不符 → 校验失败。
    #[test]
    fn wrong_manifest_key_fails() {
        let dir = seed_vault("wrongkey");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");

        assert!(matches!(
            verify_manifest(&dir, &other_key(), &test_key()),
            Err(CfFormatError::ManifestMismatch(_))
        ));
    }

    /// 错误 attach_mac_key → 首个 content_mac 校验失败。
    #[test]
    fn wrong_attach_mac_key_fails() {
        let dir = seed_vault("wrongattkey");
        write_manifest(&dir, &test_key(), &test_key()).expect("写清单成功");

        assert!(matches!(
            verify_manifest(&dir, &test_key(), &other_key()),
            Err(CfFormatError::ManifestMismatch(_))
        ));
    }

    /// 库版本过新时不能生成清单（vault_uuid 需从当前版本 header 读取）。
    #[test]
    fn write_manifest_rejects_too_new() {
        let dir = temp_vault_dir("manifest_toonew");
        fs::write(dir.join("header.json"), r#"{ "format_version": 2 }"#).expect("写入成功");
        assert!(matches!(
            write_manifest(&dir, &test_key(), &test_key()),
            Err(CfFormatError::UnsupportedVersion(_))
        ));
    }
}
