//! 容器生命周期操作：打开（版本三态）、原子写 header、布局校验、迁移。
//!
//! 对应 `docs/04-系统设计.md` §6（格式兼容与迁移策略）与
//! `docs/03-详细设计.md` §1.2（工作目录结构）。
//!
//! # 目录形态识别（无魔数）
//!
//! 本项目没有「目录魔数」：识别一个目录是不是 Coffer 库，依据是
//! `header.json` **存在且可解析**、且 `format_version` **受支持**
//! （见 `docs/02-概要设计.md` 修正 A 的说明）。

use std::cmp::Ordering;
use std::fs;
use std::path::Path;

use crate::atomic::atomic_write_bytes;
use crate::error::CfFormatError;
use crate::header::{validate_header, Header, FORMAT_VERSION};

/// 容器形态。
///
/// M1 仅支持**目录形态**（工作形态）。**交换形态**（`.lvvault` ZIP 单文件）
/// 归 `cf-exporter`（M2），不在此处。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// 工作形态：`<vault_uuid>/` 目录（见 §1.2 工作目录结构）。
    Directory,
}

/// 打开容器后，根据 `format_version` 得到的三种结局。
///
/// 对应 `docs/04-系统设计.md` §6.2 的三路分支：
///
/// ```text
/// 读取 header.format_version
///   ├── == 当前支持版本 → Current
///   ├── <  当前支持版本 → NeedsMigration
///   └── >  当前支持版本 → TooNew（错误码 1006，提示升级 App）
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    /// 版本与当前 App 支持一致，可直接使用。
    Current(Header),
    /// 版本低于当前（旧库），进入迁移流程。
    ///
    /// M1 迁移表为空（[`migrate`] 恒返回不支持），此分支为未来格式
    /// 版本递增预留。
    NeedsMigration {
        /// 旧版本库的 header（迁移需要读取其 KDF / wrapped_dek 等）。
        header: Header,
        /// 旧版本号。
        from: u16,
    },
    /// 版本高于当前（新库），应拒绝打开并提示升级 App。
    TooNew(u16),
}

/// 工作目录中的头部文件名。
const HEADER_FILE: &str = "header.json";

/// 工作目录中的数据库文件名。
const DB_FILE: &str = "db.sqlite";

/// 打开容器：读取 `header.json` 并按版本三态分派。
///
/// # 版本先于结构解析
///
/// 先抽取 `format_version` 做三态判断，**再用当前版本的结构去解析**。
/// 这是刻意为之：未来版本（TooNew）的 header 字段结构可能完全不同，
/// 用 v1 结构解析会失败——但我们应当返回「版本过新」而不是「格式损坏」。
///
/// # 错误
///
/// - 目录缺少 `header.json` → [`CfFormatError::ContainerLayout`]
/// - JSON 畸形 / 缺 `format_version` / `format_version` 为 0
///   → [`CfFormatError::InvalidHeader`]
/// - 版本等于当前但结构或字段非法 → [`CfFormatError::InvalidHeader`]
pub fn open_container(vault_dir: &Path) -> Result<OpenOutcome, CfFormatError> {
    let header_path = vault_dir.join(HEADER_FILE);
    if !header_path.is_file() {
        return Err(CfFormatError::ContainerLayout(format!(
            "目录缺少 {HEADER_FILE}（vault_dir={}）",
            vault_dir.display()
        )));
    }

    let text = fs::read_to_string(&header_path)
        .map_err(|e| CfFormatError::Io(format!("读取 {} 失败：{e}", header_path.display())))?;

    // 先抽取 format_version 做三态判断（见函数文档「版本先于结构解析」）
    let root: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| CfFormatError::InvalidHeader(format!("header.json 不是合法 JSON：{e}")))?;
    let raw_version = root
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| CfFormatError::InvalidHeader("缺少或非法的 format_version".to_string()))?;

    // 0 不是任何历史版本，视为损坏而非「旧库」；超出 u16 视为「版本过新」
    if raw_version == 0 {
        return Err(CfFormatError::InvalidHeader(
            "format_version 必须 ≥ 1".to_string(),
        ));
    }
    let version = raw_version.min(u16::MAX as u64) as u16;

    match version.cmp(&FORMAT_VERSION) {
        Ordering::Greater => Ok(OpenOutcome::TooNew(version)),
        Ordering::Less => {
            // 旧库：仍需把 header 解析出来供迁移使用；解析失败视为损坏
            let header: Header = serde_json::from_str(&text).map_err(|e| {
                CfFormatError::InvalidHeader(format!("旧版本 header 无法解析：{e}"))
            })?;
            Ok(OpenOutcome::NeedsMigration {
                header,
                from: version,
            })
        }
        Ordering::Equal => {
            let header: Header = serde_json::from_str(&text)
                .map_err(|e| CfFormatError::InvalidHeader(format!("header 解析失败：{e}")))?;
            validate_header(&header)?;
            Ok(OpenOutcome::Current(header))
        }
    }
}

/// 原子写入 `header.json`（临时文件 → fsync → rename 覆盖）。
///
/// 写前会先校验 header 内容（不校验就不写，见 [`validate_header`]）。
///
/// # 前置条件
///
/// `vault_dir` 必须已存在；目录的创建由上层「建库」流程负责。
///
/// # 原子性
///
/// 见 [`crate::atomic::atomic_write_bytes`]：任何一步失败都不会留下
/// 半截的 `header.json`，rename 失败的临时文件会被清理。
pub fn write_header(vault_dir: &Path, h: &Header) -> Result<(), CfFormatError> {
    validate_header(h)?;

    let json = serde_json::to_vec_pretty(h)
        .map_err(|e| CfFormatError::InvalidHeader(format!("header 序列化失败：{e}")))?;
    atomic_write_bytes(vault_dir, HEADER_FILE, &json)
}

/// 校验容器布局：`header.json` 与 `db.sqlite` 必须都存在。
///
/// 用于「目录形态无魔数」的识别（模块文档）：结合
/// [`open_container`] 的「header 存在可解析 + 版本受支持」，
/// 这里补上数据文件存在性检查。
///
/// # 注意
///
/// 本函数**只做存在性检查**，不解析 header 内容（那是
/// [`open_container`] 的职责）。`db.sqlite` 的内容归 `cf-store`。
pub fn verify_container_layout(vault_dir: &Path) -> Result<(), CfFormatError> {
    if !vault_dir.is_dir() {
        return Err(CfFormatError::ContainerLayout(format!(
            "路径不是目录：{}",
            vault_dir.display()
        )));
    }
    for required in [HEADER_FILE, DB_FILE] {
        if !vault_dir.join(required).is_file() {
            return Err(CfFormatError::ContainerLayout(format!(
                "缺少必需文件 {required}（vault_dir={}）",
                vault_dir.display()
            )));
        }
    }
    Ok(())
}

/// 把容器迁移到目标格式版本。
///
/// **M1 迁移表为空**：任何迁移请求都返回
/// [`CfFormatError::UnsupportedVersion`]（上层可按错误码 1006 语义提示）。
///
/// 未来实现时须满足 `docs/04-系统设计.md` §6.2 的硬性要求：
/// 先备份 → 写新临时目录 → 全部成功后原子替换 → 失败保留原库。
pub fn migrate(_vault_dir: &Path, to: u16) -> Result<(), CfFormatError> {
    Err(CfFormatError::UnsupportedVersion(to))
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{b64, sample_header, temp_vault_dir};

    use std::fs;

    /// 把一个 header 写入临时目录的 header.json（直接写，不走 write_header，
    /// 便于构造非法 / 旧版本 fixture）。
    fn write_raw_header(dir: &Path, json: &str) {
        fs::write(dir.join("header.json"), json).expect("写入 header.json 成功");
    }

    /// open_container 三态之一：版本等于当前 → Current，逐字段相等。
    #[test]
    fn open_current_version() {
        let dir = temp_vault_dir("current");
        let h = sample_header();
        write_header(&dir, &h).expect("写入成功");

        match open_container(&dir).expect("打开成功") {
            OpenOutcome::Current(got) => assert_eq!(got, h),
            other => panic!("应为 Current，实际为 {other:?}"),
        }
    }

    /// open_container 三态之二：版本高于当前（v2）→ TooNew(2)。
    ///
    /// 关键断言：**即使 v2 的其余字段结构与 v1 完全不同**，也必须返回
    /// TooNew 而非「格式损坏」——这正是「版本先于结构解析」的用意。
    #[test]
    fn open_too_new_version() {
        let dir = temp_vault_dir("toonew");
        // 只写 format_version，其余字段留空（v2 的字段结构我们无从知晓）
        write_raw_header(&dir, r#"{ "format_version": 2 }"#);

        match open_container(&dir).expect("打开成功") {
            OpenOutcome::TooNew(v) => assert_eq!(v, 2),
            other => panic!("应为 TooNew(2)，实际为 {other:?}"),
        }
    }

    /// 目录缺少 header.json → ContainerLayout。
    #[test]
    fn missing_header_reports_layout() {
        let dir = temp_vault_dir("missing");
        fs::write(dir.join("db.sqlite"), b"x").expect("写入成功");
        assert!(matches!(
            open_container(&dir),
            Err(CfFormatError::ContainerLayout(_))
        ));
    }

    /// 畸形 JSON → InvalidHeader。
    #[test]
    fn malformed_json_reports_invalid_header() {
        let dir = temp_vault_dir("badjson");
        write_raw_header(&dir, "this is { not json");
        assert!(matches!(
            open_container(&dir),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// format_version=0 → InvalidHeader（0 不是任何历史版本）。
    #[test]
    fn version_zero_reports_invalid_header() {
        let dir = temp_vault_dir("ver0");
        write_raw_header(&dir, r#"{ "format_version": 0 }"#);
        assert!(matches!(
            open_container(&dir),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// 版本等于当前但结构非法（salt 长度不符）→ InvalidHeader。
    #[test]
    fn current_version_with_bad_header_rejected() {
        let dir = temp_vault_dir("badcurrent");
        let mut h = sample_header();
        h.kdf.salt_b64 = b64(&[0x01u8; 16]); // 16 字节而非 32 字节
        let json = serde_json::to_string(&h).expect("序列化成功");
        write_raw_header(&dir, &json);

        assert!(matches!(
            open_container(&dir),
            Err(CfFormatError::InvalidHeader(_))
        ));
    }

    /// 原子写成功：header.json 存在、内容与输入一致、无临时文件残留。
    #[test]
    fn atomic_write_replaces_and_cleans_tmp() {
        let dir = temp_vault_dir("atomic");
        let h1 = sample_header();
        write_header(&dir, &h1).expect("首次写入成功");

        // 修改 modified_at 后再次写入，验证「替换」而非「追加」
        let mut h2 = sample_header();
        h2.modified_at = 1_800_000_000;
        write_header(&dir, &h2).expect("二次写入成功");

        let back: Header =
            serde_json::from_slice(&fs::read(dir.join("header.json")).expect("读取成功"))
                .expect("解析成功");
        assert_eq!(back, h2);
        // 无临时文件残留
        assert!(!dir.join(".header.json.tmp").exists(), "临时文件应被清理");
    }

    /// 原子写失败：rename 目标被同名目录占用时失败，且临时文件被清理。
    #[test]
    fn atomic_write_failure_cleans_tmp() {
        let dir = temp_vault_dir("atomicfail");
        // 用同名目录占住 header.json，让 rename 失败（Unix 上文件→目录 会报错）
        fs::create_dir_all(dir.join("header.json")).expect("创建同名目录成功");

        let h = sample_header();
        let err = write_header(&dir, &h).expect_err("rename 应失败");
        assert!(matches!(err, CfFormatError::Io(_)));

        // 关键：临时文件必须被清理，不能残留
        assert!(
            !dir.join(".header.json.tmp").exists(),
            "rename 失败后临时文件应被清理"
        );
    }

    /// 布局校验：header.json + db.sqlite 齐全 → Ok；缺 db.sqlite → Err。
    #[test]
    fn verify_layout() {
        let ok_dir = temp_vault_dir("layout_ok");
        let h = sample_header();
        write_header(&ok_dir, &h).expect("写入成功");
        fs::write(ok_dir.join("db.sqlite"), b"sqlite-data").expect("写入成功");
        verify_container_layout(&ok_dir).expect("布局应完整");

        let missing_db = temp_vault_dir("layout_no_db");
        let h = sample_header();
        write_header(&missing_db, &h).expect("写入成功");
        assert!(matches!(
            verify_container_layout(&missing_db),
            Err(CfFormatError::ContainerLayout(_))
        ));
    }

    /// migrate：M1 迁移表为空，任何目标版本都返回 UnsupportedVersion。
    #[test]
    fn migrate_is_unsupported_in_m1() {
        let dir = temp_vault_dir("migrate");
        assert_eq!(migrate(&dir, 2), Err(CfFormatError::UnsupportedVersion(2)));
    }
}
