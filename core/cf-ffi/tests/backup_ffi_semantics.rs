//! v0.2 备份 FFI 语义测试（FR-8.1 / FR-8.5 / FR-8.6，docs/09 §3.1）。
//!
//! 聚焦跨 FFI 的回环语义，与 cf-exporter 内核单测互补：
//!
//! 1. **导出 → 校验 → 恢复回环**：FFI 导出的 `.coffer` 包可被 FFI 校验、
//!    可被恢复到新工作目录，恢复产物经常规 open_vault + unlock 可用，
//!    条目数据完整；
//! 2. **锁定态可执行**（TC-EXP-08）：备份是 CofferApp 级操作，不解锁即可
//!    导出 / 校验 / 恢复；
//! 3. **FR-8.5 打点联动**：导出成功后源库 `meta.last_backup_at` 有值，
//!    提醒判定随之翻转（内核 stamp_last_backup 的跨 FFI 证据）；
//! 4. **错误码跨 FFI**：非法源目录 → 1012、非 Coffer 包 → 2001、
//!    恢复目标已存在 → 1004。
//!
//! 测试约定与 `ffi_contract.rs` 一致：每测试独立临时目录；快速 KDF 建库；
//! FFI 入口一律走公开 API。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_ffi::api::CofferApp;
use cf_ffi::types::*;

/// 提取错误码。
fn err_code<T>(r: Result<T, cf_ffi::FfiError>) -> u16 {
    match r {
        Ok(_) => panic!("预期应返回错误，实际成功"),
        Err(e) => e.code(),
    }
}

/// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

/// 每测试独立的临时工作目录。
fn temp_base(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cf-ffi-bak-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &std::path::Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 最小合法登录条目（与 ffi_contract.rs 同款）。
fn login_draft(title: &str, password: &str) -> FfiItemDraft {
    FfiItemDraft {
        title: title.to_owned(),
        category: FfiItemCategory::Login,
        urls: Vec::new(),
        tags: Vec::new(),
        sections: Vec::new(),
        fields: vec![
            FfiFieldDraft {
                name: "用户名".to_owned(),
                value: Some("qa-user".to_owned()),
                field_type: FfiFieldType::Text,
                designation: Some(FfiDesignation::Username),
                section_index: None,
                position: 0,
            },
            FfiFieldDraft {
                name: "密码".to_owned(),
                value: Some(password.to_owned()),
                field_type: FfiFieldType::Concealed,
                designation: Some(FfiDesignation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

/// 建库 → 解锁 → 建一条条目 → 锁定（数据落库，验证打包非空）。
fn vault_with_item(
    base: &std::path::Path,
    name: &str,
) -> (cf_domain::vault::Vault, Arc<CofferApp>, String) {
    let brief = setup_vault(base, name);
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    session
        .create_item(login_draft("GitHub", "p@ssw0rd-42!"))
        .unwrap();
    session.lock();
    let uuid = brief.uuid.to_string();
    (brief, app, uuid)
}

/// 导出 → 校验 → 恢复 → 打开解锁 → 数据完整（FR-8.1 全回环，跨 FFI）。
#[test]
fn 备份导出校验恢复全回环() {
    let base = temp_base("roundtrip");
    let (brief, app, uuid) = vault_with_item(&base, "回环库");

    // 锁定态导出（TC-EXP-08：CofferApp 级操作）
    let out_path = base.join("backup.coffer");
    let exported = app
        .export_backup(
            base.join(&uuid).to_string_lossy().into_owned(),
            out_path.to_string_lossy().into_owned(),
        )
        .unwrap();
    assert!(exported.verified, "导出自检（FR-8.6）必须通过");
    assert!(exported.file_count >= 2, "至少含 header.json + db.sqlite");
    assert!(exported.size_bytes > 0);
    assert_eq!(exported.file_path, out_path.to_string_lossy().into_owned());

    // 结构校验（FR-8.6）：UUID 与包内声明一致
    let report = app
        .verify_backup(out_path.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(report.vault_uuid, uuid);
    assert_eq!(report.format_version, brief.format_version);
    assert_eq!(report.file_count, exported.file_count);

    // 恢复到新工作目录 → 常规 open + unlock（主密码校验在解锁侧）
    let restore_base = temp_base("restore");
    let restored_dir = app
        .restore_backup(
            out_path.to_string_lossy().into_owned(),
            restore_base.to_string_lossy().into_owned(),
        )
        .unwrap();
    assert_eq!(
        std::path::Path::new(&restored_dir)
            .file_name()
            .unwrap()
            .to_string_lossy(),
        uuid,
        "恢复目录名必须是库 uuid"
    );

    let session = app
        .open_vault(restore_base.to_string_lossy().into_owned(), uuid.clone())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    let items = session.list_items(None).unwrap();
    assert_eq!(items.len(), 1, "恢复产物必须含打包前创建的条目");
    assert_eq!(items[0].title, "GitHub");
}

/// FR-8.5 跨 FFI 联动：导出成功后源库 last_backup_at 有值，提醒翻转。
#[test]
fn 导出成功后备份提醒翻转() {
    let base = temp_base("reminder");
    let (_brief, app, uuid) = vault_with_item(&base, "提醒库");

    let session = app
        .open_vault(base.to_string_lossy().into_owned(), uuid.clone())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();

    // 从未备份 → 应提醒（last_backup_at 为 None）
    assert_eq!(session.last_backup_at().unwrap(), None);
    assert!(session.should_suggest_backup(300, 9_999_999).unwrap());

    // FFI 导出 → 内核自动打点（FR-8.5）→ 提醒翻转
    let out_path = base.join("backup.coffer");
    app.export_backup(
        base.join(&uuid).to_string_lossy().into_owned(),
        out_path.to_string_lossy().into_owned(),
    )
    .unwrap();

    let stamped = session.last_backup_at().unwrap();
    assert!(stamped.is_some(), "导出成功必须写入 last_backup_at 打点");
    assert!(
        !session.should_suggest_backup(300, 9_999_999).unwrap(),
        "阈值远未到期不得提醒"
    );
    // 阈值禁用（<= 0）永不提醒
    assert!(!session.should_suggest_backup(0, 9_999_999).unwrap());
}

/// 错误码跨 FFI：非法源目录 → 1012；非 Coffer 包 → 2001；恢复目标已存在 → 1004。
#[test]
fn 备份错误码跨ffi() {
    let base = temp_base("errors");
    let (_brief, app, uuid) = vault_with_item(&base, "错误码库");

    // 非法源目录（空目录，缺 header/db）→ Validation 1012
    let empty = base.join("empty-dir");
    std::fs::create_dir_all(&empty).unwrap();
    assert_eq!(
        err_code(app.export_backup(
            empty.to_string_lossy().into_owned(),
            base.join("x.coffer").to_string_lossy().into_owned(),
        )),
        1012
    );

    // 非 ZIP 垃圾文件 → ImportUnknownFormat 2001（verify 与 restore 双路径）
    let junk = base.join("junk.coffer");
    std::fs::write(&junk, b"not a zip file at all").unwrap();
    assert_eq!(
        err_code(app.verify_backup(junk.to_string_lossy().into_owned())),
        2001
    );
    assert_eq!(
        err_code(app.restore_backup(
            junk.to_string_lossy().into_owned(),
            base.to_string_lossy().into_owned(),
        )),
        2001
    );

    // 恢复目标已存在 → VaultExists 1004
    let out_path = base.join("backup.coffer");
    app.export_backup(
        base.join(&uuid).to_string_lossy().into_owned(),
        out_path.to_string_lossy().into_owned(),
    )
    .unwrap();
    let restore_base = temp_base("exists");
    app.restore_backup(
        out_path.to_string_lossy().into_owned(),
        restore_base.to_string_lossy().into_owned(),
    )
    .unwrap();
    assert_eq!(
        err_code(app.restore_backup(
            out_path.to_string_lossy().into_owned(),
            restore_base.to_string_lossy().into_owned(),
        )),
        1004
    );
}
