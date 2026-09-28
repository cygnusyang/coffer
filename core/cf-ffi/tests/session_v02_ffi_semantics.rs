//! v0.2 会话新能力 FFI 语义测试（FR-1.8 / FR-8.5 / FR-14.2，docs/09 §2）。
//!
//! 与 cf-session 内核单测互补，聚焦跨 FFI 的错误码与语义：
//!
//! 1. **改密回环（FR-1.8）**：FFI 路径改密后旧密码失败（1002）、新密码
//!    成功；弱密码 1010 / 旧密码错 1002 时 header 不变；
//! 2. **剪贴板档位（FR-14.2）**：合法档位设置生效、非法值 5002 且原值
//!    不变；档位常量 / 默认值 / 校验函数可到 Swift 侧；
//! 3. **备份提醒（FR-8.5）**：锁定态 1001 门禁、从未备份应提醒；
//! 4. **门禁**：改密 / 剪贴板读写在锁定态的可见性（剪贴板为会话级
//!    元配置、跨 lock 存活，无解锁门禁——与内核语义一致）。
//!
//! 测试约定与 `ffi_contract.rs` 一致。

use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_ffi::api::{CofferApp, VaultSession};
use cf_ffi::types::{FfiAuditEvent, FfiKdfParams};

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
/// 换成的新强密码。
const NEW_PASSWORD: &str = "portable-copper-drift-lantern-77#";

/// 每测试独立的临时工作目录。
fn temp_base(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cf-ffi-v02-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &std::path::Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 打开并解锁一个库。
fn unlocked_session(
    app: &std::sync::Arc<CofferApp>,
    base: &std::path::Path,
    uuid: &str,
) -> std::sync::Arc<VaultSession> {
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), uuid.to_owned())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    session
}

/// 读磁盘上的 header.json（字节级，供「header 未变」断言）。
fn header_bytes(vault_dir: &std::path::Path) -> Vec<u8> {
    std::fs::read(vault_dir.join("header.json")).unwrap()
}

/// FFI 改密回环：改密 → lock → 旧密码 1002 → 新密码成功 → 可再换回。
#[test]
fn 改密后旧密码失败新密码成功() {
    let base = temp_base("cp");
    let brief = setup_vault(&base, "改密库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    session
        .change_password(STRONG_PASSWORD.to_owned(), NEW_PASSWORD.to_owned(), None)
        .unwrap();
    session.lock();

    let err = session.unlock(STRONG_PASSWORD.to_owned()).unwrap_err();
    assert_eq!(err.code(), 1002, "旧密码必须失效");
    assert!(
        session.unlock(NEW_PASSWORD.to_owned()).is_ok(),
        "新密码必须生效"
    );

    // 对称换回：FFI 路径可往返
    session
        .change_password(NEW_PASSWORD.to_owned(), STRONG_PASSWORD.to_owned(), None)
        .unwrap();
    session.lock();
    assert!(session.unlock(STRONG_PASSWORD.to_owned()).is_ok());
}

/// 门禁与错误码：锁定态改密 1001；旧密码错 1002 / 新密码弱 1010 时
/// 磁盘 header 字节不变（先于任何文件操作）。
#[test]
fn 改密门禁与header不变量() {
    let base = temp_base("cp_guard");
    let brief = setup_vault(&base, "门禁库");
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();

    // 锁定态 → 1001
    assert_eq!(
        err_code(session.change_password(
            STRONG_PASSWORD.to_owned(),
            NEW_PASSWORD.to_owned(),
            None,
        )),
        1001
    );

    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    let vault_dir = base.join(brief.uuid.to_string());
    let before = header_bytes(&vault_dir);

    // 旧密码错 → 1002，header 未变
    assert_eq!(
        err_code(session.change_password(
            "totally-wrong-password-99!".to_owned(),
            NEW_PASSWORD.to_owned(),
            None,
        )),
        1002
    );
    assert_eq!(
        header_bytes(&vault_dir),
        before,
        "旧密码错后 header 必须未变"
    );

    // 新密码弱 → 1010，header 未变
    assert_eq!(
        err_code(session.change_password(STRONG_PASSWORD.to_owned(), "123456".to_owned(), None,)),
        1010
    );
    assert_eq!(
        header_bytes(&vault_dir),
        before,
        "弱密码被拒后 header 必须未变"
    );

    // kdf 档位越界 → 5002（FFI record → KdfParams 校验）
    assert_eq!(
        err_code(session.change_password(
            STRONG_PASSWORD.to_owned(),
            NEW_PASSWORD.to_owned(),
            Some(FfiKdfParams {
                m_cost_kib: 1, // 低于 MIN_M_COST_KIB（8 MiB）
                t_cost: 1,
                p_cost: 1,
            }),
        )),
        5002
    );
    assert_eq!(
        header_bytes(&vault_dir),
        before,
        "非法档位下 header 必须未变"
    );

    // 带合法 kdf 档位改密 → 新密码按新档位解锁成功
    session
        .change_password(
            STRONG_PASSWORD.to_owned(),
            NEW_PASSWORD.to_owned(),
            Some(FfiKdfParams {
                m_cost_kib: 16 * 1024,
                t_cost: 1,
                p_cost: 1,
            }),
        )
        .unwrap();
    session.lock();
    assert!(session.unlock(NEW_PASSWORD.to_owned()).is_ok());
}

/// 剪贴板档位（FR-14.2）：默认 30s；合法档位 10/30/60/120/0 生效；
/// 非法值 5002 且原值不变；Swift 侧选择器数据源（档位 / 默认 / 校验）可用。
#[test]
fn 剪贴板档位设置与非法值拒绝() {
    // Swift 侧选择器数据源：档位常量 + 默认值 + 0（从不）语义
    assert_eq!(cf_ffi::api::clipboard_clear_tiers(), vec![10, 30, 60, 120]);
    assert_eq!(cf_ffi::api::default_clipboard_clear_secs(), 30);
    assert!(
        cf_ffi::api::validate_clipboard_clear_secs(0).is_ok(),
        "0 = 从不"
    );
    assert!(cf_ffi::api::validate_clipboard_clear_secs(120).is_ok());
    assert_eq!(
        err_code(cf_ffi::api::validate_clipboard_clear_secs(-1)),
        5002
    );
    assert_eq!(
        err_code(cf_ffi::api::validate_clipboard_clear_secs(45)),
        5002
    );

    let base = temp_base("clip");
    let brief = setup_vault(&base, "剪贴板库");
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();

    // 会话级元配置：默认值、锁定态可读写、跨 lock 存活
    assert_eq!(session.clipboard_clear_secs(), 30);
    for tier in [10, 30, 60, 120, 0] {
        session.set_clipboard_clear_secs(tier).unwrap();
        assert_eq!(session.clipboard_clear_secs(), tier);
    }
    session.lock();
    assert_eq!(session.clipboard_clear_secs(), 0, "配置跨 lock 存活");
    session.set_clipboard_clear_secs(60).unwrap();

    // 非法值 → 5002 且保持原值
    for bad in [-1, 45, 121] {
        assert_eq!(err_code(session.set_clipboard_clear_secs(bad)), 5002);
        assert_eq!(session.clipboard_clear_secs(), 60, "拒绝后配置保持原值");
    }
}

/// 备份提醒（FR-8.5）：锁定态 1001 门禁；解锁后从未备份应提醒；
/// 阈值 <= 0 禁用。
#[test]
fn 备份提醒门禁与判定() {
    let base = temp_base("remind");
    let brief = setup_vault(&base, "提醒门禁库");
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();

    // 锁定态 → 1001（提醒判定需读 meta，属解锁态数据访问）
    assert_eq!(err_code(session.last_backup_at()), 1001);
    assert_eq!(err_code(session.should_suggest_backup(300, 1_000)), 1001);

    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    assert_eq!(session.last_backup_at().unwrap(), None, "新库从未备份");
    assert!(
        session.should_suggest_backup(300, 1_000).unwrap(),
        "从未备份应提醒"
    );
    assert!(
        !session.should_suggest_backup(0, 1_000).unwrap(),
        "0 视为禁用"
    );
    assert!(
        !session.should_suggest_backup(-1, 1_000).unwrap(),
        "负值视为禁用"
    );
}

/// CSV 导出（FR-8.3）+ 审计打点/查询回环（FR-12.6）：导出成功后
/// recent_audit_events 可查到 CsvExport 事件（内核动作自动打点）。
#[test]
fn csv导出落审计且可查询() {
    let base = temp_base("csvexp");
    let brief = setup_vault(&base, "导出库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let out = base.join("export.csv");
    let r = session
        .export_csv(out.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(r.row_count, 0, "空库无数据行");
    assert!(out.exists(), "CSV 文件应已写出");

    let events = session.recent_audit_events(None, None).unwrap();
    assert_eq!(events.len(), 1, "应恰好有 CSV 导出事件");
    assert!(matches!(events[0].event, FfiAuditEvent::CsvExport));
}

/// 审计分页与锁定门禁（FR-12.6）：改密落 PasswordChange 事件（倒序在最前）；
/// 锁定态查询/导出 → 1001。
#[test]
fn 审计分页与锁定门禁() {
    let base = temp_base("audit");
    let brief = setup_vault(&base, "审计库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    session
        .change_password(STRONG_PASSWORD.to_owned(), NEW_PASSWORD.to_owned(), None)
        .unwrap();

    let events = session.recent_audit_events(None, None).unwrap();
    assert_eq!(events.len(), 1, "应恰好有改密事件");
    assert!(matches!(events[0].event, FfiAuditEvent::PasswordChange));

    // 分页：limit=0 → 空；offset 越界 → 空
    assert!(session
        .recent_audit_events(None, Some(0))
        .unwrap()
        .is_empty());
    assert!(session
        .recent_audit_events(Some(9), None)
        .unwrap()
        .is_empty());

    // 锁定态 → 1001
    session.lock();
    assert_eq!(err_code(session.recent_audit_events(None, None)), 1001);
    assert_eq!(
        err_code(session.export_csv(base.join("x.csv").to_string_lossy().into_owned())),
        1001
    );
}
