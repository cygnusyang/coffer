//! 1PUX 导出 FFI 语义测试（docs/22 §3.4 / §6 T04；docs/23 TC-EXP-09/10/15、
//! TC-GATE-05、回环端到端）。
//!
//! 门禁落点在 cf-session（`write_guard(LicensedOp::ExportData)`，export_gate.rs）
//! 与 cf-ffi 边界（out_path 参数校验），故 TC-EXP-09/10/15 三个原 cf-exporter
//! 的 `#ignore` 占位迁至本文件（T04 收口，docs/22 §6）。与
//! `cf-exporter/tests/pux_export.rs` 的内核级验收（T01）互补：
//!
//! - **TC-EXP-09**：只读许可态（ExportData 组）注入 6002/6003 双态 →
//!   `export_one_pux` → `Err(6002)` / `Err(6003)`；**拒绝不产生输出文件**；
//! - **TC-EXP-10**：锁定态 → 1001（锁定态下绝不产出明文导出）；
//! - **TC-EXP-15**：out_path 参数非法（空串）→ 5002 InvalidArgument
//!   （FFI 边界校验，内核不接收空路径）；
//! - **TC-GATE-05（审计面）**：成功导出打点 `FfiAuditEvent::PuxExport`
//!   （FR-12.6，本地审计）；
//! - **回环端到端（FFI）**：建库播种 → `export_one_pux` → 新库 `import_1pux`
//!   → 条目数一致 + 密码字段逐字段一致。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cf_crypto::kdf::KdfParams;
use cf_domain::license::{LicenseDecision, LicenseDenial, LicenseGate, LicensedOp};
use cf_ffi::api::{CofferApp, VaultSession};
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

/// 每测试独立的临时工作目录（pid + 进程内原子计数器）。
fn temp_base(tag: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("cf-ffi-pux-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 双态测试 gate（对齐 `license_gate_ffi.rs`）。
struct FixedGate(LicenseDecision);

impl LicenseGate for FixedGate {
    fn check(&self, _op: LicensedOp) -> LicenseDecision {
        self.0
    }
}

fn expired_gate() -> Arc<dyn LicenseGate> {
    Arc::new(FixedGate(LicenseDecision::Deny(
        LicenseDenial::TrialExpired,
    )))
}

fn abnormal_gate() -> Arc<dyn LicenseGate> {
    Arc::new(FixedGate(LicenseDecision::Deny(
        LicenseDenial::StateUnavailable,
    )))
}

/// Login 条目草稿（用户名 + 密码）。
fn login_draft(title: &str, username: &str, password: &str) -> FfiItemDraft {
    FfiItemDraft {
        title: title.to_owned(),
        category: FfiItemCategory::Login,
        urls: Vec::new(),
        tags: Vec::new(),
        sections: Vec::new(),
        fields: vec![
            FfiFieldDraft {
                name: "用户名".to_owned(),
                value: Some(username.to_owned()),
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

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧打开 + 解锁。
fn unlocked_session(
    base: &std::path::Path,
    name: &str,
) -> (cf_domain::vault::Vault, Arc<VaultSession>) {
    let brief = cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap();
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    (brief, session)
}

/// TC-EXP-09：只读许可态拒绝（ExportData 组）——注入 6002/6003 双态 →
/// `export_one_pux` → `Err(6002)` / `Err(6003)`；**拒绝不产生输出文件**。
#[test]
fn tc_exp_09_gate_deny_export_data_no_output() {
    // 6002（试用到期）
    let base = temp_base("deny-6002");
    let brief =
        cf_session::create_vault_with_kdf(&base, "出口库", STRONG_PASSWORD, fast_kdf()).unwrap();
    let app = CofferApp::new();
    app.set_license_gate(expired_gate());
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();

    let out = base.join("deny6002.1pux");
    let err = err_code(session.export_one_pux(out.to_string_lossy().into_owned()));
    assert_eq!(err, 6002, "export_one_pux 只读态（到期）必须 6002");
    assert!(!out.exists(), "被拒导出不得产生输出文件");

    // 6003（异常退化）
    let base2 = temp_base("deny-6003");
    let brief2 =
        cf_session::create_vault_with_kdf(&base2, "出口库", STRONG_PASSWORD, fast_kdf()).unwrap();
    let app2 = CofferApp::new();
    app2.set_license_gate(abnormal_gate());
    let session2 = app2
        .open_vault(
            base2.to_string_lossy().into_owned(),
            brief2.uuid.to_string(),
        )
        .unwrap();
    session2.unlock(STRONG_PASSWORD.to_owned()).unwrap();

    let out2 = base2.join("deny6003.1pux");
    let err2 = err_code(session2.export_one_pux(out2.to_string_lossy().into_owned()));
    assert_eq!(err2, 6003, "export_one_pux 只读态（异常退化）必须 6003");
    assert!(!out2.exists(), "被拒导出不得产生输出文件");
}

/// TC-EXP-10：锁定态 → 1001（锁定态下绝不产出明文导出）。
#[test]
fn tc_exp_10_locked_1001() {
    let base = temp_base("locked");
    let brief =
        cf_session::create_vault_with_kdf(&base, "锁定库", STRONG_PASSWORD, fast_kdf()).unwrap();
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    // 不解锁直接导出
    let out = base.join("locked.1pux");
    let err = err_code(session.export_one_pux(out.to_string_lossy().into_owned()));
    assert_eq!(err, 1001, "锁定态导出必须 1001");
    assert!(!out.exists(), "锁定态拒绝不得产生输出文件");
}

/// TC-EXP-15：out_path 参数非法（空串）→ 5002 InvalidArgument（FFI 边界校验）。
#[test]
fn tc_exp_15_invalid_out_path_5002() {
    let base = temp_base("badpath");
    let (_brief, session) = unlocked_session(&base, "参数库");
    let err = err_code(session.export_one_pux(String::new()));
    assert_eq!(err, 5002, "空 out_path 必须 5002 InvalidArgument");
}

/// TC-GATE-05（审计面）：成功导出打点 `FfiAuditEvent::PuxExport`（FR-12.6）。
#[test]
fn tc_gate_05_success_appends_pux_export_audit() {
    let base = temp_base("audit");
    let (_brief, session) = unlocked_session(&base, "审计库");
    session
        .create_item(login_draft("GitHub", "alice", "hunter2"))
        .unwrap();

    let out = base.join("audit.1pux");
    let r = session
        .export_one_pux(out.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(r.item_count, 1, "应导出 1 条");
    assert!(out.exists(), "导出文件应已写出");

    let events = session.recent_audit_events(None, None).unwrap();
    assert_eq!(events.len(), 1, "应恰好有一条导出审计事件");
    assert!(matches!(events[0].event, FfiAuditEvent::PuxExport));
}

/// 回环端到端（FFI）：建库播种 → `export_one_pux` → 新库 `import_1pux` →
/// 条目数一致 + 密码字段逐字段一致（对齐 docs/23 TC-EXP-02 的自回环锚点）。
#[test]
fn ffi_loopback_end_to_end() {
    let base = temp_base("loopback");
    let (_brief, session) = unlocked_session(&base, "源库");
    session
        .create_item(login_draft("GitHub", "alice", "hunter2-secret"))
        .unwrap();
    session
        .create_item(login_draft("邮箱", "bob", "pw-42!"))
        .unwrap();

    let out = base.join("loopback.1pux");
    let r = session
        .export_one_pux(out.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(r.item_count, 2, "应导出 2 条");
    assert_eq!(r.attachment_count, 0, "无附件");
    assert_eq!(r.skipped_trashed, 0, "无回收站跳过");
    assert_eq!(r.skipped_passkeys, 0, "无 passkey 跳过");
    assert!(out.exists(), "导出文件应已写出");

    // 新库导入回环
    let (_brief2, session2) = unlocked_session(&base, "目标库");
    let imported = session2
        .import_1pux(out.to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(imported.imported_items, 2, "回环导入条目数一致");

    let items = session2.list_items(None).unwrap();
    assert_eq!(items.len(), 2);
    // 逐字段：密码明文一致（Concealed 经 get_field_value 下发）
    let gh = items
        .iter()
        .find(|i| i.title == "GitHub")
        .expect("GitHub 条目存在");
    let details = session2
        .get_item(gh.uuid.clone())
        .unwrap()
        .expect("回环后条目可读");
    let pwd = details
        .fields
        .iter()
        .find(|f| f.designation == Some(FfiDesignation::Password))
        .expect("密码字段存在");
    let value = session2
        .get_field_value(gh.uuid.clone(), pwd.uuid.clone())
        .unwrap();
    assert_eq!(
        value.as_deref(),
        Some("hunter2-secret"),
        "密码明文逐字节一致"
    );
}
