//! FR-14.4 本地诊断 FFI 语义测试（docs/22 §3.4；docs/23 §1.5 TC-DIAG 组）。
//!
//! 聚焦跨 FFI 契约与错误码，与 cf-session 层单测互补：
//!
//! 1. **TC-DIAG-01**：`diagnostic_summary()` 跨 FFI 返回字段集；条目数 =
//!    `list_items` 计数一致；
//! 2. **TC-DIAG-02**：`format_version()`（CofferApp 级）= `cf_format::FORMAT_VERSION`
//!    常量经 FFI 暴露（TC-NET 诊断页展示的事实基座）；
//! 3. **TC-DIAG-03**：FFI 字段集白名单——`FfiDiagnosticSummary` 编译期穷尽
//!    构造钉住字段集（多一个敏感字段即编译失败）；
//! 4. **TC-DIAG-04**：锁定态 → 1001；
//! 5. **TC-DIAG-05**：允许面无门禁——注入 6002/6003 只读态仍成功（gate 经
//!    `open_vault` 下传）；
//! 6. **TC-DIAG-06**：空库条目数 = 0。

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
    let dir = std::env::temp_dir().join(format!("cf-ffi-diag-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &std::path::Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 建库 → 打开 → 解锁，返回 FFI 会话。
fn unlocked_session(
    base: &std::path::Path,
    name: &str,
) -> (cf_domain::vault::Vault, Arc<VaultSession>) {
    let brief = setup_vault(base, name);
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    (brief, session)
}

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

/// TC-DIAG-01：正向字段集跨 FFI；条目数 = `list_items` 计数一致。
#[test]
fn 正向字段集跨ffi() {
    let base = temp_base("pos");
    let (brief, session) = unlocked_session(&base, "诊断库");
    let id1 = session.create_item(login_draft("第一项", "pw-1")).unwrap();
    session
        .add_attachment(id1.clone(), "a.txt".to_owned(), b"hello".to_vec())
        .unwrap();
    session.create_item(login_draft("第二项", "pw-2")).unwrap();

    let sum = session.diagnostic_summary().unwrap();
    assert_eq!(sum.item_count, 2);
    assert_eq!(
        sum.item_count as usize,
        session.list_items(None).unwrap().len(),
        "条目数须与 list_items 计数一致（TC-DIAG-01）"
    );
    assert_eq!(sum.attachment_count, 1);
    assert!(sum.vault_created_at > 0);
    assert_eq!(sum.last_backup_at, None);
    assert_eq!(sum.vault_uuid_prefix.len(), 8);
    assert_eq!(sum.vault_uuid_prefix, &brief.uuid.to_string()[..8]);
}

/// TC-DIAG-02：`format_version()`（CofferApp 级）= `cf_format::FORMAT_VERSION`
/// 常量（经 FFI 暴露，诊断页 / 网络自证页展示的库格式版本事实基座）。
#[test]
fn format_version等于常量() {
    let app = CofferApp::new();
    assert_eq!(
        app.format_version(),
        cf_format::FORMAT_VERSION.to_string(),
        "format_version 必须等于 cf_format::FORMAT_VERSION 常量"
    );
}

/// TC-DIAG-03：FFI 字段集白名单（可断言接口面）——`FfiDiagnosticSummary`
/// 只含计数 / 时间 / uuid 前缀类字段，以编译期穷尽构造钉住字段集，多一个
/// 敏感字段即编译失败。
#[test]
fn 字段集白名单钉住无敏感字段() {
    let s = FfiDiagnosticSummary {
        item_count: 2,
        attachment_count: 1,
        vault_created_at: 1_700_000_000,
        last_backup_at: Some(1_700_000_100),
        vault_uuid_prefix: "0195b0b5".to_owned(),
    };
    let FfiDiagnosticSummary {
        item_count,
        attachment_count,
        vault_created_at,
        last_backup_at,
        vault_uuid_prefix,
    } = s;
    assert_eq!(item_count, 2);
    assert_eq!(attachment_count, 1);
    assert_eq!(vault_created_at, 1_700_000_000);
    assert_eq!(last_backup_at, Some(1_700_000_100));
    assert_eq!(vault_uuid_prefix, "0195b0b5");
}

/// TC-DIAG-04：锁定态 → 1001（锁定态下绝不展示条目级数据）。
#[test]
fn 锁定态报1001() {
    let base = temp_base("locked");
    let brief = setup_vault(&base, "锁定库");
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    let err = err_code(session.diagnostic_summary());
    assert_eq!(err, 1001, "锁定态诊断必须 1001");
}

/// TC-DIAG-05：允许面无门禁——注入 6002/6003 只读态，诊断仍成功
/// （gate 经 `open_vault` 下传会话，对齐 `license_gate_ffi.rs`）。
#[test]
fn 允许面无门禁_注入只读门禁仍成功() {
    let base = temp_base("allow");
    let brief = setup_vault(&base, "允许面库");

    // 到期态 → 6002（对写路径），诊断不拦
    let app = CofferApp::new();
    app.set_license_gate(expired_gate());
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    let sum = session.diagnostic_summary().unwrap();
    assert_eq!(sum.item_count, 0);

    // 异常退化态 → 6003（对写路径），诊断不拦
    let app2 = CofferApp::new();
    app2.set_license_gate(abnormal_gate());
    let session2 = app2
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session2.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    let sum2 = session2.diagnostic_summary().unwrap();
    assert_eq!(sum2.item_count, 0);
}

/// TC-DIAG-06：空库条目数 = 0。
#[test]
fn 空库条目数为0() {
    let base = temp_base("empty");
    let (_brief, session) = unlocked_session(&base, "空库");
    let sum = session.diagnostic_summary().unwrap();
    assert_eq!(sum.item_count, 0);
    assert_eq!(sum.attachment_count, 0);
    assert_eq!(sum.last_backup_at, None);
}
