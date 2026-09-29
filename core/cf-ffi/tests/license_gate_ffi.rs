//! FR-15 只读门禁 FFI 语义测试（`docs/12-注册激活测试计划.md` §2.4；
//! `docs/03-详细设计.md` §14.6）。
//!
//! 覆盖**应用级写操作**的门禁收口（`docs/02` §10.3 方案 C：不经过会话的
//! create_vault / export_backup / restore_backup 在 CofferApp 装配层判定），
//! 及 gate 经 `open_vault` 向会话的下传：
//!
//! - TC-GATE-04：import / restore 拒绝（应用级 restore_backup 6002）；
//! - TC-GATE-05：数据出口拒绝（export_backup / export_csv 6002）；
//! - TC-GATE-07：拒绝码区分（6002 vs 6003，应用级）；
//! - TC-GATE-09：激活（换 gate）后写路径恢复；
//! - TC-GATE-10：开源默认 PermitAll——默认装配全写通过。
//!
//! 会话内写用例的门禁矩阵已在 cf-session `tests/license_gate.rs` 覆盖。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_domain::license::{LicenseDecision, LicenseDenial, LicenseGate, LicensedOp, PermitAllGate};
use cf_ffi::api::CofferApp;
use cf_ffi::types::*;

/// 提取错误码。
fn err_code<T>(r: Result<T, cf_ffi::FfiError>) -> u16 {
    match r {
        Ok(_) => panic!("预期应返回错误，实际成功"),
        Err(e) => e.code(),
    }
}

/// 双态测试 gate：对全部受管辖操作返回固定判定。
struct FixedGate(LicenseDecision);

impl LicenseGate for FixedGate {
    fn check(&self, _op: LicensedOp) -> LicenseDecision {
        self.0
    }
}

fn expired_gate() -> Arc<dyn LicenseGate> {
    Arc::new(FixedGate(LicenseDecision::Deny(LicenseDenial::TrialExpired)))
}

fn abnormal_gate() -> Arc<dyn LicenseGate> {
    Arc::new(FixedGate(LicenseDecision::Deny(
        LicenseDenial::StateUnavailable,
    )))
}

/// 测试用快速 KDF 档位。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

/// 每测试独立的临时工作目录。
fn temp_base(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cf-ffi-gate-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

/// TC-GATE-04：应用级恢复被拒（restore_backup → 6002）。
#[test]
fn readonly_deny_restore_backup() {
    let base = temp_base("deny-restore");
    let app = CofferApp::new();
    app.set_license_gate(expired_gate());

    let err = err_code(app.restore_backup(
        base.join("any.coffer").to_string_lossy().into_owned(),
        base.join("target").to_string_lossy().into_owned(),
    ));
    assert_eq!(err, 6002, "restore_backup 只读态必须 6002");
}

/// TC-GATE-04（会话路径下传）：open_vault 创建的会话继承应用 gate，
/// import_csv / import_1pux 被拒 6002。
#[test]
fn readonly_deny_session_import_via_ffi() {
    let base = temp_base("deny-import");
    let app = CofferApp::new();
    app.set_license_gate(expired_gate());

    // 建库走 Rust 侧（绕开被门禁拦截的 FFI create_vault），FFI 侧打开
    let brief = cf_session::create_vault_with_kdf(&base, "导入库", STRONG_PASSWORD, fast_kdf())
        .unwrap();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();

    let missing = base.join("nope.csv");
    let err = err_code(session.import_csv(missing.to_string_lossy().into_owned()));
    assert_eq!(err, 6002, "import_csv 只读态必须 6002（gate 下传）");
}

/// TC-GATE-05：数据出口全拒——export_backup（应用级）与 export_csv
/// （会话级）都 6002；被拒导出不产生输出文件。
#[test]
fn readonly_deny_exports() {
    let base = temp_base("deny-export");
    let brief = cf_session::create_vault_with_kdf(&base, "出口库", STRONG_PASSWORD, fast_kdf())
        .unwrap();
    let app = CofferApp::new();
    app.set_license_gate(expired_gate());

    // 应用级：加密备份
    let out = base.join("backup.coffer");
    let err = err_code(app.export_backup(
        base.join(brief.uuid.to_string()).to_string_lossy().into_owned(),
        out.to_string_lossy().into_owned(),
    ));
    assert_eq!(err, 6002, "export_backup 只读态必须 6002");
    assert!(!out.exists(), "被拒导出不得产生输出文件");

    // 会话级：CSV 明文导出
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    let csv_out = base.join("out.csv");
    let err = err_code(session.export_csv(csv_out.to_string_lossy().into_owned()));
    assert_eq!(err, 6002, "export_csv 只读态必须 6002");
    assert!(!csv_out.exists(), "被拒导出不得产生输出文件");
}

/// TC-GATE-07：拒绝码区分（应用级）——到期 6002 vs 异常退化 6003。
#[test]
fn deny_code_6002_vs_6003_app_level() {
    let base = temp_base("codes-app");

    let app = CofferApp::new();
    app.set_license_gate(expired_gate());
    let err = err_code(app.create_vault(
        base.to_string_lossy().into_owned(),
        "到期库".into(),
        STRONG_PASSWORD.into(),
    ));
    assert_eq!(err, 6002);

    let app2 = CofferApp::new();
    app2.set_license_gate(abnormal_gate());
    let err = err_code(app2.create_vault(
        base.to_string_lossy().into_owned(),
        "异常库".into(),
        STRONG_PASSWORD.into(),
    ));
    assert_eq!(err, 6003);
}

/// TC-GATE-09：激活后门禁解除——换回放行 gate 后原被拒操作成功。
#[test]
fn activation_restores_app_writes() {
    let base = temp_base("restore-app");
    let app = CofferApp::new();
    app.set_license_gate(expired_gate());
    let err = err_code(app.create_vault(
        base.to_string_lossy().into_owned(),
        "激活库".into(),
        STRONG_PASSWORD.into(),
    ));
    assert_eq!(err, 6002);

    // 「激活」：官方产物中 cf-license 判定转为 active
    app.set_license_gate(Arc::new(PermitAllGate));
    let brief = app
        .create_vault(
            base.to_string_lossy().into_owned(),
            "激活库".into(),
            STRONG_PASSWORD.into(),
        )
        .unwrap();
    assert!(!brief.vault_uuid.is_empty());
}

/// TC-GATE-10：开源默认 PermitAll——不注入时应用级 + 会话级全写通过。
#[test]
fn permit_all_default_via_ffi() {
    let base = temp_base("permit-all");
    let app = CofferApp::new();

    let brief = app
        .create_vault(
            base.to_string_lossy().into_owned(),
            "免费库".into(),
            STRONG_PASSWORD.into(),
        )
        .unwrap();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.vault_uuid.clone())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    session
        .create_item(login_draft("GitHub", "p@ssw0rd-42!"))
        .unwrap();

    let out = base.join("backup.coffer");
    let exported = app
        .export_backup(
            base.join(brief.vault_uuid).to_string_lossy().into_owned(),
            out.to_string_lossy().into_owned(),
        )
        .unwrap();
    assert!(exported.verified, "默认装配导出自检必须通过");
    assert!(out.exists());
}
