//! OPVault 导入 FFI 语义测试（docs/22 §3.4 / §6 T05；docs/23 TC-OPV-01/02/03/
//! 05/07/08——门禁与预检语义属 FFI 边界，故以 FFI 驱动验收）。
//!
//! 门禁落点在 cf-session（`write_guard(LicensedOp::ImportRestore)`，vault.rs）
//! 与 cf-ffi 边界；precheck 只读**无门禁**（TC-OPV-05 语义偏差）。与
//! `cf-importer/tests/opvault_import.rs` 的内核级验收（T02）互补。
//!
//! - **TC-OPV-05**：`precheck_opvault` 只读不触密码，锁定态可预检；结构
//!   字段填充、全量分析字段恒空（语义偏差，docs/22 §2.2.3）；
//! - **TC-OPV-07**：只读许可态（ImportRestore 组）注入 6002/6003 双态 →
//!   `import_opvault` → `Err(6002)` / `Err(6003)`；**拒绝不落半截数据**；
//!   `precheck_opvault` 拒绝态下仍可预检；
//! - **TC-OPV-08**：锁定态 → `import_opvault` → 1001；
//! - **TC-OPV-03**：错误主密码 → 2002（含「密码错误」文案，非 1002），
//!   all-or-nothing 零落库；
//! - **TC-OPV-01/02**：正确主密码（"password"，UTF-8 原始字节进 PBKDF2）
//!   → vendor 样本 3 条全导入，Login 字段逐字段一致。
//!
//! 样本：`cf-importer/tests/fixtures/opvault/test.opvault`（vendor，
//! detunized/opvault-ruby，MIT；password = "password"，iterations = 40000）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use cf_crypto::kdf::KdfParams;
use cf_domain::license::{LicenseDecision, LicenseDenial, LicenseGate, LicensedOp};
use cf_ffi::api::{CofferApp, VaultSession};
use cf_ffi::types::*;
use cf_ffi::FfiError;

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

/// vendor 样本主密码（docs/24 §1.5 实证）。
const OPV_VAULT_PASSWORD: &str = "password";

/// 每测试独立的临时工作目录（pid + 进程内原子计数器）。
fn temp_base(tag: &str) -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("cf-ffi-opv-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// vendor 样本路径（相对 cf-ffi 的 CARGO_MANIFEST_DIR）。
fn opvault_fixture() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cf-importer/tests/fixtures/opvault/test.opvault")
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

/// TC-OPV-05：结构预检只读不触密码——锁定态可预检；结构字段填充、
/// 全量分析字段恒空（语义偏差 docs/22 §2.2.3）。
#[test]
fn tc_opv_05_precheck_locked_structural() {
    let base = temp_base("precheck");
    let brief =
        cf_session::create_vault_with_kdf(&base, "预检库", STRONG_PASSWORD, fast_kdf()).unwrap();
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    // 不解锁直接预检（锁定态可预检）
    let report = session
        .precheck_opvault(opvault_fixture().to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(report.profile_name, "default");
    assert_eq!(report.profile_uuid, "714A14D7017048CC9577AD050FC9C6CA");
    assert_eq!(report.iterations, 40000);
    assert_eq!(report.band_file_count, 4);
    assert_eq!(report.attachment_count, 0);
    assert!(report.other_profiles.is_empty());
    // 全量分析字段属解锁后内容：纯结构预检恒空（TC-OPV-05 语义偏差）
    assert_eq!(report.total_items, 0);
    assert_eq!(report.importable_items, 0);
    assert_eq!(report.folder_count, 0);
    assert_eq!(report.trashed_items, 0);
    assert!(report.category_distribution.is_empty());
    assert!(report.unknown_field_types.is_empty());
    assert!(report.not_imported.is_empty());
}

/// TC-OPV-07：只读许可态拒绝（ImportRestore 组）——注入 6002/6003 双态 →
/// `import_opvault` → `Err(6002)` / `Err(6003)`；**拒绝不落半截数据**；
/// `precheck_opvault` 只读无门禁（拒绝态下仍可预检）。
#[test]
fn tc_opv_07_gate_deny_import_no_partial_precheck_still_ok() {
    // 6002（试用到期）
    let base = temp_base("deny-6002");
    let brief =
        cf_session::create_vault_with_kdf(&base, "拒导库", STRONG_PASSWORD, fast_kdf()).unwrap();
    let app = CofferApp::new();
    app.set_license_gate(expired_gate());
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();

    let fixture = opvault_fixture().to_string_lossy().into_owned();
    let err = err_code(session.import_opvault(
        fixture.clone(),
        OPV_VAULT_PASSWORD.to_owned(),
        base.to_string_lossy().into_owned(),
    ));
    assert_eq!(err, 6002, "import_opvault 只读态（到期）必须 6002");
    assert!(session.list_items(None).unwrap().is_empty(), "被拒导入不得落任何条目");
    // 预检只读无门禁：拒绝态下仍可预检
    let report = session.precheck_opvault(fixture.clone()).unwrap();
    assert_eq!(report.profile_name, "default", "拒绝态下预检仍应成功");

    // 6003（异常退化）
    let base2 = temp_base("deny-6003");
    let brief2 =
        cf_session::create_vault_with_kdf(&base2, "拒导库", STRONG_PASSWORD, fast_kdf()).unwrap();
    let app2 = CofferApp::new();
    app2.set_license_gate(abnormal_gate());
    let session2 = app2
        .open_vault(
            base2.to_string_lossy().into_owned(),
            brief2.uuid.to_string(),
        )
        .unwrap();
    session2.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    let err2 = err_code(session2.import_opvault(
        fixture.clone(),
        OPV_VAULT_PASSWORD.to_owned(),
        base2.to_string_lossy().into_owned(),
    ));
    assert_eq!(err2, 6003, "import_opvault 只读态（异常退化）必须 6003");
    assert!(session2.list_items(None).unwrap().is_empty(), "被拒导入不得落任何条目");
}

/// TC-OPV-08：锁定态 → `import_opvault` → 1001。
#[test]
fn tc_opv_08_locked_1001() {
    let base = temp_base("locked");
    let brief =
        cf_session::create_vault_with_kdf(&base, "锁定库", STRONG_PASSWORD, fast_kdf()).unwrap();
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    // 不解锁直接导入
    let err = err_code(session.import_opvault(
        opvault_fixture().to_string_lossy().into_owned(),
        OPV_VAULT_PASSWORD.to_owned(),
        base.to_string_lossy().into_owned(),
    ));
    assert_eq!(err, 1001, "锁定态导入必须 1001");
}

/// TC-OPV-03：错误主密码 → 2002（含「密码错误」文案，非 1002），
/// all-or-nothing 零落库。
#[test]
fn tc_opv_03_wrong_password_2002_zero_items() {
    let base = temp_base("wrongpw");
    let (_brief, session) = unlocked_session(&base, "导入库");
    let err = session.import_opvault(
        opvault_fixture().to_string_lossy().into_owned(),
        "wrong-password".to_owned(),
        base.to_string_lossy().into_owned(),
    );
    let e = err.unwrap_err();
    assert_eq!(e.code(), 2002, "错误密码必须 2002 ImportFailed");
    let msg = match e {
        FfiError::Coffer { message, .. } => message,
        FfiError::InternalPanic { .. } => panic!("不应是内部 panic"),
    };
    assert!(
        msg.contains("密码错误"),
        "文案须含「密码错误或数据损坏」（非 1002 主密码文案），实际 {msg:?}"
    );
    assert!(session.list_items(None).unwrap().is_empty(), "错误密码不得落任何条目");
}

/// TC-OPV-01/02：正确主密码（UTF-8 原始字节进 PBKDF2，勿追加 NUL）→
/// vendor 样本 3 条全导入，报告完整档 + Login 字段逐字段一致。
#[test]
fn tc_opv_01_02_positive_import_vendor_fields() {
    let base = temp_base("positive");
    let (_brief, session) = unlocked_session(&base, "导入库");
    let r = session
        .import_opvault(
            opvault_fixture().to_string_lossy().into_owned(),
            OPV_VAULT_PASSWORD.to_owned(),
            base.to_string_lossy().into_owned(),
        )
        .unwrap();
    assert_eq!(r.imported_items, 3, "vendor 样本 3 条全导入");

    // 报告完整档（import 管线产出，TC-OPV-05 完整档）
    let report = &r.report;
    assert_eq!(report.total_items, 3);
    assert_eq!(report.importable_items, 3);
    assert_eq!(report.folder_count, 2);
    assert_eq!(report.trashed_items, 0);
    assert_eq!(
        report.category_distribution,
        vec![FfiCategoryCount {
            category: "login".to_owned(),
            count: 3,
        }],
        "3 条 category 001 → Login"
    );

    // 字段抽查：facebook.com username=mark / password=secret
    let items = session.list_items(None).unwrap();
    assert_eq!(items.len(), 3);
    let fb = items.iter().find(|i| i.title == "facebook.com").expect("facebook 条目存在");
    let detail = session.get_item(fb.uuid.clone()).unwrap().expect("facebook 可读");
    let pwd = detail
        .fields
        .iter()
        .find(|f| f.designation == Some(FfiDesignation::Password))
        .expect("密码字段存在");
    let value = session
        .get_field_value(fb.uuid.clone(), pwd.uuid.clone())
        .unwrap();
    assert_eq!(value.as_deref(), Some("secret"), "密码明文逐字节一致");
}
