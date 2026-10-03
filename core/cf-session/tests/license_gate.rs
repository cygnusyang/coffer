//! FR-15 只读门禁测试（`docs/12-注册激活测试计划.md` §2.4 TC-GATE；
//! 矩阵定义 `docs/03-详细设计.md` §14.6）。
//!
//! 双态 FakeGate 注入（试用到期 → 6002 / 异常退化 → 6003），验证：
//! 允许面（TC-GATE-01）、拒绝面逐组（02/03）、拒绝码区分（07）、
//! 拒绝不落半截数据（08）、激活后解除（09）、开源默认 PermitAll
//! （10）、锁定态 1001 优先（11）。
//!
//! TC-GATE-06（Passkey 断言白名单）随 v0.5.0 Passkey 实现补；
//! TC-GATE-04/05（应用级 import/export 包）在 cf-ffi tests；
//! TC-GATE-12 为统一入口审读勾稽（`VaultSession::write_guard`）。

use std::path::PathBuf;
use std::sync::Arc;

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft};
use cf_domain::license::{LicenseDecision, LicenseDenial, LicenseGate, LicensedOp, PermitAllGate};
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::VaultSession;

const STRONG: &str = "correct-horse-battery-staple-42!";

fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-session-license-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库 + 开会话 + 解锁 + 种子一条目（门禁默认 PermitAll，写操作放行）。
fn seeded_session(tag: &str) -> (PathBuf, VaultSession) {
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(&base, tag, STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap();
    session.create_item(&login_draft("种子条目")).unwrap();
    (base, session)
}

fn login_draft(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields: vec![
            FieldDraft {
                name: "用户名".to_owned(),
                value: Some("alice@example.com".to_owned()),
                field_type: FieldType::Text,
                designation: Some(Designation::Username),
                section_index: None,
                position: 0,
            },
            FieldDraft {
                name: "密码".to_owned(),
                value: Some("hunter2-secret".to_owned()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
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
    Arc::new(FixedGate(LicenseDecision::Deny(
        LicenseDenial::TrialExpired,
    )))
}

fn abnormal_gate() -> Arc<dyn LicenseGate> {
    Arc::new(FixedGate(LicenseDecision::Deny(
        LicenseDenial::StateUnavailable,
    )))
}

/// 断言错误码为 6002 / 6003（拒绝码，`docs/03` §12）。
fn assert_deny_code<T: std::fmt::Debug>(
    result: Result<T, cf_domain::CfError>,
    expected: u16,
    label: &str,
) {
    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        expected,
        "{label} 拒绝码不符：{err:?}（应为 {expected}）"
    );
}

/// TC-GATE-01：只读态允许面——查看 / 搜索 / 历史 / 审计 / 体检全部成功。
#[test]
fn readonly_allow_surface() {
    let (_base, session) = seeded_session("allow");
    session.set_license_gate(expired_gate());

    // 查看与搜索
    let items = session.list_items(None).unwrap();
    assert_eq!(items.len(), 1);
    let summary = &items[0];
    assert_eq!(summary.title, "种子条目");
    let item_id = summary.uuid.to_string();
    assert!(session.get_item(&item_id).unwrap().is_some());
    let found = session.search("种子").unwrap();
    assert_eq!(found.len(), 1);

    // 字段明文（复制路径）
    let details = session.get_item(&item_id).unwrap().unwrap();
    let field = details
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("密码字段存在");
    let value = session.get_field_value(&item_id, &field.uuid).unwrap();
    assert_eq!(value.as_ref().map(|s| s.expose()), Some("hunter2-secret"));

    // 历史与审计日志
    assert!(session.list_history(&item_id).unwrap().is_empty());
    assert!(session.recent_audit_events(None, None).unwrap().is_empty());

    // 体检（允许面：只读无副作用）
    session.run_watchtower().unwrap();

    // TOTP 展示路径：无 TOTP 条目 → 1011（允许面：门禁不拦展示路径，
    // 03 §14.6 允许组「复制与展示」）
    let totp_err = session.totp_code(&item_id).unwrap_err();
    assert_eq!(
        totp_err.code(),
        1011,
        "TOTP 展示路径不得被许可门禁拦截：{totp_err:?}"
    );
}

/// TC-GATE-02：拒绝面——条目写逐方法 6002。
#[test]
fn readonly_deny_item_writes() {
    let (_base, session) = seeded_session("deny-item");
    session.set_license_gate(expired_gate());
    let item_id = session.list_items(None).unwrap()[0].uuid.to_string();

    assert_deny_code(
        session.create_item(&login_draft("新条目")),
        6002,
        "create_item",
    );
    let draft = login_draft("种子条目");
    assert_deny_code(session.update_item(&item_id, &draft), 6002, "update_item");
    assert_deny_code(
        session.update_item_with_totp(&item_id, &draft, cf_domain::totp_data::TotpUpdate::Keep),
        6002,
        "update_item_with_totp",
    );
    assert_deny_code(
        session.delete_item(&item_id, false),
        6002,
        "delete_item(soft)",
    );
    assert_deny_code(
        session.delete_item(&item_id, true),
        6002,
        "delete_item(hard)",
    );
    assert_deny_code(session.restore_item(&item_id), 6002, "restore_item");
    assert_deny_code(session.set_favorite(&item_id, true), 6002, "set_favorite");
    assert_deny_code(
        session.restore_history(&item_id, "any-uuid"),
        6002,
        "restore_history",
    );
    assert_deny_code(
        session.add_attachment(&item_id, "a.txt", b"content"),
        6002,
        "add_attachment",
    );
    assert_deny_code(
        session.remove_attachment("nonexistent"),
        6002,
        "remove_attachment",
    );
}

/// TC-GATE-03：拒绝面——库级写 6002（改主密码 / bio 开关）。
#[test]
fn readonly_deny_vault_writes() {
    let (_base, session) = seeded_session("deny-vault");
    session.set_license_gate(expired_gate());

    // 改主密码：门禁拒绝先于旧密码校验（不跑 KDF）
    assert_deny_code(
        session.change_password(STRONG, "another-strong-passphrase-99!", None),
        6002,
        "change_password",
    );
    assert_deny_code(
        session.enable_biometric(STRONG, &[0u8; 32]),
        6002,
        "enable_biometric",
    );
    assert_deny_code(session.disable_biometric(), 6002, "disable_biometric");
}

/// TC-GATE-02/05（会话侧）：导入与数据出口拒绝——import_csv / export_csv。
#[test]
fn readonly_deny_import_and_export() {
    let (base, session) = seeded_session("deny-io");
    session.set_license_gate(expired_gate());

    let missing = base.join("nope.csv");
    assert_deny_code(session.import_csv(&missing), 6002, "import_csv");

    let out = base.join("out.csv");
    assert_deny_code(session.export_csv(&out), 6002, "export_csv");
    assert!(
        !out.exists(),
        "被拒绝的导出不得产生输出文件（不落半截数据）"
    );
}

/// TC-GATE（拒绝面补充）：跨库复制是对目标库的条目写，dst 门禁拒绝 6002。
#[test]
fn readonly_deny_cross_copy_writes() {
    let (_base_a, src) = seeded_session("cc-src");
    let (_base_b, dst) = seeded_session("cc-dst");
    // dst 注入到期 gate（src 保持 PermitAll）
    dst.set_license_gate(expired_gate());
    let item_id = src.list_items(None).unwrap()[0].uuid.to_string();

    assert_deny_code(
        cf_session::copy_item(&src, &item_id, &dst),
        6002,
        "copy_item(dst denied)",
    );
    // 目标库零写入
    assert_eq!(dst.list_items(None).unwrap().len(), 1);
}

/// TC-GATE-07：拒绝码区分——到期（6002）vs 异常退化（6003），同一操作。
#[test]
fn deny_code_6002_vs_6003() {
    let (_base, session) = seeded_session("codes");

    session.set_license_gate(expired_gate());
    assert_deny_code(session.create_item(&login_draft("x")), 6002, "expired gate");

    session.set_license_gate(abnormal_gate());
    assert_deny_code(
        session.create_item(&login_draft("x")),
        6003,
        "abnormal gate",
    );
}

/// TC-GATE-08：拒绝不落半截数据——拒绝前后库内容一致。
#[test]
fn denied_write_no_partial_state() {
    let (_base, session) = seeded_session("no-partial");
    let item_id = session.list_items(None).unwrap()[0].uuid.to_string();
    let before = session.get_item(&item_id).unwrap().unwrap();
    let count_before = session.list_items(None).unwrap().len();

    session.set_license_gate(expired_gate());
    let draft = login_draft("改名尝试");
    let _ = session.update_item(&item_id, &draft);
    let _ = session.create_item(&login_draft("新增尝试"));
    let _ = session.delete_item(&item_id, true);

    session.set_license_gate(Arc::new(PermitAllGate));
    let after = session.get_item(&item_id).unwrap().unwrap();
    assert_eq!(session.list_items(None).unwrap().len(), count_before);
    assert_eq!(after.title.expose(), before.title.expose());
    assert_eq!(after.fields.len(), before.fields.len());
}

/// TC-GATE-09：激活后门禁解除——换回 PermitAll 后原被拒操作成功。
#[test]
fn activation_restores_writes() {
    let (_base, session) = seeded_session("restore");
    session.set_license_gate(expired_gate());
    assert_deny_code(session.create_item(&login_draft("x")), 6002, "denied");

    // 「激活」：注入放行 gate（官方产物中即 cf-license 判定转为 active）
    session.set_license_gate(Arc::new(PermitAllGate));
    let new_id = session.create_item(&login_draft("激活后")).unwrap();
    assert!(session.get_item(&new_id).unwrap().is_some());
}

/// TC-GATE-10：开源默认 PermitAllGate——不注入时全部写路径照常。
#[test]
fn permit_all_default() {
    let (base, session) = seeded_session("permit-all");
    // seeded_session 已覆盖 create_item；此处补其余代表面
    let item_id = session.list_items(None).unwrap()[0].uuid.to_string();
    session.set_favorite(&item_id, true).unwrap();
    let draft = login_draft("种子条目");
    session.update_item(&item_id, &draft).unwrap();
    session.add_attachment(&item_id, "a.txt", b"hello").unwrap();

    let out = base.join("export.csv");
    session.export_csv(&out).unwrap();
    assert!(out.exists());
}

/// TC-GATE-11：锁定态门禁优先——未解锁直接写仍 1001，而非 6xxx。
#[test]
fn locked_state_takes_priority_over_license() {
    let base = temp_dir("locked-first");
    let brief = create_vault_with_kdf(&base, "locked-first", STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    session.set_license_gate(expired_gate());

    let err = session.create_item(&login_draft("x")).unwrap_err();
    assert_eq!(err.code(), 1001, "锁定态必须 1001 优先于许可拒绝");
}
