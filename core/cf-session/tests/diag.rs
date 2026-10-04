//! FR-14.4 本地诊断会话层测试（docs/22 §2.4 / §3.3；docs/23 §1.5 TC-DIAG 组）。
//!
//! 覆盖（与 `cf-ffi/tests/diag_ffi_semantics.rs` 的跨 FFI 契约面互补）：
//!
//! - **TC-DIAG-01**：正向字段集——条目数 / 附件数 / 库创建时间 / 最后备份
//!   时间 / uuid 前缀；条目数 = `list_items` 计数一致；
//! - **TC-DIAG-03**：字段集白名单——`DiagnosticSummary` 编译期穷尽构造钉住
//!   字段集，多一个敏感字段（密码明文 / 标题 / secret / 密钥材料）即编译失败；
//! - **TC-DIAG-04**：锁定态 → 1001（锁定态下绝不展示条目级数据）；
//! - **TC-DIAG-05**：允许面无门禁——注入 6002/6003 只读态仍成功；
//! - **TC-DIAG-06**：空库条目数 = 0；未备份 `last_backup_at = None` / 备份
//!   打点后回读 `Some`。

use std::path::PathBuf;
use std::sync::Arc;

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft};
use cf_domain::license::{LicenseDecision, LicenseDenial, LicenseGate, LicensedOp, PermitAllGate};
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::DiagnosticSummary;
use cf_session::VaultSession;
use rusqlite::Connection;

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
        "cf-session-diag-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库 + 开会话 + 解锁，返回 (base, vault_dir, session)。
fn unlocked_session(tag: &str) -> (PathBuf, PathBuf, VaultSession) {
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(&base, tag, STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap();
    (base, dir, session)
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

/// 双态测试 gate（对齐 `tests/license_gate.rs`）。
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

/// 读取磁盘 header（Current）以取得权威 created_at 对照。
fn disk_header_created_at(dir: &std::path::Path) -> i64 {
    match cf_format::open_container(dir).expect("磁盘 header 可读") {
        cf_format::OpenOutcome::Current(h) => h.created_at,
        other => panic!("库应为 Current：{other:?}"),
    }
}

/// TC-DIAG-01：正向字段集——条目数 / 附件数 / 库创建时间 / 最后备份时间 /
/// uuid 前缀；条目数 = `list_items` 计数一致。
#[test]
fn 正向字段集() {
    let (_base, dir, session) = unlocked_session("pos");
    let id1 = session.create_item(&login_draft("第一项")).unwrap();
    session.add_attachment(&id1, "a.txt", b"hello").unwrap();
    session.create_item(&login_draft("第二项")).unwrap();

    let sum = session.diagnostic_summary().unwrap();
    assert_eq!(sum.item_count, 2, "条目数 = meta.item_count");
    assert_eq!(
        sum.item_count as usize,
        session.list_items(None).unwrap().len(),
        "条目数须与 list_items 计数一致（TC-DIAG-01）"
    );
    assert_eq!(sum.attachment_count, 1, "附件数 = attachments 行数");
    assert_eq!(
        sum.vault_created_at,
        disk_header_created_at(&dir),
        "库创建时间 = header.created_at"
    );
    assert_eq!(sum.last_backup_at, None, "从未备份 → None");
    let full = session.vault_uuid().to_string();
    assert_eq!(sum.vault_uuid_prefix.len(), 8, "前缀为固定长度（冻结契约）");
    assert_eq!(sum.vault_uuid_prefix, &full[..8], "前缀 = uuid 前 8 字符");
}

/// TC-DIAG-03：字段集白名单（可断言接口面）——`DiagnosticSummary` 只含
/// 计数 / 时间 / uuid 前缀类字段，以编译期穷尽构造钉住字段集，多一个
/// 敏感字段（密码明文 / 标题 / secret / 密钥材料）即编译失败。
#[test]
fn 字段集白名单钉住无敏感字段() {
    let s = DiagnosticSummary {
        item_count: 3,
        attachment_count: 1,
        vault_created_at: 1_700_000_000,
        last_backup_at: Some(1_700_000_100),
        vault_uuid_prefix: "0195b0b5".to_owned(),
    };
    let DiagnosticSummary {
        item_count,
        attachment_count,
        vault_created_at,
        last_backup_at,
        vault_uuid_prefix,
    } = s;
    assert_eq!(item_count, 3);
    assert_eq!(attachment_count, 1);
    assert_eq!(vault_created_at, 1_700_000_000);
    assert_eq!(last_backup_at, Some(1_700_000_100));
    assert_eq!(vault_uuid_prefix, "0195b0b5");
}

/// TC-DIAG-04：锁定态 → 1001（锁定态下绝不展示条目级数据）。
#[test]
fn 锁定态报1001() {
    let base = temp_dir("locked");
    let brief = create_vault_with_kdf(&base, "锁定库", STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();

    let err = session.diagnostic_summary().unwrap_err();
    assert_eq!(err.code(), 1001, "锁定态诊断必须 1001：{err:?}");
}

/// TC-DIAG-05：允许面无门禁——注入 6002/6003 只读态，诊断仍成功
/// （与 `list_items` 同类，docs/22 §5）。
#[test]
fn 允许面无门禁_注入只读门禁仍成功() {
    let (_base, _dir, session) = unlocked_session("allow");
    session.create_item(&login_draft("一条")).unwrap();

    // 到期态 → 6002（对写路径），诊断不拦
    session.set_license_gate(expired_gate());
    let sum = session.diagnostic_summary().unwrap();
    assert_eq!(sum.item_count, 1);

    // 异常退化态 → 6003（对写路径），诊断不拦
    session.set_license_gate(abnormal_gate());
    let sum2 = session.diagnostic_summary().unwrap();
    assert_eq!(sum2.item_count, 1);

    // 放行态照常
    session.set_license_gate(Arc::new(PermitAllGate));
    assert!(session.diagnostic_summary().is_ok());
}

/// TC-DIAG-06：空库边界——条目数 = 0、附件数 = 0、未备份 = None；前缀仍有效。
#[test]
fn 空库条目数为0() {
    let (_base, _dir, session) = unlocked_session("empty");
    let sum = session.diagnostic_summary().unwrap();
    assert_eq!(sum.item_count, 0);
    assert_eq!(sum.attachment_count, 0);
    assert_eq!(sum.last_backup_at, None);
    assert_eq!(sum.vault_uuid_prefix.len(), 8);
}

/// TC-DIAG-06 补：备份打点后 `last_backup_at` 回读为 `Some`（直接写
/// meta 表模拟成功备份打点，i64-LE BLOB，对齐 MetaRepo::set_i64 编码）。
#[test]
fn 备份时间回读() {
    let (_base, dir, session) = unlocked_session("backup");
    let db = dir.join("db.sqlite");
    let conn = Connection::open(&db).unwrap();
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('last_backup_at', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![1_700_000_000i64.to_le_bytes().to_vec()],
    )
    .unwrap();
    drop(conn);

    let sum = session.diagnostic_summary().unwrap();
    assert_eq!(sum.last_backup_at, Some(1_700_000_000));
}
