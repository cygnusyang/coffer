//! FR-1.8 修改主密码验收用例（docs/10 §2，自动化落点冻结于 §0.3）。
//!
//! 每个用例注释标注 TC 编号；判据基准 = `docs/10-v0.2验收用例.md` §2。
//! 判据备注（§2 题头）：docs/01「换密后全库重新加密」已经 docs/09 §3.2
//! D-2 裁决为「仅重封装 header」，本质判据 = **旧密码失效**；
//! db.sqlite 字节不变是方案 A 的可观测推论（TC-CPW-04，lead 已确认采纳）。
//!
//! 走真实建库 / 解锁 / 会话 API（docs/10 §0.4：临时目录、真实路径）。

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft};
use cf_session::{create_vault_with_kdf, open_vault, VaultSession};

/// 测试用快速 KDF（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 主密码 P1（建库密码）。
const P1: &str = "correct-horse-battery-staple-42!";
/// 新密码 P2。
const P2: &str = "portable-copper-drift-lantern-77#";
/// 错误旧密码。
const WRONG: &str = "totally-wrong-password-99!";

/// 唯一临时目录（docs/10 §0.4：测试间零共享）。
fn temp_base(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cf-session-cpw-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// 建库 + 解锁，返回会话与库工作目录。
fn unlocked_vault(tag: &str) -> (VaultSession, PathBuf) {
    let base = temp_base(tag);
    let brief = create_vault_with_kdf(&base, "换密库", P1, fast_kdf()).unwrap();
    let vault_dir = base.join(brief.uuid.to_string());
    let session = open_vault(&vault_dir).unwrap();
    session.unlock(P1).unwrap();
    (session, vault_dir)
}

/// 最小 Login 草稿（username + password 模板必填）。
fn login_draft(title: &str, password: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields: vec![
            FieldDraft {
                name: "用户名".to_owned(),
                value: Some("alice".to_owned()),
                field_type: FieldType::Text,
                designation: Some(Designation::Username),
                section_index: None,
                position: 0,
            },
            FieldDraft {
                name: "密码".to_owned(),
                value: Some(password.to_owned()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

fn header_bytes(vault_dir: &Path) -> Vec<u8> {
    fs::read(vault_dir.join("header.json")).unwrap()
}

fn db_bytes(vault_dir: &Path) -> Vec<u8> {
    fs::read(vault_dir.join("db.sqlite")).unwrap()
}

/// 读磁盘 header 的 JSON 视图。
fn header_json(vault_dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&header_bytes(vault_dir)).unwrap()
}

/// TC-CPW-01 换密后新密码解锁：成功；条目数据逐字段不变。
#[test]
fn new_password_unlocks() {
    let (session, _dir) = unlocked_vault("cpw01");
    let id = session.create_item(&login_draft("GitHub 登录", "hunter2")).unwrap();
    let before = session.get_item(&id).unwrap().unwrap();

    session.change_password(P1, P2, None).unwrap();
    session.lock();

    let info = session.unlock(P2).unwrap();
    assert!(info.item_count >= 1, "换密不触碰数据，条目应可读");

    let after = session.get_item(&id).unwrap().unwrap();
    assert_eq!(after.title.expose(), before.title.expose());
    assert_eq!(after.fields.len(), before.fields.len());
    let pw = after
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .unwrap();
    assert_eq!(pw.value.as_ref().unwrap().expose(), "hunter2");
}

/// TC-CPW-02 旧密码失效：换密后 unlock(P1) → 1002。
#[test]
fn old_password_rejected() {
    let (session, _dir) = unlocked_vault("cpw02");
    session.change_password(P1, P2, None).unwrap();
    session.lock();

    let err = session.unlock(P1).unwrap_err();
    assert_eq!(err.code(), 1002, "旧密码必须失效（D-2 本质判据）");
    assert!(session.unlock(P2).is_ok());
}

/// TC-CPW-03 header 重封装正确性：wrapped_dek / verifier / salt /
/// modified_at 已变；kdf 其余参数与 vault_uuid 不变。
#[test]
fn header_rewrapped_fields() {
    let (session, dir) = unlocked_vault("cpw03");
    let before = header_json(&dir);

    session.change_password(P1, P2, None).unwrap();

    let after = header_json(&dir);
    assert_ne!(
        after["wrapped_dek"]["ct_b64"], before["wrapped_dek"]["ct_b64"],
        "wrapped_dek 必须重封装"
    );
    assert_ne!(after["verifier"]["ct_b64"], before["verifier"]["ct_b64"], "verifier 必须重封装");
    assert_ne!(after["kdf"]["salt_b64"], before["kdf"]["salt_b64"], "盐必须换新");
    assert!(
        after["modified_at"].as_i64().unwrap() >= before["modified_at"].as_i64().unwrap(),
        "modified_at 必须更新"
    );
    // 不变项
    assert_eq!(after["vault_uuid"], before["vault_uuid"]);
    assert_eq!(after["kdf"]["m_cost_kib"], before["kdf"]["m_cost_kib"]);
    assert_eq!(after["kdf"]["t_cost"], before["kdf"]["t_cost"]);
    assert_eq!(after["kdf"]["p_cost"], before["kdf"]["p_cost"]);
    assert_eq!(after["kdf"]["algo"], before["kdf"]["algo"]);
    assert_eq!(after["display_name"], before["display_name"]);
}

/// TC-CPW-04 db 字节不变（方案 A 可观测判据，lead 已确认采纳）：
/// 换密前后 db.sqlite 字节完全相等。
#[test]
fn db_bytes_untouched() {
    let (session, dir) = unlocked_vault("cpw04");
    let before = db_bytes(&dir);
    assert!(!before.is_empty());

    session.change_password(P1, P2, None).unwrap();

    assert_eq!(db_bytes(&dir), before, "换密不得触碰 db.sqlite 一个字节");
}

/// TC-CPW-05 错误旧密码拒绝且状态不变：1002；header 字节级不变；
/// 此后 P1 仍可正常解锁。
#[test]
fn wrong_old_password_header_untouched() {
    let (session, dir) = unlocked_vault("cpw05");
    let before = header_bytes(&dir);

    let err = session.change_password(WRONG, P2, None).unwrap_err();
    assert_eq!(err.code(), 1002);
    assert_eq!(header_bytes(&dir), before, "header 必须字节级不变");

    session.lock();
    assert!(session.unlock(P1).is_ok(), "P1 仍可正常解锁");
}

/// TC-CPW-06 新密码弱拒绝先于文件操作：1010；header 字节不变；P1 仍可解锁。
#[test]
fn weak_new_password_rejected_first() {
    let (session, dir) = unlocked_vault("cpw06");
    let before = header_bytes(&dir);

    let err = session.change_password(P1, "123456", None).unwrap_err();
    assert_eq!(err.code(), 1010, "zxcvbn <3 → WeakPassword");
    assert_eq!(header_bytes(&dir), before, "门禁必须先于任何文件操作");
    assert!(!dir.join(".header.json.tmp").exists(), "不得有临时文件残留");

    session.lock();
    assert!(session.unlock(P1).is_ok());
}

/// TC-CPW-07 锁定态门禁：change_password → 1001。
#[test]
fn locked_rejected() {
    let base = temp_base("cpw07");
    let brief = create_vault_with_kdf(&base, "锁定库", P1, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    assert!(!session.is_unlocked());

    let err = session.change_password(P1, P2, None).unwrap_err();
    assert_eq!(err.code(), 1001);
}

/// TC-CPW-08 原子性：write_header 前注入失败（目录置只读 → rename 必败）
/// → 返回错误；旧 header 完整；P1 仍可解锁；无 `.header.json.tmp` 残留。
///
/// root 环境下 chmod 不构成写入屏障——探测到写仍成功则跳过注入断言
/// （CI 用户态有效）。
#[test]
fn midway_failure_atomic() {
    let (session, dir) = unlocked_vault("cpw08");
    let before = header_bytes(&dir);

    let mut perms = fs::metadata(&dir).unwrap().permissions();
    let original_mode = perms.mode();
    perms.set_mode(0o555);
    fs::set_permissions(&dir, perms).unwrap();

    if fs::metadata(&dir).unwrap().permissions().mode() == 0o555 {
        let err = session.change_password(P1, P2, None).unwrap_err();
        assert!(
            matches!(err, cf_domain::CfError::Io(_) | cf_domain::CfError::Corrupted(_)),
            "写失败应报 Io/Corrupted，实际 {err:?}"
        );
        assert_eq!(header_bytes(&dir), before, "旧 header 必须完整");
        assert!(
            !dir.join(".header.json.tmp").exists(),
            "rename 失败不得残留 .tmp（cf-format 原子写清理纪律）"
        );
    }

    // 收尾恢复权限（无论是否注入成功）
    let mut perms = fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(original_mode);
    fs::set_permissions(&dir, perms).unwrap();

    session.lock();
    assert!(session.unlock(P1).is_ok(), "失败换密后 P1 仍可解锁");
}

/// TC-CPW-09 bio 封装不受影响：启用 bio → 换密 → lock → unlock_with_bio
/// 成功；header 的 wrapped_dek_bio 字段不变（K_bio 封装 DEK 本身）。
#[test]
fn bio_unwrap_survives_change() {
    let (session, dir) = unlocked_vault("cpw09");
    let k_bio = cf_session::new_biometric_unwrap_key().unwrap();
    session
        .enable_biometric(P1, k_bio.as_bytes())
        .unwrap();
    let bio_before = header_json(&dir)["biometric_wrap"].clone();

    session.change_password(P1, P2, None).unwrap();

    let bio_after = header_json(&dir)["biometric_wrap"].clone();
    assert_eq!(
        bio_after["wrapped_dek_b64"], bio_before["wrapped_dek_b64"],
        "wrapped_dek_bio 不得被换密触碰（K_bio 封装 DEK，与 KEK 无关）"
    );

    session.lock();
    assert!(
        session.unlock_with_biometric(k_bio.as_bytes()).is_ok(),
        "bio 解锁照常可用"
    );
    session.lock();
    assert!(session.unlock(P2).is_ok());
}

/// TC-CPW-10 换密 + 升级 KDF 档位：header.kdf 更新为 new_kdf；
/// P2 解锁走新参数；数据可读。
#[test]
fn kdf_upgrade_with_change() {
    let (session, dir) = unlocked_vault("cpw10");
    let id = session.create_item(&login_draft("GitHub 登录", "hunter2")).unwrap();
    let new_kdf = KdfParams::new(16 * 1024, 2, 1).unwrap();

    session.change_password(P1, P2, Some(new_kdf)).unwrap();

    let kdf = header_json(&dir)["kdf"].clone();
    assert_eq!(kdf["m_cost_kib"], serde_json::json!(16 * 1024));
    assert_eq!(kdf["t_cost"], serde_json::json!(2));
    assert_eq!(kdf["p_cost"], serde_json::json!(1));

    session.lock();
    session.unlock(P2).unwrap();
    let details = session.get_item(&id).unwrap().unwrap();
    assert_eq!(details.title.expose(), "GitHub 登录", "新参数下数据可读");
}

/// TC-CPW-11 换密 × 备份回环：export_backup → restore → unlock(P2)
/// 成功、unlock(P1) 拒绝（新 header 进入备份）。
#[test]
fn backup_after_change_uses_new_password() {
    let (session, dir) = unlocked_vault("cpw11");
    session.create_item(&login_draft("备份回环", "hunter2")).unwrap();

    session.change_password(P1, P2, None).unwrap();

    let base = dir.parent().unwrap().join("cpw11-restore");
    let out_path = dir.parent().unwrap().join("cpw11-backup.coffer");
    cf_exporter::export_backup(&dir, &out_path).unwrap();
    let restored = cf_exporter::restore_backup(&out_path, &base).unwrap();

    let session2 = open_vault(&restored).unwrap();
    let err = session2.unlock(P1).unwrap_err();
    assert_eq!(err.code(), 1002, "备份携带的是换密后 header，旧密码必须失效");
    assert!(session2.unlock(P2).is_ok(), "P2 解锁恢复的库");
    let _ = fs::remove_dir_all(&base);
}

/// TC-CPW-12 并发换密：两线程同持 session 并发 change_password →
/// 实现层串行化（header/状态互斥锁）：至少一个成功，库始终可用、
/// 数据无损坏、最终密码可解锁。
#[test]
fn concurrent_change_no_corruption() {
    use std::sync::Arc;

    let (session, dir) = unlocked_vault("cpw12");
    session.create_item(&login_draft("并发换密", "hunter2")).unwrap();
    let session = Arc::new(session);

    let s1 = Arc::clone(&session);
    let t1 = std::thread::spawn(move || s1.change_password(P1, P2, None));
    let s2 = Arc::clone(&session);
    let t2 = std::thread::spawn(move || s2.change_password(P1, P2, None));

    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();
    // 串行化语义：两线程可能都基于同一旧 header 快照重封装（后写覆盖
    // 前写），也可能后者因前写已使 header 变更而失败——判据核心是
    // 「至少一个成功、库无损坏、最终密码可解锁」。
    let ok_count = usize::from(r1.is_ok()) + usize::from(r2.is_ok());
    assert!(ok_count >= 1, "至少一个换密成功：r1={r1:?} r2={r2:?}");

    session.lock();
    let info = session.unlock(P2).unwrap();
    assert!(info.item_count >= 1, "数据可读（无损坏）");
    let _ = fs::remove_dir_all(dir.parent().unwrap());
}
