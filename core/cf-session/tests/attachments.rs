//! 附件会话门面集成测试（FR-9.3 / FR-9.4，docs/15 §3.1.2 / §3.1.5）。
//!
//! 判据基准 = 方案 §3.1.5 测试要点 1~3、5：回环逐字节、超限快失败无残留、
//! 锁定态与不存在路径错误码、硬删级联 / 软删保留。走真实建库 / 解锁 /
//! 会话 API，快速 KDF 档位控制运行时长。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::item::{ItemDraft, ItemState};
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::VaultSession;
use cf_store::MAX_ATTACHMENT_BYTES;

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG: &str = "correct-horse-battery-staple-42!";

/// 测试用快速 KDF 档位（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 唯一临时目录（pid + 进程内原子计数器，测试间零共享）。
fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "cf-session-attach-{tag}-{}-{seq}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库并解锁。
fn unlocked_vault(base: &Path, tag: &str) -> VaultSession {
    let brief = create_vault_with_kdf(base, tag, STRONG, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    session.unlock(STRONG).unwrap();
    session
}

/// 最小 Login 草稿（含类别必填的 username / password 字段，附件测试
/// 只关心条目行存在）。
fn minimal_draft(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields: vec![
            cf_domain::item::FieldDraft {
                name: "用户名".to_owned(),
                value: Some("alice@example.com".to_owned()),
                field_type: cf_domain::field::FieldType::Text,
                designation: Some(cf_domain::field::Designation::Username),
                section_index: None,
                position: 0,
            },
            cf_domain::item::FieldDraft {
                name: "密码".to_owned(),
                value: Some("hunter2-secret".to_owned()),
                field_type: cf_domain::field::FieldType::Concealed,
                designation: Some(cf_domain::field::Designation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

/// 附件旁路目录（vault_dir/attachments）。
fn attachments_dir(session: &VaultSession) -> PathBuf {
    session.vault_dir().join("attachments")
}

// ------------------------------------------------ 判据：add → list → read 回环

/// 测试要点 1：add → list → read_content 回环逐字节相等；filename
/// 中文 / 空格 / emoji 往返。
#[test]
fn 附件回环逐字节一致且文件名往返() {
    let base = temp_dir("roundtrip");
    let session = unlocked_vault(&base, "回环库");
    let item_id = session.create_item(&minimal_draft("附件回环条目")).unwrap();

    let plain = b"ssh private key bytes \xe2\x9c\x93 \xf0\x9f\x94\x90".to_vec();
    let filename = "私钥 文件 ✅.md";
    let info = session.add_attachment(&item_id, filename, &plain).unwrap();

    assert!(!info.uuid.is_empty());
    assert_eq!(info.item_uuid, item_id);
    assert_eq!(info.filename, filename, "filename 应明文往返");
    assert_eq!(info.size_bytes, plain.len() as i64);

    let listed = session.list_attachments(&item_id).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], info, "list 与 add 返回的元数据应一致");

    let got = session.read_attachment(&info.uuid).unwrap();
    assert_eq!(got, plain, "附件内容必须逐字节一致");

    // 旁路文件确实落在 vault_dir/attachments/<uuid> 下
    assert!(attachments_dir(&session).join(&info.uuid).is_file());
}

/// 测试要点 1 补充：同文件名不判重（1PUX 导入同语义，方案 §3.1.2
/// 边界声明钉住）。
#[test]
fn 同文件名不判重() {
    let base = temp_dir("dup_name");
    let session = unlocked_vault(&base, "重名库");
    let item_id = session.create_item(&minimal_draft("重名条目")).unwrap();

    session
        .add_attachment(&item_id, "same.bin", b"first")
        .unwrap();
    session
        .add_attachment(&item_id, "same.bin", b"second")
        .unwrap();

    let listed = session.list_attachments(&item_id).unwrap();
    assert_eq!(listed.len(), 2, "同文件名应各自成行，不判重");
}

/// 测试要点 2：超限（MAX + 1 字节）→ 1012，且 `attachments/` 目录
/// 无残留文件（门面预检先于任何 IO）。
#[test]
fn 超限附件快失败且无文件残留() {
    let base = temp_dir("over_limit");
    let session = unlocked_vault(&base, "超限库");
    let item_id = session.create_item(&minimal_draft("超限条目")).unwrap();

    let over: Vec<u8> = vec![0u8; MAX_ATTACHMENT_BYTES + 1];
    let err = session
        .add_attachment(&item_id, "big.bin", &over)
        .unwrap_err();
    assert_eq!(err.code(), 1012, "超限应报 Validation(1012)：{err:?}");

    // 快失败先于任何 IO：目录未建立（或为空），零残留
    let dir = attachments_dir(&session);
    assert!(
        !dir.exists() || fs::read_dir(&dir).unwrap().next().is_none(),
        "超限拒绝后 attachments/ 不得残留文件"
    );
}

// ------------------------------------------------ 判据：错误码（负路径）

/// 测试要点 3（前半）：锁定态四方法全部 1001。
#[test]
fn 锁定态四方法全部拒绝() {
    let base = temp_dir("locked");
    let brief = create_vault_with_kdf(&base, "锁定附件库", STRONG, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

    assert_eq!(
        session.list_attachments("no-item").unwrap_err().code(),
        1001
    );
    assert_eq!(
        session
            .add_attachment("no-item", "x.bin", b"data")
            .unwrap_err()
            .code(),
        1001
    );
    assert_eq!(session.read_attachment("no-uuid").unwrap_err().code(), 1001);
    assert_eq!(
        session.remove_attachment("no-uuid").unwrap_err().code(),
        1001
    );
}

/// 测试要点 3（中）：条目不存在 add / list → 1011。
#[test]
fn 条目不存在时添加与列出报条目不存在() {
    let base = temp_dir("no_item");
    let session = unlocked_vault(&base, "无条目库");

    let err = session
        .add_attachment("00000000-0000-0000-0000-000000000000", "x.bin", b"d")
        .unwrap_err();
    assert_eq!(
        err.code(),
        1011,
        "条目不存在应报 ItemNotFound(1011)：{err:?}"
    );
    let err = session
        .list_attachments("00000000-0000-0000-0000-000000000000")
        .unwrap_err();
    assert_eq!(err.code(), 1011);
}

/// 测试要点 3（中）：附件行不存在 read / remove → 1012。
#[test]
fn 附件行不存在时读取与删除报校验错误() {
    let base = temp_dir("no_row");
    let session = unlocked_vault(&base, "无行库");

    let err = session.read_attachment("no-such-uuid").unwrap_err();
    assert_eq!(err.code(), 1012, "行不存在应报 Validation(1012)：{err:?}");
    let err = session.remove_attachment("no-such-uuid").unwrap_err();
    assert_eq!(err.code(), 1012);
}

/// 测试要点 3（后）：旁路文件被外部删除 → read → 1005 Corrupted。
#[test]
fn 旁路文件被外部删除读取报损坏() {
    let base = temp_dir("file_missing");
    let session = unlocked_vault(&base, "缺文件库");
    let item_id = session.create_item(&minimal_draft("缺文件条目")).unwrap();
    let info = session
        .add_attachment(&item_id, "gone.bin", b"payload")
        .unwrap();

    fs::remove_file(attachments_dir(&session).join(&info.uuid)).unwrap();

    let err = session.read_attachment(&info.uuid).unwrap_err();
    assert_eq!(err.code(), 1005, "行在文件无应报 Corrupted(1005)：{err:?}");
}

/// 删除附件：行与旁路文件均消失；再读 → 1012。
#[test]
fn 删除附件后行与文件均消失() {
    let base = temp_dir("remove");
    let session = unlocked_vault(&base, "删除库");
    let item_id = session.create_item(&minimal_draft("删除条目")).unwrap();
    let info = session
        .add_attachment(&item_id, "bye.bin", b"payload")
        .unwrap();

    session.remove_attachment(&info.uuid).unwrap();

    assert!(!attachments_dir(&session).join(&info.uuid).exists());
    let err = session.read_attachment(&info.uuid).unwrap_err();
    assert_eq!(err.code(), 1012, "删除后行应消失：{err:?}");
    assert!(session.list_attachments(&item_id).unwrap().is_empty());
}

// ------------------------------------------------ 判据：硬删级联 / 软删保留

/// 测试要点 5（硬删）：条目挂 2 附件 → hard delete → 行消失**且两个
/// 旁路文件消失**（既有缺口修复：ON DELETE CASCADE 只级联 DB 行）。
#[test]
fn 硬删条目级联删除附件旁路文件() {
    let base = temp_dir("hard_cascade");
    let session = unlocked_vault(&base, "硬删库");
    let item_id = session.create_item(&minimal_draft("硬删条目")).unwrap();
    let a = session.add_attachment(&item_id, "a.bin", b"aaa").unwrap();
    let b = session.add_attachment(&item_id, "b.bin", b"bbb").unwrap();

    session.delete_item(&item_id, true).unwrap();

    assert!(
        !attachments_dir(&session).join(&a.uuid).exists(),
        "附件 a 旁路文件应随硬删消失"
    );
    assert!(
        !attachments_dir(&session).join(&b.uuid).exists(),
        "附件 b 旁路文件应随硬删消失"
    );

    // DB 行同样消失：新建同名条目不可达旧行，直接断言附件目录只剩空
    let leftovers: Vec<_> = fs::read_dir(attachments_dir(&session))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name())
        .collect();
    assert!(leftovers.is_empty(), "附件目录不得残留：{leftovers:?}");
}

/// 测试要点 5（软删）：软删 → 文件仍在；恢复后附件可读（现状语义钉住）。
#[test]
fn 软删条目附件保留恢复后可读() {
    let base = temp_dir("soft_keep");
    let session = unlocked_vault(&base, "软删库");
    let item_id = session.create_item(&minimal_draft("软删条目")).unwrap();
    let plain = b"keep me".to_vec();
    let info = session
        .add_attachment(&item_id, "keep.bin", &plain)
        .unwrap();

    session.delete_item(&item_id, false).unwrap();
    assert!(
        attachments_dir(&session).join(&info.uuid).is_file(),
        "软删不得动附件旁路文件"
    );
    // 回收站态仍可读（UI 在回收站详情可达，现状语义）
    assert_eq!(session.read_attachment(&info.uuid).unwrap(), plain);

    session.restore_item(&item_id).unwrap();
    let listed = session.list_attachments(&item_id).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(session.read_attachment(&info.uuid).unwrap(), plain);
}

/// 测试要点（方案 §3.1.2 边界声明钉住）：add_attachment 只校验条目
/// 存在，**不限制条目状态**——Trashed 态条目仍可添加附件。
#[test]
fn 回收站条目仍可添加附件() {
    let base = temp_dir("trashed_add");
    let session = unlocked_vault(&base, "回收站附件库");
    let item_id = session.create_item(&minimal_draft("回收站条目")).unwrap();
    session.delete_item(&item_id, false).unwrap();
    assert_eq!(
        session.get_item(&item_id).unwrap().unwrap().state,
        ItemState::Trashed
    );

    let info = session
        .add_attachment(&item_id, "late.bin", b"late add")
        .unwrap();
    assert_eq!(info.item_uuid, item_id);
    assert_eq!(session.list_attachments(&item_id).unwrap().len(), 1);
}

// ------------------------------------------------ 判据：开库孤儿清理（M-2）

/// M-2（审查打回）：open_vault 成功路径真调 cleanup_orphans——孤儿旁路
/// 文件（行在文件无）与崩溃残留的 `.tmp-` 半截文件在重新开库时被清理，
/// 且**被 DB 行引用的附件文件不受影响**（清理以 DB 引用集为准，不得误删）。
///
/// 孤儿构造：直连 db.sqlite 删行（schema 明文，无需密钥），模拟
/// 「先删行后删文件」被中断的残留形态。
#[test]
fn 开库时清理孤儿附件且保留在引用文件() {
    let base = temp_dir("open_cleanup");
    let session = unlocked_vault(&base, "孤儿清理库");
    let item_id = session.create_item(&minimal_draft("孤儿清理条目")).unwrap();
    let orphan = session
        .add_attachment(&item_id, "orphan.bin", b"orphan")
        .unwrap();
    let kept = session
        .add_attachment(&item_id, "kept.bin", b"kept")
        .unwrap();
    let vault_dir = session.vault_dir().to_path_buf();
    let dir = attachments_dir(&session);

    // 孤儿一：行在文件无——直删 DB 行，旁路文件成为孤儿
    {
        let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).unwrap();
        conn.execute(
            "DELETE FROM attachments WHERE uuid = ?1",
            rusqlite::params![orphan.uuid],
        )
        .unwrap();
    }
    // 孤儿二：崩溃残留的 .tmp- 半截文件
    fs::write(dir.join(".tmp-crash-residue"), b"half written").unwrap();

    // 重新开库（open_vault 成功路径）
    session.lock();
    drop(session);
    let _reopened = open_vault(&vault_dir).unwrap();

    assert!(
        !dir.join(&orphan.uuid).exists(),
        "行在文件无的孤儿旁路文件应在 open_vault 时被清理"
    );
    assert!(
        !dir.join(".tmp-crash-residue").exists(),
        ".tmp- 崩溃残留应在 open_vault 时被清理"
    );
    assert!(
        dir.join(&kept.uuid).is_file(),
        "被 DB 行引用的附件文件不得被误删"
    );
}
