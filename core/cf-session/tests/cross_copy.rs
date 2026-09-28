//! FR-2.10 跨库复制集成测试（v0.4.0-T01）。
//!
//! 判据基准 = 任务冻结设计 ①~⑪（⑦ 附件逐字节 / ⑧ 孤儿清理 / ⑩ 校验
//! 失败注入需触碰 `ItemStore` 内部，落 `usecase/cross_copy.rs` 单元测试）。
//!
//! 走真实建库 / 解锁 / 会话 API，快速 KDF 档位控制运行时长。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft, SectionDraft, UrlDraft};
use cf_domain::totp_data::{TotpAlgo, TotpData};
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::{copy_item, VaultSession};

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG: &str = "correct-horse-battery-staple-42!";

/// 测试用快速 KDF 档位（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 唯一临时目录（pid + 纳秒，测试间零共享）。
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-session-xcopy-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库并解锁，返回（库目录, 会话）。
fn unlocked_vault(base: &Path, tag: &str) -> (PathBuf, VaultSession) {
    let brief = create_vault_with_kdf(base, tag, STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap();
    (dir, session)
}

/// 内容丰富的 Login 草稿：URL + 标签 + 分区 + 分区内字段 + TOTP。
fn rich_draft(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![UrlDraft {
            label: Some("登录页".to_owned()),
            url: "https://github.com/login".to_owned(),
            is_primary: true,
            position: 0,
        }],
        tags: vec!["工作".to_owned(), "重要".to_owned()],
        sections: vec![SectionDraft {
            title: "服务器".to_owned(),
            position: 0,
        }],
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
            FieldDraft {
                name: "主机".to_owned(),
                value: Some("s1.example.com".to_owned()),
                field_type: FieldType::Text,
                designation: None,
                section_index: Some(0),
                position: 2,
            },
        ],
        totp: Some(TotpData {
            secret: b"0123456789abcdef0123".to_vec(),
            algo: TotpAlgo::Sha1,
            digits: 6,
            period: 30,
        }),
    }
}

// ---------------------------------------------------------------- 判据 ①

/// 判据 ①：双锁定 / 仅源锁定 / 仅目标锁定 → 1001（VaultLocked）
#[test]
fn 锁定态拒绝跨库复制() {
    let base = temp_dir("gate");
    let (_src_dir, src) = unlocked_vault(&base, "源库门禁");
    let (_dst_dir, dst) = unlocked_vault(&base, "目标库门禁");
    let id = src.create_item(&rich_draft("门禁条目")).unwrap();

    // 双锁定
    src.lock();
    dst.lock();
    assert_eq!(copy_item(&src, &id, &dst).unwrap_err().code(), 1001);

    // 仅源解锁
    src.unlock(STRONG).unwrap();
    assert_eq!(copy_item(&src, &id, &dst).unwrap_err().code(), 1001);

    // 仅目标解锁（源锁定）
    src.lock();
    dst.unlock(STRONG).unwrap();
    assert_eq!(copy_item(&src, &id, &dst).unwrap_err().code(), 1001);
}

// ---------------------------------------------------------------- 判据 ②③

/// 判据 ②：正常跨库复制——新 uuid、标题 / 字段值 / URL / 标签 / 分区 /
/// TOTP 逐项相等、created_at / updated_at 保留；判据 ③（正向）：目标库
/// 全部内容可用目标库密钥读回。
#[test]
fn 正常跨库复制内容逐项相等且时间戳保留() {
    let base = temp_dir("normal");
    let (_src_dir, src) = unlocked_vault(&base, "源库正常");
    let (_dst_dir, dst) = unlocked_vault(&base, "目标库正常");
    let src_id = src.create_item(&rich_draft("GitHub 登录")).unwrap();
    let src_before = src.get_item(&src_id).unwrap().unwrap();

    let new_id = copy_item(&src, &src_id, &dst).unwrap();

    // 产物恒用新 uuid（≠ 源 uuid）
    assert_ne!(new_id, src_id);

    let copied = dst.get_item(&new_id).unwrap().unwrap();
    assert_eq!(copied.title.expose(), "GitHub 登录");
    assert_eq!(copied.category, ItemCategory::Login);

    // 字段逐项相等（按名称对位：类型 / 语义 / 值 / 挂接分区标题）
    assert_eq!(copied.fields.len(), src_before.fields.len());
    for f in &src_before.fields {
        let target = copied
            .fields
            .iter()
            .find(|c| c.name.expose() == f.name.expose())
            .unwrap_or_else(|| panic!("目标库缺少字段 {}", f.name.expose()));
        assert_eq!(target.field_type, f.field_type);
        assert_eq!(target.designation, f.designation);
        assert_eq!(
            target.value.as_ref().map(|v| v.expose()),
            f.value.as_ref().map(|v| v.expose())
        );
        let src_section = f
            .section_uuid
            .as_ref()
            .map(|su| {
                src_before
                    .sections
                    .iter()
                    .find(|s| &s.uuid == su)
                    .unwrap()
                    .title
                    .expose()
            });
        let dst_section = target
            .section_uuid
            .as_ref()
            .map(|su| {
                copied
                    .sections
                    .iter()
                    .find(|s| &s.uuid == su)
                    .unwrap()
                    .title
                    .expose()
            });
        assert_eq!(src_section, dst_section, "字段挂接分区标题应相等");
    }

    // URL / 标签 / 分区
    assert_eq!(copied.urls.len(), src_before.urls.len());
    assert_eq!(
        copied.urls[0].url.expose(),
        src_before.urls[0].url.expose()
    );
    assert_eq!(copied.urls[0].is_primary, src_before.urls[0].is_primary);
    let mut src_tags: Vec<_> = src_before.tags.iter().map(|t| t.expose()).collect();
    src_tags.sort();
    let mut dst_tags: Vec<_> = copied.tags.iter().map(|t| t.expose()).collect();
    dst_tags.sort();
    assert_eq!(src_tags, dst_tags);
    assert_eq!(copied.sections.len(), src_before.sections.len());
    assert_eq!(
        copied.sections[0].title.expose(),
        src_before.sections[0].title.expose()
    );

    // TOTP 元数据相等 + secret 随快照走（目标库可出码 = 用 dst key 解开）
    let src_totp = src_before.totp.as_ref().unwrap();
    let dst_totp = copied.totp.as_ref().unwrap();
    assert_eq!(dst_totp.algo, src_totp.algo);
    assert_eq!(dst_totp.digits, src_totp.digits);
    assert_eq!(dst_totp.period, src_totp.period);
    assert_eq!(dst.totp_code(&new_id).unwrap().code.len(), 6);

    // created_at / updated_at 从快照注入保留
    assert_eq!(copied.created_at, src_before.created_at);
    assert_eq!(copied.updated_at, src_before.updated_at);
}

/// 判据 ③：换绑验证——目标库落盘密文是重新加密的（enc_title 密文
/// 字节 ≠ 源库密文字节：key 与 AAD 均换绑到目标库新行），且目标库可读。
#[test]
fn 跨库复制密文换绑重加密() {
    let base = temp_dir("rebind");
    let (src_vault_dir, src) = unlocked_vault(&base, "源库换绑");
    let (dst_vault_dir, dst) = unlocked_vault(&base, "目标库换绑");
    let src_id = src.create_item(&rich_draft("换绑条目")).unwrap();

    let new_id = copy_item(&src, &src_id, &dst).unwrap();

    let src_blob: Vec<u8> = {
        let conn = rusqlite::Connection::open(src_vault_dir.join("db.sqlite")).unwrap();
        conn.query_row(
            "SELECT enc_title FROM items WHERE uuid = ?1",
            rusqlite::params![src_id],
            |r| r.get(0),
        )
        .unwrap()
    };
    let dst_blob: Vec<u8> = {
        let conn = rusqlite::Connection::open(dst_vault_dir.join("db.sqlite")).unwrap();
        conn.query_row(
            "SELECT enc_title FROM items WHERE uuid = ?1",
            rusqlite::params![new_id],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_ne!(
        src_blob, dst_blob,
        "目标库密文必须是 dst key 重密封的产物，不得原样搬运"
    );
    // 目标库用自己的密钥可正常读回（正向换绑成立）
    assert_eq!(dst.get_item(&new_id).unwrap().unwrap().title.expose(), "换绑条目");
}

// ---------------------------------------------------------------- 判据 ④

/// 判据 ④：同库复制（src == dst）合法，产物独立（编辑副本不影响源）。
#[test]
fn 同库复制合法且产物独立() {
    let base = temp_dir("same_vault");
    let (_dir, session) = unlocked_vault(&base, "同库复制");
    let src_id = session.create_item(&rich_draft("原始条目")).unwrap();

    let copy_id = copy_item(&session, &src_id, &session).unwrap();
    assert_ne!(copy_id, src_id);

    // 两条并存且内容相等
    let original = session.get_item(&src_id).unwrap().unwrap();
    let copied = session.get_item(&copy_id).unwrap().unwrap();
    assert_eq!(copied.title.expose(), original.title.expose());
    assert_eq!(copied.fields.len(), original.fields.len());

    // 产物独立：改副本不动源
    let mut edited = rich_draft("副本改标题");
    edited.totp = None;
    session.update_item(&copy_id, &edited).unwrap();
    assert_eq!(session.get_item(&src_id).unwrap().unwrap().title.expose(), "原始条目");
    assert_eq!(session.get_item(&copy_id).unwrap().unwrap().title.expose(), "副本改标题");
}

// ---------------------------------------------------------------- 判据 ⑤

/// 判据 ⑤：源条目零改动——字段值与 history 行数不变。
#[test]
fn 跨库复制源条目零改动() {
    let base = temp_dir("src_intact");
    let (_src_dir, src) = unlocked_vault(&base, "源库零改动");
    let (_dst_dir, dst) = unlocked_vault(&base, "目标库零改动");
    let src_id = src.create_item(&rich_draft("源条目")).unwrap();
    // 编辑一次产生一条历史
    let mut edited = rich_draft("源条目二版");
    edited.totp = None;
    src.update_item(&src_id, &edited).unwrap();

    let before = src.get_item(&src_id).unwrap().unwrap();
    let history_len = src.list_history(&src_id).unwrap().len();

    copy_item(&src, &src_id, &dst).unwrap();

    let after = src.get_item(&src_id).unwrap().unwrap();
    assert_eq!(after.title.expose(), before.title.expose());
    assert_eq!(after.fields.len(), before.fields.len());
    for f in &before.fields {
        let now = after
            .fields
            .iter()
            .find(|c| c.name.expose() == f.name.expose())
            .unwrap();
        assert_eq!(
            now.value.as_ref().map(|v| v.expose()),
            f.value.as_ref().map(|v| v.expose())
        );
    }
    assert_eq!(after.created_at, before.created_at);
    assert_eq!(after.updated_at, before.updated_at);
    assert_eq!(
        src.list_history(&src_id).unwrap().len(),
        history_len,
        "源条目 history 不得因复制而变化"
    );
}

// ---------------------------------------------------------------- 判据 ⑥

/// 判据 ⑥：dst history 为空；首次编辑后 version 从 1 起。
#[test]
fn 目标库历史为空且首次更新从版本1起() {
    let base = temp_dir("dst_history");
    let (_src_dir, src) = unlocked_vault(&base, "源库历史");
    let (_dst_dir, dst) = unlocked_vault(&base, "目标库历史");
    let src_id = src.create_item(&rich_draft("历史条目")).unwrap();
    let mut edited = rich_draft("历史条目二版");
    edited.totp = None;
    src.update_item(&src_id, &edited).unwrap();
    assert_eq!(src.list_history(&src_id).unwrap().len(), 1, "源有 1 个版本");

    let new_id = copy_item(&src, &src_id, &dst).unwrap();
    assert!(
        dst.list_history(&new_id).unwrap().is_empty(),
        "跨库复制只复制当前版本，目标库 history 必须为空"
    );

    // 首次编辑 → version 从 1 起
    let mut next = rich_draft("历史条目三版");
    next.totp = None;
    dst.update_item(&new_id, &next).unwrap();
    let entries = dst.list_history(&new_id).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].version, 1, "目标库新条目版本号必须从 1 起");
}

// ---------------------------------------------------------------- 判据 ⑨

/// 判据 ⑨：源库与目标库各恰一条 ItemCopy 审计事件，detail 非敏感
/// （只含 uuid，不含标题 / 字段值）。
#[test]
fn 审计源库与目标库各一条且非敏感() {
    let base = temp_dir("audit");
    let (src_dir, src) = unlocked_vault(&base, "源库审计");
    let (dst_dir, dst) = unlocked_vault(&base, "目标库审计");
    let src_id = src.create_item(&rich_draft("审计条目")).unwrap();

    let new_id = copy_item(&src, &src_id, &dst).unwrap();

    let dst_events: Vec<(String, Option<String>)> = {
        let conn = rusqlite::Connection::open(dst_dir.join("db.sqlite")).unwrap();
        let mut stmt = conn.prepare("SELECT event, detail FROM audit_local").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    };
    assert_eq!(
        dst_events.len(),
        1,
        "目标库应恰有一条审计事件：{dst_events:?}"
    );
    assert_eq!(dst_events[0].0, "item_copy");
    assert_eq!(
        dst_events[0].1.as_deref(),
        Some(format!("src:{} item:{src_id}", src.vault_uuid()).as_str())
    );

    let src_events: Vec<(String, Option<String>)> = {
        let conn = rusqlite::Connection::open(src_dir.join("db.sqlite")).unwrap();
        let mut stmt = conn.prepare("SELECT event, detail FROM audit_local").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    };
    assert_eq!(
        src_events.len(),
        1,
        "源库应恰有一条审计事件：{src_events:?}"
    );
    assert_eq!(src_events[0].0, "item_copy");
    assert_eq!(
        src_events[0].1.as_deref(),
        Some(format!("dst:{} item:{new_id}", dst.vault_uuid()).as_str())
    );

    // 非敏感纪律：detail 不含标题与字段明文
    for (event, detail) in dst_events.iter().chain(src_events.iter()) {
        assert_eq!(event, "item_copy");
        let detail = detail.as_deref().unwrap_or_default();
        assert!(!detail.contains("审计条目"), "detail 不得含标题：{detail}");
        assert!(!detail.contains("hunter2"), "detail 不得含字段明文：{detail}");
    }
}

// ---------------------------------------------------------------- 判据 ⑪

/// 判据 ⑪：copy(a→b) 后 copy(b→a) 顺序调用不死锁、不串数据。
#[test]
fn 往返复制顺序调用不死锁不串数据() {
    let base = temp_dir("roundtrip_copy");
    let (_a_dir, a) = unlocked_vault(&base, "往返库甲");
    let (_b_dir, b) = unlocked_vault(&base, "往返库乙");

    let a_id = a.create_item(&rich_draft("甲库条目")).unwrap();
    let in_b = copy_item(&a, &a_id, &b).unwrap();
    assert_eq!(b.get_item(&in_b).unwrap().unwrap().title.expose(), "甲库条目");

    // 反向：把 b 里的副本复制回 a（新条目，不与源冲突）
    let back_in_a = copy_item(&b, &in_b, &a).unwrap();
    assert_ne!(back_in_a, a_id, "回程复制必须产生新条目");
    assert_eq!(
        a.get_item(&back_in_a).unwrap().unwrap().title.expose(),
        "甲库条目"
    );
    assert_eq!(
        a.get_item(&a_id).unwrap().unwrap().title.expose(),
        "甲库条目",
        "回程复制不得污染源条目"
    );
    assert_eq!(a.list_items(None).unwrap().len(), 2);
    assert_eq!(b.list_items(None).unwrap().len(), 1);
}

/// 审查 MEDIUM 补测：源条目为回收站态时，产物强制 Active
/// （trashed_at 不在快照、无法忠实迁移，模块文档「产物形态」已声明）。
#[test]
fn 回收站态源条目复制产物为active() {
    let base = temp_dir("trashed");
    let (dir_a, a) = unlocked_vault(&base, "a");
    let (_dir_b, b) = unlocked_vault(&base, "b");

    let draft = rich_draft("回收站里的条目");
    let src_id = a.create_item(&draft).unwrap();
    a.delete_item(&src_id, false).unwrap(); // 软删 → Trashed
    assert!(matches!(
        a.get_item(&src_id).unwrap().unwrap().state,
        cf_domain::item::ItemState::Trashed
    ));

    let new_id = copy_item(&a, &src_id, &b).unwrap();
    let copied = b.get_item(&new_id).unwrap().unwrap();
    assert!(
        matches!(copied.state, cf_domain::item::ItemState::Active),
        "回收站态源条目的副本应为 Active"
    );
    // 源条目回收站态不被复制动作影响
    assert!(matches!(
        a.get_item(&src_id).unwrap().unwrap().state,
        cf_domain::item::ItemState::Trashed
    ));
    let _ = dir_a;
}
