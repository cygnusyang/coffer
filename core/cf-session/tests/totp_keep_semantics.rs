//! T06 QA 严过关：TOTP 保留语义三态（Keep / Replace / Remove）的边界验证。
//!
//! 与 `integration.rs` 的三态基础测试互补，本文件聚焦**实现细节层**的攻击面：
//!
//! 1. Keep 的「行不动」语义：直接开第二条 SQLite 连接读 `db.sqlite` 的
//!    totp 表，断言行 uuid 与 enc_secret BLOB **逐字节不变**（而非
//!    「重新插入一份一样的」——重加密会因随机 nonce 产生不同密文）；
//! 2. Keep 与其它编辑动作的组合（改标题 / 改字段 / 连续两次 Keep 幂等 /
//!    对无 TOTP 条目静默无害）；
//! 3. Replace / Remove 的数据完整性（旧行真删除无孤儿、非法载荷拒绝后
//!    旧行完好、Remove 后 totp_code 报 1011）；
//! 4. draft.totp 在更新路径被忽略（即使携带非法载荷也不生效不报错）；
//! 5. Keep → 锁定 → 解锁 → TOTP 仍可出码（会话重建后加密行仍解得开）；
//! 6. totp_config 三分返回：不存在条目 / 无 TOTP 条目 → None；软删条目 →
//!    Some（回收站保留 TOTP 行，恢复后仍可出码）；
//! 7. CSV 导入新建的 TOTP 条目走编辑 Keep 路径。
//!
//! 直连数据库的方法：库是「明文 SQLite + 加密 BLOB 列」形态，db.sqlite
//! 位于 `vault_dir()` 下；会话连接空闲（无未提交事务）时第二条连接可安全读。

use std::path::{Path, PathBuf};

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft};
use cf_domain::totp_data::{TotpAlgo, TotpData, TotpUpdate};
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::VaultSession;

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG: &str = "correct-horse-battery-staple-42!";

/// 合法 TOTP 密钥（20 字节，≥ 10 字节校验线）。
const SECRET_A: &[u8] = b"0123456789abcdef0123";
/// 另一把合法 TOTP 密钥（Replace 用）。
const SECRET_B: &[u8] = b"fedcba9876543210fedc";

/// 测试用快速 KDF 档位。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 唯一临时目录（pid + 纳秒）。
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-session-t06-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库并开会话（快速档位），返回 (库目录, 已解锁会话)。
fn fresh_session(tag: &str) -> (PathBuf, VaultSession) {
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(&base, tag, STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap();
    (dir, session)
}

/// 构造 Login 草稿（username + password 必填齐全，TOTP 由调用方注入）。
fn login_draft(title: &str, totp: Option<TotpData>) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![cf_domain::item::UrlDraft {
            label: Some("登录页".to_owned()),
            url: "https://github.com/login".to_owned(),
            is_primary: true,
            position: 0,
        }],
        tags: vec!["工作".to_owned()],
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
        totp,
    }
}

/// 更新用草稿：不带 TOTP（模拟 FFI 侧拿不到 secret 的真实形态）。
fn login_draft_without_totp(title: &str) -> ItemDraft {
    login_draft(title, None)
}

/// totp 数据便捷构造。
fn totp_data(secret: &[u8], digits: u8, period: u32) -> TotpData {
    TotpData {
        secret: secret.to_vec(),
        algo: TotpAlgo::Sha1,
        digits,
        period,
    }
}

/// 直连 db.sqlite 读取某条目名下全部 totp 行（uuid, enc_secret BLOB），
/// 按 created_at 排序。会话连接无未提交事务时并发读安全。
fn totp_rows(vault_dir: &Path, item_id: &str) -> Vec<(String, Vec<u8>)> {
    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT uuid, enc_secret FROM totp WHERE item_uuid = ?1 ORDER BY created_at ASC, uuid ASC",
        )
        .unwrap();
    let mut rows = stmt.query(rusqlite::params![item_id]).unwrap();
    let mut out = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        let uuid: String = row.get(0).unwrap();
        let blob: Vec<u8> = row.get(1).unwrap();
        out.push((uuid, blob));
    }
    out
}

/// 建一个含 TOTP 的条目，返回条目 ID。
fn item_with_totp(session: &VaultSession, title: &str) -> String {
    session
        .create_item(&login_draft(title, Some(totp_data(SECRET_A, 6, 30))))
        .unwrap()
}

// ============================================================ Keep 语义

/// Keep 后 totp 行 uuid 与 enc_secret BLOB 逐字节不变（同一行未被动过，
/// 不是「删旧插一份一模一样的」——重加密因随机 nonce 必然产生不同密文）。
#[test]
fn keep后totp行逐字节不变() {
    let (dir, session) = fresh_session("keep_row");
    let id = item_with_totp(&session, "Keep 行级不变");

    let before = totp_rows(&dir, &id);
    assert_eq!(before.len(), 1);

    session
        .update_item(&id, &login_draft_without_totp("改标题不动TOTP"))
        .unwrap();

    let after = totp_rows(&dir, &id);
    assert_eq!(after.len(), 1, "Keep 不得增删 totp 行");
    assert_eq!(after[0].0, before[0].0, "行 uuid 必须不变");
    assert_eq!(
        after[0].1, before[0].1,
        "enc_secret BLOB 必须逐字节不变（重加密会因随机 nonce 变形）"
    );

    // 行未动 ⇒ 密钥仍可用：出码正常
    assert_eq!(session.totp_code(&id).unwrap().code.len(), 6);
}

/// Keep + 同时改标题 / 字段 / 标签：TOTP 仍存活，其它编辑照常生效。
#[test]
fn keep与其它编辑组合_totp仍存活() {
    let (dir, session) = fresh_session("keep_combo");
    let id = item_with_totp(&session, "组合编辑");

    let before = totp_rows(&dir, &id);

    let mut draft = login_draft_without_totp("组合编辑后");
    draft.tags = vec!["新标签".to_owned()];
    draft.fields[0].value = Some("bob@example.com".to_owned());
    session.update_item(&id, &draft).unwrap();

    let after = totp_rows(&dir, &id);
    assert_eq!(after[0].0, before[0].0);
    assert_eq!(after[0].1, before[0].1);

    let details = session.get_item(&id).unwrap().unwrap();
    assert_eq!(details.title.expose(), "组合编辑后");
    assert!(details.totp.is_some(), "组合编辑后 TOTP 必须存活");
    assert_eq!(
        details.tags.iter().map(|t| t.expose().to_owned()).collect::<Vec<_>>(),
        vec!["新标签".to_owned()]
    );
    let username = details
        .fields
        .iter()
        .find(|f| f.designation == Some(cf_domain::field::Designation::Username))
        .unwrap();
    assert_eq!(username.value.as_ref().map(|v| v.expose()), Some("bob@example.com"));
}

/// 对无 TOTP 的条目 Keep：静默无害——不报错、不凭空造出 totp 行。
#[test]
fn keep对无totp条目静默无害() {
    let (dir, session) = fresh_session("keep_no_totp");
    let id = session
        .create_item(&login_draft("本来就没有TOTP", None))
        .unwrap();
    assert!(totp_rows(&dir, &id).is_empty());

    session
        .update_item(&id, &login_draft_without_totp("编辑无TOTP条目"))
        .unwrap();
    assert!(
        totp_rows(&dir, &id).is_empty(),
        "Keep 对无 TOTP 条目不得凭空产生 totp 行"
    );

    // 显式 Keep 三态版同样静默无害
    session
        .update_item_with_totp(&id, &login_draft_without_totp("再编辑"), TotpUpdate::Keep)
        .unwrap();
    assert!(totp_rows(&dir, &id).is_empty());
    assert!(session.get_item(&id).unwrap().unwrap().totp.is_none());
}

/// 连续两次 Keep 幂等：行 uuid 与 BLOB 均不变，出码稳定。
#[test]
fn 连续两次keep幂等() {
    let (dir, session) = fresh_session("keep_twice");
    let id = item_with_totp(&session, "连续Keep");

    session
        .update_item_with_totp(&id, &login_draft_without_totp("第一次Keep"), TotpUpdate::Keep)
        .unwrap();
    let mid = totp_rows(&dir, &id);

    session
        .update_item_with_totp(&id, &login_draft_without_totp("第二次Keep"), TotpUpdate::Keep)
        .unwrap();
    let end = totp_rows(&dir, &id);

    assert_eq!(end.len(), 1);
    assert_eq!(end[0], mid[0], "两次 Keep 后行必须完全一致");
    assert_eq!(session.totp_code(&id).unwrap().code.len(), 6);
}

/// draft.totp 在更新路径被忽略：即使携带非法载荷（secret 过短），
/// Keep 更新也照常成功且既有 TOTP 不受影响（以三态参数为准）。
#[test]
fn 更新路径draft_totp被忽略_非法载荷不生效() {
    let (dir, session) = fresh_session("draft_ignored");
    let id = item_with_totp(&session, "draft被忽略");

    let before = totp_rows(&dir, &id);

    // draft 携带非法 TOTP（secret 仅 5 字节）：若未清空，validate_item 会拒绝；
    // 更新路径应清空 draft.totp 以三态参数为准
    let mut draft = login_draft_without_totp("携带非法draft");
    draft.totp = Some(totp_data(b"short", 6, 30));
    session
        .update_item_with_totp(&id, &draft, TotpUpdate::Keep)
        .unwrap();

    let after = totp_rows(&dir, &id);
    assert_eq!(after, before, "draft.totp 不得影响更新路径");

    // 三态为 Remove 时同样忽略 draft.totp
    session
        .update_item_with_totp(&id, &draft, TotpUpdate::Remove)
        .unwrap();
    assert!(totp_rows(&dir, &id).is_empty(), "Remove 后 TOTP 应被删除");
}

// ===================================================== Replace / Remove 完整性

/// Replace 后旧行真删除：条目名下恰 1 行、uuid 变化、旧密钥失效新密钥生效、
/// 无孤儿行（旧 uuid 在全表已不存在）。
#[test]
fn replace删旧插新_无孤儿行() {
    let (dir, session) = fresh_session("replace_orphan");
    let id = item_with_totp(&session, "Replace孤儿检查");
    let old_uuid = totp_rows(&dir, &id)[0].0.clone();

    session
        .update_item_with_totp(
            &id,
            &login_draft_without_totp("替换后"),
            TotpUpdate::Replace(totp_data(SECRET_B, 8, 60)),
        )
        .unwrap();

    let rows = totp_rows(&dir, &id);
    assert_eq!(rows.len(), 1, "Replace 后条目名下应恰有 1 行");
    assert_ne!(rows[0].0, old_uuid, "Replace 必须是新行（新 uuid）");

    // 无孤儿：旧 uuid 全表已不存在
    let conn = rusqlite::Connection::open(dir.join("db.sqlite")).unwrap();
    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM totp WHERE uuid = ?1",
            rusqlite::params![old_uuid],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphans, 0, "Replace 后旧行必须真删除，不得留孤儿");

    // 新配置生效、可出 8 位码
    let meta = session.get_item(&id).unwrap().unwrap().totp.unwrap();
    assert_eq!(meta.digits, 8);
    assert_eq!(meta.period, 60);
    assert_eq!(session.totp_code(&id).unwrap().code.len(), 8);
}

/// Replace 非法载荷（secret < 10 字节）被拒绝：无部分写入——旧行 uuid /
/// BLOB / 行数原样，条目其它内容也不被本次调用改动。
#[test]
fn replace非法载荷拒绝后旧totp完好() {
    let (dir, session) = fresh_session("replace_invalid");
    let id = item_with_totp(&session, "非法Replace");
    let before = totp_rows(&dir, &id);
    let title_before = session.get_item(&id).unwrap().unwrap().title.expose().to_owned();

    // 单独的非法 Replace（载荷 9 字节，恰好低于校验线）
    let err = session
        .update_item_with_totp(
            &id,
            &login_draft_without_totp("不该生效的标题"),
            TotpUpdate::Replace(totp_data(b"012345678", 6, 30)),
        )
        .unwrap_err();
    assert_eq!(err.code(), 5002, "非法载荷应报 InvalidArgument(5002)");

    let after = totp_rows(&dir, &id);
    assert_eq!(after, before, "被拒的 Replace 不得触碰既有 totp 行");

    // 整体替换语义下其余从表同样不得被部分写入
    let details = session.get_item(&id).unwrap().unwrap();
    assert_eq!(details.title.expose(), title_before, "被拒的更新不得改标题");
    assert_eq!(session.totp_code(&id).unwrap().code.len(), 6);
}

/// Remove 后：totp 行清空、totp_config / 详情 totp 回 None、totp_code 报 1011。
#[test]
fn remove后行清空且totp_code报1011() {
    let (dir, session) = fresh_session("remove_clean");
    let id = item_with_totp(&session, "Remove清空");

    session
        .update_item_with_totp(&id, &login_draft_without_totp("移除后"), TotpUpdate::Remove)
        .unwrap();

    assert!(totp_rows(&dir, &id).is_empty(), "Remove 后 totp 行必须清空");
    assert!(session.totp_config(&id).unwrap().is_none());
    assert!(session.get_item(&id).unwrap().unwrap().totp.is_none());
    assert_eq!(session.totp_code(&id).unwrap_err().code(), 1011);

    // Remove 对已无 TOTP 的条目再执行一次：空操作不报错（幂等）
    session
        .update_item_with_totp(&id, &login_draft_without_totp("再Remove"), TotpUpdate::Remove)
        .unwrap();
    assert!(totp_rows(&dir, &id).is_empty());
}

// ===================================================== 跨锁定周期一致性

/// Keep → 锁定 → 解锁：会话重建（SubKeys 重派生）后 totp 加密行仍解得开，
/// 元数据一致、仍可出码。
#[test]
fn keep后锁定解锁totp仍可出码() {
    let (_dir, session) = fresh_session("keep_relock");
    let id = item_with_totp(&session, "锁定周期");
    let meta_before = session.totp_config(&id).unwrap().unwrap();

    session.lock();
    assert!(!session.is_unlocked());
    assert_eq!(session.totp_code(&id).unwrap_err().code(), 1001);
    assert_eq!(session.totp_config(&id).unwrap_err().code(), 1001);

    session.unlock(STRONG).unwrap();
    let meta_after = session.totp_config(&id).unwrap().unwrap();
    assert_eq!(meta_after.algo, meta_before.algo);
    assert_eq!(meta_after.digits, meta_before.digits);
    assert_eq!(meta_after.period, meta_before.period);
    let code = session.totp_code(&id).unwrap();
    assert_eq!(code.code.len(), 6);
    assert!(code.code.chars().all(|c| c.is_ascii_digit()));
}

// ===================================================== totp_config 三分返回

/// totp_config 三分：不存在条目 → Ok(None)（docs/07 语义：编辑界面只需
/// 区分「有 / 无」）；无 TOTP 条目 → Ok(None)；软删条目 → Ok(Some)——
/// 软删不动从表，恢复后 TOTP 仍存活可出码。
#[test]
fn totp_config三分_不存在无totp软删() {
    let (dir, session) = fresh_session("config_tri");
    let id = item_with_totp(&session, "三分返回");
    let bare = session
        .create_item(&login_draft("无TOTP", None))
        .unwrap();

    // ① 不存在条目 → Ok(None)
    assert!(session.totp_config("no-such-item").unwrap().is_none());
    // ② 存在但无 TOTP → Ok(None)
    assert!(session.totp_config(&bare).unwrap().is_none());
    // ③ 软删条目 → Ok(Some)（回收站保留从表）
    session.delete_item(&id, false).unwrap();
    let meta = session
        .totp_config(&id)
        .unwrap()
        .expect("软删条目的 TOTP 行必须保留");
    assert_eq!(meta.digits, 6);

    // 恢复后 TOTP 仍存活、仍可出码
    session.restore_item(&id).unwrap();
    assert!(session.totp_config(&id).unwrap().is_some());
    assert_eq!(session.totp_code(&id).unwrap().code.len(), 6);
    assert_eq!(totp_rows(&dir, &id).len(), 1);
}

// ===================================================== CSV 导入 × Keep

/// CSV 导入新建的 TOTP 条目再走编辑 Keep 路径：导入行不动、仍可出码。
#[test]
fn csv导入的totp条目走keep路径() {
    let (_dir, session) = fresh_session("csv_keep");
    let csv = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/csv/good_basic.csv")
        .canonicalize()
        .unwrap();
    let result = session.import_csv(&csv).unwrap();
    assert_eq!(result.imported_rows, 3);

    let hits = session.search("GitHub").unwrap();
    assert_eq!(hits.len(), 1);
    let id = hits[0].uuid.to_string();
    assert!(session.totp_config(&id).unwrap().is_some());

    // 编辑（Keep 默认语义）：导入的 TOTP 行原样保留
    session
        .update_item(&id, &login_draft_without_totp("导入后编辑"))
        .unwrap();

    let details = session.get_item(&id).unwrap().unwrap();
    assert_eq!(details.title.expose(), "导入后编辑");
    assert!(details.totp.is_some(), "导入的 TOTP 必须在编辑后存活");
    assert_eq!(session.totp_code(&id).unwrap().code.len(), 6);
}
