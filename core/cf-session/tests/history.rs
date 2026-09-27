//! FR-2.9 历史版本编排层验收用例（docs/10 §3，自动化落点冻结于 §0.3）。
//!
//! 每个用例注释标注 TC 编号；判据基准 = `docs/10-v0.2验收用例.md` §3。
//! 走真实建库 / 解锁 / 编排 API（docs/10 §0.4：临时目录、真实路径）。

use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft, UrlDraft};
use cf_domain::totp_data::{TotpAlgo, TotpData, TotpUpdate};
use cf_session::{create_vault_with_kdf, open_vault, VaultSession};

/// 测试用快速 KDF（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 强密码（zxcvbn score ≥ 3）。
const P1: &str = "correct-horse-battery-staple-42!";

/// 建库 + 解锁，返回会话与其工作目录。
fn unlocked_vault(tag: &str) -> (VaultSession, PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "cf-session-his-{tag}-{}-{nanos}",
        std::process::id()
    ));
    let brief = create_vault_with_kdf(&base, "历史库", P1, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    session.unlock(P1).unwrap();
    (session, base)
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

fn totp_data(secret_byte: u8) -> TotpData {
    TotpData {
        secret: vec![secret_byte; 20],
        algo: TotpAlgo::Sha1,
        digits: 6,
        period: 30,
    }
}

/// TC-HIS-06 回滚 = 走 update 路径：编辑（改标题+改密码值+换 TOTP）→
/// restore_history(v1) → 当前条目与 v1 逐字段相等（含 TOTP Replace
/// 语义）；history 新增一条版本（回滚本身是修改）。
#[test]
fn restore_replaces_current_and_appends_version() {
    let (session, _dir) = unlocked_vault("his06");
    let id = session.create_item(&login_draft("初版", "pw-v1")).unwrap();

    // 编辑：改标题 + 改密码值 + 加 URL + 换 TOTP（Replace）
    let mut edited = login_draft("改版", "pw-v2");
    edited.urls = vec![UrlDraft {
        label: Some("新地址".to_owned()),
        url: "https://changed.example.com".to_owned(),
        is_primary: true,
        position: 0,
    }];
    session
        .update_item_with_totp(&id, &edited, TotpUpdate::Replace(totp_data(0xAA)))
        .unwrap();

    let v1 = session.list_history(&id).unwrap()[0].history_uuid.clone();

    // 回滚到 v1（创建态）
    session.restore_history(&id, &v1).unwrap();

    let details = session.get_item(&id).unwrap().unwrap();
    assert_eq!(details.title.expose(), "初版");
    let password = details
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .expect("密码字段应存在");
    assert_eq!(password.value.as_ref().unwrap().expose(), "pw-v1");
    assert!(details.urls.is_empty(), "v1 无 URL，不得残留编辑期 URL");
    assert!(details.totp.is_none(), "v1 无 TOTP，Replace 语义下不得残留");

    // 回滚本身是修改 → history 新增一条版本
    let after = session.list_history(&id).unwrap();
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].version, 2, "回滚产生的版本号最高");
}

/// TC-HIS-07 回滚的回滚：TC-HIS-06 之后 restore_history 回 v2（回滚前
/// 状态）→ 当前条目恢复为编辑后状态。
#[test]
fn restore_can_be_restored() {
    let (session, _dir) = unlocked_vault("his07");
    let id = session.create_item(&login_draft("初版", "pw-v1")).unwrap();

    let mut edited = login_draft("改版", "pw-v2");
    edited.urls = vec![UrlDraft {
        label: None,
        url: "https://changed.example.com".to_owned(),
        is_primary: true,
        position: 0,
    }];
    session
        .update_item_with_totp(&id, &edited, TotpUpdate::Replace(totp_data(0xBB)))
        .unwrap();

    let v1 = session.list_history(&id).unwrap()[0].history_uuid.clone();
    session.restore_history(&id, &v1).unwrap(); // → 初版

    let v2 = session.list_history(&id).unwrap()[0].history_uuid.clone();
    session.restore_history(&id, &v2).unwrap(); // 回滚的回滚 → 改版

    let details = session.get_item(&id).unwrap().unwrap();
    assert_eq!(details.title.expose(), "改版", "回滚到 v2 应恢复编辑后状态");
    assert_eq!(details.urls.len(), 1);
    let password = details
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .unwrap();
    assert_eq!(password.value.as_ref().unwrap().expose(), "pw-v2");
    let totp = details.totp.expect("v2 含 TOTP，应恢复");
    assert_eq!(totp.algo, "sha1");
}

/// TC-HIS-08 回滚到不存在的版本：伪造 / 已删 history_uuid → 1011，
/// 当前条目不变。
#[test]
fn restore_unknown_history_1011() {
    let (session, _dir) = unlocked_vault("his08");
    let id = session.create_item(&login_draft("初版", "pw")).unwrap();
    let before = session.get_item(&id).unwrap().unwrap();

    let err = session
        .restore_history(&id, &uuid::Uuid::now_v7().to_string())
        .unwrap_err();
    assert_eq!(err.code(), 1011, "不存在的 history_uuid 必须 ItemNotFound");

    let after = session.get_item(&id).unwrap().unwrap();
    assert_eq!(after.title.expose(), before.title.expose(), "条目不变");
}

/// TC-HIS-09 软删条目历史保留：软删 → 恢复 → list_history 不变。
#[test]
fn soft_delete_preserves_history() {
    let (session, _dir) = unlocked_vault("his09");
    let id = session.create_item(&login_draft("初版", "pw")).unwrap();
    session
        .update_item(&id, &login_draft("二版", "pw"))
        .unwrap();
    let before = session.list_history(&id).unwrap();
    assert_eq!(before.len(), 1);

    session.delete_item(&id, false).unwrap(); // 软删
    assert_eq!(
        session.list_history(&id).unwrap().len(),
        1,
        "软删不动 history"
    );

    session.restore_item(&id).unwrap();
    let after = session.list_history(&id).unwrap();
    assert_eq!(after, before, "恢复后 history 原样保留");
}

/// TC-HIS-03 内容无变化不写（端到端判据；落点偏移说明见
/// cf-store/tests/history_repo.rs 文件头）：以相同内容 update 3 次 →
/// history 仍 1 条。
#[test]
fn no_change_no_snapshot() {
    let (session, _dir) = unlocked_vault("his03");
    let id = session.create_item(&login_draft("同一标题", "同一密码")).unwrap();
    let draft = login_draft("同一标题", "同一密码");

    for _ in 0..3 {
        session.update_item(&id, &draft).unwrap();
    }
    assert_eq!(
        session.list_history(&id).unwrap().len(),
        1,
        "内容无变化的重复 update 不得新增版本"
    );

    // 真实内容变化 → 下一次 update 落新版本
    session
        .update_item(&id, &login_draft("新标题", "同一密码"))
        .unwrap();
    session
        .update_item(&id, &login_draft("新标题", "同一密码"))
        .unwrap();
    assert_eq!(
        session.list_history(&id).unwrap().len(),
        2,
        "内容变化应恰好落一版（变化前状态），重复保存不再累加"
    );
}

/// TC-HIS-12 快照含 TOTP secret 不出 FFI：list_history 返回体仅 meta
/// （history_uuid / version / created_at），无任何快照明文字段。
///
/// 编译期断言 + 运行期断言双重承载：解构必须穷尽 HistoryEntry 全部
/// 字段（新增字段会编译失败，迫使回看此判据）；Debug 输出不含快照内容。
#[test]
fn ffi_meta_only() {
    let (session, _dir) = unlocked_vault("his12");
    let mut draft = login_draft("含 TOTP", "pw");
    draft.totp = Some(totp_data(0x5A));
    let id = session.create_item(&draft).unwrap();
    session
        .update_item(&id, &login_draft("二版", "pw"))
        .unwrap();

    let entries = session.list_history(&id).unwrap();
    assert!(!entries.is_empty());
    for entry in &entries {
        // 穷尽解构：HistoryEntry 只允许 meta 三字段（编译期闸门）
        let cf_session::HistoryEntry {
            history_uuid: _,
            version: _,
            created_at: _,
        } = entry;
    }
    let debug = format!("{entries:?}");
    assert!(
        !debug.contains("含 TOTP") && !debug.contains("hunter2") && !debug.contains("二版"),
        "list_history 返回结构不得携带快照明文"
    );
}

/// TC-HIS-13 list 性能基线（#[ignore]，CI release 档执行）：
/// 1000 条目 × 平均 3 版本，list_history 单次平均 < 200ms。
///
/// 阈值语义见 docs/10 §0.5：200ms 为 release 基线；本测试用
/// cf-session 内建吞吐校准（tests_support::perf_budget，健康机因子
/// = 1，即 200ms 原值）以兼容负载波动环境。
#[test]
#[ignore = "性能基线：CI release 档执行（docs/10 §0.5）"]
fn list_perf_baseline() {
    let (session, _dir) = unlocked_vault("his13");

    let mut item_ids = Vec::with_capacity(1_000);
    for i in 0..1_000 {
        let id = session
            .create_item(&login_draft(&format!("条目 {i}"), "pw"))
            .unwrap();
        for round in 1..=3 {
            session
                .update_item(&id, &login_draft(&format!("条目 {i} 第{round}改"), "pw"))
                .unwrap();
        }
        item_ids.push(id);
    }

    // 计时口径：单条目 list_history × 1000（判据：单次平均 < 200ms）
    let start = Instant::now();
    let mut total_versions = 0usize;
    for id in &item_ids {
        total_versions += session.list_history(id).unwrap().len();
    }
    let elapsed = start.elapsed();
    assert_eq!(total_versions, 3_000);

    // 名义阈值：单次平均 < 200ms（docs/10 §0.5），经机器吞吐校准
    let budget = cf_session::testing::perf_budget(200) * 1_000u32;
    assert!(
        elapsed < budget,
        "1000 条目 × 3 版本 list 总耗时 {elapsed:?}，平均超出校准后的 200ms/条基线"
    );
}
