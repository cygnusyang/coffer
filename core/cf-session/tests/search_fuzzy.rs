//! FR-11.2 模糊匹配搜索验收用例（docs/10 §6，自动化落点冻结于 §0.3）。
//!
//! 每个用例注释标注 TC 编号；判据基准 = `docs/10-v0.2验收用例.md` §6。
//! TC-SRH-01（子串回归）由既有 `cf-session` 单元测试
//! `usecase::search::tests` 承载（行为不回退）。
//!
//! 走真实建库 / 解锁 / 会话 API（docs/10 §0.4：临时目录、真实路径）。

use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft, UrlDraft};
use cf_session::{create_vault_with_kdf, open_vault, VaultSession};

/// 测试用快速 KDF（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 主密码 P1。
const P1: &str = "correct-horse-battery-staple-42!";

/// 唯一临时目录（docs/10 §0.4：测试间零共享）。
fn temp_base(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cf-session-srh-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// 建库 + 解锁，返回会话。
fn unlocked_vault(tag: &str) -> VaultSession {
    let base = temp_base(tag);
    let brief = create_vault_with_kdf(&base, "搜索库", P1, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    session.unlock(P1).unwrap();
    session
}

/// Login 草稿（username 为模板必填，恒构造；URL / 标签可选）。
fn login_draft_full(title: &str, username: &str, url: Option<&str>, tags: &[&str]) -> ItemDraft {
    let fields = vec![
        FieldDraft {
            name: "用户名".to_owned(),
            value: Some(username.to_owned()),
            field_type: FieldType::Text,
            designation: Some(Designation::Username),
            section_index: None,
            position: 0,
        },
        FieldDraft {
            name: "密码".to_owned(),
            value: Some("hunter2".to_owned()),
            field_type: FieldType::Concealed,
            designation: Some(Designation::Password),
            section_index: None,
            position: 1,
        },
    ];
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: url
            .map(|u| UrlDraft {
                label: None,
                url: u.to_owned(),
                is_primary: true,
                position: 0,
            })
            .into_iter()
            .collect(),
        tags: tags.iter().map(|s| s.to_string()).collect(),
        sections: vec![],
        fields,
        totp: None,
    }
}

/// TC-SRH-02 近似：编辑距离 1。条目标题 `GitHub`，query =
/// `githb` / `gihub` / `githu` 全部命中（词级 DL≤1；`githu` 兼为子串）。
#[test]
fn edit_distance_one_hits() {
    let session = unlocked_vault("srh02");
    session.create_item(&login_draft_full("GitHub 登录", "alice", None, &[])).unwrap();

    for query in ["githb", "gihub", "githu"] {
        let hits = session.search(query).unwrap();
        assert_eq!(hits.len(), 1, "query={query} 应按词级距离 ≤1 命中");
        assert_eq!(hits[0].title, "GitHub 登录");
    }
}

/// TC-SRH-03 近似：距离 2 不命中。query=`gtxbx`（对 github 距离 ≥2）。
#[test]
fn edit_distance_two_misses() {
    let session = unlocked_vault("srh03");
    session.create_item(&login_draft_full("GitHub 登录", "alice", None, &[])).unwrap();

    assert!(
        session.search("gtxbx").unwrap().is_empty(),
        "距离 ≥2 不得命中（防误报）"
    );
}

/// TC-SRH-04 短词关闭近似。条目 `ab bank`，query=`ac`：词长 <4 近似
/// 关闭；子串亦不含 → 不命中。
#[test]
fn short_word_no_fuzzy() {
    let session = unlocked_vault("srh04");
    session
        .create_item(&login_draft_full("ab bank", "alice", None, &[]))
        .unwrap();

    assert!(session.search("ac").unwrap().is_empty());
    // 对照：距离 1 的长词仍命中（近似确实在工作，只是短词被关闭）
    session
        .create_item(&login_draft_full("bank only", "alice", None, &[]))
        .unwrap();
    assert_eq!(session.search("bnk").unwrap().len(), 0, "bnk 词长 3 同样关闭近似");
    assert_eq!(session.search("bank").unwrap().len(), 2, "精确子串不受影响");
}

/// TC-SRH-05 多字段命中：命中仅存在于 用户名 / URL / 标签 的条目各自命中。
#[test]
fn multi_field_match() {
    let session = unlocked_vault("srh05");
    session
        .create_item(&login_draft_full(
            "仅用户名可命中",
            "bob.builder@example.com",
            Some("https://unrelated-a.example.net"),
            &[],
        ))
        .unwrap();
    session
        .create_item(&login_draft_full(
            "仅URL可命中",
            "charlie",
            Some("https://tracker.example.org/portal"),
            &[],
        ))
        .unwrap();
    session
        .create_item(&login_draft_full(
            "仅标签可命中",
            "dave",
            Some("https://unrelated-b.example.net"),
            &["基础设施"],
        ))
        .unwrap();

    // 用户名命中（仅第一条）
    let hits = session.search("bob.builder").unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].title, "仅用户名可命中");

    // URL 命中（仅第二条）
    assert_eq!(session.search("tracker.example.org").unwrap().len(), 1);

    // 标签命中（仅第三条）
    assert_eq!(session.search("基础设施").unwrap().len(), 1);
}

/// TC-SRH-06 NFC 归一化：组合 / 分解形式同字（é 两种编码）结果一致。
#[test]
fn nfc_equivalence() {
    let session = unlocked_vault("srh06");
    // 标题含 NFC 形式的 é
    session
        .create_item(&login_draft_full("café 登录", "alice", None, &[]))
        .unwrap();

    let nfc_hits = session.search("caf\u{00E9}").unwrap();
    let nfd_hits = session.search("cafe\u{0301}").unwrap();
    assert_eq!(nfc_hits.len(), 1, "NFC 查询命中");
    assert_eq!(nfd_hits.len(), 1, "NFD 查询同样命中");
    assert_eq!(
        nfc_hits[0].title, nfd_hits[0].title,
        "两种编码形式结果一致"
    );
}

/// TC-SRH-07 大小写不敏感回归：`GitHub` vs `github` 双向均命中。
#[test]
fn case_insensitive() {
    let session = unlocked_vault("srh07");
    session.create_item(&login_draft_full("GitHub 登录", "alice", None, &[])).unwrap();
    session.create_item(&login_draft_full("github 小写", "alice", None, &[])).unwrap();

    assert_eq!(session.search("GitHub").unwrap().len(), 2);
    assert_eq!(session.search("github").unwrap().len(), 2);
    assert_eq!(session.search("GITHUB").unwrap().len(), 2);
}

/// TC-SRH-08 多关键词全命中语义：标题 `GitHub Work`，query=`githb work`
/// → 两词都命中才返回（`githb` 走近似、`work` 走子串）。
#[test]
fn all_terms_must_match() {
    let session = unlocked_vault("srh08");
    session.create_item(&login_draft_full("GitHub Work", "alice", None, &[])).unwrap();
    session.create_item(&login_draft_full("GitHub Play", "alice", None, &[])).unwrap();
    session.create_item(&login_draft_full("GitLab Work", "alice", None, &[])).unwrap();

    let hits = session.search("githb work").unwrap();
    assert_eq!(hits.len(), 1, "githb（近似）+ work（子串）必须同时命中");
    assert_eq!(hits[0].title, "GitHub Work");

    // 只命中一词不返回
    assert_eq!(session.search("githb").unwrap().len(), 2, "GitHub 两词同源近似命中");
    assert_eq!(session.search("work").unwrap().len(), 2);
}

/// TC-SRH-09 无结果：不相关库，query=不匹配词 → 空列表，不 panic。
#[test]
fn no_results_empty() {
    let session = unlocked_vault("srh09");
    session
        .create_item(&login_draft_full("银行登录", "alice", None, &[]))
        .unwrap();

    let hits = session.search("nonexistent-term").unwrap();
    assert!(hits.is_empty(), "不匹配应返回空列表");
    // 边界输入不 panic
    assert!(session.search("").unwrap().is_empty());
    assert!(session.search("   ").unwrap().is_empty());
}

/// TC-SRH-10 仅 Active 出结果：回收站条目与 query 匹配 → 不出现。
///
/// 归档态经公开会话 API 无法构造（set_archived 归 G4 FFI 接线），
/// Archived 过滤由单元测试 `usecase::search::tests::多关键词全命中`
/// （含 Archived 条目夹具）承载；本用例覆盖 Trashed 路径。
#[test]
fn inactive_excluded() {
    let session = unlocked_vault("srh10");
    let id = session
        .create_item(&login_draft_full("可搜索的标题", "alice", None, &[]))
        .unwrap();
    assert_eq!(session.search("可搜索").unwrap().len(), 1);

    session.delete_item(&id, false).unwrap(); // 软删 → Trashed
    assert!(
        session.search("可搜索").unwrap().is_empty(),
        "回收站条目不得出现在搜索结果"
    );

    session.restore_item(&id).unwrap();
    assert_eq!(session.search("可搜索").unwrap().len(), 1, "恢复后重新可搜索");
}

/// TC-SRH-11 性能基线（#[ignore]，CI release 档执行）：1000 条 × 4 字段
/// 单次平均 < 200ms（NFR-PERF-03 基线更新）。
#[test]
#[ignore = "性能基线：CI release 档执行（docs/10 §0.5）"]
fn perf_1000_items() {
    let session = unlocked_vault("srh11");

    for i in 0..1_000 {
        session
            .create_item(&login_draft_full(
                &format!("基线条目 {i:04} GitHub"),
                &format!("user{i:04}@example.com"),
                Some("https://example.com/path"),
                &["标签"],
            ))
            .unwrap();
    }

    let start = Instant::now();
    let hits = session.search("基线").unwrap();
    let elapsed = start.elapsed();

    assert_eq!(hits.len(), 1_000);
    // 名义阈值 200ms（NFR-PERF-03 / docs/10 §0.5）；经机器吞吐校准
    // （健康机因子 = 1，即原值），热限流环境下等比放大防止环境误报
    let budget = cf_session::testing::perf_budget(200);
    assert!(
        elapsed < budget,
        "1000 条 × 4 字段搜索耗时 {elapsed:?}，超出校准后的 200ms 基线（{budget:?}，NFR-PERF-03）"
    );
}
