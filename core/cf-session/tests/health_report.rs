//! FR-6.7 体检报告会话侧编排验收用例（v0.3.0-T04）。
//!
//! 覆盖五类检测（FR-6.2 重复密码 / 6.3 弱 URL / 6.4 陈旧密码 /
//! 6.5 泄露启发式 / 6.6 无 2FA）的编排命中、汇总统计、明文纪律与
//! 边界语义（与 cf-audit 纯函数判据一致）。走真实建库 / 解锁 / 会话 API。

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft, UrlDraft};
use cf_domain::totp_data::{TotpAlgo, TotpData};
use cf_session::{create_vault_with_kdf, open_vault, VaultSession};

/// 测试用快速 KDF（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 主密码 P1。
const P1: &str = "correct-horse-battery-staple-42!";

/// 一天的秒数。
const SECS_PER_DAY: i64 = 86_400;

/// 唯一临时目录（docs/10 §0.4：测试间零共享）。
fn temp_base(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cf-session-health-{tag}-{}-{nanos}",
        std::process::id()
    ))
}

/// 建库 + 解锁，返回（会话, 库目录）。
fn unlocked_vault(tag: &str) -> (VaultSession, PathBuf) {
    let base = temp_base(tag);
    let brief = create_vault_with_kdf(&base, "体检库", P1, fast_kdf()).unwrap();
    let vault_dir = base.join(brief.uuid.to_string());
    let session = open_vault(&vault_dir).unwrap();
    session.unlock(P1).unwrap();
    (session, vault_dir)
}

/// Login 草稿（指定标题 / 密码 / URL 列表 / TOTP）。
fn login_draft(
    title: &str,
    password: &str,
    urls: Vec<UrlDraft>,
    totp: Option<TotpData>,
) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls,
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
        totp,
    }
}

/// 单 URL 草稿。
fn url_draft(url: &str) -> UrlDraft {
    UrlDraft {
        label: None,
        url: url.to_owned(),
        is_primary: true,
        position: 0,
    }
}

/// 测试 TOTP 数据（SHA-1 / 6 位 / 30s）。
fn totp_data() -> TotpData {
    TotpData {
        secret: vec![0x31u8; 20],
        algo: TotpAlgo::Sha1,
        digits: 6,
        period: 30,
    }
}

/// 直连 db.sqlite 回写 updated_at（明文列；与 totp_keep_semantics 同模式）。
fn backdate_updated_at(vault_dir: &Path, item_id: &str, updated_at: i64) {
    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).unwrap();
    conn.execute(
        "UPDATE items SET updated_at = ?1 WHERE uuid = ?2",
        rusqlite::params![updated_at, item_id],
    )
    .unwrap();
}

/// TC-HR-01 全净库：五类 0 finding，汇总统计全零。
#[test]
fn 空库五类全零() {
    let (session, _dir) = unlocked_vault("hr01");
    let now = 1_700_000_000i64;

    let report = session.health_report(now).unwrap();

    assert!(report.duplicate_groups.is_empty(), "空库无重复组");
    assert!(report.http_url_items.is_empty(), "空库无弱 URL");
    assert!(report.stale_items.is_empty(), "空库无陈旧密码");
    assert!(report.leak_suspects.is_empty(), "空库无泄露命中");
    assert!(report.missing_totp_items.is_empty(), "空库无 2FA 提示");
    assert_eq!(report.summary.duplicate_group_count, 0);
    assert_eq!(report.summary.weak_url_count, 0);
    assert_eq!(report.summary.stale_count, 0);
    assert_eq!(report.summary.leak_suspect_count, 0);
    assert_eq!(report.summary.missing_totp_count, 0);
    assert_eq!(report.summary.total_findings, 0);
}

/// TC-HR-02 五类命中与汇总统计：各构造一条命中项，断言类别、标题、
/// 元数据与汇总计数。
#[test]
fn 五类命中与汇总统计() {
    let (session, dir) = unlocked_vault("hr02");
    let now = 1_700_000_000i64;

    // 6.2：两条同密码（强密码，避免同时命中 6.5）
    let strong = "correct-horse-battery-staple-42!";
    let dup1 = session
        .create_item(&login_draft(
            "重复一",
            strong,
            vec![url_draft("https://dup1.example.com")],
            None,
        ))
        .unwrap();
    let dup2 = session
        .create_item(&login_draft(
            "重复二",
            strong,
            vec![url_draft("https://dup2.example.com")],
            None,
        ))
        .unwrap();
    // 6.3：http URL（强唯一密码）
    let http = session
        .create_item(&login_draft(
            "弱URL",
            "portable-copper-drift-99!",
            vec![url_draft("http://plain.example.com")],
            None,
        ))
        .unwrap();
    // 6.4：365+ 天未改
    let stale = session
        .create_item(&login_draft(
            "陈旧",
            "quartz-lantern-vault-meridian-93#",
            vec![url_draft("https://stale.example.com")],
            None,
        ))
        .unwrap();
    backdate_updated_at(&dir, &stale, now - 400 * SECS_PER_DAY);
    // 6.5：字典常见密码（audit_rules 字典命中，High）
    let leak = session
        .create_item(&login_draft(
            "常见密码",
            "password",
            vec![url_draft("https://leak.example.com")],
            None,
        ))
        .unwrap();
    // 6.6：github.com 白名单域名 + 有密码无 TOTP
    let nototp = session
        .create_item(&login_draft(
            "无2FA",
            "granite-harbor-emerald-ratchet-71$",
            vec![url_draft("https://github.com/foo")],
            None,
        ))
        .unwrap();
    // 有 TOTP 的对照条目：同域名但不在 6.6 命中
    let _withtotp = session
        .create_item(&login_draft(
            "有2FA",
            "onyx-voyage-saffron-kestrel-55&",
            vec![url_draft("https://github.com/bar")],
            Some(totp_data()),
        ))
        .unwrap();

    let report = session.health_report(now).unwrap();

    // 6.2：恰一组、含两条，带解密标题
    assert_eq!(report.duplicate_groups.len(), 1, "恰一组重复");
    let group = &report.duplicate_groups[0];
    assert_eq!(group.item_ids, vec![dup1.clone(), dup2.clone()]);
    assert_eq!(group.titles, vec!["重复一".to_owned(), "重复二".to_owned()]);

    // 6.3：仅 http 条目
    assert_eq!(report.http_url_items.len(), 1, "仅 http:// 条目命中");
    assert_eq!(report.http_url_items[0].item_id, http);
    assert_eq!(report.http_url_items[0].title, "弱URL");

    // 6.4：陈旧条目 + 非敏感元数据（距今天数）
    assert_eq!(report.stale_items.len(), 1, "仅陈旧条目命中");
    assert_eq!(report.stale_items[0].item_id, stale);
    assert_eq!(report.stale_items[0].title, "陈旧");
    assert_eq!(
        report.stale_items[0].days_since_update, 400,
        "距今天数按整天向下取整"
    );

    // 6.5：字典命中，携带规则与置信度（无明文）
    assert_eq!(report.leak_suspects.len(), 1, "仅字典命中条目");
    assert_eq!(report.leak_suspects[0].item_id, leak);
    assert_eq!(report.leak_suspects[0].title, "常见密码");
    assert_eq!(
        report.leak_suspects[0].rule,
        cf_session::usecase::health::LeakRule::DictionaryExact
    );
    assert_eq!(
        report.leak_suspects[0].confidence,
        cf_session::usecase::health::LeakConfidence::High
    );

    // 6.6：白名单域名无 TOTP 命中；有 TOTP 对照条目不命中
    assert_eq!(report.missing_totp_items.len(), 1, "仅无 TOTP 条目命中");
    assert_eq!(report.missing_totp_items[0].item_id, nototp);
    assert_eq!(report.missing_totp_items[0].title, "无2FA");

    // 汇总统计
    assert_eq!(report.summary.duplicate_group_count, 1);
    assert_eq!(report.summary.weak_url_count, 1);
    assert_eq!(report.summary.stale_count, 1);
    assert_eq!(report.summary.leak_suspect_count, 1);
    assert_eq!(report.summary.missing_totp_count, 1);
    assert_eq!(report.summary.total_findings, 5, "重复组按组计 1");
}

/// TC-HR-03 陈旧密码阈值边界：恰好 365 天不报、366 天报（与
/// find_stale_passwords「> 阈值」语义一致）。
#[test]
fn 陈旧密码阈值边界与纯函数语义一致() {
    let (session, dir) = unlocked_vault("hr03");
    let now = 1_700_000_000i64;

    let boundary = session
        .create_item(&login_draft(
            "恰满365",
            "tundra-cobalt-falcon-marble-27%",
            vec![url_draft("https://boundary.example.com")],
            None,
        ))
        .unwrap();
    backdate_updated_at(&dir, &boundary, now - 365 * SECS_PER_DAY);

    let report = session.health_report(now).unwrap();
    assert!(
        report.stale_items.is_empty(),
        "恰好 365 天（= 阈值）不报，与纯函数语义一致"
    );

    backdate_updated_at(&dir, &boundary, now - 366 * SECS_PER_DAY);
    let report = session.health_report(now).unwrap();
    assert_eq!(report.stale_items.len(), 1, "满 366 天（> 阈值）应报陈旧");
    assert_eq!(report.stale_items[0].days_since_update, 366);
}

/// TC-HR-04 明文纪律：报告（含 Debug 表示）不得携带密码明文。
#[test]
fn 报告不含明文密码() {
    let (session, _dir) = unlocked_vault("hr04");
    let now = 1_700_000_000i64;
    let canary = "totally-unique-canary-password-88!";
    let canary_common = "unique-canary-birthday-19900115x";

    let id = session
        .create_item(&login_draft(
            "金丝雀",
            canary,
            vec![url_draft("http://canary.example.com")],
            None,
        ))
        .unwrap();
    let _leak = session
        .create_item(&login_draft(
            "金丝雀二",
            "password",
            vec![url_draft("https://canary2.example.com")],
            None,
        ))
        .unwrap();

    let report = session.health_report(now).unwrap();

    // Debug 表示检索（对抗日志误带明文）
    let debug = format!("{report:?}");
    assert!(!debug.contains(canary), "Debug 输出不得泄露明文密码");
    assert!(!debug.contains(canary_common), "Debug 输出不得泄露明文密码");

    // 命中本身成立（否则测试失去意义）：金丝雀进弱 URL 清单且带标题
    assert!(report.http_url_items.iter().any(|f| f.item_id == id));
}

/// TC-HR-05 无密码条目 / 无 URL 条目不误报：SecureNote（无密码字段、
/// 无 URL）与无 URL 的 Login 条目均不出现在任何清单。
#[test]
fn 无密码与无url条目不误报() {
    let (session, _dir) = unlocked_vault("hr05");
    let now = 1_700_000_000i64;

    // SecureNote：无密码字段、无 URL
    let note = ItemDraft {
        title: "纯笔记".to_owned(),
        category: ItemCategory::SecureNote,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields: vec![FieldDraft {
            name: "笔记".to_owned(),
            value: Some("只是普通文字".to_owned()),
            field_type: FieldType::Text,
            designation: None,
            section_index: None,
            position: 0,
        }],
        totp: None,
    };
    let note_id = session.create_item(&note).unwrap();

    // Login：有密码但无 URL、无 TOTP（6.6 因无 URL 不命中，与纯函数一致）
    let nolink = session
        .create_item(&login_draft(
            "无链接登录",
            "velvet-anchor-rustic-plume-63*",
            vec![],
            None,
        ))
        .unwrap();

    let report = session.health_report(now).unwrap();

    for (name, ids) in [
        (
            "duplicate",
            report
                .duplicate_groups
                .iter()
                .flat_map(|g| g.item_ids.iter())
                .collect::<Vec<_>>(),
        ),
        (
            "http_url",
            report.http_url_items.iter().map(|f| &f.item_id).collect(),
        ),
        (
            "stale",
            report.stale_items.iter().map(|f| &f.item_id).collect(),
        ),
        (
            "leak",
            report.leak_suspects.iter().map(|f| &f.item_id).collect(),
        ),
        (
            "missing_totp",
            report
                .missing_totp_items
                .iter()
                .map(|f| &f.item_id)
                .collect(),
        ),
    ] {
        assert!(!ids.contains(&&note_id), "{name} 不得误报无密码条目");
        assert!(!ids.contains(&&nolink), "{name} 不得误报无 URL 条目");
    }
}

/// TC-HR-06 锁定态门禁：health_report → 1001。
#[test]
fn 锁定态拒绝体检报告() {
    let base = temp_base("hr06");
    let brief = create_vault_with_kdf(&base, "锁定体检库", P1, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    assert!(!session.is_unlocked());

    let err = session.health_report(1_700_000_000).unwrap_err();
    assert_eq!(err.code(), 1001);
}
