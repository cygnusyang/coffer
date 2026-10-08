//! FR-6.2 / FR-6.3 Watchtower 编排层验收用例（docs/10 §5，
//! 自动化落点冻结于 §0.3）。纯函数侧（TC-WTW-01~06）归 cf-audit
//! tests/watchtower.rs（G2 产出）；本文件只覆盖编排侧 TC-WTW-07~11。
//!
//! 判据基准 = `docs/10-v0.2验收用例.md` §5；走真实建库 / 解锁 / 会话 API。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// 唯一临时目录（docs/10 §0.4：测试间零共享；pid + 进程内原子计数器）。
fn temp_base(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("cf-session-wtw-{tag}-{}-{seq}", std::process::id()))
}

/// 建库 + 解锁，返回会话。
fn unlocked_vault(tag: &str) -> VaultSession {
    let base = temp_base(tag);
    let brief = create_vault_with_kdf(&base, "体检库", P1, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    session.unlock(P1).unwrap();
    session
}

/// Login 草稿（指定标题 / 密码 / URL）。
fn login_draft(title: &str, password: &str, url: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![UrlDraft {
            label: None,
            url: url.to_owned(),
            is_primary: true,
            position: 0,
        }],
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

/// TC-WTW-07 弱密码复检（FR-6.1 覆盖导入数据）：构造 zxcvbn score < 3
/// 的密码（模拟 CSV 导入——导入路径不设强度门禁）→ 出现在
/// weak_password_items。
#[test]
fn weak_password_detected() {
    let session = unlocked_vault("wtw07");
    // CSV 导入路径（cf_importer::import_csv 不做 zxcvbn 门禁）可写入弱
    // 密码；此处直接经 create_item 构造等价状态（create 同样不设强度门禁，
    // 弱密码只能由 Watchtower 复检兜底——判据点一致）
    let weak_id = session
        .create_item(&login_draft(
            "弱密码条目",
            "123456",
            "https://weak.example.com",
        ))
        .unwrap();

    let report = session.run_watchtower().unwrap();
    assert_eq!(
        report.weak_password_items,
        vec![weak_id],
        "弱密码必须被复检命中"
    );
}

/// TC-WTW-08 编排端到端：建库注入 2 条同密码、1 条弱密码、1 条 http URL
/// → 三个清单各命中预期 item_id；无误报。
#[test]
fn report_end_to_end() {
    let session = unlocked_vault("wtw08");

    let strong = "correct-horse-battery-staple-42!";
    let dup1 = session
        .create_item(&login_draft("重复一", strong, "https://dup1.example.com"))
        .unwrap();
    let dup2 = session
        .create_item(&login_draft("重复二", strong, "https://dup2.example.com"))
        .unwrap();
    let weak = session
        .create_item(&login_draft("弱密码", "123456", "https://weak.example.com"))
        .unwrap();
    let http = session
        .create_item(&login_draft(
            "弱URL",
            "portable-copper-drift-99!",
            "http://plain.example.com",
        ))
        .unwrap();

    let report = session.run_watchtower().unwrap();

    // 恰一组、两条同密码条目。组内顺序非契约（`ItemStore::list` ORDER BY
    // updated_at DESC 无次级键，并列顺序不保证，KNOWN-ISSUES BUG-15）——
    // 按 item_id 排序后比较成员集合，判据只要求命中与无误报（docs/10 §5
    // TC-WTW-08），不约束组内顺序。
    assert_eq!(report.duplicate_groups.len(), 1, "恰一组同密码条目");
    let mut group: Vec<String> = report.duplicate_groups[0].clone();
    let mut expected: Vec<String> = vec![dup1.clone(), dup2.clone()];
    group.sort();
    expected.sort();
    assert_eq!(group, expected, "组内恰为两条同密码条目");
    assert_eq!(
        report.weak_password_items,
        vec![weak.clone()],
        "仅弱密码条目命中"
    );
    assert_eq!(report.http_url_items, vec![http], "仅 http:// 条目命中");
    // 无误报：dup1/dup2 不进弱密码或弱 URL 清单；weak/http 不进重复组
    assert!(!report.weak_password_items.contains(&dup1));
    assert!(!report.http_url_items.contains(&dup2));
    assert!(!report
        .duplicate_groups
        .iter()
        .flatten()
        .any(|id| id == &weak));
}

/// TC-WTW-09 空库：三清单全空，不 panic。
#[test]
fn empty_vault_empty_report() {
    let session = unlocked_vault("wtw09");

    let report = session.run_watchtower().unwrap();
    assert!(report.duplicate_groups.is_empty());
    assert!(report.weak_password_items.is_empty());
    assert!(report.http_url_items.is_empty());
}

/// TC-WTW-10 锁定态门禁：run_security_audit → 1001。
#[test]
fn locked_rejected() {
    let base = temp_base("wtw10");
    let brief = create_vault_with_kdf(&base, "锁定体检库", P1, fast_kdf()).unwrap();
    let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
    assert!(!session.is_unlocked());

    let err = session.run_watchtower().unwrap_err();
    assert_eq!(err.code(), 1001);
}

/// TC-WTW-11 明文即用即弃（对抗）：含独特密码条目 → 跑完 audit 后检索
/// 返回结构，报告结构中无明文密码（只有 item_id / 指纹）。
#[test]
fn report_contains_no_plaintext() {
    let session = unlocked_vault("wtw11");
    let canary = "totally-unique-canary-password-88!";
    let _ = session
        .create_item(&login_draft("金丝雀", canary, "https://canary.example.com"))
        .unwrap();

    let report = session.run_watchtower().unwrap();

    // 结构化检索：报告的全部字符串字段不包含明文
    let all_strings: Vec<&str> = report
        .duplicate_groups
        .iter()
        .flatten()
        .map(String::as_str)
        .chain(report.weak_password_items.iter().map(String::as_str))
        .chain(report.http_url_items.iter().map(String::as_str))
        .collect();
    assert!(
        !all_strings.iter().any(|s| s.contains(canary)),
        "报告不得携带明文密码"
    );

    // Debug 表示检索（对抗日志误带明文）
    let debug = format!("{report:?}");
    assert!(!debug.contains(canary), "Debug 输出不得泄露明文");
    // 指纹不泄露明文（TC-WTW-03 在纯函数侧冻结；此处验证报告载体）
    assert!(
        report
            .duplicate_groups
            .iter()
            .flatten()
            .all(|id| uuid::Uuid::parse_str(id).is_ok()),
        "报告只应携带 item_id / 指纹，不携带可读载荷"
    );
}
