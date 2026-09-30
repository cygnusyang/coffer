//! v0.3.0-T05 会话新能力 FFI 语义测试（FR-7 1PUX 导入链 / FR-2.9 历史 /
//! FR-6.7 体检，docs/09 §6）。
//!
//! 与 `session_v02_ffi_semantics.rs` 同骨架，聚焦跨 FFI 的错误码与语义：
//!
//! 1. **1PUX 预检（FR-7.4~7.7）**：合成附件样本（仓库根
//!    `tests/fixtures/sample_coverage.1pux`）的计数与内核测试
//!    （cf-importer/tests/pux_import.rs）同口径；锁定态可预检；
//! 2. **1PUX 导入（FR-7.1）**：附件密文落 `<vault_dir>/attachments/`；
//!    导入返回的 report 与预检一致（FR-7.4 所见即所得）；重复导入全部
//!    新建（v0.3 固定策略）；FR-7.8 删源建议数据驱动（D-6）；
//! 3. **历史（FR-2.9）**：列表 version DESC、回滚后条目复原且多出新
//!    版本；缺失条目 1011；快照明文不跨 FFI；
//! 4. **体检（FR-6.7）**：五类检测跨 FFI + 汇总一致性；报告不含密码
//!    明文（与 usecase::health 明文纪律同断言）。
//!
//! 断言口径来源（先跑 fixture 预检实测，再冻结断言）：
//! total=30 / importable=30 / attachment=5 / unknown_categories=30
//! / trashed=1 / password_history_dropped=0 / not_imported=空。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cf_crypto::kdf::KdfParams;
use cf_ffi::api::{CofferApp, VaultSession};
use cf_ffi::types::{
    FfiDesignation, FfiFieldDraft, FfiFieldType, FfiHealthReport, FfiItemCategory, FfiItemDraft,
    FfiLeakConfidence, FfiLeakRule,
};

/// 仓库根 tests/fixtures/sample_coverage.1pux（30 条合成样本，5 附件）。
fn pux_fixture() -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sample_coverage.1pux");
    assert!(
        path.exists(),
        "fixture 不存在：{}（需在仓库根 tests/fixtures 下准备 sample_coverage.1pux）",
        path.display()
    );
    path
}

/// 提取错误码。
fn err_code<T>(r: Result<T, cf_ffi::FfiError>) -> u16 {
    match r {
        Ok(_) => panic!("预期应返回错误，实际成功"),
        Err(e) => e.code(),
    }
}

/// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

/// 每测试独立的临时工作目录（pid + 进程内原子计数器）。
fn temp_base(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("cf-ffi-v03-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 打开并解锁一个库。
fn unlocked_session(
    app: &std::sync::Arc<CofferApp>,
    base: &Path,
    uuid: &str,
) -> std::sync::Arc<VaultSession> {
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), uuid.to_owned())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    session
}

/// 最小 Login 草稿（模板必填：username + password）。
fn login_draft(title: &str, username: &str, password: &str) -> FfiItemDraft {
    FfiItemDraft {
        title: title.to_owned(),
        category: FfiItemCategory::Login,
        urls: Vec::new(),
        tags: Vec::new(),
        sections: Vec::new(),
        fields: vec![
            FfiFieldDraft {
                name: "用户名".to_owned(),
                value: Some(username.to_owned()),
                field_type: FfiFieldType::Text,
                designation: Some(FfiDesignation::Username),
                section_index: None,
                position: 0,
            },
            FfiFieldDraft {
                name: "密码".to_owned(),
                value: Some(password.to_owned()),
                field_type: FfiFieldType::Concealed,
                designation: Some(FfiDesignation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

/// 1PUX 预检跨 FFI（FR-7.4~7.7）：合成附件样本计数与内核测试同口径
/// （30 条全降级为 secure_note、5 附件、1 条回收站、无未导入项）。
#[test]
fn pux预检跨ffi_合成附件样本() {
    let base = temp_base("pux_precheck");
    let brief = setup_vault(&base, "预检库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let report = session
        .precheck_1pux(pux_fixture().to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(report.total_items, 30);
    assert_eq!(report.importable_items, 30, "样本无 Tombstone / 附件缺失");
    assert_eq!(report.attachment_count, 5);
    assert_eq!(
        report.category_distribution,
        vec![cf_ffi::types::FfiCategoryCount {
            category: "secure_note".to_owned(),
            count: 30,
        }],
        "占位 categoryUuid 全部降级，分布严格按可导入模型统计（FR-7.4）"
    );
    assert_eq!(report.unknown_categories.len(), 30, "占位类别码全部未识别");
    assert_eq!(report.unknown_categories[0].item_uuid, "IT0001");
    assert_eq!(report.unknown_categories[0].category_uuid, "901");
    assert_eq!(report.trashed_count, 1);
    assert_eq!(report.password_history_dropped, 0);
    assert!(report.unmapped_value_types.is_empty());
    assert!(report.duplicate_document_ids.is_empty());
    assert!(report.not_imported.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("已降级导入为安全笔记")),
        "降级必须 surface 到预检警告（E-4 / D-6）"
    );
}

/// 1PUX 导入跨 FFI（FR-7.1）：imported == importable；附件密文落
/// `<vault_dir>/attachments/`；返回 report 与预检一致（所见即所得）。
#[test]
fn pux导入跨ffi_附件密文落盘() {
    let base = temp_base("pux_import");
    let brief = setup_vault(&base, "导入库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());
    let pux = pux_fixture();

    let precheck = session
        .precheck_1pux(pux.to_string_lossy().into_owned())
        .unwrap();
    let result = session
        .import_1pux(pux.to_string_lossy().into_owned())
        .unwrap();

    assert_eq!(result.imported_items, 30);
    assert_eq!(result.imported_items, precheck.importable_items);
    assert_eq!(
        result.report, precheck,
        "导入返回 report 必须与预检一致（FR-7.4）"
    );

    // 附件密文落盘：<vault_dir>/attachments/ 下应有 5 个密文文件
    let vault_dir = base.join(brief.uuid.to_string());
    let attachments_dir = vault_dir.join("attachments");
    assert!(attachments_dir.is_dir(), "attachments 目录应存在");
    let files: Vec<_> = std::fs::read_dir(&attachments_dir)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(files.len(), 5, "5 个附件条目各落 1 个密文文件");
    for f in &files {
        let meta = f.metadata().unwrap();
        assert!(
            meta.len() > 0,
            "附件密文文件不得为空：{}",
            f.path().display()
        );
    }

    // 条目侧可见：30 条新建（条目 ID 全新 UUIDv7，非 1PUX 原 uuid）
    let items = session.list_items(None).unwrap();
    assert_eq!(items.len(), 30);
    assert!(
        items
            .iter()
            .all(|i| i.title.starts_with("SYNTH-") || i.title.starts_with("边界-")),
        "导入条目标题应来自 1PUX 样本（SYNTH-* / 边界-*）"
    );
    assert!(
        items.iter().any(|i| i.title == "SYNTH-回收站"),
        "回收站条目应按回收站语义导入"
    );
}

/// 1PUX 重复导入（v0.3 固定「全部新建」策略）：二次导入计数再增、
/// 条目总数翻倍，不合并不冲突。
#[test]
fn pux重复导入全部新建() {
    let base = temp_base("pux_repeat");
    let brief = setup_vault(&base, "重复导入库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());
    let pux = pux_fixture().to_string_lossy().into_owned();

    let first = session.import_1pux(pux.clone()).unwrap();
    assert_eq!(first.imported_items, 30);
    let second = session.import_1pux(pux).unwrap();
    assert_eq!(second.imported_items, 30, "二次导入应再次全量新建");
    assert_eq!(
        session.list_items(None).unwrap().len(),
        60,
        "条目总数应翻倍"
    );
}

/// FR-7.8 删源建议（D-6 数据驱动）：fixture 30 条全部未知类别降级 →
/// can_delete = false、degraded_items 逐条 30 条、blockers 含降级说明。
/// （干净样本的可删除分支由 cf-importer 内核测试锁定，fixture 无降级
/// 场景不可用，跨 FFI 只断言本样本的实际行为。）
#[test]
fn pux删源建议数据驱动() {
    let base = temp_base("pux_advice");
    let brief = setup_vault(&base, "删源建议库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let result = session
        .import_1pux(pux_fixture().to_string_lossy().into_owned())
        .unwrap();
    let advice = result.deletion_advice;
    assert!(
        !advice.can_delete,
        "30 条全部降级（结构信息丢失）→ 不可删源"
    );
    assert!(
        advice
            .blockers
            .iter()
            .any(|b| b.contains("未识别类别") && b.contains("降级")),
        "blockers 应聚合说明未识别类别降级：{:?}",
        advice.blockers
    );
    assert_eq!(advice.degraded_items.len(), 30, "每条降级条目逐条列出");
    assert_eq!(advice.degraded_items[0].key, "IT0001");
    assert!(
        advice.degraded_items[0].reason.contains("未识别类别 901"),
        "降级原因应携带原始 categoryUuid"
    );
}

/// 锁定态门禁：import / health / history 需解锁态（1001）；
/// precheck_1pux 纯文件只读、无解锁门禁。
#[test]
fn pux与体检与历史的锁定态门禁() {
    let base = temp_base("pux_gate");
    let brief = setup_vault(&base, "门禁库");
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    assert!(!session.is_unlocked());

    // 锁定态可用：预检（无密钥材料接触）
    let report = session
        .precheck_1pux(pux_fixture().to_string_lossy().into_owned())
        .unwrap();
    assert_eq!(report.total_items, 30, "锁定态预检应正常返回");

    // 锁定态拒绝：1001
    assert_eq!(
        err_code(session.import_1pux(pux_fixture().to_string_lossy().into_owned())),
        1001
    );
    assert_eq!(err_code(session.health_report(0)), 1001);
    assert_eq!(err_code(session.list_history("any-item".to_owned())), 1001);
    assert_eq!(
        err_code(session.restore_history("any-item".to_owned(), "any-history".to_owned())),
        1001
    );
}

/// 历史列表与回滚跨 FFI（FR-2.9）：create → update ×2 → list len=2
/// version DESC → restore(v1) → 标题复原 + list len=3（回滚本身是
/// 一次修改）。
#[test]
fn 历史列表与回滚跨ffi() {
    let base = temp_base("history");
    let brief = setup_vault(&base, "历史库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let item_id = session
        .create_item(login_draft("初版", "alice", "pw-v1"))
        .unwrap();

    // 编辑 2 次（内容各变）→ 2 个历史版本
    session
        .update_item(item_id.clone(), login_draft("二版", "alice", "pw-v2"))
        .unwrap();
    session
        .update_item(item_id.clone(), login_draft("三版", "alice", "pw-v3"))
        .unwrap();

    let entries = session.list_history(item_id.clone()).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].version, 2, "list 必须 version DESC");
    assert_eq!(entries[1].version, 1);
    assert!(entries[0].created_at >= entries[1].created_at);

    // 回滚到 v1（创建态）→ 标题复原；快照明文不跨 FFI（仅元数据）
    session
        .restore_history(item_id.clone(), entries[1].history_uuid.clone())
        .unwrap();
    let details = session.get_item(item_id.clone()).unwrap().unwrap();
    assert_eq!(details.title, "初版", "回滚后标题应复原为 v1 内容");

    // 回滚本身写入一份新版本（当前状态先成为快照）
    let after = session.list_history(item_id).unwrap();
    assert_eq!(after.len(), 3);
    assert_eq!(after[0].version, 3, "回滚产生的版本号最高");
}

/// 历史缺失条目跨 FFI → 1011（list 与 restore 双路径）。
#[test]
fn 历史缺失条目返回1011() {
    let base = temp_base("history_1011");
    let brief = setup_vault(&base, "缺失历史库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    assert_eq!(
        err_code(session.list_history("no-such-item".to_owned())),
        1011
    );
    assert_eq!(
        err_code(session.restore_history("no-such-item".to_owned(), "no-such-history".to_owned())),
        1011
    );
}

/// 体检五类与汇总跨 FFI（FR-6.7）：2 条同密码（重复组 + 泄露命中）+
/// 1 条 http URL；now 注入远未来使全部 stale；summary 与清单一一对应。
#[test]
fn 体检五类与汇总跨ffi() {
    let base = temp_base("health");
    let brief = setup_vault(&base, "体检库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    // A、B 同密码（字典命中 → 重复组 1 + 泄露 2）；C 用 http:// URL
    session
        .create_item(login_draft("账户甲", "alice", "p@ssw0rd"))
        .unwrap();
    session
        .create_item(login_draft("账户乙", "bob", "p@ssw0rd"))
        .unwrap();
    let mut draft_c = login_draft("账户丙", "carol", "xK9#mQ2$vL8pZ4!");
    draft_c.urls = vec![cf_ffi::types::FfiUrlDraft {
        label: None,
        url: "http://example.com".to_owned(),
        is_primary: true,
        position: 0,
    }];
    let c = session.create_item(draft_c).unwrap();

    // now 注入远未来 → 全部条目 stale（> 365 天）
    let report = session.health_report(4_000_000_000).unwrap();

    // 五类清单
    assert_eq!(report.duplicate_groups.len(), 1, "同密码 2 条 → 1 组");
    assert_eq!(report.duplicate_groups[0].item_ids.len(), 2);
    assert_eq!(report.duplicate_groups[0].titles.len(), 2);
    assert_eq!(report.http_url_items.len(), 1, "http:// 条目应命中弱 URL");
    assert_eq!(report.http_url_items[0].item_id, c);
    assert_eq!(report.stale_items.len(), 3, "now 远未来 → 全部 stale");
    assert!(
        report.stale_items.iter().all(|f| f.days_since_update > 365),
        "距今天数应超过 365 天阈值"
    );
    assert_eq!(report.leak_suspects.len(), 2, "p@ssw0rd 字典精确命中");
    assert!(
        report
            .leak_suspects
            .iter()
            .all(|f| f.rule == FfiLeakRule::DictionaryExact
                && f.confidence == FfiLeakConfidence::High)
    );
    assert_eq!(report.missing_totp_items.len(), 0, "example.com 不在白名单");

    // 汇总与清单一一对应（total_findings = 各类计数之和）
    let s = report.summary;
    assert_eq!(s.duplicate_group_count, 1);
    assert_eq!(s.weak_url_count, 1);
    assert_eq!(s.stale_count, 3);
    assert_eq!(s.leak_suspect_count, 2);
    assert_eq!(s.missing_totp_count, 0);
    assert_eq!(s.total_findings, 7, "重复 1 + 弱URL 1 + 陈旧 3 + 泄露 2");
}

/// 体检报告不含密码明文（docs/09 §8 风险 7 明文纪律跨 FFI 冻结）：
/// Debug 渲染检索不到构造密码明文与隐藏字段值。
#[test]
fn 体检报告不含明文() {
    let base = temp_base("health_plain");
    let brief = setup_vault(&base, "明文纪律库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    // 两处同密码（会进重复组与泄露清单——最可能携带明文的位置）
    const SECRET_PW: &str = "S3cret-Fixture-Pw-42!";
    session
        .create_item(login_draft("账户甲", "alice", SECRET_PW))
        .unwrap();
    session
        .create_item(login_draft("账户乙", "bob", SECRET_PW))
        .unwrap();

    let report: FfiHealthReport = session.health_report(4_000_000_000).unwrap();
    let rendered = format!("{report:?}");
    assert!(
        !rendered.contains(SECRET_PW),
        "体检报告 Debug 渲染不得包含密码明文"
    );
    assert!(
        !rendered.contains("alice"),
        "报告只携带条目 ID 与标题，不含字段值（用户名等非报告载荷）"
    );
}
