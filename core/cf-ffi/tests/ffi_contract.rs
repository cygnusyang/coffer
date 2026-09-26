//! cf-ffi FFI 契约集成测试（T04 QA 验证，docs/07 §2.3 / §7 T04 验收标准）。
//!
//! 与 `src/api.rs` 内嵌单测互补，本文件聚焦单测未覆盖的路径：
//!
//! 1. **会话注册表并发**：open_vault 同 uuid 多线程并发是否真幂等
//! 2. **uuid 输入归一**：大小写 / 无连字符文本指向同一会话
//! 3. **错误码边界**：5002 / 1003 区分、1001 全 CRUD 门禁、1011 vs None、
//!    1009 写库冲突跨 FFI 形态
//! 4. **掩码泄漏面**：列表 / 搜索 / 详情全部返回值 Debug 序列化不含明文
//!    密码与 TOTP 共享密钥
//! 5. **import_csv 委托链**：cf-ffi → VaultSession → cf_importer 全链路
//!    （预检 / 导入 / 掩码 / TOTP / 重复导入「全部新建」语义）
//! 6. **未守卫导出路径不 panic**：generate_password / strength_estimate /
//!    parse_otpauth_uri 的参数边界（panic 走到 extern "C" 即 abort）
//!
//! 测试约定：每测试独立临时目录；快速 KDF（8 MiB）建库；FFI 入口
//! （`CofferApp` / `VaultSession`）一律走公开 API，不触内部状态。

use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_ffi::api::{CofferApp, VaultSession};
use cf_ffi::types::*;

/// 提取错误码（`unwrap_err` 要求 Ok 类型实现 Debug，而 VaultSession 无
/// Debug 派生——统一走本助手避免该耦合）。
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

/// 每测试独立的临时工作目录。
fn temp_base(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-ffi-qa-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &std::path::Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 打开并解锁一个库（返回会话 + 工作目录字符串）。
fn unlocked_session(
    app: &Arc<CofferApp>,
    base: &std::path::Path,
    uuid: &str,
) -> Arc<VaultSession> {
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), uuid.to_owned())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    session
}

/// 最小合法条目草稿（登录类：用户名 + Concealed 密码，校验要求 Login
/// 类目必须有 username designation 字段）。
fn login_draft(title: &str, password: &str) -> FfiItemDraft {
    FfiItemDraft {
        title: title.to_owned(),
        category: FfiItemCategory::Login,
        urls: vec![FfiUrlDraft {
            label: None,
            url: format!("https://{title}.example.com"),
            is_primary: true,
            position: 0,
        }],
        tags: vec!["qa".to_owned()],
        sections: Vec::new(),
        fields: vec![
            FfiFieldDraft {
                name: "用户名".to_owned(),
                value: Some("qa-user".to_owned()),
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

// ================================================== 1. 会话注册表并发

/// open_vault 同 uuid 多线程并发：注册表互斥锁覆盖「查 → 开 → 插」全程，
/// 任何时刻只允许一个会话实例存在——全部线程拿到的是同一 Arc。
///
/// 若实现把注册表锁提前释放（查完就放、开完再插），两个并发 open 会各自
/// 建会话并互相覆盖插入，本测试将以 `Arc::ptr_eq` 失败暴露。
#[test]
fn 并发open_vault同uuid_单一会话实例() {
    let base = temp_base("concurrent_open");
    let brief = setup_vault(&base, "并发库");
    let base_str = base.to_string_lossy().into_owned();
    let app = CofferApp::new();

    let n = 8;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for _ in 0..n {
        let app = Arc::clone(&app);
        let base = base_str.clone();
        let uuid = brief.uuid.to_string();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            app.open_vault(base, uuid).unwrap()
        }));
    }
    let sessions: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // 全部线程拿到同一实例（Arc 指针相等）
    let first = &sessions[0];
    for s in &sessions[1..] {
        assert!(
            Arc::ptr_eq(first, s),
            "并发 open_vault 产生了多个会话实例——注册表幂等被破坏"
        );
    }

    // 解锁状态共享：经任一引用解锁，其余引用可见
    first.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    for s in &sessions[1..] {
        assert!(s.is_unlocked());
    }

    // lock_all 批量锁定对全部引用生效
    app.lock_all();
    for s in &sessions {
        assert!(!s.is_unlocked());
    }
}

/// uuid 文本归一：大写 / 无连字符变体经 `Uuid::parse_str` 归一为规范文本
/// 后作为注册表键——不同输入形式打开的是同一会话（不会重复建会话）。
#[test]
fn open_vault_uuid文本归一_变体指向同一会话() {
    let base = temp_base("uuid_forms");
    let brief = setup_vault(&base, "归一库");
    let base_str = base.to_string_lossy().into_owned();
    let app = CofferApp::new();

    let canonical = brief.uuid.to_string();
    let upper = canonical.to_uppercase();
    let hyphenless: String = canonical.chars().filter(|c| *c != '-').collect();
    assert_ne!(upper, canonical, "变体测试前提：大写文本不同于规范文本");
    assert_ne!(hyphenless, canonical, "变体测试前提：无连字符文本不同于规范文本");

    let a = app.open_vault(base_str.clone(), upper).unwrap();
    let b = app.open_vault(base_str.clone(), hyphenless).unwrap();
    let c = app.open_vault(base_str, canonical).unwrap();
    assert!(Arc::ptr_eq(&a, &b), "大写变体应命中同一会话");
    assert!(Arc::ptr_eq(&a, &c), "无连字符变体应命中同一会话");
}

// ================================================== 2. 错误码边界

/// uuid 形态错误（5002）与「合法 uuid 但库不存在」（1003）必须可区分，
/// 且路径逃逸形态（../escape）不能绕过 uuid 校验。
#[test]
fn uuid非法5002_库不存在1003_可区分() {
    let base = temp_base("uuid_errors");
    let app = CofferApp::new();
    let base_str = base.to_string_lossy().into_owned();

    // 形态非法 → 5002（含路径逃逸尝试）
    for bad in ["../escape", "not-a-uuid", ""] {
        assert_eq!(
            err_code(app.open_vault(base_str.clone(), bad.to_owned())),
            5002,
            "非法 uuid {bad:?} 应返回 5002"
        );
    }

    // 形态合法但库不存在 → 1003（不是 5002，也不是 panic）
    let missing = uuid::Uuid::now_v7().to_string();
    assert_eq!(err_code(app.open_vault(base_str, missing)), 1003);
}

/// 锁定态全 CRUD 门禁：所有数据访问（含导入）统一 1001，门禁在 Rust 侧。
#[test]
fn 锁定态全crud与导入门禁_1001() {
    let base = temp_base("locked_crud");
    let brief = setup_vault(&base, "门禁库");
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();

    let draft = login_draft("门禁条目", "irrelevant-pw");
    let csv = base.join("never.csv");
    std::fs::write(&csv, b"Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\nA,https://a.example.com,u,p,,,,,\n").unwrap();
    let csv_str = csv.to_string_lossy().into_owned();

    let cases: Vec<(&str, u16)> = vec![
        ("create_item", err_code(session.create_item(draft.clone()))),
        (
            "update_item",
            err_code(session.update_item("nope".to_owned(), draft)),
        ),
        (
            "delete_item",
            err_code(session.delete_item("nope".to_owned(), false)),
        ),
        (
            "restore_item",
            err_code(session.restore_item("nope".to_owned())),
        ),
        (
            "set_favorite",
            err_code(session.set_favorite("nope".to_owned(), true)),
        ),
        ("search", err_code(session.search("x".to_owned()))),
        ("get_item", err_code(session.get_item("nope".to_owned()))),
        ("import_csv", err_code(session.import_csv(csv_str))),
    ];
    for (name, code) in cases {
        assert_eq!(code, 1001, "锁定态 {name} 门禁码应为 1001");
    }
    assert!(!session.is_unlocked(), "失败的访问不得意外解锁");
}

/// 条目不存在的形态区分：读路径 Ok(None)，写路径 1011；
/// get_field_value 条目不存在 → 1011、字段缺失 → Ok(None)（QA F-2：
/// 文档已对齐此语义）。
#[test]
fn 不存在条目_none与1011区分() {
    let base = temp_base("not_found");
    let brief = setup_vault(&base, "不存在库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    // 读路径：Ok(None)
    assert_eq!(session.get_item("nope".to_owned()).unwrap(), None);

    // 写路径：1011
    assert_eq!(
        session.delete_item("nope".to_owned(), false).unwrap_err().code(),
        1011
    );
    assert_eq!(
        session.delete_item("nope".to_owned(), true).unwrap_err().code(),
        1011
    );
    assert_eq!(
        session.restore_item("nope".to_owned()).unwrap_err().code(),
        1011
    );
    assert_eq!(
        session
            .set_favorite("nope".to_owned(), true)
            .unwrap_err()
            .code(),
        1011
    );
    assert_eq!(
        session
            .update_item("nope".to_owned(), login_draft("x", "y"))
            .unwrap_err()
            .code(),
        1011
    );
    assert_eq!(session.totp_code("nope".to_owned()).unwrap_err().code(), 1011);

    // get_field_value：条目不存在 → 1011；条目在、字段不在 → Ok(None)
    assert_eq!(
        session
            .get_field_value("nope".to_owned(), "f".to_owned())
            .unwrap_err()
            .code(),
        1011
    );
    let item_id = session
        .create_item(login_draft("有条目", "pw-123456!"))
        .unwrap();
    let details = session.get_item(item_id.clone()).unwrap().unwrap();
    assert_eq!(details.fields.len(), 2);
    assert_eq!(
        session
            .get_field_value(item_id, "no-such-field".to_owned())
            .unwrap(),
        None
    );
}

/// 写库冲突跨 FFI 形态：外部连接持有 EXCLUSIVE 写锁时，FFI create_item
/// 的 SQLite BUSY 必须映射为 1009（StorageError），且锁释放后恢复可写。
#[test]
fn 写库冲突busy跨ffi映射1009_释放后恢复() {
    let base = temp_base("busy_1009");
    let brief = setup_vault(&base, "冲突库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    // 外部裸连接持有写锁（模拟另一进程/另一会话写库）
    let raw = rusqlite::Connection::open(base.join(brief.uuid.to_string()).join("db.sqlite"))
        .unwrap();
    raw.execute_batch("BEGIN EXCLUSIVE").unwrap();

    let err = session
        .create_item(login_draft("冲突条目", "pw-1009!"))
        .unwrap_err();
    assert_eq!(err.code(), 1009, "SQLITE_BUSY 应映射为 StorageError 1009");

    // 冲突不污染会话：释放锁后写入恢复
    raw.execute_batch("ROLLBACK").unwrap();
    drop(raw);
    let id = session
        .create_item(login_draft("恢复条目", "pw-after!"))
        .unwrap();
    assert!(!id.is_empty());
    assert_eq!(session.get_item(id).unwrap().unwrap().title, "恢复条目");
}

// ================================================== 3. 掩码泄漏面

/// 掩码泄漏面审计：列表 / 搜索 / 详情的全部返回值经 Debug 序列化后
/// 不得出现明文密码或 TOTP 共享密钥（含 base32 文本）；明文只允许
/// 从 get_field_value / totp_code 按需取。
#[test]
fn 掩码泄漏面审计_列表搜索详情不含明文() {
    const PLAIN_PASSWORD: &str = "S3cret-明文-泄漏审计!";
    const TOTP_SECRET_B32: &str = "JBSWY3DPEHPK3PXP"; // RFC 4231 典型测试密钥

    let base = temp_base("mask_audit");
    let brief = setup_vault(&base, "掩码库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let mut draft = login_draft("掩码条目", PLAIN_PASSWORD);
    draft.totp = Some(FfiTotpDraft {
        secret: TOTP_SECRET_B32.as_bytes().to_vec(),
        digits: 6,
        period: 30,
        issuer: Some("GitHub".to_owned()),
        account: Some("alice".to_owned()),
    });
    let item_id = session.create_item(draft).unwrap();

    // 列表与搜索：结构上只有摘要（title / 元数据），逐值 Debug 审计
    let list = session.list_items(None).unwrap();
    assert_eq!(list.len(), 1);
    let hits = session.search("掩码".to_owned()).unwrap();
    assert_eq!(hits.len(), 1);
    for summary in list.iter().chain(hits.iter()) {
        let dump = format!("{summary:?}");
        assert!(!dump.contains(PLAIN_PASSWORD), "列表/搜索泄漏明文密码");
        assert!(!dump.contains(TOTP_SECRET_B32), "列表/搜索泄漏 TOTP 密钥");
    }

    // 详情：Concealed 值为 None；全量 Debug 不含明文密码与 TOTP 密钥
    let details = session.get_item(item_id.clone()).unwrap().unwrap();
    let dump = format!("{details:?}");
    assert!(!dump.contains(PLAIN_PASSWORD), "详情 Debug 泄漏明文密码");
    assert!(!dump.contains(TOTP_SECRET_B32), "详情 Debug 泄漏 TOTP 密钥");

    let concealed = details
        .fields
        .iter()
        .find(|f| f.field_type == FfiFieldType::Concealed)
        .unwrap();
    assert_eq!(concealed.value, None, "Concealed 值必须掩码");
    let username = details
        .fields
        .iter()
        .find(|f| f.field_type == FfiFieldType::Text)
        .unwrap();
    assert_eq!(username.value.as_deref(), Some("qa-user"), "非敏感字段正常下发");

    // TOTP 元数据只有 algo/digits（v0.1 已知边界：TotpData 无 issuer/account
    // 字段，入库存的元数据不带发行方），且绝无密钥
    let totp_meta = details.totp.as_ref().expect("TOTP 元数据应存在");
    assert_eq!(totp_meta.algo, "sha1");
    assert_eq!(totp_meta.digits, 6);
    assert_eq!(totp_meta.period, 30);
    assert_eq!(totp_meta.issuer, None, "v0.1 TotpData 不落 issuer（已知边界）");

    // 明文只从两个按需口取
    let real = session
        .get_field_value(item_id.clone(), concealed.uuid.clone())
        .unwrap();
    assert_eq!(real.as_deref(), Some(PLAIN_PASSWORD));
    let code = session.totp_code(item_id).unwrap();
    assert_eq!(code.code.len(), 6);
    assert!(code.secs_remaining > 0 && code.secs_remaining <= 30);
    let code_dump = format!("{code:?}");
    assert!(!code_dump.contains(TOTP_SECRET_B32), "totp_code 不得回带密钥");
}

// ================================================== 4. import_csv 委托链

/// import_csv 全链路：FFI 预检 → 导入（单事务）→ 详情掩码 → 按需取值
/// → TOTP（完整委托链 cf-ffi → VaultSession → cf_importer / ItemStore）。
/// 重复导入验证「全部新建」策略（计数累加，不报错不覆盖）。
#[test]
fn import_csv全链路跨ffi_预检导入掩码totp() {
    let base = temp_base("import_csv");
    let brief = setup_vault(&base, "导入库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    // 仓库级 1Password 9 列样本（BOM + 正常 TOTP + 空行字段）
    let csv_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/csv/good_basic.csv")
        .canonicalize()
        .unwrap();
    let csv_str = csv_path.to_string_lossy().into_owned();

    // 预检（只读、可反复调用）
    let report = session.precheck_csv(csv_str.clone()).unwrap();
    assert_eq!(report.total_rows, 3, "样本应有 3 数据行：{report:?}");
    assert_eq!(report.valid_rows, 3);

    // 导入（单事务 all-or-nothing）
    let result = session.import_csv(csv_str.clone()).unwrap();
    assert_eq!(result.imported_rows, 3);

    // 导入结果经 FFI 读回：掩码 + 按需取值 + TOTP 委托链
    let hits = session.search("GitHub".to_owned()).unwrap();
    assert_eq!(hits.len(), 1);
    let details = session.get_item(hits[0].uuid.clone()).unwrap().unwrap();
    assert_eq!(details.title, "GitHub");
    assert_eq!(details.urls[0].url, "https://github.com");
    assert!(details.tags.contains(&"dev".to_owned()));
    assert!(details.tags.contains(&"重要".to_owned()));

    let concealed = details
        .fields
        .iter()
        .find(|f| f.field_type == FfiFieldType::Concealed)
        .expect("导入的密码字段应为 Concealed");
    assert_eq!(concealed.value, None, "导入后的密码同样必须掩码");
    let real = session
        .get_field_value(hits[0].uuid.clone(), concealed.uuid.clone())
        .unwrap();
    assert_eq!(real.as_deref(), Some("s3cret!"));

    // TOTP：导入的 otpauth 经映射入库，totp_code 走完整委托链
    let code = session.totp_code(hits[0].uuid.clone()).unwrap();
    assert_eq!(code.code.len(), 6);

    // 「全部新建」策略：重复导入计数累加、不报错
    let again = session.import_csv(csv_str).unwrap();
    assert_eq!(again.imported_rows, 3);
    assert_eq!(session.list_items(None).unwrap().len(), 6);
}

/// 预检 / 导入对不存在文件与坏格式的错误形态：Io 5001 / 格式 2001/2002，
/// 不得 panic（precheck_csv / import_csv 均过 session_call 守卫）。
#[test]
fn 导入错误形态_5001与200x不panic() {
    let base = temp_base("import_err");
    let brief = setup_vault(&base, "导入错误库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    // 文件不存在 → 5001（Io）
    let missing = base.join("no-such.csv").to_string_lossy().into_owned();
    let pre_err = session.precheck_csv(missing.clone()).unwrap_err();
    assert_eq!(pre_err.code(), 5001);
    let imp_err = session.import_csv(missing).unwrap_err();
    assert_eq!(imp_err.code(), 5001);

    // 列数不足 / 非法表头 → 2001 / 2002 段，不 panic
    let bad = base.join("bad.csv");
    std::fs::write(&bad, b"Foo,Bar\n1,2\n").unwrap();
    let err = session.import_csv(bad.to_string_lossy().into_owned()).unwrap_err();
    assert!(
        err.code() == 2001 || err.code() == 2002,
        "坏格式应返回导入类错误，实际 {}",
        err.code()
    );
}

// ================================================== 5. 未守卫导出路径不 panic

/// generate_password / strength_estimate / parse_otpauth_uri 未过
/// session_call 守卫——本测试用恶意参数边界证明这些路径不会 panic
/// （panic 一旦穿透 UniFFI 的 extern "C" 即 abort，进程无法挽回性）。
#[test]
fn 未守卫导出路径_参数边界不panic() {
    let base = temp_base("unguarded");
    let brief = setup_vault(&base, "边界库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    // generate_password：长度越界 / 全字符集关闭 → 1012（Validation），非 panic
    for opts in [
        FfiPasswordGenOptions {
            length: 4,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            exclude_similar_characters: false,
        },
        FfiPasswordGenOptions {
            length: 500,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            exclude_similar_characters: false,
        },
        FfiPasswordGenOptions {
            length: 20,
            numbers: false,
            lowercase_letters: false,
            uppercase_letters: false,
            symbols: false,
            exclude_similar_characters: false,
        },
    ] {
        let err = session.generate_password(opts).unwrap_err();
        assert_eq!(err.code(), 1012, "生成器参数越界应返回 Validation");
    }

    // strength_estimate：空串 / 巨型输入不 panic
    let empty = session.strength_estimate(String::new()).unwrap();
    assert!(empty.score <= 4);
    let huge = session.strength_estimate("x".repeat(10_000)).unwrap();
    assert!(huge.score <= 4);

    // parse_otpauth_uri：非 otpauth / 缺 secret / 坏参数 → 1012，非 panic
    for uri in [
        "https://example.com",
        "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/x",
        "otpauth://totp/x?secret=",
        "otpauth://totp/x?digits=7",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=abc",
    ] {
        let err = session.parse_otpauth_uri(uri.to_owned()).unwrap_err();
        assert_eq!(err.code(), 1012, "otpauth {uri:?} 应返回 Validation");
    }
}

/// 过滤器跨 FFI：state / limit / offset 转换生效（FfiItemFilter →
/// cf_store::ItemListFilter）。
#[test]
fn list_items过滤器跨ffi() {
    let base = temp_base("filter");
    let brief = setup_vault(&base, "过滤库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    for i in 0..4 {
        session
            .create_item(login_draft(&format!("条目{i}"), "pw-x!"))
            .unwrap();
    }

    let paged = session
        .list_items(Some(FfiItemFilter {
            state: None,
            category: None,
            offset: Some(1),
            limit: Some(2),
        }))
        .unwrap();
    assert_eq!(paged.len(), 2, "offset=1 limit=2 应只返回 2 条");

    let trashed = session
        .list_items(Some(FfiItemFilter {
            state: Some(FfiItemState::Trashed),
            category: None,
            offset: None,
            limit: None,
        }))
        .unwrap();
    assert!(trashed.is_empty(), "未删除时应无回收站条目");

    // 软删后 Trashed 过滤命中、Active 过滤减少
    let id = session
        .create_item(login_draft("待删条目", "pw-x!"))
        .unwrap();
    session.delete_item(id, false).unwrap();
    let trashed = session
        .list_items(Some(FfiItemFilter {
            state: Some(FfiItemState::Trashed),
            category: None,
            offset: None,
            limit: None,
        }))
        .unwrap();
    assert_eq!(trashed.len(), 1);
    assert_eq!(trashed[0].state, FfiItemState::Trashed);
}

// ================================================== 6. panic 载荷脱敏（QA F-1 修复验证）

/// panic 载荷脱敏（QA F-1 修复后转正）：`panic_payload_to_error` 对
/// String / &str 载荷**整段丢弃内容**，message 只保留「固定文案 +
/// 类型/字节数指纹」——任何以含敏感值文本 panic 的路径，敏感值都不得
/// 跨 FFI 出现在 `InternalPanic.message` 中（原则：FFI 错误消息里
/// 不允许出现任何运行时拼接的用户数据）。
#[test]
fn panic载荷含敏感串时message已脱敏() {
    const SENSITIVE: &str = "TOPSECRET-主密码-p@ssw0rd";
    let result = cf_ffi::ffi_guard(|| -> i32 {
        panic!("unlock failed: password={SENSITIVE}");
    });
    let err = result.unwrap_err();
    assert_eq!(err.code(), 5999);
    match err {
        cf_ffi::FfiError::InternalPanic { message } => {
            assert!(
                !message.contains(SENSITIVE),
                "载荷敏感值泄漏进 InternalPanic.message: {message:?}"
            );
            assert!(
                !message.contains("unlock failed"),
                "panic 文案不应原样透传: {message:?}"
            );
            assert!(
                message.contains("panic payload redacted (type=String"),
                "message 应为脱敏指纹（固定文案 + 类型/字节数），实际 {message:?}"
            );
        }
        other => panic!("应为 InternalPanic，实际 {other:?}"),
    }
}
