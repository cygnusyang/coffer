//! T02 集成测试：真实文件库（临时目录）上的建库 → 锁定 → 解锁往返、
//! 错误码 1002 三态合并、NFC 双形式解锁、四类条目 CRUD、搜索、
//! 空闲自动锁定（docs/07 §7 T02 验收标准 ①–⑧）。
//!
//! 测试统一使用快速 KDF 档位（8 MiB / t=1 / p=1）控制运行时长；
//! 生产默认档位（256 MiB / t=3 / p=4）由 `default_kdf_params` 提供。

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft, ItemState};
use cf_domain::totp_data::{TotpAlgo, TotpData};
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::VaultSession;

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG: &str = "correct-horse-battery-staple-42!";

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
        "cf-session-it-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库并开会话（快速档位），返回会话。
fn fresh_session(tag: &str) -> (PathBuf, VaultSession) {
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(&base, tag, STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    (base, session)
}

/// 构造 Login 草稿（username + password 必填齐全，可附 TOTP / URL / 标签）。
fn login_draft(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::Login,
        urls: vec![cf_domain::item::UrlDraft {
            label: Some("登录页".to_owned()),
            url: "https://github.com/login".to_owned(),
            is_primary: true,
            position: 0,
        }],
        tags: vec!["工作".to_owned(), "重要".to_owned()],
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
        totp: Some(TotpData {
            secret: b"0123456789abcdef0123".to_vec(),
            algo: TotpAlgo::Sha1,
            digits: 6,
            period: 30,
        }),
    }
}

/// 构造 CreditCard 草稿（模板必填 cc-number）。
fn credit_card_draft(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        category: ItemCategory::CreditCard,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields: vec![
            FieldDraft {
                name: "持卡人".to_owned(),
                value: Some("ALICE".to_owned()),
                field_type: FieldType::Text,
                designation: Some(Designation::Other("cardholder".to_owned())),
                section_index: None,
                position: 0,
            },
            FieldDraft {
                name: "卡号".to_owned(),
                value: Some("4111111111111111".to_owned()),
                field_type: FieldType::Text,
                designation: Some(Designation::Other("cc-number".to_owned())),
                section_index: None,
                position: 1,
            },
            FieldDraft {
                name: "安全码".to_owned(),
                value: Some("123".to_owned()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Other("cvv".to_owned())),
                section_index: None,
                position: 2,
            },
        ],
        totp: None,
    }
}

/// 构造 Password / SecureNote 草稿。
fn simple_draft(title: &str, category: ItemCategory, value: &str) -> ItemDraft {
    let fields = match category {
        ItemCategory::Password => vec![FieldDraft {
            name: "密码".to_owned(),
            value: Some(value.to_owned()),
            field_type: FieldType::Concealed,
            designation: Some(Designation::Password),
            section_index: None,
            position: 0,
        }],
        ItemCategory::SecureNote => vec![FieldDraft {
            name: "备注".to_owned(),
            value: Some(value.to_owned()),
            field_type: FieldType::Multiline,
            designation: Some(Designation::NotesPlain),
            section_index: None,
            position: 0,
        }],
        _ => vec![],
    };
    ItemDraft {
        title: title.to_owned(),
        category,
        urls: vec![],
        tags: vec![],
        sections: vec![],
        fields,
        totp: None,
    }
}

// ---------------------------------------------------------------- 验收 ①

/// 验收 ①：建库 → 锁定 → 解锁往返；正确密码解锁成功
#[test]
fn 建库_锁定_解锁往返() {
    let (_base, session) = fresh_session("roundtrip_it");
    assert!(!session.is_unlocked());

    // 锁定态数据访问被拒（1001）
    assert_eq!(session.list_items(None).unwrap_err().code(), 1001);

    // 错误密码 → 1002，仍锁定
    assert_eq!(
        session.unlock("not-the-password-9!").unwrap_err().code(),
        1002
    );
    assert!(!session.is_unlocked());

    // 正确密码 → 解锁成功，item_count = 0
    let info = session.unlock(STRONG).unwrap();
    assert!(session.is_unlocked());
    assert_eq!(info.item_count, 0);
    assert_eq!(info.display_name, "roundtrip_it");

    // 写入一条再锁定 → 解锁，数据仍在（往返持久性）
    let id = session.create_item(&login_draft("GitHub 登录")).unwrap();
    session.lock();
    session.unlock(STRONG).unwrap();
    let items = session.list_items(None).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].uuid.to_string(), id);
    assert_eq!(items[0].title, "GitHub 登录");
}

/// 验收 ①：错误密码 / 篡改 wrapped_dek / 篡改 verifier 三者返回同一错误码 1002
#[test]
fn 三态错误码合并为1002() {
    let base = temp_dir("tristate");
    let brief = create_vault_with_kdf(&base, "三态库", STRONG, fast_kdf()).unwrap();
    let vault_dir = base.join(brief.uuid.to_string());

    // 形态一：错误密码
    let s1 = open_vault(&vault_dir).unwrap();
    let err_password = s1.unlock("totally-wrong-password-1!").unwrap_err();
    assert_eq!(err_password.code(), 1002);

    // 形态二：篡改 wrapped_dek.ct_b64（翻转密文一个比特）
    tamper_header_field(&vault_dir, "wrapped_dek", "ct_b64");
    let s2 = open_vault(&vault_dir).unwrap();
    let err_wdek = s2.unlock(STRONG).unwrap_err();
    assert_eq!(err_wdek.code(), 1002, "篡改 wrapped_dek 必须与密码错同码");

    // 重建库后形态三：篡改 verifier.ct_b64
    let brief = create_vault_with_kdf(&base, "三态库乙", STRONG, fast_kdf()).unwrap();
    let vault_dir = base.join(brief.uuid.to_string());
    tamper_header_field(&vault_dir, "verifier", "ct_b64");
    let s3 = open_vault(&vault_dir).unwrap();
    let err_verifier = s3.unlock(STRONG).unwrap_err();
    assert_eq!(err_verifier.code(), 1002, "篡改 verifier 必须与密码错同码");

    // 三态完全同码（不只是同为「错误」）
    assert_eq!(err_password, err_wdek);
    assert_eq!(err_password, err_verifier);
}

/// 篡改 header.json 中指定段指定字段的密文（翻转末字节一个比特）。
fn tamper_header_field(vault_dir: &Path, section: &str, field: &str) {
    let path = vault_dir.join("header.json");
    let text = fs::read_to_string(&path).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let ct_b64 = json[section][field].as_str().unwrap().to_owned();
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(&ct_b64)
        .unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    json[section][field] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&bytes));
    fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();
}

// ---------------------------------------------------------------- 验收 ②

/// 验收 ②：lock() 后 require（数据访问）拒绝且子密钥随解锁态 drop 清零
/// （ZeroizeOnDrop 编译期断言 + 门禁行为断言）
#[test]
fn 锁定后门禁拒绝且密钥类型保证清零() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<cf_crypto::subkeys::SubKeys>();
    assert_zeroize_on_drop::<cf_crypto::aead::SessionKey>();

    let (_base, session) = fresh_session("lock_zero");
    session.unlock(STRONG).unwrap();
    assert!(session.is_unlocked());

    session.lock();
    assert!(!session.is_unlocked());
    assert_eq!(session.get_item("whatever").unwrap_err().code(), 1001);
    assert_eq!(
        session.get_field_value("whatever", "f").unwrap_err().code(),
        1001
    );
    assert_eq!(session.totp_code("whatever").unwrap_err().code(), 1001);
}

// ---------------------------------------------------------------- 验收 ③

/// 验收 ③：NFC 归一化——合成主密码两种 Unicode 形式均可解锁
#[test]
fn nfc_双形式等价密码解锁() {
    let base = temp_dir("nfc");
    // NFC 形式建库（é = U+00E9 预组合）
    let nfc_password = "café-Correct-Horse-42!";
    assert_ne!(
        nfc_password.as_bytes(),
        "cafe\u{0301}-Correct-Horse-42!".as_bytes()
    );
    let brief = create_vault_with_kdf(&base, "NFC 库", nfc_password, fast_kdf()).unwrap();
    let vault_dir = base.join(brief.uuid.to_string());

    // NFD 形式（e + U+0301 组合尖音）解锁
    let session = open_vault(&vault_dir).unwrap();
    session.unlock("cafe\u{0301}-Correct-Horse-42!").unwrap();
    assert!(session.is_unlocked());
}

// ---------------------------------------------------------------- 验收 ④

/// 验收 ④：ItemDraft 校验失败 → 拒绝且不落库
#[test]
fn 校验失败不落库() {
    let (_base, session) = fresh_session("validate");
    session.unlock(STRONG).unwrap();

    // 空标题
    let mut bad = login_draft("占位");
    bad.title = "   ".to_owned();
    let err = session.create_item(&bad).unwrap_err();
    assert_eq!(err.code(), 5002); // InvalidArgument
    assert_eq!(session.list_items(None).unwrap().len(), 0);

    // 缺 Login 必填的 password 字段
    let mut missing = login_draft("缺密码");
    missing
        .fields
        .retain(|f| f.designation != Some(Designation::Password));
    assert!(session.create_item(&missing).is_err());
    assert_eq!(session.list_items(None).unwrap().len(), 0);

    // 字段 position 重复
    let mut dup = login_draft("重复位次");
    for f in &mut dup.fields {
        f.position = 0;
    }
    assert!(session.create_item(&dup).is_err());
    assert_eq!(session.list_items(None).unwrap().len(), 0);
}

// ---------------------------------------------------------------- 验收 ⑤

/// 验收 ⑤：四类条目 CRUD 编排集成（临时目录真文件库）
#[test]
fn 四类条目crud编排() {
    let (_base, session) = fresh_session("crud");
    session.unlock(STRONG).unwrap();

    // ---- 创建（四类） ----
    let login_id = session.create_item(&login_draft("GitHub 登录")).unwrap();
    let card_id = session
        .create_item(&credit_card_draft("招行信用卡"))
        .unwrap();
    let pw_id = session
        .create_item(&simple_draft(
            "路由器密码",
            ItemCategory::Password,
            "wifi-pass-99",
        ))
        .unwrap();
    let note_id = session
        .create_item(&simple_draft(
            "恢复码备忘",
            ItemCategory::SecureNote,
            "第一行\n第二行",
        ))
        .unwrap();
    assert_eq!(session.list_items(None).unwrap().len(), 4);

    // ---- 读取：逐字段往返 ----
    let login = session.get_item(&login_id).unwrap().unwrap();
    assert_eq!(login.title.expose(), "GitHub 登录");
    assert_eq!(login.category, ItemCategory::Login);
    assert_eq!(login.urls.len(), 1);
    assert_eq!(login.urls[0].url.expose(), "https://github.com/login");
    assert_eq!(login.tags.len(), 2);
    assert_eq!(login.fields.len(), 2);
    let password_field = login
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .unwrap();
    assert_eq!(
        password_field.value.as_ref().unwrap().expose(),
        "hunter2-secret"
    );
    let totp = login.totp.as_ref().unwrap();
    assert_eq!(totp.algo, "sha1");
    assert_eq!(totp.digits, 6);
    assert_eq!(totp.period, 30);

    let card = session.get_item(&card_id).unwrap().unwrap();
    assert_eq!(card.category, ItemCategory::CreditCard);
    assert_eq!(card.fields.len(), 3);

    // ---- get_field_value：按需取明文 ----
    let value = session
        .get_field_value(&login_id, &password_field.uuid)
        .unwrap()
        .unwrap();
    assert_eq!(value.expose(), "hunter2-secret");
    // 条目不存在 → ItemNotFound(1011)；字段不存在 → None
    assert_eq!(
        session.get_field_value("no-such", "f").unwrap_err().code(),
        1011
    );
    assert!(session
        .get_field_value(&login_id, "no-such-field")
        .unwrap()
        .is_none());

    // ---- 更新：标题 + 字段 + TOTP 整体替换 ----
    let mut updated = login_draft("GitHub 工作登录");
    updated.fields[1].value = Some("new-password-77".to_owned());
    updated.totp = None; // 删除 TOTP
    session.update_item(&login_id, &updated).unwrap();

    let reloaded = session.get_item(&login_id).unwrap().unwrap();
    assert_eq!(reloaded.title.expose(), "GitHub 工作登录");
    let pw = reloaded
        .fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .unwrap();
    assert_eq!(pw.value.as_ref().unwrap().expose(), "new-password-77");
    assert!(reloaded.totp.is_none(), "TOTP 应被整体替换删除");
    assert_eq!(
        session.list_items(None).unwrap().len(),
        4,
        "update 不改变条目数"
    );

    // 更新不存在的条目 → 1011
    assert_eq!(
        session.update_item("no-such", &updated).unwrap_err().code(),
        1011
    );

    // ---- 收藏 ----
    session.set_favorite(&card_id, true).unwrap();
    assert!(session.get_item(&card_id).unwrap().unwrap().is_favorite);

    // ---- 软删 / 回收站 / 恢复 ----
    // list(None) 返回全部状态（含回收站）；活跃计数用 state=Active 过滤
    session.delete_item(&pw_id, false).unwrap();
    let active = session
        .list_items(Some(cf_store::ItemListFilter {
            state: Some(ItemState::Active),
            ..cf_store::ItemListFilter::default()
        }))
        .unwrap();
    assert_eq!(active.len(), 3);
    let trashed = session
        .list_items(Some(cf_store::ItemListFilter {
            state: Some(ItemState::Trashed),
            ..cf_store::ItemListFilter::default()
        }))
        .unwrap();
    assert_eq!(trashed.len(), 1);
    assert_eq!(trashed[0].uuid.to_string(), pw_id);

    session.restore_item(&pw_id).unwrap();
    assert_eq!(session.list_items(None).unwrap().len(), 4);

    // ---- 硬删：条目数减一，item_count 同步 ----
    session.delete_item(&note_id, true).unwrap();
    let items = session.list_items(None).unwrap();
    assert_eq!(items.len(), 3);
    assert!(session.get_item(&note_id).unwrap().is_none());
    let info = session.unlock(STRONG).unwrap(); // 幂等返回当前信息
    assert_eq!(info.item_count, 3);

    // ---- 删除不存在条目 → 1011 ----
    assert_eq!(
        session.delete_item("no-such", true).unwrap_err().code(),
        1011
    );
}

// ---------------------------------------------------------------- 验收 ⑥

/// 验收 ⑥：搜索子串命中、多关键词全命中（真文件库路径）
#[test]
fn 搜索编排() {
    let (_base, session) = fresh_session("search_it");
    session.unlock(STRONG).unwrap();

    session
        .create_item(&login_draft("GitHub 工作账号"))
        .unwrap();
    session
        .create_item(&simple_draft("github 个人", ItemCategory::Password, "x"))
        .unwrap();
    session
        .create_item(&simple_draft("银行官网", ItemCategory::SecureNote, "y"))
        .unwrap();

    // 子串 + 大小写不敏感
    let hits = session.search("HUB").unwrap();
    assert_eq!(hits.len(), 2);

    // 多关键词全命中
    assert_eq!(session.search("github 工作").unwrap().len(), 1);
    assert_eq!(session.search("github 无此词").unwrap().len(), 0);

    // 空查询 → 空
    assert!(session.search("").unwrap().is_empty());
}

/// 验证码生成（FR-5.4）：6 位数字码 + 倒计时；非 SHA-1 显式拒绝
#[test]
fn totp验证码编排() {
    let (_base, session) = fresh_session("totp_it");
    session.unlock(STRONG).unwrap();
    let id = session.create_item(&login_draft("GitHub 登录")).unwrap();

    let totp = session.totp_code(&id).unwrap();
    assert_eq!(totp.code.len(), 6);
    assert!(totp.code.chars().all(|c| c.is_ascii_digit()));
    assert!(totp.secs_remaining > 0 && totp.secs_remaining <= 30);

    // sha256 记录 → Validation（显式拒绝，错误码 1012）
    let mut bad = login_draft("SHA256 登录");
    bad.totp = Some(TotpData {
        secret: b"0123456789abcdef0123".to_vec(),
        algo: TotpAlgo::Sha256,
        digits: 6,
        period: 30,
    });
    let bad_id = session.create_item(&bad).unwrap();
    assert_eq!(session.totp_code(&bad_id).unwrap_err().code(), 1012);

    // 无 TOTP 的条目 → 1011
    let note_id = session
        .create_item(&simple_draft("纯笔记", ItemCategory::SecureNote, "n"))
        .unwrap();
    assert_eq!(session.totp_code(&note_id).unwrap_err().code(), 1011);
}

// ---------------------------------------------------------------- 验收 ⑦⑧

/// 验收 ⑦（会话级）：空闲超时判定由平台注入时间驱动
#[test]
fn 会话级空闲自动锁定() {
    let (_base, session) = fresh_session("idle_it");
    session.unlock(STRONG).unwrap();

    session.set_idle_timeout_secs(300);
    session.set_last_activity(50_000);
    assert!(!session.is_idle_expired(50_299));
    assert!(session.auto_lock_if_expired(50_300));
    assert!(!session.is_unlocked());
}

/// 验收 ⑧：zxcvbn score < 3 硬拒绝建库（错误码 1010，不只是提示）
#[test]
fn 弱密码硬拒绝建库() {
    let base = temp_dir("weak");
    for weak in ["123456", "password", "qwerty123!"] {
        let err = create_vault_with_kdf(&base, "弱密码库", weak, fast_kdf()).unwrap_err();
        assert_eq!(err.code(), 1010, "「{weak}」应被 WeakPassword 拒绝");
    }
    // 强密码可通过
    let brief = create_vault_with_kdf(&base, "强密码库", STRONG, fast_kdf()).unwrap();
    assert_eq!(brief.display_name, "强密码库");
}

/// 建库参数边界：空库名 / 越界 KDF 被拒
#[test]
fn 建库参数边界() {
    let base = temp_dir("bounds");
    let err = create_vault_with_kdf(&base, "  ", STRONG, fast_kdf()).unwrap_err();
    assert_eq!(err.code(), 5002); // InvalidArgument

    // m_cost 低于 MIN_M_COST_KIB（8 MiB）→ InvalidArgument
    let below_min = cf_crypto::kdf::KdfParams {
        m_cost_kib: 4 * 1024,
        t_cost: 1,
        p_cost: 1,
    };
    let err = create_vault_with_kdf(&base, "越界库", STRONG, below_min).unwrap_err();
    assert_eq!(err.code(), 5002);
}

/// 打开不存在的库 → VaultNotFound(1003)
#[test]
fn 打开不存在的库报未找到() {
    let base = temp_dir("missing_vault");
    let err = match open_vault(&base.join("no-such-vault")) {
        Err(e) => e,
        Ok(_) => panic!("打开不存在的库应报错"),
    };
    assert_eq!(err.code(), 1003);
}
