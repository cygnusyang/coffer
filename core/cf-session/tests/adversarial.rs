//! T02 QA 验证测试（adversarial / boundary pass，2026-09-29）。
//!
//! 工程师自报 304 全绿之外的**独立攻击者视角验证**，覆盖：
//!
//! 1. 解锁流：连续错密码、KDF 参数篡改（越界 / 界内极端）、wrapped_dek /
//!    verifier 跨库替换与交叉组合、salt 篡改、db 缺失、版本过新；
//! 2. 会话与并发：双会话同库写入、lock() 后无密码缓存绕过、失败后重解锁；
//! 3. CRUD 边界：1001 字段往返、重复 position（urls/sections）、重复 URL 值、
//!    软删→恢复→硬删→item_count 全程一致、收藏与回收/更新交叉；
//! 4. 搜索语义：emoji、NFC/NFD 混排（QA #3 修复后双向命中）、空白查询；
//! 5. idle：时钟回拨、i64 边界、timeout=1；
//! 6. KDF 参数：极小/极端参数建库 → header 记录 → 解锁往返；kdf 段缺失无兜底。
//!
//! 原「已知问题 #1/#2/#3」（update 清空收藏 / 复活回收站条目 / 搜索无
//! NFC 归一化）已随修复批（cf-totp parse_totp_uri 修复同批）**反转为
//! 断言正确行为**，见 §3 / §4 对应测试。

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use cf_crypto::kdf::KdfParams;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft, ItemState, UrlDraft};
use cf_session::unlock::{create_vault_with_kdf, open_vault};
use cf_session::VaultSession;
use serde_json::{json, Value};

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG: &str = "correct-horse-battery-staple-42!";

fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-session-qa-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库并开会话（快速档位），返回 (base, vault_dir, session)。
fn fresh(tag: &str) -> (PathBuf, PathBuf, VaultSession) {
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(&base, tag, STRONG, fast_kdf()).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    (base, dir, session)
}

/// 最小 Login 草稿（username + password 必填齐全）。
fn login_draft(title: &str) -> ItemDraft {
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
                value: Some("hunter2".to_owned()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

fn read_header_json(vault_dir: &Path) -> Value {
    let text = fs::read_to_string(vault_dir.join("header.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn write_header_json(vault_dir: &Path, v: &Value) {
    fs::write(
        vault_dir.join("header.json"),
        serde_json::to_vec_pretty(v).unwrap(),
    )
    .unwrap();
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// 打开库并取错误（VaultSession 未实现 Debug，不能用 unwrap_err）。
fn open_err(vault_dir: &Path) -> cf_domain::CfError {
    match open_vault(vault_dir) {
        Err(e) => e,
        Ok(_) => panic!("open_vault 应失败：{}", vault_dir.display()),
    }
}

// ================================================================ 1. 解锁流

/// 连续 5 次错密码：全部 1002、会话保持锁定、之后正确密码仍可解锁。
#[test]
fn 连续错密码全部1002且可恢复() {
    let (_base, _dir, session) = fresh("adv_bruteforce");
    for i in 0..5 {
        let err = session
            .unlock(&format!("wrong-password-attempt-{i}!"))
            .unwrap_err();
        assert_eq!(err.code(), 1002, "第 {i} 次错密码应报 1002");
        assert!(!session.is_unlocked(), "错密码后必须保持锁定");
    }
    session.unlock(STRONG).unwrap();
    assert!(session.is_unlocked());
}

/// 篡改 header KDF 参数越界：open_vault 阶段即拒绝（Corrupted 1005），
/// 不 panic、不 OOM、不进入 Argon2 执行。
#[test]
fn 篡改kdf参数越界建open即拒() {
    let cases: [(&str, Value); 4] = [
        // m_cost 超上限（4 GiB < 5 GiB）—— 防 OOM 的主防线
        ("m超大", json!({"m_cost_kib": 5 * 1024 * 1024, "t_cost": 1, "p_cost": 1})),
        // m_cost 低于下限 8 MiB
        ("m过小", json!({"m_cost_kib": 4 * 1024, "t_cost": 1, "p_cost": 1})),
        // t_cost 超上限 100
        ("t越界", json!({"m_cost_kib": 8 * 1024, "t_cost": 101, "p_cost": 1})),
        // p_cost 超上限 64
        ("p越界", json!({"m_cost_kib": 8 * 1024, "t_cost": 1, "p_cost": 65})),
    ];
    for (tag, kdf) in cases {
        let (base, dir, _s) = fresh("adv_kdf_oob");
        let mut header = read_header_json(&dir);
        header["kdf"] = kdf;
        write_header_json(&dir, &header);

        let err = open_err(&dir);
        assert_eq!(
            err.code(),
            1005,
            "{tag}: 越界 KDF 参数应在 open_vault 阶段报 Corrupted"
        );
        drop(base);
    }
}

/// 界内极端 t_cost（t=100，m=8MiB）：合法参数，建库与解锁应正常往返。
/// （DoS 上界 = 界内最大 m=4GiB/t=100，属参数标定权衡，见 QA 报告注记。）
#[test]
fn 界内极端t参数建库解锁往返() {
    let base = temp_dir("adv_t100");
    let kdf = KdfParams::new(8 * 1024, 100, 1).unwrap();
    let brief = create_vault_with_kdf(&base, "t100库", STRONG, kdf).unwrap();
    let dir = base.join(brief.uuid.to_string());
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap();
    assert!(session.is_unlocked());
}

/// wrapped_dek 用另一库的整段替换（AAD 钉死 vault_uuid，跨库必失败）。
#[test]
fn wrapped_dek跨库替换报1002() {
    let (base_a, dir_a, _s) = fresh("adv_x_wdek_a");
    let (base_b, dir_b, _s) = fresh("adv_x_wdek_b");

    let wrapped_b = read_header_json(&dir_b)["wrapped_dek"].clone();
    let mut header_a = read_header_json(&dir_a);
    header_a["wrapped_dek"] = wrapped_b;
    write_header_json(&dir_a, &header_a);

    let session = open_vault(&dir_a).unwrap();
    let err = session.unlock(STRONG).unwrap_err();
    assert_eq!(err.code(), 1002, "跨库 wrapped_dek 替换必须归一 1002");
    drop((base_a, base_b));
}

/// verifier 用另一库的整段替换 → 1002。
#[test]
fn verifier跨库替换报1002() {
    let (base_a, dir_a, _s) = fresh("adv_x_ver_a");
    let (base_b, dir_b, _s) = fresh("adv_x_ver_b");

    let verifier_b = read_header_json(&dir_b)["verifier"].clone();
    let mut header_a = read_header_json(&dir_a);
    header_a["verifier"] = verifier_b;
    write_header_json(&dir_a, &header_a);

    let session = open_vault(&dir_a).unwrap();
    assert_eq!(session.unlock(STRONG).unwrap_err().code(), 1002);
    drop((base_a, base_b));
}

/// 交叉组合：A 库 wrapped_dek + B 库 verifier 同时替换 → 仍 1002
/// （不存在「凑对一段就放过」的路径）。
#[test]
fn wrapped_dek与verifier交叉组合报1002() {
    let (base_a, dir_a, _s) = fresh("adv_x_mix_a");
    let (base_b, dir_b, _s) = fresh("adv_x_mix_b");

    let header_b = read_header_json(&dir_b);
    let mut header_a = read_header_json(&dir_a);
    header_a["wrapped_dek"] = header_b["wrapped_dek"].clone();
    header_a["verifier"] = header_b["verifier"].clone();
    write_header_json(&dir_a, &header_a);

    let session = open_vault(&dir_a).unwrap();
    assert_eq!(session.unlock(STRONG).unwrap_err().code(), 1002);
    drop((base_a, base_b));
}

/// 同库内段互搬：verifier 段塞入本库 wrapped_dek 密文（AAD purpose 不同）→ 1002。
#[test]
fn 同库verifier与wrapped_dek互搬报1002() {
    let (base, dir, _s) = fresh("adv_swap");
    let header = read_header_json(&dir);
    let mut tampered = header.clone();
    tampered["verifier"] = header["wrapped_dek"].clone();
    write_header_json(&dir, &tampered);

    let session = open_vault(&dir).unwrap();
    assert_eq!(
        session.unlock(STRONG).unwrap_err().code(),
        1002,
        "同库跨段（AAD purpose 不同）互搬必须失败"
    );
    drop(base);
}

/// salt 被替换为另一合法 32 字节盐 → open 通过、unlock 归一 1002。
#[test]
fn salt被篡改报1002() {
    let (base, dir, _s) = fresh("adv_salt");
    let mut header = read_header_json(&dir);
    header["kdf"]["salt_b64"] = json!(b64_encode(&[0x77u8; 32]));
    write_header_json(&dir, &header);

    let session = open_vault(&dir).unwrap();
    assert_eq!(session.unlock(STRONG).unwrap_err().code(), 1002);
    drop(base);
}

/// db.sqlite 缺失：已开会话 unlock → 1002（不区分损坏形态）；
/// 重新 open_vault → 1003（布局检查，尚未接触密钥材料）。
#[test]
fn db缺失解锁1002重开1003() {
    let (base, dir, session) = fresh("adv_nodb");
    session.unlock(STRONG).unwrap(); // 先解锁，再锁会话、删库
    session.lock(); // 否则幂等 unlock 不触碰磁盘（按设计）
    fs::remove_file(dir.join("db.sqlite")).unwrap();

    assert_eq!(session.unlock(STRONG).unwrap_err().code(), 1002);
    assert_eq!(open_err(&dir).code(), 1003);
    drop(base);
}

/// format_version 篡改为更大值 → UnsupportedFormat(1006)，提示升级。
#[test]
fn 版本过新报1006() {
    let (base, dir, _s) = fresh("adv_toonew");
    let mut header = read_header_json(&dir);
    header["format_version"] = json!(99);
    write_header_json(&dir, &header);

    assert_eq!(open_err(&dir).code(), 1006);
    drop(base);
}

// ============================================================ 2. 并发与会话

/// 两个 VaultSession 同时 open 同一库（WAL），交替写入互不干扰、
/// 计数与列表在任一会话中一致。
#[test]
fn 两会话交替写同一库一致() {
    let (base, dir, s1) = fresh("adv_two_sess");
    let s2 = open_vault(&dir).unwrap();
    s1.unlock(STRONG).unwrap();
    s2.unlock(STRONG).unwrap();

    // 交替写：s1 奇数、s2 偶数
    for i in 0..6 {
        let session = if i % 2 == 0 { &s1 } else { &s2 };
        session
            .create_item(&login_draft(&format!("条目-{i:02}")))
            .unwrap();
    }

    let list1 = s1.list_items(None).unwrap();
    let list2 = s2.list_items(None).unwrap();
    assert_eq!(list1.len(), 6);
    assert_eq!(list2.len(), 6, "两会话看到的列表必须一致");

    // 第三次 open：item_count 应为 6（WAL 持久化 + meta 一致）
    let s3 = open_vault(&dir).unwrap();
    assert_eq!(s3.unlock(STRONG).unwrap().item_count, 6);
    drop(base);
}

/// 两会话在独立线程上**真并发**写同一库。设计上 FFI 层以「同 uuid 单会话」
/// 规避双写（docs/07 §2.3），本测试验证底层边界行为：写入要么全部成功、
/// 要么报错（绝不允许 panic / 静默丢数）。
#[test]
fn 两会话线程并发写不panic不丢数() {
    let (base, dir, s1) = fresh("adv_threads");
    let s2 = open_vault(&dir).unwrap();
    s1.unlock(STRONG).unwrap();
    s2.unlock(STRONG).unwrap();

    let ok = std::sync::atomic::AtomicUsize::new(0);
    let failed = std::sync::atomic::AtomicUsize::new(0);
    {
        let ok = &ok;
        let failed = &failed;
        std::thread::scope(|scope| {
            for session in [&s1, &s2] {
                scope.spawn(move || {
                    for i in 0..10 {
                        match session.create_item(&login_draft(&format!("并发-{i}"))) {
                            Ok(_) => {
                                ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                // 设计上双会话并发写被 FFI 层规避（docs/07 §2.3
                                // 单 uuid 单会话）；底层遇 SQLITE_BUSY 显式报
                                // StorageError(1009) 即可，不许 panic/半写
                                assert_eq!(
                                    e.code(),
                                    1009,
                                    "并发冲突只允许显式 StorageError，实际 {e:?}"
                                );
                                failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        });
    }
    let total_written = s1.list_items(None).unwrap().len();
    assert_eq!(
        total_written,
        ok.load(std::sync::atomic::Ordering::Relaxed),
        "成功报数与实际落库数必须一致（不许半写）"
    );
    let _ = failed.load(std::sync::atomic::Ordering::Relaxed);
    drop(base);
}

/// lock() 后不存在密码缓存绕过：错误密码仍 1002（无残留凭据），
/// 重新用正确密码解锁后数据完整。
#[test]
fn lock后无密码缓存绕过() {
    let (base, _dir, session) = fresh("adv_no_cache");
    session.unlock(STRONG).unwrap();
    let id = session.create_item(&login_draft("缓存测试")).unwrap();

    session.lock();
    // 若 lock() 后仍残留凭据/会话，这里会错误成功
    assert_eq!(session.unlock("not-the-password-9!").unwrap_err().code(), 1002);
    assert!(!session.is_unlocked());

    session.unlock(STRONG).unwrap();
    assert_eq!(session.get_item(&id).unwrap().unwrap().title.expose(), "缓存测试");
    drop(base);
}

/// 解锁失败 → 失败 → 成功：失败路径不污染后续解锁。
#[test]
fn 多次解锁失败后成功正常() {
    let (base, _dir, session) = fresh("adv_retry");
    assert!(session.unlock("wrong-1!").is_err());
    assert!(session.unlock("wrong-2!").is_err());
    session.unlock(STRONG).unwrap();
    assert!(session.is_unlocked());
    assert!(session.create_item(&login_draft("重试后写入")).is_ok());
    drop(base);
}

// ============================================================ 3. CRUD 边界

/// 1001 字段条目：创建 → 逐字段往返 → 整体替换为 501 字段 → 往返。
#[test]
fn 千字段条目往返与整体替换() {
    let (base, _dir, session) = fresh("adv_1001f");
    session.unlock(STRONG).unwrap();

    let mut draft = login_draft("千字段条目");
    draft.fields.clear();
    // 字段 0/1 保持模板必填（username + password）
    draft.fields.push(FieldDraft {
        name: "f0000".to_owned(),
        value: Some("value-0000-密码🔑".to_owned()),
        field_type: FieldType::Text,
        designation: Some(Designation::Username),
        section_index: None,
        position: 0,
    });
    draft.fields.push(FieldDraft {
        name: "f0001".to_owned(),
        value: Some("value-0001-密码🔑".to_owned()),
        field_type: FieldType::Concealed,
        designation: Some(Designation::Password),
        section_index: None,
        position: 1,
    });
    for i in 2..1001usize {
        draft.fields.push(FieldDraft {
            name: format!("f{i:04}"),
            value: Some(format!("value-{i:04}-密码🔑")),
            field_type: FieldType::Text,
            designation: None,
            section_index: None,
            position: i as i32,
        });
    }
    let id = session.create_item(&draft).unwrap();

    let got = session.get_item(&id).unwrap().unwrap();
    assert_eq!(got.fields.len(), 1001);
    for f in &got.fields {
        let idx: usize = f.name.expose()[1..].parse().unwrap();
        assert_eq!(f.value.as_ref().unwrap().expose(), format!("value-{idx:04}-密码🔑"));
        assert_eq!(f.position as usize, idx);
    }

    // 整体替换为 501 字段（删旧插新）
    let mut updated = draft.clone();
    updated.fields.truncate(501);
    updated.fields[0].value = Some("changed-user".to_owned());
    session.update_item(&id, &updated).unwrap();

    let got = session.get_item(&id).unwrap().unwrap();
    assert_eq!(got.fields.len(), 501);
    assert_eq!(got.fields[0].value.as_ref().unwrap().expose(), "changed-user");
    assert!(
        !got.fields.iter().any(|f| f.name.expose() == "f0600"),
        "被替换掉的字段不应残留"
    );
    drop(base);
}

/// urls 与 sections 的重复 position 均被拒绝且不落库。
#[test]
fn urls与sections重复position拒绝() {
    let (base, _dir, session) = fresh("adv_dup_pos");
    session.unlock(STRONG).unwrap();

    // urls 重复 position
    let mut bad_urls = login_draft("重复URL位次");
    bad_urls.urls = vec![
        UrlDraft {
            label: Some("a".to_owned()),
            url: "https://a.example.com".to_owned(),
            is_primary: true,
            position: 0,
        },
        UrlDraft {
            label: Some("b".to_owned()),
            url: "https://b.example.com".to_owned(),
            is_primary: false,
            position: 0,
        },
    ];
    assert_eq!(session.create_item(&bad_urls).unwrap_err().code(), 5002);
    assert_eq!(session.list_items(None).unwrap().len(), 0);

    // sections 重复 position
    let mut bad_sections = login_draft("重复分区位次");
    bad_sections.sections = vec![
        cf_domain::item::SectionDraft {
            title: "分区甲".to_owned(),
            position: 3,
        },
        cf_domain::item::SectionDraft {
            title: "分区乙".to_owned(),
            position: 3,
        },
    ];
    assert_eq!(session.create_item(&bad_sections).unwrap_err().code(), 5002);
    assert_eq!(session.list_items(None).unwrap().len(), 0);
    drop(base);
}

/// 重复 URL 值（不同 label / position）允许入库且往返一致。
#[test]
fn 重复url值允许() {
    let (base, _dir, session) = fresh("adv_dup_url");
    session.unlock(STRONG).unwrap();

    let mut draft = login_draft("同值双URL");
    draft.urls = vec![
        UrlDraft {
            label: Some("登录页".to_owned()),
            url: "https://same.example.com".to_owned(),
            is_primary: true,
            position: 0,
        },
        UrlDraft {
            label: Some("备用入口".to_owned()),
            url: "https://same.example.com".to_owned(),
            is_primary: false,
            position: 1,
        },
    ];
    let id = session.create_item(&draft).unwrap();
    let got = session.get_item(&id).unwrap().unwrap();
    assert_eq!(got.urls.len(), 2);
    assert_eq!(got.urls[0].url.expose(), "https://same.example.com");
    assert_eq!(got.urls[1].url.expose(), "https://same.example.com");
    drop(base);
}

/// 软删 → 恢复 → 硬删全程 item_count 与各 state 计数一致。
#[test]
fn 软删恢复硬删item_count全程一致() {
    let (base, _dir, session) = fresh("adv_count");
    session.unlock(STRONG).unwrap();

    let ids: Vec<String> = (0..3)
        .map(|i| session.create_item(&login_draft(&format!("计数-{i}"))).unwrap())
        .collect();
    let count = || session.unlock(STRONG).unwrap().item_count;
    let active = || {
        session
            .list_items(Some(cf_store::ItemListFilter {
                state: Some(ItemState::Active),
                ..cf_store::ItemListFilter::default()
            }))
            .unwrap()
            .len()
    };
    let trashed = || {
        session
            .list_items(Some(cf_store::ItemListFilter {
                state: Some(ItemState::Trashed),
                ..cf_store::ItemListFilter::default()
            }))
            .unwrap()
            .len()
    };

    assert_eq!((count(), active(), trashed()), (3, 3, 0));

    // 软删：条目仍存在，item_count 不减
    session.delete_item(&ids[0], false).unwrap();
    assert_eq!((count(), active(), trashed()), (3, 2, 1), "软删不减 item_count");

    // 重复软删（已在回收站再软删一次）应幂等成功
    session.delete_item(&ids[0], false).unwrap();
    assert_eq!((count(), trashed()), (3, 1));

    // 恢复
    session.restore_item(&ids[0]).unwrap();
    assert_eq!((count(), active(), trashed()), (3, 3, 0));

    // 硬删：item_count 减一
    session.delete_item(&ids[1], true).unwrap();
    assert_eq!((count(), active()), (2, 2));
    assert!(session.get_item(&ids[1]).unwrap().is_none());

    // 从回收站硬删同样减一
    session.delete_item(&ids[2], false).unwrap();
    session.delete_item(&ids[2], true).unwrap();
    assert_eq!((count(), active(), trashed()), (1, 1, 0));
    drop(base);
}

/// 收藏与回收站交叉：收藏 → 软删 → 回收站中仍收藏 → 恢复后仍收藏。
#[test]
fn 收藏与回收站交叉保持() {
    let (base, _dir, session) = fresh("adv_fav_trash");
    session.unlock(STRONG).unwrap();

    let id = session.create_item(&login_draft("收藏交叉")).unwrap();
    session.set_favorite(&id, true).unwrap();
    session.delete_item(&id, false).unwrap();

    let trashed = session
        .list_items(Some(cf_store::ItemListFilter {
            state: Some(ItemState::Trashed),
            ..cf_store::ItemListFilter::default()
        }))
        .unwrap();
    assert_eq!(trashed.len(), 1);
    assert!(trashed[0].is_favorite, "软删不应清除收藏标记");

    session.restore_item(&id).unwrap();
    assert!(
        session.get_item(&id).unwrap().unwrap().is_favorite,
        "恢复后收藏标记应保留"
    );
    drop(base);
}

/// QA 已知问题 #1（已修复，断言**正确行为**）：`usecase::items::update_item`
/// 整行替换时不得硬编码收藏字段——编辑内容**保留** `is_favorite` /
/// `fav_index`（收藏的增减只走 set_favorite）。
#[test]
fn 更新条目保留收藏标记() {
    let (base, _dir, session) = fresh("adv_fav_update");
    session.unlock(STRONG).unwrap();

    let id = session.create_item(&login_draft("收藏后编辑")).unwrap();
    session.set_favorite(&id, true).unwrap();
    assert!(session.get_item(&id).unwrap().unwrap().is_favorite);

    session.update_item(&id, &login_draft("收藏后编辑-改标题")).unwrap();
    assert!(
        session.get_item(&id).unwrap().unwrap().is_favorite,
        "编辑内容不得清空收藏标记（QA #1 已修复）"
    );

    // 取消收藏后编辑同样保持「未收藏」，不被重置为其他值
    session.set_favorite(&id, false).unwrap();
    session.update_item(&id, &login_draft("收藏后编辑-再改")).unwrap();
    assert!(!session.get_item(&id).unwrap().unwrap().is_favorite);
    drop(base);
}

/// QA 已知问题 #2（已修复，断言**正确行为**）：update_item 只作用于
/// Active 态条目；对回收站条目返回 `Validation`（1012，可操作提示：
/// 先恢复再编辑），**不静默改状态、不复活**。
///
/// 选 1012 而非 ItemNotFound(1011) 的理由：条目真实存在，报「不存在」
/// 会误导调用方；1012 的定位正是「可操作的用户提示」。
#[test]
fn 更新回收站条目拒绝1012且保持trashed() {
    let (base, _dir, session) = fresh("adv_trash_update");
    session.unlock(STRONG).unwrap();

    let id = session.create_item(&login_draft("回收站编辑")).unwrap();
    session.delete_item(&id, false).unwrap();
    assert_eq!(
        session.get_item(&id).unwrap().unwrap().state,
        ItemState::Trashed
    );

    let err = session
        .update_item(&id, &login_draft("回收站编辑-改标题"))
        .unwrap_err();
    assert_eq!(err.code(), 1012, "更新回收站条目必须被显式拒绝");
    assert_eq!(
        session.get_item(&id).unwrap().unwrap().state,
        ItemState::Trashed,
        "被拒的更新不得改变条目状态（不复活）"
    );

    // 归档条目同样拒绝
    session.restore_item(&id).unwrap();
    // 恢复后先收藏、再归档路径：v0.1 无独立归档 API，Trashed 路径已覆盖门禁；
    // Active 条目正常更新不受影响（对照）
    session.update_item(&id, &login_draft("回收站编辑-恢复后可改")).unwrap();
    assert_eq!(
        session.get_item(&id).unwrap().unwrap().state,
        ItemState::Active
    );
    drop(base);
}

// ============================================================ 4. 搜索语义

/// emoji 与 ZWJ 组合字符标题可被搜索命中。
#[test]
fn emoji标题搜索() {
    let (base, _dir, session) = fresh("adv_search_emoji");
    session.unlock(STRONG).unwrap();

    session.create_item(&login_draft("🔑 GitHub 钥匙")).unwrap();
    session.create_item(&login_draft("👨‍👩‍👧‍👦 家庭账户 Apple")).unwrap();
    session.create_item(&login_draft("银行储蓄")).unwrap();

    assert_eq!(session.search("github").unwrap().len(), 1);
    assert_eq!(session.search("🔑").unwrap().len(), 1, "emoji 关键词应命中");
    assert_eq!(session.search("Apple").unwrap().len(), 1);
    // emoji 是标题的独立 token 之外的子串：与汉字相邻也可命中
    assert_eq!(session.search("钥匙").unwrap().len(), 1);
    drop(base);
}

/// QA 已知问题 #3（已修复，断言**正确行为**）：搜索匹配 = NFC 归一化 +
/// 小写折叠（docs/03 §3.3），查询串与标题两侧都归一——NFC 查询与 NFD
/// 查询**双向**命中 NFC / NFD 两种形式的标题（与 unlock 流主密码归一化
/// 同构，防输入法混排）。
#[test]
fn 搜索nfc归一化双向命中() {
    let (base, _dir, session) = fresh("adv_search_nfc");
    session.unlock(STRONG).unwrap();

    // 两个「视觉相同」的标题：NFC（U+00E9）与 NFD（e + U+0301）
    let nfc_id = session.create_item(&login_draft("café NFC 形式库")).unwrap();
    let nfd_id = session
        .create_item(&login_draft("cafe\u{0301} NFD 形式库"))
        .unwrap();
    assert_ne!(nfc_id, nfd_id);

    // ASCII 前缀两种形式都能命中（归一化无关路径，保证测试前提）
    assert_eq!(session.search("形式库").unwrap().len(), 2);

    // NFC 查询命中两条（NFC + NFD 标题都归一后匹配）
    let nfc_hits = session.search("café").unwrap();
    assert_eq!(nfc_hits.len(), 2, "NFC 查询应双向命中（QA #3 已修复）");

    // NFD 查询同样命中两条
    let nfd_hits = session.search("cafe\u{0301}").unwrap();
    assert_eq!(nfd_hits.len(), 2, "NFD 查询应双向命中（QA #3 已修复）");

    // 两次查询的命中集合一致（按标题归一后等价）
    let mut titles_a: Vec<String> = nfc_hits.iter().map(|h| h.title.clone()).collect();
    let mut titles_b: Vec<String> = nfd_hits.iter().map(|h| h.title.clone()).collect();
    titles_a.sort();
    titles_b.sort();
    assert_eq!(titles_a, titles_b);
    drop(base);
}

/// 空白与多空格查询：纯空白 → 空；多余空白不影响多关键词全命中。
#[test]
fn 空白与多空格查询() {
    let (base, _dir, session) = fresh("adv_search_ws");
    session.unlock(STRONG).unwrap();

    session.create_item(&login_draft("GitHub 工作账号")).unwrap();

    assert!(session.search("").unwrap().is_empty());
    assert!(session.search("   ").unwrap().is_empty());
    assert!(session.search(" \t\n ").unwrap().is_empty());
    assert_eq!(session.search("  github  ").unwrap().len(), 1, "首尾空白应被吞");
    assert_eq!(
        session.search("github   工作").unwrap().len(),
        1,
        "关键词间多空白应等同单空格"
    );
    drop(base);
}

// ================================================================ 5. idle

/// 时钟回拨与 i64 边界：now < last_activity 不误判；极端值不溢出 panic。
#[test]
fn idle时钟回拨与i64边界() {
    use cf_session::idle;

    // 大幅回拨
    assert!(!idle::is_expired(1_000, 100, 300));
    assert!(!idle::is_expired(i64::MAX, 0, 1), "极端回拨不得溢出/误判");
    // now == last_activity
    assert!(!idle::is_expired(1_000, 1_000, 300));
    // timeout = 1 的边界
    assert!(!idle::is_expired(100, 100, 1));
    assert!(idle::is_expired(100, 101, 1));
    // timeout <= 0 禁用（即使时间差 i64 量级）
    assert!(!idle::is_expired(0, i64::MAX, 0));
    assert!(!idle::is_expired(0, i64::MAX, -5));
    // 恰好等于边界（含等号）
    assert!(idle::is_expired(1_000, 1_300, 300));

    // 会话级：注入回拨时间不锁定
    let (_base, _dir, session) = fresh("adv_idle");
    session.unlock(STRONG).unwrap();
    session.set_idle_timeout_secs(300);
    session.set_last_activity(1_000_000);
    assert!(!session.auto_lock_if_expired(999_999), "回拨不得触发锁定");
    assert!(session.is_unlocked());
    // 锁定态下超时判定不重复报告
    session.lock();
    assert!(!session.auto_lock_if_expired(9_999_999));
    drop(_base);
}

// ================================================================ 6. KDF 参数

/// 极端 KDF 参数建库：header 如实记录 → 解锁往返 → 错密码 1002。
/// 极小档（m=8MiB, t=1）与极端档（m=1GiB, t=10）各建一库。
#[test]
fn 极端kdf参数建库记录与解锁往返() {
    let base = temp_dir("adv_kdf_extreme");

    // 极小档（下限）
    let min_kdf = KdfParams::new(8 * 1024, 1, 1).unwrap();
    let brief_min = create_vault_with_kdf(&base, "极小档库", STRONG, min_kdf).unwrap();
    let dir_min = base.join(brief_min.uuid.to_string());
    let h = read_header_json(&dir_min);
    assert_eq!(h["kdf"]["m_cost_kib"], json!(8 * 1024));
    assert_eq!(h["kdf"]["t_cost"], json!(1));
    assert_eq!(h["kdf"]["p_cost"], json!(1));
    assert_eq!(b64_decode(h["kdf"]["salt_b64"].as_str().unwrap()).len(), 32);
    open_vault(&dir_min).unwrap().unlock(STRONG).unwrap();

    // 极端档（m=1GiB, t=10）：header 记录 + 双向解锁
    let big_kdf = KdfParams::new(1024 * 1024, 10, 1).unwrap();
    let brief_big = create_vault_with_kdf(&base, "极端档库", STRONG, big_kdf).unwrap();
    let dir_big = base.join(brief_big.uuid.to_string());
    let h = read_header_json(&dir_big);
    assert_eq!(h["kdf"]["m_cost_kib"], json!(1024 * 1024));
    assert_eq!(h["kdf"]["t_cost"], json!(10));
    assert_eq!(h["kdf"]["p_cost"], json!(1));

    let session = open_vault(&dir_big).unwrap();
    session.unlock(STRONG).unwrap();
    assert!(session.is_unlocked());
    session.lock();
    assert_eq!(session.unlock("wrong-password-x!").unwrap_err().code(), 1002);
}

/// kdf 段整体缺失的库：open_vault 即报 Corrupted(1005)，
/// **不会**静默用默认参数解锁（无兜底路径）。
#[test]
fn kdf段缺失报1005无默认参数兜底() {
    let (base, dir, _s) = fresh("adv_kdf_missing");
    let mut header = read_header_json(&dir);
    let removed = header.as_object_mut().unwrap().remove("kdf");
    assert!(removed.is_some(), "测试前提：header 含 kdf 段");
    write_header_json(&dir, &header);

    let err = open_err(&dir);
    assert_eq!(err.code(), 1005, "kdf 段缺失必须报损坏，禁止默认参数兜底");
    drop(base);
}
