//! cf-exporter 集成测试共用夹具。
//!
//! cf-session 正由并行组（G3）开发，本夹具**不经 cf-session**，直接用
//! `cf-crypto`（KDF / AEAD / SubKeys）+ `cf-format`（Header）+
//! `cf-store`（ItemStore）构造一个合法的工作形态库目录，并按
//! docs/03-详细设计.md §2.6 / §2.7 的既定参数模拟「建库 + 解锁」：
//!
//! - `wrapped_dek` = AEAD(KEK, aad = `vault_uuid_bytes ‖ b"wrapped_dek"`, DEK)
//! - `verifier`    = AEAD(KEK, aad = `vault_uuid_bytes ‖ b"verifier"`,
//!   `VERIFIER_PLAINTEXT = b"coffer-verifier-v1"`)
//! - 解锁 = Argon2id(password, salt) → KEK → 解封 DEK → `SubKeys::derive`
//!   → `ItemStore::open`
//!
//! 测试 KDF 用下限参数（8 MiB / t=1 / p=1），只为快，不参与安全声明。
// support 模块被多个测试二进制各自包含：个别夹具项在部分二进制中不使用
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use base64::Engine as _;
use cf_crypto::aead::{open as aead_open, seal as aead_seal, SessionKey};
use cf_crypto::kdf::{derive_key, KdfParams, KEY_LEN, SALT_LEN};
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_format::header::{
    AeadSection, BiometricWrap, Header, HeaderFlags, KdfSection, McpWrap, VerifierSection,
    WrappedKey, AEAD_ALGO, ARGON2_VERSION, FORMAT_VERSION, KDF_ALGO, NONCE_LEN, VERIFIER_CT_MIN,
    WRAPPED_DEK_CT_MIN,
};
use cf_store::rows::{FieldRow, TagRow, UrlRow};
use cf_store::{ItemRow, ItemStore};

/// 测试主密码。
pub const PASSWORD: &str = "loopback-test-password-42!";

/// 错误主密码（解锁必须失败）。
pub const WRONG_PASSWORD: &str = "definitely-not-the-password";

/// docs/03 §2.6：verifier 明文常量。
pub const VERIFIER_PLAINTEXT: &[u8] = b"coffer-verifier-v1";

/// 夹具库固定 DEK（make_header 写入 wrapped_dek 的同一值；种子追加用
/// reopen_store 依赖本常量，防两处漂移）。
pub const TEST_DEK: [u8; 32] = [0x5Au8; 32];

/// 测试用快速 KDF（Argon2id 下限，约几十毫秒）。
pub fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 测试盐（固定，便于复现）。
pub fn test_salt() -> [u8; SALT_LEN] {
    [0x42u8; SALT_LEN]
}

/// 唯一临时目录（进程号 + 原子计数器，无外部依赖）。
pub fn temp_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("cf-exporter-{}-{}-{}", tag, std::process::id(), n));
    fs::create_dir_all(&dir).expect("创建临时目录成功");
    dir
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn uuid_bytes(vault_uuid: &str) -> [u8; 16] {
    *uuid::Uuid::parse_str(vault_uuid)
        .expect("测试 uuid 必须合法")
        .as_bytes()
}

/// 主密码 → KEK。
pub fn derive_kek(password: &str) -> zeroize::Zeroizing<[u8; KEY_LEN]> {
    derive_key(password, &test_salt(), fast_kdf()).expect("KDF 派生成功")
}

/// 用 KEK 封装 DEK / verifier（AAD 按 docs/03 §2.6 v1.5）。
fn seal_with_kek(
    kek: &[u8; KEY_LEN],
    vault_uuid: &str,
    purpose: &str,
    plain: &[u8],
) -> (String, String) {
    let mut aad = uuid_bytes(vault_uuid).to_vec();
    aad.extend_from_slice(purpose.as_bytes());
    let sealed = aead_seal(&SessionKey::new(*kek), &aad, plain).expect("封装成功");
    let (nonce, ct) = sealed.split_at(cf_crypto::aead::NONCE_LEN);
    (b64(nonce), b64(ct))
}

/// 构造一份合法 header（不落盘）。返回 (header, dek)。
///
/// DEK 用固定测试值——测试库，确定性优先；AAD/子密钥派生路径与生产一致。
pub fn make_header(vault_uuid: &str) -> (Header, [u8; 32]) {
    let dek = TEST_DEK;
    let kek = derive_kek(PASSWORD);
    let (wd_nonce, wd_ct) = seal_with_kek(&kek, vault_uuid, "wrapped_dek", &dek);
    let (vf_nonce, vf_ct) = seal_with_kek(&kek, vault_uuid, "verifier", VERIFIER_PLAINTEXT);

    let header = Header {
        format_version: FORMAT_VERSION,
        vault_uuid: vault_uuid.to_owned(),
        display_name: "回环测试库".to_owned(),
        created_at: 1_700_000_000,
        modified_at: 1_700_000_000,
        kdf: KdfSection {
            algo: KDF_ALGO.to_owned(),
            argon2_version: ARGON2_VERSION,
            m_cost_kib: fast_kdf().m_cost_kib,
            t_cost: fast_kdf().t_cost,
            p_cost: fast_kdf().p_cost,
            salt_b64: b64(&test_salt()),
        },
        aead: AeadSection {
            algo: AEAD_ALGO.to_owned(),
        },
        wrapped_dek: WrappedKey {
            nonce_b64: wd_nonce,
            ct_b64: wd_ct,
        },
        verifier: VerifierSection {
            nonce_b64: vf_nonce,
            ct_b64: vf_ct,
        },
        biometric_wrap: BiometricWrap {
            available: false,
            provider: None,
            key_alias: None,
            wrapped_dek_b64: None,
        },
        mcp_wrap: McpWrap::default(),
        recovery_wrap: None,
        flags: HeaderFlags {
            sort_key_enabled: false,
            attachments_inline: false,
        },
    };
    (header, dek)
}

/// 静态形状断言（防夹具自身退化）。
#[test]
fn header_shape_matches_docs_1_3() {
    let uuid = uuid::Uuid::now_v7().to_string();
    let (h, _dek) = make_header(&uuid);
    let wd_len = base64::engine::general_purpose::STANDARD
        .decode(&h.wrapped_dek.ct_b64)
        .unwrap()
        .len();
    let vf_len = base64::engine::general_purpose::STANDARD
        .decode(&h.verifier.ct_b64)
        .unwrap()
        .len();
    assert_eq!(wd_len, 32 + 16, "wrapped_dek = DEK(32) + tag(16)");
    assert_eq!(vf_len, VERIFIER_PLAINTEXT.len() + 16);
    assert!(vf_len >= VERIFIER_CT_MIN);
    assert!(wd_len >= WRAPPED_DEK_CT_MIN);
    assert_eq!(h.kdf.salt_b64.len(), 44, "32 字节盐的标准 base64 长度");
    let _ = NONCE_LEN;
}

/// 在 `base` 下建一个工作形态库：header.json + db.sqlite（含六类条目）。
///
/// 返回 (库目录, vault_uuid)。条目清单（对齐 docs/10 §1.1 TC-EXP-01
/// 的「3 类条目 + 1 条归档」与其余对抗性形状）：
///
/// | 标题 | 类别 | 状态 | 内容 |
/// | --- | --- | --- | --- |
/// | GitHub 登录 | Login | Active | 用户名 / 密码 / 备注 + 2 URL（主/副） + 2 标签 + TOTP |
/// | 服务器安全笔记 | SecureNote | Active | 备注（多行） |
/// | 信用卡 | CreditCard | Active | 卡号（Concealed） + 有效期 |
/// | 归档的条目 | Login | Archived | 用户名 / 密码 |
/// | 回收站条目 | Login | Trashed | 仅标题（CSV 不导出） |
/// | 公式条目 | Login | Active | Username/Password/Notes 均以 `=`/`@` 开头 |
///
/// 连接关闭后返回（WAL 已合并或截断，见各测试对 -wal 的单独处理）。
pub fn build_vault(base: &Path) -> (PathBuf, String) {
    let vault_uuid = uuid::Uuid::now_v7().to_string();
    let (header, dek) = make_header(&vault_uuid);
    let dir = base.join(&vault_uuid);
    fs::create_dir_all(&dir).expect("建库目录成功");
    cf_format::write_header(&dir, &header).expect("写 header 成功");

    let conn = rusqlite::Connection::open(dir.join("db.sqlite")).expect("打开 db 成功");
    let subkeys = SubKeys::derive(&dek, &uuid_bytes(&vault_uuid)).expect("派生子密钥成功");
    let mut store = ItemStore::open(conn, subkeys).expect("初始化 schema 成功");

    seed_items(&mut store);
    (dir, vault_uuid)
}

/// 向库中写入六类条目（GitHub 登录 / SecureNote / CreditCard / 归档 /
/// 回收站 / 公式）。
pub fn seed_items(store: &mut ItemStore) {
    let now = 1_700_000_000i64;
    store
        .with_tx(|repos| {
            // ---- GitHub 登录（Active，全字段） ----
            let gh = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: gh.clone(),
                    category: ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: true,
                    fav_index: 1,
                    created_at: now,
                    updated_at: now,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("GitHub 登录"),
            )?;
            repos.fields.replace_fields_for_item(
                &gh,
                &[
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: gh.clone(),
                        section_uuid: None,
                        field_type: FieldType::Text,
                        designation: Some(Designation::Username),
                        name: "用户名".into(),
                        value: Some("octocat".into()),
                        position: 0,
                    },
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: gh.clone(),
                        section_uuid: None,
                        field_type: FieldType::Concealed,
                        designation: Some(Designation::Password),
                        name: "密码".into(),
                        value: Some("s3cret-明文密码!".into()),
                        position: 1,
                    },
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: gh.clone(),
                        section_uuid: None,
                        field_type: FieldType::Multiline,
                        designation: Some(Designation::NotesPlain),
                        name: "备注".into(),
                        value: Some("Main account\n第二行备注".into()),
                        position: 2,
                    },
                ],
            )?;
            repos.urls.replace_for_item(
                &gh,
                &[
                    UrlRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: gh.clone(),
                        label: None,
                        url: "https://github.com".into(),
                        is_primary: true,
                        position: 0,
                    },
                    UrlRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: gh.clone(),
                        label: Some("管理后台".into()),
                        url: "https://api.github.com".into(),
                        is_primary: false,
                        position: 1,
                    },
                ],
            )?;
            repos.tags.replace_for_item(
                &gh,
                &[
                    TagRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: gh.clone(),
                        name: "dev".into(),
                    },
                    TagRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: gh.clone(),
                        name: "重要".into(),
                    },
                ],
            )?;
            repos.totp.insert_totp(
                &uuid::Uuid::now_v7().to_string(),
                &gh,
                b"Hello!\xDE\xAD\xBE\xEF", // 10 字节，80-bit 下限
                "sha1",
                6,
                30,
                Some("GitHub"),
                Some("octocat"),
            )?;

            // ---- SecureNote（Active，多行备注） ----
            let note = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: note.clone(),
                    category: ItemCategory::SecureNote,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: now,
                    updated_at: now,
                    trashed_at: None,
                    position: 4,
                },
                &SecretString::from_exposed("服务器安全笔记"),
            )?;
            repos.fields.replace_fields_for_item(
                &note,
                &[FieldRow {
                    uuid: uuid::Uuid::now_v7().to_string(),
                    item_uuid: note.clone(),
                    section_uuid: None,
                    field_type: FieldType::Multiline,
                    designation: Some(Designation::NotesPlain),
                    name: "备注".into(),
                    value: Some("恢复短语：astral tungsten\n第二行".into()),
                    position: 0,
                }],
            )?;

            // ---- CreditCard（Active，卡号 Concealed + 有效期） ----
            let card = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: card.clone(),
                    category: ItemCategory::CreditCard,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: now,
                    updated_at: now,
                    trashed_at: None,
                    position: 5,
                },
                &SecretString::from_exposed("测试信用卡"),
            )?;
            repos.fields.replace_fields_for_item(
                &card,
                &[
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: card.clone(),
                        section_uuid: None,
                        field_type: FieldType::Concealed,
                        designation: Some(Designation::Other("cardNumber".into())),
                        name: "卡号".into(),
                        value: Some("4111 1111 1111 1111".into()),
                        position: 0,
                    },
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: card.clone(),
                        section_uuid: None,
                        field_type: FieldType::Text,
                        designation: Some(Designation::Other("expiry".into())),
                        name: "有效期".into(),
                        value: Some("12/27".into()),
                        position: 1,
                    },
                ],
            )?;

            // ---- 归档条目（Archived，最小字段） ----
            let arch = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: arch.clone(),
                    category: ItemCategory::Login,
                    state: ItemState::Archived,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: now,
                    updated_at: now,
                    trashed_at: None,
                    position: 1,
                },
                &SecretString::from_exposed("归档的条目"),
            )?;
            repos.fields.replace_fields_for_item(
                &arch,
                &[
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: arch.clone(),
                        section_uuid: None,
                        field_type: FieldType::Text,
                        designation: Some(Designation::Username),
                        name: "用户名".into(),
                        value: Some("arch-user".into()),
                        position: 0,
                    },
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: arch.clone(),
                        section_uuid: None,
                        field_type: FieldType::Concealed,
                        designation: Some(Designation::Password),
                        name: "密码".into(),
                        value: Some("arch-pass".into()),
                        position: 1,
                    },
                ],
            )?;

            // ---- 回收站条目（Trashed，CSV 不导出） ----
            let trash = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: trash.clone(),
                    category: ItemCategory::Login,
                    state: ItemState::Trashed,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: now,
                    updated_at: now,
                    trashed_at: Some(now),
                    position: 2,
                },
                &SecretString::from_exposed("回收站条目"),
            )?;

            // ---- 公式条目（Active，Username/Password/Notes 均公式形） ----
            let formula = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: formula.clone(),
                    category: ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: now,
                    updated_at: now,
                    trashed_at: None,
                    position: 3,
                },
                &SecretString::from_exposed("公式条目"),
            )?;
            repos.fields.replace_fields_for_item(
                &formula,
                &[
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: formula.clone(),
                        section_uuid: None,
                        field_type: FieldType::Text,
                        designation: Some(Designation::Username),
                        name: "用户名".into(),
                        value: Some("=SUM(A1)".into()),
                        position: 0,
                    },
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: formula.clone(),
                        section_uuid: None,
                        field_type: FieldType::Concealed,
                        designation: Some(Designation::Password),
                        name: "密码".into(),
                        value: Some("=p=ss".into()),
                        position: 1,
                    },
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: formula.clone(),
                        section_uuid: None,
                        field_type: FieldType::Multiline,
                        designation: Some(Designation::NotesPlain),
                        name: "备注".into(),
                        value: Some("@cmd note".into()),
                        position: 2,
                    },
                ],
            )?;

            repos.meta.add_item_count(6)?;
            Ok(())
        })
        .expect("写入六类条目成功");
}

/// 模拟「打开库 + 主密码解锁」：header 校验 → KEK → 解封 DEK → SubKeys →
/// 打开 ItemStore。解锁失败返回 `None`（对应错误码 1002 的语义）。
///
/// 返回 (header, store)。store 持有独立连接，与夹具建库连接互不影响。
pub fn unlock_store(vault_dir: &Path, password: &str) -> Option<(Header, ItemStore)> {
    let header = match cf_format::open_container(vault_dir).expect("打开容器成功") {
        cf_format::OpenOutcome::Current(h) => h,
        _ => return None,
    };
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&header.kdf.salt_b64)
        .expect("盐是合法 base64");
    let params = KdfParams::new(header.kdf.m_cost_kib, header.kdf.t_cost, header.kdf.p_cost)
        .expect("header 内 KDF 参数合法");
    let kek = derive_key(password, &salt, params).ok()?;

    // verifier 校验（解不出 / 明文不符 → 解锁失败）
    let mut vf_aad = uuid_bytes(&header.vault_uuid).to_vec();
    vf_aad.extend_from_slice(b"verifier");
    let vf_sealed = [
        base64::engine::general_purpose::STANDARD
            .decode(&header.verifier.nonce_b64)
            .ok()?,
        base64::engine::general_purpose::STANDARD
            .decode(&header.verifier.ct_b64)
            .ok()?,
    ]
    .concat();
    let vf_plain = aead_open(&SessionKey::new(*kek), &vf_aad, &vf_sealed).ok()?;
    if vf_plain != VERIFIER_PLAINTEXT {
        return None;
    }

    // 解封 DEK
    let mut wd_aad = uuid_bytes(&header.vault_uuid).to_vec();
    wd_aad.extend_from_slice(b"wrapped_dek");
    let wd_sealed = [
        base64::engine::general_purpose::STANDARD
            .decode(&header.wrapped_dek.nonce_b64)
            .ok()?,
        base64::engine::general_purpose::STANDARD
            .decode(&header.wrapped_dek.ct_b64)
            .ok()?,
    ]
    .concat();
    let dek_plain = aead_open(&SessionKey::new(*kek), &wd_aad, &wd_sealed).ok()?;
    let dek: [u8; 32] = dek_plain.try_into().ok()?;

    let subkeys = SubKeys::derive(&dek, &uuid_bytes(&header.vault_uuid)).ok()?;
    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).ok()?;
    let store = ItemStore::open(conn, subkeys).ok()?;
    Some((header, store))
}

/// 递归删除目录（测试清理；不存在视为已清理）。
pub fn remove_dir_all_quiet(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// 用夹具固定 DEK（[`TEST_DEK`]）重新打开已建库（种子数据追加用；
/// build_vault 返回后连接已关闭，重开须用同一密钥材料）。
pub fn reopen_store(vault_dir: &Path, vault_uuid: &str) -> ItemStore {
    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).expect("打开 db 成功");
    let subkeys = SubKeys::derive(&TEST_DEK, &uuid_bytes(vault_uuid)).expect("派生子密钥成功");
    ItemStore::open(conn, subkeys).expect("重开库成功")
}
