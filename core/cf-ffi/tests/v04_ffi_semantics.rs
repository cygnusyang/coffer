//! v0.4 FFI 语义测试（附件 FR-9.3/9.4 / 跨库复制 FR-2.10 / 密码短语
//! FR-3.3，docs/15 §3.1.5 / §3.2.2 / §3.3.4）。
//!
//! 聚焦跨 FFI 的回环语义与错误码，与 cf-session 门面单测互补：
//!
//! 1. **附件**：add → list → read 回环逐字节相等；旁路文件 ≠ 明文
//!    （密文落盘断言）；锁定态 1001；条目不存在 1011；行不存在 1012；
//!    文件被外部删除 1005；
//! 2. **跨库复制**：TOTP + 标签 + 附件条目复制到目标库 → 逐字段一致、
//!    附件文件落在**目标库**目录、源库原样；源/目标锁定 1001；
//!    源条目不存在 1011；
//! 3. **密码短语**：默认参数 5 词 `-` 分隔；词数 / 分隔符越界 → 1012
//!    （镜像 generate_password 的 Validation 映射）。
//!
//! 测试约定与 `backup_ffi_semantics.rs` 一致：每测试独立临时目录；快速
//! KDF 建库；FFI 入口一律走公开 API。错误码契约零扩展（docs/15 §4）。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_ffi::api::{CofferApp, VaultSession};
use cf_ffi::types::*;

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

/// 每测试独立的临时工作目录。
fn temp_base(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cf-ffi-v04-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &std::path::Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 建库 → 打开 → 解锁，返回 FFI 会话。
fn unlocked_session(
    base: &std::path::Path,
    name: &str,
) -> (cf_domain::vault::Vault, Arc<VaultSession>) {
    let brief = setup_vault(base, name);
    let app = CofferApp::new();
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    (brief, session)
}

/// 最小合法登录条目（与 backup_ffi_semantics.rs 同款，附 TOTP 与标签）。
fn login_draft(title: &str, password: &str, totp: Option<FfiTotpDraft>) -> FfiItemDraft {
    FfiItemDraft {
        title: title.to_owned(),
        category: FfiItemCategory::Login,
        urls: Vec::new(),
        tags: vec!["dev".to_owned(), "v04".to_owned()],
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
        totp,
    }
}

// -------------------------------------------------- 附件（FR-9.3 / 9.4）

/// add → list → read 回环逐字节相等；旁路文件是密文（≠ 明文）；
/// remove 后行消失（再读 → 1012）。文件名覆盖中文 / 空格 / emoji。
#[test]
fn 附件增列读删回环与密文落盘() {
    let base = temp_base("att_roundtrip");
    let (_brief, session) = unlocked_session(&base, "附件库");
    let item_id = session
        .create_item(login_draft("GitHub", "p@ssw0rd-42!", None))
        .unwrap();

    let filename = "机密 文档 📎.txt";
    let content = b"plain attachment \xE2\x9C\x94 content".to_vec();
    let meta = session
        .add_attachment(item_id.clone(), filename.to_owned(), content.clone())
        .unwrap();

    // 元数据镜像：文件名明文往返、size、时间戳
    assert_eq!(meta.filename, filename);
    assert_eq!(meta.item_uuid, item_id);
    assert_eq!(meta.size_bytes, content.len() as i64);
    assert!(meta.created_at > 0);

    // list：created_at 升序、元数据一致
    let listed = session.list_attachments(item_id.clone()).unwrap();
    assert_eq!(listed, vec![meta.clone()]);

    // read：逐字节相等
    let read_back = session
        .read_attachment(meta.attachment_uuid.clone())
        .unwrap();
    assert_eq!(read_back, content);

    // 密文落盘断言：旁路文件 ≠ 明文（docs/15 §3.1.5 要点 4）
    let sidecar = std::path::Path::new(&session.vault_dir())
        .join("attachments")
        .join(&meta.attachment_uuid);
    let on_disk = std::fs::read(&sidecar).unwrap();
    assert_ne!(on_disk, content, "旁路文件必须是密文");
    assert!(!on_disk.is_empty());

    // remove → 行消失；再读 / 再删 → 1012
    session
        .remove_attachment(meta.attachment_uuid.clone())
        .unwrap();
    assert!(session.list_attachments(item_id).unwrap().is_empty());
    assert_eq!(
        err_code(session.read_attachment(meta.attachment_uuid.clone())),
        1012
    );
    assert_eq!(
        err_code(session.remove_attachment(meta.attachment_uuid)),
        1012
    );
}

/// 锁定态四方法全部 1001（门禁在 Rust 侧强制，docs/15 §4）。
#[test]
fn 附件锁定态四方法返回1001() {
    let base = temp_base("att_locked");
    let (_brief, session) = unlocked_session(&base, "锁定附件库");
    let item_id = session
        .create_item(login_draft("GitHub", "p@ssw0rd-42!", None))
        .unwrap();
    let meta = session
        .add_attachment(item_id, "a.txt".to_owned(), b"data".to_vec())
        .unwrap();
    session.lock();

    assert_eq!(
        err_code(session.list_attachments("some-item".to_owned())),
        1001
    );
    assert_eq!(
        err_code(session.add_attachment("some-item".to_owned(), "a.txt".to_owned(), b"d".to_vec())),
        1001
    );
    assert_eq!(
        err_code(session.read_attachment(meta.attachment_uuid.clone())),
        1001
    );
    assert_eq!(
        err_code(session.remove_attachment(meta.attachment_uuid)),
        1001
    );
}

/// 条目不存在：add / list → 1011（存在性门禁由会话层承担）。
#[test]
fn 附件条目不存在返回1011() {
    let base = temp_base("att_no_item");
    let (_brief, session) = unlocked_session(&base, "无条目库");

    assert_eq!(
        err_code(session.add_attachment(
            "no-such-item".to_owned(),
            "a.txt".to_owned(),
            b"d".to_vec()
        )),
        1011
    );
    assert_eq!(
        err_code(session.list_attachments("no-such-item".to_owned())),
        1011
    );
}

/// 行不存在（未入库的 uuid）：read / remove → 1012。
#[test]
fn 附件行不存在读删返回1012() {
    let base = temp_base("att_no_row");
    let (_brief, session) = unlocked_session(&base, "无附件行库");

    assert_eq!(
        err_code(session.read_attachment("01940000-0000-7000-8000-000000000000".to_owned())),
        1012
    );
    assert_eq!(
        err_code(session.remove_attachment("01940000-0000-7000-8000-000000000000".to_owned())),
        1012
    );
}

/// 行在而旁路文件被外部删除：read → 1005 Corrupted。
#[test]
fn 附件文件被外部删除读返回1005() {
    let base = temp_base("att_missing_file");
    let (_brief, session) = unlocked_session(&base, "缺文件库");
    let item_id = session
        .create_item(login_draft("GitHub", "p@ssw0rd-42!", None))
        .unwrap();
    let meta = session
        .add_attachment(item_id, "gone.txt".to_owned(), b"data".to_vec())
        .unwrap();

    let sidecar = std::path::Path::new(&session.vault_dir())
        .join("attachments")
        .join(&meta.attachment_uuid);
    std::fs::remove_file(&sidecar).unwrap();

    assert_eq!(
        err_code(session.read_attachment(meta.attachment_uuid)),
        1005
    );
}

// ---------------------------------------------- 跨库复制（FR-2.10）

/// 含 TOTP + 标签 + 附件的条目复制到目标库：返回新 uuid → 逐字段一致、
/// 附件文件落在目标库目录、源库条目与附件原样。
#[test]
fn 跨库复制回环_附件落在目标库目录() {
    let base = temp_base("copy_roundtrip");
    let (src_brief, src) = unlocked_session(&base, "源库");
    let (dst_brief, dst) = unlocked_session(&base, "目标库");

    let totp = src
        .parse_otpauth_uri(
            "otpauth://totp/GitHub:alice@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
                .to_owned(),
        )
        .unwrap();
    let item_id = src
        .create_item(login_draft("GitHub", "p@ssw0rd-源库!", Some(totp)))
        .unwrap();
    let content = b"copy me \xF0\x9F\x93\x8E".to_vec();
    let att = src
        .add_attachment(item_id.clone(), "便携附件.txt".to_owned(), content.clone())
        .unwrap();

    let new_id = src.copy_item(item_id.clone(), dst.clone()).unwrap();
    assert_ne!(new_id, item_id, "目标库应产生新条目 uuid");

    // 目标库条目：标题 / 标签 / 字段 / TOTP 元数据一致
    let dst_details = dst.get_item(new_id.clone()).unwrap().unwrap();
    assert_eq!(dst_details.title, "GitHub");
    assert_eq!(dst_details.tags, vec!["dev".to_owned(), "v04".to_owned()]);
    let dst_password = dst_details
        .fields
        .iter()
        .find(|f| f.field_type == FfiFieldType::Concealed)
        .unwrap();
    assert_eq!(
        dst.get_field_value(new_id.clone(), dst_password.uuid.clone())
            .unwrap()
            .as_deref(),
        Some("p@ssw0rd-源库!")
    );
    assert!(dst.totp_config(new_id.clone()).unwrap().is_some());

    // 附件随复制：目标库可读且逐字节一致；文件在**目标库**目录下
    let dst_atts = dst.list_attachments(new_id.clone()).unwrap();
    assert_eq!(dst_atts.len(), 1);
    assert_eq!(dst_atts[0].filename, "便携附件.txt");
    let dst_read = dst
        .read_attachment(dst_atts[0].attachment_uuid.clone())
        .unwrap();
    assert_eq!(dst_read, content);
    assert!(
        std::path::Path::new(&dst.vault_dir())
            .join("attachments")
            .join(&dst_atts[0].attachment_uuid)
            .is_file(),
        "附件旁路文件必须落在目标库目录"
    );
    assert_ne!(
        dst_atts[0].attachment_uuid, att.attachment_uuid,
        "目标库应产生新附件行"
    );

    // 源库原样：条目仍在、附件仍可读
    assert!(src.get_item(item_id.clone()).unwrap().is_some());
    assert_eq!(
        src.read_attachment(att.attachment_uuid.clone()).unwrap(),
        content
    );

    // 隔离断言：目标库新增附件后源库附件列表不变
    assert_eq!(src.list_attachments(item_id).unwrap().len(), 1);
    let _ = (src_brief, dst_brief);
}

/// 源或目标锁定 → 1001（docs/15 §3.2.2 错误面）。
#[test]
fn 跨库复制锁定态返回1001() {
    let base = temp_base("copy_locked");
    let (_src_brief, src) = unlocked_session(&base, "复制源库");
    let (_dst_brief, dst) = unlocked_session(&base, "复制目标库");
    let item_id = src
        .create_item(login_draft("GitHub", "p@ssw0rd-42!", None))
        .unwrap();

    // 目标库锁定 → 1001
    dst.lock();
    assert_eq!(err_code(src.copy_item(item_id.clone(), dst.clone())), 1001);

    // 源库锁定（目标已锁，锁目标侧）→ 1001
    src.lock();
    assert_eq!(err_code(src.copy_item(item_id, dst.clone())), 1001);
}

/// 源条目不存在 → 1011（目标库零写入）。
#[test]
fn 跨库复制源条目不存在返回1011() {
    let base = temp_base("copy_no_item");
    let (_src_brief, src) = unlocked_session(&base, "源条目缺失库");
    let (_dst_brief, dst) = unlocked_session(&base, "零写入库");

    assert_eq!(
        err_code(src.copy_item("no-such-item".to_owned(), dst.clone())),
        1011
    );
    // 目标库零写入
    assert_eq!(dst.list_items(None).unwrap().len(), 0);
}

// ---------------------------------------------- 密码短语（FR-3.3）

/// 默认参数（5 词 + `-`）生成成功且形态正确；显式四参回环。
#[test]
fn 密码短语生成形态正确() {
    let base = temp_base("phrase");
    let (_brief, session) = unlocked_session(&base, "短语库");

    // 默认参数（Swift 侧可全参显式传入；FFI Record 无默认值）
    let phrase = session
        .generate_passphrase(FfiPassphraseOptions {
            word_count: 5,
            separator: "-".to_owned(),
            capitalize: false,
            number_suffix: false,
        })
        .unwrap();
    let words: Vec<&str> = phrase.split('-').collect();
    assert_eq!(words.len(), 5, "5 词由 `-` 分隔：{phrase}");

    // 边界词数 3 与 10 均合法；Title Case + 数字后缀形态
    let capitalized = session
        .generate_passphrase(FfiPassphraseOptions {
            word_count: 3,
            separator: " ".to_owned(),
            capitalize: true,
            number_suffix: true,
        })
        .unwrap();
    let mut parts = capitalized.split(' ').rev();
    let suffix = parts.next().unwrap();
    assert!(
        suffix.ends_with(|c: char| c.is_ascii_digit()),
        "number_suffix 应在短语尾部追加数字：{capitalized}"
    );
    for word in parts {
        assert!(
            word.chars().next().unwrap().is_uppercase(),
            "capitalize 应词首大写：{capitalized}"
        );
    }

    // 10 词（上边界）
    let long = session
        .generate_passphrase(FfiPassphraseOptions {
            word_count: 10,
            separator: ".".to_owned(),
            capitalize: false,
            number_suffix: false,
        })
        .unwrap();
    assert_eq!(long.split('.').count(), 10);
}

/// 参数越界 → 1012 Validation（docs/15 §3.3.4；词数 3..=10、
/// 分隔符 1..=3 可打印字符）。
#[test]
fn 密码短语参数越界返回1012() {
    let base = temp_base("phrase_bounds");
    let (_brief, session) = unlocked_session(&base, "越界库");
    let opts = |word_count: u32, separator: &str| FfiPassphraseOptions {
        word_count,
        separator: separator.to_owned(),
        capitalize: false,
        number_suffix: false,
    };

    // 词数越界：2（下界外）、11（上界外）、0（usize 负值不可表达，0 兜底）
    assert_eq!(err_code(session.generate_passphrase(opts(2, "-"))), 1012);
    assert_eq!(err_code(session.generate_passphrase(opts(11, "-"))), 1012);
    assert_eq!(err_code(session.generate_passphrase(opts(0, "-"))), 1012);

    // 分隔符越界：空、4 字符、含不可打印字符（控制字符）
    assert_eq!(err_code(session.generate_passphrase(opts(5, ""))), 1012);
    assert_eq!(err_code(session.generate_passphrase(opts(5, "abcd"))), 1012);
    assert_eq!(
        err_code(session.generate_passphrase(opts(5, "\u{7}"))),
        1012
    );
}
