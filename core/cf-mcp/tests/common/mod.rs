//! CLI 集成测试共享夹具（cli.rs / cli_pro.rs 共用；docs/36 隔离轮拆出）。
//!
//! 拆分背景（2026-10-11 免费/Pro 隔离）：`set-env`（Pro 专属）用例迁至
//! `cli_pro.rs`（整文件 `#![cfg(feature = "pro")]` 门控，免费仓不存在该文件），
//! 两者共用的二进制路径 / fake op / 临时目录 / 运行器夹具落本模块。

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// 编译产物 `coffer` 二进制绝对路径（cargo 在集成测试构建期注入）。
pub(crate) fn coffer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_coffer")
}

/// fake `op` 脚本绝对路径。
pub(crate) fn fake_op() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/op/op")
}

/// fake op 的「未登录」哨兵（tests/fixtures/op/op 内定义）。
/// common 逐测试目标编译：仅 cli.rs 经 `use common::*` 消费，
/// 其余目标各自定义本地常量，故不消费的目标会报 dead_code——显式豁免。
#[allow(dead_code)]
pub(crate) const FAKE_OP_EXPIRED_SESSION: &str = "COFFER_FAKE_OP_EXPIRED_SESSION";

/// 每用例独立临时目录（tag 必唯一，规避 BUG-12 并行撞名）。
pub(crate) fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "coffer-mcp-cli-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 以 fake op 运行 `coffer` 并收集完整输出（stdin 立即 EOF → 干净路径退出 0）。
pub(crate) fn run_coffer(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(coffer_bin());
    cmd.args(args)
        .env("COFFER_OP_BIN", fake_op())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run coffer binary")
}

/// 快速档库 + 解锁会话，返回 (库目录, 解锁密码, 会话)。
pub(crate) fn fast_vault_setup(tag: &str) -> (PathBuf, String, cf_session::VaultSession) {
    let (vault_dir, pw) = create_fast_vault(tag);
    let s = cf_session::open_vault(&vault_dir).expect("open vault");
    s.unlock(&pw).expect("unlock vault");
    (vault_dir, pw, s)
}

/// 建一个带密码字段的 Login 条目，返回 uuid。
pub(crate) fn create_login_item_in(session: &cf_session::VaultSession, title: &str) -> String {
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::{FieldDraft, ItemDraft};
    let mut d = ItemDraft {
        title: title.to_string(),
        category: ItemCategory::Login,
        urls: Vec::new(),
        tags: Vec::new(),
        sections: Vec::new(),
        fields: vec![FieldDraft {
            name: "username".to_string(),
            value: Some("octocat".to_string()),
            field_type: FieldType::Text,
            designation: Some(Designation::Username),
            section_index: None,
            position: 0,
        }],
        totp: None,
    };
    d.fields.push(FieldDraft {
        name: "password".to_string(),
        value: Some("old-secret".to_string()),
        field_type: FieldType::Concealed,
        designation: Some(Designation::Password),
        section_index: None,
        position: 1,
    });
    session.create_item(&d).expect("create login item")
}

/// 重新开库，读取指定条目的密码字段值（None = 无密码字段）。
pub(crate) fn item_password_value(vault_dir: &std::path::Path, password: &str, item_id: &str) -> Option<String> {
    use cf_domain::field::Designation;
    let s = cf_session::open_vault(vault_dir).expect("reopen vault");
    s.unlock(password).expect("unlock vault");
    let d = s
        .get_item(item_id)
        .expect("get item")
        .expect("item exists");
    d.fields
        .iter()
        .find(|f| f.designation == Some(Designation::Password))
        .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
}

/// 建一个独立快速档测试库（cf-session 快速 KDF / cf-crypto KdfParams；与
/// provider/coffer.rs 内测同款），返回 (库目录, 解锁密码)。
pub(crate) fn create_fast_vault(tag: &str) -> (PathBuf, String) {
    use cf_crypto::kdf::KdfParams;
    use cf_session::create_vault_with_kdf;

    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(
        &base,
        "测试库",
        STRONG_PASSWORD,
        KdfParams::new(8 * 1024, 1, 1).expect("8 MiB fast KDF params"),
    )
    .expect("create fast test vault");
    let vault_dir = base.join(brief.uuid.to_string());
    (vault_dir, STRONG_PASSWORD.to_string())
}
