//! OpProvider 元数据面测试 —— 由 fake `op` fixture 驱动。
//!
//! 覆盖 `SecretProvider` 的 list_secret_names / list_secrets / get_secret_metadata
//! 的 op 协议路径（docs/20 §4.2），全部经 `tests/fixtures/op/op`（fake op）执行，
//! 不依赖真机 `op` / 真实 1Password 会话（docs/20 §10 风险 1 缓解）。
//!
//! fixture 内嵌数据（tests/fixtures/op/op 头部注释）：
//! - `OPENAI_API_KEY`（id fixture-item-api-key，vault Personal，category LOGIN，
//!   updated_at 2026-08-01T12:30:00Z → 1785587400）
//! - `GITHUB_TOKEN`（id fixture-item-github，vault Personal，category SECURE_NOTE）
//!
//! 错误断言统一用 [`ProviderError::code`]（docs/20 §3.4 的 7xxx 段），不依赖
//! 载荷消息文本（UI 层按码映射，同 CfError 纪律）。

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_mcp::error::McpError;
use cf_mcp::provider::op::{OpProvider, OpProviderConfig};
use cf_mcp::provider::SecretProvider;

/// fake `op` 脚本的绝对路径。
fn fake_op() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/op/op")
}

/// 指向 fake `op` 的 provider（无默认 vault、无会话 token）。
fn provider() -> OpProvider {
    OpProvider::new(OpProviderConfig {
        op_bin: fake_op(),
        default_vault: None,
        session_token: None,
    })
    .expect("fake op must be executable")
}

/// 指向 fake `op`、带默认 vault 的 provider。
fn provider_with_default_vault(vault: &str) -> OpProvider {
    OpProvider::new(OpProviderConfig {
        op_bin: fake_op(),
        default_vault: Some(vault.to_string()),
        session_token: None,
    })
    .expect("fake op must be executable")
}

/// fixture 中 OPENAI_API_KEY 的 `updated_at`（2026-08-01T12:30:00Z）的 Unix 秒。
const FIXTURE_API_KEY_UPDATED_AT: i64 = 1_785_587_400;

/// fake op 的「未登录」哨兵（tests/fixtures/op/op 内定义）。
const FAKE_OP_EXPIRED_SESSION: &str = "COFFER_FAKE_OP_EXPIRED_SESSION";

// ===========================================================================
// list_secret_names
// ===========================================================================

#[test]
fn list_secret_names_returns_fixture_item_titles() {
    let provider = provider();
    let names = provider
        .list_secret_names(None)
        .expect("list_secret_names must not error");
    assert!(
        names.contains(&"OPENAI_API_KEY".to_string()),
        "fixture title must be listed, got {names:?}"
    );
    assert!(
        names.contains(&"GITHUB_TOKEN".to_string()),
        "fixture title must be listed, got {names:?}"
    );
}

#[test]
fn list_secret_names_respects_vault_filter() {
    let provider = provider();
    let names = provider
        .list_secret_names(Some("Personal"))
        .expect("existing vault must list");
    assert!(!names.is_empty(), "Personal vault has fixture items");

    let err = provider
        .list_secret_names(Some("NoSuchVault"))
        .expect_err("unknown vault must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7003,
        "unknown vault maps to 7003 SecretNotFound, got {err:?}"
    );
}

#[test]
fn list_secret_names_uses_default_vault_when_none_given() {
    let provider = provider_with_default_vault("Personal");
    let names = provider
        .list_secret_names(None)
        .expect("default vault must list");
    assert!(names.contains(&"OPENAI_API_KEY".to_string()));

    let err = provider
        .list_secret_names(Some("NoSuchVault"))
        .expect_err("explicit unknown vault must be rejected even with default");
    assert_eq!(McpError::from(err.clone()).code(), 7003);
}

#[test]
fn list_secret_names_maps_not_signed_in_to_auth_required() {
    // 验证 `COFFER_OP_SESSION_TOKEN` 被透传为 op 的 `OP_SESSION`（docs/20 §4.2）：
    // fake op 在 OP_SESSION == 哨兵值时按「账号未登录」失败（7002）。
    let provider = OpProvider::new(OpProviderConfig {
        op_bin: fake_op(),
        default_vault: None,
        session_token: Some(cf_domain::secret::SecretString::from_exposed(
            FAKE_OP_EXPIRED_SESSION,
        )),
    })
    .expect("fake op must be executable");
    let err = provider
        .list_secret_names(None)
        .expect_err("expired session must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7002,
        "not signed in maps to 7002 AuthenticationRequired, got {err:?}"
    );
}

// ===========================================================================
// list_secrets
// ===========================================================================

#[test]
fn list_secrets_returns_metadata_for_fixture_items() {
    let provider = provider();
    let entries = provider.list_secrets(None).expect("list_secrets must not error");

    let api = entries
        .iter()
        .find(|m| m.name == "OPENAI_API_KEY")
        .expect("OPENAI_API_KEY must appear in list_secrets");
    assert_eq!(api.id, "fixture-item-api-key");
    assert_eq!(api.vault, "Personal");
    assert_eq!(api.category, "LOGIN");
    assert_eq!(api.updated_at, Some(FIXTURE_API_KEY_UPDATED_AT));

    let gh = entries
        .iter()
        .find(|m| m.name == "GITHUB_TOKEN")
        .expect("GITHUB_TOKEN must appear in list_secrets");
    assert_eq!(gh.vault, "Personal");
    assert_eq!(gh.category, "SECURE_NOTE");
}

#[test]
fn list_secrets_does_not_expose_secret_values() {
    // AS-14「可用不可见」：list_secrets 只返回元数据，绝不携带明文值。
    let provider = provider();
    let entries = provider.list_secrets(None).expect("list_secrets must not error");
    let serialized = format!("{entries:?}");
    for forbidden in ["fixture-secret-value-openai", "fixture-secret-value-github"] {
        assert!(
            !serialized.contains(forbidden),
            "list_secrets metadata must never carry secret values"
        );
    }
}

// ===========================================================================
// get_secret_metadata
// ===========================================================================

#[test]
fn get_secret_metadata_resolves_op_reference() {
    let provider = provider();
    let meta = provider
        .get_secret_metadata("op://Personal/OPENAI_API_KEY/password")
        .expect("metadata must resolve");
    assert_eq!(meta.name, "OPENAI_API_KEY");
    assert_eq!(meta.id, "fixture-item-api-key");
    assert_eq!(meta.vault, "Personal");
    assert_eq!(meta.category, "LOGIN");
    assert_eq!(meta.updated_at, Some(FIXTURE_API_KEY_UPDATED_AT));
}

#[test]
fn get_secret_metadata_accepts_raw_item_id() {
    let provider = provider();
    let meta = provider
        .get_secret_metadata("fixture-item-api-key")
        .expect("raw item id must resolve");
    assert_eq!(meta.name, "OPENAI_API_KEY");
    assert_eq!(meta.id, "fixture-item-api-key");
}

#[test]
fn get_secret_metadata_rejects_empty_ref() {
    let provider = provider();
    let err = provider
        .get_secret_metadata("")
        .expect_err("empty ref must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7005,
        "empty ref maps to 7005 InvalidArgument, got {err:?}"
    );
}

#[test]
fn get_secret_metadata_rejects_malformed_op_reference() {
    // L-6（dev-reviewer）：get_secret_metadata 与 run 面同口径边界校验——
    // 畸形 `op://` 引用（无 item）在入界即拒（7005），不落到 op item get 按 7003。
    let provider = provider();
    let err = provider
        .get_secret_metadata("op://Personal")
        .expect_err("malformed op:// reference must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7005,
        "malformed op:// reference maps to 7005, got {err:?}"
    );
}

#[test]
fn get_secret_metadata_rejects_plaintext_value() {
    // L-6 延伸（§4.4「引用非明文」）：明文值（含空白）不可作 metadata 引用——与
    // run 面同口径，把「secret_ref 非明文」从约定升为结构约束。
    let provider = provider();
    let err = provider
        .get_secret_metadata("plain secret value here")
        .expect_err("plaintext value must be rejected as a reference");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7005,
        "plaintext reference maps to 7005, got {err:?}"
    );
}

#[test]
fn get_secret_metadata_unknown_item_is_secret_not_found() {
    let provider = provider();
    let err = provider
        .get_secret_metadata("op://Personal/DOES_NOT_EXIST/password")
        .expect_err("unknown item must be rejected");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7003,
        "unknown item maps to 7003 SecretNotFound, got {err:?}"
    );
}

// ===========================================================================
// 构造期
// ===========================================================================

#[test]
fn new_rejects_missing_op_binary() {
    let missing = std::env::temp_dir().join("definitely-not-an-op-binary-xyz");
    let err = OpProvider::new(OpProviderConfig {
        op_bin: missing,
        default_vault: None,
        session_token: None,
    })
    .expect_err("missing op binary must be rejected at construction");
    assert_eq!(
        McpError::from(err.clone()).code(),
        7001,
        "missing op binary maps to 7001 ProviderUnavailable, got {err:?}"
    );
}

#[test]
fn from_env_reads_coffer_env_vars() {
    // 进程级环境变量是共享可变状态，串行化读写（同 mcp_acceptance ENV_LOCK 纪律）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fake_bin = std::env::temp_dir().join(format!("coffer-op-bin-{}-{nanos}", std::process::id()));
    std::fs::write(&fake_bin, "#!/bin/sh\nexit 0\n").unwrap();

    std::env::set_var("COFFER_OP_BIN", &fake_bin);
    std::env::set_var("COFFER_OP_VAULT", "Personal");
    std::env::set_var("COFFER_OP_SESSION_TOKEN", "tok-123");

    let config = OpProviderConfig::from_env();
    assert_eq!(config.op_bin, fake_bin);
    assert_eq!(config.default_vault.as_deref(), Some("Personal"));
    assert_eq!(
        config.session_token.as_ref().map(|s| s.expose()),
        Some("tok-123")
    );

    std::fs::remove_file(&fake_bin).unwrap();
    std::env::remove_var("COFFER_OP_BIN");
    std::env::remove_var("COFFER_OP_VAULT");
    std::env::remove_var("COFFER_OP_SESSION_TOKEN");
}

#[test]
fn provider_error_codes_are_in_doc_section_34_range() {
    // docs/20 §3.4 的 7xxx 段：7001..=7006 全部可枚举且互不重复。
    // ProviderError 层无 code()（G-B 冻结契约，码值经 McpError::from 映射），
    // 此处枚举 ProviderError 全部变体 → 经 McpError 归一取码。
    use cf_mcp::provider::ProviderError;
    let variants: Vec<ProviderError> = vec![
        ProviderError::Unavailable("".into()),
        ProviderError::AuthRequired("".into()),
        ProviderError::NotFound("".into()),
        ProviderError::SubprocessFailed {
            exit_code: None,
            detail: "".into(),
        },
        ProviderError::InvalidParameter("".into()),
        ProviderError::Internal("".into()),
    ];
    let codes: Vec<i64> = variants
        .into_iter()
        .map(|e| McpError::from(e).code())
        .collect();
    let mut sorted = codes.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), codes.len(), "7xxx codes must be unique: {codes:?}");
    assert!(
        codes.iter().all(|c| (7001..=7006).contains(c)),
        "all codes must live in the 7xxx segment: {codes:?}"
    );
}
