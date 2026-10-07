//! `CofferStoreProvider` 单元测试（子模块；`super` = `provider::coffer`）。
//!
//! 用例建独立临时库（快速 KDF 档），覆盖 4 工具面 + 8 操作 + 会话态错误映射。
//! 进程级 env 写入（[`inject_environment`]）经 `ENV_LOCK` 串行化。

use super::*;
use cf_crypto::kdf::KdfParams;
    use cf_session::create_vault_with_kdf;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁，与 cf-session 测试同款）。
    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";
    /// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
    fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 进程内唯一临时目录（pid + 原子计数，cf-session 测试同型，不引依赖）。
    fn temp_dir(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "cf-mcp-coffer-{tag}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 串行化 `inject_environment` 的进程级 env 写入（不同测试不同键，仍避免并发 set_var）。
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// 建库 + 解锁 + 构造 provider（每用例独立库，KDF 快速档）。
    fn provider(tag: &str) -> (CofferStoreProvider, PathBuf) {
        let base = temp_dir(tag);
        let brief = create_vault_with_kdf(&base, "测试库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();
        (CofferStoreProvider::new(session), vault_dir)
    }

    /// 建一个带 `Designation::Password` 字段的 secret 条目，返回条目 id。
    ///
    /// `Password` 类别的模板仅必填 password designation——单字段草稿即合法。
    fn seed_secret(prov: &CofferStoreProvider, name: &str, value: &str) -> String {
        let draft = ItemDraft {
            title: name.to_string(),
            category: ItemCategory::Password,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "password".to_string(),
                value: Some(value.to_string()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        prov.session.create_item(&draft).unwrap()
    }

    /// 建一个环境容器条目（SecureNote + ENV_TAG + 指定字段）。
    fn seed_env(prov: &CofferStoreProvider, name: &str, pairs: &[(&str, &str)]) -> String {
        let draft = ItemDraft {
            title: name.to_string(),
            category: ItemCategory::SecureNote,
            urls: Vec::new(),
            tags: vec![ENV_TAG.to_string()],
            sections: Vec::new(),
            fields: pairs
                .iter()
                .enumerate()
                .map(|(i, (k, v))| FieldDraft {
                    name: (*k).to_string(),
                    value: Some((*v).to_string()),
                    field_type: FieldType::Text,
                    designation: None,
                    section_index: None,
                    position: i as i32,
                })
                .collect(),
            totp: None,
        };
        prov.session.create_item(&draft).unwrap()
    }

    fn tag_of(d: &ItemDetails, prefix: &str) -> Vec<String> {
        d.tags
            .iter()
            .filter(|t| t.expose().starts_with(prefix))
            .map(|t| t.expose().to_string())
            .collect()
    }

    // ------------------------------------------------------------ 4 工具面

    #[test]
    fn list_secret_names_excludes_environment_containers() {
        let (prov, _) = provider("list_names");
        seed_secret(&prov, "api-key", "v1");
        seed_secret(&prov, "db-pass", "v2");
        seed_env(&prov, "prod", &[]);
        let names = prov.list_secret_names(None).unwrap();
        assert_eq!(names, vec!["api-key", "db-pass"]);
    }

    #[test]
    fn list_secrets_pairs_name_with_metadata() {
        let (prov, _) = provider("list_meta");
        seed_secret(&prov, "api-key", "v1");
        let metas = prov.list_secrets(None).unwrap();
        assert_eq!(metas.len(), 1);
        let m = &metas[0];
        assert_eq!(m.name, "api-key");
        assert_eq!(m.category, "password");
        assert!(!m.id.is_empty());
        assert!(!m.vault.is_empty());
        assert!(m.updated_at.is_some());
    }

    #[test]
    fn get_secret_metadata_by_title_and_by_id() {
        let (prov, _) = provider("get_meta");
        let id = seed_secret(&prov, "api-key", "v1");
        let by_title = prov.get_secret_metadata("api-key").unwrap();
        let by_id = prov.get_secret_metadata(&id).unwrap();
        assert_eq!(by_title.id, id);
        assert_eq!(by_id.name, "api-key");
    }

    #[test]
    fn get_secret_metadata_rejects_empty_and_unknown() {
        let (prov, _) = provider("get_meta_reject");
        assert!(matches!(
            prov.get_secret_metadata(""),
            Err(ProviderError::InvalidParameter(_))
        ));
        assert!(matches!(
            prov.get_secret_metadata("no-such-secret"),
            Err(ProviderError::NotFound(_))
        ));
    }

    #[test]
    fn run_with_secret_injects_value_and_returns_zero() {
        let (prov, _) = provider("run_ok");
        seed_secret(&prov, "api-key", "s3cr3t-value");
        let spec = RunSpec {
            secret_ref: "api-key".to_string(),
            env_name: "MCP_TEST_VALUE".to_string(),
            cmd: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                "test \"$MCP_TEST_VALUE\" = \"s3cr3t-value\"".to_string(),
            ],
            cwd: None,
        };
        assert_eq!(prov.run_with_secret(&spec).unwrap(), 0);
    }

    #[test]
    fn run_with_secret_nonzero_exit_is_returned_not_error() {
        let (prov, _) = provider("run_nonzero");
        seed_secret(&prov, "api-key", "s3cr3t-value");
        let spec = RunSpec {
            secret_ref: "api-key".to_string(),
            env_name: "MCP_TEST_VALUE".to_string(),
            cmd: "/bin/sh".to_string(),
            args: vec![
                "-c".to_string(),
                // 注入值 ≠ 期望 → test 返回 1；验证「非零退出原样返回」。
                "test \"$MCP_TEST_VALUE\" = \"wrong-value\"".to_string(),
            ],
            cwd: None,
        };
        assert_eq!(prov.run_with_secret(&spec).unwrap(), 1);
    }

    #[test]
    fn run_with_secret_rejects_bad_input() {
        let (prov, _) = provider("run_reject");
        seed_secret(&prov, "api-key", "v1");
        let bad_cmd = RunSpec {
            secret_ref: "api-key".to_string(),
            env_name: "MCP_TEST_VALUE".to_string(),
            cmd: String::new(),
            args: Vec::new(),
            cwd: None,
        };
        assert!(matches!(
            prov.run_with_secret(&bad_cmd),
            Err(ProviderError::InvalidParameter(_))
        ));
        let unknown = RunSpec {
            secret_ref: "no-such".to_string(),
            env_name: "MCP_TEST_VALUE".to_string(),
            cmd: "/bin/true".to_string(),
            args: Vec::new(),
            cwd: None,
        };
        assert!(matches!(
            prov.run_with_secret(&unknown),
            Err(ProviderError::NotFound(_))
        ));
    }

    // ------------------------------------------------------------ 环境操作

    #[test]
    fn create_environment_then_list_and_duplicate_rejected() {
        let (prov, _) = provider("env_create");
        assert_eq!(prov.list_environments().unwrap(), Vec::<String>::new());
        prov.create_environment("prod").unwrap();
        assert_eq!(prov.list_environments().unwrap(), vec!["prod"]);
        // 环境容器不出现在 secret 清单。
        assert_eq!(prov.list_secret_names(None).unwrap(), Vec::<String>::new());
        // 空名 / 重名 → 7005。
        assert!(matches!(
            prov.create_environment("  "),
            Err(ProviderError::InvalidParameter(_))
        ));
        assert!(matches!(
            prov.create_environment("prod"),
            Err(ProviderError::InvalidParameter(_))
        ));
    }

    #[test]
    fn mount_environment_creates_dir_and_rejects_unknown() {
        let (prov, base) = provider("env_mount");
        prov.create_environment("prod").unwrap();
        let mount = base.join("mnt");
        prov.mount_environment("prod", mount.to_str().unwrap()).unwrap();
        assert!(mount.is_dir());
        assert!(matches!(
            prov.mount_environment("no-such-env", mount.to_str().unwrap()),
            Err(ProviderError::NotFound(_))
        ));
        assert!(matches!(
            prov.mount_environment("prod", ""),
            Err(ProviderError::InvalidParameter(_))
        ));
    }

    #[test]
    fn inject_environment_applies_to_process() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (prov, _) = provider("env_inject");
        seed_env(&prov, "prod", &[("CF_API_BASE", "https://x"), ("CF_DEBUG", "1")]);
        // 未知环境 → 7003。
        assert!(matches!(
            prov.inject_environment("no-such-env"),
            Err(ProviderError::NotFound(_))
        ));
        prov.inject_environment("prod").unwrap();
        assert_eq!(std::env::var("CF_API_BASE").unwrap(), "https://x");
        assert_eq!(std::env::var("CF_DEBUG").unwrap(), "1");
    }

    // ------------------------------------------------------------ 权限 / 生命周期

    #[test]
    fn grant_revoke_roundtrip_idempotent() {
        let (prov, _) = provider("grant_revoke");
        let id = seed_secret(&prov, "api-key", "v1");
        prov.grant_secret("api-key", "alice").unwrap();
        // 已授权 → 幂等 Ok。
        prov.grant_secret("api-key", "alice").unwrap();
        let d = prov.session.get_item(&id).unwrap().unwrap();
        assert_eq!(tag_of(&d, AGENT_TAG_PREFIX), vec!["coffer:agent:alice"]);
        // 授权不改变值。
        let pw = d
            .fields
            .iter()
            .find(|f| f.designation == Some(Designation::Password))
            .unwrap();
        assert_eq!(pw.value.as_ref().unwrap().expose(), "v1");

        prov.revoke_secret("api-key", "alice").unwrap();
        prov.revoke_secret("api-key", "alice").unwrap(); // 幂等
        let d = prov.session.get_item(&id).unwrap().unwrap();
        assert!(tag_of(&d, AGENT_TAG_PREFIX).is_empty());
    }

    #[test]
    fn grant_revoke_reject_empty_and_unknown() {
        let (prov, _) = provider("grant_revoke_reject");
        seed_secret(&prov, "api-key", "v1");
        assert!(matches!(
            prov.grant_secret("api-key", ""),
            Err(ProviderError::InvalidParameter(_))
        ));
        assert!(matches!(
            prov.grant_secret("no-such", "alice"),
            Err(ProviderError::NotFound(_))
        ));
        assert!(matches!(
            prov.revoke_secret("no-such", "alice"),
            Err(ProviderError::NotFound(_))
        ));
    }

    #[test]
    fn rotate_secret_changes_value_and_stamps() {
        let (prov, _) = provider("rotate");
        let id = seed_secret(&prov, "api-key", "old-value");
        prov.rotate_secret("api-key").unwrap();
        let d = prov.session.get_item(&id).unwrap().unwrap();
        let pw = d
            .fields
            .iter()
            .find(|f| f.designation == Some(Designation::Password))
            .unwrap();
        let new_val = pw.value.as_ref().unwrap().expose();
        assert!(new_val.starts_with("rotated-"), "got: {new_val}");
        assert_ne!(new_val, "old-value");
        let stamps = tag_of(&d, ROTATED_TAG_PREFIX);
        assert_eq!(stamps.len(), 1);
        assert!(stamps[0].starts_with("coffer:rotated:"));
    }

    #[test]
    fn rotate_secret_rejects_unknown_and_valueless() {
        let (prov, _) = provider("rotate_reject");
        assert!(matches!(
            prov.rotate_secret("no-such"),
            Err(ProviderError::NotFound(_))
        ));
        // 无任何有值字段的条目 → 7005（无值可轮换）。
        let draft = ItemDraft {
            title: "blank".to_string(),
            category: ItemCategory::SecureNote,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "note".to_string(),
                value: None,
                field_type: FieldType::Text,
                designation: None,
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        let id = prov.session.create_item(&draft).unwrap();
        let _ = id;
        assert!(matches!(
            prov.rotate_secret("blank"),
            Err(ProviderError::InvalidParameter(_))
        ));
    }

    #[test]
    fn audit_secret_usage_validates_known_and_unknown() {
        let (prov, _) = provider("audit");
        seed_secret(&prov, "api-key", "v1");
        prov.audit_secret_usage("api-key").unwrap();
        assert!(matches!(
            prov.audit_secret_usage(""),
            Err(ProviderError::InvalidParameter(_))
        ));
        assert!(matches!(
            prov.audit_secret_usage("no-such"),
            Err(ProviderError::NotFound(_))
        ));
    }

    // ------------------------------------------------------------ 会话态 / 构造

    #[test]
    fn locked_session_maps_to_auth_required() {
        let (prov, _) = provider("locked");
        seed_secret(&prov, "api-key", "v1");
        prov.session.lock();
        assert!(matches!(
            prov.list_secret_names(None),
            Err(ProviderError::AuthRequired(_))
        ));
    }

    #[test]
    fn open_constructor_roundtrip() {
        let (_, vault_dir) = provider("open_ctor");
        let p = CofferStoreProvider::open(&vault_dir, STRONG_PASSWORD).unwrap();
        assert_eq!(p.list_secret_names(None).unwrap(), Vec::<String>::new());
        // 错误密码 → 7002。
        let p = CofferStoreProvider::open(&vault_dir, "wrong-password");
        assert!(matches!(p, Err(ProviderError::AuthRequired(_))));
        // 库目录缺失 → 7001。
        let p = CofferStoreProvider::open(&vault_dir.join("no-such"), STRONG_PASSWORD);
        assert!(matches!(p, Err(ProviderError::Unavailable(_))));
    }

