    use super::*;
    use crate::provider::escrow::EscrowError;
    use cf_crypto::kdf::KdfParams;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::FieldType;
    use cf_domain::item::{FieldDraft, ItemDraft};
    use cf_session::{create_vault_with_kdf, open_vault};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn arg(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn uuid() -> &'static str {
        "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
    }

    // ------------------------------------------------------------ 参数解析

    #[test]
    fn parse_scope_and_pairs() {
        let o = parse_args(&arg(&["--scope", "prod", "LOG_LEVEL=debug", "API_KEY=abc"]))
            .expect("scope + pairs must parse");
        assert_eq!(o.scope.as_deref(), Some("prod"));
        assert_eq!(o.id, None);
        assert_eq!(
            o.pairs,
            vec![
                ("LOG_LEVEL".to_string(), "debug".to_string()),
                ("API_KEY".to_string(), "abc".to_string()),
            ]
        );
        assert_eq!(o.stdin_name, None);
        assert!(o.unset.is_empty());
    }

    #[test]
    fn parse_scope_and_bare_name() {
        let o = parse_args(&arg(&["--scope", "prod", "API_KEY"])).expect("scope + bare must parse");
        assert_eq!(o.scope.as_deref(), Some("prod"));
        assert!(o.pairs.is_empty());
        assert_eq!(o.stdin_name.as_deref(), Some("API_KEY"));
        assert!(o.unset.is_empty());
    }

    #[test]
    fn parse_id_only_locate() {
        // AC-36.1-5：`--id <UUID>` 独立定位（互斥，镜像 set-password --id 纪律）。
        let o = parse_args(&arg(&["--id", uuid(), "NAME=VALUE"])).expect("--id + pair must parse");
        assert_eq!(o.id.as_deref(), Some(uuid()));
        assert_eq!(o.scope, None);
        assert_eq!(o.pairs.len(), 1);
    }

    #[test]
    fn parse_scope_and_id_conflict() {
        let err = parse_args(&arg(&["--scope", "prod", "--id", uuid(), "NAME=VALUE"]))
            .expect_err("scope + --id rejected");
        assert!(matches!(err, SetEnvError::ConflictingLocators));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "并存 → 4");
    }

    #[test]
    fn parse_missing_scope_and_id() {
        let err = parse_args(&arg(&["NAME=VALUE"])).expect_err("no locator rejected");
        assert!(matches!(err, SetEnvError::MissingScope));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "缺定位 → 4");
    }

    #[test]
    fn parse_empty_scope_rejected() {
        for empty in ["", "   ", "\t"] {
            let err = parse_args(&arg(&["--scope", empty, "NAME=VALUE"]))
                .expect_err("empty --scope rejected");
            assert!(matches!(err, SetEnvError::EmptyScope), "实际 {err:?}");
            assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "空 scope → 4");
        }
    }

    #[test]
    fn parse_unset_mode() {
        let o = parse_args(&arg(&["--scope", "prod", "--unset", "API_KEY", "TOKEN"]))
            .expect("unset mode must parse");
        assert_eq!(o.scope.as_deref(), Some("prod"));
        assert!(o.pairs.is_empty());
        assert_eq!(o.stdin_name, None);
        assert_eq!(o.unset, vec!["API_KEY".to_string(), "TOKEN".to_string()]);
    }

    #[test]
    fn parse_unset_single_name() {
        let o = parse_args(&arg(&["--scope", "prod", "--unset", "API_KEY"]))
            .expect("unset single must parse");
        assert_eq!(o.unset, vec!["API_KEY".to_string()]);
    }

    #[test]
    fn parse_unset_with_pair_conflict() {
        let err = parse_args(&arg(&["--scope", "prod", "--unset", "API_KEY", "TOKEN=abc"]))
            .expect_err("unset + pair rejected");
        assert!(matches!(err, SetEnvError::UnsetWithPairs(_)));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "对并存 → 4");
    }

    #[test]
    fn parse_unset_requires_at_least_one_name() {
        let err = parse_args(&arg(&["--scope", "prod", "--unset"]))
            .expect_err("--unset without name rejected");
        assert!(matches!(err, SetEnvError::MissingUnsetName));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "缺 unset 名 → 4");
    }

    #[test]
    fn parse_multiple_bare_names_rejected() {
        let err = parse_args(&arg(&["--scope", "prod", "NAME1", "NAME2"]))
            .expect_err("two bare names rejected");
        assert!(matches!(err, SetEnvError::MultipleBareNames));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "裸 NAME 多个 → 4");
    }

    #[test]
    fn parse_mixed_pairs_and_single_bare_allowed() {
        // 至多一个裸 NAME（stdin 取值）可与内联对并存（值归属无歧义）。
        let o = parse_args(&arg(&["--scope", "prod", "LOG_LEVEL=debug", "API_KEY"]))
            .expect("pairs + one bare must parse");
        assert_eq!(o.pairs.len(), 1);
        assert_eq!(o.stdin_name.as_deref(), Some("API_KEY"));
    }

    #[test]
    fn parse_pair_value_may_contain_equals() {
        // 按第一个 `=` 分割，VALUE 可含 `=`。
        let o = parse_args(&arg(&["--scope", "prod", "URL=https://a=b/c"]))
            .expect("value with = must parse");
        assert_eq!(o.pairs, vec![("URL".to_string(), "https://a=b/c".to_string())]);
    }

    #[test]
    fn parse_empty_inline_value_is_legal() {
        // AC-36.1-9：`NAME=` = 显式置空串（合法，非删除）。
        let o = parse_args(&arg(&["--scope", "prod", "EMPTY="])).expect("empty value must parse");
        assert_eq!(o.pairs, vec![("EMPTY".to_string(), String::new())]);
    }

    #[test]
    fn parse_value_with_nul_rejected() {
        let err = parse_args(&arg(&["--scope", "prod", "A=x\0y"]))
            .expect_err("NUL in value rejected");
        assert!(matches!(err, SetEnvError::ValueContainsNul));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "VALUE 含 NUL → 4");
    }

    #[test]
    fn parse_invalid_names_rejected() {
        // AC-36.1-8：非法 NAME（含 `-` / 数字开头 / 中文）→ 4 不写库。
        for bad in ["1ABC", "HAS-DASH", "中文"] {
            let err = parse_args(&arg(&["--scope", "prod", &format!("{bad}=v")]))
                .expect_err(&format!("invalid name rejected: {bad}"));
            assert!(matches!(err, SetEnvError::InvalidName(ref n) if n == bad), "实际 {err:?}");
            assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "{bad} → 4");
        }
        // 空名（`=v`）同样非法。
        let err = parse_args(&arg(&["--scope", "prod", "=v"])).expect_err("empty name rejected");
        assert!(matches!(err, SetEnvError::InvalidName(n) if n.is_empty()));
        // 破折号开头是 flag 形态 → UnknownFlag（同样用法错误 4，不写库）。
        let err = parse_args(&arg(&["--scope", "prod", "-lead=v"]))
            .expect_err("dash-leading rejected");
        assert!(matches!(err, SetEnvError::UnknownFlag(_)));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "-lead → 4");
    }

    #[test]
    fn parse_valid_names_accepted() {
        // AC-36.1-8：合法（`A_Z9` / 下划线开头）→ 成功。
        let o = parse_args(&arg(&["--scope", "prod", "A_Z9=1", "_OK=2"]))
            .expect("valid names must parse");
        assert_eq!(o.pairs.len(), 2);
    }

    #[test]
    fn parse_invalid_unset_name_rejected() {
        let err = parse_args(&arg(&["--scope", "prod", "--unset", "BAD-NAME"]))
            .expect_err("invalid unset name rejected");
        assert!(matches!(err, SetEnvError::InvalidName(ref n) if n == "BAD-NAME"));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "非法 unset 名 → 4");
    }

    #[test]
    fn parse_missing_write_target_rejected() {
        let err = parse_args(&arg(&["--scope", "prod"]))
            .expect_err("no pairs/bare/unset rejected");
        assert!(matches!(err, SetEnvError::MissingWrite));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "无写意图 → 4");
    }

    #[test]
    fn parse_unknown_flag_rejected() {
        let err = parse_args(&arg(&["--scope", "prod", "--bogus", "X"]))
            .expect_err("unknown flag rejected");
        assert!(matches!(err, SetEnvError::UnknownFlag(ref f) if f == "--bogus"));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "未知 flag → 4");
    }

    #[test]
    fn parse_missing_flag_value_rejected() {
        for flag in ["--scope", "--id"] {
            let err = parse_args(&arg(&[flag])).expect_err(&format!("{flag} without value"));
            assert!(matches!(err, SetEnvError::MissingValue(ref f) if f == flag));
            assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "缺值 → 4");
        }
    }

    #[test]
    fn parse_malformed_id_rejected() {
        let err = parse_args(&arg(&["--id", "not-a-uuid", "NAME=VALUE"]))
            .expect_err("malformed id rejected");
        assert!(matches!(err, SetEnvError::InvalidId(ref v) if v == "not-a-uuid"));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "格式错 → 4");
    }

    // ------------------------------------------------------------ 读 stdin 值

    #[test]
    fn read_value_plain_strips_newline() {
        let mut r = std::io::Cursor::new(b"secret-key-1\n".to_vec());
        let v = read_value_line(&mut r, false, "").expect("plain read");
        assert_eq!(v.expose(), "secret-key-1");
    }

    #[test]
    fn read_value_plain_strips_crlf() {
        let mut r = std::io::Cursor::new(b"secret-key-1\r\n".to_vec());
        let v = read_value_line(&mut r, false, "").expect("plain read");
        assert_eq!(v.expose(), "secret-key-1");
    }

    #[test]
    fn read_value_plain_allows_empty() {
        // 与 set-password 不同：VALUE 空串合法（env 空值有语义，docs/36 §4.4）。
        let mut r = std::io::Cursor::new(b"\n".to_vec());
        let v = read_value_line(&mut r, false, "").expect("empty value must be legal");
        assert_eq!(v.expose(), "");
    }

    // ------------------------------------------------------------ draft 构建

    fn env_draft() -> ItemDraft {
        ItemDraft {
            title: "prod".to_string(),
            category: ItemCategory::SecureNote,
            urls: Vec::new(),
            tags: vec!["coffer:environment".to_string()],
            sections: Vec::new(),
            fields: vec![
                FieldDraft {
                    name: "LOG_LEVEL".to_string(),
                    value: Some("debug".to_string()),
                    field_type: FieldType::Text,
                    designation: None,
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "API_KEY".to_string(),
                    value: Some("old-key".to_string()),
                    field_type: FieldType::Text,
                    designation: None,
                    section_index: None,
                    position: 1,
                },
                FieldDraft {
                    name: "URL".to_string(),
                    value: Some("https://keep".to_string()),
                    field_type: FieldType::Text,
                    designation: None,
                    section_index: None,
                    position: 2,
                },
            ],
            totp: None,
        }
    }

    #[test]
    fn apply_pair_updates_existing_field_only() {
        let mut d = env_draft();
        apply_pair(&mut d, "API_KEY", "new-key");
        assert_eq!(d.fields[1].value.as_deref(), Some("new-key"), "命中字段更新");
        assert_eq!(d.fields[0].value.as_deref(), Some("debug"), "其它字段不动");
        assert_eq!(d.fields[2].value.as_deref(), Some("https://keep"), "其它字段不动");
        assert_eq!(d.fields.len(), 3, "不新增字段");
    }

    #[test]
    fn apply_pair_appends_missing_field_as_text_no_designation() {
        let mut d = env_draft();
        apply_pair(&mut d, "NEW_VAR", "v");
        let f = d.fields.last().expect("appended field");
        assert_eq!(f.name, "NEW_VAR");
        assert_eq!(f.value.as_deref(), Some("v"));
        assert_eq!(f.field_type, FieldType::Text, "字段形态固定 Text");
        assert_eq!(f.designation, None, "designation: None（非 secret/username）");
        assert_eq!(f.position, 3, "新字段 position = 现有最大 + 1");
        assert_eq!(d.fields.len(), 4);
    }

    #[test]
    fn apply_pair_preserves_existing_field_type_and_designation() {
        // 命中既有字段不改其 field_type / designation（用户手编字段不静默重写）。
        let mut d = env_draft();
        d.fields[1].field_type = FieldType::Concealed;
        d.fields[1].designation = Some(cf_domain::field::Designation::NotesPlain);
        apply_pair(&mut d, "API_KEY", "new");
        assert_eq!(d.fields[1].value.as_deref(), Some("new"));
        assert_eq!(
            d.fields[1].field_type,
            FieldType::Concealed,
            "field_type 不静默重写"
        );
        assert_eq!(
            d.fields[1].designation,
            Some(cf_domain::field::Designation::NotesPlain),
            "designation 不静默重写"
        );
    }

    #[test]
    fn apply_pair_empty_value_sets_empty_not_delete() {
        // AC-36.1-9：`NAME=` → 字段 = 空串（不是删除）。
        let mut d = env_draft();
        apply_pair(&mut d, "API_KEY", "");
        assert_eq!(d.fields[1].value.as_deref(), Some(""), "置空不删除");
        assert_eq!(d.fields.len(), 3, "字段仍在");
    }

    #[test]
    fn apply_unset_removes_matching_fields() {
        let mut d = env_draft();
        apply_unset(&mut d, &["API_KEY".to_string(), "MISSING".to_string()]);
        assert_eq!(
            d.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            vec!["LOG_LEVEL", "URL"],
            "命中字段删除，其余保留"
        );
    }

    #[test]
    fn apply_unset_missing_name_idempotent() {
        // 删除不存在的 NAME = 幂等成功（与 revoke_secret 幂等纪律同）。
        let mut d = env_draft();
        apply_unset(&mut d, &["NOPE".to_string()]);
        assert_eq!(d.fields.len(), 3, "无字段被删");
    }

    // ------------------------------------------------------------ 退出码映射

    #[test]
    fn exit_codes_distinct_per_category() {
        let usage = vec![
            SetEnvError::UnknownFlag("--nope".to_string()),
            SetEnvError::MissingValue("--scope".to_string()),
            SetEnvError::MissingScope,
            SetEnvError::EmptyScope,
            SetEnvError::ConflictingLocators,
            SetEnvError::InvalidId("not-a-uuid".to_string()),
            SetEnvError::InvalidName("BAD-NAME".to_string()),
            SetEnvError::ValueContainsNul,
            SetEnvError::MultipleBareNames,
            SetEnvError::UnsetWithPairs("A=B".to_string()),
            SetEnvError::MissingUnsetName,
            SetEnvError::MissingWrite,
        ];
        for e in usage {
            assert_eq!(e.exit_code(), exit_codes::USAGE_ERROR, "{e:?} → 4");
        }

        let target = vec![
            SetEnvError::ItemNotFound("nope".to_string()),
            SetEnvError::NotEnvContainer("title".to_string()),
            SetEnvError::Ambiguous {
                name: "prod".to_string(),
                count: 2,
            },
        ];
        for e in target {
            assert_eq!(e.exit_code(), exit_codes::TARGET_NOT_FOUND, "{e:?} → 2");
        }

        for e in [
            SetEnvError::ReadValue(std::io::Error::other("io")),
            SetEnvError::Storage,
        ] {
            assert_eq!(e.exit_code(), exit_codes::UNLOCK_FAILED, "{e:?} → 1");
        }
    }

    #[test]
    fn exit_code_three_reserved_unused() {
        // docs/36 §4.5：3 = 保留槽位，不适用（set-env 无强度门禁），码位维持对齐。
        assert_eq!(exit_codes::WEAK_PASSWORD, 3);
        assert_eq!(exit_codes::SUCCESS, 0);
        assert_eq!(exit_codes::UNLOCK_FAILED, 1);
        assert_eq!(exit_codes::TARGET_NOT_FOUND, 2);
        assert_eq!(exit_codes::USAGE_ERROR, 4);
    }

    // ------------------------------------------------------------ 库级 resolve

    /// 快速档测试库（8 MiB KDF，几十毫秒）。
    fn fast_vault(tag: &str) -> (PathBuf, String) {
        const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "cf-mcp-setenv-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).expect("create temp base");
        let brief = create_vault_with_kdf(
            &base,
            "测试库",
            STRONG_PASSWORD,
            KdfParams::new(8 * 1024, 1, 1).expect("8 MiB fast KDF"),
        )
        .expect("create fast vault");
        (base.join(brief.uuid.to_string()), STRONG_PASSWORD.to_string())
    }

    fn unlocked_vault(vault_dir: &std::path::Path, password: &str) -> VaultSession {
        let s = open_vault(vault_dir).expect("open vault");
        s.unlock(password).expect("unlock vault");
        s
    }

    /// 建一个环境容器条目（SecureNote + coffer:environment 标签）。
    fn create_env_item(session: &VaultSession, title: &str) -> String {
        let d = ItemDraft {
            title: title.to_string(),
            category: ItemCategory::SecureNote,
            urls: Vec::new(),
            tags: vec!["coffer:environment".to_string()],
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "API_KEY".to_string(),
                value: Some("old-key".to_string()),
                field_type: FieldType::Text,
                designation: None,
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        session.create_item(&d).expect("create env item")
    }

    /// 建一个同名**非容器**普通条目（SecureNote 无标签）。
    fn create_plain_item(session: &VaultSession, title: &str) -> String {
        let d = ItemDraft {
            title: title.to_string(),
            category: ItemCategory::SecureNote,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: Vec::new(),
            totp: None,
        };
        session.create_item(&d).expect("create plain item")
    }

    fn resolve_options(scope: &str) -> SetEnvOptions {
        SetEnvOptions {
            scope: Some(scope.to_string()),
            id: None,
            pairs: vec![("NAME".to_string(), "v".to_string())],
            stdin_name: None,
            unset: Vec::new(),
        }
    }

    #[test]
    fn resolve_by_scope_exact_container() {
        let (dir, pw) = fast_vault("resolve-exact");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_env_item(&s, "prod");
        let target = resolve_target(&s, &resolve_options("prod")).expect("exact match");
        match target {
            ResolvedTarget::Existing(d) => {
                assert_eq!(d.uuid, uuid);
                assert_eq!(d.title.expose(), "prod");
            }
            ResolvedTarget::Fresh { .. } => panic!("不得自动建容器"),
        }
    }

    #[test]
    fn resolve_by_scope_not_found_auto_creates() {
        let (dir, pw) = fast_vault("resolve-autocreate");
        let s = unlocked_vault(&dir, &pw);
        let target = resolve_target(&s, &resolve_options("brand-new")).expect("auto-create");
        match target {
            ResolvedTarget::Fresh { title, uuid } => {
                assert_eq!(title, "brand-new");
                let d = s.get_item(&uuid).expect("get").expect("present");
                assert_eq!(d.category, ItemCategory::SecureNote, "SecureNote");
                assert!(
                    d.tags.iter().any(|t| t.expose() == "coffer:environment"),
                    "coffer:environment 标签"
                );
            }
            ResolvedTarget::Existing(_) => panic!("不存在须自动建容器"),
        }
    }

    #[test]
    fn resolve_by_scope_non_container_rejected() {
        let (dir, pw) = fast_vault("resolve-noncontainer");
        let s = unlocked_vault(&dir, &pw);
        create_plain_item(&s, "prod");
        let err = resolve_target(&s, &resolve_options("prod")).expect_err("non-container rejected");
        assert!(matches!(err, SetEnvError::NotEnvContainer(ref t) if t == "prod"));
        assert_eq!(err.exit_code(), exit_codes::TARGET_NOT_FOUND, "非容器 → 2");
    }

    #[test]
    fn resolve_by_scope_ambiguous() {
        let (dir, pw) = fast_vault("resolve-ambiguous");
        let s = unlocked_vault(&dir, &pw);
        create_env_item(&s, "prod");
        create_env_item(&s, "prod");
        let err = resolve_target(&s, &resolve_options("prod")).expect_err("ambiguous");
        assert!(matches!(
            err,
            SetEnvError::Ambiguous { ref name, ref count } if name == "prod" && *count == 2
        ));
        assert_eq!(err.exit_code(), exit_codes::TARGET_NOT_FOUND, "歧义 → 2");
    }

    #[test]
    fn resolve_by_id_container_ok() {
        let (dir, pw) = fast_vault("resolve-id-ok");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_env_item(&s, "prod");
        let opts = SetEnvOptions {
            scope: None,
            id: Some(uuid.clone()),
            pairs: vec![("NAME".to_string(), "v".to_string())],
            stdin_name: None,
            unset: Vec::new(),
        };
        match resolve_target(&s, &opts).expect("by id") {
            ResolvedTarget::Existing(d) => assert_eq!(d.uuid, uuid),
            ResolvedTarget::Fresh { .. } => panic!("--id 不自动建"),
        }
    }

    #[test]
    fn resolve_by_id_miss() {
        let (dir, pw) = fast_vault("resolve-id-miss");
        let s = unlocked_vault(&dir, &pw);
        let opts = SetEnvOptions {
            scope: None,
            id: Some(uuid().to_string()),
            pairs: vec![("NAME".to_string(), "v".to_string())],
            stdin_name: None,
            unset: Vec::new(),
        };
        let err = resolve_target(&s, &opts).expect_err("unknown id");
        assert!(matches!(err, SetEnvError::ItemNotFound(_)));
        assert_eq!(err.exit_code(), exit_codes::TARGET_NOT_FOUND, "未命中 → 2");
    }

    #[test]
    fn resolve_by_id_non_container_rejected() {
        let (dir, pw) = fast_vault("resolve-id-noncontainer");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_plain_item(&s, "prod");
        let opts = SetEnvOptions {
            scope: None,
            id: Some(uuid),
            pairs: vec![("NAME".to_string(), "v".to_string())],
            stdin_name: None,
            unset: Vec::new(),
        };
        let err = resolve_target(&s, &opts).expect_err("--id 非容器拒绝");
        assert!(matches!(err, SetEnvError::NotEnvContainer(_)));
        assert_eq!(err.exit_code(), exit_codes::TARGET_NOT_FOUND, "非容器 → 2");
    }

    // ------------------------------------------------------------ run_with 端到端（mock escrow）

    /// 在测试库上启用 MCP 托管，返回 mcp_key 字节副本。
    fn escrow_enable(vault_dir: &std::path::Path, password: &str) -> [u8; 32] {
        let session = open_vault(vault_dir).expect("open vault");
        session.unlock(password).expect("unlock vault");
        let mcp_key = session.derive_mcp_key(password).expect("derive mcp_key");
        session
            .enable_mcp_escrow(password, mcp_key.as_bytes())
            .expect("enable escrow");
        *mcp_key.as_bytes()
    }

    struct MockEscrow {
        result: std::sync::Mutex<Result<Option<[u8; 32]>, EscrowError>>,
    }

    impl MockEscrow {
        fn new(result: Result<Option<[u8; 32]>, EscrowError>) -> Self {
            Self {
                result: std::sync::Mutex::new(result),
            }
        }
    }

    impl VaultEscrowStore for MockEscrow {
        fn read_mcp_key(&self, _vault_uuid: &str) -> Result<Option<[u8; 32]>, EscrowError> {
            self.result.lock().expect("mock result lock").clone()
        }
    }

    /// 取容器某字段现值（断言写入/未变用）。
    fn env_field_value(vault_dir: &std::path::Path, password: &str, item_id: &str, name: &str) -> Option<String> {
        let s = unlocked_vault(vault_dir, password);
        let item = s.get_item(item_id).expect("get item").expect("item present");
        item.fields
            .iter()
            .find(|f| f.name.expose() == name)
            .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
    }

    /// 写模式 options（env 兜底解锁：无托管 + 正确 env 密码）。
    fn write_opts(scope: &str, pairs: &[(&str, &str)]) -> SetEnvOptions {
        SetEnvOptions {
            scope: Some(scope.to_string()),
            id: None,
            pairs: pairs
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect(),
            stdin_name: None,
            unset: Vec::new(),
        }
    }

    /// AC-36.1-1：写入更新成功（退出 0，字段更新，只动目标字段）。
    #[test]
    fn run_write_updates_existing_container() {
        let (dir, pw) = fast_vault("run-write");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_env_item(&s, "prod"); // API_KEY=old-key
        drop(s);
        let escrow = MockEscrow::new(Ok(None)); // 无托管 → env 兜底
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let code = run_with(
            &mut stdin,
            false,
            &write_opts("prod", &[("API_KEY", "new-key")]),
            &dir,
            Some(SecretString::from_exposed(pw.clone())),
            &escrow,
        );
        assert_eq!(code, exit_codes::SUCCESS, "写入成功 → 0");
        assert_eq!(
            env_field_value(&dir, &pw, &uuid, "API_KEY").as_deref(),
            Some("new-key"),
            "字段已更新"
        );
    }

    /// AC-36.1-2：首写自动建容器（退出 0 + SecureNote + 标签 + NAME 字段）。
    #[test]
    fn run_write_auto_creates_container() {
        let (dir, pw) = fast_vault("run-autocreate");
        let escrow = MockEscrow::new(Ok(None));
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let code = run_with(
            &mut stdin,
            false,
            &write_opts("brand-new", &[("LOG_LEVEL", "debug")]),
            &dir,
            Some(SecretString::from_exposed(pw.clone())),
            &escrow,
        );
        assert_eq!(code, exit_codes::SUCCESS, "首写即建 → 0");
        let s = unlocked_vault(&dir, &pw);
        let items = s.list_items(None).expect("list");
        let created = items
            .iter()
            .find(|i| i.title == "brand-new")
            .expect("container created");
        let d = s.get_item(&created.uuid.to_string()).expect("get").expect("present");
        assert_eq!(d.category, ItemCategory::SecureNote);
        assert!(d.tags.iter().any(|t| t.expose() == "coffer:environment"));
        assert_eq!(
            env_field_value(&dir, &pw, &created.uuid.to_string(), "LOG_LEVEL").as_deref(),
            Some("debug")
        );
    }

    /// AC-36.1-7：--unset 删除字段（退出 0）；删除不存在的 NAME 幂等。
    #[test]
    fn run_unset_removes_field() {
        let (dir, pw) = fast_vault("run-unset");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_env_item(&s, "prod"); // API_KEY
        drop(s);
        let escrow = MockEscrow::new(Ok(None));
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let opts = SetEnvOptions {
            scope: Some("prod".to_string()),
            id: None,
            pairs: Vec::new(),
            stdin_name: None,
            unset: vec!["API_KEY".to_string(), "MISSING".to_string()],
        };
        let code = run_with(
            &mut stdin,
            false,
            &opts,
            &dir,
            Some(SecretString::from_exposed(pw.clone())),
            &escrow,
        );
        assert_eq!(code, exit_codes::SUCCESS, "unset 成功 → 0");
        assert_eq!(
            env_field_value(&dir, &pw, &uuid, "API_KEY"),
            None,
            "字段已删除（幂等 MISSING 无副作用）"
        );
    }

    /// 裸 NAME stdin 取值（管道档）：退出 0，字段 = 管道行值（剥换行）。
    #[test]
    fn run_bare_name_reads_stdin_value() {
        let (dir, pw) = fast_vault("run-bare");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_env_item(&s, "prod"); // API_KEY=old-key
        drop(s);
        let escrow = MockEscrow::new(Ok(None));
        let mut stdin = std::io::Cursor::new(b"super-secret-99\n".to_vec());
        let opts = SetEnvOptions {
            scope: Some("prod".to_string()),
            id: None,
            pairs: Vec::new(),
            stdin_name: Some("API_KEY".to_string()),
            unset: Vec::new(),
        };
        let code = run_with(
            &mut stdin,
            false,
            &opts,
            &dir,
            Some(SecretString::from_exposed(pw.clone())),
            &escrow,
        );
        assert_eq!(code, exit_codes::SUCCESS, "stdin 取值成功 → 0");
        assert_eq!(
            env_field_value(&dir, &pw, &uuid, "API_KEY").as_deref(),
            Some("super-secret-99"),
            "stdin 行值（剥换行）已写入"
        );
    }

    /// 解锁失败 fail-closed：escrow 存在但 key 错 → 退出 1，不回落 env，库不动。
    #[test]
    fn escrow_wrong_key_fails_closed() {
        let (dir, pw) = fast_vault("escrow-wrong");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_env_item(&s, "prod"); // API_KEY=old-key
        drop(s);
        escrow_enable(&dir, &pw);

        let escrow = MockEscrow::new(Ok(Some([7u8; 32])));
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let code = run_with(
            &mut stdin,
            false,
            &write_opts("prod", &[("API_KEY", "new-key")]),
            &dir,
            Some(SecretString::from_exposed(pw.clone())), // 正确 env，须被忽略
            &escrow,
        );
        assert_eq!(code, exit_codes::UNLOCK_FAILED, "escrow 解锁失败 → 1");
        assert_eq!(
            env_field_value(&dir, &pw, &uuid, "API_KEY").as_deref(),
            Some("old-key"),
            "fail-closed 不写库"
        );
    }

    /// 名称歧义经 run_with → 退出 2 不写库（AC-36.1-4）。
    #[test]
    fn run_ambiguous_scope_exits_2() {
        let (dir, pw) = fast_vault("run-ambiguous");
        let s = unlocked_vault(&dir, &pw);
        create_env_item(&s, "prod");
        create_env_item(&s, "prod");
        drop(s);
        let escrow = MockEscrow::new(Ok(None));
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let code = run_with(
            &mut stdin,
            false,
            &write_opts("prod", &[("API_KEY", "new-key")]),
            &dir,
            Some(SecretString::from_exposed(pw)),
            &escrow,
        );
        assert_eq!(code, exit_codes::TARGET_NOT_FOUND, "歧义 → 2");
    }
