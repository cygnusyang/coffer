    use super::*;
    use crate::provider::escrow::EscrowError;
    use cf_crypto::kdf::KdfParams;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::FieldType;
    use cf_domain::item::FieldDraft;
    use cf_session::{create_vault_with_kdf, open_vault};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn arg(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    // ------------------------------------------------------------ 参数解析

    #[test]
    fn parse_positional_name() {
        let o = parse_args(&arg(&["GitHub"])).expect("name must parse");
        assert_eq!(o.name.as_deref(), Some("GitHub"));
        assert_eq!(o.id, None);
        assert!(!o.force);
    }

    #[test]
    fn parse_id_flag() {
        let o = parse_args(&arg(&["--id", "1b4e28ba-2fa1-11d2-883f-0016d3cca427"]))
            .expect("--id must parse");
        assert_eq!(
            o.id.as_deref(),
            Some("1b4e28ba-2fa1-11d2-883f-0016d3cca427")
        );
        assert_eq!(o.name, None);
    }

    #[test]
    fn parse_force_with_name() {
        let o = parse_args(&arg(&["--force", "GitHub"])).expect("force+name must parse");
        assert!(o.force);
        assert_eq!(o.name.as_deref(), Some("GitHub"));
    }

    #[test]
    fn parse_force_with_id() {
        let o = parse_args(&arg(&[
            "--id",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
            "--force",
        ]))
        .expect("force+id must parse");
        assert!(o.force);
        assert_eq!(o.id.as_deref(), Some("1b4e28ba-2fa1-11d2-883f-0016d3cca427"));
    }

    #[test]
    fn parse_rejects_unknown_flag() {
        let err = parse_args(&arg(&["--bogus", "X"])).expect_err("unknown flag rejected");
        assert!(matches!(err, SetPasswordError::UnknownFlag(f) if f == "--bogus"));
    }

    #[test]
    fn parse_rejects_missing_id_value() {
        let err = parse_args(&arg(&["--id"])).expect_err("--id without value rejected");
        assert!(matches!(err, SetPasswordError::MissingValue(f) if f == "--id"));
    }

    #[test]
    fn parse_rejects_extra_positional() {
        let err = parse_args(&arg(&["a", "b"])).expect_err("two positionals rejected");
        assert!(matches!(err, SetPasswordError::UnexpectedPositional(p) if p == "b"));
    }

    #[test]
    fn parse_rejects_name_and_id_together() {
        let err =
            parse_args(&arg(&["GitHub", "--id", "1b4e28ba-2fa1-11d2-883f-0016d3cca427"]))
                .expect_err("name + --id rejected");
        assert!(matches!(err, SetPasswordError::ConflictingLocators));
    }

    #[test]
    fn parse_rejects_no_target() {
        let err = parse_args(&[]).expect_err("no target rejected");
        assert!(matches!(err, SetPasswordError::MissingTarget));
    }

    // ------------------------------------------------ v2.5.2 `--user` 可选参数（用户 2026-10-10 裁定）

    #[test]
    fn parse_user_flag_with_name() {
        let o = parse_args(&arg(&["GitHub", "--user", "octocat"])).expect("--user + name parse");
        assert_eq!(o.username.as_deref(), Some("octocat"));
        assert_eq!(o.name.as_deref(), Some("GitHub"));
        assert_eq!(o.id, None);
    }

    #[test]
    fn parse_user_flag_with_id() {
        let o = parse_args(&arg(&[
            "--id",
            "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
            "--user",
            "octocat",
        ]))
        .expect("--user + --id parse");
        assert_eq!(o.username.as_deref(), Some("octocat"));
        assert_eq!(
            o.id.as_deref(),
            Some("1b4e28ba-2fa1-11d2-883f-0016d3cca427")
        );
    }

    #[test]
    fn parse_user_flag_order_free() {
        // `--user` 可在位置参数前出现；与 `--force` 可共存。
        let o = parse_args(&arg(&["--user", "octocat", "--force", "GitHub"]))
            .expect("--user order-free parse");
        assert_eq!(o.username.as_deref(), Some("octocat"));
        assert_eq!(o.name.as_deref(), Some("GitHub"));
        assert!(o.force);
    }

    #[test]
    fn parse_rejects_missing_user_value() {
        let err = parse_args(&arg(&["GitHub", "--user"])).expect_err("--user without value");
        assert!(matches!(err, SetPasswordError::MissingValue(ref f) if f == "--user"));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "缺值 → 退出 4");
    }

    /// M-1（dev-reviewer 2026-10-10）：空 / 全空白 `--user` 拒绝——镜像空密码
    /// 语义（AC-18.2-14），防静默把既有用户名覆写为空。退出 4，不写库。
    #[test]
    fn parse_rejects_empty_user_value() {
        for empty in ["", "   ", "\t"] {
            let err = parse_args(&arg(&["GitHub", "--user", empty]))
                .expect_err("empty --user rejected");
            assert!(
                matches!(err, SetPasswordError::EmptyUsername),
                "空/全空白用户名 → EmptyUsername，实际 {err:?}"
            );
            assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "空用户名 → 退出 4");
        }
    }

    // ------------------------------------------------------------ 强度门禁

    #[test]
    fn strength_rejects_weak_password() {
        let err = enforce_strength("123456", false).expect_err("weak must be rejected");
        assert!(matches!(err, SetPasswordError::WeakPassword));
    }

    #[test]
    fn strength_accepts_strong_password() {
        enforce_strength("correct-horse-battery-staple-42!", false).expect("strong must pass");
    }

    #[test]
    fn strength_force_bypasses() {
        enforce_strength("123456", true).expect("--force bypasses strength gate");
        enforce_strength("", true).expect("--force bypasses strength gate");
    }

    // ------------------------------------------------------------ 读密

    #[test]
    fn read_password_plain_strips_newline() {
        let mut r = std::io::Cursor::new(b"hunter2\n".to_vec());
        let pw = read_password_line(&mut r, false, "").expect("plain read");
        assert_eq!(pw.expose(), "hunter2");
    }

    #[test]
    fn read_password_plain_strips_crlf() {
        let mut r = std::io::Cursor::new(b"hunter2\r\n".to_vec());
        let pw = read_password_line(&mut r, false, "").expect("plain read");
        assert_eq!(pw.expose(), "hunter2");
    }

    #[test]
    fn read_password_plain_rejects_empty() {
        let mut r = std::io::Cursor::new(b"".to_vec());
        let err = read_password_line(&mut r, false, "").expect_err("empty rejected");
        assert!(matches!(err, SetPasswordError::EmptyPassword));
    }

    /// L-1（lead 审查 2026-10-10）：trim 后全空白同样拒绝（即便 `--force` 也不写库）。
    #[test]
    fn read_password_plain_rejects_whitespace_only() {
        let mut r = std::io::Cursor::new(b"   \t  \n".to_vec());
        let err = read_password_line(&mut r, false, "").expect_err("whitespace rejected");
        assert!(matches!(err, SetPasswordError::EmptyPassword));
    }

    // ------------------------------------------------------------ 字段定位

    fn password_draft() -> ItemDraft {
        ItemDraft {
            title: "GitHub".to_string(),
            category: ItemCategory::Login,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![
                FieldDraft {
                    name: "username".to_string(),
                    value: Some("octocat".to_string()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "password".to_string(),
                    value: Some("old-secret".to_string()),
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
                FieldDraft {
                    name: "notes".to_string(),
                    value: Some("keep me".to_string()),
                    field_type: FieldType::Multiline,
                    designation: None,
                    section_index: None,
                    position: 2,
                },
            ],
            totp: None,
        }
    }

    #[test]
    fn set_field_updates_password_designated_field_only() {
        let mut d = password_draft();
        assert!(set_password_field(&mut d, "new-secret"));
        // Password 字段更新；username / notes 不动。
        assert_eq!(d.fields[1].value.as_deref(), Some("new-secret"));
        assert_eq!(d.fields[0].value.as_deref(), Some("octocat"));
        assert_eq!(d.fields[2].value.as_deref(), Some("keep me"));
    }

    /// H-1（lead 审查 2026-10-10）：**不**做 `Concealed` 兜底——非 `Password`
    /// 指定字段的条目拒绝写入（CVV 等 Concealed 字段绝不被覆盖）。
    #[test]
    fn set_field_rejects_concealed_without_password_designation() {
        let mut d = ItemDraft {
            title: "X".to_string(),
            category: ItemCategory::Password,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "password".to_string(),
                value: Some("old".to_string()),
                field_type: FieldType::Concealed,
                designation: None,
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        assert!(!set_password_field(&mut d, "new"));
        // 拒绝路径不动原值（CVV 类 Concealed 字段保原样）。
        assert_eq!(d.fields[0].value.as_deref(), Some("old"));
    }

    #[test]
    fn set_field_errors_when_no_password_field() {
        let mut d = ItemDraft {
            title: "X".to_string(),
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
        assert!(
            !set_password_field(&mut d, "new"),
            "仅用户名无密码字段 → 不得改任意有值字段（防误改）"
        );
        assert_eq!(d.fields[0].value.as_deref(), Some("octocat"), "不得误改");
    }

    // ------------------------------------------------ v2.5.2 用户名写路径（AC-18.2-17/-18）

    #[test]
    fn apply_username_updates_existing_username_field() {
        let mut d = password_draft(); // username=octocat（Designation::Username）
        apply_username_field(&mut d, "newuser");
        assert_eq!(d.fields[0].value.as_deref(), Some("newuser"), "现值更新");
        assert_eq!(d.fields.len(), 3, "不新增字段");
        assert_eq!(d.fields[1].value.as_deref(), Some("old-secret"), "密码字段不动");
    }

    #[test]
    fn apply_username_creates_missing_username_field() {
        // 条目仅密码字段、无 Username designation → 新建（template.rs 同构）。
        let mut d = ItemDraft {
            title: "X".to_string(),
            category: ItemCategory::Login,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "password".to_string(),
                value: Some("old".to_string()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        apply_username_field(&mut d, "alice");
        let u = d
            .fields
            .iter()
            .find(|f| f.designation == Some(Designation::Username))
            .expect("Username 字段已新建");
        assert_eq!(u.name, "username", "字段名与模板一致");
        assert_eq!(u.field_type, FieldType::Text, "Text 类型与模板一致");
        assert_eq!(u.value.as_deref(), Some("alice"));
        assert_eq!(u.position, 1, "新字段 position = 现有最大 + 1");
    }

    /// AC-18.2-18：写侧不做 Email 兜底——条目仅 Email 字段时，用户名写进新建的
    /// Username 字段，**不回写 Email**（只读侧 username_value 的 Email fallback 不变）。
    #[test]
    fn apply_username_does_not_touch_email_field() {
        let mut d = ItemDraft {
            title: "X".to_string(),
            category: ItemCategory::Login,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "email".to_string(),
                value: Some("a@b.com".to_string()),
                field_type: FieldType::Email,
                designation: Some(Designation::Email),
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        apply_username_field(&mut d, "alice");
        let email = d
            .fields
            .iter()
            .find(|f| f.designation == Some(Designation::Email))
            .expect("Email 字段仍在");
        assert_eq!(email.value.as_deref(), Some("a@b.com"), "Email 值不动");
        let u = d
            .fields
            .iter()
            .find(|f| f.designation == Some(Designation::Username))
            .expect("新建 Username 字段");
        assert_eq!(u.value.as_deref(), Some("alice"));
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
            "cf-mcp-setpw-{tag}-{}-{nanos}",
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

    /// 建一个带密码字段的 Login 条目，返回其 uuid。
    fn create_login_item(session: &VaultSession, title: &str) -> String {
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

    /// 建一个环境容器条目（SecureNote + coffer:environment 标签）。
    fn create_env_item(session: &VaultSession, title: &str) -> String {
        let d = ItemDraft {
            title: title.to_string(),
            category: ItemCategory::SecureNote,
            urls: Vec::new(),
            tags: vec!["coffer:environment".to_string()],
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "NAME".to_string(),
                value: Some("API_KEY".to_string()),
                field_type: FieldType::Text,
                designation: None,
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        session.create_item(&d).expect("create env item")
    }

    #[test]
    fn resolve_by_name_exact_match() {
        let (dir, pw) = fast_vault("resolve-name");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_login_item(&s, "GitHub");
        let d = resolve_by_name(&s, "GitHub").expect("exact match");
        assert_eq!(d.uuid, uuid);
        assert_eq!(d.title.expose(), "GitHub");
    }

    #[test]
    fn resolve_by_name_not_found() {
        let (dir, pw) = fast_vault("resolve-notfound");
        let s = unlocked_vault(&dir, &pw);
        let err = resolve_by_name(&s, "Nope").expect_err("not found");
        assert!(matches!(err, SetPasswordError::ItemNotFound(n) if n == "Nope"));
    }

    #[test]
    fn resolve_by_name_ambiguous() {
        let (dir, pw) = fast_vault("resolve-ambiguous");
        let s = unlocked_vault(&dir, &pw);
        create_login_item(&s, "GitHub");
        create_login_item(&s, "GitHub");
        let err = resolve_by_name(&s, "GitHub").expect_err("ambiguous");
        assert!(matches!(
            err,
            SetPasswordError::Ambiguous { name, count } if name == "GitHub" && count == 2
        ));
    }

    #[test]
    fn resolve_by_id_exact() {
        let (dir, pw) = fast_vault("resolve-id");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_login_item(&s, "GitHub");
        let d = resolve_by_id(&s, &uuid).expect("by id");
        assert_eq!(d.uuid, uuid);
    }

    #[test]
    fn resolve_by_id_not_found() {
        let (dir, pw) = fast_vault("resolve-id-notfound");
        let s = unlocked_vault(&dir, &pw);
        let err = resolve_by_id(&s, "1b4e28ba-2fa1-11d2-883f-0016d3cca427").expect_err("unknown id");
        assert!(matches!(err, SetPasswordError::ItemNotFound(_)));
    }

    #[test]
    fn resolve_rejects_env_container() {
        let (dir, pw) = fast_vault("resolve-env");
        let s = unlocked_vault(&dir, &pw);
        let uuid = create_env_item(&s, "GitHubEnv");
        let err = resolve_by_id(&s, &uuid).expect_err("env container rejected");
        assert!(matches!(err, SetPasswordError::EnvContainer(_)));
    }

    // ------------------------------------------------ 退出码映射（docs/34 §5.2 + r0.4 定稿）

    #[test]
    fn exit_codes_distinct_per_category() {
        // lead 裁定 2026-10-09：一次性写命令专用映射，各类别不混为一码，脚本可区分。
        let usage = vec![
            SetPasswordError::UnknownFlag("--nope".to_string()),
            SetPasswordError::MissingValue("--id".to_string()),
            SetPasswordError::UnexpectedPositional("x".to_string()),
            SetPasswordError::ConflictingLocators,
            SetPasswordError::MissingTarget,
            SetPasswordError::InvalidId("not-a-uuid".to_string()),
            SetPasswordError::EmptyPassword,
            SetPasswordError::EmptyUsername,
        ];
        for e in usage {
            assert_eq!(e.exit_code(), exit_codes::USAGE_ERROR, "{e:?} → 4");
        }

        let entry = vec![
            SetPasswordError::ItemNotFound("NoSuch".to_string()),
            SetPasswordError::Ambiguous {
                name: "GitHub".to_string(),
                count: 2,
            },
            SetPasswordError::EnvContainer("env".to_string()),
            SetPasswordError::NoPasswordField("NoPw".to_string()),
        ];
        for e in entry {
            assert_eq!(e.exit_code(), exit_codes::TARGET_NOT_FOUND, "{e:?} → 2");
        }

        assert_eq!(
            SetPasswordError::WeakPassword.exit_code(),
            exit_codes::WEAK_PASSWORD,
            "强度不足 → 3"
        );
        // L-4（lead 审查 2026-10-10）：读密失败（IO 层面，非空密码语义）归解锁/
        // 操作失败类别 → 1；空密码（用户输入语义）仍归用法 → 4（上面 usage 组）。
        for e in [
            SetPasswordError::ReadPassword(std::io::Error::other("io")),
            SetPasswordError::Storage,
        ] {
            assert_eq!(e.exit_code(), exit_codes::UNLOCK_FAILED, "{e:?} → 1");
        }
    }

    #[test]
    fn parse_rejects_malformed_id_uuid() {
        let args = ["--id", "not-a-uuid"].map(String::from);
        let err = parse_args(&args).expect_err("malformed id rejected");
        assert!(matches!(
            &err,
            SetPasswordError::InvalidId(v) if v == "not-a-uuid"
        ));
        assert_eq!(err.exit_code(), exit_codes::USAGE_ERROR, "格式错 → 4");
    }

    // ------------------------------------------------ escrow 注入（tester gap 2，
    // AC-18.2-11/-13：托管成功 / fail-closed 分支经 run_with 注入 mock escrow）

    /// 在测试库上启用 MCP 托管（解锁态 derive → enable），返回 mcp_key 字节副本
    /// （供 mock escrow 注入）。session 在返回前 drop（库留在磁盘）。
    fn escrow_enable(vault_dir: &std::path::Path, password: &str) -> [u8; 32] {
        let session = open_vault(vault_dir).expect("open vault");
        session.unlock(password).expect("unlock vault");
        let mcp_key = session.derive_mcp_key(password).expect("derive mcp_key");
        session
            .enable_mcp_escrow(password, mcp_key.as_bytes())
            .expect("enable escrow");
        *mcp_key.as_bytes()
    }

    /// mock escrow（trait 注入，docs/30 §1.3）：可编程结果 + 记录调用 uuid。
    struct MockEscrow {
        result: std::sync::Mutex<Result<Option<[u8; 32]>, EscrowError>>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl MockEscrow {
        fn new(result: Result<Option<[u8; 32]>, EscrowError>) -> Self {
            Self {
                result: std::sync::Mutex::new(result),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn called_with(&self) -> Vec<String> {
            self.calls.lock().expect("mock calls lock").clone()
        }
    }

    impl VaultEscrowStore for MockEscrow {
        fn read_mcp_key(&self, vault_uuid: &str) -> Result<Option<[u8; 32]>, EscrowError> {
            self.calls
                .lock()
                .expect("mock calls lock")
                .push(vault_uuid.to_string());
            self.result.lock().expect("mock result lock").clone()
        }
    }

    /// 用测试密码解锁后按 uuid 取条目 Password 字段现值（断言更新/未变用）。
    fn password_field_value(vault_dir: &std::path::Path, password: &str, item_id: &str) -> String {
        let s = unlocked_vault(vault_dir, password);
        let item = s
            .get_item(item_id)
            .expect("get item")
            .expect("item present");
        item.fields
            .iter()
            .find(|f| f.designation == Some(Designation::Password))
            .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
            .expect("password field present")
    }

    /// 托管成功：正确 mcp_key → 退出 0 + 密码字段更新；`read_mcp_key` 以
    /// vault_uuid 定位。
    #[test]
    fn escrow_correct_key_updates_item() {
        let (dir, pw) = fast_vault("escrow-ok");
        let vault_uuid = dir
            .file_name()
            .expect("dir basename")
            .to_string_lossy()
            .to_string();
        let session = unlocked_vault(&dir, &pw);
        let item_id = create_login_item(&session, "GitHub");
        drop(session);
        let key = escrow_enable(&dir, &pw);

        let escrow = MockEscrow::new(Ok(Some(key)));
        let mut stdin = std::io::Cursor::new(b"Correct-Horse-Battery-Staple-2026!".to_vec());
        let code = run_with(
            &mut stdin,
            false,
            &SetPasswordOptions {
                name: Some("GitHub".to_string()),
                id: None,
                force: false,
                username: None,
            },
            &dir,
            None,
            &escrow,
        );
        assert_eq!(code, exit_codes::SUCCESS, "托管解锁成功 → 0");
        assert_eq!(password_field_value(&dir, &pw, &item_id), "Correct-Horse-Battery-Staple-2026!");
        assert_eq!(escrow.called_with(), vec![vault_uuid], "以 vault_uuid 定位");
    }

    /// 托管失败 fail-closed：错误 32B key → 退出 1，**不回落 env**（即使给了
    /// 正确 env 密码），库不动（AC-18.2-13）。
    #[test]
    fn escrow_wrong_key_fails_closed_ignores_env() {
        let (dir, pw) = fast_vault("escrow-wrong");
        let session = unlocked_vault(&dir, &pw);
        let item_id = create_login_item(&session, "GitHub");
        drop(session);
        escrow_enable(&dir, &pw);

        let wrong = [7u8; 32];
        let escrow = MockEscrow::new(Ok(Some(wrong)));
        let mut stdin = std::io::Cursor::new(b"Correct-Horse-Battery-Staple-2026!".to_vec());
        let code = run_with(
            &mut stdin,
            false,
            &SetPasswordOptions {
                name: Some("GitHub".to_string()),
                id: None,
                force: false,
                username: None,
            },
            &dir,
            Some(SecretString::from_exposed(pw.clone())), // 正确 env，须被忽略
            &escrow,
        );
        assert_eq!(code, exit_codes::UNLOCK_FAILED, "escrow 解锁失败 → fail-closed 1");
        assert_eq!(
            password_field_value(&dir, &pw, &item_id),
            "old-secret",
            "fail-closed 不写库"
        );
    }

    /// 托管读取错误 fail-closed：`read_mcp_key` 返回 Err → 退出 1，不回落 env，
    /// 库不动。
    #[test]
    fn escrow_read_error_fails_closed_ignores_env() {
        let (dir, pw) = fast_vault("escrow-readerr");
        let session = unlocked_vault(&dir, &pw);
        let item_id = create_login_item(&session, "GitHub");
        drop(session);
        escrow_enable(&dir, &pw);

        let escrow = MockEscrow::new(Err(EscrowError::access_denied("测试 ACL 拒绝")));
        let mut stdin = std::io::Cursor::new(b"Correct-Horse-Battery-Staple-2026!".to_vec());
        let code = run_with(
            &mut stdin,
            false,
            &SetPasswordOptions {
                name: Some("GitHub".to_string()),
                id: None,
                force: false,
                username: None,
            },
            &dir,
            Some(SecretString::from_exposed(pw.clone())), // 正确 env，须被忽略
            &escrow,
        );
        assert_eq!(code, exit_codes::UNLOCK_FAILED, "escrow 读取失败 → fail-closed 1");
        assert_eq!(
            password_field_value(&dir, &pw, &item_id),
            "old-secret",
            "fail-closed 不写库"
        );
    }

    // ------------------------------------------------ v2.5.2 一对写库级集成（AC-18.2-17/-18）

    fn username_field_value(vault_dir: &std::path::Path, password: &str, item_id: &str) -> Option<String> {
        let s = unlocked_vault(vault_dir, password);
        let item = s
            .get_item(item_id)
            .expect("get item")
            .expect("item present");
        item.fields
            .iter()
            .find(|f| f.designation == Some(Designation::Username))
            .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
    }

    /// AC-18.2-17：给 `--user` → 用户名+密码一对写（既有 Username 字段更新）。
    #[test]
    fn apply_update_writes_username_and_password_pair() {
        let (dir, pw) = fast_vault("pair-write");
        let session = unlocked_vault(&dir, &pw);
        let item_id = create_login_item(&session, "GitHub"); // octocat / old-secret
        let item = session.get_item(&item_id).expect("get").expect("present");
        apply_update(&session, &item, "new-secret-2026!", Some("newuser")).expect("pair update");
        drop(session);

        assert_eq!(
            password_field_value(&dir, &pw, &item_id),
            "new-secret-2026!",
            "密码字段已更新"
        );
        assert_eq!(
            username_field_value(&dir, &pw, &item_id).as_deref(),
            Some("newuser"),
            "Username 字段已更新"
        );
    }

    /// AC-18.2-17：条目无 Username 字段时给 `--user` → 新建并写入。
    /// （用 `ItemCategory::Password`：模板中 username 非必填、password 必填——
    /// Login 的 username 是硬约束无法构造无用户名的 Login 条目，见 validate.rs。）
    #[test]
    fn apply_update_creates_username_field_when_missing() {
        let (dir, pw) = fast_vault("pair-create-user");
        let session = unlocked_vault(&dir, &pw);
        // 仅密码字段的 Password 条目（无 Username designation）。
        let mut d = ItemDraft {
            title: "GitHub".to_string(),
            category: ItemCategory::Password,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![FieldDraft {
                name: "password".to_string(),
                value: Some("old-secret".to_string()),
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                section_index: None,
                position: 0,
            }],
            totp: None,
        };
        let item_id = session.create_item(&d).expect("create item");
        let item = session.get_item(&item_id).expect("get").expect("present");
        d.fields.clear(); // drop 明文副本
        apply_update(&session, &item, "new-secret-2026!", Some("alice")).expect("create username");
        drop(session);

        assert_eq!(password_field_value(&dir, &pw, &item_id), "new-secret-2026!");
        assert_eq!(
            username_field_value(&dir, &pw, &item_id).as_deref(),
            Some("alice"),
            "无 Username 字段 → 新建并写入"
        );
    }

    /// AC-18.2-18：未给 `--user` → 只写密码，Username 字段逐字不动。
    #[test]
    fn apply_update_without_user_keeps_username() {
        let (dir, pw) = fast_vault("pair-no-user");
        let session = unlocked_vault(&dir, &pw);
        let item_id = create_login_item(&session, "GitHub"); // octocat
        let item = session.get_item(&item_id).expect("get").expect("present");
        apply_update(&session, &item, "new-secret-2026!", None).expect("password only");
        drop(session);

        assert_eq!(password_field_value(&dir, &pw, &item_id), "new-secret-2026!");
        assert_eq!(
            username_field_value(&dir, &pw, &item_id).as_deref(),
            Some("octocat"),
            "未给 --user → 用户名不动"
        );
    }
