//! `coffer set-env` CLI 集成测试（docs/36 §4，AC-36.1）——**Pro 专属测试文件**。
//!
//! 隔离轮（2026-10-11）：环境容器写面为 Pro 专属功能，本文件整文件
//! `#![cfg(feature = "pro")]` 门控（免费仓不编译也不存在本文件），与
//! `cli.rs`（免费/Pro 共有）分文件防漂移；共享夹具见 `common/mod.rs`。

#![cfg(all(feature = "coffer-store", feature = "pro"))]

mod common;
use common::*;

use std::io::Write;

use std::process::{Command, Stdio};

// ------------------------------------------------------------ set-env（docs/36 §4，AC-36.1）

/// 环境容器保留标签（docs/36 §2.1 / provider/coffer.rs:63 同源）。
#[cfg(feature = "coffer-store")]
const ENV_TAG: &str = "coffer:environment";

/// 建一个环境容器条目（SecureNote + `coffer:environment` 标签 + NAME/VALUE 字段对；
/// 字段形态固定 = `FieldType::Text` + designation None，docs/36 §4.3）。
#[cfg(feature = "coffer-store")]
fn create_env_container_in(
    session: &cf_session::VaultSession,
    owner: &str,
    pairs: &[(&str, &str)],
) -> String {
    use cf_domain::category::ItemCategory;
    use cf_domain::field::FieldType;
    use cf_domain::item::{FieldDraft, ItemDraft};
    let fields = pairs
        .iter()
        .enumerate()
        .map(|(i, (name, value))| FieldDraft {
            name: name.to_string(),
            value: Some(value.to_string()),
            field_type: FieldType::Text,
            designation: None,
            section_index: None,
            position: i as i32,
        })
        .collect();
    let d = ItemDraft {
        title: owner.to_string(),
        category: ItemCategory::SecureNote,
        urls: Vec::new(),
        tags: vec![ENV_TAG.to_string()],
        sections: Vec::new(),
        fields,
        totp: None,
    };
    session.create_item(&d).expect("create env container")
}

/// 重新开库解锁，按标题查环境容器（SecureNote + ENV_TAG）；None = 无。
#[cfg(feature = "coffer-store")]
fn find_env_container(
    vault_dir: &std::path::Path,
    password: &str,
    owner: &str,
) -> Option<cf_session::types::ItemDetails> {
    use cf_domain::category::ItemCategory;
    let s = cf_session::open_vault(vault_dir).expect("reopen vault");
    s.unlock(password).expect("unlock vault");
    for sum in s.list_items(None).expect("list items") {
        if sum.title != owner {
            continue;
        }
        let d = s
            .get_item(&sum.uuid.to_string())
            .expect("get item")
            .expect("item exists");
        if d.category == ItemCategory::SecureNote && d.tags.iter().any(|t| t.expose() == ENV_TAG) {
            return Some(d);
        }
    }
    None
}

/// 读条目中指定 NAME 字段的值（None = 无该字段）。
#[cfg(feature = "coffer-store")]
fn env_field_value(d: &cf_session::types::ItemDetails, name: &str) -> Option<String> {
    d.fields
        .iter()
        .find(|f| f.name.expose() == name)
        .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
}

/// 重新开库解锁并读条目（按 id）。
#[cfg(feature = "coffer-store")]
fn reopen_item(
    vault_dir: &std::path::Path,
    password: &str,
    id: &str,
) -> cf_session::types::ItemDetails {
    let s = cf_session::open_vault(vault_dir).expect("reopen vault");
    s.unlock(password).expect("unlock vault");
    s.get_item(id).expect("get item").expect("item exists")
}

/// AC-36.1-1：写入更新成功——`set-env --scope <存在容器> NAME=VALUE` → 退出 0；
/// 目标字段更新、其它字段/标签/类别逐项不变；历史 append 一条（含旧值可回滚）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_update_existing_container_field_and_preserves_others() {
    use cf_domain::field::FieldType;
    let (vault_dir, pw, s) = fast_vault_setup("setenv-update");
    let id = create_env_container_in(&s, "prod", &[("API_KEY", "old-key"), ("LOG_LEVEL", "debug")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "API_KEY=new-key"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "更新成功 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("prod"), "成功消息带容器名，stdout: {stdout}");
    assert!(stdout.contains("环境容器"), "成功消息带容器标记，stdout: {stdout}");
    assert!(!stdout.contains("new-key"), "stdout 不得含新 VALUE，stdout: {stdout}");
    assert!(!stderr.contains("new-key"), "stderr 不得含新 VALUE，stderr: {stderr}");

    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("new-key"), "目标字段已更新");
    assert_eq!(
        env_field_value(&d, "LOG_LEVEL").as_deref(),
        Some("debug"),
        "其它字段不变"
    );
    assert_eq!(d.fields.len(), 2, "只动目标字段，不增删字段");
    assert_eq!(
        d.category,
        cf_domain::category::ItemCategory::SecureNote,
        "类别不变"
    );
    assert!(d.tags.iter().any(|t| t.expose() == ENV_TAG), "coffer:environment 标签不变");
    // 命中既有字段不改 field_type / designation（docs/36 §4.3）。
    let target = d
        .fields
        .iter()
        .find(|f| f.name.expose() == "API_KEY")
        .expect("API_KEY field");
    assert_eq!(target.field_type, FieldType::Text, "命中字段不改 field_type");
    assert_eq!(target.designation, None, "命中字段不改 designation");
    // 历史 append 一条（FR-2.9）。
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    assert_eq!(
        s.list_history(&id).expect("list history").len(),
        1,
        "更新须 append 一条历史"
    );
}

/// AC-36.1-2：首写自动建容器——`set-env --scope <不存在>` → 退出 0 + 新建
/// SecureNote + `coffer:environment` 标签 + NAME 字段。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_first_write_auto_creates_container() {
    use cf_domain::category::ItemCategory;
    let (vault_dir, pw, s) = fast_vault_setup("setenv-autocreate");
    drop(s); // 库为空，无 "staging" 容器

    let out = run_coffer(
        &["set-env", "--scope", "staging", "STAGE_FLAG=on"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "首写自动建容器 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("staging"), "成功消息带容器名，stdout: {stdout}");

    let d = find_env_container(&vault_dir, &pw, "staging")
        .expect("首写须自动建环境容器（SecureNote + coffer:environment）");
    assert_eq!(d.category, ItemCategory::SecureNote, "新建条目须为 SecureNote");
    assert!(d.tags.iter().any(|t| t.expose() == ENV_TAG), "须带 coffer:environment 标签");
    assert_eq!(env_field_value(&d, "STAGE_FLAG").as_deref(), Some("on"), "NAME 字段已写入");
}

/// AC-36.1-3：同名非容器拒绝——存在同名普通条目 → 退出 2 + 不建不写
/// （标题撞车防混淆，D-36.2 硬约束）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_scope_matches_non_container_exits_2_no_write() {
    use cf_domain::category::ItemCategory;
    let (vault_dir, pw, s) = fast_vault_setup("setenv-noncont");
    let id = create_login_item_in(&s, "conflict"); // Login，非环境容器
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "conflict", "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "同名非容器 → 退出码 2，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("不是环境容器")
            || stderr.contains("not an environment container")
            || stderr.contains("环境容器"),
        "错误须说明非环境容器（中文/英文均可），stderr: {stderr}"
    );
    // 不建不写：Login 条目仍在且未改；无新建 SecureNote。
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id).as_deref(),
        Some("old-secret"),
        "非容器条目不得被写"
    );
    assert!(
        find_env_container(&vault_dir, &pw, "conflict").is_none(),
        "不得自动建容器（标题撞车防混淆）"
    );
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    let items = s.list_items(None).expect("list items");
    assert_eq!(items.len(), 1, "不得新增条目");
    assert_eq!(items[0].category, ItemCategory::Login, "原条目类别不变");
}

/// AC-36.1-4：歧义——同名多容器 → 退出 2 + 提示 `--id`，任一匹配容器不写。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_ambiguous_scope_exits_2_hints_id() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-amb");
    let id1 = create_env_container_in(&s, "dup", &[("A", "1")]);
    let id2 = create_env_container_in(&s, "dup", &[("B", "2")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "dup", "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "歧义 → 退出码 2，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("歧义") || stderr.contains("ambiguous"),
        "错误须说明歧义，stderr: {stderr}"
    );
    assert!(stderr.contains("--id"), "歧义须提示 --id，stderr: {stderr}");
    for id in [&id1, &id2] {
        let d = reopen_item(&vault_dir, &pw, id);
        assert!(env_field_value(&d, "FOO").is_none(), "歧义不得写 {id}");
    }
}

/// AC-36.1-5：`--id` 兜底——`--id <容器UUID>` 更新成功。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_by_id_updates_container() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-id");
    let id = create_env_container_in(&s, "target", &[("API_KEY", "old")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--id", &id, "API_KEY=new"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "--id 定位更新成功 → 退出码 0，out: {out:?}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("new"), "--id 更新落库");
}

/// AC-36.1-5：`--id` 命中非容器 → 退出 2，不写库。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_by_id_non_container_exits_2() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-id-noncont");
    let id = create_login_item_in(&s, "GitHub"); // Login，非环境容器
    drop(s);

    let out = run_coffer(
        &["set-env", "--id", &id, "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "--id 命中非容器 → 退出码 2，out: {out:?}");
    assert_eq!(
        item_password_value(&vault_dir, &pw, &id).as_deref(),
        Some("old-secret"),
        "非容器不得被写"
    );
}

/// AC-36.1-5：`--id` 未命中 → 退出 2（--id 无自动建语义）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_by_id_missing_exits_2() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-id-missing");
    drop(s);

    let out = run_coffer(
        &["set-env", "--id", "00000000-0000-4000-8000-000000000000", "FOO=bar"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(2), "--id 未命中 → 退出码 2，out: {out:?}");
    assert!(
        find_env_container(&vault_dir, &pw, "FOO").is_none(),
        "未命中不得自动建容器（--id 无自动建语义）"
    );
}

/// AC-36.1-7：`--unset` 删除字段 → 退出 0；历史 append 一条。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_unset_removes_field_and_appends_history() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-unset");
    let id = create_env_container_in(&s, "prod", &[("FOO", "v1"), ("BAR", "v2")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "--unset", "FOO"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "--unset 删除字段 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("prod"), "成功消息带容器名，stdout: {stdout}");

    let d = reopen_item(&vault_dir, &pw, &id);
    assert!(env_field_value(&d, "FOO").is_none(), "FOO 字段已删除");
    assert_eq!(env_field_value(&d, "BAR").as_deref(), Some("v2"), "其它字段保留");
    assert_eq!(d.fields.len(), 1, "仅删除目标字段");
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    assert_eq!(
        s.list_history(&id).expect("list history").len(),
        1,
        "删除须 append 一条历史"
    );
}

/// AC-36.1-7：删除不存在的 NAME = 幂等成功（退出 0，不增删字段；内容无变化不
/// append 历史——FR-2.9 update_item 内建语义）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_unset_missing_name_idempotent_success() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-unset-miss");
    let id = create_env_container_in(&s, "prod", &[("FOO", "v1")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "--unset", "NOPE"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "删除不存在的 NAME = 幂等成功，out: {out:?}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "FOO").as_deref(), Some("v1"), "既有字段不变");
    assert_eq!(d.fields.len(), 1, "不增删字段");
    // 幂等语义（docs/36 §4.3「删除缺失的 NAME = 幂等成功」+ §3「内容无变化
    // 不写」）：draft 无内容变化 → 不 update、不 append 历史。
    let s = cf_session::open_vault(&vault_dir).expect("reopen vault");
    s.unlock(&pw).expect("unlock vault");
    assert_eq!(
        s.list_history(&id).expect("list history").len(),
        0,
        "幂等删除（无内容变化）不得 append 历史"
    );
}

/// AC-36.1-13（spawn 可测分支）：无托管（快速库未启用 escrow）+ $COFFER_VAULT_PASSWORD
/// → env 兜底解锁成功（source="env-fallback"），写入落库。
///
/// 注：escrow「启用→托管解锁成功」与「存在但解锁失败→退出 1 不回落 env」两分支须
/// MockEscrow 注入，跨 spawn 边界不可行（子进程用平台真实 Keychain，无签名身份），
/// 由 P1 的 set_env_tests.rs in-process 单测覆盖（复用 cli::unlock_vault，与 cli.rs
/// 内测同面）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_no_escrow_env_fallback_success() {
    let (vault_dir, pw, s) = fast_vault_setup("setenv-envfb");
    let id = create_env_container_in(&s, "prod", &[("API_KEY", "old")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "API_KEY=new"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "无托管 + env → env 兜底成功，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("env-fallback"), "须日志 env 兜底线索，stderr: {stderr}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("new"));
}

/// AC-36.1-13（spawn 可测分支）：无托管无 env → fail-closed 退出 1（消息提示
/// $COFFER_VAULT_PASSWORD），不写库。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_no_escrow_no_env_fail_closed_exit_1() {
    let (vault_dir, _pw, s) = fast_vault_setup("setenv-nounlock");
    let id = create_env_container_in(&s, "prod", &[("API_KEY", "old")]);
    drop(s);

    let out = run_coffer(
        &["set-env", "--scope", "prod", "API_KEY=new"],
        &[("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path"))],
    );
    assert_eq!(out.status.code(), Some(1), "escrow+env 均无 → fail-closed 退出 1，out: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("COFFER_VAULT_PASSWORD"),
        "错误须指明解锁途径缺失，stderr: {stderr}"
    );
    let d = reopen_item(&vault_dir, &_pw, &id);
    assert_eq!(env_field_value(&d, "API_KEY").as_deref(), Some("old"), "fail-closed 不得写库");
}

/// AC-36.1-14：并发写原子性（镜像 set-password 并发口径，docs/36 §6 判据）——
/// 两进程并发 `set-env` 同容器同 NAME：每个写者退出 0 或干净失败 1、至少一个成功、
/// 库可重开解锁、容器字段健康、最终值取成功写者之一（无损坏）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_concurrent_writers_no_corruption() {
    const VAL_A: &str = "value-alpha-2026";
    const VAL_B: &str = "value-bravo-2026";
    let (vault_dir, pw, s) = fast_vault_setup("setenv-conc");
    let id = create_env_container_in(&s, "conc", &[("SHARED", "v0")]);
    drop(s);

    let vd_a = vault_dir.to_str().expect("utf8 path").to_string();
    let vd_b = vd_a.clone();
    let env_a = pw.clone();
    let env_b = pw.clone();
    let h_a = std::thread::spawn(move || {
        let pair = format!("SHARED={VAL_A}");
        run_coffer(
            &["set-env", "--scope", "conc", pair.as_str()],
            &[("COFFER_VAULT_DIR", &vd_a), ("COFFER_VAULT_PASSWORD", &env_a)],
        )
    });
    let h_b = std::thread::spawn(move || {
        let pair = format!("SHARED={VAL_B}");
        run_coffer(
            &["set-env", "--scope", "conc", pair.as_str()],
            &[("COFFER_VAULT_DIR", &vd_b), ("COFFER_VAULT_PASSWORD", &env_b)],
        )
    });
    let out_a = h_a.join().expect("thread a");
    let out_b = h_b.join().expect("thread b");
    let mut successes = 0;
    for (i, out) in [&out_a, &out_b].iter().enumerate() {
        let code = out.status.code();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            code == Some(0) || code == Some(1),
            "并发写者 {i} 须成功(0)或干净失败(1)，code: {code:?}, stderr: {stderr}"
        );
        if code == Some(0) {
            successes += 1;
        } else {
            assert!(
                stderr.contains("未写入"),
                "失败写者 {i} 须报未写入（干净失败），stderr: {stderr}"
            );
        }
    }
    assert!(successes >= 1, "两并发写者至少一个成功");

    let s = cf_session::open_vault(&vault_dir).expect("reopen vault after concurrent writes");
    s.unlock(&pw).expect("unlock vault");
    let d = s.get_item(&id).expect("get item").expect("item exists");
    let v = env_field_value(&d, "SHARED");
    assert!(
        v.as_deref() == Some(VAL_A) || v.as_deref() == Some(VAL_B),
        "最终 SHARED 须为成功写者之一（库未损坏），实际: {v:?}"
    );
    assert_eq!(d.fields.len(), 1, "容器字段健康（无重复/半写）");
}

/// AC-36.1-11：值不进 argv/日志——裸 NAME 形态下值走 stdin，`ps` 进程列表 argv
/// 不含 VALUE；喂值后成功，stdout/stderr 亦不得泄露明文（内联形态是显式知情
/// 逃生口，本判据仅断言裸 NAME 形态）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_bare_name_value_not_in_argv_stdout_stderr() {
    const SECRET: &str = "ps-secret-VALUE-7f3a9c-x1";
    let (vault_dir, pw, s) = fast_vault_setup("setenv-ps");
    let id = create_env_container_in(&s, "psenv", &[("EXISTING", "keep")]);
    drop(s);

    let mut cmd = Command::new(coffer_bin());
    cmd.args(["set-env", "--scope", "psenv", "API_TOKEN"])
        .env("COFFER_OP_BIN", fake_op())
        .env("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path"))
        .env("COFFER_VAULT_PASSWORD", &pw)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn coffer binary");
    let pid = child.id();

    // 裸 NAME 形态：值走 stdin，子进程阻塞读 stdin 时 argv 已定型且绝不含值。
    let mut ps_line: Option<String> = None;
    for _ in 0..40 {
        let out = Command::new("ps")
            .args(["-o", "args=", "-p", &pid.to_string()])
            .output()
            .expect("run ps");
        if out.status.success() {
            ps_line = Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let ps_line = ps_line.expect("child process visible to ps");
    assert!(ps_line.contains("set-env"), "argv 含子命令，ps: {ps_line}");
    assert!(ps_line.contains("API_TOKEN"), "argv 含裸 NAME（NAME 非值），ps: {ps_line}");
    assert!(!ps_line.contains(SECRET), "argv 不得含 VALUE（进程列表可见性），ps: {ps_line}");

    // 喂值 → 更新成功；stdout / stderr 亦不得泄露明文。
    {
        let mut si = child.stdin.take().expect("stdin pipe");
        si.write_all(format!("{SECRET}\n").as_bytes())
            .expect("write secret");
    }
    let out = child.wait_with_output().expect("collect output");
    assert_eq!(out.status.code(), Some(0), "喂值后更新成功 → 退出码 0，out: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(SECRET), "stdout 不得含明文，stdout: {stdout}");
    assert!(!stderr.contains(SECRET), "stderr 不得含明文，stderr: {stderr}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "API_TOKEN").as_deref(), Some(SECRET), "stdin 值落库");
    assert_eq!(env_field_value(&d, "EXISTING").as_deref(), Some("keep"), "其它字段不变");
}

/// AC-36.1-12（退出码纪律，退出 4 面）：缺 `--scope` / `--scope`+`--id` 并存 /
/// `--unset` 与对并存 / 非法 NAME → 用法错误退出 4，parse 阶段即可判定
/// （无需库配置），不写库（docs/36 §4.1 / §4.5）。
#[cfg(feature = "coffer-store")]
#[test]
fn set_env_usage_errors_exit_4() {
    let out = run_coffer(&["set-env", "FOO=bar"], &[]);
    assert_eq!(out.status.code(), Some(4), "缺 --scope → 退出码 4，out: {out:?}");

    let out = run_coffer(
        &["set-env", "--scope", "a", "--id", "00000000-0000-4000-8000-000000000000", "FOO=bar"],
        &[],
    );
    assert_eq!(out.status.code(), Some(4), "--scope+--id 并存 → 退出码 4，out: {out:?}");

    let out = run_coffer(&["set-env", "--scope", "a", "--unset", "FOO", "BAR=baz"], &[]);
    assert_eq!(out.status.code(), Some(4), "--unset 与对并存 → 退出码 4，out: {out:?}");

    // 非法 NAME（含 `-`）→ 退出 4 不写库（需库配置以验证「不写」）。
    let (vault_dir, pw, s) = fast_vault_setup("setenv-badname");
    let id = create_env_container_in(&s, "prod", &[("GOOD", "keep")]);
    drop(s);
    let out = run_coffer(
        &["set-env", "--scope", "prod", "BAD-NAME=x"],
        &[
            ("COFFER_VAULT_DIR", vault_dir.to_str().expect("utf8 path")),
            ("COFFER_VAULT_PASSWORD", &pw),
        ],
    );
    assert_eq!(out.status.code(), Some(4), "非法 NAME → 退出码 4，out: {out:?}");
    let d = reopen_item(&vault_dir, &pw, &id);
    assert_eq!(env_field_value(&d, "GOOD").as_deref(), Some("keep"), "用法错误不写库");
    assert!(env_field_value(&d, "BAD-NAME").is_none(), "非法 NAME 字段未写入");
}
