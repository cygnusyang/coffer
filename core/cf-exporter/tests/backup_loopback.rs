//! FR-8.1 / FR-8.6 集成测试：加密备份的导出、结构校验与恢复回环。
//!
//! 验收对齐：docs/01 §8.1 AC-06（导出加密备份 → 删除库 → 恢复 →
//! 数据完全一致）与 docs/09 §3.1 测试要点 1–3、6。
//!
//! 解锁模拟按 docs/03 §2.6/§2.7 的既定参数直接使用 cf-crypto +
//! cf-store（不经 cf-session，该 crate 由并行组 G3 开发中）。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::Read as _;

use cf_domain::item::ItemState;
use cf_exporter::{export_backup, restore_backup, verify_backup};
use cf_format::OpenOutcome;
use zip::ZipArchive;

mod support;

use support::{
    build_vault, remove_dir_all_quiet, temp_dir, unlock_store, PASSWORD, VERIFIER_PLAINTEXT,
    WRONG_PASSWORD,
};

/// 读出 .coffer 包内全部条目名与字节。
fn zip_entries(path: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let file = fs::File::open(path).expect("打开备份成功");
    let mut archive = ZipArchive::new(file).expect("解析 ZIP 成功");
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("读条目成功");
        assert!(!entry.is_dir(), "夹具只写文件条目");
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).expect("读条目内容成功");
        out.push((entry.name().to_owned(), buf));
    }
    out
}

/// 用既有条目重打包 ZIP：
/// - `skip` 中的条目名被剔除（模拟删除 db.sqlite 等）；
/// - `replace` 中的 (条目名, 字节) 被替换（模拟篡改 header / 换入垃圾 db）；
/// - 其余条目照抄原字节。
fn repack(
    dest: &std::path::Path,
    entries: &[(String, Vec<u8>)],
    skip: &[&str],
    replace: &[(&str, &[u8])],
) {
    let file = fs::File::create(dest).expect("建文件成功");
    let mut zip = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    use std::io::Write as _;
    for (name, bytes) in entries {
        if skip.contains(&name.as_str()) {
            continue;
        }
        let payload = replace
            .iter()
            .find(|(n, _)| *n == name.as_str())
            .map(|(_, b)| b.to_vec())
            .unwrap_or_else(|| bytes.clone());
        zip.start_file(name.as_str(), opts).expect("写条目成功");
        zip.write_all(&payload).expect("写内容成功");
    }
    zip.finish().expect("收尾成功");
}

/// TC-EXP-01 全量回环：建库（Login 含 TOTP/标签/多 URL、SecureNote、
/// CreditCard、归档条目）→ export → 删除工作目录 → restore → 解锁 →
/// 逐条目逐字段比对完全相等（含 Concealed 值、TOTP secret、标签、
/// 多 URL、归档状态）。
#[test]
fn tc_exp_01_loopback_full_restore_unlock_match() {
    let base = temp_dir("loopback");
    let (vault_dir, vault_uuid) = build_vault(&base);
    let out_path = base.join("我的密码库.coffer");

    // 持一个未关闭的连接制造 -wal 文件，一并验证排除逻辑（TC-EXP-03）
    let wal_conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).expect("重开连接成功");
    wal_conn
        .execute_batch("INSERT INTO audit_local (ts, event) VALUES (0, 'trigger-wal');")
        .expect("制造 WAL 写入成功");

    let result = export_backup(&vault_dir, &out_path).expect("导出成功");
    assert!(result.verified, "导出后自动结构校验应通过（FR-8.6）");
    assert_eq!(result.file_path, out_path);
    assert!(result.size_bytes > 0);
    assert!(out_path.is_file());

    // ---- 模拟灾难：删除工作目录 ----
    drop(wal_conn);
    remove_dir_all_quiet(&vault_dir);
    assert!(!vault_dir.exists());

    // ---- 恢复 + 解锁（正确主密码） ----
    let target_base = temp_dir("restore");
    let restored = restore_backup(&out_path, &target_base).expect("恢复成功");
    assert_eq!(restored, target_base.join(&vault_uuid));
    let (header, store) = unlock_store(&restored, PASSWORD).expect("主密码解锁成功");
    assert_eq!(header.vault_uuid, vault_uuid);

    // ---- 逐条目逐字段比对 ----
    let repos = store.repos();
    let items = repos
        .items
        .list(&cf_store::ItemListFilter::default())
        .expect("列条目成功");
    assert_eq!(items.len(), 6, "六类条目全部恢复（含回收站条目）");

    // Login：全字段
    let gh = items
        .iter()
        .find(|i| i.title.expose() == "GitHub 登录")
        .expect("GitHub 登录应恢复");
    assert_eq!(gh.row.category, cf_domain::category::ItemCategory::Login);
    assert_eq!(gh.row.state, ItemState::Active);
    assert!(gh.row.is_favorite);
    let fields = repos
        .fields
        .read_fields_for_item(&gh.row.uuid)
        .expect("读字段成功");
    let get_field = |des: &cf_domain::field::Designation| {
        fields
            .iter()
            .find(|f| f.designation.as_ref() == Some(des))
            .and_then(|f| f.value.as_ref().map(|v| v.expose().to_owned()))
            .unwrap_or_default()
    };
    assert_eq!(
        get_field(&cf_domain::field::Designation::Username),
        "octocat"
    );
    assert_eq!(
        get_field(&cf_domain::field::Designation::Password),
        "s3cret-明文密码!"
    );
    assert_eq!(
        get_field(&cf_domain::field::Designation::NotesPlain),
        "Main account\n第二行备注"
    );
    let urls = repos.urls.read_for_item(&gh.row.uuid).expect("读 URL 成功");
    assert_eq!(urls.len(), 2, "多 URL");
    assert_eq!(urls[0].url.expose(), "https://github.com");
    assert!(urls[0].is_primary);
    assert_eq!(urls[1].label.as_ref().map(|l| l.expose()), Some("管理后台"));
    let tags = repos.tags.read_for_item(&gh.row.uuid).expect("读标签成功");
    let mut tag_names: Vec<&str> = tags.iter().map(|t| t.name.expose()).collect();
    tag_names.sort();
    assert_eq!(tag_names, vec!["dev", "重要"]);

    // TOTP：元数据与共享密钥逐字节恢复（含 Concealed 语义的 secret）
    let totp_uuid = repos
        .totp
        .totp_uuids_for_item(&gh.row.uuid)
        .expect("列 TOTP 成功")
        .into_iter()
        .next()
        .expect("TOTP 记录应恢复");
    let meta = repos
        .totp
        .totp_meta(&totp_uuid)
        .expect("读 TOTP 成功")
        .expect("记录存在");
    assert_eq!(meta.algo, "sha1");
    assert_eq!(meta.digits, 6);
    assert_eq!(meta.period, 30);
    assert_eq!(meta.issuer.as_deref(), Some("GitHub"));
    assert_eq!(meta.account.as_deref(), Some("octocat"));
    let secret = repos
        .totp
        .totp_secret(&totp_uuid)
        .expect("读密钥成功")
        .expect("密钥存在");
    assert_eq!(
        secret.as_slice(),
        b"Hello!\xDE\xAD\xBE\xEF",
        "TOTP 共享密钥逐字节一致"
    );

    // SecureNote / CreditCard：类别与字段逐字段
    let note = items
        .iter()
        .find(|i| i.title.expose() == "服务器安全笔记")
        .expect("SecureNote 应恢复");
    assert_eq!(
        note.row.category,
        cf_domain::category::ItemCategory::SecureNote
    );
    let note_fields = repos
        .fields
        .read_fields_for_item(&note.row.uuid)
        .expect("读字段成功");
    assert_eq!(
        note_fields[0].value.as_ref().map(|v| v.expose()),
        Some("恢复短语：astral tungsten\n第二行")
    );
    let card = items
        .iter()
        .find(|i| i.title.expose() == "测试信用卡")
        .expect("CreditCard 应恢复");
    assert_eq!(
        card.row.category,
        cf_domain::category::ItemCategory::CreditCard
    );
    let card_fields = repos
        .fields
        .read_fields_for_item(&card.row.uuid)
        .expect("读字段成功");
    assert_eq!(
        card_fields[0].value.as_ref().map(|v| v.expose()),
        Some("4111 1111 1111 1111"),
        "Concealed 值逐字段相等"
    );

    // 归档 / 回收站状态一致
    let archived = items
        .iter()
        .find(|i| i.title.expose() == "归档的条目")
        .expect("归档条目应恢复");
    assert_eq!(archived.row.state, ItemState::Archived);
    let trashed = items
        .iter()
        .find(|i| i.title.expose() == "回收站条目")
        .expect("回收站条目应恢复");
    assert_eq!(trashed.row.state, ItemState::Trashed);

    drop(store);
    let _ = fs::remove_file(out_path);
    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}

/// TC-EXP-02 错误主密码：恢复后错误密码 unlock 失败（1002 语义）；
/// 原备份文件字节级不被修改。
#[test]
fn tc_exp_02_restore_wrong_password_rejected() {
    let base = temp_dir("wrong_pw");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");
    let backup_before = fs::read(&out_path).expect("读备份成功");

    let target_base = temp_dir("wrong_pw_target");
    let restored = restore_backup(&out_path, &target_base).expect("恢复成功");
    assert!(
        unlock_store(&restored, WRONG_PASSWORD).is_none(),
        "错误主密码不得解锁（FR-1.4：归一 1002 语义）"
    );

    let backup_after = fs::read(&out_path).expect("读备份成功");
    assert_eq!(backup_before, backup_after, "备份文件不得被修改");

    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}

/// TC-EXP-03 备份内容结构：恰含 header.json + db.sqlite；不含
/// -wal/-shm（checkpoint(TRUNCATE) 生效）。
#[test]
fn tc_exp_03_zip_contains_header_and_db_only() {
    let base = temp_dir("zip_members");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");

    // 制造 -wal：持未关闭连接写入（见 TC-EXP-01 注释）
    let wal_conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).expect("重开连接成功");
    wal_conn
        .execute_batch("INSERT INTO audit_local (ts, event) VALUES (0, 'trigger-wal');")
        .expect("制造 WAL 写入成功");

    export_backup(&vault_dir, &out_path).expect("导出成功");
    drop(wal_conn);

    let names: Vec<String> = zip_entries(&out_path).into_iter().map(|(n, _)| n).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec!["db.sqlite".to_owned(), "header.json".to_owned()],
        "夹具库无附件，包应恰含两个成员；实际 {names:?}"
    );

    remove_dir_all_quiet(&base);
}

/// TC-EXP-04 verify_backup 正向：无需密码，校验通过。
#[test]
fn tc_exp_04_verify_ok_without_password() {
    let base = temp_dir("verify_ok");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    let exported = export_backup(&vault_dir, &out_path).expect("导出成功");
    assert!(exported.verified, "export 内建校验通过");

    let report = verify_backup(&out_path).expect("校验通过");
    assert_eq!(report.format_version, 1);
    assert_eq!(report.file_count, 2);
    assert!(uuid::Uuid::parse_str(&report.vault_uuid).is_ok());

    remove_dir_all_quiet(&base);
}

/// TC-EXP-05 verify 检出 header 篡改：畸形 header → 报错。
#[test]
fn tc_exp_05_verify_detects_header_tamper() {
    let base = temp_dir("verify_tamper");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");

    let entries = zip_entries(&out_path);
    let tampered = base.join("tampered.coffer");
    repack(
        &tampered,
        &entries,
        &[],
        &[(
            "header.json",
            b"{ \"format_version\": 1, \"vault_uuid\": \"broken\" }",
        )],
    );

    let err = verify_backup(&tampered).expect_err("篡改 header 必须检出");
    assert!(
        matches!(err, cf_domain::CfError::Corrupted(_)),
        "畸形但存在的 header → Corrupted，实际 {err:?}"
    );

    remove_dir_all_quiet(&base);
}

/// TC-EXP-06① verify 检出缺 db：删掉 db.sqlite 重打包 → 检出失败。
#[test]
fn tc_exp_06_verify_detects_missing_db() {
    let base = temp_dir("verify_no_db");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");

    let entries = zip_entries(&out_path);
    let no_db = base.join("no_db.coffer");
    repack(&no_db, &entries, &["db.sqlite"], &[]);

    let err = verify_backup(&no_db).expect_err("缺 db.sqlite 必须拒绝");
    assert_eq!(err, cf_domain::CfError::ImportUnknownFormat, "错误码 2001");

    remove_dir_all_quiet(&base);
}

/// TC-EXP-06② verify 检出「换入他库 db」——⏸ 未覆盖（升际裁决中）。
///
/// verify_backup 是**无密钥**结构校验；无密钥侧不存在可绑定 db 与
/// header 的公开参数，跨库 db 替换在密码学上不可无密钥检出（攻击者
/// 可同时改写任何明文摘要字段）。该伪造由**解锁侧**检出：字段 AAD 与
/// SubKeys 派生均钉死本库 vault_uuid，他库数据在本库密钥下解密必然
/// 失败（见 `错误密码与他库密钥均无法解锁`）。
///
/// 如需在 verify 层检出，须改冻结格式（header 增加字段，且即便如此
/// 明文摘要仍只防误操作不防对抗）——已升级 team-lead，裁决前不实现。
#[test]
#[ignore = "TC-EXP-06②：无密钥不可检出，待格式层裁决（已升级 team-lead）"]
fn tc_exp_06_part2_foreign_db_detection_pending_adjudication() {
    // 占位：裁决后按结论实现（或由 dev-tester 标 ⏸）。
}

/// TC-EXP-07 restore 冲突：目标已存在同名 vault 目录 → VaultExists，
/// 且已存在目录内容零改动。
#[test]
fn tc_exp_07_restore_rejects_existing_vault() {
    let base = temp_dir("restore_exists");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");

    let target_base = temp_dir("restore_target");
    let first = restore_backup(&out_path, &target_base).expect("首次恢复成功");
    let marker_before = fs::read(first.join("db.sqlite")).expect("读已存在 db 成功");

    let err = restore_backup(&out_path, &target_base).expect_err("二次恢复必须失败");
    assert_eq!(err, cf_domain::CfError::VaultExists, "错误码 1004");

    // 已存在目录内容零改动
    let marker_after = fs::read(first.join("db.sqlite")).expect("读已存在 db 成功");
    assert_eq!(marker_before, marker_after);
    assert!(first.join("header.json").is_file(), "原目录完整保留");

    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}

/// TC-EXP-08 锁定态可备份：export_backup 为 CofferApp 级（不需密钥），
/// 全程无任何解锁动作即可导出（§5 设计：锁定态可用）。
///
/// 本测试环境无 VaultSession（G3 并行开发中）；「锁定态」的等价断言 =
/// 进程内从未派生过该库的任何密钥材料，导出仍然成功。
#[test]
fn tc_exp_08_export_works_while_locked() {
    let base = temp_dir("locked_export");
    let (vault_dir, _uuid) = build_vault(&base);
    // 此处刻意不调用 unlock_store——密钥从未在本进程解锁态出现
    let out_path = base.join("backup.coffer");
    let result = export_backup(&vault_dir, &out_path).expect("锁定态导出成功");
    assert!(result.verified);
    assert!(out_path.is_file());

    remove_dir_all_quiet(&base);
}

/// TC-EXP-09 零明文密钥（对抗）：对整个 .coffer 文件字节做 strings 式
/// 子串检索全部明文敏感值，命中数为 0（沿用 cf-store 对抗测试模式）。
#[test]
fn tc_exp_09_no_plaintext_secrets_in_backup() {
    let base = temp_dir("no_plaintext");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");

    let bytes = fs::read(&out_path).expect("读备份成功");
    // 全部明文敏感值：标题 / 密码 / 用户名 / 备注 / 卡号 / TOTP secret
    // （原始字节与其 base32 形态）/ 标签 / URL / issuer / account。
    // 注意 header.json 的 display_name 是威胁模型已声明的明文泄露项
    // （docs/03 §1.3），夹具库名因此使用非敏感值。
    let secrets: &[&str] = &[
        "GitHub 登录",
        "s3cret-明文密码!",
        "octocat",
        "Main account",
        "4111 1111 1111 1111",
        "恢复短语：astral tungsten",
        "dev",
        "重要",
        "https://github.com",
        "https://api.github.com",
        "管理后台",
    ];
    for s in secrets {
        assert!(
            !bytes.windows(s.len()).any(|w| w == s.as_bytes()),
            ".coffer 字节中不得出现明文 {s:?}"
        );
    }
    // TOTP secret：原始字节与其 base32（"JBSWY3DPEHPK3PXP" 形态）
    let raw = b"Hello!\xDE\xAD\xBE\xEF";
    assert!(
        !bytes.windows(raw.len()).any(|w| w == raw),
        "TOTP secret 原始字节不得出现"
    );
    let b32 = "JBSWY3DPEHPK3PXP";
    assert!(
        !bytes.windows(b32.len()).any(|w| w == b32.as_bytes()),
        "TOTP secret 的 base32 形态不得出现"
    );

    remove_dir_all_quiet(&base);
}

/// TC-EXP-10 目标不可写：目标父目录不存在 / 只读 → Err(ExportFailed)
/// 且目标路径不产生半个文件（含临时残留）。
#[test]
fn tc_exp_10_export_unwritable_target_no_partial_file() {
    use std::os::unix::fs::PermissionsExt;

    let base = temp_dir("export_unwritable");
    let (vault_dir, _uuid) = build_vault(&base);

    // ① 父目录不存在
    let out_missing = base.join("no_such_dir").join("backup.coffer");
    let err = export_backup(&vault_dir, &out_missing).expect_err("必须失败");
    assert_eq!(err.code(), 2003, "ExportFailed，实际 {err:?}");
    assert!(!base.join("no_such_dir").exists(), "不得创建目标父目录");

    // ② 父目录只读（root 环境下 chmod 无效，跳过该分支）
    let ro_dir = base.join("readonly_dir");
    fs::create_dir_all(&ro_dir).expect("建只读目录成功");
    let probe = ro_dir.join(".probe");
    let writable = fs::write(&probe, b"x").is_err()
        || fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).is_ok()
            && fs::write(&probe, b"x").is_err();
    let _ = fs::remove_file(&probe);
    if writable {
        let err = export_backup(&vault_dir, &ro_dir.join("backup.coffer")).expect_err("必须失败");
        assert_eq!(err.code(), 2003, "ExportFailed，实际 {err:?}");
        assert!(
            fs::read_dir(&ro_dir)
                .expect("读目录成功")
                .filter_map(|e| e.ok())
                .next()
                .is_none(),
            "只读目录内不得有残留（含 .tmp）"
        );
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755)).expect("恢复目录权限成功");
    } else {
        eprintln!("TC-EXP-10②：当前为 root 环境，chmod 只读不可模拟，分支跳过");
    }

    remove_dir_all_quiet(&base);
}

/// TC-EXP-11 导出中途失败不落半个文件：打包中途注入 IO 失败（源文件
/// 不可读）→ 返回错误；out_path 处无文件、无 .tmp 残留。
#[test]
fn tc_exp_11_export_midway_failure_no_partial() {
    use std::os::unix::fs::PermissionsExt;

    let base = temp_dir("export_midway");
    let (vault_dir, _uuid) = build_vault(&base);

    // 注入点：attachments/ 下放一个打包中途才会读到的不可读文件
    // （collect 阶段只列目录，write_zip 阶段才 fs::read → 中途失败）。
    // root 环境 chmod 不生效：先探测，不可模拟则跳过。
    let att = vault_dir.join("attachments");
    fs::create_dir_all(&att).expect("建 attachments 成功");
    let unreadable = att.join("chunk.bin");
    fs::write(&unreadable, b"encrypted-blob").expect("写附件成功");
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).expect("chmod 成功");
    if fs::read(&unreadable).is_ok() {
        eprintln!("TC-EXP-11：当前为 root 环境，注入不可读文件不可模拟，跳过");
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644)).ok();
        remove_dir_all_quiet(&base);
        return;
    }

    let out_path = base.join("backup.coffer");
    let err = export_backup(&vault_dir, &out_path).expect_err("中途 IO 失败必须报错");
    assert_eq!(err.code(), 2003, "ExportFailed，实际 {err:?}");
    assert!(!out_path.exists(), "out_path 处不得有文件");
    let tmp_residue: Vec<_> = fs::read_dir(&base)
        .expect("读目录成功")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .collect();
    assert!(
        tmp_residue.is_empty(),
        "不得残留临时文件，实际 {tmp_residue:?}"
    );

    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644)).ok();
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------ 补充测试（无用例编号）

/// 补充：恢复同样拒绝篡改包——垃圾 db 在恢复落盘后被检出，且失败
/// 不残留半截目录（fail fast，调用方可见干净状态）。
#[test]
fn restore_篡改包拒绝且不落盘() {
    let base = temp_dir("restore_tamper");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");

    let entries = zip_entries(&out_path);
    let tampered = base.join("tampered.coffer");
    repack(
        &tampered,
        &entries,
        &[],
        &[("db.sqlite", b"definitely not sqlite")],
    );

    let target_base = temp_dir("restore_tamper_target");
    let err = restore_backup(&tampered, &target_base).expect_err("垃圾 db 必须检出");
    // 垃圾字节 → cf-store 把 "file is not a database" 折叠为 StorageError
    // （其错误统一纪律）；Corrupted / UnsupportedFormat 为其他损坏形态
    assert!(
        matches!(
            err,
            cf_domain::CfError::Corrupted(_)
                | cf_domain::CfError::UnsupportedFormat(_)
                | cf_domain::CfError::StorageError(_)
        ),
        "实际 {err:?}"
    );
    let leftovers: Vec<_> = fs::read_dir(&target_base)
        .expect("目标基目录存在")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        leftovers.is_empty(),
        "失败的恢复不得残留任何目录，实际 {leftovers:?}"
    );

    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}

/// 补充（TC-EXP-06② 的解锁侧证据）：错误密码 / 他库密钥均无法解锁。
///
/// verify 层检出不了的跨库 db 替换，在解锁时由密钥绑定检出——此处
/// 钉住该语义（字段 AAD / SubKeys 派生均钉死本库 vault_uuid）。
#[test]
fn 错误密码与他库密钥均无法解锁() {
    let base = temp_dir("unlock_boundary");
    let (vault_dir, _uuid) = build_vault(&base);

    // 错误密码：verifier 解封失败 → 无解锁
    assert!(
        unlock_store(&vault_dir, WRONG_PASSWORD).is_none(),
        "错误密码不得解锁（FR-1.4 语义）"
    );

    // 他库密钥材料：SubKeys 派生盐 = 他库 uuid，解不开本库字段密文。
    // 注意不能用 items.list（它解密标题，会先在本库行上失败）；
    // 用裸 SQL 取行 uuid（不触发解密），再走字段仓库。
    let other_dek = [0x11u8; 32];
    let other_uuid = uuid::Uuid::now_v7();
    let other_keys =
        cf_crypto::subkeys::SubKeys::derive(&other_dek, other_uuid.as_bytes()).expect("派生成功");
    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).expect("打开 db 成功");
    let foreign = cf_store::ItemStore::open(conn, other_keys).expect("schema 打开成功");
    let repos = foreign.repos();
    let some_uuid: String = foreign
        .connection()
        .query_row("SELECT uuid FROM items LIMIT 1", [], |r| r.get(0))
        .expect("本库有条目");
    assert!(
        repos.fields.read_fields_for_item(&some_uuid).is_err(),
        "他库子密钥不得解开本库字段密文"
    );

    // 正密码回来确认夹具本身没坏
    let (_, store) = unlock_store(&vault_dir, PASSWORD).expect("正密码解锁成功");
    drop(store);

    // verifier 明文常量固定（docs/03 §2.6），防止夹具漂移
    assert_eq!(VERIFIER_PLAINTEXT, b"coffer-verifier-v1");
    remove_dir_all_quiet(&base);
}

/// 补充：恢复产物通过 open_container 三态（恢复产物是合法工作目录）。
#[test]
fn 恢复产物通过_open_container() {
    let base = temp_dir("restore_container");
    let (vault_dir, vault_uuid) = build_vault(&base);
    let out_path = base.join("backup.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");

    let target_base = temp_dir("restore_container_target");
    let restored = restore_backup(&out_path, &target_base).expect("恢复成功");
    match cf_format::open_container(&restored).expect("打开容器成功") {
        OpenOutcome::Current(h) => assert_eq!(h.vault_uuid, vault_uuid),
        other => panic!("恢复产物应为 Current，实际 {other:?}"),
    }

    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}

/// FR-8.5 备份提醒打点：导出成功后，源库 `meta.last_backup_at` 必须有值
/// （Unix 秒，落在导出前后 1 秒窗口内）；失败导出不得打点。
#[test]
fn fr_8_5_export_stamps_last_backup_at() {
    use cf_store::MetaRepo;

    let base = temp_dir("fr_8_5_stamp");
    let (vault_dir, _vault_uuid) = build_vault(&base);
    let out_path = base.join("提醒.coffer");

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时钟正常")
            .as_secs() as i64
    };
    let before = now() - 1;
    export_backup(&vault_dir, &out_path).expect("导出成功");
    let after = now() + 1;

    let conn = rusqlite::Connection::open(vault_dir.join("db.sqlite")).expect("打开源库成功");
    let stamped = MetaRepo::new(&conn)
        .last_backup_at()
        .expect("读 meta 成功")
        .expect("导出成功必须打点 last_backup_at");
    assert!(
        (before..=after).contains(&stamped),
        "打点时间 {stamped} 应落在 [{before}, {after}]"
    );

    remove_dir_all_quiet(&base);
}

// ------------------------------------------------ 第二批验收（docs/10 §11.4）

/// 统计指定库 audit_local 表中某事件的条数（TC-AUD-02 专用探针）。
fn count_audit_events(db: &std::path::Path, event: cf_store::AuditEvent) -> usize {
    let conn = rusqlite::Connection::open(db).expect("打开 db 成功");
    cf_store::AuditRepo::new(&conn)
        .list_desc(None, None)
        .expect("读审计表成功")
        .into_iter()
        .filter(|e| e.event == event)
        .count()
}

/// TC-AUD-02 ③④（docs/10 §11.4）：`export_backup` / `restore_backup`
/// 成功路径各恰落 1 条审计事件（`backup_export` / `backup_restore`，
/// FR-12.6）；失败导出不打点（负路径）。
///
/// 注：打点发生在 ZIP 生成**之后**（backup.rs 成功路径尾部），故备份包
/// 内的 db 不含本次 backup_export 行——恢复库的 backup_restore 恰为 1 条
/// 的断言同时钉住该时序。
#[test]
fn tc_aud_02_export_and_restore_stamp_audit_events() {
    use cf_store::AuditEvent;

    let base = temp_dir("tc_aud_02");
    let (vault_dir, _uuid) = build_vault(&base);
    let src_db = vault_dir.join("db.sqlite");
    let out_path = base.join("audit.coffer");

    // 前置：夹具库无 backup_export 事件
    assert_eq!(count_audit_events(&src_db, AuditEvent::BackupExport), 0);

    // 负路径：失败导出（目标父目录不存在 → 2003）不得打点
    let err = export_backup(&vault_dir, &base.join("no_such_dir").join("b.coffer"))
        .expect_err("失败导出必须报错");
    assert_eq!(err.code(), 2003, "ExportFailed，实际 {err:?}");
    assert_eq!(
        count_audit_events(&src_db, AuditEvent::BackupExport),
        0,
        "失败导出不得落审计事件"
    );

    // 成功导出 → 源库恰 1 条 backup_export
    export_backup(&vault_dir, &out_path).expect("导出成功");
    assert_eq!(
        count_audit_events(&src_db, AuditEvent::BackupExport),
        1,
        "导出成功应恰落 1 条 backup_export"
    );

    // 成功恢复 → 恢复库恰 1 条 backup_restore（源库的 0 条随包恢复）
    let target_base = temp_dir("tc_aud_02_target");
    let restored = restore_backup(&out_path, &target_base).expect("恢复成功");
    let restored_db = restored.join("db.sqlite");
    assert_eq!(
        count_audit_events(&restored_db, AuditEvent::BackupRestore),
        1,
        "恢复成功应恰落 1 条 backup_restore"
    );
    assert_eq!(
        count_audit_events(&restored_db, AuditEvent::BackupExport),
        0,
        "打点在打包之后：备份包内不含本次导出事件"
    );

    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}

/// TC-MAC-09（docs/10 §11.5）root_mac × 备份回环兼容（NFR-REL，门禁）：
///
/// ① **新版备份**：`record_count` / `root_mac` 两行随备份包原样恢复
///    （与源库值一致），`verify_integrity` 直接通过（非自举路径）；
/// ② **旧版备份模拟**（备份包早于完整性特性、包内 db 缺两行）：删除
///    恢复产物的两行 → verify 走缺行自举，同样通过且以当前状态重建
///    基线（record_count = 实际 items 行数），重建后二次 verify 仍过。
///
/// 预期语义来自实现者（d4eaf05 交付说明）；verify 显式调用——本夹具的
/// `unlock_store` 不经 cf-session（那里 verify 才挂在 finish_unlock）。
#[test]
fn tc_mac_09_restore_verify_direct_and_bootstrap() {
    let base = temp_dir("tc_mac_09");
    let (vault_dir, _uuid) = build_vault(&base);
    let src_db = vault_dir.join("db.sqlite");
    let out_path = base.join("mac09.coffer");
    export_backup(&vault_dir, &out_path).expect("导出成功");

    let target_base = temp_dir("tc_mac_09_target");
    let restored = restore_backup(&out_path, &target_base).expect("恢复成功");
    let restored_db = restored.join("db.sqlite");

    // ---- ① 新版备份：两行随包恢复，verify 直接通过 ----
    let (src_count, src_mac) = read_integrity_rows(&src_db).expect("源库基线应已就位");
    let (restored_count, restored_mac) =
        read_integrity_rows(&restored_db).expect("恢复库两行应随包恢复");
    assert_eq!(src_count, restored_count, "record_count 随备份原样恢复");
    assert_eq!(src_mac, restored_mac, "root_mac 随备份原样恢复");

    {
        let (_header, store) = unlock_store(&restored, PASSWORD).expect("解锁成功");
        store
            .repos()
            .meta
            .verify_integrity(&store.subkeys().root_mac_key)
            .expect("新版备份：verify 应直接通过（非自举路径）");
    }

    // ---- ② 旧版备份模拟：删两行 → 缺行自举，同样通过 ----
    {
        let conn = rusqlite::Connection::open(&restored_db).expect("打开恢复库成功");
        let deleted = conn
            .execute(
                "DELETE FROM meta WHERE key IN ('record_count','root_mac')",
                [],
            )
            .expect("删两行成功");
        assert_eq!(deleted, 2, "应恰好删除两行");
    }
    assert!(
        read_integrity_rows(&restored_db).is_none(),
        "两行应已删除（旧版备份形态）"
    );

    {
        let (_header, store) = unlock_store(&restored, PASSWORD).expect("解锁成功");
        store
            .repos()
            .meta
            .verify_integrity(&store.subkeys().root_mac_key)
            .expect("缺行自举应通过（旧库兼容）");

        let (count, _) = read_integrity_rows(&restored_db).expect("自举应重建两行");
        assert_eq!(count, 6, "record_count 应以实际 items 行数重建");

        // 重建基线自洽：二次 verify 仍通过（不是「缺失被容忍」而是基线已正确）
        store
            .repos()
            .meta
            .verify_integrity(&store.subkeys().root_mac_key)
            .expect("重建基线二次 verify 应通过");
    }

    remove_dir_all_quiet(&base);
    remove_dir_all_quiet(&target_base);
}

/// 读库的完整性基线两行：(record_count i64, root_mac base64 文本)；
/// 任一行缺失返回 `None`（TC-MAC-09 专用探针，不经密钥）。
/// 两行 value 均按 BLOB 读取（record_count 为 i64-LE BLOB；root_mac 为
/// base64 文本的字节，`set` 以 BLOB 形态写入）。
fn read_integrity_rows(db: &std::path::Path) -> Option<(i64, String)> {
    let conn = rusqlite::Connection::open(db).expect("打开 db 成功");
    let count_blob: Vec<u8> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'record_count'",
            [],
            |r| r.get(0),
        )
        .ok()?;
    let count = i64::from_le_bytes(count_blob.as_slice().try_into().ok()?);
    let mac_blob: Vec<u8> = conn
        .query_row("SELECT value FROM meta WHERE key = 'root_mac'", [], |r| {
            r.get(0)
        })
        .ok()?;
    let mac = String::from_utf8(mac_blob).ok()?;
    Some((count, mac))
}
