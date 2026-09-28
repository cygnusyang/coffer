//! v0.3.0-T01 集成测试：1PUX 导入端到端（FR-7.1 含 `files/` 附件 +
//! FR-7.4~7.7 预检报告）。
//!
//! 样本：仓库根 `tests/fixtures/sample_coverage.1pux`（30 条，含 22 类各 1
//! 条与边界条目，5 附件；categoryUuid 901-922 / 1000-1005 / 1100-1101 均为
//! 占位值，预期全走未知类别降级路径，docs/09 E-4）。
//!
//! 断言依据：docs/09-版本开发计划.md v0.3.0-T01 与映射冻结裁决。

use std::path::{Path, PathBuf};

use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::field::Designation;
use cf_domain::item::ItemState;
use cf_importer::{
    import_1pux, import_1pux_with_options, precheck_1pux, ImportOptions, PuxImportResult,
};
use cf_store::{AttachmentRepo, ItemListFilter, ItemStore};

/// 仓库根 tests/fixtures 下的样本路径。
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// 内存库 + 固定子密钥的 ItemStore 门面 + 临时 vault 目录。
struct Harness {
    store: ItemStore,
    vault_dir: PathBuf,
    _tmp: tempfile::TempDir,
}

fn harness() -> Harness {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    Harness {
        store: ItemStore::open(conn, keys).unwrap(),
        vault_dir: tmp.path().to_path_buf(),
        _tmp: tmp,
    }
}

/// 1PUX ZIP 内某附件条目的原始字节（回环对照基准）。
fn zip_entry_bytes(pux_path: &Path, entry: &str) -> Vec<u8> {
    let f = std::fs::File::open(pux_path).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(f)).unwrap();
    use std::io::Read as _;
    let mut out = Vec::new();
    zip.by_name(entry).unwrap().read_to_end(&mut out).unwrap();
    out
}

/// 端到端：30 条全导入成功、unknown_categories 全量、4 附件逐字节回环、
/// 字段抽查（FR-7.1 / E-4 / docs/09 v0.3.0-T01）。
#[test]
 fn 样本全量导入与附件逐字节回环() {
    let pux = fixture("sample_coverage.1pux");
    let mut h = harness();

    // 预检（FR-7.4）
    let report = precheck_1pux(&pux).unwrap();
    assert_eq!(report.total_items, 30);
    assert_eq!(report.importable_items, 30, "样本无 Tombstone / 附件缺失");
    assert_eq!(report.attachment_count, 5);
    assert_eq!(report.unknown_categories.len(), 30, "占位 categoryUuid 全部未识别");
    assert_eq!(report.trashed_count, 1);
    assert!(report.not_imported.is_empty());
    assert!(
        report.warnings.iter().any(|w| w.contains("已降级导入为安全笔记")),
        "降级必须 surface 到预检警告（E-4 / D-6）"
    );

    // 导入
    let result: PuxImportResult = import_1pux_with_options(&pux, &mut h.store, &h.vault_dir, &ImportOptions::default()).unwrap();
    assert_eq!(result.imported_items, 30);

    let repos = h.store.repos();
    assert_eq!(repos.items.count(None).unwrap(), 30);
    assert_eq!(repos.meta.item_count().unwrap(), 30);

    // 全部 30 条应为 SecureNote（未知类别降级），1 条 trashed + 1 条 archived
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert!(all.iter().all(|i| i.row.category == ItemCategory::SecureNote));
    assert_eq!(all.iter().filter(|i| i.row.state == ItemState::Trashed).count(), 1);
    assert_eq!(all.iter().filter(|i| i.row.state == ItemState::Archived).count(), 1);

    // 字段抽查：SYNTH-Login（降级条目，username/password 并入 notes）
    let login = all
        .iter()
        .find(|i| i.title.expose() == "SYNTH-Login")
        .expect("应存在 SYNTH-Login");
    let fields = repos.fields.read_fields_for_item(&login.row.uuid).unwrap();
    let notes = fields
        .iter()
        .find(|f| f.designation.as_ref() == Some(&Designation::NotesPlain))
        .expect("降级条目应有备注字段")
        .value
        .as_ref()
        .unwrap()
        .expose()
        .to_owned();
    assert!(notes.contains("[loginField username (T)] user@example.com"));
    assert!(notes.contains("P@ssw0rd-测试-🔐"), "emoji 与中文保真");

    // 多 URL：SYNTH-Login 的 overview.urls 两行，首条 primary
    let urls = repos.urls.read_for_item(&login.row.uuid).unwrap();
    assert_eq!(urls.len(), 2);
    assert!(urls[0].is_primary);
    assert_eq!(urls[0].url.expose(), "https://example1.com");
    assert!(!urls[1].is_primary);
    assert_eq!(urls[1].url.expose(), "https://admin.example1.com");

    // 附件逐字节回环：5 个条目各 1 附件，read_content == ZIP 条目原始字节
    let pux_abs = pux.clone();
    let attachments = all
        .iter()
        .filter_map(|i| {
            let metas = repos.attachments.list_for_item(&i.row.uuid).unwrap();
            (!metas.is_empty()).then_some((i, metas))
        })
        .collect::<Vec<_>>();
    assert_eq!(attachments.len(), 5);
    let expected = [
        ("SYNTH-Login", "files/doc1.pdf"),
        ("SYNTH-CreditCard", "files/doc6.pdf"),
        ("SYNTH-SecureNote", "files/doc11.pdf"),
        ("SYNTH-RewardProgram", "files/doc16.pdf"),
        ("SYNTH-SshKey", "files/doc21.pdf"),
    ];
    for (item, metas) in &attachments {
        let title = item.title.expose();
        let (_, entry) = expected
            .iter()
            .find(|e| e.0 == title)
            .unwrap_or_else(|| panic!("意外附件宿主条目 {title}"));
        assert_eq!(metas.len(), 1);
        let meta = &metas[0];
        assert_eq!(meta.filename, entry.rsplit('/').next().unwrap());
        let plain = repos
            .attachments
            .read_content(&meta.uuid, &h.vault_dir)
            .unwrap();
        assert_eq!(
            plain,
            zip_entry_bytes(&pux_abs, entry),
            "附件 {entry} 必须逐字节回环"
        );
    }
}

/// 故障注入：带附件条目的事务在附件写入后失败 → 该条目回滚、
/// 附件文件成孤儿 → 收尾 cleanup_orphans 清零（docs/09 接缝裁决）。
#[test]
 fn 事务失败回滚且孤儿附件被清理() {
    let pux = fixture("sample_coverage.1pux");
    let mut h = harness();

    // 第 7 个条目（0 起 = 6）是 SYNTH-CreditCard（带 doc6.pdf 附件）：
    // 注入点在其附件文件落盘之后 → 必然产生孤儿文件
    let err = import_1pux_with_options(
        &pux,
        &mut h.store,
        &h.vault_dir,
        &ImportOptions { fail_after_rows: Some(6) },
    )
    .unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("注入")));

    // 前 6 条已提交（每条目独立事务），第 7 条回滚
    let repos = h.store.repos();
    assert_eq!(repos.items.count(None).unwrap(), 6);
    assert_eq!(repos.meta.item_count().unwrap(), 6, "meta 计数随失败事务回滚");
    // 第 1 条（SYNTH-Login）的附件已随其事务成功提交且文件在
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    let login = all.iter().find(|i| i.title.expose() == "SYNTH-Login").unwrap();
    assert_eq!(repos.attachments.list_for_item(&login.row.uuid).unwrap().len(), 1);

    // 孤儿已被收尾清理：attachments 目录中不留未被 DB 行引用的文件
    let removed = AttachmentRepo::cleanup_orphans(&h.vault_dir, h.store.connection()).unwrap();
    assert_eq!(removed, 0, "导入收尾应已清零孤儿，二次清理不应再有");
    let dir = h.vault_dir.join("attachments");
    if dir.is_dir() {
        let referenced: std::collections::HashSet<String> = all
            .iter()
            .flat_map(|i| repos.attachments.list_for_item(&i.row.uuid).unwrap())
            .map(|m| m.uuid)
            .collect();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            assert!(referenced.contains(&name), "残留孤儿文件 {name}");
        }
    }
}

/// 损坏输入：坏 ZIP / 缺 export.attributes / JSON 缺 accounts ——
/// 报错且不落库（FR-7.1）。
#[test]
 fn 损坏输入报错且不落库() {
    let h = harness();

    // 坏 ZIP
    let bad_zip = h._tmp.path().join("bad.1pux");
    std::fs::write(&bad_zip, b"this is not a zip file").unwrap();
    let err = precheck_1pux(&bad_zip).unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportUnknownFormat));

    // 合法 ZIP 但缺 export.attributes
    let missing_attrs = h._tmp.path().join("missing_attrs.1pux");
    {
        let f = std::fs::File::create(&missing_attrs).unwrap();
        let mut zip = zip::ZipWriter::new(f);
        zip.start_file("export.data", zip::write::SimpleFileOptions::default())
            .unwrap();
        use std::io::Write as _;
        zip.write_all(br#"{"accounts": []}"#).unwrap();
        zip.finish().unwrap();
    }
    let err = precheck_1pux(&missing_attrs).unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("export.attributes")));

    // export.data 缺 accounts
    let no_accounts = h._tmp.path().join("no_accounts.1pux");
    {
        let f = std::fs::File::create(&no_accounts).unwrap();
        let mut zip = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("export.attributes", opts).unwrap();
        use std::io::Write as _;
        zip.write_all(br#"{"version": 3}"#).unwrap();
        zip.start_file("export.data", opts).unwrap();
        zip.write_all(br#"{"not_accounts": []}"#).unwrap();
        zip.finish().unwrap();
    }
    let err = precheck_1pux(&no_accounts).unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("accounts")));

    // 以上任何输入都不落库
    assert_eq!(h.store.repos().items.count(None).unwrap(), 0);
}

/// 官方形态 B 附件（documentAttributes + `files/<documentId>` 前缀枚举、
/// 分隔符不硬编码）与小样本导入（categoryUuid 用 docs/03 §6.4.1 真实码：
/// 001 Login / 004 Identity / 112 降级）。
#[test]
 fn 官方形态b附件前缀枚举与真实类别码() {
    let pux_path = tmp_1pux();
    let mut h = harness();

    let result = import_1pux(&pux_path, &mut h.store, &h.vault_dir).unwrap();
    assert_eq!(result.imported_items, 3);
    let report = &result.report;
    assert_eq!(report.unknown_categories.len(), 1, "仅 112 降级");
    assert_eq!(
        report.unknown_categories[0].1, "112",
        "未识别类别清单带原始 categoryUuid"
    );

    let repos = h.store.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();

    // 001 → Login
    let login = all.iter().find(|i| i.title.expose() == "L").unwrap();
    assert_eq!(login.row.category, ItemCategory::Login);
    let fields = repos.fields.read_fields_for_item(&login.row.uuid).unwrap();
    let get = |d: &Designation| -> String {
        fields
            .iter()
            .find(|f| f.designation.as_ref() == Some(d))
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(get(&Designation::Username), "u1");
    assert_eq!(get(&Designation::Password), "p1");

    // 004 → Identity
    let identity = all.iter().find(|i| i.title.expose() == "I").unwrap();
    assert_eq!(identity.row.category, ItemCategory::Identity);

    // 112 → 降级 SecureNote
    let doc = all.iter().find(|i| i.title.expose() == "D").unwrap();
    assert_eq!(doc.row.category, ItemCategory::SecureNote);

    // 形态 B 附件：`files/DOCXYZ` 前缀枚举命中 `files/DOCXYZ___manual.pdf`
    let plain = repos
        .attachments
        .list_for_item(&doc.row.uuid)
        .unwrap();
    assert_eq!(plain.len(), 1);
    assert_eq!(plain[0].filename, "manual.pdf");
    let content = repos
        .attachments
        .read_content(&plain[0].uuid, &h.vault_dir)
        .unwrap();
    assert_eq!(content, b"official form B content");
}

/// 附件 zip bomb（dev-review HIGH-1）：`files/` 条目 central directory
/// 声明的解压大小很小、实际解压内容超过单附件 100 MiB 上限 → 导入报
/// `ImportFailed` 且不落库（不得依赖 cf-store 落库前的第二道检查兜底）。
#[test]
 fn 附件zip炸弹声明尺寸小实际解压超限被拒() {
    let pux_path = bomb_1pux("attachment_bomb", 110 * 1024 * 1024, 0);
    tamper_central_dir_uncompressed_size(&pux_path, "files/BOMBDOC___bomb.bin", 16);

    let mut h = harness();
    let err = import_1pux(&pux_path, &mut h.store, &h.vault_dir).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("实际解压")),
        "应报实际解压超限的 ImportFailed，实际 {err:?}"
    );
    assert_eq!(
        h.store.repos().items.count(None).unwrap(),
        0,
        "炸弹条目不得落库"
    );
}

/// export.data zip bomb：central directory 声明很小、实际解压超过
/// 64 MiB 上限 → 预检报 `ImportFailed`（读入阶段拦截，不进 JSON 解析）。
#[test]
 fn 导出数据zip炸弹声明尺寸小实际解压超限被拒() {
    let pux_path = bomb_1pux("data_bomb", 1, 65 * 1024 * 1024);
    tamper_central_dir_uncompressed_size(&pux_path, "export.data", 20);

    let err = precheck_1pux(&pux_path).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("实际解压")),
        "应报实际解压超限的 ImportFailed，实际 {err:?}"
    );
}

/// 把 ZIP central directory 中指定条目的「解压后大小」字段篡改为
/// `fake`（模拟 zip bomb：声明小尺寸、实际解压内容远大于声明）。
/// 只改 central directory（`f.size()` 的来源），不动压缩数据与 CRC。
fn tamper_central_dir_uncompressed_size(path: &Path, entry: &str, fake: u32) {
    let mut raw = std::fs::read(path).unwrap();
    let needle = entry.as_bytes();
    let mut patched = false;
    let mut from = 0;
    while let Some(off) = find_subslice(&raw[from..], b"PK\x01\x02") {
        let base = from + off;
        from = base + 4;
        let name_len = u16::from_le_bytes([raw[base + 28], raw[base + 29]]) as usize;
        if &raw[base + 46..base + 46 + name_len] == needle {
            raw[base + 24..base + 28].copy_from_slice(&fake.to_le_bytes());
            patched = true;
        }
    }
    assert!(patched, "central directory 中未找到条目 {entry}");
    std::fs::write(path, &raw).unwrap();
}

/// 在 `haystack` 中定位 `needle` 首次出现位置。
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 构造 zip bomb 测试用单条目 1PUX（形态 B 附件，`files/BOMBDOC___bomb.bin`）。
///
/// `content_len`：附件条目内容字节数（重复 `'A'`，deflate 高度可压，
/// 实际 ZIP 文件仍然很小）；`data_pad`：export.data 尾部空白填充字节数
/// （JSON 合法性不受影响）。`file_stem` 须各测试唯一——测试并行运行，
/// 共享路径会互相覆盖产生损坏的 ZIP。
fn bomb_1pux(file_stem: &str, content_len: usize, data_pad: usize) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("coffer-pux-bomb-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{file_stem}.1pux"));
    let f = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default();
    use std::io::Write as _;
    zip.start_file("export.attributes", opts).unwrap();
    zip.write_all(br#"{"version": 3}"#).unwrap();
    let mut data = serde_json::json!({
        "accounts": [{
            "attrs": {"name": "B"},
            "vaults": [{
                "attrs": {"uuid": "VB", "name": "v", "type": "P"},
                "items": [{
                    "uuid": "SB1", "categoryUuid": "112", "state": "active",
                    "createdAt": 1_700_000_000i64, "updatedAt": 1_700_000_000i64,
                    "overview": {"title": "B"},
                    "details": {"documentAttributes": {
                        "fileName": "bomb.bin", "documentId": "BOMBDOC",
                        "decryptedSize": content_len as i64
                    }}
                }]
            }]
        }]
    })
    .to_string()
    .into_bytes();
    data.resize(data.len() + data_pad, b' ');
    zip.start_file("export.data", opts).unwrap();
    zip.write_all(&data).unwrap();
    zip.start_file("files/BOMBDOC___bomb.bin", opts).unwrap();
    let chunk = [b'A'; 65536];
    let mut left = content_len;
    while left > 0 {
        let n = chunk.len().min(left);
        zip.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    zip.finish().unwrap();
    path
}

/// 构造官方形态（fieldType 键 + documentAttributes）的小样本 1PUX。
fn tmp_1pux() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("coffer-pux-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("official_form.1pux");
    let f = std::fs::File::create(&path).unwrap();
    let mut zip = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default();
    use std::io::Write as _;
    zip.start_file("export.attributes", opts).unwrap();
    zip.write_all(br#"{"version": 3, "description": "test"}"#).unwrap();
    let data = br#"{"accounts": [{"attrs": {"name": "T"}, "vaults": [
        {"attrs": {"uuid": "V", "name": "v", "type": "P"}, "items": [
            {"uuid": "S1", "categoryUuid": "001", "state": "active",
             "createdAt": 1700000000, "updatedAt": 1700000000,
             "overview": {"title": "L"},
             "details": {"loginFields": [
                 {"designation": "username", "name": "username", "fieldType": "T", "value": "u1"},
                 {"designation": "password", "name": "password", "fieldType": "P", "value": "p1"}]}},
            {"uuid": "S2", "categoryUuid": "004", "state": "active",
             "overview": {"title": "I"}, "details": {}},
            {"uuid": "S3", "categoryUuid": "112", "state": "active",
             "overview": {"title": "D"},
             "details": {"documentAttributes": {"fileName": "manual.pdf", "documentId": "DOCXYZ", "decryptedSize": 23}}}
        ]}]}]}"#;
    zip.start_file("export.data", opts).unwrap();
    zip.write_all(data).unwrap();
    zip.start_file("files/DOCXYZ___manual.pdf", opts).unwrap();
    zip.write_all(b"official form B content").unwrap();
    zip.finish().unwrap();
    path
}
