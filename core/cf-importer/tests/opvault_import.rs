//! v0.7.0-T02 集成测试：OPVault 导入端到端（TC-OPV-01~06，docs/22 §2.2）。
//!
//! 样本：vendor `test.opvault`（detunized/opvault-ruby，MIT，见 fixtures
//! README；password = `password`，iterations = 40000）。明文经探针固化：
//!
//! - facebook.com（category 001）：mark / secret，notes "Look at this place I found online"
//! - google.com（001）：larry / page，notes "Hey, Google!"
//! - github.com（001，folder 1D3B2B34…"Cool Stuff"）：linus / linux，
//!   notes "This is where I put my codez."
//! - folders.js：2 个（"Cool Stuff" + 空标题 trashed:true）
//! - 附件 0
//!
//! 断言纪律（TC-OPV-03/04）：解密映射先于写入完成，任一失败 → 2002 且
//! **零落库**；条目级 hmac 不验证（opdata MAC 是唯一完整性防线）。

use std::path::{Path, PathBuf};

use base64::Engine as _;
use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::field::Designation;
use cf_domain::item::ItemState;
use cf_domain::CfError;
use cf_importer::{import_opvault, precheck_opvault};
use cf_store::rows::FieldDecrypted;
use cf_store::{ItemListFilter, ItemStore};

/// 仓库根 tests/fixtures 下的样本路径。
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/opvault")
        .join(name)
}

/// 内存库 + 固定子密钥的 ItemStore 门面 + 临时 vault 目录（附件旁路位）。
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

/// 递归拷贝目录（vendor fixture 只读，篡改用副本）。
fn copy_dir_all(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_all(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// 一份可变副本 + 篡改句柄（每个用例独立，互不污染）。
struct Vault {
    root: PathBuf,
    _tmp: tempfile::TempDir,
}

fn copied_vault() -> Vault {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("test.opvault");
    copy_dir_all(&fixture("test.opvault"), &root);
    Vault { root, _tmp: tmp }
}

impl Vault {
    fn path(&self) -> &Path {
        &self.root
    }

    /// 把指定 band 文件里首个 `"<key>":"…"` 的值替换为 `value`
    /// （vendor band 每文件单条目，首处即目标条目）。
    fn tamper(&self, band: &str, key: &str, value: &str) {
        let file = self.root.join("default").join(band);
        let mut content = std::fs::read_to_string(&file).unwrap();
        let needle = format!("\"{key}\":\"");
        let start = content
            .find(&needle)
            .unwrap_or_else(|| panic!("band {band} 未找到键 {key}"));
        let vstart = start + needle.len();
        let vend = content[vstart..].find('"').unwrap() + vstart;
        content.replace_range(vstart..vend, value);
        std::fs::write(&file, &content).unwrap();
    }
}

/// 取某 designation 的字段值（无则空串）。
fn field(fields: &[FieldDecrypted], d: Designation) -> String {
    fields
        .iter()
        .find(|f| f.designation.as_ref() == Some(&d))
        .and_then(|f| f.value.as_ref())
        .map(|v| v.expose().to_owned())
        .unwrap_or_default()
}

/// TC-OPV-01/02 正向导入：vendor 样本 3 条全导入，字段/备注/URL 与
/// 探针固化的明文逐条吻合，报告结构字段正确。
#[test]
fn 正向导入vendor样本() {
    let v = copied_vault();
    let mut h = harness();

    let result = import_opvault(v.path(), "password", &mut h.store, &h.vault_dir).unwrap();
    assert_eq!(result.imported_items, 3);

    // ---- 报告（完整档，import 管线产出） ----
    let report = &result.report;
    assert_eq!(report.profile_name, "default");
    assert_eq!(report.profile_uuid, "714A14D7017048CC9577AD050FC9C6CA");
    assert_eq!(report.iterations, 40000);
    assert_eq!(report.band_file_count, 4);
    assert_eq!(report.total_items, 3);
    assert_eq!(report.importable_items, 3);
    assert_eq!(report.folder_count, 2);
    assert_eq!(report.attachment_count, 0);
    assert_eq!(report.trashed_items, 0, "样本条目无 trashed");
    assert!(report.unknown_field_types.is_empty());
    assert!(report.unknown_categories.is_empty());
    assert!(report.not_imported.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("out-of-scope")),
        "附件 out-of-scope 必须 surface 到报告"
    );
    assert_eq!(
        report.category_distribution,
        vec![("login".to_string(), 3)],
        "3 条 category 001 → Login"
    );

    // ---- 落库 ----
    let repos = h.store.repos();
    assert_eq!(repos.items.count(None).unwrap(), 3);
    assert_eq!(repos.meta.item_count().unwrap(), 3);

    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert!(all.iter().all(|i| i.row.category == ItemCategory::Login));
    assert!(all.iter().all(|i| i.row.state == ItemState::Active));

    // facebook.com：mark / secret / notes / 单 URL primary
    let fb = all.iter().find(|i| i.title.expose() == "facebook.com").unwrap();
    let fb_fields = repos.fields.read_fields_for_item(&fb.row.uuid).unwrap();
    assert_eq!(field(&fb_fields, Designation::Username), "mark");
    assert_eq!(field(&fb_fields, Designation::Password), "secret");
    assert_eq!(
        field(&fb_fields, Designation::NotesPlain),
        "Look at this place I found online"
    );
    let fb_urls = repos.urls.read_for_item(&fb.row.uuid).unwrap();
    assert_eq!(fb_urls.len(), 1);
    assert!(fb_urls[0].is_primary);
    assert_eq!(fb_urls[0].url.expose(), "http://facebook.com");

    // google.com：larry / page
    let gg = all.iter().find(|i| i.title.expose() == "google.com").unwrap();
    let gg_fields = repos.fields.read_fields_for_item(&gg.row.uuid).unwrap();
    assert_eq!(field(&gg_fields, Designation::Username), "larry");
    assert_eq!(field(&gg_fields, Designation::Password), "page");
    assert_eq!(field(&gg_fields, Designation::NotesPlain), "Hey, Google!");

    // github.com：linus / linux（含 folder，但文件夹本版不落库，仅计数）
    let gh = all.iter().find(|i| i.title.expose() == "github.com").unwrap();
    let gh_fields = repos.fields.read_fields_for_item(&gh.row.uuid).unwrap();
    assert_eq!(field(&gh_fields, Designation::Username), "linus");
    assert_eq!(field(&gh_fields, Designation::Password), "linux");
    assert_eq!(
        field(&gh_fields, Designation::NotesPlain),
        "This is where I put my codez."
    );
}

/// TC-OPV-03 错误密码：报 2002（不是 1002 文案），all-or-nothing 零落库。
#[test]
fn 错误密码报2002且零落库() {
    let v = copied_vault();
    let mut h = harness();

    let err = import_opvault(v.path(), "wrong-password", &mut h.store, &h.vault_dir).unwrap_err();
    assert!(
        matches!(err, CfError::ImportFailed(ref m) if m.contains("密码错误")),
        "错误密码应报 ImportFailed(2002) 且含密码错误文案，实际 {err:?}"
    );
    assert_eq!(
        h.store.repos().items.count(None).unwrap(),
        0,
        "错误密码不得落任何条目"
    );
}

/// TC-OPV-04a 条目级 hmac 篡改：不验证 → 照常导入（opdata MAC 是唯一
/// 完整性防线，docs/24 §1.4）。
#[test]
fn 篡改条目级hmac仍导入() {
    let v = copied_vault();
    v.tamper("band_6.js", "hmac", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    let mut h = harness();

    let result = import_opvault(v.path(), "password", &mut h.store, &h.vault_dir).unwrap();
    assert_eq!(result.imported_items, 3, "条目级 hmac 不验证，篡改不得拦截");
}

/// TC-OPV-04b 篡改 details 载荷：解密失败 → 2002，all-or-nothing 零落库。
#[test]
fn 篡改details载荷报2002且零落库() {
    let fake_d = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 128]);
    let v = copied_vault();
    v.tamper("band_6.js", "d", &fake_d);
    let mut h = harness();

    let err = import_opvault(v.path(), "password", &mut h.store, &h.vault_dir).unwrap_err();
    assert!(
        matches!(err, CfError::ImportFailed(ref m) if m.contains("解密失败")),
        "details 解密失败应报 ImportFailed(2002)，实际 {err:?}"
    );
    assert_eq!(
        h.store.repos().items.count(None).unwrap(),
        0,
        "解密失败不得落任何条目"
    );
}

/// TC-OPV-05 结构预检：只读、不触密码——锁定态可预检，全量分析字段恒空。
#[test]
fn 结构预检不触密码() {
    let v = copied_vault();

    let report = precheck_opvault(v.path()).unwrap();
    assert_eq!(report.profile_name, "default");
    assert_eq!(report.profile_uuid, "714A14D7017048CC9577AD050FC9C6CA");
    assert_eq!(report.iterations, 40000);
    assert_eq!(report.password_hint.as_deref(), Some(""));
    assert_eq!(report.band_file_count, 4);
    assert_eq!(report.attachment_count, 0);
    assert!(report.other_profiles.is_empty());
    assert!(report.warnings.is_empty(), "样本无 salt/keys/多 profile 告警");

    // 全量分析字段属解锁后内容：纯结构预检恒空（docs/22 §2.2.3）
    assert_eq!(report.total_items, 0);
    assert_eq!(report.importable_items, 0);
    assert_eq!(report.folder_count, 0);
    assert_eq!(report.trashed_items, 0);
    assert!(report.unknown_field_types.is_empty());
    assert!(report.not_imported.is_empty());
}

/// TC-OPV-06 非 opvault 目录：预检与导入同源报 2001，零落库。
#[test]
fn 非opvault目录报2001() {
    let tmp = tempfile::tempdir().unwrap();
    let plain = tmp.path().join("not_an_opvault");
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(plain.join("random.txt"), "hi").unwrap();

    let err = precheck_opvault(&plain).unwrap_err();
    assert!(
        matches!(err, CfError::ImportUnknownFormat),
        "预检非 opvault 目录应报 2001，实际 {err:?}"
    );

    let mut h = harness();
    let err = import_opvault(&plain, "pw", &mut h.store, &h.vault_dir).unwrap_err();
    assert!(
        matches!(err, CfError::ImportUnknownFormat),
        "导入非 opvault 目录应报 2001，实际 {err:?}"
    );
    assert_eq!(h.store.repos().items.count(None).unwrap(), 0);
}
