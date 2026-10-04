//! v0.7.0-T01 集成测试：1PUX 导出与回环（FR-8.2）。
//!
//! 判据基准：`docs/23-v0.7.0验收判据骨架.md` §1.1 TC-EXP 组（FFI/内核
//! 驱动项，T01 负责）。主判据 = **导出 → 重新导入回环逐字节等价**
//! （`22` §2.1.6：自回环为本版验收锚点）。
//!
//! 归属说明：TC-EXP-09（只读许可态 6002/6003）/ TC-EXP-10（锁定态
//! 1001）/ TC-EXP-15（FFI 参数无效 1012/5002）的落点在 cf-session /
//! cf-ffi 门禁层（`T04`，G2 串行），本层以 `&ItemStore` 为入参无门禁
//! 语义——与 CSV 测试 TC-EXP-17 同款占位纪律。TC-EXP-16/17 为 UI/
//! 真机人工项（`T06`）。
//!
//! §0.4 纪律：临时目录 / 内存 fixture、时间戳固定值、无网络、测试间
//! 零共享可变状态。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::{BufReader, Read, Write as _};
use std::path::Path;

use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_exporter::pux::{category_to_1p_code, export_one_pux};
use cf_importer::import_1pux;
use cf_store::rows::{FieldDecrypted, FieldRow, UrlDecrypted};
use cf_store::{ItemListFilter, ItemRow, ItemStore, PasskeyRecord, COSE_ALG_ES256};
use serde_json::{json, Value};
use zip::ZipArchive;

mod support;

use support::{build_vault, remove_dir_all_quiet, temp_dir, unlock_store, PASSWORD};

// ------------------------------------------------------------ 基础夹具

/// 用夹具主密码解锁已建库目录。
fn unlocked_store(vault_dir: &Path) -> ItemStore {
    let (_, store) = unlock_store(vault_dir, PASSWORD).expect("解锁夹具库成功");
    store
}

/// 新建空内存库（导入侧 / 空库导出夹具）。
fn new_store() -> ItemStore {
    let conn = rusqlite::Connection::open_in_memory().expect("内存库成功");
    let keys =
        cf_crypto::subkeys::SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).expect("派生子密钥成功");
    ItemStore::open(conn, keys).expect("打开成功")
}

/// 读取导出 ZIP 的 export.data 并解析为 JSON。
fn export_data_json(path: &Path) -> Value {
    let f = fs::File::open(path).expect("打开导出文件成功");
    let mut zip = ZipArchive::new(BufReader::new(f)).expect("导出必须是合法 ZIP");
    let mut buf = Vec::new();
    zip.by_name("export.data")
        .expect("ZIP 内必须有 export.data")
        .read_to_end(&mut buf)
        .expect("读取 export.data 成功");
    serde_json::from_slice(&buf).expect("export.data 必须是合法 JSON")
}

/// 定位导出 JSON 中的全部条目（accounts[0].vaults[0].items）。
fn exported_items(data: &Value) -> Vec<&Value> {
    data["accounts"][0]["vaults"][0]["items"]
        .as_array()
        .expect("items 必须是数组")
        .iter()
        .collect()
}

/// 写一份 1PUX 夹具 ZIP（FR-7.1 导入侧的输入形态）。
fn write_1pux_fixture(path: &Path, items: &[Value], attachments: &[(&str, &[u8])]) {
    let data = json!({
        "accounts": [{
            "attrs": {"name": "Coffer", "type": "P"},
            "vaults": [{"attrs": {"name": "Vault", "type": "P"}, "items": items}]
        }]
    });
    let attributes = json!({"version": 3, "createdAt": 1_700_000_000});
    let f = fs::File::create(path).expect("创建夹具成功");
    let mut zip = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in [
        ("export.attributes", attributes.to_string().as_bytes().to_vec()),
        ("export.data", data.to_string().as_bytes().to_vec()),
    ] {
        zip.start_file(name, opts).expect("起条目成功");
        zip.write_all(&content).expect("写条目成功");
    }
    for (name, bytes) in attachments {
        zip.start_file(*name, opts).expect("起附件条目成功");
        zip.write_all(bytes).expect("写附件成功");
    }
    zip.finish().expect("收尾 ZIP 成功");
}

/// 导入 1PUX 到新库（返回 (store, vault_dir)）。
fn import_fixture(path: &Path) -> (ItemStore, std::path::PathBuf) {
    let base = temp_dir("pux_import");
    let vault_dir = base.join("vault");
    fs::create_dir_all(&vault_dir).expect("建附件宿主目录成功");
    let mut store = new_store();
    import_1pux(path, &mut store, &vault_dir).expect("导入 1PUX 成功");
    (store, vault_dir)
}

// ------------------------------------------------------------ 对拍助手

fn field_sig(f: &FieldDecrypted) -> (String, String, String, Option<String>) {
    (
        format!("{:?}", f.field_type),
        f.designation
            .as_ref()
            .map(|d| d.to_1p_str().to_owned())
            .unwrap_or_default(),
        f.name.expose().to_owned(),
        f.value.as_ref().map(|v| v.expose().to_owned()),
    )
}

fn url_sig(u: &UrlDecrypted) -> (Option<String>, String, bool) {
    (
        u.label.as_ref().map(|l| l.expose().to_owned()),
        u.url.expose().to_owned(),
        u.is_primary,
    )
}

/// 回环主判据对拍：dst（再导入）逐字段逐字节等价 src（首次导入）。
/// 只对拍非回收站条目（回收站条目不导出，TC-EXP-05 单独核）。
fn assert_loopback(
    src: &ItemStore,
    src_vault_dir: &Path,
    dst: &ItemStore,
    dst_vault_dir: &Path,
) {
    let srep = src.repos();
    let drep = dst.repos();
    let s_items = srep.items.list(&ItemListFilter::default()).expect("列 src 条目成功");
    let d_items = drep.items.list(&ItemListFilter::default()).expect("列 dst 条目成功");
    let s_active: Vec<_> = s_items
        .iter()
        .filter(|i| i.row.state != ItemState::Trashed)
        .collect();
    assert_eq!(
        s_active.len(),
        d_items.len(),
        "导出条目数 = 再导入条目数（回收站除外）"
    );

    for s in &s_active {
        let d = d_items
            .iter()
            .find(|d| d.title.expose() == s.title.expose())
            .unwrap_or_else(|| panic!("dst 应含条目 {:?}", s.title.expose()));
        // 行级：category / state / 收藏 / 时间戳
        assert_eq!(s.row.category, d.row.category, "category 回环");
        assert_eq!(s.row.state, d.row.state, "state 回环");
        assert_eq!(s.row.is_favorite, d.row.is_favorite, "favorite 回环");
        assert_eq!(s.row.fav_index, d.row.fav_index, "fav_index 回环");
        assert_eq!(s.row.created_at, d.row.created_at, "created_at 回环");
        assert_eq!(s.row.updated_at, d.row.updated_at, "updated_at 回环");

        // 字段集（含 username / password / notes / 自定义字段）
        let mut sf: Vec<_> = srep
            .fields
            .read_fields_for_item(&s.row.uuid)
            .expect("读 src 字段成功")
            .iter()
            .map(field_sig)
            .collect();
        let mut df: Vec<_> = drep
            .fields
            .read_fields_for_item(&d.row.uuid)
            .expect("读 dst 字段成功")
            .iter()
            .map(field_sig)
            .collect();
        sf.sort();
        df.sort();
        assert_eq!(sf, df, "字段集逐字节等价（title={:?}）", s.title.expose());

        // URLs（顺序 + 主标记）
        let su: Vec<_> = srep
            .urls
            .read_for_item(&s.row.uuid)
            .expect("读 src urls 成功")
            .iter()
            .map(url_sig)
            .collect();
        let du: Vec<_> = drep
            .urls
            .read_for_item(&d.row.uuid)
            .expect("读 dst urls 成功")
            .iter()
            .map(url_sig)
            .collect();
        assert_eq!(su, du, "URLs 回环");

        // 标签（多重集）
        let mut st: Vec<String> = srep
            .tags
            .read_for_item(&s.row.uuid)
            .expect("读 src tags 成功")
            .iter()
            .map(|t| t.name.expose().to_owned())
            .collect();
        let mut dt: Vec<String> = drep
            .tags
            .read_for_item(&d.row.uuid)
            .expect("读 dst tags 成功")
            .iter()
            .map(|t| t.name.expose().to_owned())
            .collect();
        st.sort();
        dt.sort();
        assert_eq!(st, dt, "tags 回环");

        // TOTP（meta + secret 逐字节）
        let s_totp = read_totp(&srep, &s.row.uuid);
        let d_totp = read_totp(&drep, &d.row.uuid);
        assert_eq!(s_totp, d_totp, "TOTP 回环");

        // 附件（filename + 内容逐字节）
        let s_att = srep
            .attachments
            .list_for_item(&s.row.uuid)
            .expect("列 src 附件成功");
        let d_att = drep
            .attachments
            .list_for_item(&d.row.uuid)
            .expect("列 dst 附件成功");
        assert_eq!(s_att.len(), d_att.len(), "附件数回环");
        for (sa, da) in s_att.iter().zip(d_att.iter()) {
            assert_eq!(sa.filename, da.filename, "附件文件名回环");
            let s_content = srep
                .attachments
                .read_content(&sa.uuid, src_vault_dir)
                .expect("读 src 附件内容成功");
            let d_content = drep
                .attachments
                .read_content(&da.uuid, dst_vault_dir)
                .expect("读 dst 附件内容成功");
            assert_eq!(s_content, d_content, "附件内容逐字节回环");
        }
    }
}

/// 读取某条目第一条 TOTP 的元数据与密钥。
#[derive(Debug, PartialEq, Eq)]
struct ParsedTotp {
    algo: String,
    digits: u8,
    period: u32,
    issuer: Option<String>,
    account: Option<String>,
    secret: Vec<u8>,
}

/// 读取某条目第一条 TOTP 的元数据与密钥。
fn read_totp(repos: &cf_store::Repos<'_>, item_uuid: &str) -> Option<ParsedTotp> {
    let uuid = repos
        .totp
        .totp_uuids_for_item(item_uuid)
        .expect("列 TOTP 成功")
        .into_iter()
        .next()?;
    let meta = repos.totp.totp_meta(&uuid).expect("读 TOTP 成功")?;
    let secret = repos.totp.totp_secret(&uuid).expect("读密钥成功")?;
    Some(ParsedTotp {
        algo: meta.algo,
        digits: meta.digits,
        period: meta.period,
        issuer: meta.issuer,
        account: meta.account,
        secret: secret.to_vec(),
    })
}

// ------------------------------------------------------------ TC-EXP-01 结构

/// TC-EXP-01 结构合法：产物为合法 ZIP，含 export.attributes(version=3) /
/// export.data(accounts→vaults→items) / files/；字段键官方形态。
#[test]
fn tc_exp_01_structure_official_keys() {
    let base = temp_dir("pux_structure");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("export.1pux");
    let store = unlocked_store(&vault_dir);
    let result = export_one_pux(&store, &vault_dir, &out_path).expect("导出成功");

    let f = fs::File::open(&out_path).expect("产物存在");
    let mut zip = ZipArchive::new(BufReader::new(f)).expect("合法 ZIP");

    // export.attributes: version = 3
    let mut attrs_buf = Vec::new();
    zip.by_name("export.attributes")
        .expect("有 export.attributes")
        .read_to_end(&mut attrs_buf)
        .expect("读 attributes 成功");
    let attrs: Value = serde_json::from_slice(&attrs_buf).expect("attributes 是 JSON");
    assert_eq!(attrs["version"], 3, "version 必须为 3");

    // export.data: accounts→vaults→items 三级 + 官方键
    let mut data_buf = Vec::new();
    zip.by_name("export.data")
        .expect("有 export.data")
        .read_to_end(&mut data_buf)
        .expect("读 data 成功");
    let data: Value = serde_json::from_slice(&data_buf).expect("data 是 JSON");
    assert!(data["accounts"].is_array());
    assert!(data["accounts"][0]["vaults"].is_array());
    let items = exported_items(&data);
    assert!(!items.is_empty());
    for it in &items {
        // 官方键：loginFields / sections / documentAttributes，绝不出现合成键
        let details = &it["details"];
        assert!(
            details.get("loginFields").is_none_or(Value::is_array),
            "loginFields 官方键"
        );
        assert!(
            it.get("file").is_none(),
            "不得发射合成 item.file（必须用 documentAttributes）"
        );
        for lf in details["loginFields"].as_array().unwrap_or(&vec![]) {
            assert!(
                lf.get("fieldType").is_some() || lf.get("value").is_some(),
                "loginField 用 fieldType 官方键"
            );
            assert!(lf.get("type").is_none(), "不得发射合成 type 键");
        }
    }

    // 附件产物在 files/ 下（docs/22 §2.1：有附件才产出 files/ 段；
    // build_vault 无附件 → 本库无 files/；有附件的形态由 TC-EXP-03 覆盖）
    let names: Vec<String> = zip.file_names().map(str::to_owned).collect();
    if result.attachment_count > 0 {
        assert!(
            names.iter().any(|n| n.starts_with("files/")),
            "有附件时 files/ 段必须存在"
        );
    } else {
        assert!(
            !names.iter().any(|n| n.starts_with("files/")),
            "无附件时不得产出 files/ 段"
        );
    }

    // 四计数
    assert_eq!(result.item_count, 5, "build_vault 6 条含 1 回收站");
    assert_eq!(result.skipped_trashed, 1);
    remove_dir_all_quiet(&base);
}

// --------------------------------------------- MEDIUM-2 附件条目名净化

/// MEDIUM-2 出口防御：恶意附件文件名（含 `../`/`/`/`\`/`:` 路径成分）→
/// ZIP 条目名净化防 zip-slip；`documentAttributes.fileName` 保留原始名
/// （导出 JSON 层无损，回环无损）；附件不因文件名被丢弃（计数不变）。
#[test]
fn tc_exp_malicious_attachment_filename_zip_entry_safe() {
    let base = temp_dir("pux_att_name");
    let (vault_dir, _uuid) = build_vault(&base);
    let mut store = unlocked_store(&vault_dir);
    let out_path = base.join("att-name.1pux");

    // 直写恶意文件名（绕过导入侧净化，独立锁定导出侧防御）
    let now = 1_700_000_000i64;
    store
        .with_tx(|repos| {
            let uuid = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: uuid.clone(),
                    category: ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: now,
                    updated_at: now,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("恶意附件条目"),
            )?;
            repos.meta.add_item_count(1)?;
            repos.attachments.add(
                &uuid,
                b"../../etc/passwd",
                b"evil content",
                &vault_dir,
            )?;
            Ok(())
        })
        .expect("写条目与恶意附件成功");

    let result = export_one_pux(&store, &vault_dir, &out_path).expect("导出成功");
    assert_eq!(result.attachment_count, 1, "恶意文件名附件仍须导出（不丢弃）");

    let f = fs::File::open(&out_path).expect("产物存在");
    let mut zip = ZipArchive::new(BufReader::new(f)).expect("合法 ZIP");

    // 条目名安全：files/ 下恰一成分，尾段无 `/`/`\`/`:`、非 `.`/`..`
    let entries: Vec<String> = zip.file_names().map(str::to_owned).collect();
    let att_entries: Vec<&String> = entries.iter().filter(|n| n.starts_with("files/")).collect();
    assert_eq!(att_entries.len(), 1, "恰一个 files/ 条目");
    for entry in &att_entries {
        let tail = entry.strip_prefix("files/").expect("files/ 前缀");
        assert!(!tail.contains('/'), "条目名 {entry:?} 含路径分隔 /");
        assert!(!tail.contains('\\'), "条目名 {entry:?} 含反斜杠");
        assert!(!tail.contains(':'), "条目名 {entry:?} 含冒号");
        assert!(tail != "." && tail != "..", "条目名 {entry:?} 自指");
    }

    // 内容逐字节在位
    let mut content = Vec::new();
    zip.by_name(att_entries[0])
        .expect("读附件条目成功")
        .read_to_end(&mut content)
        .expect("读内容成功");
    assert_eq!(content, b"evil content", "附件内容逐字节在位");

    // documentAttributes.fileName 保留原始名（JSON 层无损）
    let data = export_data_json(&out_path);
    let items = exported_items(&data);
    let att_it = items
        .iter()
        .find(|it| it["overview"]["title"] == "恶意附件条目")
        .expect("条目在导出 JSON 中");
    assert_eq!(
        att_it["details"]["documentAttributes"]["fileName"],
        "../../etc/passwd",
        "fileName 保留原始名（净化仅在 ZIP 条目名，回环无损）"
    );

    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-02/03 回环

/// TC-EXP-02 回环主判据 + TC-EXP-03 附件面：导入 1PUX → 导出 → 新库再
/// 导入 → 逐字段逐字节等价（含附件 / TOTP / 标签 / 收藏 / 时间戳）。
#[test]
fn tc_exp_02_03_loopback_roundtrip() {
    let base = temp_dir("pux_loopback");
    let fixture = base.join("src.1pux");

    let items = [
        json!({
            "uuid": "FIX-0001", "categoryUuid": "001", "state": "active",
            "createdAt": 1_700_000_000, "updatedAt": 1_700_001_000, "favIndex": 1,
            "overview": {
                "title": "GitHub 登录",
                "urls": [
                    {"label": null, "url": "https://github.com"},
                    {"label": "管理后台", "url": "https://api.github.com"}
                ],
                "tags": ["dev", "重要"]
            },
            "details": {
                "loginFields": [
                    {"designation": "username", "name": "用户名", "fieldType": "T", "value": "octocat"},
                    {"designation": "password", "name": "密码", "fieldType": "P", "value": "s3cret-明文密码!"},
                    {"designation": "totp", "name": "one-time password",
                     "value": {"totp": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30"}}
                ],
                "notesPlain": "Main account\n第二行备注",
                "documentAttributes": {"fileName": "ticket.pdf", "documentId": "DOC-0001", "decryptedSize": 5}
            }
        }),
        json!({
            "uuid": "FIX-0002", "categoryUuid": "003", "state": "active",
            "createdAt": 1_700_000_000, "updatedAt": 1_700_001_000, "favIndex": 3,
            "overview": {"title": "安全笔记", "tags": []},
            "details": {
                "notesPlain": "恢复短语：astral tungsten",
                "sections": [
                    {"title": "自定义", "fields": [
                        {"title": "电话", "designation": "phone", "fieldType": "T", "value": "13800000000"},
                        {"title": "开启", "designation": "flag", "fieldType": "B", "value": "true"}
                    ]}
                ]
            }
        }),
        json!({
            "uuid": "FIX-0003", "categoryUuid": "002", "state": "active",
            "createdAt": 1_700_000_000, "updatedAt": 1_700_001_000, "favIndex": 0,
            "overview": {"title": "测试信用卡", "tags": ["卡"]},
            "details": {
                "sections": [
                    {"title": "卡信息", "fields": [
                        {"title": "卡号", "designation": "cardNumber", "fieldType": "C", "value": "4111 1111 1111 1111"}
                    ]}
                ]
            }
        }),
        json!({
            "uuid": "FIX-0004", "categoryUuid": "001", "state": "archived",
            "createdAt": 1_700_000_000, "updatedAt": 1_700_002_000, "favIndex": 0,
            "overview": {"title": "归档的条目", "tags": []},
            "details": {
                "loginFields": [
                    {"designation": "username", "name": "用户名", "fieldType": "T", "value": "arch-user"},
                    {"designation": "password", "name": "密码", "fieldType": "P", "value": "arch-pass"}
                ]
            }
        }),
        json!({
            "uuid": "FIX-0005", "categoryUuid": "001", "state": "trashed",
            "createdAt": 1_700_000_000, "updatedAt": 1_700_003_000, "favIndex": 0,
            "overview": {"title": "回收站条目", "tags": []},
            "details": {}
        }),
    ];
    write_1pux_fixture(
        &fixture,
        &items,
        &[("files/DOC-0001___ticket.pdf", b"hello")],
    );

    // 导入 → 导出
    let (src, src_vault_dir) = import_fixture(&fixture);
    let out_path = base.join("roundtrip.1pux");
    let result = export_one_pux(&src, &src_vault_dir, &out_path).expect("导出成功");
    assert_eq!(result.item_count, 4, "4 条 Active+Archived，1 回收站跳过");
    assert_eq!(result.skipped_trashed, 1);
    assert_eq!(result.attachment_count, 1);

    // 结构面（TC-EXP-03）：documentAttributes + files/<docId>___<name>
    let data = export_data_json(&out_path);
    let items = exported_items(&data);
    let gh = items
        .iter()
        .find(|it| it["overview"]["title"] == "GitHub 登录")
        .expect("GitHub 登录应在导出中");
    let da = &gh["details"]["documentAttributes"];
    assert_eq!(da["fileName"], "ticket.pdf");
    assert_eq!(da["decryptedSize"], 5);
    let doc_id = da["documentId"].as_str().expect("documentId 存在");
    let uuid = uuid::Uuid::parse_str(doc_id).expect("documentId 必须是合法 UUID");
    assert_eq!(uuid.get_version_num(), 7, "documentId 必须是 UUIDv7");
    let entry = format!("files/{doc_id}___ticket.pdf");
    let f = fs::File::open(&out_path).expect("打开导出成功");
    let mut zip = ZipArchive::new(BufReader::new(f)).expect("合法 ZIP");
    let mut content = Vec::new();
    zip.by_name(&entry)
        .expect("ZIP 内应有附件条目")
        .read_to_end(&mut content)
        .expect("读附件成功");
    assert_eq!(content, b"hello", "附件内容逐字节一致");

    // 再导入新库 → 逐字段逐字节等价
    let (dst, dst_vault_dir) = import_fixture(&out_path);
    assert_loopback(&src, &src_vault_dir, &dst, &dst_vault_dir);

    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-04 空库

/// TC-EXP-04 空库导出：0 条目 → 合法 1PUX（items 空）→ 再导入成功（0 条）。
#[test]
fn tc_exp_04_empty_vault_export_import() {
    let base = temp_dir("pux_empty");
    let out_path = base.join("empty.1pux");
    let store = new_store();
    let result = export_one_pux(&store, &base, &out_path).expect("空库导出成功");
    assert_eq!(result.item_count, 0);
    assert_eq!(result.attachment_count, 0);
    assert_eq!(result.skipped_trashed, 0);
    assert_eq!(result.skipped_passkeys, 0);

    let data = export_data_json(&out_path);
    assert_eq!(exported_items(&data).len(), 0, "items 为空");

    let (dst, _) = import_fixture(&out_path);
    assert_eq!(
        dst.repos()
            .items
            .list(&ItemListFilter::default())
            .expect("列条目成功")
            .len(),
        0
    );
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-05 范围

/// TC-EXP-05 导出范围：Active + Archived 导出；回收站跳过且计数；
/// accounts.len()==1、vaults.len()==1。
#[test]
fn tc_exp_05_scope_and_single_account_vault() {
    let base = temp_dir("pux_scope");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("scope.1pux");
    let store = unlocked_store(&vault_dir);
    let result = export_one_pux(&store, &vault_dir, &out_path).expect("导出成功");
    assert_eq!(result.item_count, 5, "build_vault 6 条含 1 回收站");
    assert_eq!(result.skipped_trashed, 1);

    let data = export_data_json(&out_path);
    assert_eq!(data["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(data["accounts"][0]["vaults"].as_array().unwrap().len(), 1);
    let titles: Vec<&str> = exported_items(&data)
        .iter()
        .filter_map(|it| it["overview"]["title"].as_str())
        .collect();
    assert!(titles.contains(&"归档的条目"), "Archived 条目导出");
    assert!(!titles.contains(&"回收站条目"), "回收站条目不导出");
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-06 TOTP

/// TC-EXP-06 TOTP 全量导出（裁决 D）：designation="totp" +
/// value={"totp": "<otpauth URI>"}；SHA-1 回环等价；非 SHA-1 导出 → 报告
/// 注明 + 本仓回环降级 SHA-1。
#[test]
fn tc_exp_06_totp_full_export_sha1_and_non_sha1() {
    let base = temp_dir("pux_totp");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("totp.1pux");
    let store = unlocked_store(&vault_dir);
    let result = export_one_pux(&store, &vault_dir, &out_path).expect("导出成功");

    // SHA-1（build_vault 种子）→ 导出为 designation=totp + value={totp: uri}
    let data = export_data_json(&out_path);
    let items = exported_items(&data);
    let gh = items
        .iter()
        .find(|it| it["overview"]["title"] == "GitHub 登录")
        .expect("GitHub 登录在导出中");
    let totp_field = gh["details"]["loginFields"]
        .as_array()
        .expect("loginFields")
        .iter()
        .find(|lf| lf["designation"] == "totp")
        .expect("应有 totp loginField");
    assert_eq!(totp_field["value"]["totp"].as_str().unwrap(),
        "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30&algorithm=sha1");
    assert_eq!(result.report.non_sha1_totp, 0, "SHA-1 全导出");

    // 回环：TOTP 参数逐字节一致
    let (dst, _) = import_fixture(&out_path);
    let dgh = dst
        .repos()
        .items
        .list(&ItemListFilter::default())
        .expect("列条目成功")
        .into_iter()
        .find(|i| i.title.expose() == "GitHub 登录")
        .expect("GitHub 登录回环");
    let got = read_totp(&dst.repos(), &dgh.row.uuid).expect("TOTP 应回环");
    assert_eq!(got.algo, "sha1");
    assert_eq!(got.digits, 6);
    assert_eq!(got.period, 30);
    assert_eq!(got.issuer.as_deref(), Some("GitHub"));
    assert_eq!(got.account.as_deref(), Some("octocat"));
    assert_eq!(got.secret, b"Hello!\xDE\xAD\xBE\xEF", "secret 逐字节回环");

    // 非 SHA-1：sha256 TOTP → 导出带 algorithm=sha256，报告计数；回环降级 sha1
    let mut store2 = new_store();
    seed_totp(&mut store2, "sha256", 8, 30);
    let out2 = base.join("totp256.1pux");
    let r2 = export_one_pux(&store2, &base, &out2).expect("导出成功");
    assert_eq!(r2.report.non_sha1_totp, 1, "非 SHA-1 必须进报告");
    let data2 = export_data_json(&out2);
    let items2 = exported_items(&data2);
    let login = items2[0]["details"]["loginFields"]
        .as_array()
        .expect("loginFields")
        .iter()
        .find(|lf| lf["designation"] == "totp")
        .expect("totp 字段");
    let uri = login["value"]["totp"].as_str().expect("URI");
    assert!(
        uri.contains("algorithm=sha256"),
        "URI 必须自带 algorithm=sha256，实际 {uri}"
    );

    let (dst2, _) = import_fixture(&out2);
    let item2 = dst2
        .repos()
        .items
        .list(&ItemListFilter::default())
        .expect("列条目成功")
        .pop()
        .expect("有条目");
    let got2 = read_totp(&dst2.repos(), &item2.row.uuid).expect("TOTP 回环");
    assert_eq!(got2.algo, "sha1", "本仓回环非 SHA-1 降级 SHA-1");
    assert_eq!(got2.digits, 8);
    assert_eq!(got2.period, 30);
    assert_eq!(got2.secret, b"0123456789abcdef", "secret 逐字节回环");

    remove_dir_all_quiet(&base);
}

/// 向空库写一条含 TOTP 的 Login 条目（TC-EXP-06 专用）。
fn seed_totp(store: &mut ItemStore, algo: &str, digits: u8, period: u32) {
    let now = 1_700_000_000i64;
    store
        .with_tx(|repos| {
            let uuid = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: uuid.clone(),
                    category: ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: now,
                    updated_at: now,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("TOTP 条目"),
            )?;
            repos.totp.insert_totp(
                &uuid::Uuid::now_v7().to_string(),
                &uuid,
                b"0123456789abcdef",
                algo,
                digits,
                period,
                Some("Issuer"),
                Some("acct"),
            )?;
            repos.meta.add_item_count(1)?;
            Ok(())
        })
        .expect("写 TOTP 条目成功");
}

// ------------------------------------------------------------ TC-EXP-07 passkey

/// TC-EXP-07 passkey 不导出（裁决 C）：含 passkey 条目导出 → 计数正确、
/// passkey 数据不随导出、四计数逐一断言。
#[test]
fn tc_exp_07_passkey_not_exported_and_counted() {
    let base = temp_dir("pux_passkey");
    let (vault_dir, _uuid) = build_vault(&base);
    let mut store = unlocked_store(&vault_dir);
    let out_path = base.join("passkey.1pux");

    // 给 GitHub 登录加一条 passkey
    seed_passkey(&mut store, "GitHub 登录", "github.com");

    let result = export_one_pux(&store, &vault_dir, &out_path).expect("导出成功");
    assert_eq!(result.item_count, 5);
    assert_eq!(result.attachment_count, 0);
    assert_eq!(result.skipped_trashed, 1);
    assert_eq!(result.skipped_passkeys, 1, "passkey 显式计数（不静默）");

    // passkey 数据（credentialId/rpId）不得出现在 export.data 明文里
    let data = export_data_json(&out_path);
    let raw = serde_json::to_string(&data).expect("序列化");
    assert!(
        !raw.contains("credentialId") && !raw.contains("rpId"),
        "passkey 数据不得随 1PUX 导出"
    );

    remove_dir_all_quiet(&base);
}

/// 向库中指定标题条目追加一条 passkey（TC-EXP-07 专用）。
fn seed_passkey(store: &mut ItemStore, title: &str, rp_id: &str) {
    let repos = store.repos();
    let item = repos
        .items
        .list(&ItemListFilter::default())
        .expect("列条目成功")
        .into_iter()
        .find(|i| i.title.expose() == title)
        .expect("目标条目存在");
    let item_uuid = item.row.uuid;
    store
        .with_tx(|repos| {
            repos.passkeys.add(
                &item_uuid,
                &PasskeyRecord {
                    rp_id: rp_id.to_owned(),
                    rp_name: Some("Example".into()),
                    user_name: Some("octocat".into()),
                    user_handle: vec![0x11; 16],
                    credential_id: vec![0x22; 32],
                    private_key_pkcs8: vec![0x33; 40],
                    algorithm: COSE_ALG_ES256,
                    sign_count: 0,
                },
                1_700_000_000,
            )?;
            Ok(())
        })
        .expect("写 passkey 成功");
}

// ------------------------------------------------------------ TC-EXP-08 反向映射

/// TC-EXP-08 categoryUuid 反向映射：复用 §6.4.1 权威表；Custom/未命中 →
/// "003"。
#[test]
fn tc_exp_08_category_reverse_mapping() {
    // 单元面：权威表往返 + Custom 兜底
    assert_eq!(category_to_1p_code(ItemCategory::Login), "001");
    assert_eq!(category_to_1p_code(ItemCategory::CreditCard), "002");
    assert_eq!(category_to_1p_code(ItemCategory::SecureNote), "003");
    assert_eq!(category_to_1p_code(ItemCategory::Identity), "004");
    assert_eq!(category_to_1p_code(ItemCategory::SoftwareLicense), "100");
    assert_eq!(category_to_1p_code(ItemCategory::EmailAccount), "111");
    assert_eq!(category_to_1p_code(ItemCategory::Custom), "003", "Custom 兜底 SecureNote");

    // 端到端：Custom 条目导出后 categoryUuid == "003"
    let base = temp_dir("pux_custom");
    let out_path = base.join("custom.1pux");
    let mut store = new_store();
    store
        .with_tx(|repos| {
            repos.items.insert(
                &ItemRow {
                    uuid: uuid::Uuid::now_v7().to_string(),
                    category: ItemCategory::Custom,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_000,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("自定义条目"),
            )?;
            repos.meta.add_item_count(1)?;
            Ok(())
        })
        .expect("写 Custom 条目成功");
    export_one_pux(&store, &base, &out_path).expect("导出成功");
    let data = export_data_json(&out_path);
    let items = exported_items(&data);
    let it = &items[0];
    assert_eq!(it["categoryUuid"], "003");
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-11 失败面

/// TC-EXP-11 导出失败面：目标路径不可写 → 2003 ExportFailed；不留半成品；
/// 源库无副作用。
#[test]
fn tc_exp_11_unwritable_target_2003_no_partial() {
    let base = temp_dir("pux_fail");
    let (vault_dir, _uuid) = build_vault(&base);
    let store = unlocked_store(&vault_dir);
    let out_path = base.join("no_such_dir").join("export.1pux");
    let err = export_one_pux(&store, &vault_dir, &out_path).expect_err("父目录不存在必须失败");
    assert_eq!(err.code(), 2003, "ExportFailed，实际 {err:?}");
    assert!(
        !base.join("no_such_dir").exists(),
        "不得创建目标父目录 / 半成品"
    );

    // 源库无副作用：条目数不变
    let repos = store.repos();
    assert_eq!(
        repos.items.list(&ItemListFilter::default()).expect("列条目").len(),
        6
    );
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-12 无副作用

/// TC-EXP-12 导出无副作用：导出后源库条目逐字段不变（导出只读面）。
#[test]
fn tc_exp_12_export_no_source_side_effect() {
    let base = temp_dir("pux_noeffect");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("ok.1pux");
    let store = unlocked_store(&vault_dir);

    let snapshot = |s: &ItemStore| {
        let repos = s.repos();
        let items = repos.items.list(&ItemListFilter::default()).expect("列条目");
        items
            .iter()
            .map(|i| {
                let fields = repos
                    .fields
                    .read_fields_for_item(&i.row.uuid)
                    .expect("读字段")
                    .iter()
                    .map(field_sig)
                    .collect::<Vec<_>>();
                (i.title.expose().to_owned(), i.row.updated_at, fields)
            })
            .collect::<Vec<_>>()
    };

    let before = snapshot(&store);
    export_one_pux(&store, &vault_dir, &out_path).expect("导出成功");
    let after = snapshot(&store);
    assert_eq!(before, after, "导出后源库条目不变");
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-13 边界

/// TC-EXP-13 边界：emoji / CJK / 组合字符 / ≥64 KiB 备注 → 回环逐字节等价。
#[test]
fn tc_exp_13_long_unicode_roundtrip() {
    let base = temp_dir("pux_unicode");
    let (vault_dir, _uuid) = build_vault(&base);
    let out_path = base.join("unicode.1pux");
    let mut store = unlocked_store(&vault_dir);

    // 给 GitHub 登录追加超长 Unicode 备注字段
    let long_note = format!(
        "emoji 🎉 中文 用户 e\u{301}（组合） 😀\n{}",
        "x".repeat(64 * 1024)
    );
    let repos = store.repos();
    let item = repos
        .items
        .list(&ItemListFilter::default())
        .expect("列条目")
        .into_iter()
        .find(|i| i.title.expose() == "GitHub 登录")
        .expect("GitHub 登录存在");
    let item_uuid = item.row.uuid;
    store
        .with_tx(|repos| {
            let existing = repos
                .fields
                .read_fields_for_item(&item_uuid)
                .expect("读字段");
            let mut rows: Vec<FieldRow> = existing
                .iter()
                .map(|f| FieldRow {
                    uuid: f.uuid.clone(),
                    item_uuid: item_uuid.clone(),
                    section_uuid: f.section_uuid.clone(),
                    field_type: f.field_type,
                    designation: f.designation.clone(),
                    name: f.name.expose().to_owned(),
                    value: f.value.as_ref().map(|v| v.expose().to_owned()),
                    position: f.position,
                })
                .collect();
            rows.push(FieldRow {
                uuid: uuid::Uuid::now_v7().to_string(),
                item_uuid: item_uuid.clone(),
                section_uuid: None,
                field_type: FieldType::Multiline,
                designation: Some(Designation::Other("longNote".into())),
                name: "长备注".into(),
                value: Some(long_note.clone()),
                position: rows.len() as i64,
            });
            repos.fields.replace_fields_for_item(&item_uuid, &rows)?;
            Ok(())
        })
        .expect("写长备注成功");

    export_one_pux(&store, &vault_dir, &out_path).expect("导出成功");
    let (dst, _dst_vault) = import_fixture(&out_path);
    let dgh = dst
        .repos()
        .items
        .list(&ItemListFilter::default())
        .expect("列条目")
        .into_iter()
        .find(|i| i.title.expose() == "GitHub 登录")
        .expect("回环存在");
    let df = dst.repos().fields.read_fields_for_item(&dgh.row.uuid).expect("读字段");
    let got = df
        .iter()
        .find(|f| f.designation.as_ref() == Some(&Designation::Other("longNote".into())))
        .and_then(|f| f.value.as_ref())
        .map(|v| v.expose().to_owned())
        .expect("长备注字段回环");
    assert_eq!(got, long_note, "≥64KiB Unicode 备注逐字节回环");

    // Multiline 自定义字段在本仓 1PUX 无承载码 → 降级 Text（TC-EXP-14 语义）
    assert_eq!(df.iter().find(|f| f.name.expose() == "长备注").unwrap().field_type, FieldType::Text);
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------------------ TC-EXP-14 未知类型

/// TC-EXP-14 未知 FieldType 降级 Text 并入报告（不静默）。
#[test]
fn tc_exp_14_unknown_fieldtype_degrades_with_report() {
    let base = temp_dir("pux_unknown");
    let out_path = base.join("unknown.1pux");
    let mut store = new_store();
    store
        .with_tx(|repos| {
            let uuid = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: uuid.clone(),
                    category: ItemCategory::SecureNote,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_000,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("未知类型条目"),
            )?;
            repos.fields.replace_fields_for_item(
                &uuid,
                &[
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: uuid.clone(),
                        section_uuid: None,
                        field_type: FieldType::Unsupported,
                        designation: None,
                        name: "怪字段".into(),
                        value: Some("value-保留".into()),
                        position: 0,
                    },
                    FieldRow {
                        uuid: uuid::Uuid::now_v7().to_string(),
                        item_uuid: uuid.clone(),
                        section_uuid: None,
                        field_type: FieldType::Phone,
                        designation: Some(Designation::Other("phone".into())),
                        name: "电话".into(),
                        value: Some("13800000000".into()),
                        position: 1,
                    },
                ],
            )?;
            repos.meta.add_item_count(1)?;
            Ok(())
        })
        .expect("写未知类型条目成功");

    let result = export_one_pux(&store, &base, &out_path).expect("导出成功");
    assert!(
        result.report.degraded_fields.len() >= 2,
        "两个无 1P 承载码的字段必须进报告（不静默），实际 {:?}",
        result.report.degraded_fields
    );

    // 导出后回环：值保留（Text 降级）
    let data = export_data_json(&out_path);
    let items = exported_items(&data);
    let it = &items[0];
    let fields = &it["details"]["sections"][0]["fields"];
    let raw = serde_json::to_string(fields).expect("序列化");
    assert!(raw.contains("value-保留"), "未知类型字段值不丢");
    assert!(raw.contains("13800000000"), "Phone 字段值不丢");
    remove_dir_all_quiet(&base);
}

// ------------------------------------------------- 门禁 / 参数校验（T04 迁出）

// TC-EXP-09/10/15 由 T04 迁至 cf-ffi（门禁落点在 cf-session / cf-ffi 边界，
// 本层无门禁与参数校验语义；cf-exporter 不能 dev-依赖 cf-ffi 防循环）：
//   - TC-EXP-09：只读许可态 6002/6003 + 拒绝不产生输出文件
//   - TC-EXP-10：锁定态 1001
//   - TC-EXP-15：out_path 参数非法 → 5002
// 实现在 `core/cf-ffi/tests/pux_export_ffi_semantics.rs`（T04，docs/22 §6）。
