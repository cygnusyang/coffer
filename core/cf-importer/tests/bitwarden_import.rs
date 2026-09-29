//! v0.5.0-PK2 集成测试：Bitwarden JSON 导入端到端（FR-10.1 / FR-10.6，
//! docs/17 §4.2 PK2、docs/18 TCB-1 / TCB-7）。
//!
//! 样本：`tests/fixtures/bitwarden/`（全部合成数据，真实凭据不进仓库，
//! 字段形态注记见该目录 README——TCB-1 真实样本逆向核对降级门禁）。
//!
//! 断言依据：docs/17 r2.1 §4.2（D-6 / 导入事务语义 / DoS 上限）、
//! docs/18 r1.2 TCB-1（双格式导入判据）与 TCB-7（坏 passkey 行纪律）。

use std::path::PathBuf;

use cf_crypto::subkeys::SubKeys;
use cf_domain::category::ItemCategory;
use cf_domain::field::Designation;
use cf_domain::item::ItemState;
use cf_importer::{
    import_bitwarden_json_with_options, precheck_bitwarden_json, BwImportResult, ImportOptions,
};
use cf_store::{ItemListFilter, ItemStore};

/// 合成 fixture 路径（crate 内 tests/fixtures/bitwarden/）。
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bitwarden")
        .join(name)
}

/// 内存库 + 固定子密钥的 ItemStore 门面（passkeys 仓库随 Repos 聚合）。
fn store() -> ItemStore {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    ItemStore::open(conn, keys).unwrap()
}

/// 按标题取条目（导入固定「全部新建 UUIDv7」，须以标题定位）。
fn find_by_title(st: &ItemStore, title: &str) -> cf_store::ItemWithTitle {
    st.repos()
        .items
        .list(&ItemListFilter::default())
        .unwrap()
        .into_iter()
        .find(|i| i.title.expose() == title)
        .unwrap_or_else(|| panic!("应存在标题为 {title} 的条目"))
}

/// 取条目指定 designation 的字段值（字节，FR-10.6 逐字节口径）。
fn field_bytes(st: &ItemStore, item_uuid: &str, d: &Designation) -> Vec<u8> {
    st.repos()
        .fields
        .read_fields_for_item(item_uuid)
        .unwrap()
        .into_iter()
        .find(|f| f.designation.as_ref() == Some(d))
        .unwrap_or_else(|| panic!("条目 {item_uuid} 应有 {d:?} 字段"))
        .value
        .map(|v| v.expose().as_bytes().to_vec())
        .unwrap_or_default()
}

/// 内存 JSON 字符串 → 临时文件 → 导入（DoS 用例辅助）。
fn import_str(json: &str, st: &mut ItemStore) -> Result<BwImportResult, cf_domain::CfError> {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("sample.json");
    std::fs::write(&path, json.as_bytes()).unwrap();
    import_bitwarden_json_with_options(&path, st, &ImportOptions::default())
}

/// TCB-1①：合成样本回环——条目数、逐字段（含密码）、passkey 逐字段一致。
#[test]
fn 合成样本回环条目与passkey逐字段一致() {
    let bw = fixture("login_with_passkey.json");
    let mut st = store();

    // 预检（只读，TCB-1④）
    let report = precheck_bitwarden_json(&bw).unwrap();
    assert_eq!(report.total_items, 2);
    assert_eq!(report.importable_items, 2);
    assert_eq!(report.passkey_total, 1);
    assert_eq!(report.passkey_importable, 1);
    assert_eq!(report.passkey_item_count, 1);
    assert_eq!(
        report.items_with_password_and_passkey, 1,
        "FR-10.6 证据计数"
    );
    assert!(report.non_es256.is_empty());
    assert!(report.bad_passkeys.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("unknownFutureField")),
        "未知 fido2 字段须记 warning 不丢弃（docs/17 §4.2）"
    );

    // 导入
    let result =
        import_bitwarden_json_with_options(&bw, &mut st, &ImportOptions::default()).unwrap();
    assert_eq!(result.imported_items, 2);

    let repos = st.repos();
    assert_eq!(repos.items.count(None).unwrap(), 2);
    assert_eq!(repos.meta.item_count().unwrap(), 2);

    // 条目 1：逐字段
    let item1 = find_by_title(&st, "Example Site");
    assert_eq!(item1.row.category, ItemCategory::Login);
    assert_eq!(item1.row.state, ItemState::Active);
    assert!(item1.row.is_favorite);
    assert_eq!(item1.row.created_at, 1_785_585_600);
    assert_eq!(item1.row.updated_at, 1_786_784_400);
    assert_eq!(
        field_bytes(&st, &item1.row.uuid, &Designation::Username),
        b"alice@example.com".to_vec()
    );
    assert_eq!(
        field_bytes(&st, &item1.row.uuid, &Designation::Password),
        "P@ssw0rd-逐字节".as_bytes().to_vec()
    );
    // 自定义字段（type 0 → Text）
    let fields = repos.fields.read_fields_for_item(&item1.row.uuid).unwrap();
    assert!(fields.iter().any(|f| f.name.expose() == "备注字段"
        && f.value.as_ref().is_some_and(|v| v.expose() == "自定义值")));
    // URL（首条 is_primary）
    let urls = repos.urls.read_for_item(&item1.row.uuid).unwrap();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].url.expose(), "https://example.com/login");
    assert!(urls[0].is_primary);
    // 标签 = folder 名（folders[id].name）
    let tags = repos.tags.read_for_item(&item1.row.uuid).unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].name.expose(), "开发账号");
    // TOTP（otpauth 解析成功）
    assert_eq!(
        repos
            .totp
            .totp_uuids_for_item(&item1.row.uuid)
            .unwrap()
            .len(),
        1
    );

    // passkey 逐字段（PasskeyMeta 白名单，无私钥——FR-10.2）
    let pks = repos.passkeys.list_for_item(&item1.row.uuid).unwrap();
    assert_eq!(pks.len(), 1);
    let pk = &pks[0];
    assert_eq!(pk.rp_id, "example.com");
    assert_eq!(pk.rp_name.as_deref(), Some("Example"));
    assert_eq!(pk.user_name.as_deref(), Some("alice@example.com"));
    assert_eq!(pk.credential_id_b64, "Y3JlZC1pZC0x");
    assert_eq!(pk.algorithm, -7);
    assert_eq!(pk.sign_count, 3);
    assert_eq!(pk.created_at, 1_785_587_400);
    assert_eq!(pk.last_used_at, None);

    // 条目 2：纯密码条目（无 passkey / 无 URL / 无标签）
    let item2 = find_by_title(&st, "No Passkey Site");
    assert_eq!(
        field_bytes(&st, &item2.row.uuid, &Designation::Password),
        b"bob-password-2".to_vec()
    );
    assert!(repos
        .passkeys
        .list_for_item(&item2.row.uuid)
        .unwrap()
        .is_empty());
}

/// TCB-6（FR-10.6 双证据之一）：导入前后 password 字段逐字节不变（D-6）。
#[test]
fn fr10_密码字段逐字节不变() {
    let bw = fixture("login_with_passkey.json");
    let mut st = store();
    import_bitwarden_json_with_options(&bw, &mut st, &ImportOptions::default()).unwrap();

    let item = find_by_title(&st, "Example Site");
    assert_eq!(
        field_bytes(&st, &item.row.uuid, &Designation::Password),
        "P@ssw0rd-逐字节".as_bytes().to_vec(),
        "含 passkey 的条目照常携带密码字段入库，逐字节一致（D-6）"
    );
}

/// TCB-1④：预检只读、可反复调用，不落库。
#[test]
fn 预检只读可反复调用() {
    let bw = fixture("login_with_passkey.json");
    let st = store();

    let r1 = precheck_bitwarden_json(&bw).unwrap();
    let r2 = precheck_bitwarden_json(&bw).unwrap();
    assert_eq!(r1, r2, "两次预检结果一致");
    assert_eq!(st.repos().items.count(None).unwrap(), 0, "预检不落库");
}

/// TCB-7：非 ES256 / 坏 passkey 行 → 预检显式列出；导入跳过该行不丢条目。
#[test]
fn 坏passkey行显式列出且不丢条目() {
    let bw = fixture("passkey_variants.json");
    let mut st = store();

    let report = precheck_bitwarden_json(&bw).unwrap();
    // 7 条目全部可导入（降级 / 回收站均计入）
    assert_eq!(report.total_items, 7);
    assert_eq!(report.importable_items, 7);
    // passkey 行合计 6：可导入 1（SEC1）、非 ES256 1、坏行 4
    //（坏 credentialId / EncString 私钥 / 缺 rpId / 负 counter）
    assert_eq!(report.passkey_total, 6);
    assert_eq!(report.passkey_importable, 1);
    assert_eq!(report.non_es256.len(), 1, "非 ES256 显式列出（TCB-7）");
    assert_eq!(report.non_es256[0].item_id, "bw-p384");
    assert_eq!(report.bad_passkeys.len(), 4, "坏行逐条列出（FR-7.8 纪律）");
    let bad_items: Vec<&str> = report
        .bad_passkeys
        .iter()
        .map(|f| f.item_id.as_str())
        .collect();
    assert!(bad_items.contains(&"bw-badcred"));
    assert!(bad_items.contains(&"bw-encstring"));
    assert!(bad_items.contains(&"bw-twobad"));
    // EncString 私钥的拒绝原因须点明「加密形态」（真实样本形态，TCB-1 注记）
    let enc = report
        .bad_passkeys
        .iter()
        .find(|f| f.item_id == "bw-encstring")
        .unwrap();
    assert!(
        enc.reason.contains("加密"),
        "EncString 私钥原因须可操作：{}",
        enc.reason
    );

    assert_eq!(report.password_history_dropped, 1);
    assert_eq!(report.trashed_count, 1);

    // 导入：全部条目落库，仅 SEC1 条目有 1 条 passkey 行
    let result =
        import_bitwarden_json_with_options(&bw, &mut st, &ImportOptions::default()).unwrap();
    assert_eq!(result.imported_items, 7);
    let repos = st.repos();
    assert_eq!(repos.items.count(None).unwrap(), 7);

    let sec1 = find_by_title(&st, "Sec1 Key Item");
    let pks = repos.passkeys.list_for_item(&sec1.row.uuid).unwrap();
    assert_eq!(pks.len(), 1);
    assert_eq!(pks[0].rp_id, "sec1.example.com");

    // 坏行条目照常导入、无 passkey 行（跳行不丢条目）
    for title in [
        "Non ES256 Item",
        "Bad CredentialId Item",
        "EncString Key Item",
        "Two Bad Rows Item",
    ] {
        let item = find_by_title(&st, title);
        assert!(
            repos
                .passkeys
                .list_for_item(&item.row.uuid)
                .unwrap()
                .is_empty(),
            "{title} 不应有 passkey 行"
        );
    }

    // 降级 card：SecureNote + 原数据并入备注（E-4 同款，不静默丢弃）
    let card = find_by_title(&st, "Bank Card");
    assert_eq!(card.row.category, ItemCategory::SecureNote);
    let notes = repos
        .fields
        .read_fields_for_item(&card.row.uuid)
        .unwrap()
        .into_iter()
        .find(|f| f.designation.as_ref() == Some(&Designation::NotesPlain))
        .unwrap();
    let notes_text = notes
        .value
        .as_ref()
        .map(|v| v.expose().to_owned())
        .unwrap_or_default();
    assert!(notes_text.contains("CAROL BLACK"), "card 数据并入备注");
    assert!(notes_text.contains("原备注"), "原备注保留");

    // 回收站条目
    let trashed = find_by_title(&st, "Trashed Item");
    assert_eq!(trashed.row.state, ItemState::Trashed);
    assert_eq!(trashed.row.trashed_at, Some(1_784_534_400));
}

/// TCB-7：PKCS#8 归一化——SEC1（RFC 5915）与 PKCS#8 两种来源编码均可导入
/// （字节级等值断言在 src 内映射层单测：归一化纯函数对同一密钥的两种
/// 编码产出同一 PKCS#8 DER）。
#[test]
fn sec1来源与pkcs8来源均可导入() {
    let main = fixture("login_with_passkey.json");
    let st = store();
    let r = precheck_bitwarden_json(&main).unwrap();
    assert_eq!(r.passkey_importable, 1, "PKCS#8 来源可导入");

    let var = fixture("passkey_variants.json");
    let r = precheck_bitwarden_json(&var).unwrap();
    assert_eq!(r.passkey_importable, 1, "SEC1 来源可导入（归一化成功）");
    assert_eq!(st.repos().items.count(None).unwrap(), 0, "预检不落库");
}

/// TCB-1：DoS 上限——文件 ≤ 50 MB / items ≤ 10 000 / 单字段 ≤ 64 KiB，
/// 超限报错并指明条目。
#[test]
fn dos_上限超限报错() {
    // 单字段超限：一个条目带 64 KiB + 1 字节的 name
    let big = "A".repeat(64 * 1024 + 1);
    let json = format!(
        r#"{{"encrypted":false,"items":[{{"id":"bw-big","type":1,"name":"{big}","login":{{}}}}]}}"#
    );
    let mut st = store();
    let err = import_str(&json, &mut st).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("bw-big")),
        "错误须指明条目：{err:?}"
    );
    assert_eq!(st.repos().items.count(None).unwrap(), 0);

    // 条目数超限：10 001 条
    let items: Vec<String> = (0..10_001)
        .map(|i| format!(r#"{{"id":"i{i}","type":1,"name":"n{i}","login":{{}}}}"#))
        .collect();
    let json = format!(r#"{{"encrypted":false,"items":[{}]}}"#, items.join(","));
    let mut st = store();
    let err = import_str(&json, &mut st).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("10000")),
        "条目数超限须报错：{err:?}"
    );
    assert_eq!(st.repos().items.count(None).unwrap(), 0);

    // 文件超限：50 MB + 1 字节（真实落盘文件）
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("big.json");
    std::fs::write(&path, vec![b' '; 50 * 1024 * 1024 + 1]).unwrap();
    let err = precheck_bitwarden_json(&path).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("50")),
        "文件超限须报错：{err:?}"
    );
}

/// TCB-7：加密导出（password-protected）整体拒绝——不以密文当明文入库。
#[test]
fn 加密导出整体拒绝() {
    let bw = fixture("encrypted_export.json");
    let st = store();
    let err = precheck_bitwarden_json(&bw).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("加密")),
        "加密导出须报错：{err:?}"
    );
    assert_eq!(st.repos().items.count(None).unwrap(), 0);
}

/// 格式边界：非 JSON / 缺 items 的 JSON → 2001 格式不识别。
#[test]
fn 非法格式整体拒绝() {
    let tmp = tempfile::tempdir().unwrap();
    let st = store();

    let p1 = tmp.path().join("not-json.json");
    std::fs::write(&p1, b"this is not json").unwrap();
    let err = precheck_bitwarden_json(&p1).unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportUnknownFormat));

    let p2 = tmp.path().join("no-items.json");
    std::fs::write(&p2, br#"{"foo": 1}"#).unwrap();
    let err = precheck_bitwarden_json(&p2).unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportUnknownFormat));

    assert_eq!(st.repos().items.count(None).unwrap(), 0, "整体拒绝不落库");
}

/// TCB-1③：逐条目事务——中途注入失败回滚该条目（含其 passkey 行），
/// 已成功条目保留。
#[test]
fn 导入中途失败该条回滚已成功保留() {
    let bw = fixture("login_with_passkey.json");
    let mut st = store();
    let err = import_bitwarden_json_with_options(
        &bw,
        &mut st,
        &ImportOptions {
            fail_after_rows: Some(1),
        },
    )
    .unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportFailed(_)));

    let repos = st.repos();
    assert_eq!(repos.items.count(None).unwrap(), 1, "第 1 条已提交保留");
    assert_eq!(repos.meta.item_count().unwrap(), 1, "meta 计数随事务");

    // 已提交条目 = 第 1 条（Example Site），其 passkey 行随同事务保留
    let kept = find_by_title(&st, "Example Site");
    assert_eq!(
        repos.passkeys.list_for_item(&kept.row.uuid).unwrap().len(),
        1,
        "passkey 行与条目同事务落库"
    );
}
