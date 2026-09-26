//! T03 QA 对抗验证（独立于工程师自测的补充路径）。
//!
//! 验证重点（docs/07-macOS纵切设计.md §3 与 §7 T03 验收标准）：
//! 1. 解析器对抗输入：只含引号的文件、行数边界、64 KiB 字段边界（多字节）、
//!    引号内 CRLF、孤立 `\r`（QA-T03 F1 修复后报错）、UTF-8 多字节截断；
//! 2. 映射对抗：大小写混合、列顺序打乱、同义列重复、空文件 / 仅表头、
//!    行短于表头；
//! 3. 公式注入真实攻击向量：原值保留（钉死「库内即危险原串」的裁定语义）
//!    + 告警命中；
//! 4. 事务边界：fail_after_rows 注入第 1 行 / 中间行 / 全部行之后，
//!    以及 panic（unwind）路径的回滚；
//! 5. otpauth 合法变体（issuer 特殊字符、小写 secret、缺 digits/period）
//!    导入后 TOTP 可用（RFC 6238 Appendix B 向量）；坏 secret 行号准确；
//! 6. 端到端「报告即所得」：全部 fixture 的预检报告与落库结果一致。

use std::panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe};
use std::path::PathBuf;

use cf_crypto::subkeys::SubKeys;
use cf_domain::field::Designation;
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;
use cf_importer::csv::parser::{parse_csv, MAX_ROWS};
use cf_importer::{
    analyze_csv, import_csv, import_models, precheck_csv, CsvImportResult, ImportModel,
    ImportOptions,
};
use cf_store::{ItemListFilter, ItemRow, ItemStore};
use cf_totp::TotpConfig;

// ---------- 公共辅助 ----------

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/csv")
        .join(name)
}

fn store() -> ItemStore {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let keys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
    ItemStore::open(conn, keys).unwrap()
}

/// 预置一条既有条目（模拟导入前库里已有数据）。
fn insert_existing(store: &mut ItemStore, title: &str) -> String {
    store
        .with_tx(|repos| {
            let uuid = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: uuid.clone(),
                    category: cf_domain::category::ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_000,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed(title),
            )?;
            repos.meta.add_item_count(1)?;
            Ok(uuid)
        })
        .unwrap()
}

// ---------- 1. 解析器对抗 ----------

/// 只包含一个 `"` 的文件：引号未闭合，必须报错而非静默吞掉
#[test]
fn 只含单个引号的文件报错() {
    let err = parse_csv(b"\"").unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("引号未闭合")),
        "孤立引号应报「引号未闭合」：{err}"
    );
}

/// 只包含引号对的文件：偶数个引号解析层收尾后无可识别表头 → 格式校验拒绝；
/// 奇数个引号（如 `"""`）解析层直接报「引号未闭合」——均不允许产生可导入结果
#[test]
fn 只含引号对的文件被格式校验拒绝() {
    for input in ["\"\"", "\"\"\"\""] {
        let err = analyze_csv(input.as_bytes()).unwrap_err();
        assert!(
            matches!(err, cf_domain::CfError::ImportUnknownFormat),
            "输入 {input:?} 应被格式校验拒绝，实际 {err:?}"
        );
    }
    let err = analyze_csv(b"\"\"\"").unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("引号未闭合")),
        "奇数个引号应报未闭合：{err:?}"
    );
}

/// 行数边界：恰好 10 000 行数据放行（上限闭区间内合法）
#[test]
fn 行数恰好上限放行() {
    let mut csv = String::from("Title\n");
    for _ in 0..MAX_ROWS {
        csv.push_str("v\n");
    }
    let parsed = parse_csv(csv.as_bytes()).unwrap();
    assert_eq!(parsed.rows.len(), MAX_ROWS);
}

/// 单字段恰好 64 KiB：多字节字符（2 字节 é × 32768 = 65536 B）放行
#[test]
fn 多字节字段恰好64kib放行() {
    let field = "é".repeat(32_768);
    assert_eq!(field.len(), 64 * 1024);
    let parsed = parse_csv(format!("Title\n{field}\n").as_bytes()).unwrap();
    assert_eq!(parsed.rows[0].cells[0].len(), 64 * 1024);
}

/// 单字段 64 KiB + 1 字节（多字节字符内部越界）：拒绝并报行号
#[test]
fn 多字节字段超64kib拒绝() {
    let field = "é".repeat(32_768) + "x";
    let err = parse_csv(format!("Title\n{field}\n").as_bytes()).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("64 KiB")),
        "字段超限应报错：{err}"
    );
}

/// UTF-8 多字节字符被从中间截断：整体拒绝并提示转码
#[test]
fn utf8多字节截断拒绝() {
    // 「你」= E4 BD A0，砍掉最后一个字节
    let err = parse_csv(b"Title\n\xe4\xbd").unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("UTF-8")),
        "截断的多字节字符应报 UTF-8 错误：{err}"
    );
}

/// CRLF 只出现在引号字段内：归一为 LF，记录行号取起始行
#[test]
fn 引号内crlf归一并保持行号() {
    let parsed = parse_csv(b"Title\r\n\"a\r\nb\",x\r\n").unwrap();
    assert_eq!(parsed.rows.len(), 1);
    assert_eq!(parsed.rows[0].cells, vec!["a\nb", "x"]);
    assert_eq!(parsed.rows[0].line_no, 2, "记录行号取起始行");

    // 引号内 CRLF 之后文件在引号字段中间结束 → 报「引号未闭合」
    let err = parse_csv(b"Title\n\"x\r\n").unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("引号未闭合")),
        "引号内 CRLF 后 EOF 应报未闭合：{err}"
    );
}

/// 孤立 `\r`（老 Mac 行尾，RFC 4180 不认可）——【QA-T03 F1 已修复】
///
/// 修复后行为：引号外的裸 CR（后随非 LF 或位于 EOF）**显式报错**（与
/// 解析器严格模式哲学一致；RFC 4180 不认可裸 CR），错误信息提示可能
/// 是老 Mac 行尾文件。旧实现静默切分记录，会把行尾格式问题伪装成
/// 「导入成功」。
#[test]
fn 孤立cr报错并提示老mac行尾() {
    let err = parse_csv(b"Title,Website\rA,https://x\r").unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("孤立的 CR") && m.contains("老 Mac")),
        "裸 CR 应报错并提示老 Mac 行尾：{err}"
    );
    // EOF 处的裸 CR 同样拒绝
    let err = parse_csv(b"Title,Website\nA,https://x\r").unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("孤立的 CR")),
        "EOF 处裸 CR 同样应报错：{err}"
    );
    // CRLF 不受影响：记录仍正常切分
    let parsed = parse_csv(b"Title,Website\r\nA,https://x\r\n").unwrap();
    assert_eq!(parsed.header, vec!["Title", "Website"]);
    assert_eq!(parsed.rows.len(), 1);
    assert_eq!(parsed.rows[0].cells, vec!["A", "https://x"]);
}

/// 引号内孤立 `\r` 归一为 LF（QA-T03 F2 已澄清：注释已对齐实际行为）
#[test]
fn 引号内孤立cr归一为lf() {
    let parsed = parse_csv(b"Title\n\"a\rb\"\n").unwrap();
    assert_eq!(parsed.rows[0].cells, vec!["a\nb"], "引号内孤立 CR 归一为 LF");
}

/// 空引号字段 `""` 与后续列正常切分
#[test]
fn 空引号字段切分() {
    let parsed = parse_csv(b"Title,Website\n\"\",x\n").unwrap();
    assert_eq!(parsed.rows[0].cells, vec!["", "x"]);
}

// ---------- 2. 映射对抗 ----------

/// 表头大小写混合 + 列顺序完全打乱：映射结果与标准顺序一致（端到端读回）
#[test]
fn 表头大小写混合与列序打乱端到端() {
    let csv = "\
Tags,Notes,Title,One-Time Password,Website,Password,FAVORITE STATUS,Username,Archived Status\n\
t1;n2,备注内容,乱序条目,otpauth://totp/Ok:acct?secret=JBSWY3DPEHPK3PXP,https://s.example,pw1,true,user1,FALSE\n";
    let analysis = analyze_csv(csv.as_bytes()).unwrap();
    assert_eq!(analysis.report.valid_rows, 1);
    assert!(analysis.report.unmapped_columns.is_empty());
    assert!(analysis.report.warnings.is_empty(), "合法行不应有任何告警");

    let mut st = store();
    let result = import_models(&analysis.models, &mut st, &ImportOptions::default()).unwrap();
    assert_eq!(result.imported_rows, 1);

    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    assert_eq!(all[0].title.expose(), "乱序条目");
    assert!(all[0].row.is_favorite);
    assert_eq!(all[0].row.state, ItemState::Active, "FALSE 大小写不敏感");
    let uuid = &all[0].row.uuid;

    let urls = repos.urls.read_for_item(uuid).unwrap();
    assert_eq!(urls[0].url.expose(), "https://s.example");

    let fields = repos.fields.read_fields_for_item(uuid).unwrap();
    let get = |d: &Designation| -> String {
        fields
            .iter()
            .find(|f| f.designation.as_ref() == Some(d))
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(get(&Designation::Username), "user1");
    assert_eq!(get(&Designation::Password), "pw1");
    assert_eq!(get(&Designation::NotesPlain), "备注内容");

    let tags = repos.tags.read_for_item(uuid).unwrap();
    let mut names: Vec<String> = tags.iter().map(|t| t.name.expose().to_owned()).collect();
    names.sort();
    assert_eq!(names, vec!["n2", "t1"]);

    assert_eq!(repos.totp.totp_uuids_for_item(uuid).unwrap().len(), 1);
}

/// 同义列同时出现（两个 Title 列，大小写不同）：整文件拒绝
#[test]
fn 同义列同时出现整文件拒绝() {
    let csv = "Title,Website,tItLe,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\nA,,B,u,p,,false,false,,\n";
    let err = analyze_csv(csv.as_bytes()).unwrap_err();
    assert!(
        matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("重复列")),
        "重复规范列应整文件拒绝：{err:?}"
    );
}

/// 空文件 / 仅表头：空文件被格式校验拒绝；仅表头合法导入 0 条
#[test]
fn 空文件与仅表头() {
    let err = analyze_csv(b"").unwrap_err();
    assert!(matches!(err, cf_domain::CfError::ImportUnknownFormat), "空文件应报格式无法识别");

    let analysis = analyze_csv(
        "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\n".as_bytes(),
    )
    .unwrap();
    assert_eq!(analysis.report.total_rows, 0);
    assert_eq!(analysis.report.valid_rows, 0);
    assert_eq!(analysis.models.len(), 0);

    let mut st = store();
    let result = import_models(&analysis.models, &mut st, &ImportOptions::default()).unwrap();
    assert_eq!(result.imported_rows, 0);
    assert_eq!(st.repos().items.count(None).unwrap(), 0);
    assert_eq!(st.repos().meta.item_count().unwrap(), 0);
}

/// 行短于表头：缺失单元格按空处理，不 panic、不误报
#[test]
fn 行短于表头按空处理() {
    let analysis = analyze_csv(
        "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\n短行,https://x.example\n".as_bytes(),
    )
    .unwrap();
    assert_eq!(analysis.report.valid_rows, 1);
    assert_eq!(analysis.models.len(), 1);
    let m = &analysis.models[0];
    assert_eq!(m.title, "短行");
    assert_eq!(m.url.as_deref(), Some("https://x.example"));
    assert!(m.username.is_none());
    assert!(m.password.is_none());
    assert!(!m.is_favorite);
}

// ---------- 3. 公式注入语义 ----------

/// 真实攻击向量：`=cmd|' /C calc'!A0` ——原值原样入库（库内存的就是危险
/// 原串，docs/07 §3.2 裁定：防护主战场在导出侧），且预检告警命中
#[test]
fn 公式注入真实攻击向量原值保留且告警() {
    let csv = concat!(
        "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes,Evil\n",
        "Calc,https://c.example,=cmd|' /C calc'!A0,=p@ss,,false,false,,-1+SUM(A1),\n",
        "AtPrefix,,@import_excel,,,,,,,@SUM(1)\n",
    );
    let analysis = analyze_csv(csv.as_bytes()).unwrap();
    let report = &analysis.report;
    assert_eq!(report.valid_rows, 2);

    let cols: Vec<(u32, &str)> = report
        .formula_like_cells
        .iter()
        .map(|(l, c)| (*l, c.as_str()))
        .collect();
    assert_eq!(
        cols,
        vec![(2, "username"), (2, "notes"), (3, "username"), (3, "Evil")],
        "Username / Notes / 未映射列告警，Password 不告警"
    );
    assert!(
        report.warnings.iter().any(|w| w.contains("公式前缀")),
        "warnings 应包含公式前缀提示：{:?}",
        report.warnings
    );

    // 导入后逐字节读回：库内存的必须是危险原串（不修改原值裁定）
    let mut st = store();
    import_models(&analysis.models, &mut st, &ImportOptions::default()).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();
    let calc = all.iter().find(|i| i.title.expose() == "Calc").unwrap();
    let fields = repos.fields.read_fields_for_item(&calc.row.uuid).unwrap();
    let value_of = |d: &Designation| -> String {
        fields
            .iter()
            .find(|f| f.designation.as_ref() == Some(d))
            .and_then(|f| f.value.as_ref())
            .map(|v| v.expose().to_owned())
            .unwrap_or_default()
    };
    assert_eq!(
        value_of(&Designation::Username),
        "=cmd|' /C calc'!A0",
        "原值保留：库内存的就是危险原串（导出侧防护的输入前提）"
    );
    assert_eq!(value_of(&Designation::Password), "=p@ss", "Password 列原值保留且不告警");
    assert_eq!(value_of(&Designation::NotesPlain), "-1+SUM(A1)");
}

// ---------- 4. 事务边界 ----------

/// fail_after_rows 注入：第 1 行前（0）/ 中间行前（2）/ 最后一行前（4），
/// 三种位置回滚后既有条目与 item_count 均完全不变。
/// （注入点语义 = 「写入下标 N 的行之前」失败，下标 0 起且恒 < 行数，
/// 故不存在「全部行写完之后」的可注入位置。）
#[test]
fn 事务注入三种位置回滚零残留() {
    for fail_at in [0u32, 2, 4] {
        let mut st = store();
        let existing = insert_existing(&mut st, "既有条目");
        let before_count = st.repos().items.count(None).unwrap();
        let before_meta = st.repos().meta.item_count().unwrap();

        let models: Vec<ImportModel> = (0..5)
            .map(|i| ImportModel {
                title: format!("条目{i}"),
                url: Some(format!("https://{i}.example")),
                username: Some(format!("user{i}")),
                password: Some(format!("pw{i}")),
                totp: None,
                is_favorite: false,
                archived: false,
                tags: vec![format!("tag{i}")],
                notes: format!("note{i}"),
            })
            .collect();
        let err =
            import_models(&models, &mut st, &ImportOptions { fail_after_rows: Some(fail_at) })
                .unwrap_err();
        assert!(
            matches!(err, cf_domain::CfError::ImportFailed(ref m) if m.contains("注入")),
            "fail_at={fail_at} 应返回注入错误：{err:?}"
        );

        let repos = st.repos();
        assert_eq!(
            repos.items.count(None).unwrap(),
            before_count,
            "fail_at={fail_at}：回滚后条目数不变"
        );
        assert_eq!(
            repos.meta.item_count().unwrap(),
            before_meta,
            "fail_at={fail_at}：回滚后 item_count 不变"
        );
        let kept = repos.items.get_row(&existing).unwrap();
        assert!(kept.is_some(), "fail_at={fail_at}：既有条目仍在");
        assert_eq!(kept.unwrap().uuid, existing);
        assert!(repos
            .items
            .list(&ItemListFilter::default())
            .unwrap()
            .iter()
            .all(|i| i.row.uuid == existing));
    }
}

/// panic（unwind）路径：with_tx 闭包内 panic → Transaction drop 兜底回滚。
/// import_csv 依赖的正是这条事务框架语义（公开 API 层面无法向
/// import_models 内部注入 panic，故在 cf-store::with_tx 层验证）。
#[test]
fn 事务内panic回滚() {
    let prev_hook = take_hook();
    set_hook(Box::new(|_| {})); // 抑制预期 panic 的stderr 噪音

    let mut st = store();
    insert_existing(&mut st, "既有条目");
    let before = st.repos().items.count(None).unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = st.with_tx(|repos| {
            let uuid = uuid::Uuid::now_v7().to_string();
            repos.items.insert(
                &ItemRow {
                    uuid: uuid.clone(),
                    category: cf_domain::category::ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 1_700_000_000,
                    updated_at: 1_700_000_000,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("panic 前写入"),
            )?;
            repos.meta.add_item_count(1)?;
            panic!("注入的事务内 panic");
            #[allow(unreachable_code)]
            Ok::<(), cf_domain::CfError>(())
        });
    }));
    assert!(result.is_err(), "panic 应被 catch_unwind 捕获");

    set_hook(prev_hook);

    let repos = st.repos();
    assert_eq!(repos.items.count(None).unwrap(), before, "panic unwind 后必须零残留");
    assert_eq!(repos.meta.item_count().unwrap(), before, "item_count 必须随事务回滚");
    // 连接在 unwind 后仍然可用
    assert_eq!(repos.items.list(&ItemListFilter::default()).unwrap().len(), 1);
}

// ---------- 5. otpauth ----------

/// 合法 URI 变体（issuer 特殊字符 percent 解码、小写 secret、
/// 缺 digits/period 取默认值）各导一条；RFC 6238 向量验证 TOTP 可用
#[test]
fn otpauth合法变体导入且totp可用() {
    let csv = concat!(
        "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\n",
        // RFC 6238 Appendix B（SHA-1）：T=59 / 8 位 → 94287082
        "RfcVector,,u,p,otpauth://totp/RFC:vector?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30,false,false,,\n",
        // issuer 特殊字符（空格 / & / = percent 编码）、账户含斜杠
        "SpecialIssuer,,u,p,otpauth://totp/My%20Bank%26Co:alice%2Fprod?secret=JBSWY3DPEHPK3PXP&issuer=My%20Bank%26Co%3D,false,false,,\n",
        // 小写 secret、缺 digits/period（默认 6 位 / 30 s）
        "LowercaseSecret,,u,p,otpauth://totp/Ok:acct?secret=jbswy3dpehpk3pxp,false,false,,\n",
    );
    let analysis = analyze_csv(csv.as_bytes()).unwrap();
    assert!(analysis.report.rows_with_bad_totp.is_empty(), "三条都应合法");
    assert_eq!(analysis.report.valid_rows, 3);

    let mut st = store();
    import_models(&analysis.models, &mut st, &ImportOptions::default()).unwrap();
    let repos = st.repos();
    let all = repos.items.list(&ItemListFilter::default()).unwrap();

    // 变体 1：RFC 向量 —— 导入后用库内 secret 生成验证码，与标准向量一致
    let rfc = all.iter().find(|i| i.title.expose() == "RfcVector").unwrap();
    let totp_uuids = repos.totp.totp_uuids_for_item(&rfc.row.uuid).unwrap();
    assert_eq!(totp_uuids.len(), 1);
    let meta = repos.totp.totp_meta(&totp_uuids[0]).unwrap().unwrap();
    assert_eq!((meta.digits, meta.period), (8, 30));
    let secret = repos.totp.totp_secret(&totp_uuids[0]).unwrap().unwrap();
    let cfg = TotpConfig::new((*secret).clone(), meta.period, meta.digits).unwrap();
    assert_eq!(
        cfg.generate_for_counter(1).unwrap(),
        "94287082",
        "RFC 6238 Appendix B SHA-1 向量（T=59, 8 位）"
    );

    // 变体 2：issuer / account percent 解码正确
    let special = all.iter().find(|i| i.title.expose() == "SpecialIssuer").unwrap();
    let su = repos.totp.totp_uuids_for_item(&special.row.uuid).unwrap();
    let smeta = repos.totp.totp_meta(&su[0]).unwrap().unwrap();
    assert_eq!(smeta.issuer.as_deref(), Some("My Bank&Co="));
    assert_eq!(smeta.account.as_deref(), Some("alice/prod"));

    // 变体 3：小写 secret、默认 digits/period
    let lower = all.iter().find(|i| i.title.expose() == "LowercaseSecret").unwrap();
    let lu = repos.totp.totp_uuids_for_item(&lower.row.uuid).unwrap();
    let lmeta = repos.totp.totp_meta(&lu[0]).unwrap().unwrap();
    assert_eq!((lmeta.digits, lmeta.period), (6, 30), "缺省参数取默认值");
    let lsecret = repos.totp.totp_secret(&lu[0]).unwrap().unwrap();
    assert_eq!(lsecret.len(), 10, "小写 Base32 解码出同样 10 字节");
}

/// 非 Base32 字符集的 secret（`0`/`1`/`!`）：拒绝且行号逐行准确
#[test]
fn 坏secret拒绝行号准确() {
    let csv = concat!(
        "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\n",
        "Ok1,,u,p,otpauth://totp/Ok?secret=JBSWY3DPEHPK3PXP,false,false,,\n",
        "Ok2,,u,p,otpauth://totp/Ok?secret=JBSWY3DPEHPK3PXP,false,false,,\n",
        "Digit0,,u,p,otpauth://totp/Bad?secret=JBSWY3DPEHPK3PX0,false,false,,\n",
        "Bang,,u,p,otpauth://totp/Bad?secret=NOT!BASE32,false,false,,\n",
        "Ok3,,u,p,otpauth://totp/Ok?secret=JBSWY3DPEHPK3PXP,false,false,,\n",
    );
    let analysis = analyze_csv(csv.as_bytes()).unwrap();
    assert_eq!(
        analysis.report.rows_with_bad_totp,
        vec![4, 5],
        "文件行号（表头为第 1 行）必须逐行准确"
    );
    assert_eq!(analysis.report.valid_rows, 5, "坏 otpauth 的行仍导入（原值并入备注）");
    // 坏行原始 URI 保留在 notes
    for title in ["Digit0", "Bang"] {
        let m = analysis
            .models
            .iter()
            .find(|m| m.title == title)
            .unwrap_or_else(|| panic!("模型缺失 {title}"));
        assert!(
            m.notes.contains("[One-time password 无法解析，已保留原始值]"),
            "{title} 备注缺前缀：{}",
            m.notes
        );
        assert!(m.notes.contains("otpauth://totp/"), "{title} 备注缺原始 URI");
    }
}

// ---------- 6. 端到端「报告即所得」 ----------

/// 全部 fixture：precheck → import → ItemStore 读回，
/// 断言 imported_rows / items.count / meta.item_count 与预检 valid_rows 一致；
/// invalid_utf8 单独断言整体拒绝
#[test]
fn 全fixture报告即所得() {
    // (文件名, 预期 valid_rows)；invalid_utf8 预期整体拒绝，单独测
    let cases: [(&str, u32); 9] = [
        ("good_basic.csv", 3),
        ("bom_crlf.csv", 1),
        ("quoted_newline.csv", 1),
        ("formula_prefix.csv", 2),
        ("bad_otpauth.csv", 4),
        ("unknown_column.csv", 1),
        ("no_title.csv", 1),
        ("duplicate_titles.csv", 3),
        ("archived_row.csv", 1),
    ];

    for (name, expected_valid) in cases {
        let report = precheck_csv(&fixture(name)).unwrap();
        assert_eq!(report.valid_rows, expected_valid, "{name} 预检 valid_rows");

        let mut st = store();
        let result: CsvImportResult = import_csv(&fixture(name), &mut st).unwrap();
        assert_eq!(result.imported_rows, report.valid_rows, "{name} 导入数应等于预检 valid_rows");

        let repos = st.repos();
        assert_eq!(
            repos.items.count(None).unwrap(),
            i64::from(report.valid_rows),
            "{name} 条目数应等于预检 valid_rows"
        );
        assert_eq!(
            repos.meta.item_count().unwrap(),
            i64::from(report.valid_rows),
            "{name} meta.item_count 应等于预检 valid_rows"
        );
        // 全空行跳过语义：skipped 行不落库
        let expected_total_rows = report.valid_rows + u32::try_from(report.skipped_rows.len()).unwrap_or(u32::MAX);
        assert_eq!(report.total_rows, expected_total_rows, "{name} total = valid + skipped");
    }

    // invalid_utf8：整体拒绝，库零影响
    let mut st = store();
    insert_existing(&mut st, "既有条目");
    let before = st.repos().items.count(None).unwrap();
    assert!(precheck_csv(&fixture("invalid_utf8.csv")).is_err());
    assert!(import_csv(&fixture("invalid_utf8.csv"), &mut st).is_err());
    assert_eq!(st.repos().items.count(None).unwrap(), before, "被拒文件不得影响既有数据");
}
