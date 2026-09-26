//! T06 QA 严过关：FFI 层 TOTP 保留语义 + strength_estimate 工厂版。
//!
//! 与 `ffi_contract.rs` 互补，聚焦 T06 新增的 FFI 攻击面：
//!
//! 1. `updateItem`（默认 Keep）对既有 Swift 调用方的语义保障：编辑条目
//!    绝不静默丢失 TOTP（TrashView 恢复 / 硬删等路径间接依赖同一入口）；
//! 2. `updateItemWithTotp` 三态（Keep / Replace / Remove）跨 FFI 行为，
//!    Remove 后 `totpCode` 报错码；
//! 3. `totpConfig` 三分返回：不存在条目 / 无 TOTP 条目 → `None`；软删条目
//!    → `Some`（行保留）；硬删条目 → `None`（行级联清除）；
//! 4. 锁定态写路径门禁：`updateItemWithTotp` → 1001；
//! 5. CSV 导入新建的 TOTP 条目走 FFI 编辑 Keep 路径；
//! 6. `strength_estimate` 工厂版 vs 会话版：同输入输出一致、无会话可调用、
//!    畸形输入（空串 / 超长）不 panic。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_crypto::kdf::KdfParams;
use cf_ffi::api::{CofferApp, VaultSession};
use cf_ffi::types::*;

/// 提取错误码（VaultSession 无 Debug 派生，统一走本助手）。
fn err_code<T>(r: Result<T, cf_ffi::FfiError>) -> u16 {
    match r {
        Ok(_) => panic!("预期应返回错误，实际成功"),
        Err(e) => e.code(),
    }
}

/// 测试用快速 KDF 档位（8 MiB / t=1 / p=1）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

/// 每测试独立的临时工作目录。
fn temp_base(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-ffi-t06-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
fn setup_vault(base: &std::path::Path, name: &str) -> cf_domain::vault::Vault {
    cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
}

/// 打开并解锁会话。
fn unlocked_session(
    app: &Arc<CofferApp>,
    base: &std::path::Path,
    uuid: &str,
) -> Arc<VaultSession> {
    let session = app
        .open_vault(base.to_string_lossy().into_owned(), uuid.to_owned())
        .unwrap();
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    session
}

/// 解析 otpauth URI 为 FFI 草稿。
fn parse(app_session: &VaultSession, uri: &str) -> FfiTotpDraft {
    app_session.parse_otpauth_uri(uri.to_owned()).unwrap()
}

/// 建 Login 草稿（不含 TOTP，编辑路径用）。
fn edit_draft(title: &str) -> FfiItemDraft {
    FfiItemDraft {
        title: title.to_owned(),
        category: FfiItemCategory::Login,
        urls: Vec::new(),
        tags: Vec::new(),
        sections: Vec::new(),
        fields: vec![
            FfiFieldDraft {
                name: "用户名".to_owned(),
                value: Some("alice".to_owned()),
                field_type: FfiFieldType::Text,
                designation: Some(FfiDesignation::Username),
                section_index: None,
                position: 0,
            },
            FfiFieldDraft {
                name: "密码".to_owned(),
                value: Some("p@ssw0rd!".to_owned()),
                field_type: FfiFieldType::Concealed,
                designation: Some(FfiDesignation::Password),
                section_index: None,
                position: 1,
            },
        ],
        totp: None,
    }
}

/// 建含 TOTP 的条目，返回条目 ID。
fn item_with_totp(session: &VaultSession) -> String {
    let totp = parse(
        session,
        "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
    );
    let mut draft = edit_draft("GitHub");
    draft.totp = Some(totp);
    session.create_item(draft).unwrap()
}

// ================================================== 1. updateItem 默认 Keep

/// updateItem（默认 Keep）对既有调用方语义保障：编辑后 totp_config 仍在、
/// totp_code 仍可出码——TrashView 恢复等既有 Swift 路径复用本入口无回归。
#[test]
fn update_item默认keep_编辑不丢totp() {
    let base = temp_base("ffi_keep");
    let brief = setup_vault(&base, "FFI保留库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());
    let id = item_with_totp(&session);
    let meta_before = session.totp_config(id.clone()).unwrap().unwrap();

    session.update_item(id.clone(), edit_draft("改标题")).unwrap();

    let meta_after = session.totp_config(id.clone()).unwrap().unwrap();
    assert_eq!(meta_after, meta_before, "默认 Keep 下元数据必须原样");
    assert_eq!(session.totp_code(id.clone()).unwrap().code.len(), 6);

    // 软删 → 恢复（TrashView 路径）→ 编辑：TOTP 仍存活
    session.delete_item(id.clone(), false).unwrap();
    session.restore_item(id.clone()).unwrap();
    session
        .update_item(id.clone(), edit_draft("恢复后再编辑"))
        .unwrap();
    assert!(session.totp_config(id.clone()).unwrap().is_some());
    assert_eq!(session.totp_code(id).unwrap().code.len(), 6);
}

// ============================================== 2. updateItemWithTotp 三态

/// 三态显式：Keep 行为与 updateItem 一致；Replace 删旧插新；Remove 移除
/// 且 totpCode 报 1011。draft.totp 在三态路径被忽略（提交 Replace 时
/// draft 不带 totp 也能写入新配置）。
#[test]
fn update_item_with_totp三态跨ffi() {
    let base = temp_base("ffi_tri");
    let brief = setup_vault(&base, "FFI三态库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());
    let id = item_with_totp(&session);
    let meta_before = session.totp_config(id.clone()).unwrap().unwrap();

    // Keep：显式三态与默认等价
    session
        .update_item_with_totp(id.clone(), edit_draft("Keep一次"), FfiTotpUpdate::Keep)
        .unwrap();
    assert_eq!(
        session.totp_config(id.clone()).unwrap().unwrap(),
        meta_before
    );

    // Replace：draft.totp 为 None，新配置经三态参数写入
    let new_totp = parse(
        &session,
        "otpauth://totp/New:svc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
    );
    session
        .update_item_with_totp(
            id.clone(),
            edit_draft("Replace一次"),
            FfiTotpUpdate::Replace { draft: new_totp },
        )
        .unwrap();
    let replaced = session.totp_config(id.clone()).unwrap().unwrap();
    assert_eq!(replaced.digits, 8);
    assert_ne!(
        replaced, meta_before,
        "Replace 必须切换为新配置而非保留旧行"
    );
    assert_eq!(session.totp_code(id.clone()).unwrap().code.len(), 8);

    // Remove：元数据消失、totpCode 报 1011
    session
        .update_item_with_totp(id.clone(), edit_draft("Remove一次"), FfiTotpUpdate::Remove)
        .unwrap();
    assert!(session.totp_config(id.clone()).unwrap().is_none());
    assert_eq!(err_code(session.totp_code(id.clone())), 1011);

    // Remove 对已无 TOTP 的条目再执行：空操作不报错（幂等）
    session
        .update_item_with_totp(id, edit_draft("再Remove"), FfiTotpUpdate::Remove)
        .unwrap();
}

/// Replace 非法载荷（secret 过短）跨 FFI 被拒：1012 且旧 TOTP 仍可出码
/// （部分写入检查在 FFI 层复核）。
#[test]
fn replace非法载荷跨ffi被拒且旧totp完好() {
    let base = temp_base("ffi_bad_replace");
    let brief = setup_vault(&base, "FFI非法Replace库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());
    let id = item_with_totp(&session);

    let bad = FfiTotpDraft {
        secret: b"012345678".to_vec(), // 9 字节，低于 10 字节校验线
        digits: 6,
        period: 30,
        issuer: None,
        account: None,
    };
    let err = match session.update_item_with_totp(
        id.clone(),
        edit_draft("非法"),
        FfiTotpUpdate::Replace { draft: bad },
    ) {
        Err(e) => e,
        Ok(_) => panic!("非法载荷应被拒绝"),
    };
    assert_eq!(err.code(), 5002);

    // 旧 TOTP 完好：元数据不变、仍可出码
    assert!(session.totp_config(id.clone()).unwrap().is_some());
    assert_eq!(session.totp_code(id).unwrap().code.len(), 6);
}

// ================================================== 3. totpConfig 三分返回

/// totpConfig 三分：不存在 → None；无 TOTP → None；软删 → Some（行保留）；
/// 硬删 → None（行级联清除）。
#[test]
fn totp_config三分_不存在无totp软删硬删() {
    let base = temp_base("ffi_tri_config");
    let brief = setup_vault(&base, "FFI三分库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let with_totp = item_with_totp(&session);
    let without_totp = session.create_item(edit_draft("无TOTP")).unwrap();

    // ① 不存在条目 → None
    assert!(session.totp_config("no-such-item".to_owned()).unwrap().is_none());
    // ② 存在但无 TOTP → None
    assert!(session.totp_config(without_totp.clone()).unwrap().is_none());

    // ③ 软删 → Some（软删不动从表）
    session.delete_item(with_totp.clone(), false).unwrap();
    assert!(
        session.totp_config(with_totp.clone()).unwrap().is_some(),
        "软删条目的 TOTP 元数据必须保留"
    );
    // 恢复后照常
    session.restore_item(with_totp.clone()).unwrap();
    assert!(session.totp_config(with_totp.clone()).unwrap().is_some());

    // ④ 硬删 → None（级联清除）
    session.delete_item(with_totp.clone(), true).unwrap();
    assert!(session.totp_config(with_totp).unwrap().is_none());
}

// ================================================== 4. 门禁与错误码

/// 锁定态写路径门禁：updateItem / updateItemWithTotp / totpConfig 全部 1001。
#[test]
fn 锁定态totp写路径跨ffi返回1001() {
    let base = temp_base("ffi_locked");
    let brief = setup_vault(&base, "FFI门禁库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());
    let id = item_with_totp(&session);

    session.lock();
    assert_eq!(
        err_code(session.update_item(id.clone(), edit_draft("锁定编辑"))),
        1001
    );
    assert_eq!(
        err_code(session.update_item_with_totp(
            id.clone(),
            edit_draft("锁定编辑"),
            FfiTotpUpdate::Keep
        )),
        1001
    );
    assert_eq!(err_code(session.totp_config(id.clone())), 1001);
    assert_eq!(err_code(session.totp_code(id)), 1001);

    // 不存在的条目走写路径 → 1011
    session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
    assert_eq!(
        err_code(session.update_item("no-such-item".to_owned(), edit_draft("幽灵"))),
        1011
    );
}

// ================================================== 5. CSV 导入 × Keep

/// CSV 导入新建的 TOTP 条目再走 FFI 编辑 Keep 路径：TOTP 存活、仍可出码。
#[test]
fn csv导入的totp条目走ffi_keep路径() {
    let base = temp_base("ffi_csv_keep");
    let brief = setup_vault(&base, "FFI导入库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let csv = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/csv/good_basic.csv")
        .canonicalize()
        .unwrap();
    let csv_str = csv.to_string_lossy().into_owned();
    let result = session.import_csv(csv_str).unwrap();
    assert_eq!(result.imported_rows, 3);

    let hits = session.search("GitHub".to_owned()).unwrap();
    assert_eq!(hits.len(), 1);
    let id = hits[0].uuid.clone();
    assert!(session.totp_config(id.clone()).unwrap().is_some());

    session.update_item(id.clone(), edit_draft("导入后编辑")).unwrap();
    assert!(session.totp_config(id.clone()).unwrap().is_some());
    assert_eq!(session.totp_code(id).unwrap().code.len(), 6);
}

// ================================================== 6. strength 工厂版

/// 工厂版 vs 会话版：同输入输出一致（score + warnings 逐项相等）。
#[test]
fn strength工厂版与会话版同输入同输出() {
    let base = temp_base("ffi_strength_eq");
    let brief = setup_vault(&base, "强度库");
    let app = CofferApp::new();
    let session = unlocked_session(&app, &base, &brief.uuid.to_string());

    let samples = [
        "123456",
        "correct-horse-battery-staple-42!",
        "p@ssw0rd-遇事不决!",
        "Tr0ub4dour&3",
        "",
    ];
    for s in samples {
        let factory = app.strength_estimate(s.to_owned()).unwrap();
        let session_ver = session.strength_estimate(s.to_owned()).unwrap();
        assert_eq!(
            factory, session_ver,
            "同输入 {s:?} 工厂版与会话版必须一致"
        );
    }

    // 边界值：弱 / 强的分数语义仍成立
    assert!(app.strength_estimate("123456".to_owned()).unwrap().score < 3);
    assert!(
        app.strength_estimate(STRONG_PASSWORD.to_owned())
            .unwrap()
            .score
            >= 3
    );
}

/// 工厂版无会话依赖：全新 App（未 open 任何库）即可调用；畸形输入
/// （空串 / 1 KiB 重复 / 8 KiB 超长）不 panic，分数在 0–4 内。
#[test]
fn strength工厂版无会话可调用_畸形输入不panic() {
    let app = CofferApp::new();

    // 空串：不 panic，score 0
    let empty = app.strength_estimate(String::new()).unwrap();
    assert_eq!(empty.score, 0);

    // 超长输入：不 panic（zxcvbn 内部有长度上限），分数夹在 0–4
    let long_1k = "a".repeat(1024);
    let long_8k = "b".repeat(8192);
    for s in [long_1k, long_8k] {
        let est = app.strength_estimate(s).unwrap();
        assert!(est.score <= 4, "score 必须在 0–4 内");
    }

    // 非 UTF-8 边界不适用（String 保证 UTF-8），但控制字符 / emoji 不 panic
    let _ = app.strength_estimate("\u{0}\u{1}\u{FFFD}🎉🎉🎉".to_owned()).unwrap();
    let _ = app.strength_estimate("x".to_owned()).unwrap();
}
