//! NFR-REL-02/03 解锁路径完整性校验端到端测试
//! （docs/09 §2 v0.2-T04，docs/10 §11.5 TC-MAC-06）。
//!
//! 判据：篡改 db 后 `open_vault` + 正确密码 `unlock` → `1002`
//! （不泄露「完整性失败」细节，FR-1.4 不可区分性延伸到完整性路径——
//! 与密码错、wrapped_dek/verifier 篡改同码）。正常 unlock 不得回归；
//! 首次 unlock 触发 meta 基线自举（旧库兼容，TC-MAC-04 的端到端面）。
//!
//! 独立成文件（不并入 integration.rs）：与 dev-tester 并行补写的
//! TC-BKO/TC-CLP 用例隔离，避免并发写冲突（lead 2026-09-29 分区裁定）。

use std::fs;
use std::path::PathBuf;

use cf_crypto::kdf::KdfParams;
use cf_session::unlock::{create_vault_with_kdf, open_vault};

/// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
const STRONG: &str = "correct-horse-battery-staple-42!";

/// 测试用快速 KDF 档位（与 integration.rs 一致）。
fn fast_kdf() -> KdfParams {
    KdfParams::new(8 * 1024, 1, 1).unwrap()
}

/// 唯一临时目录（pid + 纳秒）。
fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "cf-session-mac-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// 建库并返回库目录。
fn fresh_vault(tag: &str) -> PathBuf {
    let base = temp_dir(tag);
    let brief = create_vault_with_kdf(&base, tag, STRONG, fast_kdf()).unwrap();
    base.join(brief.uuid.to_string())
}

/// TC-MAC-06（正向面）：正常建库 → 解锁通过；首次解锁自举 meta 基线；
/// 二次解锁（基线已就位）依旧通过。
#[test]
fn tc_mac_06_正常解锁通过且基线自举() {
    let dir = fresh_vault("mac06-ok");
    let session = open_vault(&dir).unwrap();

    // 首次解锁：verify_integrity 走自举分支（新库建库时尚未写基线）
    session.unlock(STRONG).unwrap();
    session.lock();

    // 自举结果落盘：meta 两行存在且校验通过
    let conn = rusqlite::Connection::open(dir.join("db.sqlite")).unwrap();
    let count_blob: Vec<u8> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'record_count'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut le = [0u8; 8];
    le.copy_from_slice(&count_blob);
    assert_eq!(i64::from_le_bytes(le), 0, "空库自举 record_count = 0");
    let mac: Vec<u8> = conn
        .query_row("SELECT value FROM meta WHERE key = 'root_mac'", [], |r| r.get(0))
        .unwrap();
    assert!(!mac.is_empty(), "自举重建 root_mac");
    drop(conn);

    // 二次解锁：基线已就位，正常路径通过
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap();
    assert!(session.is_unlocked());
}

/// TC-MAC-06（负路径）：直接 SQL 篡改 `record_count` 行 → 正确密码
/// unlock 必须返回 1002（归一 UnlockFailed，不泄露完整性细节）。
#[test]
fn tc_mac_06_篡改record_count后unlock返回1002() {
    let dir = fresh_vault("mac06-rc");
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap(); // 首次解锁自举基线
    session.lock();

    let conn = rusqlite::Connection::open(dir.join("db.sqlite")).unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'record_count'",
        [7_i64.to_le_bytes().as_slice()],
    )
    .unwrap();
    drop(conn);

    let session = open_vault(&dir).unwrap();
    let err = session.unlock(STRONG).unwrap_err();
    assert_eq!(err.code(), 1002, "完整性失败必须归一 1002");
    assert!(!session.is_unlocked());
}

/// TC-MAC-06（负路径）：篡改 `root_mac` 行（合法 base64、错误值）→
/// unlock 返回 1002。
#[test]
fn tc_mac_06_篡改root_mac后unlock返回1002() {
    let dir = fresh_vault("mac06-mac");
    let session = open_vault(&dir).unwrap();
    session.unlock(STRONG).unwrap();
    session.lock();

    // 用全零密钥重算出「结构合法但值必不匹配」的 MAC 文本回写
    let conn = rusqlite::Connection::open(dir.join("db.sqlite")).unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'root_mac'",
        ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
    )
    .unwrap();
    drop(conn);

    let session = open_vault(&dir).unwrap();
    let err = session.unlock(STRONG).unwrap_err();
    assert_eq!(err.code(), 1002, "MAC 不匹配必须归一 1002");
    assert!(!session.is_unlocked());
}
