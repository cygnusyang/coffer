//! Schema 初始化（`docs/03-详细设计.md` §3.1 DDL v1 全量，docs/07 §2.1）。
//!
//! ## 设计要点
//!
//! - **一次建齐全部 11 张表 + 索引**：attachments / history / passkeys 三表
//!   只建不用——格式冻结为 v1，避免 v0.2 加表触发 schema 迁移
//!   （docs/07 §2.1；当前迁移执行体为空，多建表是最便宜的"迁移"）；
//! - **幂等**：全部 `CREATE TABLE/INDEX IF NOT EXISTS`，重复打开不报错；
//! - **版本记录**：`meta.schema_version = 1`；已存在的版本**高于**当前支持
//!   时拒绝打开（向前不兼容，[`CfError::UnsupportedFormat`]）；版本值
//!   损坏（非 8 字节 BLOB）时报 [`CfError::Corrupted`]，与 verify() 语义
//!   一致，绝不静默重写（O-2，2026-09-23）；
//! - **PRAGMA**（按 docs/03 §3.1 头注释）：WAL、synchronous=FULL、
//!   foreign_keys=ON、page_size=4096。WAL 在内存库上会被 SQLite 静默
//!   忽略（返回 "memory"），不视为错误。
//!
//! ## 与 docs/03 §3.1 的对齐说明（C-2 裁定）
//!
//! `totp` 表在文档 DDL 基础上补 `created_at INTEGER NOT NULL`（实现按
//! 创建时间排序，docs/07 §5 C-2；docs/03 v1.3 已同步回补该列）。

use std::convert::TryInto;

use rusqlite::Connection;

use crate::error::{CfStoreResult, RusqliteResultExt};
use crate::repo::meta::{MetaRepo, KEY_SCHEMA_VERSION};

/// 当前支持的 schema 版本（DDL v1，docs/03 §3.1）。
pub const SCHEMA_VERSION: i64 = 1;

/// 连接初始化 PRAGMA（docs/03 §3.1 头注释）。
const PRAGMA_BATCH: &str = "
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
PRAGMA page_size = 4096;
";

/// 全部 11 张表 + 索引（docs/03 §3.1 DDL v1；totp 补 created_at，见模块文档）。
const DDL_BATCH: &str = r#"
-- 库级元数据（值多为明文，便于锁定时读取）
CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  BLOB NOT NULL
);

-- 条目
CREATE TABLE IF NOT EXISTS items (
    uuid         TEXT    PRIMARY KEY,
    category     TEXT    NOT NULL,
    state        INTEGER NOT NULL DEFAULT 0,
    is_favorite  INTEGER NOT NULL DEFAULT 0,
    fav_index    INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    trashed_at   INTEGER,
    enc_title    BLOB    NOT NULL,
    sort_key     BLOB,
    position     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_items_state_cat ON items(state, category);
CREATE INDEX IF NOT EXISTS idx_items_updated   ON items(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_fav       ON items(is_favorite, fav_index) WHERE is_favorite = 1;

-- 分区（对应 1PUX/1P 条目的 section）
CREATE TABLE IF NOT EXISTS sections (
    uuid       TEXT PRIMARY KEY,
    item_uuid  TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    enc_title  BLOB NOT NULL,
    position   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sections_item ON sections(item_uuid, position);

-- 字段
CREATE TABLE IF NOT EXISTS fields (
    uuid         TEXT PRIMARY KEY,
    item_uuid    TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    section_uuid TEXT REFERENCES sections(uuid) ON DELETE SET NULL,
    field_type   TEXT NOT NULL,
    designation  TEXT,
    enc_name     BLOB NOT NULL,
    enc_value    BLOB,
    position     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fields_item        ON fields(item_uuid, position);
CREATE INDEX IF NOT EXISTS idx_fields_designation ON fields(designation) WHERE designation IS NOT NULL;

-- URL（多 URL 带标签）
CREATE TABLE IF NOT EXISTS urls (
    uuid       TEXT PRIMARY KEY,
    item_uuid  TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    enc_label  BLOB,
    enc_url    BLOB NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0,
    position   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_urls_item ON urls(item_uuid, position);

-- 标签
CREATE TABLE IF NOT EXISTS tags (
    uuid      TEXT PRIMARY KEY,
    item_uuid TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    enc_name  BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tags_item ON tags(item_uuid);

-- 附件
CREATE TABLE IF NOT EXISTS attachments (
    uuid          TEXT PRIMARY KEY,
    item_uuid     TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    enc_filename  BLOB NOT NULL,
    storage       TEXT NOT NULL,
    inline_data   BLOB,
    file_path     TEXT,
    size_bytes    INTEGER NOT NULL,
    chunk_count   INTEGER NOT NULL DEFAULT 1,
    content_mac   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    CHECK ((storage = 'inline' AND inline_data IS NOT NULL AND file_path IS NULL)
        OR (storage = 'file'   AND file_path   IS NOT NULL AND inline_data IS NULL))
);

-- 历史版本
CREATE TABLE IF NOT EXISTS history (
    uuid         TEXT PRIMARY KEY,
    item_uuid    TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    version      INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    enc_snapshot BLOB NOT NULL,
    UNIQUE(item_uuid, version)
);
CREATE INDEX IF NOT EXISTS idx_history_item ON history(item_uuid, version DESC);

-- 本地安全日志（严禁写入任何敏感值）
CREATE TABLE IF NOT EXISTS audit_local (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    event  TEXT    NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_local(ts DESC);

-- TOTP 密钥（与 fields 分离，便于统一管理；created_at 为 C-2 裁定回补列）
CREATE TABLE IF NOT EXISTS totp (
    uuid        TEXT PRIMARY KEY,
    item_uuid   TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    enc_secret  BLOB NOT NULL,
    algo        TEXT NOT NULL DEFAULT 'sha1',
    digits      INTEGER NOT NULL DEFAULT 6,
    period      INTEGER NOT NULL DEFAULT 30,
    enc_issuer  BLOB,
    enc_account BLOB,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_totp_item ON totp(item_uuid);

-- Passkey
CREATE TABLE IF NOT EXISTS passkeys (
    uuid              TEXT PRIMARY KEY,
    item_uuid         TEXT NOT NULL REFERENCES items(uuid) ON DELETE CASCADE,
    enc_rp_id         BLOB NOT NULL,
    enc_rp_name       BLOB,
    enc_user_name     BLOB,
    enc_user_handle   BLOB NOT NULL,
    enc_credential_id BLOB NOT NULL,
    enc_private_key   BLOB NOT NULL,
    enc_public_key    BLOB,
    algorithm         INTEGER NOT NULL,
    sign_count        INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    last_used_at      INTEGER,
    rp_id_hmac        BLOB
);
CREATE INDEX IF NOT EXISTS idx_passkeys_item ON passkeys(item_uuid);
CREATE INDEX IF NOT EXISTS idx_passkeys_rp   ON passkeys(rp_id_hmac) WHERE rp_id_hmac IS NOT NULL;
"#;

/// 初始化 schema：PRAGMA + 幂等建表 + 版本记录。
///
/// 可安全地重复调用（重复打开同一库不报错）。若库中已记录的
/// `meta.schema_version` 高于本实现支持的 [`SCHEMA_VERSION`]，返回
/// [`CfError::UnsupportedFormat`]（旧 App 打开新库必须显式失败）。
pub fn init(conn: &mut Connection) -> CfStoreResult<()> {
    // page_size 必须在任何表创建前设置才对新库生效；
    // journal_mode 在内存库上被 SQLite 忽略（返回 "memory"），不视为错误。
    conn.pragma_update(None, "journal_mode", "WAL").store()?;
    conn.execute_batch(PRAGMA_BATCH).store()?;

    let tx = conn.transaction().store()?;
    tx.execute_batch(DDL_BATCH).store()?;

    let meta = MetaRepo::new(&tx);
    // 读原始 BLOB 以区分「版本行缺失」与「版本值损坏」：
    // 损坏值（非 8 字节 BLOB）不得走 None 分支静默重写为 1（O-2，
    // 2026-09-23）——与 verify() 报 Corrupted 的语义保持一致。
    match meta.get(KEY_SCHEMA_VERSION)? {
        None => meta.set_i64(KEY_SCHEMA_VERSION, SCHEMA_VERSION)?,
        Some(blob) => {
            let bytes: [u8; 8] = blob.as_slice().try_into().map_err(|_| {
                cf_domain::CfError::Corrupted(
                    "schema version value is not an 8-byte blob".into(),
                )
            })?;
            let v = i64::from_le_bytes(bytes);
            if v == SCHEMA_VERSION {
                // 当前版本：幂等放行
            } else {
                // 高版本（含负数折叠）一律 UnsupportedFormat：
                // 旧 App 打开新库必须显式失败
                return Err(cf_domain::CfError::UnsupportedFormat(
                    u16::try_from(v).unwrap_or(u16::MAX),
                ));
            }
        }
    }
    tx.commit().store()?;
    Ok(())
}

/// 确认既有库的 schema 版本可被当前实现打开（不建表）。
///
/// 供解锁路径在只读校验时调用；meta 表不存在（未初始化/非 Coffer 库）
/// 或版本行缺失均视为库损坏。
pub fn verify(conn: &Connection) -> CfStoreResult<()> {
    let has_meta: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'",
            [],
            |r| r.get(0),
        )
        .store()?;
    if has_meta == 0 {
        return Err(cf_domain::CfError::Corrupted("schema version missing".into()));
    }
    let meta = MetaRepo::new(conn);
    // 与 init() 一致：区分「缺失」与「损坏」（O-2）
    match meta.get(KEY_SCHEMA_VERSION)? {
        Some(blob) => match TryInto::<[u8; 8]>::try_into(blob.as_slice()) {
            Ok(bytes) if i64::from_le_bytes(bytes) == SCHEMA_VERSION => Ok(()),
            Ok(bytes) => {
                let v = i64::from_le_bytes(bytes);
                Err(cf_domain::CfError::UnsupportedFormat(
                    u16::try_from(v).unwrap_or(u16::MAX),
                ))
            }
            Err(_) => Err(cf_domain::CfError::Corrupted(
                "schema version value is not an 8-byte blob".into(),
            )),
        },
        None => Err(cf_domain::CfError::Corrupted(
            "schema version missing".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 首次 init：11 张表全部建齐，schema_version = 1
    #[test]
    fn 首次建表写入版本号() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&mut conn).unwrap();

        let meta = MetaRepo::new(&conn);
        assert_eq!(meta.get_i64(KEY_SCHEMA_VERSION).unwrap(), Some(1));

        let n_tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
                 AND name IN ('meta','items','sections','fields','urls','tags',
                              'attachments','history','audit_local','totp','passkeys')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_tables, 11, "11 张表必须全部建齐");
    }

    /// 重复执行幂等：不报错、版本不变、表数量不变
    #[test]
    fn 重复执行幂等() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&mut conn).unwrap();
        init(&mut conn).unwrap();
        init(&mut conn).unwrap();

        let meta = MetaRepo::new(&conn);
        assert_eq!(meta.get_i64(KEY_SCHEMA_VERSION).unwrap(), Some(1));

        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table'", [], |r| {
                r.get(0)
            })
            .unwrap();
        // 11 张业务表 + sqlite 内部表（本用例无 AUTOINCREMENT 序列表，
        // audit_local 的 AUTOINCREMENT 会产生 sqlite_sequence）
        assert!(n >= 11);
    }

    /// 全部索引建齐（含两个 partial index）
    #[test]
    fn 索引建齐() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&mut conn).unwrap();

        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // items 3 + sections 1 + fields 2 + urls 1 + tags 1 + history 1
        // + audit 1 + totp 1 + passkeys 2 = 13
        assert_eq!(n, 13, "全部 idx_* 索引必须建齐");
    }

    /// PRAGMA 生效：外键开启、页大小 4096
    #[test]
    fn pragma配置生效() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&mut conn).unwrap();

        let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
        assert_eq!(fk, 1, "foreign_keys 必须开启（级联删除依赖它）");

        let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        assert_eq!(page, 4096);
    }

    /// 高版本库拒绝打开（UnsupportedFormat，1006）
    #[test]
    fn 高版本库拒绝打开() {
        let mut conn = Connection::open_in_memory().unwrap();
        init(&mut conn).unwrap();
        MetaRepo::new(&conn).set_i64(KEY_SCHEMA_VERSION, SCHEMA_VERSION + 1).unwrap();

        let result = init(&mut conn);
        assert!(matches!(result, Err(cf_domain::CfError::UnsupportedFormat(2))));
    }

    /// verify：版本匹配放行、缺失报 Corrupted、高版本报 UnsupportedFormat
    #[test]
    fn verify按版本三态判定() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert!(matches!(
            verify(&conn),
            Err(cf_domain::CfError::Corrupted(_))
        ));

        init(&mut conn).unwrap();
        verify(&conn).unwrap();

        MetaRepo::new(&conn).set_i64(KEY_SCHEMA_VERSION, 99).unwrap();
        assert!(matches!(
            verify(&conn),
            Err(cf_domain::CfError::UnsupportedFormat(99))
        ));
    }
}
