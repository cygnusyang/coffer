//! 事务框架（`docs/07-macOS纵切设计.md` §2.1 / NFR-REL-01）。
//!
//! 条目写入（create / update / delete）与 CSV 导入都必须走 [`with_tx`]：
//! 闭包返回 `Err` 时 ROLLBACK 并向上传播，满足"任一步失败全部回滚、
//! 已有数据零影响"（NFR-REL-01 / NFR-REL-04）。
//!
//! `meta.item_count` 的增量维护见 [`crate::repo::meta::MetaRepo::add_item_count`]，
//! 由调用方在同一事务内完成（防删除检测的 record_count / root_mac 推后
//! v0.2，docs/07 §5 C-4）。

use rusqlite::{Connection, Transaction};

use crate::error::{CfStoreResult, RusqliteResultExt};

/// 单事务内执行写入闭包；闭包返回 `Err` 时 ROLLBACK 并向上传播。
///
/// 成功路径显式 COMMIT；失败路径显式 ROLLBACK（即使 rollback 本身
/// 失败，事务也会在 drop 时被 SQLite 回滚，随后返回**原始**错误——
/// 回滚失败不得吞掉业务错误）。
pub fn with_tx<T>(
    conn: &mut Connection,
    f: impl FnOnce(&Transaction<'_>) -> CfStoreResult<T>,
) -> CfStoreResult<T> {
    let tx = conn.transaction().store()?;
    let result = f(&tx);
    match result {
        Ok(value) => {
            tx.commit().store()?;
            Ok(value)
        }
        Err(err) => {
            // 显式回滚；即使失败，drop 时的隐式回滚仍兜底。
            // 返回值必须是业务错误本身，而非回滚错误。
            let _ = tx.rollback();
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{CfError, RusqliteResultExt};

    /// 成功路径：闭包内的写入被提交
    #[test]
    fn 成功路径提交写入() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (v INTEGER NOT NULL);").unwrap();

        with_tx(&mut conn, |tx| {
            tx.execute("INSERT INTO t (v) VALUES (1)", []).store()?;
            Ok(())
        })
        .unwrap();

        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    /// 失败路径：注入错误 → 全部回滚，行数归零（零残留）
    #[test]
    fn 注入失败全部回滚() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (v INTEGER NOT NULL);").unwrap();

        let result: CfStoreResult<()> = with_tx(&mut conn, |tx| {
            tx.execute("INSERT INTO t (v) VALUES (1)", []).store()?;
            tx.execute("INSERT INTO t (v) VALUES (2)", []).store()?;
            Err(CfError::Validation("注入的失败".into()))
        });

        assert!(matches!(result, Err(CfError::Validation(_))));
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0, "回滚后不得有残留行");
    }

    /// SQL 执行失败（如约束冲突）同样触发回滚并向上传播
    #[test]
    fn sql失败自动回滚() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (v INTEGER NOT NULL PRIMARY KEY);
             INSERT INTO t (v) VALUES (7);",
        )
        .unwrap();

        let result: CfStoreResult<()> = with_tx(&mut conn, |tx| {
            tx.execute("INSERT INTO t (v) VALUES (8)", []).store()?;
            // 主键冲突 → rusqlite 错误（经 store() 映射为 StorageError）
            tx.execute("INSERT INTO t (v) VALUES (7)", []).store()?;
            Ok(())
        });

        assert!(matches!(result, Err(CfError::StorageError(_))));
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "只有事务外的原始行");
    }
}
