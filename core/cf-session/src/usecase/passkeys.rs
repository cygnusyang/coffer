//! Passkey 会话门面（FR-10.2 / FR-10.5，docs/17 §4.1 PK1，v0.5.0）。
//!
//! 薄委托 [`cf_store::PasskeyRepo`]（镜像 [`super::attachments`] 与
//! `import_1pux` 的门面模式）。`add` 路径**不设**会话门面——唯一来源是
//! 导入编排（PK2 经 `with_tx` 内 `repos.passkeys.add`，docs/17 §4.1）；
//! ADP 重启时再增注册产物回写门面。
//!
//! ## FR-10.2 红线：私钥永不展示
//!
//! 查询面只有 [`cf_store::PasskeyMeta`]（无私钥字段）；本模块及
//! [`cf_store::PasskeyRepo`] 均不存在私钥读路径——明文只在导入那一刻
//! 入库，结构上不存在展示面（#18 审查白名单断言的结构化基础）。
//!
//! ## 错误码（docs/17 §5，契约零扩展）
//!
//! 锁定态 1001（由 [`crate::VaultSession`] 门禁承担）；条目不存在
//! 1011；passkey 行不存在 1011；rpId 非法 / 非 ES256 等校验失败 1012；
//! 密文损坏 1005（由内核映射，本层直传）。

use cf_domain::CfError;
use cf_store::ItemStore;

pub use cf_store::PasskeyMeta;

use crate::SessionResult;

/// 列出条目的全部 Passkey 元数据（created_at 升序，FR-10.2）。
///
/// 条目不存在 → [`CfError::ItemNotFound`]（1011）——内核
/// `list_for_item` 不查条目行，存在性门禁由会话层承担。
/// 元数据无私钥字段（FR-10.2 红线）。
pub fn list_passkeys(
    store: &ItemStore,
    item_id: &str,
) -> SessionResult<Vec<cf_store::PasskeyMeta>> {
    let repos = store.repos();
    if repos.items.get_row(item_id)?.is_none() {
        return Err(CfError::ItemNotFound);
    }
    repos.passkeys.list_for_item(item_id)
}

/// 删除 Passkey（FR-10.5）。纯 DB 行删除，无文件面副作用（与附件的
/// 旁路文件不同）；行不存在 → [`CfError::ItemNotFound`]（1011）。
pub fn remove_passkey(store: &mut ItemStore, passkey_uuid: &str) -> SessionResult<()> {
    store.with_tx(|repos| repos.passkeys.remove(passkey_uuid))?;
    Ok(())
}
