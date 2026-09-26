//! 标题搜索编排（docs/07 §2.2 `usecase/search.rs`，docs/03 §3.3 方案 A）。
//!
//! **全量解密内存搜索**：每次查询现解密（不建常驻明文缓存——锁定即无需
//! 清理，牺牲微小性能换内存清零边界的简单）。1000 条量级实测毫秒级，
//! 远低于 200 ms 基线（见下方 `千条搜索基线` 测试）。
//!
//! 规则（FR-11.1 / FR-11.2 / FR-11.4 v0.1 子集）：
//!
//! - 仅匹配**标题**（深度搜索推后，docs/07 §1.2）；
//! - 多关键词**全命中**（空白分隔）；
//! - **NFC 归一化 + 小写折叠**（docs/03 §3.3）：查询串与标题两侧都做
//!   Unicode NFC 归一化后再折叠小写。理由与解锁流主密码归一化
//!   （`cf-crypto::normalize_password`）同构——macOS 输入法 / 复制粘贴
//!   混排时，视觉相同的字符串可能落成 NFC 与 NFD 两种字节序列
//!   （如 `é` = U+00E9 与 `e` + U+0301），不归一化会双向 miss；
//! - 仅搜索 Active 态条目（归档 / 回收站不出现在搜索结果）；
//! - 空查询返回空结果（列表展示走 `list_items`）。

use cf_domain::item::{ItemState, ItemSummary};
use cf_domain::CfError;
use cf_store::{ItemListFilter, ItemStore};
use unicode_normalization::UnicodeNormalization;

use crate::usecase::items::to_summary;

/// 标题搜索：多关键词全命中、NFC 归一化 + 小写折叠、仅 Active 态。
pub fn search(store: &ItemStore, query: &str) -> Result<Vec<ItemSummary>, CfError> {
    let keywords: Vec<String> = query
        .split_whitespace()
        .map(|k| k.nfc().collect::<String>().to_lowercase())
        .collect();
    if keywords.is_empty() {
        return Ok(Vec::new());
    }

    let filter = ItemListFilter {
        state: Some(ItemState::Active),
        ..ItemListFilter::default()
    };
    let items = store.repos().items.list(&filter)?;

    items
        .into_iter()
        .filter(|it| {
            let title = it.title.expose().nfc().collect::<String>().to_lowercase();
            keywords.iter().all(|k| title.contains(k))
        })
        .map(|it| to_summary(it.row, &it.title))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::subkeys::SubKeys;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::ItemDraft;
    use cf_domain::secret::SecretString;
    use cf_store::ItemRow;
    use rusqlite::Connection;

    /// 内存库 + 固定子密钥的 ItemStore（不走解锁流，专注编排逻辑）。
    fn memory_store() -> ItemStore {
        let conn = Connection::open_in_memory().unwrap();
        let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        ItemStore::open(conn, subkeys).unwrap()
    }

    /// 最小 Login 草稿（满足模板必填：username + password）。
    fn login_draft(title: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            category: ItemCategory::Login,
            urls: vec![],
            tags: vec![],
            sections: vec![],
            fields: vec![
                cf_domain::item::FieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice".to_owned()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                cf_domain::item::FieldDraft {
                    name: "密码".to_owned(),
                    value: Some("hunter2".to_owned()),
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        }
    }

    /// 子串命中：标题包含查询词
    #[test]
    fn 子串命中() {
        let store = memory_store();
        store
            .repos()
            .items
            .insert(
                &ItemRow {
                    uuid: uuid::Uuid::now_v7().to_string(),
                    category: ItemCategory::Login,
                    state: ItemState::Active,
                    is_favorite: false,
                    fav_index: 0,
                    created_at: 0,
                    updated_at: 0,
                    trashed_at: None,
                    position: 0,
                },
                &SecretString::from_exposed("GitHub 工作账号"),
            )
            .unwrap();

        let hits = search(&store, "hub").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "GitHub 工作账号");
    }

    /// 多关键词全命中 + 大小写不敏感 + 仅 Active 态
    #[test]
    fn 多关键词全命中() {
        let store = memory_store();
        for (seed, title, state) in [
            (1u8, "GitHub Work Account", ItemState::Active),
            (2, "github 个人", ItemState::Active),
            (3, "GitHub Archive Only", ItemState::Archived),
            (4, "work 只有半个词", ItemState::Active),
        ] {
            let row = ItemRow {
                uuid: uuid::Uuid::from_bytes([seed; 16]).to_string(),
                category: ItemCategory::Login,
                state,
                is_favorite: false,
                fav_index: 0,
                created_at: 0,
                updated_at: 0,
                trashed_at: None,
                position: 0,
            };
            store
                .repos()
                .items
                .insert(&row, &SecretString::from_exposed(title))
                .unwrap();
        }

        // "github" + "work" 必须同时命中（大小写不敏感）；归档态不参与
        let hits = search(&store, "GITHUB Work").unwrap();
        assert_eq!(hits.len(), 1, "只有活跃态且两词全命中的条目应返回");
        assert_eq!(hits[0].title, "GitHub Work Account");

        // 单词命中两条活跃态
        assert_eq!(search(&store, "github").unwrap().len(), 2);
    }

    /// 未命中与空查询
    #[test]
    fn 未命中与空查询() {
        let mut store = memory_store();
        let draft = login_draft("银行登录");
        create_via(&mut store, &draft);

        assert!(search(&store, "github").unwrap().is_empty());
        assert!(search(&store, "").unwrap().is_empty(), "空查询应返回空结果");
        assert!(search(&store, "   ").unwrap().is_empty());
    }

    fn create_via(store: &mut ItemStore, draft: &ItemDraft) -> String {
        crate::usecase::items::create_item(store, draft).unwrap()
    }

    /// 1000 条模拟：搜索 ≤ 200 ms（docs/07 §7 T02 验收 ⑥，基线记录）
    #[test]
    fn 千条搜索基线() {
        let mut store = memory_store();
        let mut draft = login_draft("基线占位标题");
        // 建库后统一改标题加密插入：直接走仓库层批量插入更快，
        // 但为贴近真实路径仍走 create_item（1000 次单事务在内存库上无 IO 开销）
        for i in 0..1_000 {
            draft.title = format!("基线条目 {i:04} GitHub");
            create_via(&mut store, &draft);
        }

        let start = std::time::Instant::now();
        let hits = search(&store, "基线 0421").unwrap();
        let elapsed = start.elapsed();

        assert_eq!(hits.len(), 1);
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "1000 条搜索耗时 {elapsed:?}，超出 200ms 基线"
        );
    }
}
