//! 条目搜索编排（docs/07 §2.2 `usecase/search.rs`，docs/03 §3.3 方案 A，
//! v0.2 按 docs/09 §3.6 扩展：多字段 + 词级近似匹配，FR-11.1 / FR-11.2 / FR-11.4）。
//!
//! **全量解密内存搜索**：每次查询现解密（不建常驻明文缓存——锁定即无需
//! 清理，牺牲微小性能换内存清零边界的简单）。1000 条量级实测毫秒级，
//! release 档远低于 200 ms 基线（见下方 `千条搜索基线` 测试；基线断言
//! 按 debug/release 分档，N=3 采样取最小值抗瞬时停顿）。
//!
//! 规则：
//!
//! - 搜索字段从 v0.1 的仅标题扩到 **标题 + 用户名 + URL + 标签**
//!   （docs/09 §3.6 D-6 方案 A；密码等 Concealed 值不参与搜索）；
//! - 多关键词**全命中**（空白分隔）：每个关键词在任一字段命中即可；
//! - 命中 = 子串包含，**或** 与该字段任一 token 的 Damerau-Levenshtein
//!   编辑距离 ≤ 1（近似匹配限词长 ≥ 4 的关键词才启用——短词误报爆炸）；
//! - **NFC 归一化 + 小写折叠**（docs/03 §3.3）：查询串与字段两侧都做
//!   Unicode NFC 归一化后再折叠小写。理由与解锁流主密码归一化
//!   （`cf-crypto::normalize_password`）同构——macOS 输入法 / 复制粘贴
//!   混排时，视觉相同的字符串可能落成 NFC 与 NFD 两种字节序列
//!   （如 `é` = U+00E9 与 `e` + U+0301），不归一化会双向 miss；
//! - 仅搜索 Active 态条目（归档 / 回收站不出现在搜索结果）；
//! - 空查询返回空结果（列表展示走 `list_items`）。
//!
//! 近似匹配实现用 `strsim`（MIT/Apache，docs/09 §3.6 裁定）而非自写
//! Unicode 编辑距离；距离 ≤ 1 时 OSA 与真 DL 语义一致。

use cf_domain::item::{ItemState, ItemSummary};
use cf_domain::CfError;
use cf_store::{ItemListFilter, ItemStore};
use strsim::damerau_levenshtein;
use unicode_normalization::UnicodeNormalization;

use crate::usecase::items::to_summary;

/// 近似匹配启用的最小词长（docs/09 §3.6：词长 < 4 不启用，防误报）。
const FUZZY_MIN_TOKEN_LEN: usize = 4;

/// 词级近似匹配的最大编辑距离（Damerau-Levenshtein，docs/09 §3.6）。
const FUZZY_MAX_DISTANCE: usize = 1;

/// 单条目的可搜索字段集（归一化后的文本）。
struct SearchableFields {
    texts: Vec<String>,
}

impl SearchableFields {
    /// 关键词是否命中任一字段：子串包含，或词级编辑距离 ≤ 1。
    fn matches(&self, keyword: &str) -> bool {
        if self.texts.iter().any(|t| t.contains(keyword)) {
            return true;
        }
        // 近似匹配：仅对词长达标的关键词启用（docs/09 §3.6）
        if keyword.chars().count() < FUZZY_MIN_TOKEN_LEN {
            return false;
        }
        self.texts.iter().any(|t| {
            tokenize(t)
                .iter()
                .any(|tok| damerau_levenshtein(tok, keyword) <= FUZZY_MAX_DISTANCE)
        })
    }
}

/// 把归一化文本切成词级 token（连续 alphanumeric 游程；
/// CJK 字符同样按游程成词，无分隔符的长 CJK 串是单个 token）。
fn tokenize(normalized: &str) -> Vec<String> {
    normalized
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// 条目搜索：多关键词全命中、NFC + 小写折叠、多字段（标题 / 用户名 /
/// URL / 标签）、词级近似匹配（Damerau-Levenshtein ≤ 1，词长 ≥ 4）、
/// 仅 Active 态。
pub fn search(store: &ItemStore, query: &str) -> Result<Vec<ItemSummary>, CfError> {
    let keywords: Vec<String> = query.split_whitespace().map(normalize).collect();
    if keywords.is_empty() {
        return Ok(Vec::new());
    }

    let repos = store.repos();
    let filter = ItemListFilter {
        state: Some(ItemState::Active),
        ..ItemListFilter::default()
    };
    let items = repos.items.list(&filter)?;

    let mut out = Vec::new();
    for it in items {
        // 从表读取失败必须显式失败，不静默降级为「字段缺失」
        let fields = collect_fields(&repos, &it.row.uuid, &it.title)?;
        if keywords.iter().all(|k| fields.matches(k)) {
            out.push(to_summary(it.row, &it.title)?);
        }
    }
    Ok(out)
}

/// NFC 归一化 + 小写折叠（查询与字段两侧统一走此函数）。
fn normalize(s: &str) -> String {
    s.nfc().collect::<String>().to_lowercase()
}

/// 汇总单条目的可搜索字段：标题 + 用户名字段值 + URL + 标签。
///
/// 密码（Concealed）等其他字段值**不参与**搜索——深度搜索的边界
/// （docs/07 §1.2），也避免把敏感明文拖进比对循环。
fn collect_fields(
    repos: &cf_store::Repos<'_>,
    item_id: &str,
    title: &cf_domain::secret::SecretString,
) -> Result<SearchableFields, CfError> {
    let mut texts = vec![normalize(title.expose())];

    for f in repos.fields.read_fields_for_item(item_id)? {
        if f.designation == Some(cf_domain::field::Designation::Username) {
            if let Some(v) = &f.value {
                texts.push(normalize(v.expose()));
            }
        }
    }
    for u in repos.urls.read_for_item(item_id)? {
        texts.push(normalize(u.url.expose()));
    }
    for t in repos.tags.read_for_item(item_id)? {
        texts.push(normalize(t.name.expose()));
    }

    Ok(SearchableFields { texts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::subkeys::SubKeys;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::{FieldDraft, ItemDraft, UrlDraft};
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
        login_draft_full(title, "alice", "https://example.com/neutral", &[])
    }

    /// 可定制用户名、URL 与标签的 Login 草稿。
    fn login_draft_full(title: &str, username: &str, url: &str, tags: &[&str]) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            category: ItemCategory::Login,
            urls: vec![UrlDraft {
                label: None,
                url: url.to_owned(),
                is_primary: true,
                position: 0,
            }],
            tags: tags.iter().map(|s| s.to_string()).collect(),
            sections: vec![],
            fields: vec![
                FieldDraft {
                    name: "用户名".to_owned(),
                    value: Some(username.to_owned()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
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

    // ------------------------------------------------ FR-11.2 v0.2 扩展

    /// 词级近似：`githb` 命中 `github`（编辑距离 1）
    #[test]
    fn 近似匹配距离一命中() {
        let mut store = memory_store();
        create_via(&mut store, &login_draft("GitHub 工作账号"));

        let hits = search(&store, "githb").unwrap();
        assert_eq!(hits.len(), 1, "githb → github 应按词级距离 1 命中");
    }

    /// 词长 < 4 的关键词不启用近似匹配（防误报）
    #[test]
    fn 短词不启用近似() {
        let mut store = memory_store();
        create_via(&mut store, &login_draft("GitHub 工作账号"));

        // "ab" 与任何 token 的距离都不该触发（词长 < 4）
        assert!(search(&store, "ab").unwrap().is_empty());
        // 三词长也关闭
        assert!(search(&store, "gih").unwrap().is_empty());
    }

    /// 近似匹配不误报：距离 ≥ 2 的词不命中
    #[test]
    fn 近似匹配不误报() {
        let mut store = memory_store();
        create_via(&mut store, &login_draft("GitHub 工作账号"));

        // "gitxyz" 与 "github" 距离 ≥ 2，不命中
        assert!(search(&store, "gitxyz").unwrap().is_empty());
    }

    /// 多字段命中：用户名 / URL / 标签
    #[test]
    fn 多字段命中() {
        let mut store = memory_store();
        create_via(
            &mut store,
            &login_draft_full(
                "我的登录",
                "bob.builder@example.com",
                "https://tracker.example.org/portal",
                &["基础设施"],
            ),
        );
        let title_only = login_draft_full("无关标题", "charlie", "https://unrelated.example.net", &[]);
        create_via(&mut store, &title_only);

        // 用户名字段命中
        let hits = search(&store, "bob.builder").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "我的登录");

        // URL 命中（完整 URL 子串，仅第一条目的 URL 含该词）
        assert_eq!(search(&store, "tracker.example.org").unwrap().len(), 1);

        // 标签命中
        assert_eq!(search(&store, "基础设施").unwrap().len(), 1);

        // 密码值不参与搜索（Concealed 值不入索引）
        assert!(search(&store, "hunter2").unwrap().is_empty());
    }

    /// NFC 归一化：NFC / NFD 两种字节序列一致命中
    #[test]
    fn nfc归一化双向命中() {
        let mut store = memory_store();
        // 标题含 NFC 形式的 é
        create_via(&mut store, &login_draft("café 登录"));

        // 查询给 NFD 形式（e + U+0301）
        let nfd_query = "cafe\u{0301}";
        assert_eq!(search(&store, nfd_query).unwrap().len(), 1);
        // 查询给 NFC 形式
        assert_eq!(search(&store, "caf\u{00E9}").unwrap().len(), 1);
    }

    /// 1000 条模拟：搜索 ≤ 200 ms（docs/07 §7 T02 验收 ⑥，基线记录）。
    ///
    /// 阈值按 `cfg!(debug_assertions)` 分档（范式先例：
    /// `cf-totp/src/lib.rs` TOTP 性能测试）——release 200 ms；debug 档为
    /// 实测标定值（2026-09-27 标定：30 样本 p50 ≈ 78 ms、max ≈ 81 ms，阈值 =
    /// max(p50×5, 300ms) = 390 → 向上取整到 50 ms 倍数 → 400 ms）。采样 N=3 取**最小值**：取 min 而非
    /// 均值，单次瞬时停顿（swap / 页错误 / 调度抖动）才不会污染结果。
    /// （v0.2 多字段扩展后基线口径不变）
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

        let budget = if cfg!(debug_assertions) {
            std::time::Duration::from_millis(400)
        } else {
            std::time::Duration::from_millis(200)
        };

        // N=3 采样取最小值，每次采样都断言命中数（设计意图：每样本断言，
        // 而非只在取 min 后的样本上断言）
        let elapsed = (0..3)
            .map(|_| {
                let t = std::time::Instant::now();
                let hits = search(&store, "基线 0421").unwrap();
                assert_eq!(hits.len(), 1, "每次采样都应恰好命中 1 条");
                t.elapsed()
            })
            .min()
            .unwrap();
        assert!(
            elapsed < budget,
            "1000 条搜索最小耗时 {elapsed:?}，超出 {budget:?} 预算"
        );
    }
}
