//! FR-6.7 体检报告会话侧编排（v0.3.0-T04）——五类检测的取数与装配。
//!
//! 与 [`super::audit`]（FR-6.2 / 6.3 Watchtower 编排）同分层：cf-audit 持
//! **纯计算函数**（docs/03 §8 AUD-02~06），解密与取数在本模块编排。
//! 本模块在**单次遍历**内完成全部解密取数（1000 条内存库毫秒级，参照
//! search 编排），密码明文即用即弃，不驻留。
//!
//! 覆盖五类检测：
//!
//! - FR-6.2 重复密码（HMAC 指纹，`audit_key` 注入，docs/09 §3.5 D-5）；
//! - FR-6.3 弱 URL（`http://` 前缀）；
//! - FR-6.4 陈旧密码（`updated_at` 距今 > 阈值，默认
//!   [`cf_audit::DEFAULT_STALE_DAYS`]）；
//! - FR-6.5 泄露启发式（离线字典 / 形态规则，**不覆盖真实泄露事件**，
//!   能力缺口须向用户明示，X-07 零网络原则）；
//! - FR-6.6 无 2FA 提示（URL 域名在白名单且未配置 TOTP）。
//!
//! ## 明文纪律
//!
//! 每条 finding 只携带 item_id / 解密标题 / 非敏感元数据（规则、置信度、
//! 距今天数）；**密码明文与隐藏字段值绝不进报告**——与 `WatchtowerReport`
//! 同纪律（docs/09 §8 风险 7：明文即用即弃），由 tests/health_report.rs
//! 的 Debug 检索断言冻结。

use std::collections::BTreeMap;

use cf_crypto::aead::SessionKey;
use cf_domain::item::ItemState;
use cf_domain::CfError;
use cf_store::{ItemListFilter, ItemStore};

pub use cf_audit::{CommonPasswordRule as LeakRule, Confidence as LeakConfidence};

/// 一天的秒数（距今天数换算，与 cf-audit 纯函数同口径：整天向下取整）。
const SECS_PER_DAY: i64 = 86_400;

/// 单条体检 finding 的通用载荷：条目 + 解密标题（非敏感，展示用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemFinding {
    /// 条目 ID。
    pub item_id: String,
    /// 解密标题。
    pub title: String,
}

/// 重复密码组 finding（FR-6.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateGroupFinding {
    /// 共享同一密码指纹的条目 ID（≥2）。
    pub item_ids: Vec<String>,
    /// 与 `item_ids` 一一对应的解密标题。
    pub titles: Vec<String>,
}

/// 陈旧密码 finding（FR-6.4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleFinding {
    /// 条目 ID。
    pub item_id: String,
    /// 解密标题。
    pub title: String,
    /// 距上次修改的整天数（非敏感元数据，UI 展示用）。
    pub days_since_update: i64,
}

/// 泄露启发式 finding（FR-6.5，Should 非门禁）。
///
/// `rule` / `confidence` 为非敏感元数据；**本结果不覆盖真实泄露事件**
/// （FR-6.5 能力缺口声明，UI 侧须随报告展示）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakFinding {
    /// 条目 ID。
    pub item_id: String,
    /// 解密标题。
    pub title: String,
    /// 命中规则。
    pub rule: LeakRule,
    /// 置信度。
    pub confidence: LeakConfidence,
}

/// 五类体检汇总统计（与 [`HealthReport`] 各清单一一对应）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthSummary {
    /// 重复密码组数（FR-6.2，按组计）。
    pub duplicate_group_count: usize,
    /// 弱 URL 条目数（FR-6.3）。
    pub weak_url_count: usize,
    /// 陈旧密码条目数（FR-6.4）。
    pub stale_count: usize,
    /// 泄露启发式命中条目数（FR-6.5）。
    pub leak_suspect_count: usize,
    /// 无 2FA 提示条目数（FR-6.6）。
    pub missing_totp_count: usize,
    /// 各类计数的总和（重复组按组计）。
    pub total_findings: usize,
}

/// 体检报告（FR-6.7，覆盖 FR-6.2 / 6.3 / 6.4 / 6.5 / 6.6 五类）。
///
/// 回收站条目不参与体检（与 [`super::audit::run_watchtower`] 同语义）。
/// 报告不携带密码明文与隐藏字段值（见模块文档明文纪律）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthReport {
    /// 共享同一密码指纹的分组（≥2 才报，FR-6.2）。
    pub duplicate_groups: Vec<DuplicateGroupFinding>,
    /// 任一 URL 以 `http://` 开头的条目（FR-6.3）。
    pub http_url_items: Vec<ItemFinding>,
    /// 陈旧密码条目（FR-6.4）。
    pub stale_items: Vec<StaleFinding>,
    /// 泄露启发式命中条目（FR-6.5，每条目至多一条）。
    pub leak_suspects: Vec<LeakFinding>,
    /// 白名单域名且未配置 TOTP 的条目（FR-6.6）。
    pub missing_totp_items: Vec<ItemFinding>,
    /// 汇总统计。
    pub summary: HealthSummary,
}

/// 运行五类体检（FR-6.7）：单次遍历解密取数 → cf-audit 纯函数汇总。
///
/// `now` 由调用方注入（Unix 秒，与 idle / reminder 同模式，可测试）；
/// `stale_days` 为陈旧密码阈值（默认 [`cf_audit::DEFAULT_STALE_DAYS`]，
/// docs/03 §8 AUD-04：可配置）。覆盖 Active + Archived 条目（回收站
/// 条目不体检）。每条密码明文在指纹 / 启发式评估完成后立即离开作用域，
/// 不驻留。
pub fn run_health_report(
    store: &ItemStore,
    audit_key: &SessionKey,
    now: i64,
    stale_days: i64,
) -> Result<HealthReport, CfError> {
    let repos = store.repos();

    // 回收站条目不体检：Active 与 Archived 全量
    let items = repos.items.list(&ItemListFilter::default())?;

    let mut fps: Vec<cf_audit::PasswordFingerprint> = Vec::new();
    let mut common_candidates: Vec<(String, String)> = Vec::new();
    let mut urls: Vec<(String, String)> = Vec::new();
    let mut stale_entries: Vec<(String, i64)> = Vec::new();
    let mut totp_entries: Vec<(String, Option<String>, bool)> = Vec::new();
    // item_id → 解密标题（finding 装配用；标题属报告可见的非敏感载荷）
    let mut titles: BTreeMap<String, String> = BTreeMap::new();

    for it in &items {
        // 回收站条目不体检（已被用户废弃）；Active + Archived 参与
        if it.row.state == ItemState::Trashed {
            continue;
        }
        let item_id = it.row.uuid.clone();
        titles.insert(item_id.clone(), it.title.expose().to_owned());
        stale_entries.push((item_id.clone(), it.row.updated_at));

        for f in repos.fields.read_fields_for_item(&item_id)? {
            // 密码字段（designation = Password）参与指纹与泄露启发式
            if f.designation != Some(cf_domain::field::Designation::Password) {
                continue;
            }
            let Some(value) = &f.value else { continue };
            let plain = value.expose();

            fps.push(cf_audit::PasswordFingerprint {
                item_id: item_id.clone(),
                field_id: f.uuid.clone(),
                hmac_b64: cf_audit::password_fingerprint(plain, audit_key.as_bytes()),
            });
            common_candidates.push((item_id.clone(), plain.to_owned()));
            // 明文（plain）进入 common_candidates 持有至本函数末尾消费
            // （与 usecase/audit.rs 既有模式一致）：**不进报告、不越函数
            // 边界**，HealthReport 只收指纹与 item_id。
        }

        let item_urls = repos.urls.read_for_item(&item_id)?;
        let primary = item_urls
            .iter()
            .find(|u| u.is_primary)
            .or_else(|| item_urls.first());
        for u in &item_urls {
            urls.push((item_id.clone(), u.url.expose().to_owned()));
        }
        let has_totp = !repos.totp.totp_uuids_for_item(&item_id)?.is_empty();
        totp_entries.push((
            item_id.clone(),
            primary.map(|u| u.url.expose().to_owned()),
            has_totp,
        ));
    }

    let missing_totp = cf_audit::find_missing_totp(
        &totp_entries
            .iter()
            .map(|(id, url, has)| (id.clone(), url.as_deref(), *has))
            .collect::<Vec<_>>(),
    );

    let duplicate_groups: Vec<DuplicateGroupFinding> = cf_audit::find_duplicate_groups(&fps)
        .into_iter()
        .map(|ids| {
            let group_titles: Vec<String> = ids
                .iter()
                .map(|id| titles.get(id).cloned().unwrap_or_default())
                .collect();
            DuplicateGroupFinding {
                item_ids: ids,
                titles: group_titles,
            }
        })
        .collect();
    let http_url_items: Vec<ItemFinding> = cf_audit::find_http_urls(&urls)
        .into_iter()
        .map(|id| titled(&titles, id))
        .collect();
    let stale_items: Vec<StaleFinding> =
        cf_audit::find_stale_passwords(&stale_entries, now, stale_days)
            .into_iter()
            .map(|id| {
                let days_since_update = stale_entries
                    .iter()
                    .find(|(sid, _)| sid == &id)
                    .map_or(0, |(_, updated_at)| {
                        now.saturating_sub(*updated_at) / SECS_PER_DAY
                    });
                StaleFinding {
                    title: title_of(&titles, &id),
                    item_id: id,
                    days_since_update,
                }
            })
            .collect();
    let leak_suspects: Vec<LeakFinding> = cf_audit::find_common_passwords(&common_candidates)
        .into_iter()
        .map(|hit| LeakFinding {
            title: title_of(&titles, &hit.item_id),
            item_id: hit.item_id,
            rule: hit.rule,
            confidence: hit.confidence,
        })
        .collect();
    let missing_totp_items: Vec<ItemFinding> = missing_totp
        .into_iter()
        .map(|id| titled(&titles, id))
        .collect();

    let summary = HealthSummary {
        duplicate_group_count: duplicate_groups.len(),
        weak_url_count: http_url_items.len(),
        stale_count: stale_items.len(),
        leak_suspect_count: leak_suspects.len(),
        missing_totp_count: missing_totp_items.len(),
        total_findings: duplicate_groups.len()
            + http_url_items.len()
            + stale_items.len()
            + leak_suspects.len()
            + missing_totp_items.len(),
    };

    Ok(HealthReport {
        duplicate_groups,
        http_url_items,
        stale_items,
        leak_suspects,
        missing_totp_items,
        summary,
    })
}

/// 从标题表取解密标题（缺失时置空串——防御性，正常路径标题表覆盖
/// 全部参与体检条目）。
fn title_of(titles: &BTreeMap<String, String>, item_id: &str) -> String {
    titles.get(item_id).cloned().unwrap_or_default()
}

/// 从标题表装配 `ItemFinding`（条目 + 解密标题）。
fn titled(titles: &BTreeMap<String, String>, item_id: String) -> ItemFinding {
    ItemFinding {
        title: title_of(titles, &item_id),
        item_id,
    }
}
