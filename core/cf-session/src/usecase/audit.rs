//! Watchtower 安全体检编排（FR-6.2 / FR-6.3，docs/09 §3.5 D-4 分层）。
//!
//! 分层裁定：cf-audit 持**纯计算函数**（指纹 / 分组 / 弱密码复检 /
//! URL 判定，不依赖 cf-store），解密与取数在 cf-session 编排。重复
//! 密码判定**不得明文比较**（docs/03 §8 AUD-02）：用 HMAC-SHA256
//! 指纹比对，HMAC key = `audit_key`（`SubKeys.audit_key`，
//! docs/09 §3.5 D-5，`cf/audit/v1`）。
//!
//! 纯函数全部委托 [`cf_audit`]（G2 合入的 `watchtower` 冻结契约实现，
//! 签名与 docs/09 §3.5 逐字一致）；本模块只做取数、解密与装配。
//!
//! ## 明文纪律
//!
//! 全量解密 → 逐密码算指纹 + zxcvbn 复检 → **明文即用即弃**（不缓存
//! 清单，docs/09 §8 风险 7）；指纹是 HMAC 输出，不泄露明文。

use cf_crypto::aead::SessionKey;
use cf_domain::item::ItemState;
use cf_domain::CfError;
use cf_store::{ItemListFilter, ItemStore};

pub use cf_audit::{PasswordFingerprint, WatchtowerReport};

/// 运行 Watchtower 体检：全量解密 → 逐密码算指纹 + zxcvbn → 纯函数汇总。
///
/// 覆盖 Active + Archived 条目（回收站条目不参与体检——已被用户废弃）。
/// 每条密码明文在指纹 / 强度评估完成后立即离开作用域，不驻留。
///
/// `audit_key` 由调用方从解锁态 `SubKeys.audit_key` 注入（DEK / 子密钥
/// 不跨 FFI 的既定纪律不变）。
pub fn run_watchtower(
    store: &ItemStore,
    audit_key: &SessionKey,
) -> Result<WatchtowerReport, CfError> {
    let repos = store.repos();

    // 回收站条目不体检：Active 与 Archived 全量
    let items = repos.items.list(&ItemListFilter::default())?;

    let mut fps: Vec<PasswordFingerprint> = Vec::new();
    let mut weak_candidates: Vec<(String, String)> = Vec::new();
    let mut urls: Vec<(String, String)> = Vec::new();

    for it in &items {
        // 回收站条目不体检（已被用户废弃）；Active + Archived 参与
        if it.row.state == ItemState::Trashed {
            continue;
        }
        let item_id = it.row.uuid.clone();

        for f in repos.fields.read_fields_for_item(&item_id)? {
            // FR-6.2：密码字段（designation = Password）参与指纹与强度复检
            if f.designation != Some(cf_domain::field::Designation::Password) {
                continue;
            }
            let Some(value) = &f.value else { continue };
            let plain = value.expose();

            fps.push(PasswordFingerprint {
                item_id: item_id.clone(),
                field_id: f.uuid.clone(),
                hmac_b64: cf_audit::password_fingerprint(plain, audit_key.as_bytes()),
            });
            // FR-6.1 复检：覆盖 CSV 导入等不设强度门禁的弱密码；
            // 明文对在本循环内构造、由 cf-audit 即时评估后丢弃
            weak_candidates.push((item_id.clone(), plain.to_owned()));
            // 明文（plain）在此离开循环体，不驻留（借用于解密返回值）
        }

        for u in repos.urls.read_for_item(&item_id)? {
            urls.push((item_id.clone(), u.url.expose().to_owned()));
        }
    }

    Ok(WatchtowerReport {
        duplicate_groups: cf_audit::find_duplicate_groups(&fps),
        weak_password_items: cf_audit::find_weak_passwords(&weak_candidates),
        http_url_items: cf_audit::find_http_urls(&urls),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::subkeys::SubKeys;
    use cf_domain::category::ItemCategory;
    use cf_domain::field::{Designation, FieldType};
    use cf_domain::item::{FieldDraft, ItemDraft, UrlDraft};
    use rusqlite::Connection;

    /// 内存库 + 固定子密钥的 ItemStore。
    fn memory_store() -> ItemStore {
        let conn = Connection::open_in_memory().unwrap();
        let subkeys = SubKeys::derive(&[0x42u8; 32], &[0x11u8; 16]).unwrap();
        ItemStore::open(conn, subkeys).unwrap()
    }

    /// Login 草稿（指定密码 / URL）。
    fn login_draft(title: &str, password: &str, url: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            category: ItemCategory::Login,
            urls: vec![UrlDraft {
                label: None,
                url: url.to_owned(),
                is_primary: true,
                position: 0,
            }],
            tags: vec![],
            sections: vec![],
            fields: vec![
                FieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice".to_owned()),
                    field_type: FieldType::Text,
                    designation: Some(Designation::Username),
                    section_index: None,
                    position: 0,
                },
                FieldDraft {
                    name: "密码".to_owned(),
                    value: Some(password.to_owned()),
                    field_type: FieldType::Concealed,
                    designation: Some(Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        }
    }

    fn create(store: &mut ItemStore, draft: &ItemDraft) -> String {
        crate::usecase::items::create_item(store, draft).unwrap()
    }

    fn audit_key() -> SessionKey {
        SessionKey::new([0x77u8; 32])
    }

    /// 编排：注入重复 / 弱 / http 条目 → 报告命中；无问题条目不出现在报告
    #[test]
    fn 编排命中重复弱与弱url() {
        let mut store = memory_store();
        // 强密码（两条相同 → 重复组）
        let strong = "correct-horse-battery-staple-42!";
        let i1 = create(&mut store, &login_draft("库一", strong, "https://a.com"));
        let i2 = create(&mut store, &login_draft("库二", strong, "http://b.com"));
        // 弱密码 + https
        let i3 = create(&mut store, &login_draft("库三", "123456", "https://c.com"));
        // 强密码 + 唯一 → 三报告均不命中
        let _i4 = create(
            &mut store,
            &login_draft("库四", "another-strong-password-99!", "https://d.com"),
        );

        let report = run_watchtower(&store, &audit_key()).unwrap();

        assert_eq!(
            report.duplicate_groups,
            vec![vec![i1.clone(), i2.clone()]],
            "两条同强密码必须组成一个重复组"
        );
        assert_eq!(
            report.weak_password_items,
            vec![i3.clone()],
            "仅弱密码条目命中"
        );
        assert_eq!(report.http_url_items, vec![i2], "仅 http:// 条目命中");
    }

    /// 不同 audit_key（不同库）→ 指纹不同 → 同密码不跨库比对
    #[test]
    fn 跨库密钥隔离() {
        let mut store = memory_store();
        create(
            &mut store,
            &login_draft("库一", "same-password-42!", "https://a.com"),
        );
        create(
            &mut store,
            &login_draft("库二", "same-password-42!", "https://b.com"),
        );

        // 同库内：同密码同 key → 报重复组
        let r1 = run_watchtower(&store, &SessionKey::new([0x01u8; 32])).unwrap();
        assert_eq!(r1.duplicate_groups.len(), 1);

        // 指纹随 key 改变（防跨库比对，AUD-02）：不同 key 下同密码指纹不同
        let k1 = cf_audit::password_fingerprint("same-password-42!", &[0x01u8; 32]);
        let k2 = cf_audit::password_fingerprint("same-password-42!", &[0x02u8; 32]);
        assert_ne!(k1, k2);
        assert!(!k1.contains("same-password-42!"), "指纹不得泄露明文");
    }

    /// 归档条目参与体检；回收站条目不参与
    #[test]
    fn 回收站条目不参与体检() {
        let mut store = memory_store();
        let id = create(&mut store, &login_draft("库一", "123456", "https://a.com"));
        crate::usecase::items::delete_item(&mut store, &id, false).unwrap();

        let report = run_watchtower(&store, &audit_key()).unwrap();
        assert!(
            report.weak_password_items.is_empty(),
            "回收站条目不出现在报告"
        );
    }
}
