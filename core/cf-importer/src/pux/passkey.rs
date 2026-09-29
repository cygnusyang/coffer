//! 1PUX passkey 字段解析（docs/17 §4.2 PK2，恒空快速路径）。
//!
//! **桌面 1PUX 导出无 passkey 字段**（`docs/01` §5-J 限制①：仅
//! iOS/Android 可导出 passkey）——本解析器对「无 passkey 字段」走
//! **恒空快速路径**，零回归面（既有 685 条真实样本判据不破坏）。
//!
//! 检测语义（对 v0.5 的诚实边界）：iOS/Android 导出的 passkey 字段形态
//! 【未验证】（无真实样本可逆向核对），故本模块只做**结构化检测 +
//! 计数 surface**——发现疑似 passkey 字段（值对象同时含 `credentialId`
//! 与 `rpId` 键，Bitwarden/1PUX 通用的最小结构特征）时计入
//! [`crate::pux::PuxPrecheckReport::passkey_count`] 并告警，**不落库**
//! （形态核对结论出来前写库 = 赌 schema）。判定为「显式 surface，
//! 非静默丢弃」：与 docs/17 §4.2「解析器对无 passkey 字段是恒空快速
//! 路径」一致——真实桌面样本永远走空路径。

use super::model::{PuxItem, PuxLoginField, PuxSectionField};
use serde_json::Value;

/// 一处检测到的疑似 passkey 字段（仅计数 / 告警用，不落库）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuxPasskeyRef {
    /// 来源字段路径（如 `loginFields[0].value` / `sections[1].fields[2].value`）。
    pub source: String,
    /// 检测到的 rpId（缺失时为 `(未知)`，仅告警显示）。
    pub rp_id: String,
}

/// 从一条 1PUX 条目提取疑似 passkey 字段。
///
/// 桌面导出恒返回空 `Vec`（快速路径）；扫描面为 `details.loginFields[]`
/// 与 `details.sections[].fields[]` 的类型化 value 对象。
#[must_use]
pub fn passkey_refs(item: &PuxItem) -> Vec<PuxPasskeyRef> {
    let mut refs = Vec::new();
    let details = &item.details;

    for (i, field) in details.login_fields.iter().enumerate() {
        if let Some(rp_id) = value_rp_id(field_value(field)) {
            refs.push(PuxPasskeyRef {
                source: format!("loginFields[{i}].value"),
                rp_id,
            });
        }
    }
    for (si, section) in details.sections.iter().enumerate() {
        for (fi, field) in section.fields.iter().enumerate() {
            if let Some(rp_id) = value_rp_id(section_field_value(field)) {
                refs.push(PuxPasskeyRef {
                    source: format!("sections[{si}].fields[{fi}].value"),
                    rp_id,
                });
            }
        }
    }
    refs
}

/// loginField / sectionField 的 value 访问（两结构体字段同名但类型不同，
/// 各配一个取值助手）。
fn field_value(f: &PuxLoginField) -> Option<&Value> {
    f.value.as_ref()
}

fn section_field_value(f: &PuxSectionField) -> Option<&Value> {
    f.value.as_ref()
}

/// 值对象的最小 passkey 结构特征：同时含 `credentialId` 与 `rpId` 键。
fn value_rp_id(value: Option<&Value>) -> Option<String> {
    let obj = value?.as_object()?;
    if obj.contains_key("credentialId") && obj.contains_key("rpId") {
        Some(
            obj.get("rpId")
                .and_then(Value::as_str)
                .unwrap_or("(未知)")
                .to_owned(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{PuxDetails, PuxLoginField, PuxSection, PuxSectionField};
    use super::*;
    use serde_json::json;

    /// 桌面形态（无 passkey 字段）→ 恒空快速路径。
    #[test]
    fn 无passkey字段恒空() {
        let item = PuxItem {
            uuid: "IT0001".into(),
            category_uuid: "001".into(),
            state: None,
            created_at: 0,
            updated_at: 0,
            fav_index: 0,
            overview: None,
            details: PuxDetails::default(),
            file: None,
        };
        assert!(passkey_refs(&item).is_empty());
    }

    /// 疑似 passkey 值对象（loginFields / sections 双位置）→ 检出。
    #[test]
    fn 疑似passkey值对象检出() {
        let passkey_value = json!({"credentialId": "abc", "rpId": "example.com"});
        let item = PuxItem {
            uuid: "IT0002".into(),
            category_uuid: "001".into(),
            state: None,
            created_at: 0,
            updated_at: 0,
            fav_index: 0,
            overview: None,
            details: PuxDetails {
                login_fields: vec![PuxLoginField {
                    designation: None,
                    name: None,
                    field_type: None,
                    value: Some(passkey_value.clone()),
                }],
                sections: vec![PuxSection {
                    title: None,
                    name: None,
                    fields: vec![PuxSectionField {
                        title: None,
                        designation: None,
                        field_type: None,
                        value: Some(passkey_value),
                    }],
                }],
                ..PuxDetails::default()
            },
            file: None,
        };
        let refs = passkey_refs(&item);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].source, "loginFields[0].value");
        assert_eq!(refs[0].rp_id, "example.com");
        assert_eq!(refs[1].source, "sections[0].fields[0].value");

        // 普通 username 值对象不误报
        let mut plain = item;
        plain.details.login_fields[0].value = Some(json!({"username": "alice"}));
        plain.details.sections.clear();
        assert!(passkey_refs(&plain).is_empty());
    }

    // section 字段访问助手与检出路径对称覆盖
    #[test]
    fn section字段访问() {
        let f = PuxSectionField {
            title: None,
            designation: None,
            field_type: None,
            value: Some(json!({"credentialId": "abc", "rpId": "r.example"})),
        };
        assert!(value_rp_id(section_field_value(&f)).is_some());
    }
}
