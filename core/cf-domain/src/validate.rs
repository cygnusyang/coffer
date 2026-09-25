//! 条目校验规则：创建/更新前对草稿做边界校验，失败快（fail fast）。

use crate::error::CfError;
use crate::field::Designation;
use crate::item::{FieldDraft, ItemDraft};
use crate::template;

/// 条目标题最大长度（字符数）。设计文档未给上限，取 512。
pub const MAX_TITLE_CHARS: usize = 512;
/// 字段值最大长度（字符数）。设计文档未给上限，取 1 MiB 作安全阈值，
/// 防止异常大值进入存储（附件另走 100 MB 上限，不在此列）。
pub const MAX_FIELD_VALUE_CHARS: usize = 1_048_576;
/// TOTP 密钥最小长度（字节，80 bit，与 RFC 4226 §4 一致）。
pub const TOTP_SECRET_MIN_BYTES: usize = 10;

/// 校验条目草稿。
///
/// 校验项：
/// 1. 标题非空且 ≤ [`MAX_TITLE_CHARS`] 字符；
/// 2. 类别的必填模板字段（`required = true`）在草稿中存在；
/// 3. 同级 `position` 无重复（分区、URL、字段各自内部）；
/// 4. 字段值长度 ≤ [`MAX_FIELD_VALUE_CHARS`]；
/// 5. TOTP 数据自洽（secret ≥ 10 字节、digits ∈ {6,8}、period > 0）。
///
/// # Errors
///
/// 任一校验不通过返回 [`CfError::InvalidArgument`]（带可操作说明）。
pub fn validate_item(draft: &ItemDraft) -> Result<(), CfError> {
    validate_title(&draft.title)?;
    validate_required_fields(draft)?;
    validate_positions(draft)?;
    validate_field_values(&draft.fields)?;
    validate_totp(draft.totp.as_ref())?;
    Ok(())
}

fn validate_title(title: &str) -> Result<(), CfError> {
    if title.trim().is_empty() {
        return Err(CfError::InvalidArgument(
            "title must not be empty".to_owned(),
        ));
    }
    let len = title.chars().count();
    if len > MAX_TITLE_CHARS {
        return Err(CfError::InvalidArgument(format!(
            "title too long: {len} chars, max {MAX_TITLE_CHARS}"
        )));
    }
    Ok(())
}

fn validate_required_fields(draft: &ItemDraft) -> Result<(), CfError> {
    for tpl in template::templates_for(draft.category) {
        if !tpl.required {
            continue;
        }
        let present = draft
            .fields
            .iter()
            .any(|f| field_matches_designation(f, tpl.designation));
        if !present {
            return Err(CfError::InvalidArgument(format!(
                "missing required field '{}' ({}) for category {}",
                tpl.default_name,
                tpl.designation,
                draft.category.as_str()
            )));
        }
    }
    Ok(())
}

/// 字段 designation 是否命中模板的 designation 字符串。
fn field_matches_designation(field: &FieldDraft, designation: &str) -> bool {
    match &field.designation {
        // 已知 designation 用规范字符串比较；Other 用内层原字符串比较，
        // 保证自定义 designation（如模板里的 "cc-number"）也能命中。
        Some(Designation::Other(raw)) => raw == designation,
        Some(known) => known.as_str() == Some(designation),
        None => false,
    }
}

fn validate_positions(draft: &ItemDraft) -> Result<(), CfError> {
    assert_unique_positions(draft.sections.iter().map(|s| s.position), "section")?;
    assert_unique_positions(draft.urls.iter().map(|u| u.position), "url")?;
    assert_unique_positions(draft.fields.iter().map(|f| f.position), "field")?;
    Ok(())
}

fn assert_unique_positions<'a>(
    positions: impl Iterator<Item = i32> + 'a,
    kind: &str,
) -> Result<(), CfError> {
    let mut seen = std::collections::HashSet::new();
    for p in positions {
        if !seen.insert(p) {
            return Err(CfError::InvalidArgument(format!(
                "duplicate {kind} position: {p}"
            )));
        }
    }
    Ok(())
}

fn validate_field_values(fields: &[FieldDraft]) -> Result<(), CfError> {
    for f in fields {
        if let Some(value) = &f.value {
            let len = value.chars().count();
            if len > MAX_FIELD_VALUE_CHARS {
                return Err(CfError::InvalidArgument(format!(
                    "field '{}' value too long: {len} chars, max {MAX_FIELD_VALUE_CHARS}",
                    f.name
                )));
            }
        }
    }
    Ok(())
}

fn validate_totp(totp: Option<&crate::totp_data::TotpData>) -> Result<(), CfError> {
    let Some(totp) = totp else {
        return Ok(());
    };
    if totp.secret.len() < TOTP_SECRET_MIN_BYTES {
        return Err(CfError::InvalidArgument(format!(
            "totp secret too short: {} bytes, min {TOTP_SECRET_MIN_BYTES}",
            totp.secret.len()
        )));
    }
    if totp.digits != 6 && totp.digits != 8 {
        return Err(CfError::InvalidArgument(format!(
            "totp digits must be 6 or 8, got {}",
            totp.digits
        )));
    }
    if totp.period == 0 {
        return Err(CfError::InvalidArgument(
            "totp period must be positive".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::ItemCategory;
    use crate::field::FieldType;
    use crate::totp_data::{TotpAlgo, TotpData};

    fn login_draft() -> ItemDraft {
        ItemDraft {
            title: "我的登录".to_owned(),
            category: ItemCategory::Login,
            urls: vec![],
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

    #[test]
    fn valid_login_passes() {
        assert!(validate_item(&login_draft()).is_ok());
    }

    #[test]
    fn empty_title_rejected() {
        let mut d = login_draft();
        d.title = "   ".to_owned();
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn overlong_title_rejected() {
        let mut d = login_draft();
        d.title = "a".repeat(MAX_TITLE_CHARS + 1);
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn missing_required_field_rejected() {
        // 移除必填的 password 字段
        let mut d = login_draft();
        d.fields
            .retain(|f| f.designation != Some(Designation::Password));
        let err = validate_item(&d).unwrap_err();
        assert!(
            matches!(err, CfError::InvalidArgument(ref m) if m.contains("password")),
            "{err}"
        );
    }

    #[test]
    fn missing_username_rejected() {
        let mut d = login_draft();
        d.fields
            .retain(|f| f.designation != Some(Designation::Username));
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn duplicate_position_rejected() {
        let mut d = login_draft();
        // 两个字段 position 都设为 0
        for f in &mut d.fields {
            f.position = 0;
        }
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn overlong_value_rejected() {
        let mut d = login_draft();
        d.fields[1].value = Some("x".repeat(MAX_FIELD_VALUE_CHARS + 1));
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn short_totp_secret_rejected() {
        let mut d = login_draft();
        d.totp = Some(TotpData {
            secret: vec![0u8; TOTP_SECRET_MIN_BYTES - 1],
            algo: TotpAlgo::Sha1,
            digits: 6,
            period: 30,
        });
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn invalid_totp_digits_rejected() {
        let mut d = login_draft();
        d.totp = Some(TotpData {
            secret: vec![0u8; TOTP_SECRET_MIN_BYTES],
            algo: TotpAlgo::Sha1,
            digits: 5,
            period: 30,
        });
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn zero_totp_period_rejected() {
        let mut d = login_draft();
        d.totp = Some(TotpData {
            secret: vec![0u8; TOTP_SECRET_MIN_BYTES],
            algo: TotpAlgo::Sha1,
            digits: 6,
            period: 0,
        });
        assert!(matches!(
            validate_item(&d),
            Err(CfError::InvalidArgument(_))
        ));
    }

    #[test]
    fn valid_totp_accepted() {
        let mut d = login_draft();
        d.totp = Some(TotpData {
            secret: vec![0u8; TOTP_SECRET_MIN_BYTES],
            algo: TotpAlgo::Sha256,
            digits: 8,
            period: 60,
        });
        assert!(validate_item(&d).is_ok());
    }

    #[test]
    fn custom_category_no_required_fields() {
        // Custom 类别无必填模板字段，仅标题即可通过
        let mut d = login_draft();
        d.category = ItemCategory::Custom;
        d.fields.clear();
        assert!(validate_item(&d).is_ok());
    }
}
