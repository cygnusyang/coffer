//! 字段类型与 designation 语义标识（`docs/03-详细设计.md` §4.2）。

use serde::{Deserialize, Serialize};

/// 字段数据类型。
///
/// `#[serde(other)]` 让未来新增类型反序列化为 [`FieldType::Unsupported`]，
/// 向前兼容（导入时遇未知类型按 Text 降级存储，不丢值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// 单行文本
    Text,
    /// 需掩码显示（密码类）
    Concealed,
    /// 网址
    Url,
    /// 日期
    Date,
    /// 信用卡有效期 YYYY/MM
    MonthYear,
    /// 布尔
    Bool,
    /// 多行文本（备注）
    Multiline,
    /// 邮箱
    Email,
    /// 电话
    Phone,
    /// 数字
    Number,
    /// TOTP 一次性口令
    Totp,
    /// 导入时遇到未知类型 → 降级为 Text 但不丢值
    #[serde(other)]
    Unsupported,
}

/// 字段语义标识：自动填充匹配与导入映射的核心依据。
///
/// 用 **adjacently tagged**（`tag = "kind"` + `content = "value"`）序列化：
/// 单位变体输出 `{"kind": "username"}`，`Other` 输出 `{"kind": "other",
/// "value": "..."}`，使 `Other(String)` 能无损往返（1PUX → Coffer → 1PUX）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Designation {
    /// 用户名
    Username,
    /// 密码
    Password,
    /// TOTP
    Totp,
    /// 备注
    NotesPlain,
    /// 邮箱
    Email,
    /// 保留原始 designation 字符串，便于无损往返
    Other(String),
}

impl Designation {
    /// 已知 designation 的规范字符串；`Other` 返回 `None`。
    pub fn as_str(&self) -> Option<&'static str> {
        Some(match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::NotesPlain => "notesPlain",
            Self::Email => "email",
            Self::Other(_) => return None,
        })
    }

    /// 按 1Password designation 字符串映射（`docs/03-详细设计.md` §6.4.3）。
    ///
    /// `totp` 与 `otp` 均映射为 [`Designation::Totp`]；其余任意字符串
    /// 原样保留为 [`Designation::Other`]，保证导入不丢 designation 信息。
    pub fn from_1p_str(s: &str) -> Self {
        match s {
            "username" => Self::Username,
            "password" => Self::Password,
            "totp" | "otp" => Self::Totp,
            "notesPlain" => Self::NotesPlain,
            "email" => Self::Email,
            other => Self::Other(other.to_owned()),
        }
    }

    /// 返回用于导出的 1Password designation 字符串。
    ///
    /// `Other` 原样返回内层字符串，实现无损写回。
    pub fn to_1p_str(&self) -> &str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::NotesPlain => "notesPlain",
            Self::Email => "email",
            Self::Other(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_type_serde_round_trip_all() {
        let all = [
            FieldType::Text,
            FieldType::Concealed,
            FieldType::Url,
            FieldType::Date,
            FieldType::MonthYear,
            FieldType::Bool,
            FieldType::Multiline,
            FieldType::Email,
            FieldType::Phone,
            FieldType::Number,
            FieldType::Totp,
        ];
        for ft in all {
            let json = serde_json::to_string(&ft).unwrap();
            let back: FieldType = serde_json::from_str(&json).unwrap();
            assert_eq!(ft, back, "{ft:?} -> {json}");
        }
    }

    #[test]
    fn field_type_unknown_falls_back_to_unsupported() {
        let back: FieldType = serde_json::from_str("\"future_type\"").unwrap();
        assert_eq!(back, FieldType::Unsupported);
    }

    #[test]
    fn designation_known_round_trip() {
        for d in [
            Designation::Username,
            Designation::Password,
            Designation::Totp,
            Designation::NotesPlain,
            Designation::Email,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: Designation = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back, "往返失败: {d:?} -> {json}");
            assert_eq!(back, Designation::from_1p_str(d.to_1p_str()));
        }
    }

    #[test]
    fn designation_other_lossless_round_trip() {
        // Other 携带任意原始字符串，必须无损往返（含下划线/冒号等）
        for raw in ["custom.field", "sshPrivateKey", "some:weird=designation"] {
            let d = Designation::Other(raw.to_owned());
            let json = serde_json::to_string(&d).unwrap();
            assert_eq!(json, format!(r#"{{"kind":"other","value":"{raw}"}}"#));
            let back: Designation = serde_json::from_str(&json).unwrap();
            assert_eq!(back, d, "无损往返失败: {json}");
        }
    }

    #[test]
    fn designation_from_1p_str_mapping() {
        // §6.4.3：totp / otp 均映射为 Totp
        assert_eq!(Designation::from_1p_str("totp"), Designation::Totp);
        assert_eq!(Designation::from_1p_str("otp"), Designation::Totp);
        assert_eq!(Designation::from_1p_str("username"), Designation::Username);
        assert_eq!(Designation::from_1p_str("password"), Designation::Password);
        assert_eq!(
            Designation::from_1p_str("notesPlain"),
            Designation::NotesPlain
        );
        assert_eq!(Designation::from_1p_str("email"), Designation::Email);
        // 未知字符串 → Other，原样保留
        assert_eq!(
            Designation::from_1p_str("customField"),
            Designation::Other("customField".to_owned())
        );
    }

    #[test]
    fn designation_as_str() {
        assert_eq!(Designation::Username.as_str(), Some("username"));
        assert_eq!(Designation::Totp.as_str(), Some("totp"));
        assert_eq!(Designation::Other("x".into()).as_str(), None);
    }
}
