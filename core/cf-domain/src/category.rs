//! 条目类别：22 类 + Custom 兜底。

use serde::{Deserialize, Serialize};

/// 条目类别（`docs/03-详细设计.md` §4.1）。
///
/// 以 1Password Connect API 的可创建类别枚举为基准（21 类），额外容纳
/// SDK 枚举中的 `CryptoWallet` / `Person`，最后以 `Custom` 兜底。
/// 真实导入时遇到未知分类，一律落入 `Custom` 而非被丢弃（需求 FR-7.6）。
///
/// `#[serde(other)]` 让**未来新增的类别**能无损反序列化为 `Custom`，
/// 保证向前兼容（`ItemCategory` 的 serde 往返见测试）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemCategory {
    /// 登录（Login，opvault 码 001）
    Login,
    /// 密码（Password，opvault 码 005）
    Password,
    /// API 凭据（ApiCredential）
    ApiCredential,
    /// 服务器（Server，opvault 码 110）
    Server,
    /// 数据库（Database，opvault 码 102）
    Database,
    /// 信用卡（CreditCard，opvault 码 002）
    CreditCard,
    /// 会员（Membership，opvault 码 105）
    Membership,
    /// 护照（Passport，opvault 码 106）
    Passport,
    /// 软件许可证（SoftwareLicense，opvault 码 100）
    SoftwareLicense,
    /// 户外许可（OutdoorLicense，opvault 码 104）
    OutdoorLicense,
    /// 安全笔记（SecureNote，opvault 码 003）
    SecureNote,
    /// 无线路由器（WirelessRouter，opvault 码 109）
    WirelessRouter,
    /// 银行账户（BankAccount，opvault 码 101）
    BankAccount,
    /// 驾照（DriverLicense，opvault 码 103）
    DriverLicense,
    /// 身份（Identity，opvault 码 004）
    Identity,
    /// 奖励计划（RewardProgram，opvault 码 107）
    RewardProgram,
    /// 文档（Document）
    Document,
    /// 邮箱账户（EmailAccount，opvault 码 111）
    EmailAccount,
    /// 社保号（SocialSecurityNumber，opvault 码 108）
    SocialSecurityNumber,
    /// 医疗记录（MedicalRecord）
    MedicalRecord,
    /// SSH 密钥（SshKey）
    SshKey,
    /// 加密钱包（CryptoWallet，SDK 枚举含、Connect API 未列入可创建项）
    CryptoWallet,
    /// 联系人（Person，SDK 枚举含、Connect API 未列入可创建项）
    Person,
    /// 未知类别的兜底（serde 向前兼容）
    #[serde(other)]
    Custom,
}

impl ItemCategory {
    /// 返回类别的 snake_case 名称（与 serde 序列化形式一致）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Password => "password",
            Self::ApiCredential => "api_credential",
            Self::Server => "server",
            Self::Database => "database",
            Self::CreditCard => "credit_card",
            Self::Membership => "membership",
            Self::Passport => "passport",
            Self::SoftwareLicense => "software_license",
            Self::OutdoorLicense => "outdoor_license",
            Self::SecureNote => "secure_note",
            Self::WirelessRouter => "wireless_router",
            Self::BankAccount => "bank_account",
            Self::DriverLicense => "driver_license",
            Self::Identity => "identity",
            Self::RewardProgram => "reward_program",
            Self::Document => "document",
            Self::EmailAccount => "email_account",
            Self::SocialSecurityNumber => "social_security_number",
            Self::MedicalRecord => "medical_record",
            Self::SshKey => "ssh_key",
            Self::CryptoWallet => "crypto_wallet",
            Self::Person => "person",
            Self::Custom => "custom",
        }
    }

    /// 从 snake_case 名称解析类别。
    ///
    /// 未知字符串返回 `None`（调用方自行决定落入 [`ItemCategory::Custom`]
    /// 还是报错）；`serde` 反序列化则直接落入 `Custom`。
    ///
    /// 命名刻意与 [`ItemCategory::as_str`] 成对，是本模块的两向转换惯例，
    /// **不是** [`std::str::FromStr`] 的 trait 实现（返回 `Option` 而非
    /// `Result`），故允许 `should_implement_trait` 提示。
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "login" => Self::Login,
            "password" => Self::Password,
            "api_credential" => Self::ApiCredential,
            "server" => Self::Server,
            "database" => Self::Database,
            "credit_card" => Self::CreditCard,
            "membership" => Self::Membership,
            "passport" => Self::Passport,
            "software_license" => Self::SoftwareLicense,
            "outdoor_license" => Self::OutdoorLicense,
            "secure_note" => Self::SecureNote,
            "wireless_router" => Self::WirelessRouter,
            "bank_account" => Self::BankAccount,
            "driver_license" => Self::DriverLicense,
            "identity" => Self::Identity,
            "reward_program" => Self::RewardProgram,
            "document" => Self::Document,
            "email_account" => Self::EmailAccount,
            "social_security_number" => Self::SocialSecurityNumber,
            "medical_record" => Self::MedicalRecord,
            "ssh_key" => Self::SshKey,
            "crypto_wallet" => Self::CryptoWallet,
            "person" => Self::Person,
            "custom" => Self::Custom,
            _ => return None,
        })
    }

    /// 返回预设字段模板（见 [`crate::template`]）。
    pub fn preset_fields(self) -> &'static [crate::template::FieldTemplate] {
        crate::template::templates_for(self)
    }
}

/// opvault 分类码 → Coffer 类别的映射（`docs/03-详细设计.md` §6.4.1 全表）。
///
/// `099`（Tombstone，已删除标记）与未知码返回 `None`，由调用方决定
/// 跳过或报错。
pub fn from_opvault_code(code: u16) -> Option<ItemCategory> {
    Some(match code {
        1 => ItemCategory::Login,
        2 => ItemCategory::CreditCard,
        3 => ItemCategory::SecureNote,
        4 => ItemCategory::Identity,
        5 => ItemCategory::Password,
        100 => ItemCategory::SoftwareLicense,
        101 => ItemCategory::BankAccount,
        102 => ItemCategory::Database,
        103 => ItemCategory::DriverLicense,
        104 => ItemCategory::OutdoorLicense,
        105 => ItemCategory::Membership,
        106 => ItemCategory::Passport,
        107 => ItemCategory::RewardProgram,
        108 => ItemCategory::SocialSecurityNumber,
        109 => ItemCategory::WirelessRouter,
        110 => ItemCategory::Server,
        111 => ItemCategory::EmailAccount,
        // 099 = Tombstone（跳过）、其余 = 未知
        _ => return None,
    })
}

impl ItemCategory {
    /// Coffer 类别 → opvault 分类码。
    ///
    /// 无对应 opvault 码的类别（如 `Custom`、`SshKey`、`CryptoWallet`、
    /// `Person` 等）返回 `None`。
    pub fn opvault_code(self) -> Option<u16> {
        Some(match self {
            Self::Login => 1,
            Self::CreditCard => 2,
            Self::SecureNote => 3,
            Self::Identity => 4,
            Self::Password => 5,
            Self::SoftwareLicense => 100,
            Self::BankAccount => 101,
            Self::Database => 102,
            Self::DriverLicense => 103,
            Self::OutdoorLicense => 104,
            Self::Membership => 105,
            Self::Passport => 106,
            Self::RewardProgram => 107,
            Self::SocialSecurityNumber => 108,
            Self::WirelessRouter => 109,
            Self::Server => 110,
            Self::EmailAccount => 111,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全部 24 个变体的权威清单（22 类 + Person + Custom）。
    const ALL_VARIANTS: &[ItemCategory] = &[
        ItemCategory::Login,
        ItemCategory::Password,
        ItemCategory::ApiCredential,
        ItemCategory::Server,
        ItemCategory::Database,
        ItemCategory::CreditCard,
        ItemCategory::Membership,
        ItemCategory::Passport,
        ItemCategory::SoftwareLicense,
        ItemCategory::OutdoorLicense,
        ItemCategory::SecureNote,
        ItemCategory::WirelessRouter,
        ItemCategory::BankAccount,
        ItemCategory::DriverLicense,
        ItemCategory::Identity,
        ItemCategory::RewardProgram,
        ItemCategory::Document,
        ItemCategory::EmailAccount,
        ItemCategory::SocialSecurityNumber,
        ItemCategory::MedicalRecord,
        ItemCategory::SshKey,
        ItemCategory::CryptoWallet,
        ItemCategory::Person,
        ItemCategory::Custom,
    ];

    #[test]
    fn serde_round_trip_all_variants() {
        for cat in ALL_VARIANTS {
            let json = serde_json::to_string(cat).unwrap();
            let back: ItemCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back, "往返失败: {cat:?} -> {json}");
        }
    }

    #[test]
    fn unknown_string_falls_back_to_custom() {
        // 未来新增类别（未知字符串）应反序列化为 Custom，而非报错
        let back: ItemCategory = serde_json::from_str("\"future_category\"").unwrap();
        assert_eq!(back, ItemCategory::Custom);
    }

    #[test]
    fn from_str_unknown_returns_none() {
        assert_eq!(ItemCategory::from_str("future_category"), None);
        assert_eq!(ItemCategory::from_str(""), None);
    }

    #[test]
    fn as_str_from_str_round_trip() {
        for cat in ALL_VARIANTS {
            assert_eq!(ItemCategory::from_str(cat.as_str()), Some(*cat));
        }
    }

    #[test]
    fn opvault_code_round_trip_full_table() {
        // §6.4.1 全表（不含 099 Tombstone）：码 → 类别 → 码 往返
        let table: &[(u16, ItemCategory)] = &[
            (1, ItemCategory::Login),
            (2, ItemCategory::CreditCard),
            (3, ItemCategory::SecureNote),
            (4, ItemCategory::Identity),
            (5, ItemCategory::Password),
            (100, ItemCategory::SoftwareLicense),
            (101, ItemCategory::BankAccount),
            (102, ItemCategory::Database),
            (103, ItemCategory::DriverLicense),
            (104, ItemCategory::OutdoorLicense),
            (105, ItemCategory::Membership),
            (106, ItemCategory::Passport),
            (107, ItemCategory::RewardProgram),
            (108, ItemCategory::SocialSecurityNumber),
            (109, ItemCategory::WirelessRouter),
            (110, ItemCategory::Server),
            (111, ItemCategory::EmailAccount),
        ];
        for (code, cat) in table {
            assert_eq!(from_opvault_code(*code), Some(*cat), "码 {code}");
            assert_eq!(cat.opvault_code(), Some(*code), "{cat:?}");
        }
    }

    #[test]
    fn opvault_tombstone_and_unknown_return_none() {
        // 099 = Tombstone（已删除标记，跳过）
        assert_eq!(from_opvault_code(99), None);
        // 未收录/未知码
        assert_eq!(from_opvault_code(0), None);
        assert_eq!(from_opvault_code(999), None);
    }

    #[test]
    fn opvault_code_none_for_unmapped_categories() {
        // 表中未出现的类别无 opvault 码
        for cat in [
            ItemCategory::ApiCredential,
            ItemCategory::Document,
            ItemCategory::MedicalRecord,
            ItemCategory::SshKey,
            ItemCategory::CryptoWallet,
            ItemCategory::Person,
            ItemCategory::Custom,
        ] {
            assert_eq!(cat.opvault_code(), None, "{cat:?} 不应有 opvault 码");
        }
    }

    #[test]
    fn preset_fields_delegates_to_templates() {
        // 冒烟：类别 → 模板的委托接口存在且 Login 非空
        assert!(!ItemCategory::Login.preset_fields().is_empty());
        assert!(ItemCategory::Custom.preset_fields().is_empty());
    }
}
