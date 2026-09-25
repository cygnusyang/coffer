//! 22 类条目预设字段模板。
//!
//! # 字段映射表来源说明（重要）
//!
//! `docs/01-需求分析.md` FR-2.1/2.2 约定"22 类字段清单以字段映射表形式落地
//! （`03-详细设计.md` §6.3）"，但**当前 `03-详细设计.md` §6.3 实际是
//! opvault 解析，并非字段映射表**——该映射表在文档中缺位。
//!
//! 因此本表按以下依据构造，待真实 1PUX 样本（`03` §13 D-02/D-03）校准：
//! 1. 类别清单：`01` FR-2.1（22 类）+ `03` §4.1 的 `Person`；
//! 2. 字段命名/designation/类型：1Password 各条目类别的公开约定
//!    （Login 的用户名/密码、信用卡的卡号/有效期/CVV、SSH 的私钥等）；
//! 3. 必填约束：Login 的 username/password 为硬约束（自动填充依赖），
//!    其余类别仅主凭据字段标必填，避免过度约束。
//!
//! 若后续拿到官方字段映射表，本表需逐项比对替换（保持公开 API 不变）。

use crate::category::ItemCategory;
use crate::field::FieldType;

/// 预设字段模板：新建某类别条目时自动带出的字段。
///
/// `designation` 是 1Password 风格的设计ation 字符串（自动填充与导入映射
/// 的核心依据）；`default_name` 是新建时默认字段名（中文）；`required`
/// 表示创建/更新时该 designation 的字段必须存在。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldTemplate {
    /// 1Password designation 字符串（如 `username` / `password`）
    pub designation: &'static str,
    /// 字段数据类型
    pub field_type: FieldType,
    /// 新建条目时的默认字段名（中文）
    pub default_name: &'static str,
    /// 是否必填
    pub required: bool,
}

impl FieldTemplate {
    /// 构造字段模板（const 可用）。
    pub const fn new(
        designation: &'static str,
        field_type: FieldType,
        default_name: &'static str,
        required: bool,
    ) -> Self {
        Self {
            designation,
            field_type,
            default_name,
            required,
        }
    }
}

/// 返回某类别的预设字段模板表。
///
/// `Custom` 及未知类别返回空表（不预设字段）；其余类别至少 1 条。
pub fn templates_for(category: ItemCategory) -> &'static [FieldTemplate] {
    match category {
        ItemCategory::Login => LOGIN,
        ItemCategory::Password => PASSWORD,
        ItemCategory::ApiCredential => API_CREDENTIAL,
        ItemCategory::Server => SERVER,
        ItemCategory::Database => DATABASE,
        ItemCategory::CreditCard => CREDIT_CARD,
        ItemCategory::Membership => MEMBERSHIP,
        ItemCategory::Passport => PASSPORT,
        ItemCategory::SoftwareLicense => SOFTWARE_LICENSE,
        ItemCategory::OutdoorLicense => OUTDOOR_LICENSE,
        ItemCategory::SecureNote => SECURE_NOTE,
        ItemCategory::WirelessRouter => WIRELESS_ROUTER,
        ItemCategory::BankAccount => BANK_ACCOUNT,
        ItemCategory::DriverLicense => DRIVER_LICENSE,
        ItemCategory::Identity => IDENTITY,
        ItemCategory::RewardProgram => REWARD_PROGRAM,
        ItemCategory::Document => DOCUMENT,
        ItemCategory::EmailAccount => EMAIL_ACCOUNT,
        ItemCategory::SocialSecurityNumber => SOCIAL_SECURITY_NUMBER,
        ItemCategory::MedicalRecord => MEDICAL_RECORD,
        ItemCategory::SshKey => SSH_KEY,
        ItemCategory::CryptoWallet => CRYPTO_WALLET,
        ItemCategory::Person => PERSON,
        ItemCategory::Custom => &[],
    }
}

// --- 22 类 + Person 的预设字段表 ---

const LOGIN: &[FieldTemplate] = &[
    FieldTemplate::new("username", FieldType::Text, "用户名", true),
    FieldTemplate::new("password", FieldType::Concealed, "密码", true),
    FieldTemplate::new("totp", FieldType::Totp, "一次性密码", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const PASSWORD: &[FieldTemplate] = &[
    FieldTemplate::new("username", FieldType::Text, "用户名", false),
    FieldTemplate::new("password", FieldType::Concealed, "密码", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const API_CREDENTIAL: &[FieldTemplate] = &[
    FieldTemplate::new("username", FieldType::Text, "用户名", false),
    FieldTemplate::new("credential", FieldType::Concealed, "凭据", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const SERVER: &[FieldTemplate] = &[
    FieldTemplate::new("url", FieldType::Url, "网址", false),
    FieldTemplate::new("username", FieldType::Text, "用户名", false),
    FieldTemplate::new("password", FieldType::Concealed, "密码", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const DATABASE: &[FieldTemplate] = &[
    FieldTemplate::new("database", FieldType::Text, "数据库名", false),
    FieldTemplate::new("username", FieldType::Text, "用户名", false),
    FieldTemplate::new("password", FieldType::Concealed, "密码", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const CREDIT_CARD: &[FieldTemplate] = &[
    FieldTemplate::new("cardholder", FieldType::Text, "持卡人", false),
    FieldTemplate::new("cc-number", FieldType::Text, "卡号", true),
    FieldTemplate::new("expiry", FieldType::MonthYear, "有效期", false),
    FieldTemplate::new("cvv", FieldType::Concealed, "安全码", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const MEMBERSHIP: &[FieldTemplate] = &[
    FieldTemplate::new("member-id", FieldType::Text, "会员号", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const PASSPORT: &[FieldTemplate] = &[
    FieldTemplate::new("number", FieldType::Text, "护照号", true),
    FieldTemplate::new("nationality", FieldType::Text, "国籍", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const SOFTWARE_LICENSE: &[FieldTemplate] = &[
    FieldTemplate::new("license-key", FieldType::Concealed, "许可证密钥", true),
    FieldTemplate::new("version", FieldType::Text, "版本", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const OUTDOOR_LICENSE: &[FieldTemplate] = &[
    FieldTemplate::new("license-number", FieldType::Text, "执照号", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const SECURE_NOTE: &[FieldTemplate] = &[FieldTemplate::new(
    "notesPlain",
    FieldType::Multiline,
    "备注",
    false,
)];

const WIRELESS_ROUTER: &[FieldTemplate] = &[
    FieldTemplate::new("name", FieldType::Text, "名称", false),
    FieldTemplate::new("password", FieldType::Concealed, "密码", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const BANK_ACCOUNT: &[FieldTemplate] = &[
    FieldTemplate::new("bank-name", FieldType::Text, "银行名称", false),
    FieldTemplate::new("account-number", FieldType::Text, "账号", true),
    FieldTemplate::new("routing-number", FieldType::Text, "路由号", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const DRIVER_LICENSE: &[FieldTemplate] = &[
    FieldTemplate::new("license-number", FieldType::Text, "驾照号", true),
    FieldTemplate::new("expiry", FieldType::MonthYear, "有效期", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const IDENTITY: &[FieldTemplate] = &[
    FieldTemplate::new("first-name", FieldType::Text, "名", false),
    FieldTemplate::new("last-name", FieldType::Text, "姓", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const REWARD_PROGRAM: &[FieldTemplate] = &[
    FieldTemplate::new("membership-id", FieldType::Text, "会员号", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const DOCUMENT: &[FieldTemplate] = &[
    FieldTemplate::new("doc-number", FieldType::Text, "证件号", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const EMAIL_ACCOUNT: &[FieldTemplate] = &[
    FieldTemplate::new("email", FieldType::Email, "邮箱", false),
    FieldTemplate::new("password", FieldType::Concealed, "密码", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const SOCIAL_SECURITY_NUMBER: &[FieldTemplate] = &[
    FieldTemplate::new("number", FieldType::Text, "社保号", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const MEDICAL_RECORD: &[FieldTemplate] = &[
    FieldTemplate::new("record-type", FieldType::Text, "记录类型", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const SSH_KEY: &[FieldTemplate] = &[
    FieldTemplate::new("private-key", FieldType::Multiline, "私钥", true),
    FieldTemplate::new("public-key", FieldType::Multiline, "公钥", false),
    FieldTemplate::new("passphrase", FieldType::Concealed, "口令", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const CRYPTO_WALLET: &[FieldTemplate] = &[
    FieldTemplate::new("address", FieldType::Text, "地址", false),
    FieldTemplate::new("seed-phrase", FieldType::Concealed, "助记词", true),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

const PERSON: &[FieldTemplate] = &[
    FieldTemplate::new("first-name", FieldType::Text, "名", false),
    FieldTemplate::new("last-name", FieldType::Text, "姓", false),
    FieldTemplate::new("notesPlain", FieldType::Multiline, "备注", false),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Designation;

    /// 全部非 Custom 类别（22 类 + Person）。
    const NON_CUSTOM: &[ItemCategory] = &[
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
    ];

    #[test]
    fn every_non_custom_category_has_at_least_one_template() {
        for cat in NON_CUSTOM {
            assert!(!templates_for(*cat).is_empty(), "{cat:?} 至少应有 1 条模板");
        }
        // Custom 兜底：无预设字段
        assert!(templates_for(ItemCategory::Custom).is_empty());
    }

    #[test]
    fn login_has_required_username_and_password() {
        let tpl = templates_for(ItemCategory::Login);
        let username = tpl.iter().find(|t| t.designation == "username").unwrap();
        let password = tpl.iter().find(|t| t.designation == "password").unwrap();
        assert!(username.required, "Login username 必须必填");
        assert!(password.required, "Login password 必须必填");
        assert_eq!(username.field_type, FieldType::Text);
        assert_eq!(password.field_type, FieldType::Concealed);
    }

    #[test]
    fn login_templates_match_designation_mapping() {
        // 模板 designation 必须能被 Designation::from_1p_str 无冲突解析
        for t in templates_for(ItemCategory::Login) {
            match Designation::from_1p_str(t.designation) {
                Designation::Username
                | Designation::Password
                | Designation::NotesPlain
                | Designation::Totp => {}
                other => panic!("Login 模板 designation 未命中已知语义: {other:?}"),
            }
        }
    }

    #[test]
    fn all_templates_have_valid_designation_and_name() {
        for cat in NON_CUSTOM {
            for t in templates_for(*cat) {
                assert!(!t.designation.is_empty(), "{cat:?} 模板 designation 为空");
                assert!(!t.default_name.is_empty(), "{cat:?} 模板默认名称为空");
                assert_ne!(
                    t.field_type,
                    FieldType::Unsupported,
                    "{cat:?} 预设字段类型不得为 Unsupported"
                );
            }
        }
    }
}
