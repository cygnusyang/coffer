//! 会话层跨模块数据结构（docs/07 §2.2 / §2.3 的 Rust 侧形态）。
//!
//! 这些类型是 cf-ffi（T04）`types.rs` 的**上游素材**：跨 FFI 时敏感值
//! 以 `String` 传递不可避免（docs/07 §4.2），本层先用
//! [`cf_domain::secret::SecretString`] 收紧暴露面，FFI 映射时再显式降级。

use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::ItemState;
use cf_domain::secret::SecretString;

/// 解锁成功后的库信息（docs/07 §2.3 `VaultSession.unlock` 的返回值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultInfo {
    /// 库 UUID（UUIDv7 文本）。
    pub vault_uuid: String,
    /// 库显示名（header.json 明文，锁定时也可见）。
    pub display_name: String,
    /// 条目计数（meta.item_count，已知元数据泄露项）。
    pub item_count: i64,
}

/// 生物识别解锁的三态（docs/08 §7.5 设置页状态行 / §3.1 双信号语义）。
///
/// 判定依据是两个独立信号的组合：
///
/// - **header 侧持久意愿**：`biometric_wrap.available`（Rust 持有，锁定态
///   可查 [`crate::vault::VaultSession::has_biometric_wrap`]）；
/// - **Keychain 实际可用性**：K_bio 项存在且可读（Swift 侧 `itemExists` /
///   read，T03 范围）。
///
/// 两者可能不一致（指纹集变更后 Keychain 失效而 header 仍 available=true），
/// 由纯函数 [`BiometricStatus::from_availability`] 组合判定，可本地测试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricStatus {
    /// 已停用：header `available == false`（用户意图关闭或从未开启）。
    Disabled,
    /// 已启用：header `available == true` 且 Keychain 项可用。
    Enabled,
    /// 凭据已失效（BioStale）：header `available == true` 但 Keychain 项
    /// 失效（指纹集变更）。UI 应显示「重新启用」入口（docs/08 §4.1）。
    Stale,
}

impl BiometricStatus {
    /// 由「header 持久意愿」与「Keychain 实际可用性」组合判定三态。
    ///
    /// Keychain 信号由平台层（Swift）注入；Rust 侧提供纯判定逻辑，
    /// 使状态机可完全本地测试（T01 验收范围）。
    #[must_use]
    pub fn from_availability(header_available: bool, keychain_readable: bool) -> Self {
        match (header_available, keychain_readable) {
            (true, true) => Self::Enabled,
            (true, false) => Self::Stale,
            (false, _) => Self::Disabled,
        }
    }
}

/// TOTP 当前验证码（docs/07 §2.3 `TotpCode`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    /// 当前验证码（6 或 8 位数字）。
    pub code: String,
    /// 距下一个时间窗口的剩余秒数（供 UI 倒计时环）。
    pub secs_remaining: u64,
}

/// 条目读取态：完整详情（敏感字段为 `SecretString`）。
///
/// 对应 docs/07 §2.3 `ItemDetails`；与 [`cf_domain::item::Item`] 的差异：
/// TOTP 只带元数据（验证码经 `VaultSession::totp_code` 按需生成，密钥
/// 永不出会话层），附件元数据 v0.1 不读（表已建、仓库层未实现）。
#[derive(Debug)]
pub struct ItemDetails {
    /// 条目 ID（UUIDv7 文本）。
    pub uuid: String,
    /// 条目类别。
    pub category: ItemCategory,
    /// 条目状态。
    pub state: ItemState,
    /// 是否收藏。
    pub is_favorite: bool,
    /// 收藏排序索引。
    pub fav_index: i64,
    /// 创建时间（Unix 秒 UTC）。
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）。
    pub updated_at: i64,
    /// 解密后的标题。
    pub title: SecretString,
    /// URL 列表。
    pub urls: Vec<UrlDetail>,
    /// 解密后的标签。
    pub tags: Vec<SecretString>,
    /// 分区列表。
    pub sections: Vec<SectionDetail>,
    /// 字段列表。
    pub fields: Vec<FieldDetail>,
    /// TOTP 元数据（若有）。
    pub totp: Option<TotpDetail>,
}

/// URL 条目读取态（`urls` 表行，解密后）。
#[derive(Debug)]
pub struct UrlDetail {
    /// URL 行 ID。
    pub uuid: String,
    /// 解密后的标签，可为空。
    pub label: Option<SecretString>,
    /// 解密后的 URL。
    pub url: SecretString,
    /// 是否主 URL。
    pub is_primary: bool,
    /// 排序位置。
    pub position: i64,
}

/// 分区读取态（`sections` 表行，解密后）。
#[derive(Debug)]
pub struct SectionDetail {
    /// 分区 ID。
    pub uuid: String,
    /// 解密后的分区标题。
    pub title: SecretString,
    /// 排序位置。
    pub position: i64,
}

/// 字段读取态（`fields` 表行，解密后）。
#[derive(Debug)]
pub struct FieldDetail {
    /// 字段 ID。
    pub uuid: String,
    /// 所属分区；`None` 表示直接挂在条目下。
    pub section_uuid: Option<String>,
    /// 字段数据类型。
    pub field_type: FieldType,
    /// 语义标识，可为空。
    pub designation: Option<Designation>,
    /// 解密后的字段名。
    pub name: SecretString,
    /// 解密后的字段值，可空（如仅有名称的布尔标记）。
    pub value: Option<SecretString>,
    /// 排序位置。
    pub position: i64,
}

/// TOTP 元数据读取态（`totp` 表行，issuer / account 解密后）。
///
/// 刻意**不含共享密钥**：验证码经 `VaultSession::totp_code` 按需生成。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpDetail {
    /// TOTP 记录 ID。
    pub uuid: String,
    /// 哈希算法（`sha1` / `sha256` / `sha512`；运行时仅支持 `sha1`）。
    pub algo: String,
    /// 口令位数（6 或 8）。
    pub digits: u8,
    /// 时间窗口秒数。
    pub period: u32,
    /// 发行方显示名（可选）。
    pub issuer: Option<String>,
    /// 账户名（可选）。
    pub account: Option<String>,
}
