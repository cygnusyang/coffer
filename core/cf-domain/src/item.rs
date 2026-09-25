//! 条目核心结构体：条目、字段、分区、URL、附件，以及草稿 / 摘要 / 快照。

use serde::{Deserialize, Serialize};

use crate::category::ItemCategory;
use crate::field::{Designation, FieldType};
use crate::secret::SecretString;
use crate::totp_data::TotpData;
use crate::{AttachmentId, FieldId, ItemId, SectionId, UrlId};

/// 条目状态（`docs/03-详细设计.md` §3.1 items.state，0/1/2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemState {
    /// 正常（0）
    Active,
    /// 已归档（1），不出现在默认列表
    Archived,
    /// 已移入回收站（2），可恢复
    Trashed,
}

/// 附件存储形态（`docs/03-详细设计.md` §3.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentStorage {
    /// 内联存储（≤ 64 KiB，存 SQLite BLOB）
    Inline,
    /// 外置文件（> 64 KiB，写入 attachments/）
    File,
}

/// URL 条目（`docs/03-详细设计.md` §3.1 urls 表）。支持一条目多 URL 带标签。
#[derive(Debug)]
pub struct UrlEntry {
    /// URL 条目 ID
    pub uuid: UrlId,
    /// 标签（如"登录页""管理后台"），可为空
    pub label: Option<SecretString>,
    /// URL 明文（解密后才填充）
    pub url: SecretString,
    /// 是否主 URL
    pub is_primary: bool,
    /// 排序位置
    pub position: i32,
}

/// 分区（对应 1Password 条目的 section，`docs/03-详细设计.md` §3.1 sections 表）。
#[derive(Debug)]
pub struct Section {
    /// 分区 ID
    pub uuid: SectionId,
    /// 分区标题（解密后）
    pub title: SecretString,
    /// 排序位置
    pub position: i32,
}

/// 字段（`docs/03-详细设计.md` §3.1 fields 表 / §4.3）。
#[derive(Debug)]
pub struct Field {
    /// 字段 ID
    pub uuid: FieldId,
    /// 所属分区；`None` 表示直接挂在条目下
    pub section_uuid: Option<SectionId>,
    /// 字段数据类型
    pub field_type: FieldType,
    /// 语义标识（自动填充与导入映射核心依据），可为空
    pub designation: Option<Designation>,
    /// 字段名（解密后）
    pub name: SecretString,
    /// 字段值（解密后），可空（如仅有名称的布尔标记）
    pub value: Option<SecretString>,
    /// 排序位置
    pub position: i32,
}

/// 附件元数据（`docs/03-详细设计.md` §3.1 attachments 表 / §3.4）。
///
/// 注意：`content_mac` 是 base64(HMAC-SHA256)，**不是**明文哈希
/// （`03` 修正 B：明文哈希会泄露"两个附件是否相同"）。
#[derive(Debug)]
pub struct AttachmentMeta {
    /// 附件 ID
    pub uuid: AttachmentId,
    /// 文件名（解密后）
    pub filename: SecretString,
    /// 存储形态（内联 / 外置文件）
    pub storage: AttachmentStorage,
    /// 明文长度（字节；已知元数据泄露项，见 `03` §3.5）
    pub size_bytes: u64,
    /// 分块数
    pub chunk_count: u32,
    /// base64(HMAC-SHA256(attach_mac_key, 明文内容))
    pub content_mac: String,
    /// 创建时间（Unix 秒 UTC）
    pub created_at: i64,
}

/// 完整条目（`docs/03-详细设计.md` §4.3）。
///
/// 敏感字段均为 [`SecretString`]（解密后才填充）；本结构体**不含**
/// 任何未解密的状态，锁定/未解密时条目不可用。
#[derive(Debug)]
pub struct Item {
    /// 条目 ID（UUIDv7）
    pub uuid: ItemId,
    /// 条目类别
    pub category: ItemCategory,
    /// 条目状态
    pub state: ItemState,
    /// 是否收藏
    pub is_favorite: bool,
    /// 收藏排序索引（来自 1PUX favIndex）
    pub fav_index: i64,
    /// 创建时间（Unix 秒 UTC）
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）
    pub updated_at: i64,
    /// 标题（解密后才填充）
    pub title: SecretString,
    /// URL 列表
    pub urls: Vec<UrlEntry>,
    /// 标签（解密后）
    pub tags: Vec<SecretString>,
    /// 分区列表
    pub sections: Vec<Section>,
    /// 字段列表
    pub fields: Vec<Field>,
    /// TOTP 配置（若有）
    pub totp: Option<TotpData>,
    /// 附件元数据
    pub attachments: Vec<AttachmentMeta>,
}

/// 条目创建/更新的草稿（用户输入，明文）。
///
/// 用于 [`crate::validate::validate_item`] 校验后落库；`position` 为
/// 用户提供的排序意图，校验保证同层级内无重复。
#[derive(Debug, Clone, PartialEq)]
pub struct ItemDraft {
    /// 标题（非空、≤ 512 字符）
    pub title: String,
    /// 条目类别
    pub category: ItemCategory,
    /// URL 草稿列表
    pub urls: Vec<UrlDraft>,
    /// 标签列表
    pub tags: Vec<String>,
    /// 分区草稿列表
    pub sections: Vec<SectionDraft>,
    /// 字段草稿列表
    pub fields: Vec<FieldDraft>,
    /// TOTP 配置（若有）
    pub totp: Option<TotpData>,
}

/// URL 草稿。
#[derive(Debug, Clone, PartialEq)]
pub struct UrlDraft {
    /// 标签，可为空
    pub label: Option<String>,
    /// URL
    pub url: String,
    /// 是否主 URL
    pub is_primary: bool,
    /// 排序位置
    pub position: i32,
}

/// 分区草稿。
#[derive(Debug, Clone, PartialEq)]
pub struct SectionDraft {
    /// 分区标题
    pub title: String,
    /// 排序位置
    pub position: i32,
}

/// 字段草稿。
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDraft {
    /// 字段名
    pub name: String,
    /// 字段值，可空
    pub value: Option<String>,
    /// 字段数据类型
    pub field_type: FieldType,
    /// 语义标识，可为空
    pub designation: Option<Designation>,
    /// 所属分区（指向 [`ItemDraft::sections`] 的下标）
    pub section_index: Option<usize>,
    /// 排序位置
    pub position: i32,
}

/// 条目摘要（列表 / 搜索结果，`docs/03-详细设计.md` §3.2-3.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    /// 条目 ID
    pub uuid: ItemId,
    /// 类别
    pub category: ItemCategory,
    /// 状态
    pub state: ItemState,
    /// 是否收藏
    pub is_favorite: bool,
    /// 最后修改时间（Unix 秒 UTC）
    pub updated_at: i64,
    /// 标题（已解密）
    pub title: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    #[test]
    fn item_state_serde_round_trip() {
        for s in [ItemState::Active, ItemState::Archived, ItemState::Trashed] {
            let json = serde_json::to_string(&s).unwrap();
            let back: ItemState = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn attachment_storage_serde_round_trip() {
        for s in [AttachmentStorage::Inline, AttachmentStorage::File] {
            let json = serde_json::to_string(&s).unwrap();
            let back: AttachmentStorage = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    /// SecretString 参与模型（冒烟：构造与取用）。
    #[test]
    fn secret_string_used_in_model() {
        let title = SecretString::from_exposed("我的登录");
        let field = Field {
            uuid: uuid::Uuid::now_v7(),
            section_uuid: None,
            field_type: FieldType::Text,
            designation: Some(Designation::Username),
            name: SecretString::from_exposed("用户名"),
            value: Some(SecretString::from_exposed("alice")),
            position: 0,
        };
        assert_eq!(title.expose(), "我的登录");
        assert_eq!(field.name.expose(), "用户名");
        assert_eq!(field.value.unwrap().expose(), "alice");
    }
}
