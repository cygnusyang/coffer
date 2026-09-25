//! 条目快照（历史版本用，`docs/03-详细设计.md` §3.1 history 表）。
//!
//! 快照是可序列化的条目全量状态，加密后写入历史表。**文本一律用 `String`**
//! （而非 [`crate::secret::SecretString`]），因为快照会整体 CBOR 序列化；
//! 加密由存储层负责，本类型只承载"加密前的纯内存态"。

use serde::{Deserialize, Serialize};

use crate::category::ItemCategory;
use crate::field::{Designation, FieldType};
use crate::item::{AttachmentStorage, ItemState};
use crate::totp_data::TotpData;
use crate::{AttachmentId, FieldId, ItemId, SectionId, UrlId};

/// 条目快照（历史版本，CBOR 序列化后加密存储）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemSnapshot {
    /// 条目 ID
    pub uuid: ItemId,
    /// 类别
    pub category: ItemCategory,
    /// 状态
    pub state: ItemState,
    /// 是否收藏
    pub is_favorite: bool,
    /// 收藏排序索引
    pub fav_index: i64,
    /// 创建时间（Unix 秒 UTC）
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）
    pub updated_at: i64,
    /// 标题
    pub title: String,
    /// URL 快照列表
    pub urls: Vec<UrlEntrySnapshot>,
    /// 标签列表
    pub tags: Vec<String>,
    /// 分区快照列表
    pub sections: Vec<SectionSnapshot>,
    /// 字段快照列表
    pub fields: Vec<FieldSnapshot>,
    /// TOTP 配置（若有）
    pub totp: Option<TotpData>,
    /// 附件元数据快照列表
    pub attachments: Vec<AttachmentMetaSnapshot>,
}

/// URL 快照。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UrlEntrySnapshot {
    /// URL 条目 ID
    pub uuid: UrlId,
    /// 标签，可为空
    pub label: Option<String>,
    /// URL
    pub url: String,
    /// 是否主 URL
    pub is_primary: bool,
    /// 排序位置
    pub position: i32,
}

/// 分区快照。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionSnapshot {
    /// 分区 ID
    pub uuid: SectionId,
    /// 分区标题
    pub title: String,
    /// 排序位置
    pub position: i32,
}

/// 字段快照。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldSnapshot {
    /// 字段 ID
    pub uuid: FieldId,
    /// 所属分区 ID
    pub section_uuid: Option<SectionId>,
    /// 字段数据类型
    pub field_type: FieldType,
    /// 语义标识，可为空
    pub designation: Option<Designation>,
    /// 字段名
    pub name: String,
    /// 字段值，可空
    pub value: Option<String>,
    /// 排序位置
    pub position: i32,
}

/// 附件元数据快照。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentMetaSnapshot {
    /// 附件 ID
    pub uuid: AttachmentId,
    /// 文件名
    pub filename: String,
    /// 存储形态
    pub storage: AttachmentStorage,
    /// 明文长度（字节）
    pub size_bytes: u64,
    /// 分块数
    pub chunk_count: u32,
    /// base64(HMAC-SHA256(...))
    pub content_mac: String,
    /// 创建时间（Unix 秒 UTC）
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldType;
    use crate::totp_data::TotpAlgo;

    /// 构造一个完整的 ItemSnapshot（覆盖所有子结构），做 CBOR 往返。
    fn sample_snapshot() -> ItemSnapshot {
        ItemSnapshot {
            uuid: uuid::Uuid::now_v7(),
            category: ItemCategory::Login,
            state: ItemState::Active,
            is_favorite: true,
            fav_index: 3,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
            title: "示例登录".to_owned(),
            urls: vec![UrlEntrySnapshot {
                uuid: uuid::Uuid::now_v7(),
                label: Some("官网".to_owned()),
                url: "https://example.com".to_owned(),
                is_primary: true,
                position: 0,
            }],
            tags: vec!["工作".to_owned(), "重要".to_owned()],
            sections: vec![SectionSnapshot {
                uuid: uuid::Uuid::now_v7(),
                title: "服务器".to_owned(),
                position: 0,
            }],
            fields: vec![FieldSnapshot {
                uuid: uuid::Uuid::now_v7(),
                section_uuid: None,
                field_type: FieldType::Concealed,
                designation: Some(Designation::Password),
                name: "密码".to_owned(),
                value: Some("s3cret".to_owned()),
                position: 0,
            }],
            totp: Some(TotpData {
                secret: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                algo: TotpAlgo::Sha1,
                digits: 6,
                period: 30,
            }),
            attachments: vec![AttachmentMetaSnapshot {
                uuid: uuid::Uuid::now_v7(),
                filename: "ssh.txt".to_owned(),
                storage: AttachmentStorage::Inline,
                size_bytes: 1024,
                chunk_count: 1,
                content_mac: "base64mac==".to_owned(),
                created_at: 1_700_000_000,
            }],
        }
    }

    #[test]
    fn item_snapshot_cbor_round_trip() {
        let snap = sample_snapshot();
        let mut buf = Vec::new();
        ciborium::into_writer(&snap, &mut buf).unwrap();
        let back: ItemSnapshot = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(snap, back, "CBOR 往返后快照应逐字段相等");
    }
}
