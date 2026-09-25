//! 保险库元数据（`docs/03-详细设计.md` §1.3 header.json 的领域映射）。

use serde::{Deserialize, Serialize};

use crate::VaultId;

/// 保险库元数据。
///
/// 对应 `docs/03-详细设计.md` §1.3 header.json 中的非敏感头部字段。
/// `display_name` 锁定后仍需展示（库选择），故为明文已知泄露项
/// （威胁模型已声明，见 `03` §1.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    /// 保险库 ID（同时作为 KEK/DEK 的 AAD 成分，防跨库替换）
    pub uuid: VaultId,
    /// 展示名（明文，锁定时需显示）
    pub display_name: String,
    /// 创建时间（Unix 秒 UTC）
    pub created_at: i64,
    /// 最后修改时间（Unix 秒 UTC）
    pub modified_at: i64,
    /// 容器格式版本（用于格式迁移）
    pub format_version: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_serde_round_trip() {
        let v = Vault {
            uuid: uuid::Uuid::now_v7(),
            display_name: "我的密码库".to_owned(),
            created_at: 1_700_000_000,
            modified_at: 1_700_000_000,
            format_version: 1,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: Vault = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}
