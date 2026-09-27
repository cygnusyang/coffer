//! HKDF 子密钥容器（`docs/03-详细设计.md` §2.4）。
//!
//! 一钥一用：元数据、条目、字段、附件、历史、清单、附件 MAC 各有独立
//! 子密钥，统一由 DEK 经 HKDF-SHA256 派生（salt = vault_uuid）。若某子密钥
//! 因侧信道泄露，不会波及其他用途；同时保留了密钥轮换的粒度。
//!
//! 上层（如 `cf-store`）只持有 [`SubKeys`]，不直接接触 HKDF 细节。

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::SessionKey;
use crate::error::CfCryptoError;
use crate::kdf::derive_subkey;

// ---------------------------------------------------------------- 用途字面量

/// 元数据子密钥用途字面量。
pub const LABEL_META: &str = "cf/meta/v1";

/// 条目（records）子密钥用途字面量。
pub const LABEL_ITEM: &str = "cf/item/v1";

/// 字段（fields）子密钥用途字面量。
pub const LABEL_FIELD: &str = "cf/field/v1";

/// 附件（files）子密钥用途字面量。
pub const LABEL_FILE: &str = "cf/file/v1";

/// 历史记录子密钥用途字面量。
pub const LABEL_HISTORY: &str = "cf/history/v1";

/// 清单（manifest）子密钥用途字面量。
pub const LABEL_MANIFEST: &str = "cf/manifest/v1";

/// 附件 MAC 子密钥用途字面量。
pub const LABEL_ATTACH_MAC: &str = "cf/attach-mac/v1";

/// 安全审计（Watchtower）子密钥用途字面量（docs/09 §3.5 D-5）。
///
/// 用途：对条目密码做 HMAC-SHA256 指纹（重复密码检测，AUD-02），与
/// 字段加密密钥一钥一用分离。纯运行时派生：不落盘、不改 DDL、
/// 旧库打开时多派生一把即可。
pub const LABEL_AUDIT: &str = "cf/audit/v1";

// ---------------------------------------------------------------- 容器

/// `docs/03-详细设计.md` §2.4 定义的全部子密钥。
///
/// 各字段持有 [`SessionKey`]（Drop 时自动清零，NFR-SEC-04）。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubKeys {
    /// 元数据子密钥（`cf/meta/v1`）。
    pub meta_key: SessionKey,
    /// 条目子密钥（`cf/item/v1`）。
    pub item_key: SessionKey,
    /// 字段子密钥（`cf/field/v1`）。
    pub field_key: SessionKey,
    /// 附件子密钥（`cf/file/v1`）。
    pub file_key: SessionKey,
    /// 历史子密钥（`cf/history/v1`）。
    pub hist_key: SessionKey,
    /// 清单子密钥（`cf/manifest/v1`）。
    pub manifest_key: SessionKey,
    /// 附件 MAC 子密钥（`cf/attach-mac/v1`）。
    pub attach_mac_key: SessionKey,
    /// 安全审计子密钥（`cf/audit/v1`，docs/09 §3.5 D-5）。
    pub audit_key: SessionKey,
}

impl SubKeys {
    /// 从 DEK 派生全部子密钥。
    ///
    /// salt 固定取 `vault_uuid`，保证不同保险库的子密钥互不相同
    /// （见 [`crate::kdf::derive_subkey`]）。
    pub fn derive(dek: &[u8; 32], vault_uuid: &[u8; 16]) -> Result<Self, CfCryptoError> {
        Ok(Self {
            meta_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_META)?),
            item_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_ITEM)?),
            field_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_FIELD)?),
            file_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_FILE)?),
            hist_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_HISTORY)?),
            manifest_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_MANIFEST)?),
            attach_mac_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_ATTACH_MAC)?),
            audit_key: SessionKey::new(derive_subkey(dek, vault_uuid, LABEL_AUDIT)?),
        })
    }
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dek() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_vault_uuid() -> [u8; 16] {
        [0x11u8; 16]
    }

    /// 八个子密钥两两互不相同（一钥一用）。
    #[test]
    fn 八个子密钥两两互不相同() {
        let keys = SubKeys::derive(&test_dek(), &test_vault_uuid()).expect("派生成功");
        let all = [
            &keys.meta_key,
            &keys.item_key,
            &keys.field_key,
            &keys.file_key,
            &keys.hist_key,
            &keys.manifest_key,
            &keys.attach_mac_key,
            &keys.audit_key,
        ];

        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(
                    a.as_bytes(),
                    b.as_bytes(),
                    "子密钥重复（索引 {i}），一钥一用被破坏"
                );
            }
        }
    }

    /// 每个子密钥都是 32 字节且非全零。
    #[test]
    fn 每个子密钥长度与内容有效() {
        let keys = SubKeys::derive(&test_dek(), &test_vault_uuid()).expect("派生成功");
        let all = [
            &keys.meta_key,
            &keys.item_key,
            &keys.field_key,
            &keys.file_key,
            &keys.hist_key,
            &keys.manifest_key,
            &keys.attach_mac_key,
            &keys.audit_key,
        ];

        for k in all {
            assert_eq!(k.as_bytes().len(), 32);
            assert_ne!(k.as_bytes(), &[0u8; 32], "子密钥全零，实现可疑");
        }
    }

    /// 不同保险库 → 整个 SubKeys 集合都不同（逐字段比较）。
    #[test]
    fn 不同vault_uuid派生出不同子密钥集合() {
        let a = SubKeys::derive(&test_dek(), &[0x11u8; 16]).expect("派生成功");
        let b = SubKeys::derive(&test_dek(), &[0x22u8; 16]).expect("派生成功");

        assert_ne!(a.meta_key.as_bytes(), b.meta_key.as_bytes());
        assert_ne!(a.item_key.as_bytes(), b.item_key.as_bytes());
        assert_ne!(a.field_key.as_bytes(), b.field_key.as_bytes());
        assert_ne!(a.file_key.as_bytes(), b.file_key.as_bytes());
        assert_ne!(a.hist_key.as_bytes(), b.hist_key.as_bytes());
        assert_ne!(a.manifest_key.as_bytes(), b.manifest_key.as_bytes());
        assert_ne!(a.attach_mac_key.as_bytes(), b.attach_mac_key.as_bytes());
        assert_ne!(a.audit_key.as_bytes(), b.audit_key.as_bytes());
    }

    /// 相同输入 → 相同集合（确定性）。
    #[test]
    fn 派生是确定性的() {
        let a = SubKeys::derive(&test_dek(), &test_vault_uuid()).expect("派生成功");
        let b = SubKeys::derive(&test_dek(), &test_vault_uuid()).expect("派生成功");

        assert_eq!(a.meta_key.as_bytes(), b.meta_key.as_bytes());
        assert_eq!(a.attach_mac_key.as_bytes(), b.attach_mac_key.as_bytes());
        assert_eq!(a.audit_key.as_bytes(), b.audit_key.as_bytes());
    }

    /// audit_key 已知答案测试（docs/09 §3.5 D-5 冻结契约）。
    ///
    /// 期望值由独立 Python 实现按相同输入计算（2026-09-28，随 v0.2
    /// G3 引入 `cf/audit/v1` label 时首算）：HKDF-SHA256，salt =
    /// vault_uuid，ikm = dek，info = label，L = 32。
    #[test]
    fn audit_key与已知答案一致() {
        let dek = [0x42u8; 32];
        let vault_uuid = [0x11u8; 16];

        let keys = SubKeys::derive(&dek, &vault_uuid).expect("派生成功");
        let expected: Vec<u8> = "93ec6676592e99d5b4aeb1ff5b5e6a9a9aac8a3da9ecf47429e4d14e411ca6ae"
            .as_bytes()
            .chunks(2)
            .map(|h| u8::from_str_radix(std::str::from_utf8(h).expect("hex is utf-8"), 16).expect("hex digit"))
            .collect();
        assert_eq!(keys.audit_key.as_bytes(), expected.as_slice());

        // 直接走 label 派生必须与容器字段一致（防两处漂移）
        let direct = crate::kdf::derive_subkey(&dek, &vault_uuid, LABEL_AUDIT).expect("派生成功");
        assert_eq!(keys.audit_key.as_bytes(), direct.as_slice());
    }

    /// audit_key 与其余七把子密钥用途分离：不同 label 必派生不同密钥。
    #[test]
    fn audit_key与其他子密钥互不相同() {
        let keys = SubKeys::derive(&test_dek(), &test_vault_uuid()).expect("派生成功");
        assert_ne!(keys.audit_key.as_bytes(), keys.meta_key.as_bytes());
        assert_ne!(keys.audit_key.as_bytes(), keys.field_key.as_bytes());
        assert_ne!(keys.audit_key.as_bytes(), keys.attach_mac_key.as_bytes());
    }
}
