//! 修改主密码（FR-1.8，docs/09 §3.2 D-2 架构裁决）。
//!
//! ## 只重封装 DEK，不重加密全库（D-2）
//!
//! 本架构中条目数据由 DEK 经 HKDF 派生的 SubKeys 加密（docs/03 §2.4），
//! 主密码只经 Argon2id 生成 KEK 封装 DEK（docs/03 §2.2）。**换主密码 =
//! 换 KEK = 只需重封装 header 中的 `wrapped_dek` 与 `verifier`**，
//! db.sqlite 一个字节都不用动。需求措辞「全库重新加密」描述的是
//! 1Password 式实现的意图，其本质是「换密后旧密码失效」——方案 A
//! 完全满足该本质（docs/09 §3.2 D-2 裁决，docs/01 §5-A 备注由 G4 回写）。
//!
//! ## 流程（docs/09 §3.2 冻结签名）
//!
//! ```text
//! new_password 过 zxcvbn 门禁（<3 → 1010，先于任何文件操作）
//! → recover_dek(old_password) 重验证旧密码（错 → 1002，header 未动）
//! → salt' = random_salt()；KEK' = derive_key(new, salt', kdf')
//! → wrapped_dek' = seal(KEK', aad=uuid‖"wrapped_dek", DEK)
//! → verifier'    = seal(KEK', aad=uuid‖"verifier", VERIFIER_PLAINTEXT)
//! → header.modified_at 更新 → write_header 原子重写
//! ```
//!
//! bio 封装（`wrapped_dek_bio`）**不动**：K_bio 封装的是 DEK 本身，
//! 与 KEK 无关——换密后 Touch ID 解锁照常可用。`new_kdf` 可选参数
//! 支持顺带升级 KDF 档位（M0-② 标定后的补偿路径）。
//!
//! 重封装内核（① 门禁 → ② 档位校验 → ③ 新盐 + KEK → ④ 重包 → ⑤ 保留
//! wraps → ⑥ 原子写）抽为公共 helper [`repack_dek_with_new_password`]：
//! change_password 与 v2.5.0 FR-17 的 reset 三兄弟（生物识别/恢复码重置）
//! 共享之，差异只在 DEK 获取途径（主密码 / k_bio / 恢复码）。

use std::path::Path;

use cf_crypto::aead::{seal, SessionKey};
use cf_crypto::kdf::{derive_key, random_salt, KdfParams};
use cf_domain::CfError;
use zeroize::Zeroizing;

use crate::unlock::{
    format_err, header_aad, recover_dek, AAD_PURPOSE_VERIFIER, AAD_PURPOSE_WRAPPED_DEK,
    VERIFIER_PLAINTEXT,
};
use crate::SessionResult;

/// 用新主密码就地重封装 header 中的 DEK 与 verifier（v2.5.0 FR-17 公共 helper）。
///
/// change_password（FR-1.8）与 v2.5.0 FR-17 的 reset 三兄弟（生物识别/恢复码
/// 重置）共享本函数：三者都是「拿到 DEK + 新密码 → 换 KEK 重封装」，差异只在
/// DEK 获取途径（主密码 / k_bio / 恢复码），故重封装内核抽为公共段
/// （docs/31 v2.5.0 §3.2 M-REPACK）。
///
/// 就地修改 `header` 的 `kdf` / `wrapped_dek` / `verifier` / `modified_at`；
/// **bio / mcp / recovery 封装字段原样保留**——K_bio / K_mcp / K_recovery
/// 封装的都是 DEK 本身，与主密码 KEK 无关，换密后各通道解锁照常可用。
///
/// 本函数**不写盘**（签名无 `vault_dir`）：落盘由调用方经 [`cf_format::write_header`]
/// 完成，保持既有「临时文件 + rename 原子写」语义——任何失败时磁盘 header 原样、
/// 旧密码仍可解锁。调用方若需保留旧 header，应先 clone 再传本函数。
///
/// # 错误
///
/// - `new_password` zxcvbn score < 3 → [`CfError::WeakPassword`]（1010）；
/// - `new_kdf` 参数越界 → [`CfError::InvalidArgument`]（5002）；
/// - 随机源 / KDF / AEAD 失败 → [`CfError::KdfError`]（1007）；
/// - `vault_uuid` 非 UUID 文本 → [`CfError::Corrupted`]；
/// - 系统时钟在 Unix epoch 之前 → [`CfError::StorageError`]。
pub(crate) fn repack_dek_with_new_password(
    header: &mut cf_format::Header,
    dek: [u8; 32],
    new_password: &str,
    new_kdf: Option<KdfParams>,
) -> SessionResult<()> {
    // 1. 新密码强度门禁（1010）——先于任何文件/密钥操作。change_password_impl
    //    已先做过同款门禁（保持 1010 先于 1002 的既有错误优先级）；此处重复
    //    校验是为 reset 调用方自包含（它们没有 recover_dek 前置校验），幂等。
    if !cf_audit::meets_strength_threshold(new_password) {
        return Err(CfError::WeakPassword);
    }

    // 2. 可选 KDF 档位校验（5002）——同样先于密钥操作
    if let Some(k) = &new_kdf {
        k.validate()
            .map_err(|_| CfError::InvalidArgument("kdf params out of range".into()))?;
    }

    // 3. 新盐 + 新 KEK（档位 = new_kdf 或沿用 header.kdf）
    let salt = random_salt().map_err(|_| CfError::KdfError)?;
    let kdf = match new_kdf {
        Some(k) => k,
        None => KdfParams::new(header.kdf.m_cost_kib, header.kdf.t_cost, header.kdf.p_cost)
            .map_err(|_| CfError::KdfError)?,
    };
    // NFC 归一化：derive_key 内部会再做一次（幂等），此处提前归一并
    // 立即用 Zeroizing 接管（与建库/解锁路径同纪律）
    let normalized = Zeroizing::new(cf_crypto::normalize_password(new_password));
    let kek = derive_key(&normalized, &salt, kdf).map_err(|_| CfError::KdfError)?;
    let kek_key = SessionKey::new(*kek);

    // 4. 用新 KEK 重封装 DEK 与 verifier（AAD 沿用既有用途标签，钉库）
    let uuid = uuid::Uuid::parse_str(&header.vault_uuid)
        .map_err(|_| CfError::Corrupted("vault_uuid is not a valid uuid".into()))?;
    let uuid_b = *uuid.as_bytes();
    // 入参 DEK 拷贝立即用 Zeroizing 接管（离开本函数时自动清零）
    let dek = Zeroizing::new(dek);
    let wrapped = seal(
        &kek_key,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK),
        &*dek,
    )
    .map_err(|_| CfError::KdfError)?;
    let verifier_ct = seal(
        &kek_key,
        &header_aad(&uuid_b, AAD_PURPOSE_VERIFIER),
        VERIFIER_PLAINTEXT,
    )
    .map_err(|_| CfError::KdfError)?;
    // kek_key / normalized / dek 在此离开作用域，ZeroizeOnDrop 自动清零

    // 5. 就地更新 kdf / wrapped_dek / verifier / modified_at（bio/mcp/recovery
    //    封装字段不触碰、原样保留——见函数文档 ⑤ 契约）
    header.kdf = cf_format::KdfSection {
        algo: cf_format::header::KDF_ALGO.to_owned(),
        argon2_version: cf_format::header::ARGON2_VERSION,
        m_cost_kib: kdf.m_cost_kib,
        t_cost: kdf.t_cost,
        p_cost: kdf.p_cost,
        salt_b64: crate::unlock::b64_encode(&salt),
    };
    header.wrapped_dek = cf_format::WrappedKey {
        nonce_b64: crate::unlock::b64_encode(&wrapped[..cf_crypto::aead::NONCE_LEN]),
        ct_b64: crate::unlock::b64_encode(&wrapped[cf_crypto::aead::NONCE_LEN..]),
    };
    header.verifier = cf_format::VerifierSection {
        nonce_b64: crate::unlock::b64_encode(&verifier_ct[..cf_crypto::aead::NONCE_LEN]),
        ct_b64: crate::unlock::b64_encode(&verifier_ct[cf_crypto::aead::NONCE_LEN..]),
    };
    header.modified_at = crate::unix_now()?;
    Ok(())
}

/// 修改主密码（header 侧内核，docs/09 §3.2）。
///
/// 详见 [`crate::vault::VaultSession::change_password`]（门禁：解锁态
/// 1001，由会话层执行）。本函数保证：任何失败发生时磁盘 header 保持
/// 原样（`write_header` 为临时文件 + rename 原子替换；且一切密钥操作
/// 都先于文件写入），成功时返回新 header 供调用方更新内存副本。
///
/// 流程 = 旧密码重验证（recover_dek）→ 重封装内核委托
/// [`repack_dek_with_new_password`]（就地修改克隆）→ 原子重写。
///
/// # 错误
///
/// - 新密码 zxcvbn score < 3 → [`CfError::WeakPassword`]（1010）；
/// - `new_kdf` 参数越界 → [`CfError::InvalidArgument`]（5002）；
/// - 旧密码错误 / 库数据异常 → [`CfError::UnlockFailed`]（1002）；
/// - 随机源 / KDF / AEAD 失败 → [`CfError::KdfError`]（1007）；
/// - header 写失败 → [`CfError::Io`] / [`CfError::Corrupted`]（磁盘原样）。
pub(crate) fn change_password_impl(
    vault_dir: &Path,
    header: &cf_format::Header,
    old_password: &str,
    new_password: &str,
    new_kdf: Option<KdfParams>,
) -> SessionResult<cf_format::Header> {
    // 1. 新密码强度门禁（1010）——先于任何文件操作（docs/09 §3.2）。此处先做
    //    门禁是为保持 1010 先于 1002 的既有错误优先级；repack helper 内的门禁
    //    是幂等重复（供 reset 调用方自包含），两者不冲突。
    if !cf_audit::meets_strength_threshold(new_password) {
        return Err(CfError::WeakPassword);
    }

    // 2. 可选 KDF 档位校验（5002）——同样先于文件与密钥操作
    if let Some(k) = &new_kdf {
        k.validate()
            .map_err(|_| CfError::InvalidArgument("kdf params out of range".into()))?;
    }

    // 3. 旧密码重验证（1002，此时 header 未被触碰）→ 解出 DEK
    let dek = recover_dek(vault_dir, header, old_password)?;

    // 4. 用新密码重封装 header 副本（就地修改克隆；失败时原 header 与磁盘均
    //    未动——write_header 是临时文件 + rename 原子替换，docs/09 §3.2 要点 4）
    let mut new_header = header.clone();
    repack_dek_with_new_password(&mut new_header, *dek.as_bytes(), new_password, new_kdf)?;

    // 5. 原子重写（cf-format::write_header：临时文件 + rename）；失败则
    //    磁盘 header 保持原样，旧密码仍可解锁（原子性，docs/09 §3.2 要点 4）
    cf_format::write_header(vault_dir, &new_header).map_err(format_err)?;
    Ok(new_header)
}

#[cfg(test)]
mod tests {
    use crate::unlock::{create_vault_with_kdf, open_vault};
    use cf_crypto::kdf::KdfParams;

    use super::*;

    /// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
    fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";
    /// 换成的新强密码。
    const NEW_PASSWORD: &str = "portable-copper-drift-lantern-77#";

    /// 读磁盘上的 header.json（字节级，供「header 未变」断言）。
    fn header_bytes(vault_dir: &std::path::Path) -> Vec<u8> {
        std::fs::read(vault_dir.join("header.json")).unwrap()
    }

    /// 换密 → lock → 旧密码解锁失败（1002）、新密码解锁成功；
    /// bio 封装不受换密影响（启用 → 换密 → bio 解锁仍成功）
    #[test]
    fn 换密后旧密码失效新密码生效且bio不受影响() {
        let base = crate::tests_support::temp_dir("cp_roundtrip");
        let brief = create_vault_with_kdf(&base, "换密库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        // 先启用 bio 封装（D-2：bio 封装 DEK，换密不动它）
        session.unlock(STRONG_PASSWORD).unwrap();
        let k_bio = crate::unlock_bio::new_biometric_unwrap_key().unwrap();
        session
            .enable_biometric(STRONG_PASSWORD, k_bio.as_bytes())
            .unwrap();

        session
            .change_password(STRONG_PASSWORD, NEW_PASSWORD, None)
            .unwrap();
        session.lock();

        // 旧密码失效（1002）、新密码生效
        let err = session.unlock(STRONG_PASSWORD).unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(session.unlock(NEW_PASSWORD).is_ok());

        // bio 解锁不受换密影响
        session.lock();
        assert!(session.unlock_with_biometric(k_bio.as_bytes()).is_ok());
    }

    /// 旧密码错 → 1002 且 header 字节不变
    #[test]
    fn 旧密码错header不变() {
        let base = crate::tests_support::temp_dir("cp_old_wrong");
        let brief = create_vault_with_kdf(&base, "旧错库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let before = header_bytes(&vault_dir);
        let err = session
            .change_password("totally-wrong-password-99!", NEW_PASSWORD, None)
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert_eq!(header_bytes(&vault_dir), before, "header 必须未变");
    }

    /// 新密码弱 → 1010 且 header 字节不变（门禁先于一切文件操作）
    #[test]
    fn 新密码弱header不变() {
        let base = crate::tests_support::temp_dir("cp_weak");
        let brief = create_vault_with_kdf(&base, "弱密库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let before = header_bytes(&vault_dir);
        let err = session
            .change_password(STRONG_PASSWORD, "123456", None)
            .unwrap_err();
        assert_eq!(err.code(), 1010);
        assert_eq!(header_bytes(&vault_dir), before, "header 必须未变");
    }

    /// 原子性：write_header 前失败（旧密码错先触达）→ 磁盘 header 完整、
    /// 旧密码仍可解锁；写失败（目录只读注入）→ 同样保持旧 header 可用
    #[test]
    fn 中途失败旧header完整旧密码可用() {
        let base = crate::tests_support::temp_dir("cp_atomic");
        let brief = create_vault_with_kdf(&base, "原子库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        // 注入写失败：目录置只读（header 读取不受影响，rename 必败）。
        // root 环境下 chmod 不构成写入屏障，探测到即跳过（CI 用户态有效）。
        let mut perms = std::fs::metadata(&vault_dir).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        let original_mode = perms.mode();
        perms.set_mode(0o555);
        std::fs::set_permissions(&vault_dir, perms).unwrap();

        let write_blocked = std::fs::metadata(&vault_dir).unwrap().permissions().mode() == 0o555;
        if write_blocked {
            let before = header_bytes(&vault_dir);
            let err = session
                .change_password(STRONG_PASSWORD, NEW_PASSWORD, None)
                .unwrap_err();
            assert!(
                matches!(err, CfError::Io(_) | CfError::Corrupted(_)),
                "写失败应报 IO/Corrupted，实际 {err:?}"
            );
            assert_eq!(
                header_bytes(&vault_dir),
                before,
                "写失败后磁盘 header 必须完整"
            );
        }

        // 恢复权限（无论是否注入成功，收尾必须可写）
        let mut perms = std::fs::metadata(&vault_dir).unwrap().permissions();
        perms.set_mode(original_mode);
        std::fs::set_permissions(&vault_dir, perms).unwrap();

        // 旧密码仍可解锁（原子性）
        session.lock();
        assert!(
            session.unlock(STRONG_PASSWORD).is_ok(),
            "失败换密不得破坏旧密码"
        );
    }

    /// new_kdf 传入新档位 → header.kdf 更新且新密码解锁走新参数
    #[test]
    fn 换密顺带升级kdf档位() {
        let base = crate::tests_support::temp_dir("cp_kdf");
        let brief = create_vault_with_kdf(&base, "档位库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let bigger = KdfParams::new(16 * 1024, 2, 1).unwrap();
        session
            .change_password(STRONG_PASSWORD, NEW_PASSWORD, Some(bigger))
            .unwrap();
        session.lock();

        // 新密码 + 新参数解锁成功（参数从 header 读）
        let info = session.unlock(NEW_PASSWORD).unwrap();
        assert_eq!(info.item_count, 0);

        // 磁盘 header.kdf 与传入档位一致，盐已换新
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["kdf"]["m_cost_kib"], serde_json::json!(16 * 1024));
        assert_eq!(json["kdf"]["t_cost"], serde_json::json!(2));
        assert_eq!(json["kdf"]["p_cost"], serde_json::json!(1));
        assert_ne!(
            json["kdf"]["salt_b64"].as_str().unwrap(),
            "",
            "盐必须重新生成"
        );
    }

    /// new_kdf 越界 → 5002 且 header 未变（先于密钥操作）
    #[test]
    fn 非法kdf档位被拒绝() {
        let base = crate::tests_support::temp_dir("cp_bad_kdf");
        let brief =
            create_vault_with_kdf(&base, "非法档位库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        let before = header_bytes(&vault_dir);
        let err = session
            .change_password(
                STRONG_PASSWORD,
                NEW_PASSWORD,
                Some(KdfParams {
                    m_cost_kib: 1, // 低于 MIN_M_COST_KIB（8 MiB）
                    t_cost: 1,
                    p_cost: 1,
                }),
            )
            .unwrap_err();
        assert_eq!(err.code(), 5002);
        assert_eq!(header_bytes(&vault_dir), before);
    }

    /// 换密后立即换回（对称往返）：旧密码路径可再次生效
    #[test]
    fn 换密往返() {
        let base = crate::tests_support::temp_dir("cp_back");
        let brief = create_vault_with_kdf(&base, "往返库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        session
            .change_password(STRONG_PASSWORD, NEW_PASSWORD, None)
            .unwrap();
        session
            .change_password(NEW_PASSWORD, STRONG_PASSWORD, None)
            .unwrap();
        session.lock();

        assert!(session.unlock(STRONG_PASSWORD).is_ok());
        session.lock();
        assert!(
            session.unlock(NEW_PASSWORD).is_err(),
            "旧新密码已换回，NEW 应失效"
        );
    }

    /// repack helper 契约（FR-17 §3.2）：只改 kdf / wrapped_dek / verifier /
    /// modified_at，bio 与 mcp 封装原样保留（K_bio / K_mcp 封装 DEK 本身，与
    /// 主密码 KEK 无关），盐与封装全部换新。直接调用 helper（不写盘），只验证
    /// 就地修改契约。
    #[test]
    fn repack保留bio与mcp封装不动且重封装换新() {
        let base = crate::tests_support::temp_dir("cp_repack_contract");
        let brief = create_vault_with_kdf(&base, "repack库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        // 启用 bio 封装（biometric_wrap 置位），再给内存 header 手工塞 mcp_wrap
        let k_bio = crate::unlock_bio::new_biometric_unwrap_key().unwrap();
        session
            .enable_biometric(STRONG_PASSWORD, k_bio.as_bytes())
            .unwrap();
        let text = std::fs::read_to_string(vault_dir.join("header.json")).unwrap();
        let mut header: cf_format::Header = serde_json::from_str(&text).unwrap();
        let mcp = cf_format::McpWrap {
            available: true,
            provider: Some("macos-keychain".to_string()),
            key_alias: Some("cn.coffer.mcp-escrow".to_string()),
            wrapped_dek_b64: Some(crate::unlock::b64_encode(&[0x55u8; 48])),
        };
        header.mcp_wrap = mcp.clone();

        // 快照待断言字段
        let bio_before = header.biometric_wrap.clone();
        let salt_before = header.kdf.salt_b64.clone();
        let dek_nonce_before = header.wrapped_dek.nonce_b64.clone();
        let verifier_ct_before = header.verifier.ct_b64.clone();
        let modified_before = header.modified_at;

        // 直接调用 helper（不写盘：本测试只验证就地修改契约）
        repack_dek_with_new_password(&mut header, [0x42; 32], NEW_PASSWORD, None).unwrap();

        // ⑤ 契约：bio / mcp 封装原样保留
        assert_eq!(header.biometric_wrap, bio_before);
        assert_eq!(header.mcp_wrap, mcp);
        // ④ 契约：盐 / wrapped_dek nonce / verifier 密文全部换新（随机盐与 nonce，
        //    再封装必得不同密文）
        assert_ne!(header.kdf.salt_b64, salt_before);
        assert_ne!(header.wrapped_dek.nonce_b64, dek_nonce_before);
        assert_ne!(header.verifier.ct_b64, verifier_ct_before);
        // modified_at 前进（同一秒内可能相等，故用 >=）
        assert!(header.modified_at >= modified_before);
    }
}
