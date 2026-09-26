//! 建库与解锁编排（docs/07 §2.2 数据流）。
//!
//! ## 解锁数据流（对齐 docs/02 §6.1 与 docs/03 §2.2–2.6）
//!
//! ```text
//! create_vault(base_dir, name, password):
//!   zxcvbn 强度门禁（score < 3 → CfError::WeakPassword，硬拒绝）
//!   → DEK = SessionKey::random()；salt = random_salt()
//!   → KEK = derive_key(password, salt, KdfParams)
//!   → wrapped_dek = seal(KEK, aad=vault_uuid_bytes‖b"wrapped_dek", DEK)
//!   → verifier    = seal(KEK, aad=vault_uuid_bytes‖b"verifier", 固定常量)
//!   → cf-format::write_header + cf-store::ItemStore::open（schema 建齐）
//!
//! VaultSession::unlock(password):
//!   cf-format::open_container（版本三态）
//!   → normalize_password（NFC，Zeroizing）
//!   → KEK = derive_key(password, salt, header.kdf)
//!   → DEK = open(KEK, aad=vault_uuid‖"wrapped_dek", wrapped_dek)
//!   → verifier 开封并比对固定常量
//!   → SubKeys::derive(&dek, vault_uuid_bytes)
//!   → ItemStore::open(Connection::open(db.sqlite), subkeys)
//!   → password 明文在此 drop（Zeroizing）；会话只持有 SubKeys
//! ```
//!
//! ## 错误码 1002 三态合并（FR-1.4 / docs/04 §4.2）
//!
//! 进入解锁流程（容器打开成功）之后，以下失败**全部**归一为
//! [`CfError::UnlockFailed`]（1002），不泄露哪一步失败：
//!
//! 1. 主密码错误（wrapped_dek / verifier 解封失败）；
//! 2. `wrapped_dek` 密文被篡改（AEAD 认证失败）；
//! 3. `verifier` 密文被篡改（AEAD 认证失败或常量不匹配）；
//! 4. db.sqlite 缺失 / schema 版本损坏等库内数据异常。
//!
//! 容器打开阶段的错误保持区分：目录缺失 → 1003（VaultNotFound）、
//! 版本过新 → 1006（UnsupportedFormat）——此时尚未接触任何密钥材料，
//! 不存在「帮攻击者确认库文件有效性」的泄露面。
//!
//! ## 与 docs/03 §2.6 的一处对齐偏差（记录在案）
//!
//! docs/03 §2.6 的 verifier AAD 为常量 `b"cf/verifier/v1"`；本实现按
//! docs/07 §2.2 的裁定改用 `vault_uuid_bytes ‖ b"verifier"`（把 AAD 钉死
//! 在库上，防止 verifier 密文跨库重放）。 wrapped_dek 同理。

use std::path::Path;

use base64::Engine as _;
use cf_crypto::aead::{open, seal, SessionKey, NONCE_LEN};
use cf_crypto::kdf::{derive_key, random_salt, KdfParams};
use cf_crypto::subkeys::SubKeys;
use cf_domain::vault::Vault as VaultBrief;
use rusqlite::Connection;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::VaultSession;
use crate::{constant_time_eq, SessionResult};
use cf_domain::CfError;

/// verifier 明文固定常量（docs/03 §2.6）。
pub const VERIFIER_PLAINTEXT: &[u8] = b"coffer-verifier-v1";

/// `wrapped_dek` 的 AAD 用途标签（docs/07 §2.2：`vault_uuid_bytes ‖ purpose`）。
const AAD_PURPOSE_WRAPPED_DEK: &[u8] = b"wrapped_dek";

/// `verifier` 的 AAD 用途标签（同上）。
const AAD_PURPOSE_VERIFIER: &[u8] = b"verifier";

/// 工作目录中的数据库文件名（与 cf-format 容器布局一致）。
const DB_FILE: &str = "db.sqlite";

/// v0.1 默认 KDF 档位（docs/07 §6.2 Q-1：沿用 docs/05 开发机摸底值；
/// 参数随 header.json 走，后续可用 `bench_kdf` 标定后调整）。
///
/// 256 MiB / t=3 / p=4 —— 与 cf-format 测试 fixture 的档位一致，
/// 创建界面应给出「解锁约需 x 秒」提示（由平台层读取参数估算）。
#[must_use]
pub fn default_kdf_params() -> KdfParams {
    // 直接构造（字段公开）：该组合必然通过 KdfParams::new 的区间校验
    KdfParams {
        m_cost_kib: 256 * 1024,
        t_cost: 3,
        p_cost: 4,
    }
}

/// 建库：创建容器（cf-format）→ 生成 DEK → Argon2id 封装 → 写 header +
/// verifier → 建库入库（schema 建齐 + meta 初始化）。使用默认 KDF 档位。
///
/// # 错误
///
/// - 主密码 zxcvbn score < 3 → [`CfError::WeakPassword`]（1010，**硬拒绝**，
///   docs/07 §1.1 FR-1.3；裁定为拒绝而非提示）；
/// - 库名为空 / 参数越界 → [`CfError::InvalidArgument`]；
/// - 目标目录已存在（UUIDv7 碰撞，概率可忽略）→ [`CfError::VaultExists`]；
/// - 文件系统失败 → [`CfError::Io`]。
pub fn create_vault(base_dir: &Path, name: &str, password: &str) -> SessionResult<VaultBrief> {
    create_vault_with_kdf(base_dir, name, password, default_kdf_params())
}

/// 建库（可指定 KDF 档位）。测试与参数标定用入口；
/// 生产路径请用 [`create_vault`]。
///
/// # 错误
///
/// 见 [`create_vault`]；`kdf` 越界 → [`CfError::InvalidArgument`]。
pub fn create_vault_with_kdf(
    base_dir: &Path,
    name: &str,
    password: &str,
    kdf: KdfParams,
) -> SessionResult<VaultBrief> {
    if name.trim().is_empty() {
        return Err(CfError::InvalidArgument(
            "vault name must not be empty".into(),
        ));
    }
    kdf.validate()
        .map_err(|_| CfError::InvalidArgument("kdf params out of range".into()))?;

    // FR-1.3：zxcvbn 强度门禁（score < 3 硬拒绝，先于一切文件操作）
    if !cf_audit::meets_strength_threshold(password) {
        return Err(CfError::WeakPassword);
    }

    // NFC 归一化：derive_key 内部会再做一次（幂等），此处提前归一并
    // 立即用 Zeroizing 接管，保证归一化中间值不残留（docs/07 §2.2 清零边界）
    let normalized = Zeroizing::new(cf_crypto::normalize_password(password));

    let vault_uuid = uuid::Uuid::now_v7();
    std::fs::create_dir_all(base_dir).map_err(|e| CfError::Io(e.to_string()))?;
    let vault_dir = base_dir.join(vault_uuid.to_string());
    std::fs::create_dir(&vault_dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CfError::VaultExists
        } else {
            CfError::Io(e.to_string())
        }
    })?;

    let now = crate::unix_now()?;
    let salt = random_salt().map_err(|_| CfError::KdfError)?;
    let kek = derive_key(&normalized, &salt, kdf).map_err(|_| CfError::KdfError)?;
    let kek_key = SessionKey::new(*kek);
    let dek = SessionKey::random().map_err(|_| CfError::KdfError)?;

    let uuid_b = *vault_uuid.as_bytes();
    let wrapped = seal(
        &kek_key,
        &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK),
        dek.as_bytes(),
    )
    .map_err(|_| CfError::KdfError)?;
    let verifier_ct = seal(
        &kek_key,
        &header_aad(&uuid_b, AAD_PURPOSE_VERIFIER),
        VERIFIER_PLAINTEXT,
    )
    .map_err(|_| CfError::KdfError)?;
    // kek_key / dek 在此离开作用域，ZeroizeOnDrop 自动清零

    let header = cf_format::Header {
        format_version: cf_format::FORMAT_VERSION,
        vault_uuid: vault_uuid.to_string(),
        display_name: name.to_owned(),
        created_at: now,
        modified_at: now,
        kdf: cf_format::KdfSection {
            algo: cf_format::header::KDF_ALGO.to_owned(),
            argon2_version: cf_format::header::ARGON2_VERSION,
            m_cost_kib: kdf.m_cost_kib,
            t_cost: kdf.t_cost,
            p_cost: kdf.p_cost,
            salt_b64: b64_encode(&salt),
        },
        aead: cf_format::AeadSection {
            algo: cf_format::header::AEAD_ALGO.to_owned(),
        },
        wrapped_dek: cf_format::WrappedKey {
            nonce_b64: b64_encode(&wrapped[..NONCE_LEN]),
            ct_b64: b64_encode(&wrapped[NONCE_LEN..]),
        },
        verifier: cf_format::VerifierSection {
            nonce_b64: b64_encode(&verifier_ct[..NONCE_LEN]),
            ct_b64: b64_encode(&verifier_ct[NONCE_LEN..]),
        },
        biometric_wrap: cf_format::BiometricWrap {
            available: false,
            provider: None,
            key_alias: None,
            wrapped_dek_b64: None,
        },
        flags: cf_format::HeaderFlags {
            sort_key_enabled: false,
            attachments_inline: false,
        },
    };
    cf_format::write_header(&vault_dir, &header).map_err(format_err)?;

    // 建库入库：schema 一次性建齐全部 11 张表，写入 meta 基线
    let subkeys = SubKeys::derive(dek.as_bytes(), &uuid_b).map_err(|_| CfError::KdfError)?;
    let conn = Connection::open(vault_dir.join(DB_FILE))
        .map_err(|e| CfError::StorageError(e.to_string()))?;
    {
        let store = cf_store::ItemStore::open(conn, subkeys)?;
        let repos = store.repos();
        repos.meta.set_vault_display_name(name)?;
        repos.meta.set_i64(cf_store::KEY_ITEM_COUNT, 0)?;
    } // store 在此 drop；subkeys ZeroizeOnDrop 清零

    Ok(VaultBrief {
        uuid: vault_uuid,
        display_name: name.to_owned(),
        created_at: now,
        modified_at: now,
        format_version: cf_format::FORMAT_VERSION,
    })
}

/// 打开库：读取 header（版本三态）并构造**锁定态**的 [`VaultSession`]。
///
/// 解锁须另行调用 [`VaultSession::unlock`]（KDF 耗时 0.5–1.0 s，
/// 由调用方决定时机）。
///
/// # 错误
///
/// - 目录 / 必需文件缺失 → [`CfError::VaultNotFound`]（1003）；
/// - 版本高于当前支持（或旧库待迁移，v0.1 迁移表为空）→
///   [`CfError::UnsupportedFormat`]（1006，提示升级 App）；
/// - header 畸形 / 校验失败 → [`CfError::Corrupted`]（1005）。
pub fn open_vault(vault_dir: &Path) -> SessionResult<VaultSession> {
    match cf_format::open_container(vault_dir) {
        Ok(cf_format::OpenOutcome::Current(header)) => {
            cf_format::verify_container_layout(vault_dir).map_err(layout_err)?;
            VaultSession::new(vault_dir.to_path_buf(), header)
        }
        Ok(cf_format::OpenOutcome::TooNew(v)) => Err(CfError::UnsupportedFormat(v)),
        Ok(cf_format::OpenOutcome::NeedsMigration { from, .. }) => {
            // v0.1 迁移表为空（cf-format::migrate 恒不支持）；
            // 按「版本不受支持」语义上报，提示升级 App
            Err(CfError::UnsupportedFormat(from))
        }
        Err(cf_format::CfFormatError::ContainerLayout(_)) => Err(CfError::VaultNotFound),
        Err(cf_format::CfFormatError::UnsupportedVersion(v)) => Err(CfError::UnsupportedFormat(v)),
        Err(other) => Err(CfError::Corrupted(other.to_string())),
    }
}

/// 解锁内核：密码 → KEK → DEK → verifier 校验 → SubKeys → ItemStore。
///
/// **全部失败统一归一为 [`CfError::UnlockFailed`]（1002）**，
/// 详见模块文档「错误码 1002 三态合并」。
pub(crate) fn unlock_store(
    vault_dir: &Path,
    header: &cf_format::Header,
    password: &str,
) -> SessionResult<cf_store::ItemStore> {
    const UNLOCK_FAILED: CfError = CfError::UnlockFailed;

    // 布局先于密码：db.sqlite 缺失同样合并为 1002（不区分库损坏形态）
    cf_format::verify_container_layout(vault_dir).map_err(|_| UNLOCK_FAILED)?;

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid).map_err(|_| UNLOCK_FAILED)?;
    let uuid_b = *uuid.as_bytes();

    // 1. NFC 归一化 + Argon2id（参数从 header 读；open_container 已做区间校验，
    //    此处再校验一次防御纵深，失败同样归一为 1002）
    let normalized = Zeroizing::new(cf_crypto::normalize_password(password));
    let salt = b64_decode(&header.kdf.salt_b64).map_err(|_| UNLOCK_FAILED)?;
    let params = KdfParams::new(header.kdf.m_cost_kib, header.kdf.t_cost, header.kdf.p_cost)
        .map_err(|_| UNLOCK_FAILED)?;
    let kek = derive_key(&normalized, &salt, params).map_err(|_| UNLOCK_FAILED)?;
    let kek_key = SessionKey::new(*kek);

    // 2. wrapped_dek 解封 → DEK（密码错 / 密文篡改 → 1002）
    let dek = {
        let mut combined = assembled_sealed(
            header.wrapped_dek.nonce_b64.as_str(),
            header.wrapped_dek.ct_b64.as_str(),
        )
        .map_err(|_| UNLOCK_FAILED)?;
        let plain = open(
            &kek_key,
            &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK),
            &combined,
        )
        .map_err(|_| UNLOCK_FAILED)?;
        combined.zeroize();
        Zeroizing::new(<[u8; 32]>::try_from(plain.as_slice()).map_err(|_| UNLOCK_FAILED)?)
    };

    // 3. verifier 开封并比对固定常量（篡改 verifier → 1002，与密码错同码）
    let verifier_plain = {
        let mut combined = assembled_sealed(
            header.verifier.nonce_b64.as_str(),
            header.verifier.ct_b64.as_str(),
        )
        .map_err(|_| UNLOCK_FAILED)?;
        let plain = open(
            &kek_key,
            &header_aad(&uuid_b, AAD_PURPOSE_VERIFIER),
            &combined,
        )
        .map_err(|_| UNLOCK_FAILED)?;
        combined.zeroize();
        plain
    };
    if !constant_time_eq(&verifier_plain, VERIFIER_PLAINTEXT) {
        return Err(UNLOCK_FAILED);
    }

    // 4. HKDF 派生 7 子密钥（失败归一为 1002——正常输入下不会发生，
    //    但不借错误分支泄露任何派生进度信息）
    let subkeys = SubKeys::derive(&dek, &uuid_b).map_err(|_| UNLOCK_FAILED)?;

    // 5. 打开数据库（连接失败 / schema 版本异常 → 1002）
    let conn = Connection::open(vault_dir.join(DB_FILE)).map_err(|_| UNLOCK_FAILED)?;
    cf_store::ItemStore::open(conn, subkeys).map_err(|_| UNLOCK_FAILED)
}

// ---------------------------------------------------------------- 内部工具

/// 构造 header 段的 AAD：`vault_uuid_bytes ‖ purpose`（docs/07 §2.2）。
fn header_aad(vault_uuid: &[u8; 16], purpose: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_uuid.len() + purpose.len());
    aad.extend_from_slice(vault_uuid);
    aad.extend_from_slice(purpose);
    aad
}

/// header 中的 nonce_b64 + ct_b64 还原为 aead::open 需要的 `nonce ‖ ct ‖ tag`。
fn assembled_sealed(nonce_b64: &str, ct_b64: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let nonce = b64_decode(nonce_b64)?;
    let ct = b64_decode(ct_b64)?;
    let mut combined = Vec::with_capacity(nonce.len() + ct.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ct);
    Ok(combined)
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}

/// cf-format 错误 → 统一错误（建库路径；错误文本不含敏感值，仅路径与字段名）
fn format_err(e: cf_format::CfFormatError) -> CfError {
    match e {
        cf_format::CfFormatError::Io(s) => CfError::Io(s),
        other => CfError::Corrupted(other.to_string()),
    }
}

/// 容器布局错误 → VaultNotFound（open_vault 路径，尚未接触密钥材料）
fn layout_err(_e: cf_format::CfFormatError) -> CfError {
    CfError::VaultNotFound
}
