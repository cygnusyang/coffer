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
//!   → password 明文在此 drop（Zeroizing）；会话只持 SubKeys，不持 DEK
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
//!
//! ## v0.2 增量（docs/08 §6）
//!
//! [`recover_dek`]（密码 → KEK → DEK，含 verifier 校验）与
//! [`finish_unlock`](crate::unlock::finish_unlock)（DEK → SubKeys →
//! ItemStore）自 `unlock_store` 拆出，供生物识别通道
//! （[`crate::unlock_bio`]）复用：`enable_biometric` 借 `recover_dek`
//! 重验证主密码并解出 DEK（D-6），`unlock_with_biometric` 借
//! `finish_unlock` 与主密码路径共享收尾。行为零变化（T01 验收 ①）。

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
/// change_password 重封装复用同一标签（docs/09 §3.2）。
pub(crate) const AAD_PURPOSE_WRAPPED_DEK: &[u8] = b"wrapped_dek";

/// `verifier` 的 AAD 用途标签（同上）。
pub(crate) const AAD_PURPOSE_VERIFIER: &[u8] = b"verifier";

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
    // 建库写侧名校验（v2.10.0，docs/17 §6.2 F4 / AC-2.10.0-NM-1）：
    // 只拦新建；读侧（open_container / open_vault）严禁加 display_name 校验，
    // 既有含首尾空格 / 超长库名必须照常打开（兼容红线，docs/17 §6.2 ①）。
    if name.trim().is_empty() {
        return Err(CfError::InvalidArgument(
            "vault name must not be empty".into(),
        ));
    }
    if name != name.trim() {
        return Err(CfError::InvalidArgument(
            "vault name must not have leading or trailing whitespace".into(),
        ));
    }
    if name.len() > MAX_VAULT_NAME_LEN {
        return Err(CfError::InvalidArgument(format!(
            "vault name must not exceed {MAX_VAULT_NAME_LEN} bytes"
        )));
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
        // 新库默认不启用 MCP 托管（escrow 由 App 侧显式 enable，docs/29 §2）
        mcp_wrap: cf_format::McpWrap::default(),
        // 新库默认不启用恢复码封装（FR-17.2，docs/31 §1.1）
        recovery_wrap: None,
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
/// 开库成功后**顺带清理孤儿附件**（v0.4 M-2：`attachments/` 下未被 DB
/// 行引用的旁路文件与 `.tmp-` 崩溃残留；关闭 v0.3 LOW-2 登记的口子）。
/// 该清理以明文 schema 的引用集为准、无需密钥，一次性全目录扫描成本
/// 可接受；失败不阻断开库（尽力而为，孤儿留待下次开库重试）。
/// **单会话假设**（与 [`crate::usecase::cross_copy`] 同款）：若另一会话
/// 正对同一库处于「文件已落、行未提交」的写入中，其 in-flight 附件可能
/// 被误删——桌面单用户场景下不存在（open 无互斥；多会话并发写入若
/// 未来放开，须改为定向清理）。
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
            let session = VaultSession::new(vault_dir.to_path_buf(), header);
            cleanup_orphans_best_effort(vault_dir);
            session
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

/// 解锁内核第一步（docs/08 §6 拆分裁定）：**主密码 → KEK → 解封 DEK**，
/// 并完成 verifier 校验（主密码证明）。
///
/// `unlock_store` 与 bio 通道的 `enable_biometric` 共用本函数：
/// enable 借此同时校验主密码并解出 DEK（D-6），错密码 → 1002。
///
/// 步骤 1–3（布局检查 → Argon2id → wrapped_dek 解封 → verifier 比对），
/// 全部失败统一归一为 [`CfError::UnlockFailed`]（1002）。
pub(crate) fn recover_dek(
    vault_dir: &Path,
    header: &cf_format::Header,
    password: &str,
) -> SessionResult<SessionKey> {
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
        let open_result = open(
            &kek_key,
            &header_aad(&uuid_b, AAD_PURPOSE_WRAPPED_DEK),
            &combined,
        );
        combined.zeroize();
        let mut plain = open_result.map_err(|_| UNLOCK_FAILED)?;
        let dek =
            Zeroizing::new(<[u8; 32]>::try_from(plain.as_slice()).map_err(|_| UNLOCK_FAILED)?);
        // Zeroizing 持有的是拷贝；原始 Vec 同样清零，不留密钥副本
        plain.zeroize();
        dek
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

    // kek_key / normalized 在此离开作用域，自动清零
    Ok(SessionKey::new(*dek))
}

/// 解锁内核收尾（步骤 4–5）：DEK → SubKeys 派生 → ItemStore 打开。
/// 主密码路径与 bio 路径（docs/08 §6「共享步骤 3–5」）共用。
///
/// 步骤 5 之后追加**完整性校验**（NFR-REL-02/03，docs/09 §2 v0.2-T04）：
/// `verify_integrity` 校验 meta 基线（缺行自举 = 旧库兼容），任何失败
/// 归一为 [`CfError::UnlockFailed`]（1002，三态合并纪律延伸到完整性路径，
/// 不泄露「完整性失败」细节，FR-1.4 / TC-MAC-06）。
pub(crate) fn finish_unlock(
    vault_dir: &Path,
    header: &cf_format::Header,
    dek: &SessionKey,
) -> SessionResult<cf_store::ItemStore> {
    const UNLOCK_FAILED: CfError = CfError::UnlockFailed;

    let uuid = uuid::Uuid::parse_str(&header.vault_uuid).map_err(|_| UNLOCK_FAILED)?;
    let uuid_b = *uuid.as_bytes();

    // 4. HKDF 派生 9 子密钥（失败归一为 1002——正常输入下不会发生，
    //    但不借错误分支泄露任何派生进度信息）
    let subkeys = SubKeys::derive(dek.as_bytes(), &uuid_b).map_err(|_| UNLOCK_FAILED)?;

    // 5. 打开数据库（连接失败 / schema 版本异常 → 1002）
    let conn = Connection::open(vault_dir.join(DB_FILE)).map_err(|_| UNLOCK_FAILED)?;
    let store = cf_store::ItemStore::open(conn, subkeys).map_err(|_| UNLOCK_FAILED)?;

    // 5b. 完整性校验（NFR-REL-02/03）：meta 基线缺失则自举（旧库兼容，
    //     open 后连接为读写模式，可安全落盘）；计数/MAC 不符 → 1002
    let meta = cf_store::MetaRepo::new(store.connection());
    meta.verify_integrity(&store.subkeys().root_mac_key)
        .map_err(|_| UNLOCK_FAILED)?;

    Ok(store)
}

/// 解锁内核：密码 → KEK → DEK → verifier 校验 → SubKeys → ItemStore。
///
/// **全部失败统一归一为 [`CfError::UnlockFailed`]（1002）**，
/// 详见模块文档「错误码 1002 三态合并」。
///
/// 返回已打开的 [`cf_store::ItemStore`]：DEK 已转入 `SubKeys`，会话不持 DEK。
pub(crate) fn unlock_store(
    vault_dir: &Path,
    header: &cf_format::Header,
    password: &str,
) -> SessionResult<cf_store::ItemStore> {
    let dek = recover_dek(vault_dir, header, password)?;
    finish_unlock(vault_dir, header, &dek)
}

// ---------------------------------------------------------------- 内部工具

/// 构造 header 段的 AAD：`vault_uuid_bytes ‖ purpose`（docs/07 §2.2）。
/// bio 通道（unlock_bio）复用同一规则钉库（docs/08 D-2）。
pub(crate) fn header_aad(vault_uuid: &[u8; 16], purpose: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(vault_uuid.len() + purpose.len());
    aad.extend_from_slice(vault_uuid);
    aad.extend_from_slice(purpose);
    aad
}

/// header 中的 nonce_b64 + ct_b64 还原为 aead::open 需要的 `nonce ‖ ct ‖ tag`。
pub(crate) fn assembled_sealed(
    nonce_b64: &str,
    ct_b64: &str,
) -> Result<Vec<u8>, base64::DecodeError> {
    let nonce = b64_decode(nonce_b64)?;
    let ct = b64_decode(ct_b64)?;
    let mut combined = Vec::with_capacity(nonce.len() + ct.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ct);
    Ok(combined)
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}

/// cf-format 错误 → 统一错误（建库路径；错误文本不含敏感值，仅路径与字段名）。
/// bio 通道的 header 重写（enable/disable）复用同一映射。
pub(crate) fn format_err(e: cf_format::CfFormatError) -> CfError {
    match e {
        cf_format::CfFormatError::Io(s) => CfError::Io(s),
        other => CfError::Corrupted(other.to_string()),
    }
}

/// 容器布局错误 → VaultNotFound（open_vault 路径，尚未接触密钥材料）
fn layout_err(_e: cf_format::CfFormatError) -> CfError {
    CfError::VaultNotFound
}

/// 孤儿附件清理（open_vault 成功路径，见 [`open_vault`] 文档）：
/// 自开只读明文连接供 [`cf_store::AttachmentRepo::cleanup_orphans`] 构建
/// 引用集；失败静默（尽力而为纪律，与 cross_copy 的 Err 收尾一致——
/// 开库不因清理失败被阻断，孤儿留待下次开库重试）。
///
/// 防御：db.sqlite 缺失时直接返回（`Connection::open` 会凭空创建空库
/// 文件，产生无主副产物；布局校验已保证库存在，此处仅防时序边界）。
fn cleanup_orphans_best_effort(vault_dir: &Path) {
    let db_path = vault_dir.join(DB_FILE);
    if !db_path.is_file() {
        return;
    }
    if let Ok(conn) = Connection::open(&db_path) {
        let _ = cf_store::AttachmentRepo::cleanup_orphans(vault_dir, &conn);
    }
}

/// 库显示名长度上限（字节，v2.10.0 建库写侧校验，docs/04-测试与验收/17 §7
/// AC-2.10.0-NM-1）。只拦**新建**；既有超长库名读侧照常打开（兼容红线，
/// 见 [`create_vault_with_kdf`] 文档）。
const MAX_VAULT_NAME_LEN: usize = 128;

/// 物理删除一个库（v2.10.0，docs/17 §2.1 C5）：rename-then-delete，重试收敛。
///
/// 执行序列：
/// 0. 清扫历史 tombstone（`<base_dir>/.coffer-deleted-<uuid>-*`）：重试收敛
///    （docs/17 §6.3）——「①成功而②/③失败」的残留在下一次删除时先被重跑
///    ②去 header + ③物理删除；无匹配 / base_dir 不存在 → 幂等 no-op；
/// 1. `vault_uuid` 必须是合法 UUID 文本（防路径拼接逃逸，镜像 [`open_vault`]）
///    ——非法 → [`CfError::InvalidArgument`]（5002）；
/// 2. 目标目录 `<base_dir>/<uuid>/` 不存在 → `Ok(())`（幂等：对齐
///    [`crate::unlock`] 对缺失/损坏目录的韧性，删一半重试语义友好）；
/// 3. `fs::rename` 到 tombstone（`<base_dir>/.coffer-deleted-<uuid>-<epoch>`）：
///    rename 成功即库从规范位置消失；
/// 4. 移除 tombstone 内的 `header.json`：使残留 tombstone 对 list_vaults
///    **不可见**（docs/17 §2.1 机制「tombstone 目录无 header.json →
///    open_container 失败 → 被 list_vaults 天然跳过」——rename 整个库目录
///    会把 header.json 一并带进 tombstone，须显式移除才能达成该机制）；
///    孤儿目录本无 `header.json` → NotFound 按幂等 no-op（见 [`delete_vault`]
///    文档「孤儿库」语义）；
/// 5. 物理 `fs::remove_dir_all(tombstone)` 收尾。
///
/// # 错误
///
/// - uuid 非法 → [`CfError::InvalidArgument`]（5002）；
/// - 文件族删除 I/O 失败（部分删除，如步骤 4/5 之一失败）→
///   [`CfError::Io`]（5001，可重试；重试先清扫历史 tombstone 收敛）：
///   - 步骤 4 成功而 5 失败的残留已无 header.json → 不被 list_vaults 枚举；
///   - 步骤 4 失败（header 仍在，如 tombstone 只读）→ 残留被枚举（幽灵），
///     恢复权限后重试即收敛（HIGH-1）；启动期清扫归 backlog（docs/16 §6.2）。
///
/// 不做 header 解析：按 uuid 路径直删，不读 header——不产生 1005 路径，
/// 与「孤儿库 / 忘密库无密码即可删」语义一致（docs/17 §2.1）。
pub fn delete_vault(base_dir: &Path, vault_uuid: &str) -> SessionResult<()> {
    let uuid = uuid::Uuid::parse_str(vault_uuid).map_err(|_| {
        CfError::InvalidArgument("vault_uuid is not a valid uuid".into())
    })?;
    // 步骤 0：先清扫历史 tombstone，使「①成功而②/③失败」的残留在下一次
    // 删除时按契约收敛（HIGH-1，docs/17 §6.3 重试收敛）。
    cleanup_tombstones(base_dir, &uuid)?;
    let vault_dir = base_dir.join(uuid.to_string());
    if !vault_dir.exists() {
        return Ok(());
    }
    let tombstone = base_dir.join(format!(
        ".coffer-deleted-{uuid}-{}",
        crate::unix_now()?
    ));
    std::fs::rename(&vault_dir, &tombstone).map_err(|e| CfError::Io(e.to_string()))?;
    // 去 header.json（见函数文档步骤 4）：使物理删除失败时残留的 tombstone
    // 也不被 list_vaults 枚举；孤儿库本无 header.json → remove_file 报
    // NotFound 按幂等 no-op（与「目录不存在 → Ok」一致，docs/17 §2.1）。
    remove_tombstone_header(&tombstone)?;
    std::fs::remove_dir_all(&tombstone).map_err(|e| CfError::Io(e.to_string()))?;
    Ok(())
}

/// 清扫指定 uuid 的历史 tombstone（delete_vault 步骤 0）：对
/// `<base_dir>/.coffer-deleted-<uuid>-*` 每个重跑「②去 header + ③
/// remove_dir_all」，使「①成功而②/③失败」的部分删除残留按契约收敛
/// （docs/17 §6.3 重试收敛）。base_dir 不存在 / 无匹配 tombstone → 幂等
/// no-op。
fn cleanup_tombstones(base_dir: &Path, uuid: &uuid::Uuid) -> SessionResult<()> {
    let prefix = format!(".coffer-deleted-{uuid}-");
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CfError::Io(e.to_string())),
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(&prefix) {
            continue;
        }
        remove_tombstone_header(&entry.path())?;
        std::fs::remove_dir_all(entry.path()).map_err(|e| CfError::Io(e.to_string()))?;
    }
    Ok(())
}

/// 步骤 ② 原子操作：移除 tombstone 内 `header.json`，使残留 tombstone 对
/// list_vaults 不可见。NotFound（孤儿库无 header）按幂等 no-op，其余 I/O
/// 错误报 Io（可重试）。delete_vault 新 tombstone 与 cleanup_tombstones
/// 历史 tombstone 共用本步骤。
fn remove_tombstone_header(tombstone: &Path) -> SessionResult<()> {
    match std::fs::remove_file(tombstone.join("header.json")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(CfError::Io(e.to_string())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::temp_dir;

    /// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
    fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

    /// 建一个测试库（返回 brief，uuid 即目录名）。
    fn setup_vault(base: &Path, name: &str) -> cf_domain::vault::Vault {
        create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
    }

    // ------------------------------------------------------ delete_vault

    /// delete_vault：删除后 `<base>/<uuid>` 目录消失（文件族物理删除）。
    #[test]
    fn delete_vault删除后目录消失() {
        let base = temp_dir("del_gone");
        let brief = setup_vault(&base, "删除库");
        let vault_dir = base.join(brief.uuid.to_string());
        assert!(vault_dir.is_dir(), "建库后目录应存在");

        delete_vault(&base, &brief.uuid.to_string()).unwrap();

        assert!(!vault_dir.exists(), "删除后库目录应消失");
        // 无 tombstone 残留（成功路径物理收尾干净）
        let leftovers: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".coffer-deleted-"))
            .collect();
        assert!(leftovers.is_empty(), "成功删除不应残留 tombstone");
    }

    /// delete_vault：目录不存在 → Ok（幂等，第二次删同库不报错）。
    #[test]
    fn delete_vault不存在目录_幂等成功() {
        let base = temp_dir("del_idem");
        let uuid = uuid::Uuid::now_v7();
        delete_vault(&base, &uuid.to_string()).unwrap();
        // 幂等删除无副作用：不创建库目录、不残留 tombstone
        assert!(!base.join(uuid.to_string()).exists());
        let leftovers: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".coffer-deleted-"))
            .collect();
        assert!(leftovers.is_empty(), "不存在目录的删除不得残留 tombstone");
    }

    /// delete_vault：孤儿目录（无 header.json）照常可删——步骤② remove_file
    /// NotFound 按幂等 no-op（docs/17 §2.1：孤儿库/忘密库无密码即可删语义，
    /// 与「目录不存在 → Ok」幂等一致）。
    #[test]
    fn delete_vault孤儿目录无header_可删() {
        let base = temp_dir("del_orphan");
        let uuid = uuid::Uuid::now_v7();
        let vault_dir = base.join(uuid.to_string());
        std::fs::create_dir_all(&vault_dir).unwrap();

        delete_vault(&base, &uuid.to_string()).unwrap();
        assert!(!vault_dir.exists(), "孤儿目录删除后应消失");
        let leftovers: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".coffer-deleted-"))
            .collect();
        assert!(leftovers.is_empty(), "孤儿目录成功删除不应残留 tombstone");
    }

    /// delete_vault：非法 uuid → 5002（防路径拼接逃逸，镜像 open_vault）。
    #[test]
    fn delete_vault非法uuid_返回5002() {
        let base = temp_dir("del_bad");
        for bad in ["../escape", "not-a-uuid", "../vaults/../../etc/passwd"] {
            let err = delete_vault(&base, bad).unwrap_err();
            assert_eq!(err.code(), 5002, "应拒 {bad:?}");
            assert!(matches!(err, CfError::InvalidArgument(_)));
        }
    }

    /// delete_vault：rename 成功但 remove_dir_all 失败（只读子目录注入）→
    /// 库从规范位置消失、tombstone 残留且**不被枚举**（已去 header.json →
    /// open_container 失败 → list_vaults 跳过，docs/17 §2.4 测试 4）。
    #[test]
    fn delete_vault重命名后立即对枚举不可见() {
        let base = temp_dir("del_tomb");
        let brief = setup_vault(&base, "墓碑库");
        let uuid = brief.uuid.to_string();
        let vault_dir = base.join(&uuid);

        // 注入只读子目录（内含一个文件）：rename 不受影响；remove_dir_all
        // 删子目录内的文件需该目录 +w，故失败（Unix 目录权限语义）
        let ro_dir = vault_dir.join("attachments");
        std::fs::create_dir_all(&ro_dir).unwrap();
        std::fs::write(ro_dir.join("blob.dat"), b"x").unwrap();
        let mut perms = std::fs::metadata(&ro_dir).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&ro_dir, perms).unwrap();

        let err = delete_vault(&base, &uuid).unwrap_err();
        assert!(matches!(err, CfError::Io(_)), "remove_dir_all 应失败：{err}");
        assert_eq!(err.code(), 5001);

        // 库从规范位置消失（rename 生效）
        assert!(!vault_dir.exists(), "删除失败后库目录也不应存在于规范位置");

        // tombstone 残留
        let tombstones: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".coffer-deleted-"))
            .collect();
        assert_eq!(tombstones.len(), 1, "应残留一个 tombstone");

        // tombstone 不被枚举：无 header.json → open_container 失败（机制
        // 与 list_vaults 跳过一致）；同时 list_vaults 侧另有 FFI 级断言
        let tombstone_dir = tombstones[0].path();
        assert!(!tombstone_dir.join("header.json").exists(), "tombstone 不应含 header.json");
        assert!(
            cf_format::open_container(&tombstone_dir).is_err(),
            "无 header.json 的 tombstone 不应被 open_container 识别为库"
        );

        // 还原写权限（仅属主 rwx，不放开其他），让临时目录可被测试框架回收
        let ro_dir_now = tombstone_dir.join("attachments");
        let mut perms = std::fs::metadata(&ro_dir_now).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(&ro_dir_now, perms).unwrap();
    }

    /// delete_vault 重试收敛（HIGH-1，docs/17 §6.3 冻结契约）：库根只读 →
    /// rename 成功（只须 base_dir 父目录可写）、remove_file(header.json) 失败
    /// → 首调 5001，tombstone 残留且**仍含 header**（幽灵可枚举）；恢复权限
    /// 重试 → 先清扫历史 tombstone（重跑 ②③）→ Ok 且无残留、不再被枚举。
    #[test]
    fn delete_vault重试收敛_首调失败后重试成功() {
        let base = temp_dir("del_retry");
        let brief = setup_vault(&base, "重试库");
        let uuid = brief.uuid.to_string();
        let vault_dir = base.join(&uuid);

        // 库根只读：rename 可过（父目录可写），remove_file(header) 因
        // tombstone 继承库根只读权限而失败 → 首调 5001
        let mut perms = std::fs::metadata(&vault_dir).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&vault_dir, perms.clone()).unwrap();

        let err = delete_vault(&base, &uuid).unwrap_err();
        assert_eq!(err.code(), 5001, "库根只读应使 remove_file 失败");

        // 规范路径已消失、tombstone 残留且仍含 header.json（幽灵，会被
        // list_vaults 枚举——这正是必须重试收敛的原因）
        assert!(!vault_dir.exists(), "rename 后规范路径应消失");
        let tombstones: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".coffer-deleted-"))
            .collect();
        assert_eq!(tombstones.len(), 1, "应残留一个含 header 的 tombstone");
        assert!(
            tombstones[0].path().join("header.json").exists(),
            "②失败路径下 header.json 应仍在 tombstone 中"
        );

        // 恢复库根写权限后重试 → 清扫历史 tombstone 收敛，Ok 且无残留
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o700);
        std::fs::set_permissions(tombstones[0].path(), perms).unwrap();
        delete_vault(&base, &uuid).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".coffer-deleted-"))
            .collect();
        assert!(leftovers.is_empty(), "重试后应无 tombstone 残留");
    }

    // ------------------------------------------- 建库名校验（G-D，NM-1）

    /// create_vault 拒首尾空白库名（docs/17 §6.2 F4，AC-2.10.0-NM-1）。
    #[test]
    fn create_vault拒绝首尾空白库名() {
        let base = temp_dir("nm_ws");
        for name in ["  我的密码库", "我的密码库  ", "  我的密码库  "] {
            let err = create_vault_with_kdf(&base, name, STRONG_PASSWORD, fast_kdf())
                .unwrap_err();
            assert_eq!(err.code(), 5002, "应拒 {name:?}");
            assert!(matches!(err, CfError::InvalidArgument(_)));
        }
    }

    /// create_vault 拒全空白库名（既有空名校验不变，NM-1 全空白用例）。
    #[test]
    fn create_vault拒绝全空白库名() {
        let base = temp_dir("nm_blank");
        let err =
            create_vault_with_kdf(&base, "   ", STRONG_PASSWORD, fast_kdf()).unwrap_err();
        assert_eq!(err.code(), 5002);
        assert!(matches!(err, CfError::InvalidArgument(_)));
    }

    /// create_vault 拒超长库名（> 128 字节，NM-1 超长用例）。
    #[test]
    fn create_vault拒绝超长库名() {
        let base = temp_dir("nm_long");
        let too_long = "a".repeat(MAX_VAULT_NAME_LEN + 1);
        let err = create_vault_with_kdf(&base, &too_long, STRONG_PASSWORD, fast_kdf())
            .unwrap_err();
        assert_eq!(err.code(), 5002);
        assert!(matches!(err, CfError::InvalidArgument(_)));
    }

    /// create_vault 边界 128 合法（NM-1 边界用例：len == 上限放行）。
    #[test]
    fn create_vault边界128合法() {
        let base = temp_dir("nm_128");
        let ok = "a".repeat(MAX_VAULT_NAME_LEN);
        let brief = create_vault_with_kdf(&base, &ok, STRONG_PASSWORD, fast_kdf()).unwrap();
        assert_eq!(brief.display_name, ok);
    }

    /// create_vault 多字节库名字节口径（MEDIUM-1 裁定：128 = UTF-8 字节数，
    /// 实现用 `name.len()` 即字节，维持不动；本测试锁语义）：
    /// 43 个 CJK 字符 = 129B > 128 → 拒；42 个 CJK 字符 = 126B ≤ 128 → 过。
    #[test]
    fn create_vault中文字节口径_128() {
        let base = temp_dir("nm_cjk");
        // "密" 是 3 字节 UTF-8：43 * 3 = 129B > 128
        let err = create_vault_with_kdf(&base, &"密".repeat(43), STRONG_PASSWORD, fast_kdf())
            .unwrap_err();
        assert_eq!(err.code(), 5002);
        assert!(matches!(err, CfError::InvalidArgument(_)));
        // 42 * 3 = 126B ≤ 128
        let ok = "密".repeat(42);
        let brief = create_vault_with_kdf(&base, &ok, STRONG_PASSWORD, fast_kdf()).unwrap();
        assert_eq!(brief.display_name, ok);
    }

    /// 读侧回归（NM-2 兼容红线）：既有含首尾空白库名**照常打开**——
    /// 建库写侧校验不得引入读侧 display_name 校验（docs/17 §6.2 ①）。
    /// 构造方式：建正常库后直接把 header.json 的 display_name 改成含空白，
    /// 模拟历史上已存在的此类库。
    #[test]
    fn 既有首尾空白库名可打开_不受新校验影响() {
        let base = temp_dir("nm_legacy_space");
        let brief = setup_vault(&base, "正常名");
        let vault_dir = base.join(brief.uuid.to_string());
        let header_path = vault_dir.join("header.json");
        let mut root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&header_path).unwrap()).unwrap();
        root["display_name"] = serde_json::Value::String("  我的密码库  ".to_owned());
        std::fs::write(&header_path, serde_json::to_vec_pretty(&root).unwrap()).unwrap();

        let session = open_vault(&vault_dir).unwrap();
        assert_eq!(session.display_name(), "  我的密码库  ");
    }
}
