//! `VaultSession` —— 解锁会话（docs/07 §2.2 / docs/03 §11.1 `Session` 的落地版）。
//!
//! ## 状态持有与内存清零
//!
//! ```text
//! VaultSession
//! ├── vault_dir / vault_uuid / display_name / header   ← 非敏感（header 内为密文）
//! ├── state: Mutex<Option<UnlockedState>>              ← 锁定时为 None
//! │     └── UnlockedState { store: ItemStore }
//! │           └── ItemStore 持 SubKeys（全部 ZeroizeOnDrop）
//! ├── last_activity: AtomicI64                         ← 平台侧喂时间
//! └── idle_timeout_secs: AtomicI64                     ← 0 / 负值 = 禁用自动锁定
//!     clipboard_clear_secs: AtomicI64                  ← 0 = 从不清除（FR-14.2）
//!     backoff: Mutex<UnlockBackoff>                    ← FR-12.5 退避（内存级）
//! ```
//!
//! `lock()` 把 `state` 置为 `None` → `UnlockedState` 立即 drop →
//! `ItemStore` 连接关闭、`SubKeys` 全部 `ZeroizeOnDrop` 清零——这是
//! docs/07 §2.2 声明的清零边界。条目明文不常驻缓存（每次查询临时解密）。
//!
//! ## 对设计草图的一处偏离（记录在案）
//!
//! docs/07 §2.2 的 `UnlockedState` 草图为 `{ subkeys, store }`；T01 落地的
//! [`cf_store::ItemStore`] 已内持 `SubKeys`（且是加解密的唯一正确来源），
//! 故此处只持 `store`，不再重复持有一份子密钥。清零语义不变。
//!
//! ## 门禁
//!
//! 所有数据访问先经 `unlocked()` 检查（Rust 侧强制，错误码 1001），
//! 不依赖 UI 状态管理（docs/02 §4.3）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use cf_crypto::aead::SessionKey;
use cf_domain::item::ItemDraft;
use cf_domain::item::ItemSummary;
use cf_domain::origin::OriginBinding;
use cf_domain::secret::SecretString;
use cf_domain::totp_data::TotpUpdate;
use cf_store::ItemListFilter;

use crate::backoff::UnlockBackoff;
use crate::idle;
use crate::reminder;
use crate::types::{ItemDetails, TotpCode, TotpDetail, VaultInfo};
use crate::unlock_bio;
use crate::unlock_mcp;
use crate::usecase;
use crate::{SessionResult, TotpSession};
use cf_domain::license::{LicenseDecision, LicenseDenial, LicenseGate, LicensedOp, PermitAllGate};
use cf_domain::CfError;
use zeroize::Zeroizing;

/// 默认空闲超时（FR-1.6 / docs/07 §7 T05：默认 5 分钟，可配置）。
pub const DEFAULT_IDLE_TIMEOUT_SECS: i64 = 300;

/// 剪贴板自动清除的定时档位（秒，FR-14.2 / docs/09 §2 v0.2.0 范围）。
///
/// 「从不」档不计入本表：以 `0` 表示，见 [`validate_clipboard_clear_secs`]。
pub const CLIPBOARD_CLEAR_TIERS_SECS: [i64; 4] = [10, 30, 60, 120];

/// 默认剪贴板自动清除时间（FR-14.2：30s，与 macOS 现行固定 30s 行为向后兼容）。
pub const DEFAULT_CLIPBOARD_CLEAR_SECS: i64 = 30;

/// 校验剪贴板自动清除档位（FR-14.2）。
///
/// 合法值：[`CLIPBOARD_CLEAR_TIERS_SECS`] 中的 10 / 30 / 60 / 120 秒，
/// 或 `0`（「从不」——表示法与 FR-14.1 自动锁定「从不」档语义一致：
/// 0 = 不启用定时清除）。其余值（含负数与任意非档位秒数）返回
/// [`CfError::InvalidArgument`]（错误码 5002），拒绝后原配置不变。
pub fn validate_clipboard_clear_secs(secs: i64) -> SessionResult<()> {
    if secs == 0 || CLIPBOARD_CLEAR_TIERS_SECS.contains(&secs) {
        Ok(())
    } else {
        Err(CfError::InvalidArgument(format!(
            "clipboard clear secs must be 10/30/60/120 or 0 (never), got {secs}"
        )))
    }
}

/// 解锁态（docs/07 §2.2 `UnlockedState` 的落地形态，见模块文档偏离说明）。
pub(crate) struct UnlockedState {
    /// cf-store 仓库门面：持连接与 `SubKeys`（`ZeroizeOnDrop`）。
    pub(crate) store: cf_store::ItemStore,
}

/// 解锁会话：库生命周期与数据访问的门面。
///
/// 通过 [`crate::open_vault`] 构造（锁定态），[`VaultSession::unlock`]
/// 后可用。同一会话对象重复 `unlock` 幂等（已解锁时不再执行 KDF，
/// 直接返回当前信息）。
pub struct VaultSession {
    vault_dir: PathBuf,
    vault_uuid: cf_domain::VaultId,
    display_name: String,
    /// header 副本（bio enable/disable 会重写它，docs/08）。`&self` 门面
    /// 一致性：与 `state` 同用 `Mutex` 内部可变；读取侧短暂加锁后克隆。
    header: Mutex<cf_format::Header>,
    state: Mutex<Option<UnlockedState>>,
    last_activity: AtomicI64,
    idle_timeout_secs: AtomicI64,
    /// 剪贴板自动清除时间（秒，FR-14.2）；0 = 从不清除。会话级配置，
    /// 与 `idle_timeout_secs` 同策略：跨 lock 存活，不随解锁态丢弃。
    clipboard_clear_secs: AtomicI64,
    /// 解锁退避计数器（FR-12.5）：内存级，重启即清零（接受限制）。
    /// `unlock`（主密码路径）与 `enable_biometric` / `change_password`
    /// （均经 `recover_dek` 验主密码，是密码 oracle）共享；`unlock_with_biometric`
    /// 不触碰。门禁判定与 KDF 经 `try_acquire` 同临界区预占（MEDIUM-2）。
    backoff: Mutex<UnlockBackoff>,
    /// 许可只读门禁（FR-15，`docs/02` §10.3 方案 C）：写用例统一守卫
    /// [`Self::write_guard`] 的判定来源。默认 [`PermitAllGate`]（开源
    /// 产物「自编译 = 全功能免费版」契约）；官方装配经
    /// [`Self::set_license_gate`] 注入 cf-license（闭源，私有仓库）。
    license_gate: RwLock<Arc<dyn LicenseGate>>,
    /// DEK 保留开关（merge-time R1，docs/31 §4.1 / 裁定书 §1.4）：默认关闭。
    /// 开启时三条解锁内核解出的 DEK 额外保留在 [`Self::current_dek`]（供 App
    /// 侧 `export_dek` 瞬时取用，FFI 组 B 接线）。仅 Rust 内存
    /// （`SessionKey` ZeroizeOnDrop）+ `lock()` / `set_dek_retention(false)`
    /// 恒清。**安全边界变更**（裁定书 §4.3 ②，lead L-2 已确认）。
    retain_dek: AtomicBool,
    /// 当前会话保留的 DEK（仅 `retain_dek` 开启**且**解锁态时 `Some`）。
    /// `lock()` 与 `set_dek_retention(false)` 置 `None`（与 `state` 同清）。
    /// 与 `state` 同用 `Mutex` 内部可变，`&self` 门面一致。
    current_dek: Mutex<Option<SessionKey>>,
}

impl VaultSession {
    /// 由 header 构造锁定态会话（仅 [`crate::open_vault`] 调用）。
    pub(crate) fn new(vault_dir: PathBuf, header: cf_format::Header) -> SessionResult<Self> {
        let vault_uuid = uuid::Uuid::parse_str(&header.vault_uuid)
            .map_err(|_| CfError::Corrupted("vault_uuid is not a valid uuid".into()))?;
        Ok(Self {
            display_name: header.display_name.clone(),
            vault_dir,
            vault_uuid,
            header: Mutex::new(header),
            state: Mutex::new(None),
            last_activity: AtomicI64::new(crate::unix_now().unwrap_or(0)),
            idle_timeout_secs: AtomicI64::new(DEFAULT_IDLE_TIMEOUT_SECS),
            clipboard_clear_secs: AtomicI64::new(DEFAULT_CLIPBOARD_CLEAR_SECS),
            backoff: Mutex::new(UnlockBackoff::new()),
            license_gate: RwLock::new(Arc::new(PermitAllGate)),
            retain_dek: AtomicBool::new(false),
            current_dek: Mutex::new(None),
        })
    }

    // ------------------------------------------------------------ 元数据

    /// 库 UUID。
    #[must_use]
    pub fn vault_uuid(&self) -> cf_domain::VaultId {
        self.vault_uuid
    }

    /// 库显示名（锁定时也可见）。
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// 库工作目录。
    #[must_use]
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    // -------------------------------------------------------- 生命周期

    /// 解锁：主密码 → Argon2id → DEK 解封 → verifier 校验 → 子密钥派生 →
    /// 打开存储。错误码 1002 三态合并见 [`crate::unlock`] 模块文档。
    ///
    /// 已解锁时幂等：直接返回当前信息，不重复执行 KDF。
    ///
    /// # 暴力退避（FR-12.5）
    ///
    /// 失败退避期内**直接拒绝且不执行 KDF**（兼防 KDF DoS），返回
    /// [`CfError::UnlockFailed`]（1002，维持 FR-1.4 不可区分性）；剩余
    /// 等待时间经 [`Self::backoff_remaining_secs`] 旁路获取。
    ///
    /// 门禁判定与 KDF 在途预占同一临界区（`try_acquire`）：KDF 秒级执行
    /// 期间并发的第二次 `unlock` 被拒（1002），消除「gate 与 on_failure
    /// 非同一临界区」的并行猜测窗口。
    pub fn unlock(&self, password: &str) -> SessionResult<VaultInfo> {
        if self.backoff_guard().try_acquire().is_err() {
            return Err(CfError::UnlockFailed);
        }

        let header = self.header_snapshot();
        let mut guard = self.state_guard();
        if let Some(state) = guard.as_ref() {
            // 幂等路径：未做密码验证，只释放预占（不动计数与门禁）
            self.backoff_guard().release();
            return vault_info(&state.store, self.vault_uuid, &self.display_name);
        }

        let (store, dek) = match crate::unlock::unlock_store(&self.vault_dir, &header, password) {
            Ok(pair) => pair,
            Err(e) => {
                self.backoff_guard().on_failure();
                return Err(e);
            }
        };
        self.backoff_guard().on_success();
        // R1：按 retain_dek 决定是否在会话内保留 DEK（默认不保留）
        self.set_current_dek(dek);
        let info = vault_info(&store, self.vault_uuid, &self.display_name)?;
        self.last_activity
            .store(crate::unix_now().unwrap_or(0), Ordering::Release);
        *guard = Some(UnlockedState { store });
        Ok(info)
    }

    /// 锁定：立即 drop 解锁态 → 子密钥全链路清零（docs/07 §2.2）。
    ///
    /// R1：`current_dek` 与 `state` 同清——锁定即回到「不持 DEK」语义。
    ///
    /// 幂等：锁定态再调用无副作用。
    pub fn lock(&self) {
        *self.state_guard() = None;
        *self.current_dek_guard() = None;
    }

    /// 开启/关闭 DEK 保留（merge-time R1，浏览器集成启用时由 Swift 调用；
    /// broker / cf-mcp 不开）。
    ///
    /// 幂等开关：重复设置同值无副作用。关闭时**立即清零**已持有的 DEK
    /// （fail-closed，裁定书 §1.7 R1-3 缓解）；`lock()` 恒清。
    ///
    /// 安全边界变更（裁定书 §4.3 ② / §1.7 R1-1，lead L-2 已确认）：开启后
    /// 解锁态会在 Rust 内存额外保留 DEK，驻留窗口从「解锁瞬间」扩到「整个
    /// 解锁会话」；回退 = `set_dek_retention(false)` 即回「不持 DEK」。
    pub fn set_dek_retention(&self, enabled: bool) {
        self.retain_dek.store(enabled, Ordering::Release);
        if !enabled {
            *self.current_dek_guard() = None;
        }
    }

    /// 导出保留的 DEK（R1 (a-i) 门禁，裁定书 §1.7 R1-3）：仅 `retain_dek`
    /// 开启**且**解锁态（`current_dek` 为 `Some`）时返回 32B 原始 DEK；
    /// 否则 fail-closed（retention 未开 / 未解锁 →
    /// [`CfError::InvalidArgument`]，FFI 层映射 5002）。
    ///
    /// 返回值是明文 DEK 副本（`Vec<u8>` 非零化容器）——调用方
    /// （FFI → Swift）瞬时取用后必须自行零化副本；会话内保留的是
    /// `SessionKey`（`ZeroizeOnDrop`），FFI 转发出自本方法（组 B 只做
    /// `self.inner.export_dek()` 转发，会话层方法本体归本文件）。
    pub fn export_dek(&self) -> SessionResult<Vec<u8>> {
        let guard = self.current_dek_guard();
        let dek = guard
            .as_ref()
            .ok_or_else(|| CfError::InvalidArgument("dek retention disabled or locked".into()))?;
        Ok(dek.as_bytes().to_vec())
    }

    /// 是否处于解锁态。
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.state_guard().is_some()
    }

    // ---------------------------------------------------- 空闲自动锁定

    /// 记录最后一次活动时间（Unix 秒，平台侧事件驱动喂入）。
    pub fn set_last_activity(&self, unix_secs: i64) {
        self.last_activity.store(unix_secs, Ordering::Release);
    }

    /// 最后一次活动时间。
    #[must_use]
    pub fn last_activity(&self) -> i64 {
        self.last_activity.load(Ordering::Acquire)
    }

    /// 设置空闲超时秒数；`<= 0` 禁用自动锁定。
    pub fn set_idle_timeout_secs(&self, secs: i64) {
        self.idle_timeout_secs.store(secs, Ordering::Release);
    }

    /// 当前空闲超时秒数。
    #[must_use]
    pub fn idle_timeout_secs(&self) -> i64 {
        self.idle_timeout_secs.load(Ordering::Acquire)
    }

    /// 判定当前是否已过空闲超时（时间由平台注入，纯判定）。
    #[must_use]
    pub fn is_idle_expired(&self, now_secs: i64) -> bool {
        idle::is_expired(self.last_activity(), now_secs, self.idle_timeout_secs())
    }

    /// 若已超时且处于解锁态则锁定；返回是否执行了锁定。
    pub fn auto_lock_if_expired(&self, now_secs: i64) -> bool {
        if self.is_idle_expired(now_secs) && self.is_unlocked() {
            self.lock();
            true
        } else {
            false
        }
    }

    // ------------------------------------------------- 剪贴板清除（FR-14.2）

    /// 设置剪贴板自动清除时间（FR-14.2 / docs/09 §2 v0.2.0 范围）。
    ///
    /// 合法档位：10 / 30 / 60 / 120 秒；`0` 表示「从不清除」（与 FR-14.1
    /// 自动锁定「从不」档语义一致）。非法值（含负数）返回
    /// [`CfError::InvalidArgument`]，且不改变当前配置。
    ///
    /// 会话级元配置，与 [`VaultSession::set_idle_timeout_secs`] 同策略：
    /// 无解锁门禁、跨 `lock()` 存活（清除定时器由平台侧执行）。
    pub fn set_clipboard_clear_secs(&self, secs: i64) -> SessionResult<()> {
        validate_clipboard_clear_secs(secs)?;
        self.clipboard_clear_secs.store(secs, Ordering::Release);
        Ok(())
    }

    /// 当前剪贴板自动清除时间（秒）；`0` 表示从不清除。
    #[must_use]
    pub fn clipboard_clear_secs(&self) -> i64 {
        self.clipboard_clear_secs.load(Ordering::Acquire)
    }

    // ------------------------------------------------------- 备份提醒

    /// 上次成功备份时间（Unix 秒；从未备份返回 `None`，FR-8.5）。
    ///
    /// 打点方为 `cf_exporter::export_backup` 成功路径（写源库
    /// `meta.last_backup_at`），本方法只读。门禁：需解锁态（1001）。
    pub fn last_backup_at(&self) -> SessionResult<Option<i64>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        state.store.repos().meta.last_backup_at()
    }

    /// 是否应提醒备份（FR-8.5，docs/09 §2.2）：从未备份，或距上次
    /// 成功备份 `>= threshold_secs` 秒 → 应提醒；`threshold_secs <= 0`
    /// 视为禁用（永不提醒）。判定规则见 [`crate::reminder`]；
    /// `now_secs` 由平台注入（与空闲自动锁定同模式，可测试）。
    ///
    /// 门禁：需解锁态（1001）。
    pub fn should_suggest_backup(&self, threshold_secs: i64, now_secs: i64) -> SessionResult<bool> {
        Ok(reminder::should_suggest(
            self.last_backup_at()?,
            now_secs,
            threshold_secs,
        ))
    }

    // ------------------------------------------------ 生物识别（docs/08）

    /// 是否启用了生物识别封装（header `biometric_wrap.available`，
    /// docs/08 D-1：语义 = 「用户意图开启」，锁定态可查）。
    ///
    /// 纯读 header，无密钥操作；供 LockView 决定是否显示 Touch ID 按钮。
    /// 实际可用性由 Swift 侧 Keychain 信号组合判定（三态见
    /// [`crate::types::BiometricStatus`]）。
    #[must_use]
    pub fn has_biometric_wrap(&self) -> bool {
        self.header_snapshot().biometric_wrap.available
    }

    /// 启用 Touch ID 解锁（docs/08 §4.1 enable，header 侧）。
    ///
    /// 门禁：需解锁态（设置页在解锁后才可达，错误码 1001）。传入主密码
    /// 而非 DEK（D-6）：内部经 `recover_dek` 重验证主密码并解出 DEK
    /// （错 → 1002，此时 header 未变）→ K_bio 封装 → 原子重写 header。
    ///
    /// `k_bio` 必须为 32 字节随机数（Swift 经 FFI 从
    /// `new_biometric_unwrap_key` 取得并已先行写入 Keychain——先 Keychain
    /// 后 header 顺序裁定，docs/08 §4.1）；长度不符 → 5002。本方法失败
    /// 时 header 保持原样，Keychain 补偿删除由 Swift 依据 Err 执行。
    ///
    /// # 错误
    ///
    /// 1001 锁定态 / 1002 主密码错 / 5002 k_bio 长度 / 5001·1005 写失败。
    ///
    /// # 暴力退避（FR-12.5）
    ///
    /// 经 `recover_dek` 验主密码（密码 oracle），与 [`Self::unlock`]
    /// **共享同一退避计数器**：门禁期内直接拒绝（1002，不跑 KDF）；
    /// 主密码错（1002）计入失败，成功清零。k_bio 长度（5002）等参数
    /// 错误不是密码尝试，不计入。门禁判定与 KDF 同临界区预占
    /// （`try_acquire`，语义同 [`Self::unlock`]）。
    pub fn enable_biometric(&self, password: &str, k_bio: &[u8]) -> SessionResult<()> {
        if self.backoff_guard().try_acquire().is_err() {
            return Err(CfError::UnlockFailed);
        }
        let _guard = match self.write_guard(LicensedOp::VaultWrite) {
            Ok(guard) => guard,
            Err(e) => {
                // 锁定态（1001）不是密码尝试，只释放预占
                self.backoff_guard().release();
                return Err(e);
            }
        };
        let header = self.header_snapshot();
        let new_header =
            match unlock_bio::enable_biometric_impl(&self.vault_dir, &header, password, k_bio) {
                Ok(new_header) => new_header,
                Err(e) => {
                    // 仅主密码校验失败（1002）计入退避；k_bio 长度（5002）
                    // 等参数错误不是密码尝试，只释放预占
                    if matches!(e, CfError::UnlockFailed) {
                        self.backoff_guard().on_failure();
                    } else {
                        self.backoff_guard().release();
                    }
                    return Err(e);
                }
            };
        // 主密码校验通过（成功路径）：退避清零
        self.backoff_guard().on_success();
        // 写成功才更新内存副本（失败时 in-memory header 与磁盘一致）
        *self.header_guard() = new_header;
        Ok(())
    }

    /// 关闭 Touch ID 解锁（docs/08 §4.1 disable，header 侧）。
    ///
    /// 门禁：需解锁态（1001）。重写 header → 禁用态；**幂等**——已是
    /// 禁用态时不重写文件。Keychain 项删除在 Swift 侧先行且幂等，两侧
    /// 独立可重试；本方法失败非致命，可重试（docs/08 §8 降级矩阵）。
    pub fn disable_biometric(&self) -> SessionResult<()> {
        let _guard = self.write_guard(LicensedOp::VaultWrite)?;
        let header = self.header_snapshot();
        if let Some(new_header) = unlock_bio::disable_biometric_impl(&self.vault_dir, &header)? {
            *self.header_guard() = new_header;
        }
        Ok(())
    }

    /// Touch ID 解锁（docs/08 §6 `unlock_with_biometric` 的会话层门面）。
    ///
    /// K_bio 解封 wrapped_dek_bio → DEK → SubKeys → ItemStore——收尾与
    /// 主密码 [`VaultSession::unlock`] 完全共享。获得的会话与主密码路径
    /// 同生共死（`lock()` / 自动锁定清零密钥，D-5）。
    ///
    /// 已解锁时幂等：直接返回当前信息，不做密钥操作。
    ///
    /// # 错误（D-8）
    ///
    /// 未启用 → 4001；k_bio 非 32B → 5002；其余失败统一 1002。
    pub fn unlock_with_biometric(&self, k_bio: &[u8]) -> SessionResult<VaultInfo> {
        let header = self.header_snapshot();
        let mut guard = self.state_guard();
        if let Some(state) = guard.as_ref() {
            return vault_info(&state.store, self.vault_uuid, &self.display_name);
        }

        let (store, dek) = unlock_bio::unlock_store_with_bio(&self.vault_dir, &header, k_bio)?;
        self.set_current_dek(dek);
        let info = vault_info(&store, self.vault_uuid, &self.display_name)?;
        self.last_activity
            .store(crate::unix_now().unwrap_or(0), Ordering::Release);
        *guard = Some(UnlockedState { store });
        Ok(info)
    }

    // ------------------------------------------------ MCP 解锁托管（docs/29）

    /// 是否启用了 MCP 托管封装（header `mcp_wrap.available`，docs/29 §2：
    /// 语义 = 「用户意图开启」，锁定态可查）。
    ///
    /// 纯读 header，无密钥操作；供设置页决定是否显示托管开关态。实际
    /// 可用性由 Swift 侧 Keychain 信号组合判定（三态见 docs/29 §5.2）。
    #[must_use]
    pub fn has_mcp_wrap(&self) -> bool {
        self.header_snapshot().mcp_wrap.available
    }

    /// 派生 MCP 托管密钥（docs/29 §5.2 enable 流程 ①）。
    ///
    /// 门禁：需解锁态（设置页在解锁后才可达，错误码 1001）。内部经
    /// `recover_dek` 重验证主密码并解出 DEK（错 → 1002）→
    /// HKDF 确定性派生 mcp_key（DEK 派生，非随机；换主密码不吊销，
    /// docs/29 §5.3）。返回的 [`cf_crypto::aead::SessionKey`] 为
    /// `ZeroizeOnDrop`（NFR-SEC-04）；调用方（Swift，经 FFI）负责存入
    /// Keychain（先 Keychain 后 header 顺序裁定，docs/29 §5.2）。
    ///
    /// # 错误
    ///
    /// 1001 锁定态 / 1002 主密码错 / 1007 派生失败。
    ///
    /// # 暴力退避（FR-12.5）
    ///
    /// 经 `recover_dek` 验主密码（密码 oracle），与 [`Self::unlock`] /
    /// [`Self::enable_biometric`] / [`Self::enable_mcp_escrow`] **共享同一
    /// 退避计数器**：门禁期内直接拒绝（1002，不跑 KDF）；主密码错（1002）
    /// 计入失败，成功清零。门禁判定与 KDF 同临界区预占（`try_acquire`，
    /// 语义同 [`Self::unlock`]）。
    pub fn derive_mcp_key(&self, password: &str) -> SessionResult<cf_crypto::aead::SessionKey> {
        if self.backoff_guard().try_acquire().is_err() {
            return Err(CfError::UnlockFailed);
        }
        let _guard = match self.unlocked() {
            Ok(guard) => guard,
            Err(e) => {
                // 锁定态（1001）不是密码尝试，只释放预占
                self.backoff_guard().release();
                return Err(e);
            }
        };
        let header = self.header_snapshot();
        let key = match unlock_mcp::derive_mcp_key_impl(&self.vault_dir, &header, password) {
            Ok(key) => key,
            Err(e) => {
                // 仅主密码校验失败（1002）计入退避；其余（1007 派生失败等）
                // 不是密码尝试，只释放预占
                if matches!(e, CfError::UnlockFailed) {
                    self.backoff_guard().on_failure();
                } else {
                    self.backoff_guard().release();
                }
                return Err(e);
            }
        };
        // 主密码校验通过（成功路径）：退避清零
        self.backoff_guard().on_success();
        Ok(key)
    }

    /// 启用 MCP 解锁托管（docs/29 §5.2 enable，header 侧）。
    ///
    /// 门禁：需解锁态（设置页在解锁后才可达，错误码 1001）。传入主密码
    /// 而非 DEK（D-6 同款）：内部经 `recover_dek` 重验证主密码并解出 DEK
    /// （错 → 1002，此时 header 未变）→ mcp_key 封装 DEK → 原子重写
    /// header 的 `mcp_wrap` 段。
    ///
    /// `mcp_key` 必须为 32 字节（Swift 经 FFI 从 `derive_mcp_key` 取得并
    /// 已先行写入 Keychain——先 Keychain 后 header 顺序裁定，docs/29 §5.2）；
    /// 长度不符 → 5002。本方法失败时 header 保持原样，Keychain 补偿删除
    /// 由 Swift 依据 Err 执行。
    ///
    /// # 错误
    ///
    /// 1001 锁定态 / 1002 主密码错 / 5002 mcp_key 长度 / 5001·1005 写失败。
    ///
    /// # 暴力退避（FR-12.5）
    ///
    /// 经 `recover_dek` 验主密码（密码 oracle），与 [`Self::unlock`]
    /// **共享同一退避计数器**：门禁期内直接拒绝（1002，不跑 KDF）；
    /// 主密码错（1002）计入失败，成功清零。mcp_key 长度（5002）等参数
    /// 错误不是密码尝试，不计入。门禁判定与 KDF 同临界区预占
    /// （`try_acquire`，语义同 [`Self::unlock`]）。
    pub fn enable_mcp_escrow(&self, password: &str, mcp_key: &[u8]) -> SessionResult<()> {
        if self.backoff_guard().try_acquire().is_err() {
            return Err(CfError::UnlockFailed);
        }
        let _guard = match self.write_guard(LicensedOp::VaultWrite) {
            Ok(guard) => guard,
            Err(e) => {
                // 锁定态（1001）不是密码尝试，只释放预占
                self.backoff_guard().release();
                return Err(e);
            }
        };
        let header = self.header_snapshot();
        let new_header =
            match unlock_mcp::enable_mcp_escrow_impl(&self.vault_dir, &header, password, mcp_key) {
                Ok(new_header) => new_header,
                Err(e) => {
                    // 仅主密码校验失败（1002）计入退避；mcp_key 长度（5002）
                    // 等参数错误不是密码尝试，只释放预占
                    if matches!(e, CfError::UnlockFailed) {
                        self.backoff_guard().on_failure();
                    } else {
                        self.backoff_guard().release();
                    }
                    return Err(e);
                }
            };
        // 主密码校验通过（成功路径）：退避清零
        self.backoff_guard().on_success();
        // 写成功才更新内存副本（失败时 in-memory header 与磁盘一致）
        *self.header_guard() = new_header;
        Ok(())
    }

    /// 关闭 MCP 解锁托管（docs/29 §5.2 disable，header 侧）。
    ///
    /// 门禁：需解锁态（1001）。重写 header → 禁用态（`mcp_wrap` 回落
    /// 默认值）；**幂等**——已是禁用态时不重写文件。Keychain 项删除在
    /// Swift 侧先行且幂等，两侧独立可重试；本方法失败非致命，可重试
    /// （Keychain 已删时功能实际已失效，header 残留密文无泄露面）。
    pub fn disable_mcp_escrow(&self) -> SessionResult<()> {
        let _guard = self.write_guard(LicensedOp::VaultWrite)?;
        let header = self.header_snapshot();
        if let Some(new_header) = unlock_mcp::disable_mcp_escrow_impl(&self.vault_dir, &header)? {
            *self.header_guard() = new_header;
        }
        Ok(())
    }

    /// MCP 托管解锁（docs/29 §6.2 `unlock_store_with_mcp_key` 的会话层门面）。
    ///
    /// mcp_key 解封 wrapped_dek_mcp → DEK → SubKeys → ItemStore——收尾与
    /// 主密码 / 生物识别路径完全共享。获得的会话与主密码路径同生共死
    /// （`lock()` / 自动锁定清零密钥）。
    ///
    /// 已解锁时幂等：直接返回当前信息，不做密钥操作。
    ///
    /// # 错误（fail-closed，docs/29 §2 差异说明）
    ///
    /// 未启用或解封失败统一 1002（[`CfError::UnlockFailed`]，不区分原因）；
    /// mcp_key 非 32B → 5002。
    pub fn unlock_with_mcp_key(&self, mcp_key: &[u8]) -> SessionResult<VaultInfo> {
        let header = self.header_snapshot();
        let mut guard = self.state_guard();
        if let Some(state) = guard.as_ref() {
            return vault_info(&state.store, self.vault_uuid, &self.display_name);
        }

        let (store, dek) =
            unlock_mcp::unlock_store_with_mcp_key(&self.vault_dir, &header, mcp_key)?;
        self.set_current_dek(dek);
        let info = vault_info(&store, self.vault_uuid, &self.display_name)?;
        self.last_activity
            .store(crate::unix_now().unwrap_or(0), Ordering::Release);
        *guard = Some(UnlockedState { store });
        Ok(info)
    }

    /// 直开解锁（merge-time R2，供 cf-mcp browser-broker：stdin 已解析
    /// 32B DEK → 直开取密/写库，裁定书 §2）。
    ///
    /// 与 [`VaultSession::unlock_with_mcp_key`] 完全同构：幂等（已解锁直接
    /// 返回当前信息，不重开）、**不触碰退避计数器**（DEK 非密码 oracle，
    /// 无免费猜测通道）、会话与主密码路径同生共死（`lock()`/自动锁定清零）。
    /// **不保留 DEK**（broker 无导出能力，`retain_dek` 仅 App 侧能力）。
    ///
    /// # 错误（fail-closed）
    ///
    /// `dek` 非 32B → 5002（参数错误）；DEK 错/库损坏 → 1002
    /// （`finish_unlock` 的 `verify_integrity` 天然归一）。
    pub fn unlock_with_dek(&self, dek: &[u8]) -> SessionResult<VaultInfo> {
        let header = self.header_snapshot();
        let mut guard = self.state_guard();
        if let Some(state) = guard.as_ref() {
            return vault_info(&state.store, self.vault_uuid, &self.display_name);
        }

        // 输入切片归调用方所有（broker `BrokerSecrets.dek`，cli.rs）：入
        // Zeroizing 副本再进 SessionKey（ZeroizeOnDrop），长度 ≠ 32 → 5002
        let dek_copy = Zeroizing::new(dek.to_vec());
        let dek_key = SessionKey::new(
            <[u8; 32]>::try_from(dek_copy.as_slice())
                .map_err(|_| CfError::InvalidArgument("dek must be 32 bytes".into()))?,
        );

        let store = crate::unlock::unlock_store_with_dek(&self.vault_dir, &header, &dek_key)?;
        let info = vault_info(&store, self.vault_uuid, &self.display_name)?;
        self.last_activity
            .store(crate::unix_now().unwrap_or(0), Ordering::Release);
        *guard = Some(UnlockedState { store });
        Ok(info)
    }

    // ------------------------------------------------------ 条目 CRUD

    /// 创建条目：`cf-domain::validate_item` 前置校验 → 单事务写库。
    /// 返回新条目 ID（UUIDv7 文本）。
    pub fn create_item(&self, draft: &ItemDraft) -> SessionResult<String> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::create_item(&mut state.store, draft)
    }

    /// 创建条目并写入 origin 绑定（D-3，docs/31 §5.3）：语义与
    /// [`Self::create_item`] 一致，额外把 `origin_bindings` 随同一事务写入
    /// `item_origins` 从表。供 broker `capture_save` 建条目 + 绑定站点用
    /// （merge-time 接线；薄封装转发
    /// [`usecase::items::create_item_with_origin_bindings`]）。
    pub fn create_item_with_origin_bindings(
        &self,
        draft: &ItemDraft,
        origin_bindings: Vec<OriginBinding>,
    ) -> SessionResult<String> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::create_item_with_origin_bindings(&mut state.store, draft, origin_bindings)
    }

    /// 显式改写条目 origin 绑定（D-3，docs/31 §5.3）：独立于
    /// [`Self::update_item`] 的专用入口（`ItemDraft` 不含绑定字段），替换前
    /// 写 history 快照（FR-2.9，绑定变化同样进版本历史）、事务内删旧插新、
    /// 推进 `updated_at`。条目不存在 → 1011（ItemNotFound）。供 broker
    /// `capture_save` 对既有条目追加/改写绑定用（merge-time 接线；薄封装
    /// 转发 [`usecase::items::set_item_origin_bindings`]）。
    pub fn set_item_origin_bindings(
        &self,
        item_id: &str,
        origin_bindings: Vec<OriginBinding>,
    ) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::set_item_origin_bindings(&mut state.store, item_id, origin_bindings)
    }

    /// 更新条目：替换前对当前状态写 history 快照（FR-2.9，内容无变化
    /// 不写）→ 校验 → 单事务整体替换（fields / urls / tags / sections
    /// 均「删旧插新」语义）。
    ///
    /// TOTP **默认保留**（[`TotpUpdate::Keep`]）：FFI 刻意不下发 secret，
    /// 调用方无法重提交原密钥，默认删旧会让编辑静默丢失 TOTP。三态
    /// 显式控制走 [`VaultSession::update_item_with_totp`]；draft 的
    /// `totp` 字段在更新路径始终忽略。
    pub fn update_item(&self, item_id: &str, draft: &ItemDraft) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::update_item(&mut state.store, item_id, draft)
    }

    /// 更新条目（TOTP 三态显式版）：Keep 保留既有加密行 / Replace 删旧
    /// 插新 / Remove 删除。语义详见
    /// [`usecase::items::update_item_with_totp`]。
    pub fn update_item_with_totp(
        &self,
        item_id: &str,
        draft: &ItemDraft,
        totp: TotpUpdate,
    ) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::update_item_with_totp(&mut state.store, item_id, draft, totp)
    }

    /// 删除条目：`hard = false` 移入回收站（软删），`hard = true`
    /// 连同从表（fields / urls / tags / totp 等）级联硬删。
    ///
    /// 硬删级联附件（v0.4.0 既有缺口修复，docs/15 §3.1.3）：schema 的
    /// `ON DELETE CASCADE` 只级联 DB 行，`attachments/<uuid>` 旁路文件
    /// 由本层编排清理——事务前 `list_for_item` 收集附件 uuid，事务成功
    /// 返回后逐个 unlink。缺失容忍（文件不存在跳过）；删除失败不回滚
    /// DB 行（条目删除已成事实，报错只会误导），孤儿由 open_vault 成功
    /// 路径的 `cleanup_orphans` 真调兜底（unlock.rs，v0.4 M-2）——与
    /// attachment.rs「先删行后删文件」纪律一致。软删 / 恢复不动附件
    /// （回收站恢复后附件仍可用）。
    pub fn delete_item(&self, item_id: &str, hard: bool) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        let attachment_uuids = if hard {
            state
                .store
                .repos()
                .attachments
                .list_for_item(item_id)?
                .into_iter()
                .map(|m| m.uuid)
                .collect()
        } else {
            Vec::new()
        };
        usecase::items::delete_item(&mut state.store, item_id, hard)?;
        // 事务已提交：逐个清理旁路文件（尽力而为，见上方法文档）
        let dir = self
            .vault_dir
            .join(cf_store::repo::attachment::ATTACHMENTS_DIR);
        for uuid in attachment_uuids {
            let _ = std::fs::remove_file(dir.join(uuid));
        }
        Ok(())
    }

    /// 从回收站恢复条目。
    pub fn restore_item(&self, item_id: &str) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::restore_item(&mut state.store, item_id)
    }

    /// 设置 / 取消收藏。
    pub fn set_favorite(&self, item_id: &str, favorite: bool) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::set_favorite(&mut state.store, item_id, favorite)
    }

    /// 列出条目（updated_at 倒序）；`filter` 传 `None` 使用默认过滤
    /// （不过滤，全量分页参数缺省）。
    pub fn list_items(&self, filter: Option<ItemListFilter>) -> SessionResult<Vec<ItemSummary>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        let filter = filter.unwrap_or_default();
        usecase::items::list_items(&state.store, &filter)
    }

    /// 读取条目完整详情；不存在返回 `None`。
    pub fn get_item(&self, item_id: &str) -> SessionResult<Option<ItemDetails>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::items::get_item(&state.store, item_id)
    }

    /// 按需取字段明文值（密码等敏感值，随取随走，docs/07 §4.2）。
    /// 条目不存在返回 Err(1011)（ItemNotFound）；条目存在但字段不存在
    /// 返回 `None`（QA F-2：文档对齐实现，1011 语义保留）。
    pub fn get_field_value(
        &self,
        item_id: &str,
        field_id: &str,
    ) -> SessionResult<Option<SecretString>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::items::get_field_value(&state.store, item_id, field_id)
    }

    // ------------------------------------------------ 附件（FR-9.3 / 9.4）

    /// 列出条目附件（created_at 升序，FR-9.3）。锁定 → 1001；条目不存在
    /// → 1011。语义详见 [`usecase::attachments`]。
    pub fn list_attachments(
        &self,
        item_id: &str,
    ) -> SessionResult<Vec<usecase::attachments::AttachmentInfo>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::attachments::list_attachments(&state.store, item_id)
    }

    /// 添加附件（FR-9.1）：`filename` 为 UTF-8 明文，`content` 为明文
    /// 内容（≤ 100 MiB，超限 → 1012 门面预检快失败）。只校验条目存在
    /// （1011），不限制条目状态（docs/15 §3.1.2 边界声明）。锁定 → 1001。
    pub fn add_attachment(
        &self,
        item_id: &str,
        filename: &str,
        content: &[u8],
    ) -> SessionResult<usecase::attachments::AttachmentInfo> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::attachments::add_attachment(
            &mut state.store,
            &self.vault_dir,
            item_id,
            filename,
            content,
        )
    }

    /// 读附件明文内容（FR-9.2，一次一个、即用即弃；D-3 整块返回）。
    /// 行不存在 → 1012；行在文件无 / 密文损坏 → 1005。锁定 → 1001。
    pub fn read_attachment(&self, attachment_uuid: &str) -> SessionResult<Vec<u8>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::attachments::read_attachment(&state.store, &self.vault_dir, attachment_uuid)
    }

    /// 删除附件（FR-9.2）：先删行（事务）后删文件；旁路文件已不存在
    /// 视为删除成功。行不存在 → 1012。锁定 → 1001。
    pub fn remove_attachment(&self, attachment_uuid: &str) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::attachments::remove_attachment(&mut state.store, &self.vault_dir, attachment_uuid)
    }

    // ------------------------------------------------ Passkey（FR-10.2 / 10.5）

    /// 列出条目的全部 Passkey 元数据（created_at 升序，FR-10.2）。
    /// 锁定 → 1001；条目不存在 → 1011。元数据**无私钥字段**
    /// （FR-10.2 红线，docs/17 §4.1）。语义详见 [`usecase::passkeys`]。
    pub fn list_passkeys(
        &self,
        item_id: &str,
    ) -> SessionResult<Vec<usecase::passkeys::PasskeyMeta>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::passkeys::list_passkeys(&state.store, item_id)
    }

    /// 删除 Passkey（FR-10.5）：纯 DB 行删除，无文件面副作用。
    /// 行不存在 → 1011。锁定 → 1001。许可拒绝态 → 6002/6003
    /// （PasskeyWrite 组，docs/03 §14.6；TC-GATE-06）。
    pub fn remove_passkey(&self, passkey_uuid: &str) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::PasskeyWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::passkeys::remove_passkey(&mut state.store, passkey_uuid)
    }

    // ---------------------------------------------------------- 搜索

    /// 标题搜索（方案 A：全量解密内存搜索，docs/03 §3.3）。
    ///
    /// 多关键词**全命中**（空白分隔、大小写不敏感）；仅搜索 Active 态
    /// 条目；空查询返回空结果（列表展示走 `list_items`）。
    /// 1000 条量级实测为毫秒级（见 usecase::search 测试基线）。
    pub fn search(&self, query: &str) -> SessionResult<Vec<ItemSummary>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::search::search(&state.store, query)
    }

    // ----------------------------------------------------------- TOTP

    /// 生成条目当前的 TOTP 验证码（FR-5.4）。
    ///
    /// 共享密钥从存储解密后仅在函数内使用（`field_key` 由解锁态
    /// `SubKeys` 提供），不跨 FFI、不驻留会话。条目无 TOTP 记录或
    /// 不存在 → [`CfError::ItemNotFound`]；非 SHA-1 算法 →
    /// [`CfError::Validation`]（显式拒绝，docs/07 §1.2）。
    pub fn totp_code(&self, item_id: &str) -> SessionResult<TotpCode> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        let repos = state.store.repos();

        let totp_uuid = repos
            .totp
            .totp_uuids_for_item(item_id)?
            .into_iter()
            .next()
            .ok_or(CfError::ItemNotFound)?;
        let meta = repos
            .totp
            .totp_meta(&totp_uuid)?
            .ok_or(CfError::ItemNotFound)?;
        if meta.algo != "sha1" {
            return Err(CfError::Validation(format!(
                "unsupported TOTP algorithm: {}",
                meta.algo
            )));
        }
        let secret = repos
            .totp
            .totp_secret(&totp_uuid)?
            .ok_or(CfError::ItemNotFound)?;

        let config = cf_totp::TotpConfig::new(secret.to_vec(), meta.period, meta.digits)
            .map_err(crate::totp_error)?;
        let session = TotpSession::new(config);
        let code = session.generate()?;
        let now = crate::unix_now()?;
        Ok(TotpCode {
            code,
            secs_remaining: session.secs_until_next_window(now.max(0) as u64),
        })
    }

    /// 读取条目 TOTP 元数据（**绝不含 secret**，FR-5.4 编辑界面展示用）。
    ///
    /// 与 [`VaultSession::totp_code`] 的差异：只回 algo / digits / period /
    /// issuer / account 等非敏感元数据，供编辑界面展示「已有 TOTP
    /// （SHA-1 · 6 位 · 30s）」并默认保留。条目无 TOTP 记录（含条目不
    /// 存在）→ `Ok(None)`——编辑界面只需区分「有 / 无」，不区分两种
    /// 不存在，避免多一层错误分流。
    pub fn totp_config(&self, item_id: &str) -> SessionResult<Option<TotpDetail>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        let repos = state.store.repos();

        let Some(totp_uuid) = repos.totp.totp_uuids_for_item(item_id)?.into_iter().next() else {
            return Ok(None);
        };
        Ok(repos.totp.totp_meta(&totp_uuid)?.map(|m| TotpDetail {
            uuid: m.uuid,
            algo: m.algo,
            digits: m.digits,
            period: m.period,
            issuer: m.issuer,
            account: m.account,
        }))
    }

    // ----------------------------------------------------------- 导入

    /// CSV 导入（docs/07 §2.3 `import_csv`）：单事务 all-or-nothing，
    /// 任一行失败整体回滚、已有数据零影响（NFR-REL-04）。
    ///
    /// 薄委托 [`cf_importer::import_csv`]——T03 偏差记录预留的落点：
    /// 导入编排归 cf-session，cf-ffi 由此获得导入能力而不必接触
    /// `ItemStore` 内部（DEK / SubKeys 依旧不跨 FFI）。
    ///
    /// # 错误
    ///
    /// 锁定态 → 1001；解析 / 映射 / 写入失败 → 2001 / 2002（docs/03 §12）。
    pub fn import_csv(&self, path: &Path) -> SessionResult<cf_importer::CsvImportResult> {
        let mut guard = self.write_guard(LicensedOp::ImportRestore)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        cf_importer::import_csv(path, &mut state.store)
    }

    /// 1PUX 导入（v0.3.0-T05，FR-7.1 含 `files/` 附件）：每条目单事务，
    /// 任一条目失败回滚该条、已成功条目保留；附件密文落
    /// `<vault_dir>/attachments/`（vault_dir 与解锁保险库的宿主目录一致，
    /// cf-importer 的附件仓库纪律不变）。返回值携带与本次导入同管线
    /// 产出的预检报告（FR-7.4 所见即所得）；FR-7.8 删源建议由调用方对
    /// 报告调 [`cf_importer::advise_pux_source_deletion`] 组装（D-6
    /// 数据驱动，纯函数不进门面）。
    ///
    /// 薄委托 [`cf_importer::import_1pux`]，与 [`VaultSession::import_csv`]
    /// 同落点理由：导入编排归 cf-session，DEK / SubKeys 不跨 FFI。
    ///
    /// # 错误
    ///
    /// 锁定态 → 1001；解析失败 → 2001；写入失败 → 2002（docs/03 §12）。
    pub fn import_1pux(&self, path: &Path) -> SessionResult<cf_importer::PuxImportResult> {
        let mut guard = self.write_guard(LicensedOp::ImportRestore)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        cf_importer::import_1pux(path, &mut state.store, &self.vault_dir)
    }

    /// Bitwarden JSON 导入（docs/17 §4.2 PK2，FR-10.1）：每条目单事务，
    /// 任一条目失败回滚该条、已成功条目保留；坏 passkey 行预检显式列出、
    /// 导入跳过该行不丢条目（TCB-7）。返回值携带与本次导入同管线产出的
    /// 预检报告（FR-7.4 所见即所得）。
    ///
    /// 薄委托 [`cf_importer::import_bitwarden_json`]，与
    /// [`VaultSession::import_1pux`] 同落点理由：导入编排归 cf-session，
    /// DEK / SubKeys 不跨 FFI（docs/17 r2.3 门面存在性声明，PW 一次性扩权）。
    ///
    /// # 错误
    ///
    /// 锁定态 → 1001；许可拒绝态 → 6002/6003（ImportRestore 组，
    /// docs/03 §14.6；TC-GATE-04）；解析失败 → 2001；写入失败 → 2002
    /// （docs/03 §12）。
    pub fn import_bitwarden_json(&self, path: &Path) -> SessionResult<cf_importer::BwImportResult> {
        let mut guard = self.write_guard(LicensedOp::ImportRestore)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        cf_importer::import_bitwarden_json(path, &mut state.store)
    }

    /// OPVault 导入（v0.7.0-T05，FR-7.3）：密码保护目录导入。
    ///
    /// 薄委托 [`cf_importer::import_opvault`]，与 [`VaultSession::import_1pux`]
    /// 同落点理由：导入编排归 cf-session，DEK / SubKeys 不跨 FFI。密码以
    /// UTF-8 原始字节进 PBKDF2（docs/24 §1.3，勿追加 NUL）；解密映射先于
    /// 写入——密码错/数据损坏 → 2002 且零落库（all-or-nothing，TC-OPV-03）。
    /// `vault_dir` 为附件旁路目录宿主（本版附件 out-of-scope，保留扩展位）。
    ///
    /// # 错误
    ///
    /// 锁定态 → 1001；许可拒绝态 → 6002/6003（ImportRestore 组，docs/03
    /// §14.6；TC-OPV-07）；结构非法 → 2001；解密/映射/写入失败 → 2002
    /// （docs/22 §4，零新增）。
    pub fn import_opvault(
        &self,
        path: &Path,
        password: String,
        vault_dir: &Path,
    ) -> SessionResult<cf_importer::OpvaultImportResult> {
        let mut guard = self.write_guard(LicensedOp::ImportRestore)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        cf_importer::import_opvault(path, &password, &mut state.store, vault_dir)
    }

    // ------------------------------------------------------- 账户安全

    /// 修改主密码（FR-1.8，docs/09 §3.2 D-2：只重封装 header 的 DEK，
    /// 不重加密全库）。
    ///
    /// 门禁：需解锁态（1001）——与 enable_biometric 一致（设置页在解锁后
    /// 可达）。流程：new_password 过 zxcvbn 门禁（<3 → 1010，先于任何
    /// 文件操作）→ recover_dek(old_password) 重验证旧密码（错 → 1002，
    /// header 未动）→ 新盐 + 新 KEK → 重封装 wrapped_dek / verifier →
    /// `write_header` 原子重写 → 内存 header 副本更新。
    ///
    /// bio 封装（wrapped_dek_bio）不动：K_bio 封装的是 DEK 本身，换密后
    /// Touch ID 解锁照常可用。`new_kdf` 可选传入新档位顺带升级 KDF
    /// （M0-② 标定后的补偿路径）；`None` 沿用当前 header.kdf 参数。
    ///
    /// # 错误
    ///
    /// 1001 锁定态 / 1002 旧密码错 / 1010 新密码弱 / 5002 new_kdf 越界 /
    /// 1007 密钥操作失败 / 5001·1005 写失败（磁盘 header 保持原样）。
    ///
    /// # 暴力退避（FR-12.5）
    ///
    /// 经 `recover_dek` 验旧密码（密码 oracle，虽需解锁态 1001 才可达，
    /// 同会话连续错旧密码仍是免费猜测通道，须计入），与 [`Self::unlock`]
    /// / [`Self::enable_biometric`] **共享同一退避计数器**：门禁期内直接
    /// 拒绝（1002）；旧密码错（1002）计入失败，成功清零。弱新密码
    /// （1010）、new_kdf 越界（5002）、写失败等非密码错误不计入，只释放
    /// 预占。门禁判定与 KDF 同临界区预占（`try_acquire`，语义同
    /// [`Self::unlock`]）。
    pub fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
        new_kdf: Option<cf_crypto::kdf::KdfParams>,
    ) -> SessionResult<()> {
        if self.backoff_guard().try_acquire().is_err() {
            return Err(CfError::UnlockFailed);
        }
        let guard = match self.write_guard(LicensedOp::VaultWrite) {
            Ok(guard) => guard,
            Err(e) => {
                // 锁定态（1001）不是密码尝试，只释放预占
                self.backoff_guard().release();
                return Err(e);
            }
        };
        let header = self.header_snapshot();
        let new_header = match crate::change_password::change_password_impl(
            &self.vault_dir,
            &header,
            old_password,
            new_password,
            new_kdf,
        ) {
            Ok(new_header) => new_header,
            Err(e) => {
                // 仅旧密码校验失败（1002）计入退避；1010 / 5002 / 写
                // 失败等不是密码尝试，只释放预占
                if matches!(e, CfError::UnlockFailed) {
                    self.backoff_guard().on_failure();
                } else {
                    self.backoff_guard().release();
                }
                return Err(e);
            }
        };
        // 旧密码校验通过（成功路径）：退避清零
        self.backoff_guard().on_success();
        // 写成功才更新内存副本（失败时 in-memory header 与磁盘一致）
        *self.header_guard() = new_header;
        // FR-12.6 本地审计：改主密码成功事件。打点失败静默（不否定已
        // 成功的改密，与 cf-exporter stamp_* 同纪律）。
        if let Some(state) = guard.as_ref() {
            if let Ok(now) = crate::unix_now() {
                let _ = state.store.repos().audit.append(
                    now,
                    cf_store::AuditEvent::PasswordChange,
                    None,
                );
            }
        }
        Ok(())
    }

    // ------------------------------------------------------ 历史版本

    /// 列出条目的历史版本（version DESC，FR-2.9）。条目不存在 → 1011。
    pub fn list_history(
        &self,
        item_id: &str,
    ) -> SessionResult<Vec<crate::usecase::history::HistoryEntry>> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::history::list_history(&state.store, item_id)
    }

    /// 回滚条目到指定历史版本（FR-2.9）：以快照走正常 update 路径，
    /// 回滚本身也是一次修改（可再回滚）。
    pub fn restore_history(&self, item_id: &str, history_uuid: &str) -> SessionResult<()> {
        let mut guard = self.write_guard(LicensedOp::ItemWrite)?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::history::restore_history(&mut state.store, item_id, history_uuid)
    }

    // ----------------------------------------------------- Watchtower

    /// 运行 Watchtower 安全体检（FR-6.2 / FR-6.3）：重复密码（HMAC 指纹，
    /// `audit_key` 注入）+ 弱密码复检 + 弱 URL。锁定态 → 1001。
    pub fn run_watchtower(&self) -> SessionResult<crate::usecase::audit::WatchtowerReport> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::audit::run_watchtower(&state.store, &state.store.subkeys().audit_key)
    }

    /// 运行五类体检报告（FR-6.7）：重复密码 / 弱 URL / 陈旧密码 /
    /// 泄露启发式 / 无 2FA。单次遍历解密取数；报告只携带 item_id /
    /// 标题 / 非敏感元数据，不含密码明文（见 usecase::health 模块文档）。
    ///
    /// `now_secs` 由调用方注入（Unix 秒，与空闲自动锁定同模式，可测试）；
    /// 陈旧密码阈值取 [`cf_audit::DEFAULT_STALE_DAYS`]（365，docs/03 §8
    /// AUD-04 默认值）。锁定态 → 1001。
    pub fn health_report(
        &self,
        now_secs: i64,
    ) -> SessionResult<crate::usecase::health::HealthReport> {
        let guard = self.unlocked()?;
        let state = guard.as_ref().ok_or(CfError::VaultLocked)?;
        usecase::health::run_health_report(
            &state.store,
            &state.store.subkeys().audit_key,
            now_secs,
            cf_audit::DEFAULT_STALE_DAYS,
        )
    }

    // ---------------------------------------------------- 暴力退避（FR-12.5）

    /// 距退避门禁解除的剩余秒数（向上取整；无门禁返回 0）。
    ///
    /// 旁路通道：门禁期内的 `unlock` / `enable_biometric` / `change_password`
    /// 一律返回 1002（维持 FR-1.4 不可区分性），UI 显示倒计时只经本方法
    /// 获取。内存级计数，进程重启清零（设计裁决的接受限制）。
    #[must_use]
    pub fn backoff_remaining_secs(&self) -> u64 {
        self.backoff_guard().remaining_secs()
    }

    // ------------------------------------------------------- 内部工具

    /// 解锁态守卫：未解锁返回错误码 1001（不泄露其余状态）。
    pub(crate) fn unlocked(&self) -> SessionResult<MutexGuard<'_, Option<UnlockedState>>> {
        let guard = self.state_guard();
        if guard.is_some() {
            Ok(guard)
        } else {
            Err(CfError::VaultLocked)
        }
    }

    /// 注入许可门禁（官方装配点，`docs/02` §10.5 方案 A）：官方装配壳
    /// 构造会话后注入 cf-license 的 gate 实例。开源产物不调用——默认
    /// [`PermitAllGate`] 即「自编译 = 全功能免费版」契约（TC-GATE-10）。
    ///
    /// 装配期调用约定：在派发任何写操作前完成注入；运行中更换 gate
    /// 仅供测试（TC-GATE-09 激活恢复写路径用）。
    pub fn set_license_gate(&self, gate: Arc<dyn LicenseGate>) {
        *self
            .license_gate
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = gate;
    }

    /// 当前 gate 快照（Arc 克隆，缩短读锁持有窗口）。
    fn license_gate_snapshot(&self) -> Arc<dyn LicenseGate> {
        self.license_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// **写用例统一守卫**（`docs/03` §14.6 / `docs/02` §10.3 方案 C；
    /// TC-GATE-12 审读点）：解锁门禁（1001）→ 许可门禁（6002/6003），
    /// 判定落在任何写事务之前。
    ///
    /// 两道门禁叠加语义：锁定态恒 1001（许可判定不提前发生，TC-GATE-11）；
    /// 解锁后按注入 gate 判定，拒绝即返回且**不落任何半截数据**
    /// （TC-GATE-08）。新增写用例必须经本方法取得状态守卫——绕过即
    /// 偏离 §14.6 门禁矩阵（矩阵外新增操作组须同步 `LicensedOp`）。
    pub(crate) fn write_guard(
        &self,
        op: LicensedOp,
    ) -> SessionResult<MutexGuard<'_, Option<UnlockedState>>> {
        let guard = self.unlocked()?;
        match self.license_gate_snapshot().check(op) {
            LicenseDecision::Allow => Ok(guard),
            LicenseDecision::Deny(deny) => Err(match deny {
                LicenseDenial::TrialExpired => CfError::LicenseTrialExpiredWriteDenied,
                LicenseDenial::StateUnavailable => CfError::LicenseStateWriteDenied,
            }),
        }
    }

    /// 状态互斥锁守卫（poison 时不扩散失败：状态本身可安全接管）。
    fn state_guard(&self) -> MutexGuard<'_, Option<UnlockedState>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// current_dek 互斥锁守卫（poison 处理同 [`Self::state_guard`]）。
    fn current_dek_guard(&self) -> MutexGuard<'_, Option<SessionKey>> {
        self.current_dek
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 按 `retain_dek` 决定是否在会话内保留 DEK（三条解锁路径共用，
    /// merge-time R1）。retention 关闭（含 broker 直开路径不调用本方法）
    /// → 直接 drop，`SessionKey` ZeroizeOnDrop 清零，不留副本。
    fn set_current_dek(&self, dek: SessionKey) {
        if self.retain_dek.load(Ordering::Acquire) {
            *self.current_dek_guard() = Some(dek);
        }
    }

    /// header 互斥锁守卫（poison 处理同 [`Self::state_guard`]）。
    fn header_guard(&self) -> MutexGuard<'_, cf_format::Header> {
        self.header
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// header 快照：短暂加锁克隆（header 为数百字节级明文结构，
    /// 克隆开销可忽略），避免跨锁持有（如 KDF 全程）阻塞并发查询。
    fn header_snapshot(&self) -> cf_format::Header {
        self.header_guard().clone()
    }

    /// 退避计数器互斥锁守卫（poison 处理同 [`Self::state_guard`]）。
    fn backoff_guard(&self) -> MutexGuard<'_, UnlockBackoff> {
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 注入测试时钟（仅测试可见）：替换退避计数器的时钟为 FakeClock，
    /// 与 idle 判定的平台喂时同模式（时间注入，可测试）。
    #[cfg(test)]
    fn inject_backoff_clock(&self, clock: std::sync::Arc<dyn crate::backoff::MonotonicClock>) {
        *self.backoff_guard() = UnlockBackoff::with_clock(clock);
    }
}

/// 汇总解锁信息（item_count 来自 meta 表）。
fn vault_info(
    store: &cf_store::ItemStore,
    vault_uuid: cf_domain::VaultId,
    display_name: &str,
) -> SessionResult<VaultInfo> {
    let item_count = store.repos().meta.item_count()?;
    Ok(VaultInfo {
        vault_uuid: vault_uuid.to_string(),
        display_name: display_name.to_owned(),
        item_count,
    })
}

#[cfg(test)]
mod tests {
    use super::VaultSession;
    use super::DEFAULT_CLIPBOARD_CLEAR_SECS;
    use crate::unlock::{create_vault_with_kdf, open_vault};
    use cf_crypto::kdf::KdfParams;

    /// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
    pub(crate) fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    pub(crate) const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

    /// 建库 → 开会话：锁定态门禁拒绝数据访问（错误码 1001）
    #[test]
    fn 锁定态拒绝数据访问() {
        let base = crate::tests_support::temp_dir("locked_gate");
        let brief = create_vault_with_kdf(&base, "测试库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        assert!(!session.is_unlocked());
        assert_eq!(session.display_name(), "测试库");
        let err = session.list_items(None).unwrap_err();
        assert_eq!(err.code(), 1001);
    }

    /// 解锁 → 幂等解锁 → 锁定 → 重新解锁（往返）
    #[test]
    fn 解锁锁定往返() {
        let base = crate::tests_support::temp_dir("roundtrip");
        let brief = create_vault_with_kdf(&base, "往返库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        let info = session.unlock(STRONG_PASSWORD).unwrap();
        assert_eq!(info.item_count, 0);
        assert!(session.is_unlocked());

        // 幂等：已解锁再 unlock 不报错、不重跑 KDF
        let again = session.unlock("任何输入都不影响").unwrap();
        assert_eq!(again.item_count, 0);

        // 锁定后门禁拒绝，重新解锁恢复
        session.lock();
        assert!(!session.is_unlocked());
        assert_eq!(session.unlock(STRONG_PASSWORD).unwrap().item_count, 0);
        assert!(session.is_unlocked());
    }

    /// 错误密码 → 1002，且会话保持锁定态
    #[test]
    fn 错误密码保持锁定() {
        let base = crate::tests_support::temp_dir("wrong_pw");
        let brief =
            create_vault_with_kdf(&base, "错误密码库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        let err = session.unlock("wrong password indeed!").unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(!session.is_unlocked());
    }

    /// 空闲超时：注入时间驱动自动锁定
    #[test]
    fn 空闲超时自动锁定() {
        let base = crate::tests_support::temp_dir("idle");
        let brief = create_vault_with_kdf(&base, "空闲库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        session.set_idle_timeout_secs(300);
        session.set_last_activity(1_000);

        // 未超时：不锁定
        assert!(!session.auto_lock_if_expired(1_299));
        assert!(session.is_unlocked());
        // 恰好到阈值：锁定
        assert!(session.auto_lock_if_expired(1_300));
        assert!(!session.is_unlocked());
        // 锁定态下重复判定不重复报告
        assert!(!session.auto_lock_if_expired(9_999));
    }

    /// idle_timeout <= 0 视为禁用自动锁定
    #[test]
    fn 超时置零禁用自动锁定() {
        let base = crate::tests_support::temp_dir("idle_off");
        let brief = create_vault_with_kdf(&base, "禁用库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        session.set_idle_timeout_secs(0);
        session.set_last_activity(1_000);
        assert!(!session.auto_lock_if_expired(99_999_999));
        assert!(session.is_unlocked());
    }

    /// FR-14.2：默认剪贴板清除时间为 30s（向后兼容 macOS 现行固定行为）
    #[test]
    fn 剪贴板清除时间默认三十秒() {
        let base = crate::tests_support::temp_dir("clip_default");
        let brief = create_vault_with_kdf(&base, "剪贴板库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        assert_eq!(session.clipboard_clear_secs(), DEFAULT_CLIPBOARD_CLEAR_SECS);
        assert_eq!(session.clipboard_clear_secs(), 30);
    }

    /// FR-14.2：五档（10/30/60/120/从不=0）存取回环
    #[test]
    fn 剪贴板清除时间五档存取回环() {
        let base = crate::tests_support::temp_dir("clip_tiers");
        let brief =
            create_vault_with_kdf(&base, "剪贴板档位库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        for secs in [10, 30, 60, 120, 0] {
            session.set_clipboard_clear_secs(secs).unwrap();
            assert_eq!(session.clipboard_clear_secs(), secs);
        }
    }

    /// FR-14.2：非法档位（45、负数等）拒绝，错误码 5002，且原值保持不变
    #[test]
    fn 剪贴板清除时间非法值拒绝() {
        let base = crate::tests_support::temp_dir("clip_bad");
        let brief =
            create_vault_with_kdf(&base, "剪贴板非法库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        session.set_clipboard_clear_secs(60).unwrap();
        for bad in [45, 5, 121, -1, i64::MIN, i64::MAX] {
            let err = session.set_clipboard_clear_secs(bad).unwrap_err();
            assert_eq!(err.code(), 5002, "非法值 {bad} 应报 InvalidArgument");
            assert_eq!(session.clipboard_clear_secs(), 60, "拒绝后配置保持原值");
        }
    }

    /// SubKeys / SessionKey 的 ZeroizeOnDrop 编译期断言：
    /// lock() 置 None 后解锁态 drop，子密钥类型保证清零（NFR-SEC-04）。
    #[test]
    fn 密钥类型保证析构清零() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<cf_crypto::subkeys::SubKeys>();
        assert_zeroize_on_drop::<cf_crypto::aead::SessionKey>();
    }

    /// FR-8.5 备份提醒：从未备份 → 应提醒；打点后阈值内不提醒、
    /// 超阈值提醒、阈值 <= 0 禁用（时间注入，与空闲自动锁定同模式）
    #[test]
    fn 备份提醒按阈值判定() {
        let base = crate::tests_support::temp_dir("backup_reminder");
        let brief = create_vault_with_kdf(&base, "提醒库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();

        // 从未备份（meta 缺行）→ 应提醒
        assert!(session.should_suggest_backup(7 * 86_400, 1_000).unwrap());

        // 打点「上次备份 = 1000」（模拟 exporter 成功路径的写入）
        let guard = session.unlocked().unwrap();
        let state = guard.as_ref().unwrap();
        state.store.repos().meta.set_last_backup_at(1_000).unwrap();
        drop(guard);

        assert!(
            session.should_suggest_backup(300, 1_300).unwrap(),
            "恰达阈值应提醒"
        );
        assert!(
            session.should_suggest_backup(300, 9_999).unwrap(),
            "超阈值应提醒"
        );
        assert!(
            !session.should_suggest_backup(300, 1_299).unwrap(),
            "阈值内不提醒"
        );
        assert!(
            !session.should_suggest_backup(0, 9_999_999).unwrap(),
            "0 视为禁用"
        );
        assert!(
            !session.should_suggest_backup(-1, 9_999_999).unwrap(),
            "负值视为禁用"
        );
    }

    /// FR-8.5 门禁：锁定态查询提醒状态拒绝（错误码 1001）
    #[test]
    fn 锁定态拒绝备份提醒查询() {
        let base = crate::tests_support::temp_dir("backup_reminder_locked");
        let brief =
            create_vault_with_kdf(&base, "锁定提醒库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        let err = session.last_backup_at().unwrap_err();
        assert_eq!(err.code(), 1001);
        let err = session.should_suggest_backup(300, 1_000).unwrap_err();
        assert_eq!(err.code(), 1001);
    }

    // ------------------------------------------------ 暴力退避（FR-12.5）

    use std::sync::Arc;
    use std::time::Duration;

    use crate::backoff::{FakeClock, MonotonicClock};

    /// 建库 → 开会话 → 注入 FakeClock（退避时钟可测试）。
    fn session_with_fake_clock(tag: &str) -> (VaultSession, Arc<FakeClock>) {
        let base = crate::tests_support::temp_dir(tag);
        let brief = create_vault_with_kdf(&base, "退避库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();
        let clock = Arc::new(FakeClock::new());
        session.inject_backoff_clock(clock.clone());
        (session, clock)
    }

    /// FR-12.5：门禁期内 unlock 直接拒绝（1002）且**不执行 KDF**——
    /// 用正确密码仍被拒即证明 KDF 未跑（跑了就会成功）；剩余秒数经
    /// 旁路可查，等待期满后正确密码解锁成功。
    #[test]
    fn 退避门禁期内解锁被拒且不执行kdf() {
        let (session, clock) = session_with_fake_clock("backoff_gate");

        // 连续 3 次错误密码 → 触发 1s 门禁
        for _ in 0..3 {
            let err = session.unlock("wrong-password-indeed!").unwrap_err();
            assert_eq!(err.code(), 1002);
        }
        assert!(!session.is_unlocked());
        assert_eq!(session.backoff_remaining_secs(), 1, "第 3 次失败应延迟 1s");

        // 门禁期内：**正确密码**同样被拒（证明 KDF 未执行），错误码仍 1002
        let err = session.unlock(STRONG_PASSWORD).unwrap_err();
        assert_eq!(err.code(), 1002, "门禁期内正确密码也必须被拒");
        assert!(!session.is_unlocked());

        // 等待期满：正确密码解锁成功，计数清零
        clock.advance(Duration::from_secs(1));
        assert_eq!(session.unlock(STRONG_PASSWORD).unwrap().item_count, 0);
        assert_eq!(session.backoff_remaining_secs(), 0, "成功后计数应清零");
    }

    /// FR-12.5：enable_biometric 经 recover_dek 验主密码（密码 oracle），
    /// 与 unlock 共享同一退避计数器——密码错误计入失败，触发门禁。
    #[test]
    fn bio启用路径与unlock共享退避计数器() {
        let (session, _clock) = session_with_fake_clock("backoff_bio_shared");

        // enable_biometric 需解锁态（1001 门禁）；连续 3 次错误主密码
        // 均经 recover_dek 验证失败（1002）→ 计入共享计数器
        session.unlock(STRONG_PASSWORD).unwrap();
        let k_bio = [0x11u8; 32];
        for _ in 0..3 {
            let err = session
                .enable_biometric("wrong-password-indeed!", &k_bio)
                .unwrap_err();
            assert_eq!(err.code(), 1002);
        }
        assert_eq!(
            session.backoff_remaining_secs(),
            1,
            "bio 启用路径的密码失败应计入同一计数器"
        );

        // 门禁期内主密码 unlock 同样被拒（共享门禁，KDF 未执行）
        session.lock();
        let err = session.unlock(STRONG_PASSWORD).unwrap_err();
        assert_eq!(err.code(), 1002);
    }

    /// FR-12.5：unlock_with_biometric 既不受门禁也不计数——门禁期内
    /// bio 解锁照常成功，且成功不清退避计数（该路径完全不触碰计数器）。
    #[test]
    fn bio解锁不受退避门禁且不计数() {
        let (session, _clock) = session_with_fake_clock("backoff_bio_exempt");

        // 先启用 bio（成功路径会清零计数）
        session.unlock(STRONG_PASSWORD).unwrap();
        let k_bio = [0x22u8; 32];
        session.enable_biometric(STRONG_PASSWORD, &k_bio).unwrap();
        session.lock();

        // 3 次主密码错误 → 门禁激活
        for _ in 0..3 {
            session.unlock("wrong-password-indeed!").unwrap_err();
        }
        let remaining = session.backoff_remaining_secs();
        assert!(remaining > 0);

        // 门禁期内 bio 解锁照常成功（不受门禁）
        session.lock();
        assert!(session.unlock_with_biometric(&k_bio).is_ok());

        // bio 解锁不触碰计数器：门禁剩余时间不变（不计数）
        assert_eq!(
            session.backoff_remaining_secs(),
            remaining,
            "unlock_with_biometric 不应影响退避计数"
        );
    }

    /// 编译期断言：退避时钟为动态派发且跨线程可用（VaultSession 需 Send+Sync）。
    #[test]
    fn 退避时钟类型满足线程安全约束() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Arc<dyn MonotonicClock>>();
        // FakeClock 内部 Mutex 保护，可跨线程
        assert_send_sync::<Arc<FakeClock>>();
    }

    /// 换密用的新强密码（zxcvbn score ≥ 3，可过强度门禁）。
    const CHANGE_TO_PASSWORD: &str = "quartz-lantern-vault-meridian-93#";

    /// MEDIUM-1：change_password 经 recover_dek 验旧密码（密码 oracle），
    /// 连续错旧密码 ≥3 次触发退避门禁——门禁期内正确旧密码也被拒（1002），
    /// 期满后改密成功且计数清零。
    #[test]
    fn 改密错旧密码触发退避门禁() {
        let (session, clock) = session_with_fake_clock("backoff_change_pw");
        session.unlock(STRONG_PASSWORD).unwrap();

        // 连续 3 次错旧密码（新密码合法，失败来自旧密码校验）→ 1002 ×3
        for _ in 0..3 {
            let err = session
                .change_password("wrong-password-indeed!", CHANGE_TO_PASSWORD, None)
                .unwrap_err();
            assert_eq!(err.code(), 1002);
        }
        assert_eq!(
            session.backoff_remaining_secs(),
            1,
            "第 3 次错旧密码应延迟 1s"
        );

        // 门禁期内：正确旧密码同样被拒（1002），不执行 KDF
        let err = session
            .change_password(STRONG_PASSWORD, CHANGE_TO_PASSWORD, None)
            .unwrap_err();
        assert_eq!(err.code(), 1002, "门禁期内改密必须被拒");

        // 期满后改密成功，计数清零，新密码生效
        clock.advance(Duration::from_secs(1));
        session
            .change_password(STRONG_PASSWORD, CHANGE_TO_PASSWORD, None)
            .unwrap();
        assert_eq!(session.backoff_remaining_secs(), 0, "改密成功后计数应清零");
        session.lock();
        assert!(session.unlock(CHANGE_TO_PASSWORD).is_ok(), "新密码应生效");
    }

    /// MEDIUM-1：改密成功清零计数——2 次错旧密码（未达阈值）后成功改密，
    /// 后续 1 次错旧密码重新从 n=1 起算、不触发门禁。
    #[test]
    fn 改密成功后退避计数清零() {
        let (session, _clock) = session_with_fake_clock("backoff_change_pw_reset");
        session.unlock(STRONG_PASSWORD).unwrap();

        for _ in 0..2 {
            let err = session
                .change_password("wrong-password-indeed!", CHANGE_TO_PASSWORD, None)
                .unwrap_err();
            assert_eq!(err.code(), 1002);
        }
        session
            .change_password(STRONG_PASSWORD, CHANGE_TO_PASSWORD, None)
            .unwrap();
        assert_eq!(session.backoff_remaining_secs(), 0, "成功后计数应清零");

        // 重新计数：1 次错旧密码不触发门禁
        let err = session
            .change_password("wrong-password-indeed!", CHANGE_TO_PASSWORD, None)
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert_eq!(session.backoff_remaining_secs(), 0, "n=1 不应触发门禁");
    }

    /// MEDIUM-1 接线：非密码错误不计入——弱新密码（1010）连续多次不触发
    /// 门禁（与 enable_biometric 的 5002 参数错同款语义）。
    #[test]
    fn 改密弱新密码不计入退避() {
        let (session, _clock) = session_with_fake_clock("backoff_change_pw_weak");
        session.unlock(STRONG_PASSWORD).unwrap();

        for _ in 0..5 {
            let err = session
                .change_password(STRONG_PASSWORD, "123456", None)
                .unwrap_err();
            assert_eq!(err.code(), 1010);
        }
        assert_eq!(
            session.backoff_remaining_secs(),
            0,
            "弱密码错误不应计入退避"
        );
    }

    /// MEDIUM-2 串行接线验证：预占（in_flight）在 unlock / change_password
    /// 的所有退出路径都被释放——若任一路径泄漏预占，后续调用将被拒（1002）。
    /// 并发窗口内「第二调用被拒」的内核语义由 backoff 单元测试
    /// `预占期间再次获取被拒` 确定性覆盖（真实并发 KDF 时序不可靠，
    /// 不做时序断言）。
    #[test]
    fn 预占在所有退出路径释放() {
        let (session, _clock) = session_with_fake_clock("backoff_in_flight");

        // unlock 失败路径（on_failure）释放：随后解锁成功（若泄漏将 1002）
        session.unlock("wrong-password-indeed!").unwrap_err();
        session.unlock(STRONG_PASSWORD).unwrap();
        // unlock 幂等路径（release）释放：已解锁再 unlock 仍 Ok
        session.unlock("idempotent-call-does-not-matter").unwrap();

        // change_password 非密码错误路径（release）释放：弱新密码 1010
        session
            .change_password(STRONG_PASSWORD, "123456", None)
            .unwrap_err();
        // change_password 失败路径（on_failure）+ 成功路径（on_success）释放
        session
            .change_password("wrong-password-indeed!", CHANGE_TO_PASSWORD, None)
            .unwrap_err();
        session
            .change_password(STRONG_PASSWORD, CHANGE_TO_PASSWORD, None)
            .unwrap();

        // 收尾：若任一路径泄漏预占，此解锁将 1002
        session.lock();
        session.unlock(CHANGE_TO_PASSWORD).unwrap();
    }

    // ------------------------------------------------ DEK 直开（merge-time R2）

    /// 读磁盘 header（供 `recover_dek` 解出 DEK；测试辅助）。
    fn header_of(vault_dir: &std::path::Path) -> cf_format::Header {
        match cf_format::open_container(vault_dir).unwrap() {
            cf_format::OpenOutcome::Current(h) => h,
            _ => panic!("新建库应可正常打开"),
        }
    }

    /// 最小 Login 草稿（类别必填的 username / password 字段，attachments
    /// 集成测试同款）。用于给测试库写入一个条目——`with_tx` 由此写入
    /// 完整性基线（`record_count`/`root_mac`），错 DEK 才能被
    /// `verify_integrity` 检出（空库无基线走自举分支，不会失败）。
    fn draft_item(title: &str) -> cf_domain::item::ItemDraft {
        cf_domain::item::ItemDraft {
            title: title.to_owned(),
            category: cf_domain::category::ItemCategory::Login,
            urls: vec![],
            tags: vec![],
            sections: vec![],
            fields: vec![
                cf_domain::item::FieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice@example.com".to_owned()),
                    field_type: cf_domain::field::FieldType::Text,
                    designation: Some(cf_domain::field::Designation::Username),
                    section_index: None,
                    position: 0,
                },
                cf_domain::item::FieldDraft {
                    name: "密码".to_owned(),
                    value: Some("hunter2-secret!".to_owned()),
                    field_type: cf_domain::field::FieldType::Concealed,
                    designation: Some(cf_domain::field::Designation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        }
    }

    /// 建库 + 密码解锁 + 写 1 个条目（建立完整性基线），返回锁定态会话。
    fn locked_vault_with_item(tag: &str) -> (VaultSession, std::path::PathBuf) {
        let base = crate::tests_support::temp_dir(tag);
        let brief = create_vault_with_kdf(&base, "基线库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.unlock(STRONG_PASSWORD).unwrap();
        session.create_item(&draft_item("基线条目")).unwrap();
        session.lock();
        (session, vault_dir)
    }

    /// R2：DEK 直开解锁成功——建临时 vault（含 1 条目，有完整性基线），
    /// 用 recover_dek 解出 DEK 直开，解锁态数据访问正常，且直开路径不留
    /// DEK（broker 专属，无保留语义）。
    #[test]
    fn dek直开解锁成功() {
        let (session, vault_dir) = locked_vault_with_item("dek_unlock_ok");

        let header = header_of(&vault_dir);
        let dek = crate::unlock::recover_dek(&vault_dir, &header, STRONG_PASSWORD).unwrap();

        let info = session.unlock_with_dek(dek.as_bytes()).unwrap();
        assert_eq!(info.item_count, 1);
        assert!(session.is_unlocked());
        assert_eq!(session.list_items(None).unwrap().len(), 1);
        assert!(
            session.current_dek_guard().is_none(),
            "直开路径不应保留 DEK（broker 无导出能力）"
        );
    }

    /// R2：错误 DEK（形状合法 32B 但内容错）→ 1002（fail-closed，
    /// verify_integrity 的 root_mac 检出），会话保持锁定态。
    #[test]
    fn dek直开错误dek失败1002() {
        let (session, _vault_dir) = locked_vault_with_item("dek_unlock_wrong");

        let wrong = cf_crypto::aead::SessionKey::new([0xABu8; 32]);
        let err = session.unlock_with_dek(wrong.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(!session.is_unlocked());
    }

    /// R2：DEK 非 32 字节 → 5002（参数错误，非解锁失败），会话保持锁定态。
    #[test]
    fn dek直开长度校验5002() {
        let base = crate::tests_support::temp_dir("dek_unlock_keylen");
        let brief = create_vault_with_kdf(&base, "长度库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();

        for bad in [&[0u8; 31][..], &[0u8; 33][..], &[]] {
            let err = session.unlock_with_dek(bad).unwrap_err();
            assert_eq!(err.code(), 5002, "len={} 应报 InvalidArgument", bad.len());
        }
        assert!(!session.is_unlocked());
    }

    /// R2：幂等——已解锁后再直开（哪怕传错误 DEK）直接返回当前信息，不重开。
    #[test]
    fn dek直开幂等() {
        let base = crate::tests_support::temp_dir("dek_unlock_idem");
        let brief = create_vault_with_kdf(&base, "幂等库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();

        let header = header_of(&vault_dir);
        let dek = crate::unlock::recover_dek(&vault_dir, &header, STRONG_PASSWORD).unwrap();
        assert_eq!(
            session.unlock_with_dek(dek.as_bytes()).unwrap().item_count,
            0
        );

        // 已解锁再调（错误 DEK）→ 幂等成功（与 unlock_with_mcp_key 同构）
        let again = session.unlock_with_dek(&[0xFFu8; 32]).unwrap();
        assert_eq!(again.item_count, 0);
        assert!(session.is_unlocked());
    }

    /// R2：不触碰退避计数器——锁定态直开错 DEK → 1002，门禁剩余时间不变
    /// （DEK 非密码 oracle，无免费猜测通道）。
    #[test]
    fn dek直开不触碰退避() {
        let (session, _clock) = session_with_fake_clock("backoff_dek_exempt");
        // 给库建立完整性基线（首个事务写入 root_mac），并回到锁定态
        session.unlock(STRONG_PASSWORD).unwrap();
        session.create_item(&draft_item("基线条目")).unwrap();
        session.lock();

        // 3 次错误密码 → 门禁激活
        for _ in 0..3 {
            session.unlock("wrong-password-indeed!").unwrap_err();
        }
        let remaining = session.backoff_remaining_secs();
        assert!(remaining > 0);

        // 锁定态直开错 DEK → 1002（fail-closed），但不计数、不受门禁
        let wrong = cf_crypto::aead::SessionKey::new([0xCDu8; 32]);
        let err = session.unlock_with_dek(wrong.as_bytes()).unwrap_err();
        assert_eq!(err.code(), 1002);
        assert_eq!(
            session.backoff_remaining_secs(),
            remaining,
            "直开不得影响退避计数"
        );
        assert!(!session.is_unlocked());
    }

    // ------------------------------------------------ DEK 保留（merge-time R1）

    /// R1：set_dek_retention 幂等开关——默认关闭，开/关各重复调用无副作用。
    #[test]
    fn dek保留开关幂等() {
        let base = crate::tests_support::temp_dir("dek_retention_toggle");
        let brief = create_vault_with_kdf(&base, "保留库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        assert!(
            !session
                .retain_dek
                .load(std::sync::atomic::Ordering::Acquire),
            "默认关闭 retention"
        );
        session.set_dek_retention(true);
        session.set_dek_retention(true); // 幂等
        assert!(session
            .retain_dek
            .load(std::sync::atomic::Ordering::Acquire));
        session.set_dek_retention(false);
        session.set_dek_retention(false); // 幂等
        assert!(!session
            .retain_dek
            .load(std::sync::atomic::Ordering::Acquire));
    }

    /// R1：retention 开启时解锁后 current_dek 持有，且与 recover_dek 解出值一致。
    #[test]
    fn dek保留开启时解锁持有dek() {
        let base = crate::tests_support::temp_dir("dek_retention_hold");
        let brief = create_vault_with_kdf(&base, "保留库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();

        session.set_dek_retention(true);
        session.unlock(STRONG_PASSWORD).unwrap();

        let header = header_of(&vault_dir);
        let expected = crate::unlock::recover_dek(&vault_dir, &header, STRONG_PASSWORD).unwrap();
        assert_eq!(
            session.current_dek_guard().as_ref().unwrap().as_bytes(),
            expected.as_bytes(),
            "解锁后应持有 DEK"
        );
    }

    /// R1：lock() 清零 current_dek（与 state 同清）；重新解锁按 retain 恢复持有。
    #[test]
    fn dek保留lock清零且重开恢复() {
        let base = crate::tests_support::temp_dir("dek_retention_lock");
        let brief = create_vault_with_kdf(&base, "保留库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.set_dek_retention(true);
        session.unlock(STRONG_PASSWORD).unwrap();
        assert!(session.current_dek_guard().is_some());

        session.lock();
        assert!(session.current_dek_guard().is_none(), "lock() 必须清零 DEK");
        assert!(!session.is_unlocked());

        // 重新解锁 → 重新持有（retention 仍开）
        session.unlock(STRONG_PASSWORD).unwrap();
        assert!(session.current_dek_guard().is_some());
    }

    /// R1：retention 关闭时解锁不留 DEK；从开启切换到关闭时立即清零已持有 DEK。
    #[test]
    fn dek保留关闭时不留() {
        let base = crate::tests_support::temp_dir("dek_retention_off");
        let brief = create_vault_with_kdf(&base, "保留库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();

        // 默认关闭：解锁不留
        session.unlock(STRONG_PASSWORD).unwrap();
        assert!(session.current_dek_guard().is_none(), "默认不应持有 DEK");

        // 开启 → 解锁持有 → 关闭立即清零
        session.set_dek_retention(true);
        session.lock();
        session.unlock(STRONG_PASSWORD).unwrap();
        assert!(session.current_dek_guard().is_some());
        session.set_dek_retention(false);
        assert!(
            session.current_dek_guard().is_none(),
            "关闭 retention 应立即清零"
        );

        // 关闭后重新解锁不留
        session.lock();
        session.unlock(STRONG_PASSWORD).unwrap();
        assert!(session.current_dek_guard().is_none());
    }

    /// R1：三条解锁路径（主密码 / bio / mcp）在 retention 开启时均持有 DEK，
    /// 且持有的是同一 DEK（recover_dek 解出值）。
    #[test]
    fn dek保留三条解锁路径均持有() {
        let base = crate::tests_support::temp_dir("dek_retention_three_paths");
        let brief = create_vault_with_kdf(&base, "保留库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();
        session.set_dek_retention(true);

        let header = header_of(&vault_dir);
        let expected = crate::unlock::recover_dek(&vault_dir, &header, STRONG_PASSWORD).unwrap();

        // 主密码路径
        session.unlock(STRONG_PASSWORD).unwrap();
        assert_eq!(
            session.current_dek_guard().as_ref().unwrap().as_bytes(),
            expected.as_bytes(),
            "主密码路径应持有 DEK"
        );

        // bio 路径（先启用）
        let k_bio = crate::unlock_bio::new_biometric_unwrap_key().unwrap();
        session
            .enable_biometric(STRONG_PASSWORD, k_bio.as_bytes())
            .unwrap();
        session.lock();
        session.unlock_with_biometric(k_bio.as_bytes()).unwrap();
        assert_eq!(
            session.current_dek_guard().as_ref().unwrap().as_bytes(),
            expected.as_bytes(),
            "bio 路径应持有 DEK"
        );

        // mcp 路径（先启用）
        let mcp_key = session.derive_mcp_key(STRONG_PASSWORD).unwrap();
        session
            .enable_mcp_escrow(STRONG_PASSWORD, mcp_key.as_bytes())
            .unwrap();
        session.lock();
        session.unlock_with_mcp_key(mcp_key.as_bytes()).unwrap();
        assert_eq!(
            session.current_dek_guard().as_ref().unwrap().as_bytes(),
            expected.as_bytes(),
            "mcp 路径应持有 DEK"
        );
    }

    /// R1：export_dek 三态门禁——retention 开启 + 解锁 → Ok(32B) 且与
    /// recover_dek 解出值一致；retention 未开 → Err（InvalidArgument，
    /// FFI 映射 5002）；开启 + 解锁后 lock() → Err（current_dek 已清零）。
    #[test]
    fn export_dek三态门禁() {
        let base = crate::tests_support::temp_dir("export_dek_gates");
        let brief = create_vault_with_kdf(&base, "导出库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let vault_dir = base.join(brief.uuid.to_string());
        let session = open_vault(&vault_dir).unwrap();

        // 态 1：retention 关闭（默认）→ Err（5002 语义）
        session.unlock(STRONG_PASSWORD).unwrap();
        let err = session.export_dek().unwrap_err();
        assert_eq!(err.code(), 5002, "retention 未开应 fail-closed");

        // 态 2：开启 + 解锁 → Ok(32B)，与 recover_dek 解出值一致
        session.set_dek_retention(true);
        session.lock();
        session.unlock(STRONG_PASSWORD).unwrap();
        let header = header_of(&vault_dir);
        let expected = crate::unlock::recover_dek(&vault_dir, &header, STRONG_PASSWORD).unwrap();
        let exported = session.export_dek().unwrap();
        assert_eq!(exported.len(), 32);
        assert_eq!(exported, expected.as_bytes().to_vec());

        // 态 3：lock() 后 → Err（DEK 已清零）
        session.lock();
        let err = session.export_dek().unwrap_err();
        assert_eq!(err.code(), 5002, "lock() 后不应可导出");
    }

    // ------------------------------------------------ origin 绑定封装（merge-time E 前置）

    /// E 前置：两个 VaultSession 薄封装往返——锁定态 → 1001（write_guard
    /// 门禁）；建带绑定条目 → get_item 带出断言；set 改写 → get_item 断言
    /// 更新。usecase 层语义（绑定写读一致性）已由 items.rs 单测覆盖，
    /// 本测试只验封装转发 + 门禁接线。
    #[test]
    fn origin绑定封装往返() {
        let base = crate::tests_support::temp_dir("origin_binding_wrappers");
        let brief = create_vault_with_kdf(&base, "绑定库", STRONG_PASSWORD, fast_kdf()).unwrap();
        let session = open_vault(&base.join(brief.uuid.to_string())).unwrap();

        let b_exact = cf_domain::origin::OriginBinding {
            kind: cf_domain::origin::OriginBindingKind::Exact,
            value: "https://example.com".to_owned(),
        };
        let b_domain = cf_domain::origin::OriginBinding {
            kind: cf_domain::origin::OriginBindingKind::Domain,
            value: "example.org".to_owned(),
        };

        // 锁定态：两个封装都应 1001（write_guard 门禁）
        let err = session
            .create_item_with_origin_bindings(&draft_item("锁定"), vec![b_exact.clone()])
            .unwrap_err();
        assert_eq!(err.code(), 1001);
        let err = session
            .set_item_origin_bindings("some-id", vec![b_exact.clone()])
            .unwrap_err();
        assert_eq!(err.code(), 1001);

        // 建带绑定条目 → get_item 带出断言
        session.unlock(STRONG_PASSWORD).unwrap();
        let id = session
            .create_item_with_origin_bindings(&draft_item("绑定条目"), vec![b_exact.clone()])
            .unwrap();
        let item = session.get_item(&id).unwrap().unwrap();
        assert_eq!(item.origin_bindings, vec![b_exact.clone()]);

        // set 改写 → get_item 断言更新
        session
            .set_item_origin_bindings(&id, vec![b_domain.clone()])
            .unwrap();
        let item = session.get_item(&id).unwrap().unwrap();
        assert_eq!(item.origin_bindings, vec![b_domain.clone()]);
    }
}
