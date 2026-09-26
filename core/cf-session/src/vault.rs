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
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, MutexGuard};

use cf_domain::item::ItemDraft;
use cf_domain::item::ItemSummary;
use cf_domain::secret::SecretString;
use cf_store::ItemListFilter;

use crate::idle;
use crate::types::{ItemDetails, TotpCode, VaultInfo};
use crate::usecase;
use crate::{SessionResult, TotpSession};
use cf_domain::CfError;

/// 默认空闲超时（FR-1.6 / docs/07 §7 T05：默认 5 分钟，可配置）。
pub const DEFAULT_IDLE_TIMEOUT_SECS: i64 = 300;

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
    header: cf_format::Header,
    state: Mutex<Option<UnlockedState>>,
    last_activity: AtomicI64,
    idle_timeout_secs: AtomicI64,
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
            header,
            state: Mutex::new(None),
            last_activity: AtomicI64::new(crate::unix_now().unwrap_or(0)),
            idle_timeout_secs: AtomicI64::new(DEFAULT_IDLE_TIMEOUT_SECS),
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
    pub fn unlock(&self, password: &str) -> SessionResult<VaultInfo> {
        let mut guard = self.state_guard();
        if let Some(state) = guard.as_ref() {
            return vault_info(&state.store, self.vault_uuid, &self.display_name);
        }

        let store = crate::unlock::unlock_store(&self.vault_dir, &self.header, password)?;
        let info = vault_info(&store, self.vault_uuid, &self.display_name)?;
        self.last_activity
            .store(crate::unix_now().unwrap_or(0), Ordering::Release);
        *guard = Some(UnlockedState { store });
        Ok(info)
    }

    /// 锁定：立即 drop 解锁态 → 子密钥全链路清零（docs/07 §2.2）。
    ///
    /// 幂等：锁定态再调用无副作用。
    pub fn lock(&self) {
        *self.state_guard() = None;
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

    // ------------------------------------------------------ 条目 CRUD

    /// 创建条目：`cf-domain::validate_item` 前置校验 → 单事务写库。
    /// 返回新条目 ID（UUIDv7 文本）。
    pub fn create_item(&self, draft: &ItemDraft) -> SessionResult<String> {
        let mut guard = self.unlocked()?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::create_item(&mut state.store, draft)
    }

    /// 更新条目：读旧快照（为 v0.2 history 预留接口，v0.1 不写 history 表）
    /// → 校验 → 单事务整体替换（fields / urls / tags / sections / totp
    /// 均为「删旧插新」语义）。
    pub fn update_item(&self, item_id: &str, draft: &ItemDraft) -> SessionResult<()> {
        let mut guard = self.unlocked()?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::update_item(&mut state.store, item_id, draft)
    }

    /// 删除条目：`hard = false` 移入回收站（软删），`hard = true`
    /// 连同从表（fields / urls / tags / totp 等）级联硬删。
    pub fn delete_item(&self, item_id: &str, hard: bool) -> SessionResult<()> {
        let mut guard = self.unlocked()?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::delete_item(&mut state.store, item_id, hard)
    }

    /// 从回收站恢复条目。
    pub fn restore_item(&self, item_id: &str) -> SessionResult<()> {
        let mut guard = self.unlocked()?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        usecase::items::restore_item(&mut state.store, item_id)
    }

    /// 设置 / 取消收藏。
    pub fn set_favorite(&self, item_id: &str, favorite: bool) -> SessionResult<()> {
        let mut guard = self.unlocked()?;
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
        let mut guard = self.unlocked()?;
        let state = guard.as_mut().ok_or(CfError::VaultLocked)?;
        cf_importer::import_csv(path, &mut state.store)
    }

    // ------------------------------------------------------- 内部工具

    /// 解锁态守卫：未解锁返回错误码 1001（不泄露其余状态）。
    fn unlocked(&self) -> SessionResult<MutexGuard<'_, Option<UnlockedState>>> {
        let guard = self.state_guard();
        if guard.is_some() {
            Ok(guard)
        } else {
            Err(CfError::VaultLocked)
        }
    }

    /// 状态互斥锁守卫（poison 时不扩散失败：状态本身可安全接管）。
    fn state_guard(&self) -> MutexGuard<'_, Option<UnlockedState>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    /// SubKeys / SessionKey 的 ZeroizeOnDrop 编译期断言：
    /// lock() 置 None 后解锁态 drop，子密钥类型保证清零（NFR-SEC-04）。
    #[test]
    fn 密钥类型保证析构清零() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<cf_crypto::subkeys::SubKeys>();
        assert_zeroize_on_drop::<cf_crypto::aead::SessionKey>();
    }
}
