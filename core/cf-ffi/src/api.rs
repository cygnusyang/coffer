//! FFI 接口：[`CofferApp`] 工厂 + [`VaultSession`] 会话门面
//! （docs/07 §2.3 v0.1 接口清单，全同步）。
//!
//! ## 决策落点（docs/07 §2.3 关键决策表）
//!
//! | 决策 | 落点 |
//! | --- | --- |
//! | 全同步 | 所有方法均为同步 Rust 签名；Swift 侧 `Task.detached` 包裹 |
//! | 会话对象生命周期 | `CofferApp` 持 `Mutex<HashMap<uuid, Arc<VaultSession>>>`；同 uuid 重复 `open_vault` 返回同一实例（避免双会话并发写库）；`lock_all()` 供系统事件批量锁定 |
//! | 密钥暴露面 | DEK / SubKeys 不出现在任何签名；Concealed 字段值只在 `get_field_value` / `totp_code` 下发 |
//! | 错误映射 | `CfError → FfiError`（docs/03 §12 码表），见 [`crate::error`] |
//! | 平台回调 | v0.1 无 callback interface |
//!
//! ## 一处实现形态说明
//!
//! `cf_session::VaultSession` 定义在 cf-session（无 UniFFI 派生）。为满足
//! UniFFI Object 的孤儿规则并保持上游 crate 零 UniFFI 依赖，本 crate 定义
//! 同名包装类型 [`VaultSession`]（`Arc` 门面，方法逐个委托 + panic 守卫）。
//! 语义与 docs/07 §2.3 的 `object VaultSession` 一致：Swift 只持 Arc 引用
//! 计数，重复 `open_vault` 幂等。

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use cf_domain::license::{LicenseDecision, LicenseDenial, LicenseGate, LicensedOp, PermitAllGate};
use cf_domain::CfError;
use cf_importer::OtpauthData;

use crate::error::FfiError;
use crate::session_call;
use crate::types::*;

/// 应用入口工厂：库的枚举 / 创建 / 打开，以及打开会话的注册表。
#[derive(uniffi::Object)]
pub struct CofferApp {
    /// 已打开会话注册表（key = vault uuid 文本）。持强引用防止 Swift 侧
    /// 意外提前释放导致密钥 drop（docs/07 §6.1 R-4）。
    sessions: Mutex<HashMap<String, Arc<VaultSession>>>,
    /// 许可只读门禁（FR-15，`docs/02` §10.3 方案 C 应用级落点）：管辖
    /// **不经过会话**的应用级写操作（create_vault / export_backup /
    /// restore_backup），并经 [`Self::open_vault`] 下传全部会话。默认
    /// [`PermitAllGate`]；官方装配经 [`Self::set_license_gate`] 注入
    /// cf-license（闭源，私有仓库）。
    license_gate: std::sync::RwLock<Arc<dyn LicenseGate>>,
}

/// 解锁会话门面（`cf_session::VaultSession` 的 UniFFI Object 包装）。
#[derive(uniffi::Object)]
pub struct VaultSession {
    /// 内部会话（持 DEK 派生的 SubKeys，永不跨 FFI）
    inner: Arc<cf_session::VaultSession>,
}

#[uniffi::export]
impl CofferApp {
    /// 创建应用工厂。
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            license_gate: std::sync::RwLock::new(Arc::new(PermitAllGate)),
        })
    }

    /// 枚举工作目录下的全部库（只读 header.json 非敏感字段）。
    ///
    /// 目录不存在返回空列表；单个库目录 header 损坏 / 不完整（如创建中）
    /// 跳过而不中断整体枚举（创建是原子目录写入，半成品库不应阻塞 App）。
    pub fn list_vaults(&self, base_dir: String) -> Result<Vec<FfiVaultBrief>, FfiError> {
        let entries = match std::fs::read_dir(&base_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(FfiError::from(CfError::Io(e.to_string()))),
        };

        let mut briefs = Vec::new();
        for entry in entries {
            let path = match entry {
                Ok(p) => p.path(),
                // 单个目录项读取失败不中断枚举
                Err(_) => continue,
            };
            if !path.is_dir() {
                continue;
            }
            if let Ok(cf_format::OpenOutcome::Current(header)) = cf_format::open_container(&path) {
                briefs.push(FfiVaultBrief {
                    vault_uuid: header.vault_uuid,
                    display_name: header.display_name,
                    created_at: header.created_at,
                    modified_at: header.modified_at,
                    format_version: header.format_version,
                });
            }
        }
        // UUIDv7 文本排序即时间序：旧库在前，稳定输出
        briefs.sort_by(|a, b| a.vault_uuid.cmp(&b.vault_uuid));
        Ok(briefs)
    }

    /// 建库：zxcvbn 强度门禁（score < 3 → 码 1010）→ 创建容器 → 初始化库。
    ///
    /// Argon2id 256 MiB 档位，Swift 侧应以 `Task.detached` 包裹。
    pub fn create_vault(
        &self,
        base_dir: String,
        name: String,
        password: String,
    ) -> Result<FfiVaultBrief, FfiError> {
        self.license_check(LicensedOp::VaultWrite)?;
        session_call(AssertUnwindSafe(|| {
            cf_session::create_vault(Path::new(&base_dir), &name, &password)
        }))
        .map(FfiVaultBrief::from)
    }

    /// 打开会话（**幂等**）：同 uuid 已打开则返回同一实例，避免双会话
    /// 并发写库（docs/07 §7 T04 验收 ⑤）。
    ///
    /// `vault_uuid` 必须是合法 UUID 文本（同时防路径拼接逃逸）。
    pub fn open_vault(
        &self,
        base_dir: String,
        vault_uuid: String,
    ) -> Result<Arc<VaultSession>, FfiError> {
        let uuid = uuid::Uuid::parse_str(&vault_uuid).map_err(|_| {
            FfiError::from(CfError::InvalidArgument(
                "vault_uuid is not a valid uuid".into(),
            ))
        })?;
        let key = uuid.to_string();

        let mut map = self.sessions_lock();
        if let Some(existing) = map.get(&key) {
            return Ok(existing.clone());
        }

        let vault_dir = PathBuf::from(base_dir).join(&key);
        let session = session_call(AssertUnwindSafe(|| cf_session::open_vault(&vault_dir)))?;
        // 许可门禁下传（FR-15）：会话级写用例统一守卫与应用级 gate 同源
        session.set_license_gate(self.license_gate_snapshot());
        let wrapped = Arc::new(VaultSession {
            inner: Arc::new(session),
        });
        map.insert(key, wrapped.clone());
        Ok(wrapped)
    }

    /// 批量锁定全部已打开会话（系统锁屏 / 休眠 / 退出时由 Swift 侧调用）。
    ///
    /// 注册表保留会话实例：重新解锁同一库复用同一对象（幂等语义不变）。
    pub fn lock_all(&self) {
        for session in self.sessions_lock().values() {
            session.inner.lock();
        }
    }

    /// 密码强度评估（zxcvbn 0–4 + 改进建议；纯计算，无会话依赖）。
    ///
    /// 建库前尚无会话（v0.1 已知限制），建库界面的强度条由本工厂方法
    /// 供能；与 [`VaultSession::strength_estimate`] 同语义（同一实现
    /// 委托 [`strength_estimate_impl`]）。
    pub fn strength_estimate(&self, candidate: String) -> Result<FfiStrengthEstimate, FfiError> {
        Ok(strength_estimate_impl(&candidate))
    }

    /// 生成 32 字节随机 bio unwrap-key（K_bio，docs/08 §6 / D-3）。
    ///
    /// cf-crypto CSPRNG（`SessionKey::random`），仅生成、不落任何状态；
    /// 调用方（Swift）负责存入 Keychain（`ThisDeviceOnly` +
    /// `biometryCurrentSet`，docs/08 §3.2）。K_bio 是随机封装密钥——非
    /// KEK、非主密码派生物，DEK 语义不变。两次调用必不相同。
    pub fn new_biometric_unwrap_key(&self) -> Result<Vec<u8>, FfiError> {
        session_call(AssertUnwindSafe(cf_session::new_biometric_unwrap_key))
            .map(|key| key.as_bytes().to_vec())
    }

    // ---------------------------------------------------- 备份（FR-8.1）

    /// 导出加密备份（FR-8.1，docs/09 §3.1）：工作目录打包为 `.coffer`
    /// （ZIP 交换形态），成功后自动执行结构校验并给源库
    /// `meta.last_backup_at` 打点（FR-8.5）。
    ///
    /// **锁定态可执行**（TC-EXP-08）——全程不接触密钥，属 CofferApp 级
    /// 操作。导出的是完整库（非明文但可被爆破），UI 二次确认由 Swift
    /// 侧负责（docs/09 §5 FFI 备注）。
    ///
    /// # 错误
    ///
    /// 源目录不是合法库目录 → 1012；打包 / 落盘失败 → 2003
    /// （docs/09 §4 错误表）。
    pub fn export_backup(
        &self,
        vault_dir: String,
        out_path: String,
    ) -> Result<FfiBackupExportResult, FfiError> {
        // FR-15.2：数据出口在只读模式全拒（`docs/03` §14.6 边界裁决：
        // 备份诉求以「激活后可备份」文案引导，从需求原文）
        self.license_check(LicensedOp::ExportData)?;
        session_call(AssertUnwindSafe(|| {
            cf_exporter::export_backup(Path::new(&vault_dir), Path::new(&out_path))
        }))
        .map(Into::into)
    }

    /// 备份结构校验（FR-8.6，无需密码）：ZIP 可解 → `header.json` 合法 →
    /// `db.sqlite` schema 可验证。锁定态可执行。
    ///
    /// # 错误
    ///
    /// 非 ZIP / 缺关键文件（无法认定是 Coffer 备份）→ 2001；
    /// header 畸形 → 1005；格式版本过新 → 1006。
    pub fn verify_backup(&self, backup_path: String) -> Result<FfiBackupVerifyReport, FfiError> {
        session_call(AssertUnwindSafe(|| {
            cf_exporter::verify_backup(Path::new(&backup_path))
        }))
        .map(Into::into)
    }

    /// 恢复备份（FR-8.1 回环）：解包到
    /// `<target_base_dir>/<vault_uuid>/`，返回恢复产物目录路径。
    ///
    /// **锁定态可执行**；包内路径经 zip-slip 防护。恢复后走常规
    /// `open_vault` + `unlock`（主密码校验在解锁侧，FR-1.4）。
    ///
    /// # 错误
    ///
    /// 非 Coffer 包 → 2001；目标已存在同名库目录 → 1004；条目路径
    /// 非法 / 恢复产物自检失败 → 1005。
    pub fn restore_backup(
        &self,
        backup_path: String,
        target_base_dir: String,
    ) -> Result<String, FfiError> {
        self.license_check(LicensedOp::ImportRestore)?;
        session_call(AssertUnwindSafe(|| {
            cf_exporter::restore_backup(Path::new(&backup_path), Path::new(&target_base_dir))
        }))
        .map(|dir| dir.to_string_lossy().into_owned())
    }
}

/// 密码强度评估实现（zxcvbn + feedback 文案；工厂与会话两处共用）。
fn strength_estimate_impl(candidate: &str) -> FfiStrengthEstimate {
    let estimate = zxcvbn::zxcvbn(candidate, &[]);
    let mut warnings = Vec::new();
    if let Some(fb) = estimate.feedback() {
        if let Some(w) = fb.warning() {
            warnings.push(w.to_string());
        }
        warnings.extend(fb.suggestions().iter().map(|s| s.to_string()));
    }
    FfiStrengthEstimate {
        score: estimate.score() as u8,
        warnings,
    }
}

impl CofferApp {
    /// 注入许可门禁（官方装配点，`docs/02` §10.5 方案 A）：cf-ffi-official
    /// 构造工厂后注入 cf-license 的 gate 实例，应用级写操作与后续
    /// [`Self::open_vault`] 创建的全部会话共用同一判定源。开源产物不
    /// 调用——默认 [`PermitAllGate`] 即「自编译 = 全功能免费版」契约
    /// （TC-GATE-10）。
    ///
    /// **刻意不进 `#[uniffi::export]`**：本方法是 Rust 装配 API 而非
    /// FFI 面，Swift 绑定不出现该符号（TC-BLD-02：公开产物无许可代码
    /// 路径的可扫描性）；UniFFI 也不支持 trait object 参数。装配期
    /// 约定构造后、首次写操作前注入；运行中更换 gate 仅供测试
    /// （TC-GATE-09）。
    pub fn set_license_gate(&self, gate: Arc<dyn LicenseGate>) {
        *self
            .license_gate
            .write()
            .unwrap_or_else(PoisonError::into_inner) = gate;
    }

    /// 当前 gate 快照（Arc 克隆，缩短读锁持有窗口）。
    fn license_gate_snapshot(&self) -> Arc<dyn LicenseGate> {
        self.license_gate
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// 应用级写操作的许可判定（`docs/03` §14.6 拒绝面：不经会话的
    /// create_vault / export_backup / restore_backup 在此收口）。
    fn license_check(&self, op: LicensedOp) -> Result<(), FfiError> {
        match self.license_gate_snapshot().check(op) {
            LicenseDecision::Allow => Ok(()),
            LicenseDecision::Deny(deny) => Err(match deny {
                LicenseDenial::TrialExpired => CfError::LicenseTrialExpiredWriteDenied,
                LicenseDenial::StateUnavailable => CfError::LicenseStateWriteDenied,
            }
            .into()),
        }
    }

    /// 注册表互斥锁守卫（poison 不扩散：会话状态本身可安全接管）。
    fn sessions_lock(&self) -> MutexGuard<'_, HashMap<String, Arc<VaultSession>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[uniffi::export]
impl VaultSession {
    /// 库 UUID（UUIDv7 文本）。
    pub fn vault_uuid(&self) -> String {
        self.inner.vault_uuid().to_string()
    }

    /// 库显示名（锁定时也可见）。
    pub fn display_name(&self) -> String {
        self.inner.display_name().to_owned()
    }

    /// 库工作目录。
    pub fn vault_dir(&self) -> String {
        self.inner.vault_dir().to_string_lossy().into_owned()
    }

    // -------------------------------------------------------- 生命周期

    /// 解锁：NFC 归一化 → Argon2id → DEK 解封 → verifier 校验。
    /// 密码错 / 数据篡改统一码 1002（FR-1.4）。
    pub fn unlock(&self, password: String) -> Result<FfiVaultInfo, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.unlock(&password))).map(Into::into)
    }

    /// 锁定：立即清零内存密钥（幂等）。
    pub fn lock(&self) {
        self.inner.lock();
    }

    /// 是否处于解锁态。
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// 记录最后活动时间（Unix 秒，平台事件驱动喂入）。
    pub fn set_last_activity(&self, unix_secs: i64) {
        self.inner.set_last_activity(unix_secs);
    }

    /// 设置空闲超时秒数（`<= 0` 禁用自动锁定）。
    pub fn set_idle_timeout_secs(&self, secs: i64) {
        self.inner.set_idle_timeout_secs(secs);
    }

    /// 超时则锁定；返回是否执行了锁定（Swift 定时器驱动）。
    pub fn auto_lock_if_expired(&self, now_secs: i64) -> bool {
        self.inner.auto_lock_if_expired(now_secs)
    }

    // ------------------------------------------------ 生物识别（docs/08）

    /// 是否启用 Touch ID 封装（header `biometric_wrap.available`，
    /// docs/08 D-1：语义 = 「用户意图开启」，锁定态可查）。纯读 header，
    /// 无密钥操作；供 LockView 决定是否显示 Touch ID 按钮。实际可用性
    /// 由 Swift 侧 Keychain 信号组合判定（docs/08 §8 降级矩阵）。
    pub fn has_biometric_wrap(&self) -> bool {
        self.inner.has_biometric_wrap()
    }

    /// 启用 Touch ID 解锁（docs/08 §4.1 enable，header 侧）。
    ///
    /// 门禁：需解锁态（锁定 → 1001）。传入主密码而非 DEK（D-6）：内部
    /// 经 `recover_dek` 重验证主密码并解出 DEK（错 → 1002，此时 header
    /// 未变）→ K_bio 封装 DEK → 原子重写 header。
    ///
    /// `k_bio` 必须为 32 字节（否则 5002，建议经
    /// [`CofferApp::new_biometric_unwrap_key`] 取得）。调用前 Swift 已把
    /// k_bio 写入 Keychain（先 Keychain 后 header，docs/08 §4.1）；
    /// 本方法返回 Err 时 header 保持原样，Swift 依据 Err 补偿删除
    /// Keychain 项。
    pub fn enable_biometric(&self, password: String, k_bio: Vec<u8>) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.enable_biometric(&password, &k_bio)
        }))
    }

    /// 关闭 Touch ID 解锁（docs/08 §4.1 disable，header 侧）。
    ///
    /// 门禁：需解锁态（1001）。原子重写 header → 禁用态；**幂等**——
    /// 已是禁用态时不重写文件。Keychain 项删除在 Swift 侧先行且幂等；
    /// 本方法失败非致命、可重试（docs/08 §8 降级矩阵）。
    pub fn disable_biometric(&self) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.disable_biometric()))
    }

    /// Touch ID 解锁后半段（docs/08 §6）。
    ///
    /// open(K_bio, aad=uuid‖b"wrapped_dek_bio", wrapped_dek_bio) → DEK →
    /// SubKeys → ItemStore——收尾与主密码 [`VaultSession::unlock`] 完全
    /// 共享；获得的会话与主密码路径同生共死（lock / 自动锁定清零，D-5）。
    ///
    /// # 错误（D-8）
    ///
    /// 未启用（`available == false`）→ 4001；k_bio 非 32 字节 → 5002；
    /// 其余失败（k_bio 不匹配 / 封装被篡改 / 跨库搬运）统一 1002。
    /// 4002（凭据已变更）**Rust 不产生**——发生在 Swift 侧 Keychain
    /// 读取，根本不到达 Rust。
    pub fn unlock_with_biometric(&self, k_bio: Vec<u8>) -> Result<FfiVaultInfo, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.unlock_with_biometric(&k_bio)
        }))
        .map(Into::into)
    }

    // ------------------------------------------------------ 条目 CRUD

    /// 列出条目（updated_at 倒序）；`filter` 传 `None` 为默认全量。
    pub fn list_items(
        &self,
        filter: Option<FfiItemFilter>,
    ) -> Result<Vec<FfiItemSummary>, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner
                .list_items(filter.map(cf_store::ItemListFilter::from))
        }))
        .map(|items| items.into_iter().map(Into::into).collect())
    }

    /// 读取条目完整详情（Concealed 字段值掩码，docs/07 §4.2）。
    pub fn get_item(&self, item_id: String) -> Result<Option<FfiItemDetails>, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.get_item(&item_id)))
            .map(|opt| opt.map(Into::into))
    }

    /// 创建条目，返回新条目 ID（UUIDv7 文本）。
    pub fn create_item(&self, draft: FfiItemDraft) -> Result<String, FfiError> {
        let draft = draft.to_domain()?;
        session_call(AssertUnwindSafe(|| self.inner.create_item(&draft)))
    }

    /// 更新条目（整体替换：fields / urls / tags 删旧插新；TOTP **默认
    /// 保留** —— FFI 不下发 secret，编辑无法重提交原密钥，默认删旧会
    /// 静默丢失 TOTP）。TOTP 三态显式控制走 [`VaultSession::update_item_with_totp`]。
    pub fn update_item(&self, item_id: String, draft: FfiItemDraft) -> Result<(), FfiError> {
        let draft = draft.to_domain()?;
        session_call(AssertUnwindSafe(|| {
            self.inner.update_item(&item_id, &draft)
        }))
    }

    /// 更新条目（TOTP 三态显式版）：`keep` 保留既有加密行 / `replace`
    /// 删旧插新 / `remove` 移除。draft 的 `totp` 字段在此路径被忽略。
    pub fn update_item_with_totp(
        &self,
        item_id: String,
        draft: FfiItemDraft,
        totp: FfiTotpUpdate,
    ) -> Result<(), FfiError> {
        let draft = draft.to_domain()?;
        let totp = totp.to_domain();
        session_call(AssertUnwindSafe(|| {
            self.inner.update_item_with_totp(&item_id, &draft, totp)
        }))
    }

    /// 删除条目：`hard = false` 进回收站，`hard = true` 级联硬删。
    pub fn delete_item(&self, item_id: String, hard: bool) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.delete_item(&item_id, hard)))
    }

    /// 从回收站恢复条目。
    pub fn restore_item(&self, item_id: String) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.restore_item(&item_id)))
    }

    /// 设置 / 取消收藏。
    pub fn set_favorite(&self, item_id: String, favorite: bool) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.set_favorite(&item_id, favorite)
        }))
    }

    /// 标题搜索（多关键词全命中，仅 Active 态；空查询返回空结果）。
    pub fn search(&self, query: String) -> Result<Vec<FfiItemSummary>, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.search(&query)))
            .map(|items| items.into_iter().map(Into::into).collect())
    }

    // ------------------------------------------------ 附件（FR-9.3 / 9.4）

    /// 列出条目附件（created_at 升序，FR-9.3）：需解锁态（锁定 → 1001）；
    /// 条目不存在 → 1011。元数据见 [`FfiAttachmentMeta`]，明文内容只经
    /// [`VaultSession::read_attachment`] 按需取（与字段值同纪律）。
    pub fn list_attachments(&self, item_id: String) -> Result<Vec<FfiAttachmentMeta>, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.list_attachments(&item_id)))
            .map(|infos| infos.into_iter().map(Into::into).collect())
    }

    /// 添加附件（FR-9.1）：`filename` 为 UTF-8 明文，`content` 为明文
    /// 内容（≤ 100 MiB，超限 → 1012）。只校验条目存在（1011），不限制
    /// 条目状态（docs/15 §3.1.2 边界声明）；同文件名不判重。锁定 → 1001。
    pub fn add_attachment(
        &self,
        item_id: String,
        filename: String,
        content: Vec<u8>,
    ) -> Result<FfiAttachmentMeta, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.add_attachment(&item_id, &filename, &content)
        }))
        .map(Into::into)
    }

    /// 读附件明文内容（FR-9.2，一次一个、即用即弃；整块 `Data` 返回）。
    /// 行不存在 → 1012；行在文件无 / 密文损坏 → 1005。锁定 → 1001。
    pub fn read_attachment(&self, attachment_uuid: String) -> Result<Vec<u8>, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.read_attachment(&attachment_uuid)
        }))
    }

    /// 删除附件（FR-9.2）：先删行后删文件；行不存在 → 1012。锁定 → 1001。
    pub fn remove_attachment(&self, attachment_uuid: String) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.remove_attachment(&attachment_uuid)
        }))
    }

    // ---------------------------------------------- 跨库复制（FR-2.10）

    /// 复制本会话条目到目标会话所在库（FR-2.10），返回目标库新条目
    /// uuid（UUIDv7 文本）。复制载荷含 TOTP / 标签 / 附件（附件文件落
    /// **目标库**目录）。
    ///
    /// 锁不双持由内核承担（FFI 层零锁逻辑）：`dst` 须来自同一
    /// [`CofferApp`] 注册表（UI 只能经 `list_vaults` + `open_vault`
    /// 获得，结构上满足）。错误：src 或 dst 锁定 → 1001；src 条目
    /// 不存在 → 1011；校验失败 → 5002（目标库零写入）。同库复制内核
    /// 允许（产生副本），UI 层禁止选择当前库。
    pub fn copy_item(&self, item_id: String, dst: Arc<VaultSession>) -> Result<String, FfiError> {
        session_call(AssertUnwindSafe(|| {
            cf_session::copy_item(&self.inner, &item_id, &dst.inner)
        }))
    }

    // ---------------------------------------------------- 取值与 TOTP

    /// 按需取字段明文值（密码等敏感值，随取随走，docs/07 §4.2）。
    /// 条目不存在返回 Err(1011)（ItemNotFound）；条目存在但字段不存在
    /// 返回 `None`（QA F-2：文档对齐实现，1011 语义保留）。
    pub fn get_field_value(
        &self,
        item_id: String,
        field_id: String,
    ) -> Result<Option<String>, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.get_field_value(&item_id, &field_id)
        }))
        .map(|opt| opt.map(|secret| secret.expose().to_owned()))
    }

    /// 生成条目当前 TOTP 验证码（共享密钥不出会话层）。
    pub fn totp_code(&self, item_id: String) -> Result<FfiTotpCode, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.totp_code(&item_id))).map(Into::into)
    }

    /// 读取条目 TOTP 元数据（**绝不含 secret**，编辑界面展示用）。
    ///
    /// 返回 algo / digits / period / issuer / account，供编辑界面展示
    /// 「已有 TOTP（SHA-1 · 6 位 · 30s）」并默认保留（见
    /// [`VaultSession::update_item_with_totp`]）。条目无 TOTP 记录 →
    /// `None`。
    pub fn totp_config(&self, item_id: String) -> Result<Option<FfiTotpMeta>, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.totp_config(&item_id)))
            .map(|opt| opt.map(Into::into))
    }

    /// 解析 otpauth:// URI（仅 SHA-1）；失败 → 码 1012。
    pub fn parse_otpauth_uri(&self, uri: String) -> Result<FfiTotpDraft, FfiError> {
        // parse_otpauth 是纯函数（无密钥材料、无共享状态），直接调用；
        // 错误统一为 Validation(1012) 语义
        let data: OtpauthData =
            cf_importer::csv::mapping::parse_otpauth(&uri).map_err(|reason| {
                FfiError::from(CfError::Validation(format!(
                    "invalid otpauth uri: {reason}"
                )))
            })?;
        Ok(data.into())
    }

    // ------------------------------------------------------- 生成器

    /// 生成随机密码（CSPRNG，参数见 [`FfiPasswordGenOptions`]）。
    pub fn generate_password(&self, opts: FfiPasswordGenOptions) -> Result<String, FfiError> {
        let opts = cf_audit::PasswordGenOptions::try_from(opts)?;
        cf_audit::generate_password(&opts)
            .map_err(|reason| FfiError::from(CfError::Validation(reason.to_owned())))
    }

    /// 生成密码短语（FR-3.3，EFF 词表不重复抽样；参数见
    /// [`FfiPassphraseOptions`]）。镜像 [`VaultSession::generate_password`]
    /// 的 Validation 映射：词数 3..=10、分隔符 1..=3 可打印字符，越界
    /// → 码 1012。纯计算，无解锁门禁（与 `generate_password` 同语义）。
    pub fn generate_passphrase(&self, opts: FfiPassphraseOptions) -> Result<String, FfiError> {
        let opts = cf_audit::PassphraseOptions::try_from(opts)?;
        cf_audit::generate_passphrase(&opts)
            .map_err(|reason| FfiError::from(CfError::Validation(reason.to_owned())))
    }

    /// 密码强度评估（zxcvbn 0–4 + 改进建议）。
    ///
    /// 与 [`CofferApp::strength_estimate`] 同语义（同一实现委托，见
    /// [`strength_estimate_impl`]）；保留于会话对象仅为兼容既有调用方，
    /// 无会话场景（建库界面）请走工厂版本。
    pub fn strength_estimate(&self, candidate: String) -> Result<FfiStrengthEstimate, FfiError> {
        Ok(strength_estimate_impl(&candidate))
    }

    // --------------------------------------------------------- 导入

    /// CSV 预检（只读、可反复调用；1Password 9 列，docs/07 §3）。
    pub fn precheck_csv(&self, path: String) -> Result<FfiCsvPrecheckReport, FfiError> {
        session_call(AssertUnwindSafe(|| {
            cf_importer::precheck_csv(Path::new(&path))
        }))
        .map(Into::into)
    }

    /// CSV 导入（单事务 all-or-nothing；锁定态 → 码 1001）。
    pub fn import_csv(&self, path: String) -> Result<FfiCsvImportResult, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.import_csv(Path::new(&path)))).map(Into::into)
    }

    /// 1PUX 预检（FR-7.4~7.7）：纯文件只读，可反复调用。
    ///
    /// **无解锁门禁**（锁定态可预检）——与 CSV 预检同语义：预检不接触
    /// 密钥材料，供导入向导在解锁前展示报告。
    pub fn precheck_1pux(&self, path: String) -> Result<FfiPuxPrecheckReport, FfiError> {
        session_call(AssertUnwindSafe(|| {
            cf_importer::precheck_1pux(Path::new(&path))
        }))
        .map(Into::into)
    }

    /// 1PUX 导入（FR-7.1 含 `files/` 附件；锁定态 → 码 1001）。
    ///
    /// 每条目单事务，任一条目失败回滚该条、已成功条目保留；附件密文落
    /// `<vault_dir>/attachments/`。返回值内的 `deletion_advice` 是对本次
    /// 导入报告即时组装的 FR-7.8 删源建议（D-6 数据驱动），Swift 侧
    /// 无需再调建议函数。
    pub fn import_1pux(&self, path: String) -> Result<FfiPuxImportResult, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.import_1pux(Path::new(&path))
        }))
        .map(Into::into)
    }

    // ---------------------------------------------------- 历史（FR-2.9）

    /// 条目历史版本列表（FR-2.9，version 倒序）：需解锁态（1001）。
    ///
    /// 快照明文不跨 FFI，仅返回 history_uuid / version / created_at
    /// 元数据（docs/09 §3.3 风险 ②）。条目不存在 → 码 1011。
    pub fn list_history(&self, item_id: String) -> Result<Vec<FfiHistoryEntry>, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.list_history(&item_id)))
            .map(|entries| entries.into_iter().map(Into::into).collect())
    }

    /// 历史回滚（FR-2.9）：以历史快照走正常 update 路径，回滚本身也是
    /// 一次修改（可再回滚）。需解锁态（1001）；条目 / 历史行不存在 →
    /// 1011；Trashed / Archived 条目被状态门禁拒绝 → 1012（内核行为）。
    pub fn restore_history(&self, item_id: String, history_uuid: String) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.restore_history(&item_id, &history_uuid)
        }))
    }

    // ------------------------------------------------- 体检（FR-6.7）

    /// 五类体检报告（FR-6.2 / 6.3 / 6.4 / 6.5 / 6.6 编排）：需解锁态
    /// （1001）。`now_secs` 由调用方注入（Unix 秒，与空闲自动锁定同
    /// 模式，可测试）；陈旧密码阈值取内核默认（365 天，AUD-04）。
    ///
    /// 报告只携带 item_id / 标题 / 非敏感元数据，不含密码明文。
    pub fn health_report(&self, now_secs: i64) -> Result<FfiHealthReport, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.health_report(now_secs))).map(Into::into)
    }

    // ------------------------------------------------------- 账户安全

    /// 修改主密码（FR-1.8，docs/09 §3.2 D-2：只重封装 header 的 DEK，
    /// 不重加密全库；bio 封装不受影响）。
    ///
    /// 门禁：需解锁态（锁定 → 1001）。流程：新密码 zxcvbn 门禁
    /// （< 3 → 1010，先于任何文件操作）→ 旧密码重验证（错 → 1002，
    /// header 未动）→ 新盐 + 新 KEK → 重封装 → `write_header` 原子重写。
    /// 任何失败磁盘 header 保持原样，旧密码仍可解锁。
    ///
    /// `new_kdf` 可选传入新 Argon2id 档位顺带升级（越界 → 5002）；
    /// `None` 沿用当前 header.kdf 参数。
    pub fn change_password(
        &self,
        old_password: String,
        new_password: String,
        new_kdf: Option<FfiKdfParams>,
    ) -> Result<(), FfiError> {
        let new_kdf = match new_kdf {
            Some(k) => Some(k.to_domain()?),
            None => None,
        };
        session_call(AssertUnwindSafe(|| {
            self.inner
                .change_password(&old_password, &new_password, new_kdf)
        }))
    }

    // ------------------------------------------------- 暴力退避（FR-12.5）

    /// 当前暴力退避门禁剩余秒数（FR-12.5；`0` = 无退避）。
    ///
    /// 同步只读旁路通道：门禁期内 `unlock` / `enable_biometric` /
    /// `change_password` 一律返回 1002（维持 FR-1.4 不可区分性），UI 的
    /// 倒计时显示只经本方法获取等待时间。与内核语义一致：内存级计数，
    /// 进程重启清零（设计裁决的接受限制）。
    pub fn backoff_remaining_secs(&self) -> u64 {
        self.inner.backoff_remaining_secs()
    }

    // -------------------------------------------- 剪贴板清除（FR-14.2）

    /// 设置剪贴板自动清除时间（FR-14.2）。
    ///
    /// 合法档位：10 / 30 / 60 / 120 秒，或 `0`（「从不」，与自动锁定
    /// 「从不」档语义一致）。非法值（含负数）→ 5002 且原配置不变。
    /// 会话级元配置：无解锁门禁、跨 `lock()` 存活（清除定时器由平台侧
    /// 执行）；档位列表经 [`clipboard_clear_tiers`](crate::clipboard_clear_tiers) 到 Swift 侧做
    /// UI 选择器。
    pub fn set_clipboard_clear_secs(&self, secs: i64) -> Result<(), FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.set_clipboard_clear_secs(secs)
        }))
    }

    /// 当前剪贴板自动清除时间（秒）；`0` 表示从不清除。
    pub fn clipboard_clear_secs(&self) -> i64 {
        self.inner.clipboard_clear_secs()
    }

    // --------------------------------------------------- 备份提醒（FR-8.5）

    /// 上次成功备份时间（Unix 秒；从未备份返回 `None`，FR-8.5）。
    ///
    /// 打点方为 [`CofferApp::export_backup`] 成功路径（写源库
    /// `meta.last_backup_at`），本方法只读。门禁：需解锁态（1001）。
    pub fn last_backup_at(&self) -> Result<Option<i64>, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.last_backup_at()))
    }

    /// 是否应提醒备份（FR-8.5，docs/09 §2.2）：从未备份，或距上次成功
    /// 备份 `>= threshold_secs` 秒 → 应提醒；`threshold_secs <= 0` 视为
    /// 禁用（永不提醒）。`now_secs` 由平台注入（与自动锁定同模式）。
    /// 门禁：需解锁态（1001）。
    pub fn should_suggest_backup(
        &self,
        threshold_secs: i64,
        now_secs: i64,
    ) -> Result<bool, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.should_suggest_backup(threshold_secs, now_secs)
        }))
    }

    // ------------------------------------------------- 导出与审计查询

    /// CSV 明文导出（FR-8.3；锁定态 → 1001）。
    ///
    /// **明文导出的二次确认（FR-8.4）是调用方 UI 门禁**：Swift 侧必须先
    /// 取得用户显式确认（UI 明示「导出文件为明文，包含全部密码」）才可
    /// 调用本方法——内核不提供也不应绕过该门禁（D-11 默认关闭）。
    pub fn export_csv(&self, out_path: String) -> Result<FfiCsvExportResult, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.export_csv(Path::new(&out_path))
        }))
        .map(Into::into)
    }

    /// 本地审计日志只读分页查询（FR-12.6；锁定态 → 1001）。
    ///
    /// 按时间倒序；`offset` / `limit` 语义与条目过滤一致（`None` 偏移
    /// 视为 0、`None` 上限不限量）。事件只由内核动作打点，本方法只读。
    pub fn recent_audit_events(
        &self,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<FfiAuditEntry>, FfiError> {
        session_call(AssertUnwindSafe(|| {
            self.inner.recent_audit_events(offset, limit)
        }))
        .map(|entries| entries.into_iter().map(Into::into).collect())
    }
}

/// 剪贴板自动清除的定时档位（FR-14.2）：`[10, 30, 60, 120]` 秒。
///
/// Swift 侧 UI 选择器数据源；「从不」档不入本表，以 `0` 表示
/// （见 [`validate_clipboard_clear_secs`](crate::validate_clipboard_clear_secs)）。
#[uniffi::export]
pub fn clipboard_clear_tiers() -> Vec<i64> {
    cf_session::vault::CLIPBOARD_CLEAR_TIERS_SECS.to_vec()
}

/// 剪贴板自动清除的默认档位（FR-14.2）：30 秒
/// （与 macOS 现行固定 30s 行为向后兼容）。
#[uniffi::export]
pub fn default_clipboard_clear_secs() -> i64 {
    cf_session::vault::DEFAULT_CLIPBOARD_CLEAR_SECS
}

/// 校验剪贴板自动清除档位（FR-14.2，Swift 选择器侧预校验）。
///
/// 合法值：10 / 30 / 60 / 120 秒，或 `0`（「从不」）；其余值（含负数）
/// → 5002。与 [`VaultSession::set_clipboard_clear_secs`] 同一校验实现。
///
/// # Errors
///
/// 非档位值 → `FfiError`（5002 InvalidArgument）。
#[uniffi::export]
pub fn validate_clipboard_clear_secs(secs: i64) -> Result<(), FfiError> {
    session_call(AssertUnwindSafe(|| {
        cf_session::vault::validate_clipboard_clear_secs(secs)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::kdf::KdfParams;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// 测试用快速 KDF 档位（8 MiB / t=1 / p=1，约几十毫秒）。
    fn fast_kdf() -> KdfParams {
        KdfParams::new(8 * 1024, 1, 1).unwrap()
    }

    /// 强密码（zxcvbn score ≥ 3，可过建库门禁）。
    const STRONG_PASSWORD: &str = "correct-horse-battery-staple-42!";

    /// 每测试独立的临时工作目录。
    fn temp_base(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cf-ffi-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 测试库：走 Rust 侧建库入口（可注入快速 KDF），FFI 侧负责打开/解锁。
    fn setup_vault(base: &Path, name: &str) -> cf_domain::vault::Vault {
        cf_session::create_vault_with_kdf(base, name, STRONG_PASSWORD, fast_kdf()).unwrap()
    }

    fn app() -> Arc<CofferApp> {
        CofferApp::new()
    }

    /// 错误码跨 FFI：密码错误 → Swift 捕获 code=1002，且会话保持锁定
    /// （docs/07 §7 T04 验收 ③ 后半）
    #[test]
    fn 错误密码跨ffi返回1002() {
        let base = temp_base("wrong_pw");
        let brief = setup_vault(&base, "错误密码库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        let err = session
            .unlock("wrong password indeed!".to_owned())
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(!session.is_unlocked());

        // 正确密码解锁成功
        let info = session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
        assert_eq!(info.display_name, "错误密码库");
        assert_eq!(info.item_count, 0);
    }

    /// 错误码跨 FFI：锁定态数据访问 → code=1001（门禁在 Rust 侧强制）
    #[test]
    fn 锁定态数据访问跨ffi返回1001() {
        let base = temp_base("locked");
        let brief = setup_vault(&base, "锁定库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        assert_eq!(session.list_items(None).unwrap_err().code(), 1001);
        assert_eq!(
            session
                .get_field_value("some-item".to_owned(), "some-field".to_owned())
                .unwrap_err()
                .code(),
            1001
        );
        assert_eq!(
            session
                .totp_code("some-item".to_owned())
                .unwrap_err()
                .code(),
            1001
        );
    }

    /// panic 不杀进程：FFI 层守卫把 panic 转为 code=5999 的错误
    /// （docs/07 §7 T04 验收 ④；机制与全部导出方法一致）
    #[test]
    fn ffi层panic注入转为错误码5999_进程存活() {
        let result = session_call(AssertUnwindSafe(|| -> cf_session::SessionResult<()> {
            panic!("模拟不变量破坏");
        }));
        let err = result.unwrap_err();
        assert_eq!(err.code(), 5999);
        assert!(matches!(err, FfiError::InternalPanic { .. }));
    }

    /// open_vault 幂等：同 uuid 两次 open 返回同一会话（解锁状态共享，
    /// lock_all 全部生效）——docs/07 §7 T04 验收 ⑤
    #[test]
    fn open_vault同uuid幂等_会话状态共享() {
        let base = temp_base("idempotent");
        let brief = setup_vault(&base, "幂等库");
        let base_str = base.to_string_lossy().into_owned();
        let app = app();

        let first = app
            .open_vault(base_str.clone(), brief.uuid.to_string())
            .unwrap();
        let second = app.open_vault(base_str, brief.uuid.to_string()).unwrap();
        assert!(!first.is_unlocked());

        // 经第一个引用解锁，第二个引用可见同一解锁态（同一实例）
        first.unlock(STRONG_PASSWORD.to_owned()).unwrap();
        assert!(second.is_unlocked());

        // lock_all 批量锁定，两个引用一致
        app.lock_all();
        assert!(!first.is_unlocked());
        assert!(!second.is_unlocked());

        // 注册表保留实例：再次 open 复用同一对象
        let third = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();
        assert!(!third.is_unlocked());
    }

    /// open_vault 非法 uuid → 码 5002（防路径拼接逃逸）
    #[test]
    fn open_vault非法uuid被拒绝() {
        let base = temp_base("bad_uuid");
        let app = app();
        let outcome = app.open_vault(base.to_string_lossy().into_owned(), "../escape".to_owned());
        let err = match outcome {
            Err(e) => e,
            Ok(_) => panic!("非法 uuid 应被拒绝"),
        };
        assert_eq!(err.code(), 5002);
    }

    /// 端到端冒烟：otpauth 解析 → 建条目（含 TOTP）→ 搜索 → 详情掩码
    /// → 按需取敏感值 → TOTP 验证码（docs/07 §7 T04 验收 ② 的 Rust 侧）
    #[test]
    fn 建条目搜索取敏感值全链路冒烟() {
        let base = temp_base("e2e");
        let brief = setup_vault(&base, "冒烟库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();
        session.unlock(STRONG_PASSWORD.to_owned()).unwrap();

        // otpauth URI 解析（FFI 返回草稿）
        let totp = session
            .parse_otpauth_uri(
                "otpauth://totp/GitHub:alice@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
                    .to_owned(),
            )
            .unwrap();
        assert_eq!(totp.issuer.as_deref(), Some("GitHub"));

        // 建条目：用户名 + 掩码密码 + TOTP
        let item_id = session
            .create_item(FfiItemDraft {
                title: "GitHub".to_owned(),
                category: FfiItemCategory::Login,
                urls: vec![FfiUrlDraft {
                    label: None,
                    url: "https://github.com".to_owned(),
                    is_primary: true,
                    position: 0,
                }],
                tags: vec!["dev".to_owned()],
                sections: Vec::new(),
                fields: vec![
                    FfiFieldDraft {
                        name: "用户名".to_owned(),
                        value: Some("alice".to_owned()),
                        field_type: FfiFieldType::Text,
                        designation: Some(FfiDesignation::Username),
                        section_index: None,
                        position: 0,
                    },
                    FfiFieldDraft {
                        name: "密码".to_owned(),
                        value: Some("p@ssw0rd-遇事不决!".to_owned()),
                        field_type: FfiFieldType::Concealed,
                        designation: Some(FfiDesignation::Password),
                        section_index: None,
                        position: 1,
                    },
                ],
                totp: Some(totp),
            })
            .unwrap();

        // 搜索命中
        let hits = session.search("git".to_owned()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "GitHub");
        assert_eq!(hits[0].category, FfiItemCategory::Login);

        // 详情掩码纪律：Concealed 字段 value 为 None，真实值单独按需取
        let details = session.get_item(item_id.clone()).unwrap().unwrap();
        assert_eq!(details.fields.len(), 2);
        // v0.1 已知边界：ItemDraft.totp 不含 issuer/account（TotpData 无此
        // 字段），入库的 TOTP 元数据只有 algo/digits/period
        let totp_meta = details.totp.as_ref().unwrap();
        assert_eq!(totp_meta.algo, "sha1");
        assert_eq!(totp_meta.digits, 6);
        assert_eq!(totp_meta.period, 30);
        let password_field = details
            .fields
            .iter()
            .find(|f| f.field_type == FfiFieldType::Concealed)
            .unwrap();
        assert_eq!(password_field.value, None, "Concealed 值必须掩码");

        let real = session
            .get_field_value(item_id.clone(), password_field.uuid.clone())
            .unwrap();
        assert_eq!(real.as_deref(), Some("p@ssw0rd-遇事不决!"));

        // TOTP 验证码：6 位数字 + 倒计时有效
        let code = session.totp_code(item_id).unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(code.secs_remaining > 0 && code.secs_remaining <= 30);
    }

    /// 编辑保留 TOTP 端到端（v0.2 三态语义）：update_item 默认 Keep →
    /// 编辑后 totp_config 元数据仍在、totp_code 仍可出码；随后三态
    /// 显式控制（Replace / Remove）逐一验证。
    #[test]
    fn 编辑保留totp后仍可出码() {
        let base = temp_base("totp_keep");
        let brief = setup_vault(&base, "保留库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();
        session.unlock(STRONG_PASSWORD.to_owned()).unwrap();

        // 建条目（含 TOTP）
        let totp = session
            .parse_otpauth_uri(
                "otpauth://totp/GitHub:alice@github.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
                    .to_owned(),
            )
            .unwrap();
        let item_id = session
            .create_item(FfiItemDraft {
                title: "GitHub".to_owned(),
                category: FfiItemCategory::Login,
                urls: Vec::new(),
                tags: Vec::new(),
                sections: Vec::new(),
                fields: vec![
                    FfiFieldDraft {
                        name: "用户名".to_owned(),
                        value: Some("alice".to_owned()),
                        field_type: FfiFieldType::Text,
                        designation: Some(FfiDesignation::Username),
                        section_index: None,
                        position: 0,
                    },
                    FfiFieldDraft {
                        name: "密码".to_owned(),
                        value: Some("p@ssw0rd!".to_owned()),
                        field_type: FfiFieldType::Concealed,
                        designation: Some(FfiDesignation::Password),
                        section_index: None,
                        position: 1,
                    },
                ],
                totp: Some(totp),
            })
            .unwrap();

        // 编辑（草稿不带 TOTP —— FFI 本就拿不到 secret）：默认保留
        let edited = FfiItemDraft {
            title: "GitHub 工作".to_owned(),
            category: FfiItemCategory::Login,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![
                FfiFieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice-work".to_owned()),
                    field_type: FfiFieldType::Text,
                    designation: Some(FfiDesignation::Username),
                    section_index: None,
                    position: 0,
                },
                FfiFieldDraft {
                    name: "密码".to_owned(),
                    value: Some("new-pass-42!".to_owned()),
                    field_type: FfiFieldType::Concealed,
                    designation: Some(FfiDesignation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        };
        session.update_item(item_id.clone(), edited).unwrap();

        // 元数据仍在（secret 永不下发，编辑界面据此展示「已有 TOTP」）
        let meta = session.totp_config(item_id.clone()).unwrap().unwrap();
        assert_eq!(meta.algo, "sha1");
        assert_eq!(meta.digits, 6);
        assert_eq!(meta.period, 30);
        // v0.1 已知边界：issuer/account 暂不采集入库（otpauth 解析随 T03）
        assert_eq!(meta.issuer, None);

        // 保留后仍可出码：原 secret 未被替换
        let code = session.totp_code(item_id.clone()).unwrap();
        assert_eq!(code.code.len(), 6);

        // Replace：粘贴新 URI → 元数据切换为 8 位（draft 的 totp 字段
        // 被忽略，以三态参数为准；必填字段照常提交）
        let new_totp = session
            .parse_otpauth_uri(
                "otpauth://totp/New:svc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"
                    .to_owned(),
            )
            .unwrap();
        let replace_draft = FfiItemDraft {
            title: "GitHub 工作".to_owned(),
            category: FfiItemCategory::Login,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![
                FfiFieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice-work".to_owned()),
                    field_type: FfiFieldType::Text,
                    designation: Some(FfiDesignation::Username),
                    section_index: None,
                    position: 0,
                },
                FfiFieldDraft {
                    name: "密码".to_owned(),
                    value: Some("new-pass-42!".to_owned()),
                    field_type: FfiFieldType::Concealed,
                    designation: Some(FfiDesignation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        };
        session
            .update_item_with_totp(
                item_id.clone(),
                replace_draft,
                FfiTotpUpdate::Replace { draft: new_totp },
            )
            .unwrap();
        let replaced = session.totp_config(item_id.clone()).unwrap().unwrap();
        assert_eq!(replaced.digits, 8, "Replace 后应切换为新配置");
        let replaced_code = session.totp_code(item_id.clone()).unwrap();
        assert_eq!(replaced_code.code.len(), 8);

        // Remove：显式移除 → 元数据消失
        let remove_draft = FfiItemDraft {
            title: "GitHub 工作".to_owned(),
            category: FfiItemCategory::Login,
            urls: Vec::new(),
            tags: Vec::new(),
            sections: Vec::new(),
            fields: vec![
                FfiFieldDraft {
                    name: "用户名".to_owned(),
                    value: Some("alice-work".to_owned()),
                    field_type: FfiFieldType::Text,
                    designation: Some(FfiDesignation::Username),
                    section_index: None,
                    position: 0,
                },
                FfiFieldDraft {
                    name: "密码".to_owned(),
                    value: Some("new-pass-42!".to_owned()),
                    field_type: FfiFieldType::Concealed,
                    designation: Some(FfiDesignation::Password),
                    section_index: None,
                    position: 1,
                },
            ],
            totp: None,
        };
        session
            .update_item_with_totp(item_id.clone(), remove_draft, FfiTotpUpdate::Remove)
            .unwrap();
        assert!(
            session.totp_config(item_id.clone()).unwrap().is_none(),
            "Remove 后 TOTP 应消失"
        );
    }

    // -------------------------------------------------- 生物识别（docs/08 T02）

    /// 4 接口跨 FFI 冒烟（docs/08 §9 T02 验收 ①）：两次
    /// `new_biometric_unwrap_key` 不同且 32B → enable（错密码 1002）→
    /// 正确密码 → hasBiometricWrap=true → lock → unlockWithBiometric 成功。
    #[test]
    fn bio四接口跨ffi冒烟() {
        let base = temp_base("bio_smoke");
        let brief = setup_vault(&base, "生物识别库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        // 工厂接口：32B 随机钥匙，两次调用不同（CSPRNG）
        let k_bio = app.new_biometric_unwrap_key().unwrap();
        assert_eq!(k_bio.len(), 32, "K_bio 必须是 32 字节（docs/08 D-3）");
        let k_bio_other = app.new_biometric_unwrap_key().unwrap();
        assert_ne!(k_bio, k_bio_other, "两次调用必须产生不同的随机数");

        // 未启用态：hasBiometricWrap=false
        assert!(!session.has_biometric_wrap());

        // 解锁（enable 的门禁要求解锁态）→ 错密码 enable → 1002 且 header 未变
        session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
        let err = session
            .enable_biometric("wrong password indeed!".to_owned(), k_bio.clone())
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(
            !session.has_biometric_wrap(),
            "错密码 enable 后 header 不得变更"
        );

        // 正确密码 enable → 意图位翻转
        session
            .enable_biometric(STRONG_PASSWORD.to_owned(), k_bio.clone())
            .unwrap();
        assert!(session.has_biometric_wrap());

        // 锁定 → bio 解锁成功（与主密码路径同收尾）
        session.lock();
        assert!(!session.is_unlocked());
        let info = session.unlock_with_biometric(k_bio).unwrap();
        assert_eq!(info.display_name, "生物识别库");
        assert_eq!(info.vault_uuid, brief.uuid.to_string());
        assert!(session.is_unlocked());
    }

    /// `available == false` 时调 `unlock_with_biometric` → 4001
    /// （docs/08 §9 T02 验收 ②；D-8：Rust 只产 4001，不产 4002）
    #[test]
    fn bio未启用时解锁跨ffi返回4001() {
        let base = temp_base("bio_unavailable");
        let brief = setup_vault(&base, "未启用库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        let k_bio = app.new_biometric_unwrap_key().unwrap();
        assert!(!session.has_biometric_wrap());
        let err = session.unlock_with_biometric(k_bio).unwrap_err();
        assert_eq!(err.code(), 4001);
        assert!(!session.is_unlocked(), "4001 后会话必须保持锁定");
    }

    /// k_bio 非 32 字节 → 5002（enable 与 unlock 双门禁，docs/08 §6）
    #[test]
    fn bio接口k_bio长度不符返回5002() {
        let base = temp_base("bio_len");
        let brief = setup_vault(&base, "长度库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        let short = vec![7u8; 16];
        session.unlock(STRONG_PASSWORD.to_owned()).unwrap();
        assert_eq!(
            session
                .enable_biometric(STRONG_PASSWORD.to_owned(), short.clone())
                .unwrap_err()
                .code(),
            5002
        );
        assert!(
            !session.has_biometric_wrap(),
            "长度门禁失败后 header 不得变更"
        );

        // 解锁路径的 4001（未启用）先于长度门禁（D-8 检查顺序），
        // 须先正确启用才能在 unlock 侧命中 5002
        let k_bio = app.new_biometric_unwrap_key().unwrap();
        session
            .enable_biometric(STRONG_PASSWORD.to_owned(), k_bio)
            .unwrap();
        session.lock();
        assert_eq!(
            session.unlock_with_biometric(short).unwrap_err().code(),
            5002
        );
    }

    /// 锁定态 enable / disable → 1001（门禁在 Rust 侧强制，docs/08 §6）
    #[test]
    fn bio接口锁定态门禁返回1001() {
        let base = temp_base("bio_locked");
        let brief = setup_vault(&base, "锁定门禁库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        let k_bio = app.new_biometric_unwrap_key().unwrap();
        assert_eq!(
            session
                .enable_biometric(STRONG_PASSWORD.to_owned(), k_bio.clone())
                .unwrap_err()
                .code(),
            1001
        );
        assert_eq!(session.disable_biometric().unwrap_err().code(), 1001);
        assert!(
            !session.has_biometric_wrap(),
            "锁定态门禁失败后 header 不得变更"
        );
    }

    /// panic 注入（新接口同守卫）→ 5999 不杀进程
    /// （docs/08 §9 T02 验收 ③；机制与全部导出方法一致）
    #[test]
    fn bio接口panic注入转为错误码5999_进程存活() {
        let result = session_call(AssertUnwindSafe(
            || -> cf_session::SessionResult<Vec<u8>> {
                panic!("模拟随机源不变量破坏");
            },
        ));
        let err = result.unwrap_err();
        assert_eq!(err.code(), 5999);
        assert!(matches!(err, FfiError::InternalPanic { .. }));
    }

    /// list_vaults 枚举：只读 header.json，损坏目录跳过不中断
    #[test]
    fn list_vaults枚举_损坏目录跳过() {
        let base = temp_base("list");
        let b1 = setup_vault(&base, "甲库");
        let b2 = setup_vault(&base, "乙库");

        // 伪装一个损坏库（空目录，open_container 必败）
        std::fs::create_dir_all(base.join("not-a-vault")).unwrap();
        std::fs::write(base.join("loose-file.txt"), b"junk").unwrap();

        let app = app();
        let briefs = app
            .list_vaults(base.to_string_lossy().into_owned())
            .unwrap();
        let names: Vec<&str> = briefs.iter().map(|b| b.display_name.as_str()).collect();
        assert_eq!(names, vec!["甲库", "乙库"]);
        assert_eq!(briefs[0].vault_uuid, b1.uuid.to_string());
        assert_eq!(briefs[1].vault_uuid, b2.uuid.to_string());

        // 不存在的工作目录 → 空列表（不是错误）
        let empty = app
            .list_vaults(base.join("no-such-dir").to_string_lossy().into_owned())
            .unwrap();
        assert!(empty.is_empty());
    }

    /// 生成器与强度评估跨 FFI：参数生成 + zxcvbn 分数 + 建库弱密码 1010
    #[test]
    fn 生成器与强度评估跨ffi() {
        let app = app();
        let base = temp_base("gen");
        let brief = setup_vault(&base, "生成器库");
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        let pw = session
            .generate_password(FfiPasswordGenOptions {
                length: 24,
                numbers: true,
                lowercase_letters: true,
                uppercase_letters: true,
                symbols: true,
                exclude_similar_characters: true,
            })
            .unwrap();
        assert_eq!(pw.chars().count(), 24);

        let weak = session.strength_estimate("123456".to_owned()).unwrap();
        assert!(weak.score < 3, "弱密码分数必须 < 3：{:?}", weak.warnings);

        let strong = session
            .strength_estimate(STRONG_PASSWORD.to_owned())
            .unwrap();
        assert!(strong.score >= 3);

        // 工厂版强度评估（无会话依赖）：与 会话版 同语义
        let factory_weak = app.strength_estimate("123456".to_owned()).unwrap();
        assert!(factory_weak.score < 3);
        let factory_strong = app.strength_estimate(STRONG_PASSWORD.to_owned()).unwrap();
        assert!(factory_strong.score >= 3);

        // 建库门禁跨 FFI：弱密码 → 码 1010
        let weak_base = temp_base("weak");
        let err = app
            .create_vault(
                weak_base.to_string_lossy().into_owned(),
                "弱密码库".to_owned(),
                "123456".to_owned(),
            )
            .unwrap_err();
        assert_eq!(err.code(), 1010);
    }

    /// FR-12.5 退避旁路跨 FFI：新会话无退避 → 0；连续 4 次错误密码触发
    /// 门禁 → 剩余秒数 > 0（UI 倒计时数据源，docs/09 §2 v0.2.0 Must）。
    ///
    /// 曲线（cf-session backoff）：第 3 次失败起延迟 `min(2^(n-3), 60)` 秒
    /// ——第 3 次 1s；门禁期内 unlock 直接 1002 且**不计数**，须等待期满
    /// 后第 4 次失败才设 2s 门禁。FFI 层无时钟注入（注入口仅内核测试可见），
    /// 以真实短暂 sleep 换取确定性。
    #[test]
    fn 退避剩余秒数跨ffi() {
        let base = temp_base("backoff");
        let brief = setup_vault(&base, "退避库");
        let app = app();
        let session = app
            .open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string())
            .unwrap();

        // 无失败记录：无门禁
        assert_eq!(session.backoff_remaining_secs(), 0, "新会话不应有退避");

        // 前 3 次错误密码 → 第 3 次失败设 1s 门禁（均为密码错误 1002）
        for _ in 0..3 {
            let err = session
                .unlock("wrong password indeed!".to_owned())
                .unwrap_err();
            assert_eq!(err.code(), 1002);
        }

        // 门禁期内第 4 次尝试被拒且不计数（1002），先等 1s 门禁期满
        std::thread::sleep(Duration::from_millis(1100));

        // 第 4 次失败 → 2s 门禁（2^(4-3)），旁路可查剩余秒数
        let err = session
            .unlock("wrong password indeed!".to_owned())
            .unwrap_err();
        assert_eq!(err.code(), 1002);
        assert!(
            session.backoff_remaining_secs() > 0,
            "第 4 次失败应触发 2s 门禁，剩余秒数必须 > 0"
        );
    }
}
