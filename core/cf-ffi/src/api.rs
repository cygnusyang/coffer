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

use cf_domain::CfError;
use cf_importer::OtpauthData;

use crate::error::FfiError;
use crate::types::*;
use crate::session_call;

/// 应用入口工厂：库的枚举 / 创建 / 打开，以及打开会话的注册表。
#[derive(uniffi::Object)]
pub struct CofferApp {
    /// 已打开会话注册表（key = vault uuid 文本）。持强引用防止 Swift 侧
    /// 意外提前释放导致密钥 drop（docs/07 §6.1 R-4）。
    sessions: Mutex<HashMap<String, Arc<VaultSession>>>,
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
        let uuid = uuid::Uuid::parse_str(&vault_uuid)
            .map_err(|_| FfiError::from(CfError::InvalidArgument(
                "vault_uuid is not a valid uuid".into(),
            )))?;
        let key = uuid.to_string();

        let mut map = self.sessions_lock();
        if let Some(existing) = map.get(&key) {
            return Ok(existing.clone());
        }

        let vault_dir = PathBuf::from(base_dir).join(&key);
        let session = session_call(AssertUnwindSafe(|| cf_session::open_vault(&vault_dir)))?;
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
    /// 注册表互斥锁守卫（poison 不扩散：会话状态本身可安全接管）。
    fn sessions_lock(&self) -> MutexGuard<'_, HashMap<String, Arc<VaultSession>>> {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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
        session_call(AssertUnwindSafe(|| self.inner.update_item(&item_id, &draft)))
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
        session_call(AssertUnwindSafe(|| self.inner.set_favorite(&item_id, favorite)))
    }

    /// 标题搜索（多关键词全命中，仅 Active 态；空查询返回空结果）。
    pub fn search(&self, query: String) -> Result<Vec<FfiItemSummary>, FfiError> {
        session_call(AssertUnwindSafe(|| self.inner.search(&query)))
            .map(|items| items.into_iter().map(Into::into).collect())
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
        let data: OtpauthData = cf_importer::csv::mapping::parse_otpauth(&uri).map_err(|reason| {
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
        session_call(AssertUnwindSafe(|| {
            self.inner.import_csv(Path::new(&path))
        }))
        .map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cf_crypto::kdf::KdfParams;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let dir = std::env::temp_dir().join(format!(
            "cf-ffi-{tag}-{}-{nanos}",
            std::process::id()
        ));
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

        let err = session.unlock("wrong password indeed!".to_owned()).unwrap_err();
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
            session.totp_code("some-item".to_owned()).unwrap_err().code(),
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

        let first = app.open_vault(base_str.clone(), brief.uuid.to_string()).unwrap();
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
        let third = app.open_vault(base.to_string_lossy().into_owned(), brief.uuid.to_string()).unwrap();
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
            .list_vaults(
                base.join("no-such-dir").to_string_lossy().into_owned(),
            )
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
}
