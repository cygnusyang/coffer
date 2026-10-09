//! Coffer 自家 Secret Store 数据源（feature `coffer-store`，docs/20 §4.5）。
//!
//! 依赖链 `cf-mcp → cf-session → cf-store`（单向，docs/20 §2.2 只下不上）。
//! 启用 `coffer-store` feature 后 workspace 依赖树新增 `cf-mcp → cf-session`
//! 边（docs/20 §9.2 互斥矩阵核对）。
//!
//! # 状态（2026-10-05 lead 裁定 #2）
//!
//! docs/20 §4.5 原稿「本版仅骨架、不实现」已被 lead 裁定覆盖：本文件以
//! **feature 门控生产实现**落地（`SecretProvider` 4 方法与 8 操作同语义映射
//! cf-store），但**不做** mcp_acceptance 23 条判据（那是门面 + test_seed 的
//! 验收面）。U-4（Secret/Environment/权限实体的正式存储模型）与 D-1~D-4 一起
//! 挂起，待用户 v2.0.0 最终汇报追认。
//!
//! ## 临时映射约定（U-4 落定前，**可逆、可整体替换**）
//!
//! Coffer 现有模型是 条目/字段（密码管理器），无 Secret / Environment / 权限
//! 实体。本实现用**已有实体 + 保留标签**承载，全部写在库内（真实持久化），
//! 语义与门面一致；U-4 落定后此映射整体替换为新实体，不残留脏数据：
//!
//! | 概念 | cf-store 载体 |
//! | --- | --- |
//! | Secret | 条目（标题 = secret 名；值 = `Designation::Password` 字段值，无则首个 Concealed，再无则首个有值字段） |
//! | Secret 伴随用户名 | `run_with_secret` 额外注入 `<ENV>_USERNAME` = `Designation::Username` 字段值（Email 兜底），无则不注入 |
//! | Secret id | 条目 uuid |
//! | Environment | `SecureNote` 条目 + 保留标签 [`ENV_TAG`]（字段 = `NAME`/`VALUE` 对） |
//! | allowed_agents | secret 条目上的保留标签 [`AGENT_TAG_PREFIX`]`<agent>` |
//! | 最后轮换时间 | secret 条目上的保留标签 [`ROTATED_TAG_PREFIX`]`<unix>` |
//!
//! 标签即数据：移除标签即撤消约定，不产生孤儿行，也不改变条目的类别/字段，
//! 因此**可逆**。轮换新值用 Coffer 生成器强随机值（`cf_audit::generate_password`
//! 默认档，MEDIUM-2，docs/27 裁定 B），不再用可预测时间戳 nonce。
//!
//! ## 不变量
//!
//! - 冻结契约不动：`SecretProvider` 4 方法签名、7xxx 错误码零新增（错误映射
//!   复用既有码：1001 锁态 → 7002，1011 无条目 → 7003，1012/5002 → 7005，
//!   其余 → 7006）；
//! - 值永不出 trait 面：`run_with_secret` 把值直接注入子进程 env，cf-mcp
//!   进程内不持有（与 §4.1 不变量一致）；
//! - 环境容器条目不出现在 secret 清单（`list_secret_names` / `list_secrets`
//!   排除 [`ENV_TAG`] 条目）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use cf_audit::{generate_password, PasswordGenOptions};
use cf_domain::category::ItemCategory;
use cf_domain::field::{Designation, FieldType};
use cf_domain::item::{FieldDraft, ItemDraft, ItemState, ItemSummary, SectionDraft, UrlDraft};
use cf_domain::secret::SecretString;
use cf_domain::CfError;
use cf_session::types::ItemDetails;
use cf_session::{open_vault, VaultSession};

use crate::provider::{is_valid_env_name, ProviderError, RunSpec, SecretMeta, SecretProvider};

/// 标记环境容器条目的保留标签（U-4 落定前约定，见模块文档）。
const ENV_TAG: &str = "coffer:environment";
/// 允许代理保留标签前缀（完整 = 前缀 + 代理名）。
const AGENT_TAG_PREFIX: &str = "coffer:agent:";
/// 最后轮换时间保留标签前缀（完整 = 前缀 + unix 秒）。
const ROTATED_TAG_PREFIX: &str = "coffer:rotated:";
/// UUIDv7 文本长度（36，含连字符）；命中即按条目 id 直查，否则按标题匹配。
const UUID_REF_LEN: usize = 36;

/// Coffer 自家库 provider（docs/20 §4.5，feature `coffer-store` 门控生产实现）。
///
/// 持有一个 [`cf_session::VaultSession`]（解锁态门禁 1001 复用）；构造见
/// [`Self::open`]（开库 + 解锁）或 [`Self::new`]（调用方已解锁后移交）。
///
/// 不 derive `Debug`：`VaultSession` 未实现 `Debug`（注册表亦不要求）。
pub struct CofferStoreProvider {
    /// 主 App 会话（解锁态门禁，1001 复用）。
    session: VaultSession,
}

impl CofferStoreProvider {
    /// 打开并解锁库（KDF 秒级），构造可用 provider。
    ///
    /// 库缺失 / 版本不受支持 → [`ProviderError::Unavailable`]；解锁失败 /
    /// 密码错误 → [`ProviderError::AuthRequired`]。
    pub fn open(vault_dir: &Path, password: &str) -> Result<Self, ProviderError> {
        let session = open_vault(vault_dir).map_err(|e| match e {
            CfError::VaultNotFound | CfError::UnsupportedFormat(_) => {
                ProviderError::Unavailable(format!("cannot open vault: {e}"))
            }
            other => map_session_err(other),
        })?;
        session.unlock(password).map_err(map_session_err)?;
        Ok(Self { session })
    }

    /// 由已解锁会话构造（调用方负责 `open_vault` + `unlock`）。
    #[must_use]
    pub fn new(session: VaultSession) -> Self {
        Self { session }
    }

    /// 库 UUID 文本（`SecretMeta.vault` 用）。
    fn vault_id(&self) -> String {
        self.session.vault_uuid().to_string()
    }

    /// 可见条目摘要（Active 态，全量）。
    fn active_items(&self) -> Result<Vec<ItemSummary>, ProviderError> {
        let items = self.session.list_items(None).map_err(map_session_err)?;
        Ok(items
            .into_iter()
            .filter(|i| i.state == ItemState::Active)
            .collect())
    }

    /// 摘要条目是否为环境容器（SecureNote + 保留标签；摘要无 tags，需查详情）。
    fn is_env_item(&self, s: &ItemSummary) -> Result<bool, ProviderError> {
        if s.category != ItemCategory::SecureNote {
            return Ok(false);
        }
        let d = self
            .session
            .get_item(&s.uuid.to_string())
            .map_err(map_session_err)?;
        Ok(d.map(|d| Self::is_env_details(&d)).unwrap_or(false))
    }

    /// 详情条目是否带环境容器保留标签。
    ///
    /// `pub(crate)`：`set_password` 复用同界（环境容器不写密码，docs/34 §5）。
    pub(crate) fn is_env_details(d: &ItemDetails) -> bool {
        d.tags.iter().any(|t| t.expose() == ENV_TAG)
    }

    /// 解析 secret_ref（uuid 或标题）→ 可见 secret 条目（环境容器除外）。
    ///
    /// 空 → [`ProviderError::InvalidParameter`]；不可解析 / 命中环境容器 →
    /// [`ProviderError::NotFound`]。
    fn resolve_secret(&self, secret_ref: &str) -> Result<ItemDetails, ProviderError> {
        let secret_ref = secret_ref.trim();
        if secret_ref.is_empty() {
            return Err(ProviderError::InvalidParameter("empty secret ref".into()));
        }
        // UUID 形态（UUIDv7 文本）：直接按 id 读。
        if secret_ref.len() == UUID_REF_LEN && secret_ref.contains('-') {
            if let Some(d) = self.session.get_item(secret_ref).map_err(map_session_err)? {
                if Self::is_env_details(&d) {
                    return Err(ProviderError::NotFound(format!(
                        "secret not found: {secret_ref}"
                    )));
                }
                return Ok(d);
            }
            return Err(ProviderError::NotFound(format!(
                "secret not found: {secret_ref}"
            )));
        }
        // 标题精确匹配（Active 可见条目，首个命中；环境容器跳过）。
        for s in self.active_items()? {
            if s.title == secret_ref && !self.is_env_item(&s)? {
                if let Some(d) = self
                    .session
                    .get_item(&s.uuid.to_string())
                    .map_err(map_session_err)?
                {
                    return Ok(d);
                }
            }
        }
        Err(ProviderError::NotFound(format!(
            "secret not found: {secret_ref}"
        )))
    }

    /// 解析环境容器条目（必须带保留标签）。
    ///
    /// 空 → [`ProviderError::InvalidParameter`]；未命中 → [`ProviderError::NotFound`]。
    fn resolve_env(&self, env: &str) -> Result<ItemDetails, ProviderError> {
        let env = env.trim();
        if env.is_empty() {
            return Err(ProviderError::InvalidParameter(
                "empty environment name".into(),
            ));
        }
        for s in self.active_items()? {
            if s.title == env && self.is_env_item(&s)? {
                if let Some(d) = self
                    .session
                    .get_item(&s.uuid.to_string())
                    .map_err(map_session_err)?
                {
                    return Ok(d);
                }
            }
        }
        Err(ProviderError::NotFound(format!(
            "environment not found: {env}"
        )))
    }

    /// 环境是否已存在（未命中 → `false`，与「不存在」同语义）。
    fn environment_exists(&self, name: &str) -> Result<bool, ProviderError> {
        match self.resolve_env(name) {
            Ok(_) => Ok(true),
            Err(ProviderError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 条目明文值：`Designation::Password` 字段 → 首个 Concealed → 首个有值字段。
    ///
    /// 返回借用（`SecretString` 非 `Clone`，避免为取值产生多余副本）；无值字段
    /// 返回 `None`（调用方按「不注入该 env」处理，与门面 ANON 同语义）。
    fn secret_value(d: &ItemDetails) -> Option<&SecretString> {
        d.fields
            .iter()
            .find(|f| f.designation == Some(Designation::Password) && f.value.is_some())
            .or_else(|| {
                d.fields
                    .iter()
                    .find(|f| f.field_type == FieldType::Concealed && f.value.is_some())
            })
            .or_else(|| d.fields.iter().find(|f| f.value.is_some()))
            .and_then(|f| f.value.as_ref())
    }

    /// 条目登录用户名：`Designation::Username` 字段 → `Designation::Email` 兜底 → 无。
    ///
    /// 与 [`Self::secret_value`] 同构的借用解析，供 `run_with_secret` 的伴随注入
    /// （`<ENV>_USERNAME`）使用。仅认显式 designation 的字段——纯 Text 字段
    /// （如环境容器的 NAME/VALUE 对）不参与，避免误注入。
    fn username_value(d: &ItemDetails) -> Option<&SecretString> {
        d.fields
            .iter()
            .find(|f| f.designation == Some(Designation::Username) && f.value.is_some())
            .or_else(|| {
                d.fields
                    .iter()
                    .find(|f| f.designation == Some(Designation::Email) && f.value.is_some())
            })
            .and_then(|f| f.value.as_ref())
    }
}

impl SecretProvider for CofferStoreProvider {
    fn list_secret_names(&self, _vault: Option<&str>) -> Result<Vec<String>, ProviderError> {
        // 单库会话：忽略 vault 过滤（未来多库时按 vault 名过滤）。
        let mut names = Vec::new();
        for s in self.active_items()? {
            if !self.is_env_item(&s)? {
                names.push(s.title);
            }
        }
        Ok(names)
    }

    fn list_secrets(&self, _vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError> {
        let mut metas = Vec::new();
        for s in self.active_items()? {
            if self.is_env_item(&s)? {
                continue;
            }
            metas.push(SecretMeta {
                name: s.title.clone(),
                id: s.uuid.to_string(),
                vault: self.vault_id(),
                category: s.category.as_str().to_string(),
                updated_at: Some(s.updated_at),
            });
        }
        Ok(metas)
    }

    fn get_secret_metadata(&self, secret_ref: &str) -> Result<SecretMeta, ProviderError> {
        let d = self.resolve_secret(secret_ref)?;
        Ok(SecretMeta {
            name: d.title.expose().to_string(),
            id: d.uuid.clone(),
            vault: self.vault_id(),
            category: d.category.as_str().to_string(),
            updated_at: Some(d.updated_at),
        })
    }

    fn run_with_secret(&self, spec: &RunSpec) -> Result<i32, ProviderError> {
        if spec.secret_ref.is_empty() {
            return Err(ProviderError::InvalidParameter("empty secret ref".into()));
        }
        if spec.cmd.is_empty() {
            return Err(ProviderError::InvalidParameter("empty command".into()));
        }
        // env_name 合法性（MEDIUM-1）：与 op 路径同源校验（provider/mod.rs
        // `is_valid_env_name`），`=`/换行/NUL 等非法名在 spawn 前拒收（7005）——
        // 两 provider 校验对称，纵深防御（MCP tools/call 可达）。
        if !is_valid_env_name(&spec.env_name) {
            return Err(ProviderError::InvalidParameter(
                "env_name is not a valid environment variable name".to_string(),
            ));
        }
        let item = self.resolve_secret(&spec.secret_ref)?;
        let value = Self::secret_value(&item);
        let mut cmd = Command::new(&spec.cmd);
        cmd.args(&spec.args);
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        // 注入值只在 SecretString 生命周期内存在（ZeroizeOnDrop），用后即毁。
        if let Some(v) = value {
            cmd.env(&spec.env_name, v.expose());
        }
        // 伴随用户名注入（v2.5.0，MCP 取密语义补全）：条目带 `Designation::Username`
        // （或 Email 兜底）字段时，额外注入 `<ENV>_USERNAME`，供 agent 全自动登录
        // 使用。无该字段则不注入——与主值「无则不注入」同语义。派生名随主名校验，
        // 非法即跳过（防御式，合法 env_name 派生出的名字恒合法）。
        if let Some(u) = Self::username_value(&item) {
            let user_env = format!("{}_USERNAME", spec.env_name);
            if is_valid_env_name(&user_env) {
                cmd.env(&user_env, u.expose());
            }
        }
        let status = cmd.status().map_err(|e| ProviderError::SubprocessFailed {
            exit_code: None,
            detail: format!("failed to spawn {}: {e}", spec.cmd),
        })?;
        Ok(status.code().unwrap_or(255))
    }
}

impl CofferStoreProvider {
    /// 列出现有环境名（U-4 落定前 = SecureNote + 保留标签条目，见模块文档）。
    pub fn list_environments(&self) -> Result<Vec<String>, ProviderError> {
        let mut envs = Vec::new();
        for s in self.active_items()? {
            if self.is_env_item(&s)? {
                envs.push(s.title);
            }
        }
        Ok(envs)
    }

    /// 创建环境容器（SecureNote + [`ENV_TAG`] 标签）。
    ///
    /// 空名 → [`ProviderError::InvalidParameter`]；重名 → 同样
    /// [`ProviderError::InvalidParameter`]（与门面 duplicate 语义一致）。
    pub fn create_environment(&self, name: &str) -> Result<(), ProviderError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ProviderError::InvalidParameter(
                "empty environment name".into(),
            ));
        }
        if self.environment_exists(name)? {
            return Err(ProviderError::InvalidParameter(format!(
                "environment already exists: {name}"
            )));
        }
        let draft = ItemDraft {
            title: name.to_string(),
            category: ItemCategory::SecureNote,
            urls: Vec::new(),
            tags: vec![ENV_TAG.to_string()],
            sections: Vec::new(),
            fields: Vec::new(),
            totp: None,
        };
        self.session.create_item(&draft).map_err(map_session_err)?;
        Ok(())
    }

    /// 挂载环境到目录（cf-store 无挂载实体；语义 = 创建目标目录，与门面一致）。
    ///
    /// 空参数 → [`ProviderError::InvalidParameter`]；未知环境 →
    /// [`ProviderError::NotFound`]（AS-5 模式 C：环境须先创建）；目录创建失败 →
    /// [`ProviderError::Internal`]。
    pub fn mount_environment(&self, env: &str, path: &str) -> Result<(), ProviderError> {
        let env = env.trim();
        if env.is_empty() {
            return Err(ProviderError::InvalidParameter(
                "empty environment name".into(),
            ));
        }
        let path = path.trim();
        if path.is_empty() {
            return Err(ProviderError::InvalidParameter("empty mount path".into()));
        }
        if !self.environment_exists(env)? {
            return Err(ProviderError::NotFound(format!(
                "environment not found: {env}"
            )));
        }
        std::fs::create_dir_all(path)
            .map_err(|e| ProviderError::Internal(format!("create_dir_all({path}): {e}")))?;
        Ok(())
    }

    /// 将环境条目字段（`NAME`/`VALUE` 对）注入当前进程 env（子进程继承）。
    ///
    /// 未知环境 → [`ProviderError::NotFound`]；空字段名跳过（无对应门面报错
    /// 路径——门面按 `NAME=VALUE` 文本解析，本实现在结构内天然无畸形形态）。
    pub fn inject_environment(&self, env: &str) -> Result<(), ProviderError> {
        let item = self.resolve_env(env)?;
        for f in &item.fields {
            let key = f.name.expose().trim();
            if key.is_empty() {
                continue;
            }
            let val = f.value.as_ref().map(SecretString::expose).unwrap_or("");
            std::env::set_var(key, val);
        }
        Ok(())
    }

    /// 授权：为 secret 条目打 [`AGENT_TAG_PREFIX`]`<agent>` 标签（幂等）。
    ///
    /// 空参数 → [`ProviderError::InvalidParameter`]；未知 secret →
    /// [`ProviderError::NotFound`]；已授权 → 直接 `Ok`（不改写，无副作用）。
    pub fn grant_secret(&self, secret: &str, agent: &str) -> Result<(), ProviderError> {
        let item = self.resolve_secret(secret)?;
        let agent = agent.trim();
        if agent.is_empty() {
            return Err(ProviderError::InvalidParameter("empty agent name".into()));
        }
        let tag = agent_tag(agent);
        if item.tags.iter().any(|t| t.expose() == tag) {
            return Ok(());
        }
        let mut draft = draft_from_details(&item);
        draft.tags.push(tag);
        self.session
            .update_item(&item.uuid, &draft)
            .map_err(map_session_err)?;
        Ok(())
    }

    /// 撤销授权：移除 [`AGENT_TAG_PREFIX`]`<agent>` 标签（幂等）。
    ///
    /// 空参数 → [`ProviderError::InvalidParameter`]；未知 secret →
    /// [`ProviderError::NotFound`]；未授权 → 直接 `Ok`（移除不存在即成功）。
    pub fn revoke_secret(&self, secret: &str, agent: &str) -> Result<(), ProviderError> {
        let item = self.resolve_secret(secret)?;
        let agent = agent.trim();
        if agent.is_empty() {
            return Err(ProviderError::InvalidParameter("empty agent name".into()));
        }
        let tag = agent_tag(agent);
        let mut draft = draft_from_details(&item);
        draft.tags.retain(|t| t != &tag);
        self.session
            .update_item(&item.uuid, &draft)
            .map_err(map_session_err)?;
        Ok(())
    }

    /// 轮换：改写条目值为新值，并刷新 [`ROTATED_TAG_PREFIX`] 时间戳标签。
    ///
    /// 改写目标与读取约定一致：`Designation::Password` → 首个 Concealed →
    /// 首个有值字段。条目无任何有值字段 → [`ProviderError::InvalidParameter`]
    /// （无值可轮换）。未知 secret → [`ProviderError::NotFound`]。
    pub fn rotate_secret(&self, secret: &str) -> Result<(), ProviderError> {
        let item = self.resolve_secret(secret)?;
        let mut draft = draft_from_details(&item);
        let new_value = rotated_value()?;
        let mut rotated = false;
        for f in &mut draft.fields {
            if f.designation == Some(Designation::Password) {
                f.value = Some(new_value.clone());
                rotated = true;
                break;
            }
        }
        if !rotated {
            for f in &mut draft.fields {
                if f.field_type == FieldType::Concealed {
                    f.value = Some(new_value.clone());
                    rotated = true;
                    break;
                }
            }
        }
        if !rotated {
            for f in &mut draft.fields {
                if f.value.is_some() {
                    f.value = Some(new_value.clone());
                    rotated = true;
                    break;
                }
            }
        }
        if !rotated {
            return Err(ProviderError::InvalidParameter(format!(
                "secret has no value to rotate: {}",
                item.uuid
            )));
        }
        let now_secs = unix_now_secs();
        draft.tags.retain(|t| !t.starts_with(ROTATED_TAG_PREFIX));
        draft.tags.push(format!("{ROTATED_TAG_PREFIX}{now_secs}"));
        self.session
            .update_item(&item.uuid, &draft)
            .map_err(map_session_err)?;
        Ok(())
    }

    /// 审计：校验 secret 可解析（语义同门面——仅校验，无副作用；真实审计
    /// 轨迹在工具层记录，D-3 未定）。未知 secret →
    /// [`ProviderError::NotFound`]；空名 → [`ProviderError::InvalidParameter`]。
    pub fn audit_secret_usage(&self, secret: &str) -> Result<(), ProviderError> {
        let _ = self.resolve_secret(secret)?;
        Ok(())
    }
}

// 测试子模块独立成文件（coffer/tests.rs），控制本文件行数（编码风格：<800）。
#[cfg(test)]
mod tests;

/// `CfError` → `ProviderError`（复用既有 7xxx 码，零新增）。
fn map_session_err(e: CfError) -> ProviderError {
    match e {
        // 1001：锁态 = 需身份解锁 → 7002。
        CfError::VaultLocked => {
            ProviderError::AuthRequired("vault is locked; unlock required".into())
        }
        // 1002：解锁失败 = 身份校验失败 → 7002。
        CfError::UnlockFailed => ProviderError::AuthRequired("vault unlock failed".into()),
        // 1003：库不存在 → 7001（provider 不可用）。
        CfError::VaultNotFound => ProviderError::Unavailable("vault not found".into()),
        // 1011：条目不存在 → 7003。
        CfError::ItemNotFound => ProviderError::NotFound("secret not found".into()),
        // 1012 / 5002：校验 / 参数错误 → 7005。
        CfError::Validation(m) | CfError::InvalidArgument(m) => ProviderError::InvalidParameter(m),
        // 其余（1005 损坏 / 存储错误等）→ 7006，不泄露细节。
        other => ProviderError::Internal(other.to_string()),
    }
}

/// `coffer:agent:<agent>` 标签。
fn agent_tag(agent: &str) -> String {
    format!("{AGENT_TAG_PREFIX}{agent}")
}

/// 轮换新值（MEDIUM-2，docs/27 裁定 B）：Coffer 生成器强随机值，按
/// `PasswordGenOptions::default()` 默认档（20 位、四类字符齐全、排除易混淆字符，
/// CSPRNG 后端，cf-audit/lib.rs:86-98）。生成失败静态不可达（默认参数恒合法），
/// 仍显式映射 [`ProviderError::Internal`]（7006，不静默降级、不 unwrap）。
fn rotated_value() -> Result<String, ProviderError> {
    generate_password(&PasswordGenOptions::default())
        .map_err(|reason| ProviderError::Internal(format!("password generation failed: {reason}")))
}

/// 当前 unix 秒（标签时间戳用）。
fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `ItemDetails` → `ItemDraft`（grant/revoke/rotate 的读-改-写重建；
/// `pub(crate)`：`set_password` 复用同一整换重建，docs/34 §5）。
///
/// `update_item` 是整换语义（fields/urls/tags/sections 删旧插新），重建须
/// 还原全量字段，否则丢数据。TOTP 恒传 `None`——`update_item` 默认
/// `TotpUpdate::Keep`，不会丢既有 TOTP（docs/08 §6 拆分裁定）。
pub(crate) fn draft_from_details(d: &ItemDetails) -> ItemDraft {
    ItemDraft {
        title: d.title.expose().to_string(),
        category: d.category,
        urls: d
            .urls
            .iter()
            .map(|u| UrlDraft {
                label: u.label.as_ref().map(|s| s.expose().to_string()),
                url: u.url.expose().to_string(),
                is_primary: u.is_primary,
                position: u.position as i32,
            })
            .collect(),
        tags: d.tags.iter().map(|t| t.expose().to_string()).collect(),
        sections: d
            .sections
            .iter()
            .map(|s| SectionDraft {
                title: s.title.expose().to_string(),
                position: s.position as i32,
            })
            .collect(),
        fields: d
            .fields
            .iter()
            .map(|f| FieldDraft {
                name: f.name.expose().to_string(),
                value: f.value.as_ref().map(|v| v.expose().to_string()),
                field_type: f.field_type,
                designation: f.designation.clone(),
                section_index: f
                    .section_uuid
                    .as_ref()
                    .and_then(|suid| d.sections.iter().position(|s| &s.uuid == suid)),
                position: f.position as i32,
            })
            .collect(),
        totp: None,
    }
}
