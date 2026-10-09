//! `coffer set-password` 子命令（docs/34 §5，FR-18.2，v2.5.0 写面）。
//!
//! 行为（docs/34 §5.2 / §3 纪律）：
//!
//! 1. 条目定位：display name 精确匹配优先（未命中 / 歧义 → 明确报错，**不写库**，
//!    非零退出）；`--id <UUID>` 按 UUID 定位兜底；
//! 2. 取密链（与 `coffer mcp` 同构，D-4）：MCP 解锁托管（escrow）→
//!    `COFFER_VAULT_PASSWORD` env 兜底 → 都无 **fail-closed 退出 1**——
//!    复用 [`crate::cli::unlock_vault`]，不重复造轮子；
//! 3. 强度门禁：zxcvbn ≥ 强（= 3 分，与 App `PasswordStrength` 同款阈值，
//!    `cf_audit::meets_strength_threshold`），弱密码拒绝并给引导；`--force` 绕过
//!    （用户 2026-10-09 批准保留，docs/34 §3）；
//! 4. 更新：复用 cf-store 既有 item update 路径（`VaultSession::update_item`）+
//!    自动 append 历史（FR-2.9，内容无变化不写——`update_item` 内建语义）；
//! 5. **密码绝不进 argv / 不进日志 / 不进进程列表可见**（stdin 取密，TTY 隐藏
//!    输入；临时缓冲用后 zeroize）。
//!
//! 目标字段语义（与 App `UpdatePassword.passwordField` / `ItemDetailView.hasPasswordField`
//! 门禁对齐，docs/34 §4.2「仅改密码字段」）：**仅** `Designation::Password` 字段可写；
//! 无该字段 → 报错不写库（退出 2）。**不做 `Concealed` 兜底**——无 Password 标注的
//! Concealed 字段（信用卡 CVV / 软件许可证 key 等）不是密码，回写会破坏数据（H-1，
//! lead 审查 2026-10-10）；也不回落到任意有值字段，避免误改用户名等。环境容器条目
//! （SecureNote + `coffer:environment` 标签）拒绝写密码（与 MCP provider 的 secret
//! 解析同界）。
//!
//! stdout 只写成功消息（本子命令非协议会话）；诊断/错误经 [`Logger`] 走 stderr。
//! 退出码（docs/34 §5.2 + r0.4，lead 裁定 2026-10-09；一次性写命令专用映射，**不复用**
//! docs/20 §5.3 的 MCP 服务器进程码——长驻服务器语义不适用）：
//! `0` 成功（更新 + 历史 append）；`1` 解锁失败 fail-closed（escrow 与 env 均无 /
//! escrow 存在但解锁失败不回落 env / vault 定位失败）；`2` 条目未命中或歧义
//! （1011 语义，歧义提示 `--id`）；`3` 强度不足拒绝（1010 语义，`--force` 绕过）；
//! `4` 参数/用法错误（未知 flag / 缺条目名 / `--id` 格式错）。stderr 文案按各类别
//! 给引导。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, IsTerminal, Write};

use cf_domain::field::Designation;
use cf_domain::item::{ItemDraft, ItemState, ItemSummary};
use cf_domain::secret::SecretString;
use cf_session::types::ItemDetails;
use cf_session::VaultSession;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::cli::Logger;
use crate::provider::escrow::VaultEscrowStore;

/// 一次性写命令退出码（docs/34 §5.2 + r0.4，lead 裁定 2026-10-09）——`set-password` 专用，
/// 不复用 [`crate::cli::exit_code`] 的 MCP 服务器进程码（长驻服务器语义，docs/20 §5.3）。
pub mod exit_codes {
    /// 成功（更新 + 历史 append）。
    pub const SUCCESS: i32 = 0;
    /// 解锁失败 fail-closed（escrow 与 env 均无；escrow 存在但解锁失败不回落 env；
    /// 含 vault 定位失败）。
    pub const UNLOCK_FAILED: i32 = 1;
    /// 条目未命中 / 歧义（1011 语义）。
    pub const TARGET_NOT_FOUND: i32 = 2;
    /// 强度不足拒绝（1010 语义；`--force` 绕过）。
    pub const WEAK_PASSWORD: i32 = 3;
    /// 参数 / 用法错误（未知 flag / 缺条目名 / `--id` 格式错）。
    pub const USAGE_ERROR: i32 = 4;
}

/// `coffer set-password` 已解析选项（docs/34 §5.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPasswordOptions {
    /// display name（位置参数）；与 `id` 互斥。
    pub name: Option<String>,
    /// 条目 UUID（`--id` 兜底定位）；与 `name` 互斥。
    pub id: Option<String>,
    /// 绕过强度门禁（`--force`，用户批准保留）。
    pub force: bool,
}

/// `set-password` 参数 / 条目定位 / 强度 / 读密错误（docs/34 §5.2 映射非零退出）。
#[derive(Debug, thiserror::Error)]
pub enum SetPasswordError {
    /// 未知 flag。
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    /// flag 缺值。
    #[error("flag `{0}` requires a value")]
    MissingValue(String),
    /// 多余位置参数。
    #[error("unexpected positional argument: {0}")]
    UnexpectedPositional(String),
    /// 名称与 `--id` 同时给定。
    #[error("cannot specify both an entry name and `--id`")]
    ConflictingLocators,
    /// 既无名称也无 `--id`。
    #[error("missing target: provide an entry name or `--id <UUID>` (docs/34 §5.1)")]
    MissingTarget,
    /// 条目未命中。
    #[error("entry not found: {0}")]
    ItemNotFound(String),
    /// 名称歧义（多条同名 Active 条目）。
    #[error("entry name is ambiguous ({count} matches): {name}；请用 `--id <UUID>` 定位")]
    Ambiguous {
        /// 歧义条目名。
        name: String,
        /// 同名 Active 条目数。
        count: usize,
    },
    /// 目标为环境容器条目。
    #[error("entry is an environment container, not a password item: {0}")]
    EnvContainer(String),
    /// 无可更新的密码字段（无 `Designation::Password`，退出 2）。
    #[error("entry has no password (Password) field to update: {0}")]
    NoPasswordField(String),
    /// `--id` 值不是合法 UUID（格式错 → 退出码 4）。
    #[error("invalid `--id` value (expected a UUID): {0}")]
    InvalidId(String),
    /// 空密码 / 全空白（EOF 无内容或 trim 后全空白；即便 `--force` 也不写库，
    /// lead 裁定 2026-10-10）。
    #[error("empty password: provide a non-empty value on stdin")]
    EmptyPassword,
    /// 强度不达标。
    #[error("password strength below threshold (zxcvbn < 强)；换更强密码或显式 `--force` 绕过（docs/34 §3）")]
    WeakPassword,
    /// 会话层存储错误（解锁后不应出现；消息不带详情，防泄露）。
    #[error("vault operation failed, not written")]
    Storage,
    /// 读 stdin 失败。
    #[error("failed to read password from stdin: {0}")]
    ReadPassword(#[from] std::io::Error),
}

impl SetPasswordError {
    /// 退出码映射（docs/34 §5.2 + r0.4，lead 裁定 2026-10-09）——一次性写命令专用：
    /// 参数/用法（含空密码、`--id` 格式错）→ 4；条目未命中/歧义（含目标非密码
    /// 条目：环境容器 / 无密码字段）→ 2；强度不足 → 3；运行时失败（stdin IO /
    /// 存储操作）→ 1（L-4：读 stdin IO 故障是运行时错误，非用法错误）。
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::UnknownFlag(_)
            | Self::MissingValue(_)
            | Self::UnexpectedPositional(_)
            | Self::ConflictingLocators
            | Self::MissingTarget
            | Self::InvalidId(_)
            | Self::EmptyPassword => exit_codes::USAGE_ERROR,
            Self::ItemNotFound(_)
            | Self::Ambiguous { .. }
            | Self::EnvContainer(_)
            | Self::NoPasswordField(_) => exit_codes::TARGET_NOT_FOUND,
            Self::WeakPassword => exit_codes::WEAK_PASSWORD,
            Self::ReadPassword(_) | Self::Storage => exit_codes::UNLOCK_FAILED,
        }
    }
}

/// 从 argv（不含子命令 `set-password`）解析选项（docs/34 §5.1）。
///
/// 位置参数 = display name；`--id <UUID>` 兜底定位（格式错 →
/// [`SetPasswordError::InvalidId`]，退出码 4）；`--force` 布尔。名称与 `--id`
/// 互斥（同时给定 → [`SetPasswordError::ConflictingLocators`]）；二者皆无 →
/// [`SetPasswordError::MissingTarget`]；未知 flag / 缺值 / 多余位置参数 → 对应错误。
pub fn parse_args(args: &[String]) -> Result<SetPasswordOptions, SetPasswordError> {
    let mut name: Option<String> = None;
    let mut id: Option<String> = None;
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--id" => {
                let next = i + 1;
                if next >= args.len() {
                    return Err(SetPasswordError::MissingValue("--id".to_string()));
                }
                let value = args[next].clone();
                if Uuid::parse_str(&value).is_err() {
                    return Err(SetPasswordError::InvalidId(value));
                }
                id = Some(value);
                i = next;
            }
            "--force" => force = true,
            other if other.starts_with('-') => {
                return Err(SetPasswordError::UnknownFlag(other.to_string()));
            }
            other => {
                if name.is_some() {
                    return Err(SetPasswordError::UnexpectedPositional(other.to_string()));
                }
                name = Some(other.to_string());
            }
        }
        i += 1;
    }
    if name.is_some() && id.is_some() {
        return Err(SetPasswordError::ConflictingLocators);
    }
    if name.is_none() && id.is_none() {
        return Err(SetPasswordError::MissingTarget);
    }
    Ok(SetPasswordOptions { name, id, force })
}

/// 从 stdin 读一行密码（docs/34 §5.1：TTY 下隐藏输入，不回显）。
///
/// - `hide == true`（真实 stdin 为 TTY）：提示写 stderr（不污染 stdout），经
///   `rpassword` 关回显从真实 tty 读（密码不进 argv / 不进进程列表）；
/// - `hide == false`（管道 / 重定向，脚本与测试路径）：从 `reader` 读一行
///   （`\r\n` / `\n` 结尾剥离）。
///
/// 返回的 [`SecretString`] 析构清零（`ZeroizeOnDrop`）；空输入 → [`SetPasswordError::EmptyPassword`]。
fn read_password_line(
    reader: &mut dyn BufRead,
    hide: bool,
    prompt: &str,
) -> Result<SecretString, SetPasswordError> {
    if hide {
        if !prompt.is_empty() {
            eprint!("{prompt}");
            let _ = std::io::stderr().flush();
        }
        let pw = rpassword::read_password()?;
        if pw.trim().is_empty() {
            return Err(SetPasswordError::EmptyPassword);
        }
        return Ok(SecretString::from_exposed(pw));
    }
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let pw = line.trim_end_matches(&['\r', '\n'][..]).to_string();
    line.zeroize();
    // 全空白一律视为空密码（lead 裁定 2026-10-10，L-1）——`--force` 也不绕过
    // （EmptyPassword 在读密阶段即拒绝，早于强度门禁）。
    if pw.trim().is_empty() {
        return Err(SetPasswordError::EmptyPassword);
    }
    Ok(SecretString::from_exposed(pw))
}

/// 强度门禁（docs/34 §3）：zxcvbn ≥ 强（`cf_audit::meets_strength_threshold`，与 App
/// 同款阈值）；`--force` 显式绕过。返回 `Err(WeakPassword)` 表示拒绝。
fn enforce_strength(pw: &str, force: bool) -> Result<(), SetPasswordError> {
    if force {
        return Ok(());
    }
    if cf_audit::meets_strength_threshold(pw) {
        Ok(())
    } else {
        Err(SetPasswordError::WeakPassword)
    }
}

/// 在 draft 中定位并改写密码目标字段——**仅** `Designation::Password` 字段
/// （与 App `UpdatePassword.passwordField` / `ItemDetailView.hasPasswordField` 门禁
/// 对齐，docs/34 §4.2「仅改密码字段」）。返回 `false` = 无密码字段（调用方报
/// [`SetPasswordError::NoPasswordField`]，退出 2）。
///
/// **不做 `Concealed` 兜底**（H-1，lead 审查 2026-10-10）：无 Password 标注的
/// Concealed 字段（如信用卡 CVV / 软件许可证 key）不是密码，回写会破坏数据；
/// 也不回落到任意有值字段，避免误改用户名等非密码字段。
fn set_password_field(draft: &mut ItemDraft, pw: &str) -> bool {
    for f in &mut draft.fields {
        if f.designation == Some(Designation::Password) {
            f.value = Some(pw.to_string());
            return true;
        }
    }
    false
}

/// 按 UUID 精确读条目（`--id` 兜底定位）。
///
/// 未命中 → [`SetPasswordError::ItemNotFound`]；命中的是环境容器 →
/// [`SetPasswordError::EnvContainer`]；会话层错误 → [`SetPasswordError::Storage`]。
fn resolve_by_id(session: &VaultSession, id: &str) -> Result<ItemDetails, SetPasswordError> {
    let d = session
        .get_item(id)
        .map_err(|_| SetPasswordError::Storage)?
        .ok_or_else(|| SetPasswordError::ItemNotFound(id.to_string()))?;
    if crate::provider::coffer::CofferStoreProvider::is_env_details(&d) {
        return Err(SetPasswordError::EnvContainer(d.title.expose().to_string()));
    }
    Ok(d)
}

/// 按 display name 精确匹配定位（Active 条目）。
///
/// 0 命中 → [`SetPasswordError::ItemNotFound`]；>1 命中 → [`SetPasswordError::Ambiguous`]
/// （不写库，提示 `--id`）；恰 1 命中 → 校验非环境容器后返回。
fn resolve_by_name(session: &VaultSession, name: &str) -> Result<ItemDetails, SetPasswordError> {
    let items = session
        .list_items(None)
        .map_err(|_| SetPasswordError::Storage)?;
    let matches: Vec<ItemSummary> = items
        .into_iter()
        .filter(|s| s.state == ItemState::Active && s.title == name)
        .collect();
    match matches.len() {
        0 => Err(SetPasswordError::ItemNotFound(name.to_string())),
        1 => {
            let d = session
                .get_item(&matches[0].uuid.to_string())
                .map_err(|_| SetPasswordError::Storage)?
                .ok_or_else(|| SetPasswordError::ItemNotFound(name.to_string()))?;
            if crate::provider::coffer::CofferStoreProvider::is_env_details(&d) {
                return Err(SetPasswordError::EnvContainer(d.title.expose().to_string()));
            }
            Ok(d)
        }
        n => Err(SetPasswordError::Ambiguous {
            name: name.to_string(),
            count: n,
        }),
    }
}

/// 条目定位总入口：`--id` 兜底优先于 name（互斥已由 [`parse_args`] 保证）。
fn resolve_item(
    session: &VaultSession,
    opts: &SetPasswordOptions,
) -> Result<ItemDetails, SetPasswordError> {
    if let Some(id) = &opts.id {
        return resolve_by_id(session, id);
    }
    let name = opts.name.as_deref().ok_or(SetPasswordError::MissingTarget)?;
    resolve_by_name(session, name)
}

/// `set-password` 入口（`cli::run` 分派）：读 env（库路径 / 兜底密码）→ 委托
/// [`run_with`]（escrow 用平台默认）。返回进程退出码（docs/34 §5.2）。
pub fn run(args: &[String]) -> i32 {
    let mut logger = Logger::stderr();
    // 用法校验最先（docs/34 §5.2）：参数/用法错（退出码 4）无需库配置即可判定，
    // 先于 vault 定位检查——避免缺 $COFFER_VAULT_DIR 环境时把用法错误报为 1。
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            logger.error(&e.to_string());
            return e.exit_code();
        }
    };

    // vault 定位：`COFFER_VAULT_DIR` 必填（缺 = 定位失败 → 退出码 1，docs/34 §5.2）。
    let vault_dir = match std::env::var("COFFER_VAULT_DIR") {
        Ok(v) if !v.trim().is_empty() => std::path::PathBuf::from(v),
        _ => {
            logger.error("set-password 需要 $COFFER_VAULT_DIR（库目录路径，docs/20 §4.5）");
            return exit_codes::UNLOCK_FAILED;
        }
    };
    let env_password = std::env::var("COFFER_VAULT_PASSWORD")
        .ok()
        .map(SecretString::from_exposed);
    let escrow = crate::provider::escrow::platform_escrow();
    let mut stdin = std::io::stdin().lock();
    run_with(
        &mut stdin,
        std::io::stdin().is_terminal(),
        &opts,
        &vault_dir,
        env_password,
        &escrow,
    )
}

/// 内部入口（escrow / stdin / 库路径可注入，测试用）：五步编排——1 取密+门禁 →
/// 2 解锁 → 3 定位 → 4 更新 → 5 报告。返回进程退出码（docs/34 §5.2）。
///
/// `run` 负责参数解析 + env 收集后委托本函数；测试经本函数注入 mock escrow /
/// 管道 reader（已解析选项），覆盖 escrow 成功与 fail-closed 分支（AC-18.2-11/-13）。
fn run_with(
    stdin: &mut dyn BufRead,
    hide: bool,
    opts: &SetPasswordOptions,
    vault_dir: &std::path::Path,
    env_password: Option<SecretString>,
    escrow: &dyn VaultEscrowStore,
) -> i32 {
    let mut logger = Logger::stderr();

    // 1. stdin 取密 + 强度门禁（TTY 隐藏 / 管道直读；`--force` 绕过强度）。
    let password = match read_password_guarded(stdin, hide, opts) {
        Ok(p) => p,
        Err(e) => {
            logger.error(&e.to_string());
            return e.exit_code();
        }
    };
    let pw = password.expose();

    // 2. 取密链解锁（escrow → env 兜底 → fail-closed，D-4）。
    //    `unlock_vault` 沿用 MCP 服务器码（1/3）返回；一次性写命令在此**统一归并到
    //    退出码 1（解锁失败类别）**——各类别不复用服务器进程码。
    let session = match crate::cli::unlock_vault(vault_dir, escrow, env_password, &mut logger) {
        Ok(s) => s,
        Err(_) => return exit_codes::UNLOCK_FAILED,
    };

    // 3. 条目定位（歧义 / 未命中不写库，退出 2）。
    let item = match resolve_item(&session, opts) {
        Ok(i) => i,
        Err(e) => {
            logger.error(&e.to_string());
            return e.exit_code();
        }
    };

    // 4. 改密码字段 → update（`update_item` 自动 append 历史，FR-2.9）。
    if let Err((msg, code)) = apply_update(&session, &item, pw) {
        logger.error(&msg);
        return code;
    }

    // 5. 报告。
    println!("已更新 {} · 旧版本可在 App 历史中回滚", item.title.expose());
    exit_codes::SUCCESS
}

/// 第 1 步：stdin 取密（TTY 隐藏 / 管道直读）+ 强度门禁（`--force` 绕过）。
///
/// 顺序注记（L-3，lead 审查 2026-10-10）：取密 + 强度门禁在**解锁之前**——弱密码 +
/// 锁库场景返回 3（强度类别）而非 1（解锁类别）。此为有意顺序（先验用户输入、
/// 再动钥匙链），两类均为可区分非零码，脚本可判。
fn read_password_guarded(
    stdin: &mut dyn BufRead,
    hide: bool,
    opts: &SetPasswordOptions,
) -> Result<SecretString, SetPasswordError> {
    let password = read_password_line(stdin, hide, "新密码（输入不显示）: ")?;
    enforce_strength(password.expose(), opts.force)?;
    Ok(password)
}

/// 第 4 步：改密码字段 → update（`update_item` 自动 append 历史，FR-2.9）。
///
/// 明文临时缓冲（draft 中密码副本）在返回前**统一清零**——成功与失败分支一致
/// （M-3，lead 审查 2026-10-10：失败路径直接 return 漏清零的既有缺口）。
fn apply_update(
    session: &VaultSession,
    item: &ItemDetails,
    pw: &str,
) -> Result<(), (String, i32)> {
    let mut draft = crate::provider::coffer::draft_from_details(item);
    let result = if set_password_field(&mut draft, pw) {
        session
            .update_item(&item.uuid, &draft)
            .map_err(map_update_error)
    } else {
        let msg = SetPasswordError::NoPasswordField(item.title.expose().to_string());
        Err((format!("{msg}；未写入"), msg.exit_code()))
    };
    for f in &mut draft.fields {
        if let Some(v) = &mut f.value {
            v.zeroize();
        }
    }
    result
}

/// `update_item` 的 `CfError` → (消息, 退出码)（docs/34 §5.2 一次性写命令映射）：
/// 条目消失 → 2；校验/参数被拒（目标不可用，如 Trashed/Archived）→ 2（L-7）；
/// 库锁定 → 1（操作/解锁失败）；其余 → 1。
fn map_update_error(e: cf_domain::CfError) -> (String, i32) {
    match e {
        cf_domain::CfError::ItemNotFound => (
            "条目不存在（可能已被删除），未写入".to_string(),
            exit_codes::TARGET_NOT_FOUND,
        ),
        cf_domain::CfError::Validation(m) | cf_domain::CfError::InvalidArgument(m) => (
            format!("更新被拒（目标不可用 / 校验失败），未写入：{m}"),
            exit_codes::TARGET_NOT_FOUND,
        ),
        cf_domain::CfError::VaultLocked => (
            "库已锁定，未写入".to_string(),
            exit_codes::UNLOCK_FAILED,
        ),
        other => (
            format!("更新失败，未写入：{other}"),
            exit_codes::UNLOCK_FAILED,
        ),
    }
}

// ===========================================================================
// 单元测试 —— 拆至 `set_password_tests.rs`（M-1，lead 审查 2026-10-10：主文件
// 回落 <800 行）。`#[path]` 使测试仍为同 crate 单元测试（可访问私有项）。
// ===========================================================================

#[cfg(test)]
#[path = "set_password_tests.rs"]
mod tests;
