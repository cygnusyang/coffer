//! `coffer set-env` 子命令（docs/36 §4，v2.8.0 环境容器写面）。
//!
//! 行为（docs/36 §4.1~§4.7）：
//!
//! 1. 目标定位：`--scope <owner>` 按标题精确匹配（owner = 容器标题，R1 扁平）；
//!    `--id <UUID>` 按 UUID 定位兜底（名称歧义 / 改名场景，镜像
//!    `set-password --id` 纪律）。**互斥**，至少给一个。
//!    0 命中且无任何条目同名 → **自动建容器**（SecureNote + `coffer:environment`
//!    标签，D-36.2）；同名**非容器**条目（含 Login+标签，H-2）→ 拒绝不建
//!    （退出 2）；>1 命中 → 歧义报错提示 `--id`（退出 2）。自动建容器并发安全
//!    （H-1）：`environment_exists` 守卫挡顺序重复 + uuid tie-break 自愈——两
//!    进程同时首写同名单容器时库内恒恰 1 容器，输家干净失败（退出 2）；
//! 2. 写入语义：一次 `update_item` 整换重建（多条 NAME=VALUE + `--unset` 同一次
//!    调用，FR-2.9 自动 append 一条历史可回滚）。字段形态固定
//!    [`FieldType::Text`] + `designation: None`——与 MCP `username_value` /
//!    `secret_value` 只读语义对齐；命中既有字段不改其 field_type / designation；
//!    `--unset` 按 name 删字段、幂等；
//! 3. 值来源两档（D-36.3）：内联 `NAME=VALUE`（非敏感值逃生口，显式知情）；
//!    裸 `NAME` 该值走 stdin（TTY 隐藏 / 管道读一行剥换行，供敏感值）；
//!    **至多一个裸 NAME**。`NAME=` 空值合法（env 空值有语义，置空不删除）；
//! 4. 取密链完全复用 [`crate::cli::unlock_vault`]（escrow → env 兜底 →
//!    fail-closed 退出 1，docs/30 §1.3 同构）；用法校验最先（先验用户输入、
//!    再动钥匙链）；
//! 5. **值绝不进 argv / stdout / 日志**：stdout 成功消息与 stderr 诊断只含 NAME
//!    与容器名，不含 VALUE 明文（§3 载荷纪律）；明文临时缓冲用后 zeroize
//!    （镜像 `set-password` M-3）。
//!
//! stdout 只写成功消息（本子命令非协议会话）；诊断/错误经 [`Logger`] 走 stderr。
//! 退出码（docs/36 §4.5，一次性写命令映射，与 docs/34 §5.2 对齐）：
//! `0` 成功（写入/更新/删除 + 历史 append；含首写自动建容器）；`1` 解锁失败
//! fail-closed；`2` 目标未命中 / 歧义 / 目标非环境容器 / 并发建容器撞车；
//! `3` 保留槽位不适用（set-env 无强度门禁，码位维持跨写命令映射对齐）；
//! `4` 参数/用法错误。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, IsTerminal, Write};

use cf_domain::category::ItemCategory;
use cf_domain::field::FieldType;
use cf_domain::item::{FieldDraft, ItemDraft, ItemState, ItemSummary};
use cf_domain::secret::SecretString;
use cf_session::types::ItemDetails;
use cf_session::VaultSession;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::cli::Logger;
use crate::provider::escrow::VaultEscrowStore;
use crate::provider::is_valid_env_name;

/// 标记环境容器条目的保留标签（与 `provider/coffer.rs:63` 的 `ENV_TAG` 同源，
/// docs/36 §4.2 自动建容器复用 create_environment 语义）。
const ENV_TAG: &str = "coffer:environment";

/// 一次性写命令退出码（docs/36 §4.5）——`set-env` 专用，不复用
/// [`crate::cli::exit_code`] 的 MCP 服务器进程码（长驻服务器语义）。
pub mod exit_codes {
    /// 成功（写入/更新/删除 + 历史 append；含首写自动建容器）。
    pub const SUCCESS: i32 = 0;
    /// 解锁失败 fail-closed（escrow 与 env 均无；escrow 存在但解锁失败不回落
    /// env；含 vault 定位失败与会话层存储错误）。
    pub const UNLOCK_FAILED: i32 = 1;
    /// 目标未命中 / 歧义 / 目标非环境容器（含「标题已存在但非容器」）。
    pub const TARGET_NOT_FOUND: i32 = 2;
    /// 保留槽位，**不适用**（docs/36 §4.5：set-env 无强度门禁，保留该码位
    /// 维持跨写命令映射对齐——set-password 3 = 强度不足；本子命令恒不使用）。
    pub const WEAK_PASSWORD: i32 = 3;
    /// 参数 / 用法错误（未知 flag / 缺 `--scope` / NAME 非法 / VALUE 含 NUL /
    /// `--unset` 与对并存 / 裸 NAME 多个 / 多余位置参数）。
    pub const USAGE_ERROR: i32 = 4;
}

/// `coffer set-env` 已解析选项（docs/36 §4.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetEnvOptions {
    /// 容器标题（`--scope <owner>`，R1 扁平）；与 `id` 互斥。
    pub scope: Option<String>,
    /// 条目 UUID（`--id <UUID>` 兜底定位）；与 `scope` 互斥。
    pub id: Option<String>,
    /// 内联 `NAME=VALUE` 对（按第一个 `=` 分割；VALUE 可含 `=`）。
    pub pairs: Vec<(String, String)>,
    /// 裸 `NAME`（至多一个）——该值从 stdin 读（TTY 隐藏 / 管道一行）。
    pub stdin_name: Option<String>,
    /// `--unset` 模式：待删除字段名（非空 ⟺ unset 模式；与对互斥）。
    pub unset: Vec<String>,
}

/// `set-env` 参数 / 目标定位 / 值读取错误（docs/36 §4.5 映射非零退出）。
#[derive(Debug, thiserror::Error)]
pub enum SetEnvError {
    /// 未知 flag。
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    /// flag 缺值。
    #[error("flag `{0}` requires a value")]
    MissingValue(String),
    /// 既无 `--scope` 也无 `--id`。
    #[error("missing target: provide `--scope <owner>` or `--id <UUID>` (docs/36 §4.1)")]
    MissingScope,
    /// `--scope` 值为空 / 全空白。
    #[error("empty `--scope` value")]
    EmptyScope,
    /// `--scope` 与 `--id` 同时给定（互斥）。
    #[error("cannot specify both `--scope` and `--id`")]
    ConflictingLocators,
    /// `--id` 值不是合法 UUID（格式错 → 退出码 4）。
    #[error("invalid `--id` value (expected a UUID): {0}")]
    InvalidId(String),
    /// NAME 不合法（`is_valid_env_name`：`[A-Za-z_][A-Za-z0-9_]*`）。
    #[error("invalid environment variable name `{0}` (expected [A-Za-z_][A-Za-z0-9_]*)")]
    InvalidName(String),
    /// VALUE 含 NUL（POSIX env 单行惯例，拒 NUL）。
    #[error("value contains a NUL byte")]
    ValueContainsNul,
    /// 裸 `NAME` 多个（stdin 值归属歧义，docs/36 §4.4）。
    #[error("at most one bare NAME (stdin value) is allowed")]
    MultipleBareNames,
    /// `--unset` 与 `NAME=VALUE` 对并存（本版每次调用一个意图，docs/36 §4.1）。
    #[error("cannot combine `--unset` with `NAME=VALUE` pairs: {0}")]
    UnsetWithPairs(String),
    /// `--unset` 未跟任何 NAME。
    #[error("`--unset` requires at least one NAME")]
    MissingUnsetName,
    /// 写模式（非 unset）无任何 NAME=VALUE / 裸 NAME。
    #[error("missing write: provide at least one `NAME=VALUE` or a bare `NAME`")]
    MissingWrite,
    /// 目标条目未命中（`--id` 未命中）。
    #[error("entry not found: {0}")]
    ItemNotFound(String),
    /// 目标条目存在但**不是**环境容器（标题撞车 / `--id` 命中非容器）。
    #[error("entry is not an environment container（不是环境容器）: {0}")]
    NotEnvContainer(String),
    /// 名称歧义（多条同名 Active 条目，提示 `--id`）。
    #[error("environment name is ambiguous ({count} matches): {name}；请用 `--id <UUID>` 定位")]
    Ambiguous {
        /// 歧义容器名。
        name: String,
        /// 同名 Active 条目数。
        count: usize,
    },
    /// 首写自动建容器与并发写者撞车（同名单容器已存在 / 本进程被 tie-break
    /// 裁掉；重跑即可写入，H-1）。
    #[error("environment `{0}` was just created by another writer；请重跑 set-env 写入（并发建容器撞车）")]
    EnvConcurrentCreate(String),
    /// 读 stdin 失败。
    #[error("failed to read value from stdin: {0}")]
    ReadValue(#[from] std::io::Error),
    /// 会话层存储错误（解锁后不应出现；消息不带详情，防泄露）。
    #[error("vault operation failed, not written")]
    Storage,
}

impl SetEnvError {
    /// 退出码映射（docs/36 §4.5）——一次性写命令专用：参数/用法（含缺 `--scope`、
    /// NAME 非法、VALUE 含 NUL、`--unset` 与对并存、裸 NAME 多个）→ 4；目标
    /// 未命中 / 歧义 / 非环境容器 → 2；运行时失败（stdin IO / 存储操作）→ 1。
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::UnknownFlag(_)
            | Self::MissingValue(_)
            | Self::MissingScope
            | Self::EmptyScope
            | Self::ConflictingLocators
            | Self::InvalidId(_)
            | Self::InvalidName(_)
            | Self::ValueContainsNul
            | Self::MultipleBareNames
            | Self::UnsetWithPairs(_)
            | Self::MissingUnsetName
            | Self::MissingWrite => exit_codes::USAGE_ERROR,
            Self::ItemNotFound(_)
            | Self::NotEnvContainer(_)
            | Self::Ambiguous { .. }
            | Self::EnvConcurrentCreate(_) => exit_codes::TARGET_NOT_FOUND,
            Self::ReadValue(_) | Self::Storage => exit_codes::UNLOCK_FAILED,
        }
    }
}

/// 从 argv（不含子命令 `set-env`）解析选项（docs/36 §4.1）。
///
/// 位置参数两档：写模式（无 `--unset`）下 `NAME=VALUE` 对（按**第一个** `=`
/// 分割，VALUE 可含 `=`）或至多一个裸 `NAME`（stdin 取值）；`--unset` 模式下
/// 全部为待删字段名（含 `=` 即「对并存」用法错误）。`--scope` 与 `--id`
/// 互斥（同时给定 → [`SetEnvError::ConflictingLocators`]）；二者皆无 →
/// [`SetEnvError::MissingScope`]；未知 flag / 缺值 → 对应错误。
///
/// NAME 校验（`is_valid_env_name`）与 VALUE NUL 校验在**本解析阶段**完成——
/// 用法错误最先判定，无需解锁（docs/36 §4.4 校验顺序）。
pub fn parse_args(args: &[String]) -> Result<SetEnvOptions, SetEnvError> {
    let mut scope: Option<String> = None;
    let mut id: Option<String> = None;
    let mut unset_mode = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--scope" => {
                let next = i + 1;
                if next >= args.len() {
                    return Err(SetEnvError::MissingValue("--scope".to_string()));
                }
                let value = args[next].clone();
                if value.trim().is_empty() {
                    return Err(SetEnvError::EmptyScope);
                }
                scope = Some(value);
                i = next;
            }
            "--id" => {
                let next = i + 1;
                if next >= args.len() {
                    return Err(SetEnvError::MissingValue("--id".to_string()));
                }
                let value = args[next].clone();
                if Uuid::parse_str(&value).is_err() {
                    return Err(SetEnvError::InvalidId(value));
                }
                id = Some(value);
                i = next;
            }
            "--unset" => unset_mode = true,
            other if other.starts_with('-') => {
                return Err(SetEnvError::UnknownFlag(other.to_string()));
            }
            other => positionals.push(other.to_string()),
        }
        i += 1;
    }

    if scope.is_some() && id.is_some() {
        return Err(SetEnvError::ConflictingLocators);
    }
    if scope.is_none() && id.is_none() {
        return Err(SetEnvError::MissingScope);
    }

    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut stdin_name: Option<String> = None;
    let mut unset: Vec<String> = Vec::new();
    if unset_mode {
        for p in positionals {
            if p.contains('=') {
                return Err(SetEnvError::UnsetWithPairs(p));
            }
            if !is_valid_env_name(&p) {
                return Err(SetEnvError::InvalidName(p));
            }
            unset.push(p);
        }
        if unset.is_empty() {
            return Err(SetEnvError::MissingUnsetName);
        }
    } else {
        for p in positionals {
            if let Some((name, value)) = p.split_once('=') {
                if value.contains('\0') {
                    return Err(SetEnvError::ValueContainsNul);
                }
                if !is_valid_env_name(name) {
                    return Err(SetEnvError::InvalidName(name.to_string()));
                }
                pairs.push((name.to_string(), value.to_string()));
            } else if stdin_name.is_some() {
                return Err(SetEnvError::MultipleBareNames);
            } else {
                if !is_valid_env_name(&p) {
                    return Err(SetEnvError::InvalidName(p));
                }
                stdin_name = Some(p);
            }
        }
        if pairs.is_empty() && stdin_name.is_none() {
            return Err(SetEnvError::MissingWrite);
        }
    }

    Ok(SetEnvOptions {
        scope,
        id,
        pairs,
        stdin_name,
        unset,
    })
}

/// 从 stdin 读一行值（docs/36 §4.4：裸 NAME 档）。
///
/// - `hide == true`（真实 stdin 为 TTY）：提示写 stderr（不污染 stdout），经
///   `rpassword` 关回显从真实 tty 读（值不进 argv / 进程列表）；
/// - `hide == false`（管道 / 重定向，脚本与测试路径）：从 `reader` 读一行
///   （`\r\n` / `\n` 结尾剥离）。
///
/// 返回的 [`SecretString`] 析构清零（`ZeroizeOnDrop`）；**空值合法**（env 空值
/// 有语义，与 set-password 空密码不同）。
fn read_value_line(
    reader: &mut dyn BufRead,
    hide: bool,
    prompt: &str,
) -> Result<SecretString, SetEnvError> {
    if hide {
        if !prompt.is_empty() {
            eprint!("{prompt}");
            let _ = std::io::stderr().flush();
        }
        let v = rpassword::read_password()?;
        return Ok(SecretString::from_exposed(v));
    }
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let v = line.trim_end_matches(&['\r', '\n'][..]).to_string();
    line.zeroize();
    Ok(SecretString::from_exposed(v))
}

/// 写入一条 NAME/VALUE：遍历 draft 字段按 `name == NAME` 命中 → 更新现值；
/// 未命中 → append [`FieldDraft`]（`FieldType::Text` + `designation: None`，
/// position = 现有最大 + 1，docs/36 §4.3）。
///
/// **命中既有字段不改其 field_type / designation**（用户手编字段不静默重写）；
/// `NAME=` 空值 = 置空串（不是删除，AC-36.1-9）。
fn apply_pair(draft: &mut ItemDraft, name: &str, value: &str) {
    for f in &mut draft.fields {
        if f.name == name {
            f.value = Some(value.to_string());
            return;
        }
    }
    let next_position = draft
        .fields
        .iter()
        .map(|f| f.position)
        .max()
        .map_or(0, |p| p + 1);
    draft.fields.push(FieldDraft {
        name: name.to_string(),
        value: Some(value.to_string()),
        field_type: FieldType::Text,
        designation: None,
        section_index: None,
        position: next_position,
    });
}

/// `--unset`：按 name 删除字段（`draft.fields.retain`）。删除缺失的 NAME =
/// 幂等成功（与 `revoke_secret` 幂等纪律同，docs/36 §4.3）。
fn apply_unset(draft: &mut ItemDraft, names: &[String]) {
    draft.fields.retain(|f| !names.iter().any(|n| n == &f.name));
}

/// 空环境容器 draft（SecureNote + [`ENV_TAG`] 标签，无字段）——首写自动建容器
/// 用，语义与 `provider/coffer.rs` 的 `create_environment` 一致（docs/36 §4.2）。
fn fresh_container_draft(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_string(),
        category: ItemCategory::SecureNote,
        urls: Vec::new(),
        tags: vec![ENV_TAG.to_string()],
        sections: Vec::new(),
        fields: Vec::new(),
        totp: None,
    }
}

/// 目标解析结果。
///
/// `Existing` 装箱（`ItemDetails` 体型大：≤304B vs Fresh 48B）——仅只读还原
/// draft，装箱消 clippy `large_enum_variant`（`draft_from_details` 取 `&ItemDetails`，
/// 经 deref 自动解包）。
#[derive(Debug)]
enum ResolvedTarget {
    /// 已存在容器（含既有字段，须经 draft_from_details 还原）。
    Existing(Box<ItemDetails>),
    /// 本调用自动新建的空容器（首写即建，D-36.2）。
    Fresh { title: String, uuid: String },
}

/// 详情条目是否为环境容器（**SecureNote + 保留标签** 双条件，H-2）——镜像
/// [`CofferStoreProvider::is_env_item`]（coffer.rs:120）的 MCP 读面语义：
/// `is_env_details` 仅查标签，Login 手加 `coffer:environment` 标签会被它放过，
/// 但 MCP 永不注入 → set-env 认作容器即静默分歧，故须补类别校验。
fn is_env_container(d: &ItemDetails) -> bool {
    d.category == ItemCategory::SecureNote
        && crate::provider::coffer::CofferStoreProvider::is_env_details(d)
}

/// 按 UUID 精确读容器（`--id` 兜底定位，docs/36 §4.2）。
///
/// 未命中 → [`SetEnvError::ItemNotFound`]；命中的非容器条目（含 Login+标签，
/// H-2）→ [`SetEnvError::NotEnvContainer`]；会话层错误 → [`SetEnvError::Storage`]。
/// `--id` **不自动建容器**。
fn resolve_by_id(session: &VaultSession, id: &str) -> Result<ResolvedTarget, SetEnvError> {
    let d = session
        .get_item(id)
        .map_err(|_| SetEnvError::Storage)?
        .ok_or_else(|| SetEnvError::ItemNotFound(id.to_string()))?;
    if is_env_container(&d) {
        Ok(ResolvedTarget::Existing(Box::new(d)))
    } else {
        Err(SetEnvError::NotEnvContainer(d.title.expose().to_string()))
    }
}

/// 按 owner（`--scope`）精确匹配定位（Active 条目，docs/36 §4.2 表）。
///
/// 0 命中且无任何条目同名 → **自动建容器**（`Fresh`）；0 命中但同名条目存在
/// （非容器）→ 本分支不会出现（见 `resolve_by_scope` 的匹配聚合）；恰 1 命中 →
/// 校验为环境容器后返回；>1 命中 → [`SetEnvError::Ambiguous`]（不写库，提示
/// `--id`）。
fn resolve_by_scope(session: &VaultSession, scope: &str) -> Result<ResolvedTarget, SetEnvError> {
    let items = session
        .list_items(None)
        .map_err(|_| SetEnvError::Storage)?;
    let matches: Vec<ItemSummary> = items
        .into_iter()
        .filter(|s| s.state == ItemState::Active && s.title == scope)
        .collect();
    match matches.len() {
        0 => {
            // D-36.2：owner 缺失 = 首次写入即初始化（空容器无害且可删）。
            let uuid = auto_create_environment(session, scope)?;
            Ok(ResolvedTarget::Fresh {
                title: scope.to_string(),
                uuid,
            })
        }
        1 => {
            let d = session
                .get_item(&matches[0].uuid.to_string())
                .map_err(|_| SetEnvError::Storage)?
                .ok_or_else(|| SetEnvError::ItemNotFound(scope.to_string()))?;
            if is_env_container(&d) {
                Ok(ResolvedTarget::Existing(Box::new(d)))
            } else {
                Err(SetEnvError::NotEnvContainer(scope.to_string()))
            }
        }
        n => Err(SetEnvError::Ambiguous {
            name: scope.to_string(),
            count: n,
        }),
    }
}

/// 列出与 `name` 同名的环境容器（Active + SecureNote + 保留标签）uuid。
///
/// 镜像 [`CofferStoreProvider::environment_exists`]（coffer.rs:204）的容器
/// 判据（H-2 双条件）；H-1 守卫与并发自愈共用。
fn env_containers(session: &VaultSession, name: &str) -> Result<Vec<String>, SetEnvError> {
    let items = session.list_items(None).map_err(|_| SetEnvError::Storage)?;
    let mut out = Vec::new();
    for s in items {
        if s.state != ItemState::Active || s.title != name || s.category != ItemCategory::SecureNote {
            continue;
        }
        if let Some(d) = session
            .get_item(&s.uuid.to_string())
            .map_err(|_| SetEnvError::Storage)?
        {
            if is_env_container(&d) {
                out.push(s.uuid.to_string());
            }
        }
    }
    Ok(out)
}

/// 并发首写自愈（H-1）：创建后再查，若同名单容器 >1（两个 `set-env` 同时首写
/// 撞车）→ 按 uuid 字典序唯一赢家收敛：赢家保留自己的并清理其余输家容器，
/// 输家删自己的并干净失败——**库内恒恰 1 个同名容器**。
///
/// items 表无 title UNIQUE（标题加密存储，schema.rs），跨进程无原子查重，
/// 故在命令层用确定性 tie-break（uuid 排序）收敛：无论并发交错如何，双方
/// 算出的赢家一致，恰一者存活。赢家清理的输家容器若已并发写入字段，按
/// 「恰一胜者」语义丢弃（另一写者按 exit 2 干净失败，不会留下永久歧义）。
///
/// **残余明示**（dev-reviewer 原子性边界）：本自愈是命令层收敛，非
/// `create-if-absent` 式数据库原子（cf_session 无该 API，加装跨 crate 成本高）。
/// 覆盖所有非崩溃交错；唯一残余 = 两个进程均在「create 之后、prune_race 之前」
/// 的毫秒窗口内被硬杀（SIGKILL）→ 可能残留 2 个同名容器（永久歧义，用 `--id`
/// 或手动清理可解）。正常运行（无崩溃）下不会出现。
fn prune_race(session: &VaultSession, name: &str, own: &str) -> Result<(), SetEnvError> {
    let same = env_containers(session, name)?;
    if same.len() <= 1 {
        return Ok(());
    }
    match same.iter().min() {
        Some(survivor) if survivor.as_str() == own => {
            for u in &same {
                if u != own {
                    delete_container_idempotent(session, u);
                }
            }
            Ok(())
        }
        _ => {
            delete_container_idempotent(session, own);
            Err(SetEnvError::EnvConcurrentCreate(name.to_string()))
        }
    }
}

/// 瞬时锁争用判定：vault 连接未设 busy_timeout，并发写（create/update/delete）
/// 可能以 `database is locked`（SQLITE_BUSY）失败——此类可重试，确定性错误不可。
const BUSY_MARKER: &str = "database is locked";

fn is_busy(e: &cf_domain::CfError) -> bool {
    matches!(
        e,
        cf_domain::CfError::StorageError(m) if m.contains(BUSY_MARKER)
    )
}

/// 有界重试次数 / 间隔（并发写 BUSY 缓解：每次约 20ms，10 次 ≈ 200ms 上限）。
const BUSY_RETRY: usize = 10;

/// 幂等删除容器（H-1 并发清理）：vault 连接未设 busy_timeout，并发写可能
/// SQLITE_BUSY——做有界重试；被删项不存在（他方已删）视为成功（幂等）。
/// 最后仍失败则尽力而为（收敛残余，见 [`prune_race`] 文档）。
fn delete_container_idempotent(session: &VaultSession, id: &str) {
    for attempt in 0..BUSY_RETRY {
        if session.delete_item(id, true).is_ok() {
            return;
        }
        if attempt + 1 >= BUSY_RETRY {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// 自动建容器（SecureNote + [`ENV_TAG`]，无字段）。
///
/// H-1 并发安全：守卫 1 挡顺序重复（镜像 [`CofferStoreProvider::create_environment`]
/// 的 `environment_exists` 查重，coffer.rs:354）；守卫 2 [`prune_race`] 在并发
/// 双建时按 uuid tie-break 收敛到恰 1 容器。创建失败 → 存储错误（退出 1，
/// fail-closed——不写库）。
///
/// BUSY 有界重试：vault 连接未设 busy_timeout，并发首写可能瞬时 `database is
/// locked`——每次重试前重查守卫（对方可能已建成 → 干净 exit 2 而非重复建）。
fn auto_create_environment(session: &VaultSession, name: &str) -> Result<String, SetEnvError> {
    let mut attempt = 0;
    loop {
        if !env_containers(session, name)?.is_empty() {
            return Err(SetEnvError::EnvConcurrentCreate(name.to_string()));
        }
        match session.create_item(&fresh_container_draft(name)) {
            Ok(own) => {
                prune_race(session, name, &own)?;
                return Ok(own);
            }
            Err(e) if is_busy(&e) && attempt + 1 < BUSY_RETRY => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => return Err(SetEnvError::Storage),
        }
    }
}

/// 目标定位总入口：`--id` 优先（互斥已由 [`parse_args`] 保证）；否则 `--scope`。
fn resolve_target(
    session: &VaultSession,
    opts: &SetEnvOptions,
) -> Result<ResolvedTarget, SetEnvError> {
    if let Some(id) = &opts.id {
        return resolve_by_id(session, id);
    }
    let scope = opts.scope.as_deref().ok_or(SetEnvError::MissingScope)?;
    resolve_by_scope(session, scope)
}

/// 成功消息中列出的受影响 NAME（docs/36 §4.7 输出只含 NAME 与容器名）。
fn affected_names(opts: &SetEnvOptions) -> Vec<&str> {
    if !opts.unset.is_empty() {
        return opts.unset.iter().map(String::as_str).collect();
    }
    let mut names: Vec<&str> = opts.pairs.iter().map(|(n, _)| n.as_str()).collect();
    if let Some(n) = &opts.stdin_name {
        names.push(n);
    }
    names
}

/// 目标容器标题（成功消息用）。
fn target_title(target: &ResolvedTarget) -> String {
    match target {
        ResolvedTarget::Existing(d) => d.title.expose().to_string(),
        ResolvedTarget::Fresh { title, .. } => title.clone(),
    }
}

/// 第 4 步：构建 draft（既有容器经 `draft_from_details` 整换重建 / 新建空容器）+
/// 应用写入（NAME=VALUE 或 `--unset`）→ update（`update_item` 自动 append 历史，
/// FR-2.9）。
///
/// **无内容变化不写库**（幂等语义，AC-36.1-7）：应用写入后 draft 与写入前
/// 逐字段无差异（如 `--unset` 删除不存在的 NAME、`NAME=VALUE` 现值相同）→
/// 跳过 `update_item`，不 append 历史、不推进 updated_at——与 FR-2.9
/// 「内容无变化不写」同界（`update_item` 的 no-change 检测需既有历史快照，
/// 首写基线无法经其判等，故在本层先短路）。
///
/// 明文临时缓冲（draft 中 VALUE 副本）在返回前**统一清零**——成功与失败分支
/// 一致（M-3，镜像 set-password 纪律）。
fn apply_write(
    session: &VaultSession,
    target: &ResolvedTarget,
    opts: &SetEnvOptions,
    stdin_value: Option<&str>,
) -> Result<(), (String, i32)> {
    let (id, details) = match target {
        ResolvedTarget::Existing(d) => (d.uuid.clone(), Some(d)),
        ResolvedTarget::Fresh { uuid, .. } => (uuid.clone(), None),
    };
    let mut draft = match details {
        Some(d) => crate::provider::coffer::draft_from_details(d),
        None => fresh_container_draft(&target_title(target)),
    };
    let mut reference = draft.clone();

    if opts.unset.is_empty() {
        for (name, value) in &opts.pairs {
            apply_pair(&mut draft, name, value);
        }
        if let Some(name) = &opts.stdin_name {
            let value = stdin_value.ok_or_else(|| {
                (
                    "internal error: missing stdin value for bare NAME".to_string(),
                    exit_codes::UNLOCK_FAILED,
                )
            })?;
            apply_pair(&mut draft, name, value);
        }
    } else {
        apply_unset(&mut draft, &opts.unset);
    }

    // 无内容变化（幂等 unset 删除缺失名 / 现值相同）→ 不写库、不 append 历史。
    // 否则单事务 update；瞬时 `database is locked`（并发写无 busy_timeout）做
    // 有界重试（详见 [`auto_create_environment`]），确定性错误立即映射退出码。
    let result = if draft == reference {
        Ok(())
    } else {
        let mut attempt = 0;
        loop {
            match session.update_item(&id, &draft) {
                Ok(()) => break Ok(()),
                Err(e) if is_busy(&e) && attempt + 1 < BUSY_RETRY => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => break Err(map_store_error(e, &id)),
            }
        }
    };

    // 明文临时缓冲用后 zeroize（M-3）：draft 与 reference（`draft.clone()`
    // 的既有字段副本，M-1）内 VALUE 副本成功/失败分支一致清零——比较完成后
    // 两者都不再需要。
    for f in &mut draft.fields {
        if let Some(v) = &mut f.value {
            v.zeroize();
        }
    }
    for f in &mut reference.fields {
        if let Some(v) = &mut f.value {
            v.zeroize();
        }
    }
    result
}

/// 存储操作（create / update）`CfError` → (消息, 退出码)（docs/36 §4.5 一次性写
/// 命令映射）：条目消失 → 2；校验/参数被拒（目标不可用，如 Trashed/Archived）→
/// 2；库锁定 → 1；其余 → 1。
fn map_store_error(e: cf_domain::CfError, target: &str) -> (String, i32) {
    match e {
        cf_domain::CfError::ItemNotFound => (
            format!("条目不存在（可能已被删除），未写入：{target}"),
            exit_codes::TARGET_NOT_FOUND,
        ),
        cf_domain::CfError::Validation(m) | cf_domain::CfError::InvalidArgument(m) => (
            format!("写入被拒（目标不可用 / 校验失败），未写入：{m}"),
            exit_codes::TARGET_NOT_FOUND,
        ),
        cf_domain::CfError::VaultLocked => (
            "库已锁定，未写入".to_string(),
            exit_codes::UNLOCK_FAILED,
        ),
        other => (
            format!("写入失败，未写入：{other}"),
            exit_codes::UNLOCK_FAILED,
        ),
    }
}

/// `set-env` 入口（`cli::run` 分派）：读 env（库路径 / 兜底密码）→ 委托
/// [`run_with`]（escrow 用平台默认）。返回进程退出码（docs/36 §4.5）。
pub fn run(args: &[String]) -> i32 {
    let mut logger = Logger::stderr();
    // 用法校验最先（docs/36 §4.4）：参数/用法错（退出码 4）无需库配置即可判定，
    // 先于 vault 定位检查——避免缺 $COFFER_VAULT_DIR 环境时把用法错误报为 1。
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            logger.error(&e.to_string());
            return e.exit_code();
        }
    };

    // vault 定位：`COFFER_VAULT_DIR` 必填（缺 = 定位失败 → 退出码 1）。
    let vault_dir = match std::env::var("COFFER_VAULT_DIR") {
        Ok(v) if !v.trim().is_empty() => std::path::PathBuf::from(v),
        _ => {
            logger.error("set-env 需要 $COFFER_VAULT_DIR（库目录路径，docs/20 §4.5）");
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

/// 内部入口（escrow / stdin / 库路径可注入，测试用）：五步编排——1 读 stdin 值
/// （裸 NAME 档）→ 2 解锁 → 3 定位（可自动建容器）→ 4 写入 → 5 报告。返回进程
/// 退出码（docs/36 §4.5）。
///
/// `run` 负责参数解析 + env 收集后委托本函数；测试经本函数注入 mock escrow /
/// 管道 reader（已解析选项），覆盖写入成功 / 自动建容器 / fail-closed 分支。
fn run_with(
    stdin: &mut dyn BufRead,
    hide: bool,
    opts: &SetEnvOptions,
    vault_dir: &std::path::Path,
    env_password: Option<SecretString>,
    escrow: &dyn VaultEscrowStore,
) -> i32 {
    let mut logger = Logger::stderr();

    // 1. 读 stdin 值（裸 NAME 档，TTY 隐藏 / 管道直读）——先验用户输入，
    //    早于取密解锁（docs/36 §4.4 校验顺序）。空值合法；NUL 拒收（用法 4）。
    let stdin_value = match &opts.stdin_name {
        Some(name) => match read_value_line(stdin, hide, &format!("{name}（输入不显示）: ")) {
            Ok(v) => Some(v),
            Err(e) => {
                logger.error(&e.to_string());
                return e.exit_code();
            }
        },
        None => None,
    };
    if let Some(v) = &stdin_value {
        if v.expose().contains('\0') {
            logger.error(&SetEnvError::ValueContainsNul.to_string());
            return exit_codes::USAGE_ERROR;
        }
    }

    // 2. 取密链解锁（escrow → env 兜底 → fail-closed，D-4）。`unlock_vault`
    //    沿用 MCP 服务器码返回；一次性写命令在此统一归并到退出码 1。
    let session = match crate::cli::unlock_vault(vault_dir, escrow, env_password, &mut logger) {
        Ok(s) => s,
        Err(_) => return exit_codes::UNLOCK_FAILED,
    };

    // 3. 目标定位（歧义 / 非容器不写库，退出 2；scope 缺失自动建容器）。
    let target = match resolve_target(&session, opts) {
        Ok(t) => t,
        Err(e) => {
            logger.error(&e.to_string());
            return e.exit_code();
        }
    };
    let title = target_title(&target);

    // 4. 写入（一次 update_item 原子写，FR-2.9 历史 append）。
    if let Err((msg, code)) = apply_write(
        &session,
        &target,
        opts,
        stdin_value.as_ref().map(SecretString::expose),
    ) {
        logger.error(&msg);
        return code;
    }

    // 5. 报告（stdout 只含 NAME 与容器名，**不含 VALUE 明文**，docs/36 §3 / §4.7）。
    let joined = affected_names(opts).join(", ");
    if opts.unset.is_empty() {
        println!("已写入环境容器 {title}（{joined}）· 旧版本可在 App 历史中回滚");
    } else {
        println!("已从环境容器 {title} 移除（{joined}）· 旧版本可在 App 历史中回滚");
    }
    exit_codes::SUCCESS
}

// ===========================================================================
// 单元测试 —— 拆至 `set_env_tests.rs`（docs/36 §8.1 [2]，与 set_password_tests.rs
// 同模式）。`#[path]` 使测试仍为同 crate 单元测试（可访问私有项）。
// ===========================================================================

#[cfg(test)]
#[path = "set_env_tests.rs"]
mod tests;
