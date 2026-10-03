//! 1Password CLI（`op`）数据源 —— OpProvider（docs/20 §4.2，MVP 数据源）。
//!
//! # 协议承载
//!
//! | provider 方法 | op 命令 | 说明 |
//! | --- | --- | --- |
//! | `list_secret_names` / `list_secrets` | `op item list [--vault <v>] --format json` | 元数据数组，**无值** |
//! | `get_secret_metadata` | `op item get <id> [--vault <v>] --format json` | 单条目元数据（`op://` 引用先拆出 vault+item） |
//! | `run_with_secret` | 写临时 dotenv（0600）→ `op run --env-file <tmp> -- <cmd> <args>` | 值由 op 直接注入目标子进程环境 |
//!
//! # 明文暴露面（docs/20 §4.4）
//!
//! `run_with_secret` 的明文只在 **op 子进程与目标子进程之间**流转：cf-mcp 进程
//! 内存**不出现** Secret 明文（临时 dotenv 只含 `ENV_NAME=op://…` 引用，无值；
//! 用后即毁）。list/meta 全程无值。
//!
//! # 会话 token（docs/20 §4.2）
//!
//! `COFFER_OP_SESSION_TOKEN` 透传给 op 子进程为 `OP_SESSION`，**不经 argv、
//! 不经协议帧、不进日志**。`OpProviderConfig` 的 `Debug` 对 token 打码。
//!
//! # 错误归一（docs/20 §3.4 的 7xxx 段）
//!
//! op 的 stderr **不回显进错误载荷**（防泄露）——仅按关键字归类后给出稳定文案：
//! `not signed in` → 7002；item/vault 未找到、引用无法解析 → 7003；子进程无法
//! 启动 → 7004。`run_with_secret` 的子进程非零退出**不打 [ERROR]**（实测
//! op 2.32.1），作为退出码原样返回（mcp_acceptance 契约）。

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use cf_domain::secret::SecretString;

use super::{ProviderError, RunSpec, SecretMeta, SecretProvider};

/// `OpProvider` 配置（docs/20 §4.3 环境变量约定）。
///
/// 字段来源：`COFFER_OP_BIN` / `COFFER_OP_VAULT` / `COFFER_OP_SESSION_TOKEN`。
/// 测试经直接构造注入 fake `op` 路径（不读进程环境，避免用例间污染）。
pub struct OpProviderConfig {
    /// `op` 二进制路径；缺省 `op`（`PATH` 查找）。
    pub op_bin: PathBuf,
    /// 默认 vault 名（`COFFER_OP_VAULT`）；未给时省略 `--vault`。
    pub default_vault: Option<String>,
    /// 会话 token（`COFFER_OP_SESSION_TOKEN`），透传给 `op` 子进程为 `OP_SESSION`。
    /// `SecretString`：密钥材料零化持有（docs/20 §3.5-4），不经 argv/日志/协议帧。
    pub session_token: Option<SecretString>,
}

impl OpProviderConfig {
    /// 从进程环境变量构造（docs/20 §4.3）。
    ///
    /// - `COFFER_OP_BIN` → [`OpProviderConfig::op_bin`]，缺省 `op`（`PATH` 查找）
    /// - `COFFER_OP_VAULT` → [`OpProviderConfig::default_vault`]
    /// - `COFFER_OP_SESSION_TOKEN` → [`OpProviderConfig::session_token`]
    #[must_use]
    pub fn from_env() -> Self {
        let op_bin = std::env::var("COFFER_OP_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("op"));
        Self {
            op_bin,
            default_vault: std::env::var("COFFER_OP_VAULT").ok(),
            session_token: std::env::var("COFFER_OP_SESSION_TOKEN")
                .ok()
                .map(SecretString::from_exposed),
        }
    }
}

/// 会话 token 属密钥材料：`Debug` 打码（L-1 纪律延伸，docs/20 §3.5-4）。
impl std::fmt::Debug for OpProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpProviderConfig")
            .field("op_bin", &self.op_bin)
            .field("default_vault", &self.default_vault)
            .field("session_token", &"***")
            .finish()
    }
}

// `OpProviderConfig` 不复用派生 Clone：`SecretString` 无 Clone（zeroize 纪律——
// 敏感串不隐式复制），会话 token 经 `from_exposed` 显式重建，语义等价但意图可见。
impl Clone for OpProviderConfig {
    fn clone(&self) -> Self {
        Self {
            op_bin: self.op_bin.clone(),
            default_vault: self.default_vault.clone(),
            session_token: self
                .session_token
                .as_ref()
                .map(|s| SecretString::from_exposed(s.expose())),
        }
    }
}

/// 1Password CLI（`op`）数据源。
///
/// 构造即校验 `op` 可执行（`op --version` 启动探测）；不可用 → 7001。
pub struct OpProvider {
    config: OpProviderConfig,
}

/// 委托 [`OpProviderConfig`] 的掩码 `Debug`（session token 不打入日志）。
impl std::fmt::Debug for OpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpProvider").field("config", &self.config).finish()
    }
}

impl OpProvider {
    /// 构造并探测 `op` 可用性。
    ///
    /// `op` 不存在 / 不可执行 / 启动探测失败 → [`ProviderError::ProviderUnavailable`]
    /// （7001）。
    pub fn new(config: OpProviderConfig) -> Result<Self, ProviderError> {
        // 启动探测：`op --version`（无需会话即成功，实测 op 2.32.1）。
        let mut probe = Command::new(&config.op_bin);
        probe.arg("--version");
        probe.stdout(Stdio::null()).stderr(Stdio::null());
        match probe.status() {
            Ok(status) if status.success() => {}
            Ok(_) => {
                return Err(ProviderError::Unavailable(format!(
                    "op binary {} reported an error during startup probe",
                    config.op_bin.display()
                )))
            }
            Err(e) => {
                return Err(ProviderError::Unavailable(format!(
                    "failed to run op {}: {e}",
                    config.op_bin.display()
                )))
            }
        }
        Ok(Self { config })
    }

    /// 从进程环境变量构造（`COFFER_OP_BIN` / `COFFER_OP_VAULT` /
    /// `COFFER_OP_SESSION_TOKEN`，docs/20 §4.3）。
    pub fn from_env() -> Result<Self, ProviderError> {
        Self::new(OpProviderConfig::from_env())
    }

    /// 拼装 `op` 命令；会话 token 只经环境变量（`OP_SESSION`）下发，
    /// 不经 argv（docs/20 §3.5-5 / §4.2）。
    fn op_command(&self) -> Command {
        let mut cmd = Command::new(&self.config.op_bin);
        if let Some(token) = &self.config.session_token {
            cmd.env("OP_SESSION", token.expose());
        }
        cmd
    }

    /// 运行 op 命令。spawn 失败（op 消失/不可执行）→ 7001。
    fn spawn_op(&self, cmd: &mut Command) -> Result<Output, ProviderError> {
        cmd.output().map_err(|e| {
            ProviderError::Unavailable(format!("failed to run op: {e}"))
        })
    }

    /// `op item list [--vault <v>] --format json` → 条目元数据（无值）。
    fn op_item_list(&self, vault: Option<&str>) -> Result<Vec<OpItem>, ProviderError> {
        let vault = vault.or(self.config.default_vault.as_deref());
        let mut cmd = self.op_command();
        cmd.arg("item").arg("list");
        if let Some(v) = vault {
            cmd.arg("--vault").arg(v);
        }
        cmd.arg("--format").arg("json");
        let output = self.spawn_op(&mut cmd)?;
        if !output.status.success() {
            return Err(classify_list_failure(&output));
        }
        parse_op_json::<Vec<OpItem>>(&output.stdout)
    }
}

impl SecretProvider for OpProvider {
    fn list_secret_names(&self, vault: Option<&str>) -> Result<Vec<String>, ProviderError> {
        Ok(self
            .op_item_list(vault)?
            .into_iter()
            .map(|item| item.title)
            .filter(|title| !title.trim().is_empty())
            .collect())
    }

    fn list_secrets(&self, vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError> {
        Ok(self.op_item_list(vault)?.into_iter().map(OpItem::into_meta).collect())
    }

    fn get_secret_metadata(&self, secret_ref: &str) -> Result<SecretMeta, ProviderError> {
        // 边界校验与 run 面同口径（L-6/dev-reviewer）：`op://` 无 item / 明文值等
        // 畸形引用在入界即拒 7005，不落到 `op item get` 上按 7003 归类。消息不带
        // 入参回显（§3.4，M-5）。元数据面兼容裸 item id（list 返回的稳定标识）。
        if !is_valid_secret_ref(secret_ref) {
            return Err(ProviderError::InvalidParameter(
                "secret_ref is not a valid secret reference".to_string(),
            ));
        }
        // `op item get` 不接受 `op://` 引用（实测 op 2.32.1），须先拆出 vault+item。
        let (item, vault_from_ref) = parse_secret_ref(secret_ref);
        let vault = vault_from_ref.or_else(|| self.config.default_vault.clone());

        let mut cmd = self.op_command();
        cmd.arg("item").arg("get").arg(&item);
        if let Some(v) = &vault {
            cmd.arg("--vault").arg(v);
        }
        cmd.arg("--format").arg("json");
        let output = self.spawn_op(&mut cmd)?;
        if !output.status.success() {
            return Err(classify_list_failure(&output));
        }
        Ok(parse_op_json::<OpItem>(&output.stdout)?.into_meta())
    }

    fn run_with_secret(&self, spec: &RunSpec) -> Result<i32, ProviderError> {
        validate_run_spec(spec)?;
        // 写临时 dotenv（0600）：仅含 `ENV_NAME=op://…` 引用，**无明文值**；
        // `op run` 自行解析并注入目标子进程（docs/20 §4.4）。用后即毁（RAII）。
        let env_file = TempDotenv::write(spec)?;

        let mut cmd = self.op_command();
        cmd.arg("run").arg("--env-file").arg(&env_file.path);
        cmd.arg("--");
        cmd.arg(&spec.cmd);
        cmd.args(&spec.args);
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        // MCP stdio 下 stdout 是协议帧，不得让目标子进程输出混入（docs/20 §3.1）：
        // 丢弃 stdout，仅捕获 stderr 用于 op 层错误分类。
        cmd.stdout(Stdio::null());
        let output = self.spawn_op(&mut cmd)?;
        // 此处 env_file 已不再需要；出作用域即删除（用后即毁，AS-5 模式 C 纪律同构）。

        if output.status.success() {
            return Ok(0);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !is_op_level_error(&stderr) {
            // 子进程失败：op run 原样传播其退出码（实测 op 2.32.1 不打 [ERROR]），
            // 契约（mcp_acceptance）：退出码作 i32 返回，不吞、不误报 Err。
            return Ok(output.status.code().unwrap_or(1));
        }
        Err(classify_run_failure(&stderr))
    }
}

// ===========================================================================
// 校验与引用解析
// ===========================================================================

/// `run_with_secret` 入参校验（边界校验，失败即 7005）。
///
/// run 协议（docs/20 §4.2）承载于临时 dotenv：内容为 `ENV_NAME=op://vault/item/field`
/// 引用，`op run` 只解析 `op://` 形态——裸 item id / 明文会被**当字面量**注入子进程
/// env（静默注入错误"值"，H-1/dev-reviewer）。故 run 面只接受 `op://` 引用。
fn validate_run_spec(spec: &RunSpec) -> Result<(), ProviderError> {
    if spec.secret_ref.trim().is_empty() {
        return Err(ProviderError::InvalidParameter("secret_ref is empty".to_string()));
    }
    if spec.secret_ref.contains('\n') {
        // dotenv 注入防护：`\n` 会插入额外的环境变量行。
        return Err(ProviderError::InvalidParameter("secret_ref contains newline".to_string()));
    }
    if !spec.secret_ref.starts_with("op://") {
        // H-1：裸 item id / 明文不属于 run 面——`op run` 对其不解析，注入的是字面量。
        return Err(ProviderError::InvalidParameter(
            "secret_ref must be an op:// reference".to_string(),
        ));
    }
    if !is_valid_secret_ref(&spec.secret_ref) {
        // 结构校验（docs/20 §4.4）：op:// 引用须 vault/item 非空、无控制字符。
        // 消息不带入参回显（§3.4：7xxx 载荷不得含 Secret 值，M-5）。
        return Err(ProviderError::InvalidParameter(
            "secret_ref is not a valid op:// reference".to_string(),
        ));
    }
    if !is_valid_env_name(&spec.env_name) {
        return Err(ProviderError::InvalidParameter(
            "env_name is not a valid environment variable name".to_string(),
        ));
    }
    if spec.cmd.trim().is_empty() {
        return Err(ProviderError::InvalidParameter("cmd is empty".to_string()));
    }
    if let Some(cwd) = &spec.cwd {
        if !cwd.is_dir() {
            return Err(ProviderError::InvalidParameter(
                "cwd is not a directory".to_string(),
            ));
        }
    }
    Ok(())
}

/// 环境变量名合法性：`[A-Za-z_][A-Za-z0-9_]*`（dotenv 注入防护的另一半）。
fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// `secret_ref` 形态校验（docs/20 §4.4「cf-mcp 不出现 Secret 明文」不变量结构面）。
///
/// 契约是「`op://` 引用或 item id，非明文值」。此处把该不变量从约定升为结构：
///
/// - `op://<vault>/<item>[/<field>]`：vault 与 item 均非空；
/// - 其余形态：仅安全字符集 item id（无空白/控制字符，避免 dotenv 注入歧义）。
///
/// 调用方语义：run 面（[`validate_run_spec`]）先要求 `op://` 前缀再走本校验
/// （H-1：裸 id 会被 `op run` 当字面量注入子进程 env）；元数据面
/// （[`get_secret_metadata`](SecretProvider::get_secret_metadata)）两者皆可。
/// 不匹配 → 7005（由调用方转为 [`ProviderError::InvalidParameter`]）。
fn is_valid_secret_ref(secret_ref: &str) -> bool {
    if secret_ref.trim().is_empty() || secret_ref.contains('\n') {
        return false;
    }
    if let Some(rest) = secret_ref.strip_prefix("op://") {
        // `vault/item[/field]`；vault 与 item 至少各一段，且无控制字符/换行。
        // item 名可含空格与 `/`（op 允许），此处不拒绝——引用形态已明确非明文。
        let mut parts = rest.split('/');
        let vault = parts.next().unwrap_or("");
        let item = parts.next().unwrap_or("");
        !vault.is_empty()
            && !item.is_empty()
            && !vault.chars().any(char::is_control)
            && !vault.contains('\n')
            && !item.contains('\n')
    } else {
        // item id：安全字符集（无空白/控制字符）。明文值通常含空格 → 被拒，
        // 由此把「secret_ref 非明文」从不变量约定升为结构约束。
        secret_ref.chars().all(|c| !c.is_control() && !c.is_whitespace())
    }
}

/// 解析 Secret 引用为 `(item 标识, vault)`（docs/20 §3.3/§4.2）。
///
/// - `op://<vault>/<item>[/<field>]`：拆出 vault 与 item（item 名可含 `/`，
///   末段若为 field 则剥除）；`op item get` 不接受 `op://` 引用（实测 op 2.32.1）。
/// - 其余形态：原样作 item 标识，vault 取默认（`None`）。
fn parse_secret_ref(secret_ref: &str) -> (String, Option<String>) {
    let Some(rest) = secret_ref.strip_prefix("op://") else {
        return (secret_ref.to_string(), None);
    };
    let mut parts: Vec<&str> = rest.split('/').collect();
    if parts.is_empty() {
        return (secret_ref.to_string(), None);
    }
    let vault = parts.remove(0).to_string();
    if vault.is_empty() {
        return (secret_ref.to_string(), None);
    }
    let item = if parts.len() > 1 {
        parts[..parts.len() - 1].join("/")
    } else {
        parts.first().copied().unwrap_or("").to_string()
    };
    if item.is_empty() {
        return (secret_ref.to_string(), Some(vault));
    }
    (item, Some(vault))
}

// ===========================================================================
// 错误归一（docs/20 §3.4 的 7xxx 段；op stderr 不回显进载荷）
// ===========================================================================

/// 判断 stderr 是否由 op 层产生（`[ERROR] YYYY/MM/DD HH:MM:SS …` 前缀，实测
/// op 2.32.1 格式）。目标子进程经 `op run` 透传的 stderr 也汇入同一缓冲，其
/// 自带日志若含字面 `[ERROR]`（如 `[ERROR] 2026/…` 之外的形态）**不**误判为
/// op 层失败 —— 契约：子进程非零退出必须原样返回退出码，不吞、不误报 Err。
///
/// 残余边界（M-6/dev-reviewer，已登记 KNOWN-ISSUES）：若子进程日志**恰好**为
/// `[ERROR] YYYY/MM/DD HH:MM:SS …` 时间戳形态**且**命中关键字（`could not find`
/// 等），仍会误判为 op 层失败并归一为 7003/7004/7006——`op run` 把 op 与子进程
/// stderr 汇入同一缓冲，无可靠区分手段。MVP 接受该启发式边界（子进程输出不受控，
/// §3.5-3 诚实边界延伸）；修复需分隔两路 stderr（op 无原生开关）。
fn is_op_level_error(stderr: &str) -> bool {
    // `[ERROR] YYYY/MM/DD HH:MM:SS `：前缀 + 时间戳。仅子串匹配会误伤子进程
    // 日志（任何 `[ERROR]` 开头的行），故要求前缀后紧跟日期形态。
    stderr.lines().any(|line| {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("[ERROR] ") else {
            return false;
        };
        // `YYYY/MM/DD HH:MM:SS `：索引 0-3 年 / 4 `/` / 5-6 月 / 7 `/` / 8-9 日 /
        // 10 空格 / 11-12 时 / 13 `:` / 14-15 分 / 16 `:` / 17-18 秒。
        let bytes = rest.as_bytes();
        bytes.len() >= 20
            && bytes[4] == b'/'
            && bytes[7] == b'/'
            && bytes[10] == b' '
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes.iter().take(4).all(|b| b.is_ascii_digit())
            && bytes[5..7].iter().all(|b| b.is_ascii_digit())
            && bytes[8..10].iter().all(|b| b.is_ascii_digit())
    })
}

/// list / get 面：op 非零退出 → 按 stderr 关键字归类。
fn classify_list_failure(output: &Output) -> ProviderError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not signed in") {
        ProviderError::AuthRequired("op requires sign-in".to_string())
    } else if stderr.contains("isn't an item")
        || stderr.contains("could not resolve")
        || stderr.contains("could not find")
        || stderr.contains("isn't a vault")
    {
        ProviderError::NotFound("secret not found".to_string())
    } else {
        ProviderError::Internal("op output classification failed".into())
    }
}

/// run 面：op run 自身失败（stderr 含 `[ERROR]` 前缀）→ 按关键字归类。
fn classify_run_failure(stderr: &str) -> ProviderError {
    if stderr.contains("not signed in") {
        ProviderError::AuthRequired("op requires sign-in".to_string())
    } else if stderr.contains("could not resolve")
        || stderr.contains("could not find")
        || stderr.contains("isn't an item")
        || stderr.contains("isn't a vault")
    {
        ProviderError::NotFound("secret not found".to_string())
    } else if stderr.contains("error while starting process") {
        ProviderError::SubprocessFailed { exit_code: None, detail: "op could not start the child command".to_string() }
    } else {
        ProviderError::Internal("op output classification failed".into())
    }
}

/// 解析 op 的 JSON 输出；非 UTF-8 或结构不符 → 7006（内部错误，不泄露细节）。
fn parse_op_json<T: serde::de::DeserializeOwned>(stdout: &[u8]) -> Result<T, ProviderError> {
    let text = String::from_utf8(stdout.to_vec()).map_err(|_| ProviderError::Internal("op output is not UTF-8".into()))?;
    serde_json::from_str(&text).map_err(|_| ProviderError::Internal("op output is not valid JSON".into()))
}

// ===========================================================================
// op JSON 模型（仅元数据面；`fields` 等未知字段由 serde 忽略）
// ===========================================================================

/// op item 元数据（list 与 get 共用；get 输出含 `fields` 但本模型不取）。
#[derive(Debug, Deserialize)]
struct OpItem {
    id: String,
    title: String,
    #[serde(default)]
    category: String,
    vault: OpVaultRef,
    updated_at: Option<String>,
}

/// op vault 引用（仅取 `name`；`id` 等其余字段由 serde 忽略）。
#[derive(Debug, Deserialize)]
struct OpVaultRef {
    name: String,
}

impl OpItem {
    fn into_meta(self) -> SecretMeta {
        SecretMeta {
            name: self.title,
            id: self.id,
            vault: self.vault.name,
            category: self.category,
            updated_at: self.updated_at.as_deref().and_then(parse_rfc3339_utc),
        }
    }
}

// ===========================================================================
// 临时 dotenv（用后即毁，0600）
// ===========================================================================

/// 本进程内临时 dotenv 序号（与 pid+纳秒叠加，规避 BUG-12 撞名）。
static ENV_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 临时 dotenv 文件（RAII：析构即删除）。
struct TempDotenv {
    path: PathBuf,
}

impl TempDotenv {
    /// 写 `ENV_NAME=op://…` 到临时文件（Unix 下权限 0600）。
    ///
    /// 内容**无明文值**（docs/20 §4.4）；IO 失败归 7006（内部错误）。
    fn write(spec: &RunSpec) -> Result<Self, ProviderError> {
        let path = temp_env_path();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            let mut f = opts.open(&path).map_err(|_| ProviderError::Internal("temporary env file I/O failed".into()))?;
            writeln!(f, "{}={}", spec.env_name, spec.secret_ref)
                .map_err(|_| ProviderError::Internal("temporary env file I/O failed".into()))?;
        }
        #[cfg(not(unix))]
        {
            let mut f = std::fs::File::create(&path).map_err(|_| ProviderError::Internal("temporary env file I/O failed".into()))?;
            writeln!(f, "{}={}", spec.env_name, spec.secret_ref)
                .map_err(|_| ProviderError::Internal("temporary env file I/O failed".into()))?;
        }
        Ok(Self { path })
    }
}

impl Drop for TempDotenv {
    fn drop(&mut self) {
        // 用后即毁：忽略删除错误（临时目录清理失败不升级为业务错误）。
        let _ = std::fs::remove_file(&self.path);
    }
}

/// 生成进程内唯一的临时 dotenv 路径。
fn temp_env_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = ENV_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "coffer-mcp-env-{}-{nanos}-{counter}",
        std::process::id()
    ))
}

// ===========================================================================
// RFC 3339 UTC 时间戳 → Unix 秒
// ===========================================================================

/// 解析 RFC 3339 UTC 时间戳（`YYYY-MM-DDTHH:MM:SS[.fff…]Z`）为 Unix 秒。
///
/// 仅接受 `Z`/`z` 结尾（op 输出恒为 UTC，实测 op 2.32.1）；带非零偏移量或字段
/// 越界返回 `None`。改编自 cf-importer `bitwarden/parser.rs::parse_rfc3339_utc`
/// （同仓 MIT，复用其无 chrono 依赖的整数算法）。
#[must_use]
fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let digit = |r: std::ops::Range<usize>| -> Option<i64> {
        let mut n: i64 = 0;
        for &c in &b[r] {
            if !c.is_ascii_digit() {
                return None;
            }
            n = n * 10 + i64::from(c - b'0');
        }
        Some(n)
    };
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digit(0..4)?, digit(5..7)?, digit(8..10)?);
    let (hour, minute, second) = (digit(11..13)?, digit(14..16)?, digit(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // 尾部：允许 `Z`/`z`；小数秒（`.` + 数字）后仍须 `Z`/`z`。
    let mut tail = &s[19..];
    if let Some(rest) = tail.strip_prefix('.') {
        let digits_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits_end == 0 {
            return None;
        }
        tail = &rest[digits_end..];
    }
    match tail {
        "Z" | "z" => {}
        _ => return None,
    }

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Howard Hinnant `days_from_civil`（公历日期 → 自 1970-01-01 的天数）。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

// ===========================================================================
// 单元测试（纯函数面；协议面见 tests/provider_op_*.rs）
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_utc_z_form() {
        assert_eq!(parse_rfc3339_utc("2026-08-01T12:30:00Z"), Some(1_785_587_400));
        assert_eq!(parse_rfc3339_utc("2026-08-01T12:30:00.000Z"), Some(1_785_587_400));
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        // 大小写容差（op 实测输出大写 Z）
        assert_eq!(parse_rfc3339_utc("2026-08-01T12:30:00z"), Some(1_785_587_400));
    }

    #[test]
    fn rejects_rfc3339_offsets_and_invalid() {
        assert_eq!(parse_rfc3339_utc("2026-08-01T12:30:00+08:00"), None);
        assert_eq!(parse_rfc3339_utc("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc("2026-08-01T24:00:00Z"), None);
        assert_eq!(parse_rfc3339_utc("2026-08-01 12:30:00Z"), None);
        assert_eq!(parse_rfc3339_utc("短"), None);
    }

    #[test]
    fn parses_op_secret_references() {
        // op://vault/item/field → (item, Some(vault))
        assert_eq!(
            parse_secret_ref("op://Personal/OPENAI_API_KEY/password"),
            ("OPENAI_API_KEY".to_string(), Some("Personal".to_string()))
        );
        // op://vault/item（无 field）→ item 原样
        assert_eq!(
            parse_secret_ref("op://Personal/OPENAI_API_KEY"),
            ("OPENAI_API_KEY".to_string(), Some("Personal".to_string()))
        );
        // item 名含 `/`
        assert_eq!(
            parse_secret_ref("op://Personal/a/b/c/password"),
            ("a/b/c".to_string(), Some("Personal".to_string()))
        );
        // 非 op:// 形态 → 原样，vault 取默认
        assert_eq!(
            parse_secret_ref("fixture-item-api-key"),
            ("fixture-item-api-key".to_string(), None)
        );
        // 畸形：仅 op://vault（无 item）→ 原样回退，vault 保留
        assert_eq!(
            parse_secret_ref("op://Personal"),
            ("op://Personal".to_string(), Some("Personal".to_string()))
        );
        // 畸形：空 vault
        assert_eq!(
            parse_secret_ref("op:///item/password"),
            ("op:///item/password".to_string(), None)
        );
    }

    #[test]
    fn validates_env_names() {
        assert!(is_valid_env_name("MY_KEY"));
        assert!(is_valid_env_name("_private"));
        assert!(is_valid_env_name("A1_b2"));
        assert!(!is_valid_env_name(""));
        assert!(!is_valid_env_name("1ABC"));
        assert!(!is_valid_env_name("BAD NAME"));
        assert!(!is_valid_env_name("A=B"));
        assert!(!is_valid_env_name("A\nB"));
        // 非 ASCII 首字符拒绝（op run dotenv 要求 shell 变量名）
        assert!(!is_valid_env_name("环境"));
    }

    #[test]
    fn config_debug_masks_session_token() {
        let config = OpProviderConfig {
            op_bin: PathBuf::from("op"),
            default_vault: None,
            session_token: Some(SecretString::from_exposed("supersecrettoken")),
        };
        let dbg = format!("{config:?}");
        assert!(!dbg.contains("supersecrettoken"), "session token must be masked");
        assert!(dbg.contains("***"));
    }

    #[test]
    fn op_error_detection_requires_timestamp_shape() {
        // M1（dev-reviewer）：op 层错误行 = `[ERROR] YYYY/MM/DD HH:MM:SS …`。
        // 子进程透传的日志若只是含 `[ERROR]` 字样（无时间戳形态），**不**判为
        // op 层失败——否则子进程非零退出会被误报 Err，违反 mcp_acceptance 契约。
        assert!(is_op_level_error("[ERROR] 2026/09/30 15:45:51 account is not signed in"));
        assert!(is_op_level_error("  [ERROR] 2026/09/30 15:45:51 boom"));
        // 子进程日志：`[ERROR]` 开头但非 op 时间戳形态 → 非 op 层错误。
        assert!(!is_op_level_error("[ERROR] something went wrong"));
        assert!(!is_op_level_error("[ERROR] 2026/09/30 boom"));
        assert!(!is_op_level_error("child stdout only"));
        assert!(!is_op_level_error(""));
    }

    #[test]
    fn secret_ref_shape_validation_rejects_plaintext_values() {
        // M3（dev-reviewer）：secret_ref 结构面校验——`op://` 引用或安全字符集
        // item id；明文值/含空白/控制字符一律 7005，保证「明文不落临时 dotenv」。
        assert!(is_valid_secret_ref("op://Personal/OPENAI_API_KEY/password"));
        assert!(is_valid_secret_ref("op://Personal/item with / slash/password"));
        assert!(is_valid_secret_ref("abc123_-./:"));
        assert!(!is_valid_secret_ref(""));
        assert!(!is_valid_secret_ref("op:///item/password"));
        assert!(!is_valid_secret_ref("op://vault//password"));
        assert!(!is_valid_secret_ref("op://vault"));
        assert!(!is_valid_secret_ref("plain secret value here"));
        assert!(!is_valid_secret_ref("has\nnewline"));
        assert!(!is_valid_secret_ref("has\ttab"));
    }
}
