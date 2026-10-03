//! SecretProvider 抽象与注册表（docs/20 §4）。
//!
//! 依赖方向（docs/20 §2.2，硬约束）：cf-mcp 单向依赖下层。MVP 只依赖
//! cf-domain（[`SecretString`]）；**不**依赖 cf-session / cf-store / cf-ffi。
//!
//! ## 模块归属
//!
//! - [`SecretProvider`] trait / [`SecretMeta`] / [`RunSpec`] / [`ProviderError`]：
//!   docs/20 §4.1 **冻结签名**，本文件（G-B）实现；
//! - `mod op`（`OpProvider`，G-C 实现）与 `mod coffer`（`CofferStoreProvider`
//!   骨架，G-C 实现）在本文件以**空壳**声明占位，G-C 合入后替换为文件模块；
//! - [`test_seed`]：验收测试种子 provider（mcp_acceptance.rs 环境变量契约），
//!   仅服务验收用例与本地门面，非生产 provider。

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

/// Secret 元数据（docs/20 §4.1 冻结签名）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMeta {
    /// 展示名（Agent 引用的标识）。
    pub name: String,
    /// provider 内稳定标识（op: item id）。
    pub id: String,
    /// 所属 vault。
    pub vault: String,
    /// op: category / 未来 Coffer: 条目模板名。
    pub category: String,
    /// 最后更新时间（unix 秒）。
    pub updated_at: Option<i64>,
}

/// `run_with_secret` 运行规格（docs/20 §4.1 冻结签名）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSpec {
    /// `op://vault/item/field` 引用或 item id（元数据面兼容裸 id）；**非明文值**。
    /// run 面只接受 `op://` 引用形态（docs/20 §4.2——裸 id 会被 `op run` 当字面量
    /// 注入子进程 env，H-1/dev-reviewer）。
    pub secret_ref: String,
    /// 注入的环境变量名（如 `OPENAI_API_KEY`）。
    pub env_name: String,
    /// 子进程命令。
    pub cmd: String,
    /// 子进程参数。
    pub args: Vec<String>,
    /// 子进程工作目录。
    pub cwd: Option<PathBuf>,
}

/// Provider 错误（docs/20 §4.1；码值映射见 §3.4 / [`crate::error`]）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    /// 7001：Provider 不可用（op 未装 / 不可执行）。
    Unavailable(String),
    /// 7002：需要身份（op 未登录，OP_SESSION 缺失）。
    AuthRequired(String),
    /// 7003：Secret 不存在 / 无权限。
    NotFound(String),
    /// 7004：子进程失败（spawn 失败 / 包装进程非零退出）。
    SubprocessFailed {
        /// 子进程退出码；`None` = spawn 阶段失败（无码）。
        exit_code: Option<i32>,
        /// 归一化后的失败细节（剥离敏感值）。
        detail: String,
    },
    /// 7005：参数 / 协议错误。
    InvalidParameter(String),
    /// 7006：内部错误（不泄露细节）。
    Internal(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(m) => write!(f, "provider unavailable: {m}"),
            Self::AuthRequired(m) => write!(f, "authentication required: {m}"),
            Self::NotFound(m) => write!(f, "secret not found: {m}"),
            Self::SubprocessFailed { exit_code: Some(c), detail } => {
                write!(f, "subprocess failed (exit {c}): {detail}")
            }
            Self::SubprocessFailed { exit_code: None, detail } => {
                write!(f, "subprocess failed: {detail}")
            }
            Self::InvalidParameter(m) => write!(f, "invalid parameter: {m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl Error for ProviderError {}

/// SecretProvider 抽象（docs/20 §4.1 冻结签名）。
///
/// **不变量**：trait 面**无**「返回明文值」方法——`run_with_secret` 把值直接注入
/// 子进程 env（op 侧由 `op run` 解析，值不进 cf-mcp 进程内存）。未来若需 Broker
/// 内部取用（如 audit 记录指纹），经内部 `reveal_for_broker() -> SecretString`
/// （非 trait 公共面，zeroize 保护）。
pub trait SecretProvider: Send + Sync {
    /// 列出全部 secret 名（无值）。
    fn list_secret_names(&self, vault: Option<&str>) -> Result<Vec<String>, ProviderError>;
    /// 列出全部 secret 元数据（无值）。
    fn list_secrets(&self, vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError>;
    /// 取单个 secret 元数据（无值）。
    fn get_secret_metadata(&self, secret_ref: &str) -> Result<SecretMeta, ProviderError>;
    /// 用 secret 运行命令，返回子进程退出码（非零退出**不是**错误，原样返回）。
    fn run_with_secret(&self, spec: &RunSpec) -> Result<i32, ProviderError>;
}

/// Provider 注册表（docs/20 §2.4 provider/mod.rs 职责）。
///
/// 按名字注册/解析 provider；未指定默认时用首注册项。注册表仅做分发表，
/// provider 生命周期由持有者（McpServer / CLI）管理。不 derive `Debug`
/// （`dyn SecretProvider` 不保证 `Debug`）。
#[derive(Default)]
pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn SecretProvider>>,
    default: Option<String>,
}

impl ProviderRegistry {
    /// 空注册表。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个 provider。
    pub fn register(&mut self, name: impl Into<String>, provider: Box<dyn SecretProvider>) {
        if self.default.is_none() {
            let key = name.into();
            self.default = Some(key.clone());
            self.providers.insert(key, provider);
        } else {
            self.providers.insert(name.into(), provider);
        }
    }

    /// 显式指定默认 provider 名。
    pub fn set_default(&mut self, name: impl Into<String>) {
        self.default = Some(name.into());
    }

    /// 按名解析 provider；不存在返回 `None`。
    pub fn get(&self, name: &str) -> Option<&dyn SecretProvider> {
        self.providers.get(name).map(|b| b.as_ref())
    }

    /// 解析默认 provider。
    pub fn resolve_default(&self) -> Option<&dyn SecretProvider> {
        self.default.as_deref().and_then(|n| self.get(n))
    }

    /// 已注册的 provider 名清单。
    pub fn names(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// provider 文件模块（G-C 合入）
// ---------------------------------------------------------------------------

/// `OpProvider`（1Password CLI，MVP 数据源，docs/20 §4.2）。
///
/// 实现见 `provider/op.rs`。默认构建（无 feature）即包含——op 是 MVP 数据源。
/// `pub`：CLI（G-D）构造 [`op::OpProvider`]，集成测试直接引用。
pub mod op;

/// `CofferStoreProvider`（feature `coffer-store` 门控骨架，docs/20 §4.5）。
///
/// 实现见 `provider/coffer.rs`。feature 关闭时本模块不进入构建，cf-mcp
/// 默认依赖树不引入 cf-session（docs/20 §2.2 只下不上）。
#[cfg(feature = "coffer-store")]
mod coffer;

// ---------------------------------------------------------------------------
// 验收测试种子 provider
// ---------------------------------------------------------------------------

pub mod test_seed {
    //! 验收测试种子 provider（mcp_acceptance.rs 环境变量契约）。
    //!
    //! 数据源 = 进程环境变量（`tests/mcp_acceptance.rs` 文件头契约）：
    //!
    //! | 环境变量 | 语义 |
    //! | --- | --- |
    //! | [`ENV_TEST_SEED_NAMES`] | 逗号分隔的、必须已存在的 secret 名清单 |
    //! | [`ENV_TEST_SECRET_PREFIX`]`<NAME>` | secret `<NAME>` 的值（注入子进程 env） |
    //!
    //! provider 无状态：每次调用读取环境变量。测试内的进程级可变状态由用例侧
    //! `ENV_LOCK`（Mutex）串行化——本 provider 不自行加锁（跨线程锁会与用例
    //! 侧锁构成重入，且 lib 侧无进程全局可变状态可串行化）。
    //!
    //! **匿名占位**：测试草稿用 [`ANON_SECRET`]（`ANY_SECRET`）作「不关心值」
    //! 的占位名跑纯子进程执行用例（AS-5 模式 B）；本 provider 恒将其视为
    //! 已存在、值为空。这是对 mcp_acceptance.rs 起草约定的兼容（详见
    //! [`ANON_SECRET`] 文档）；若 lead 裁定严格「未登记即拒」，仅需删除
    //! [`is_known`](Self::is_known) 中的该分支。

    use std::env;
    use std::process::Command;

    use super::*;
    use cf_domain::secret::SecretString;

    /// 种子清单环境变量。
    pub const ENV_TEST_SEED_NAMES: &str = "COFFER_MCP_TEST_SEED_NAMES";
    /// secret 值环境变量前缀（完整名 = 前缀 + `<NAME>`）。
    pub const ENV_TEST_SECRET_PREFIX: &str = "COFFER_MCP_TEST_SECRET_";

    /// 匿名占位 secret 名。
    ///
    /// `mcp_acceptance.rs` 起草时用 `ANY_SECRET` 作为「不关心 secret 值」的
    /// 占位名，覆盖三处**纯子进程执行**断言（退出码 / 副作用 marker /
    /// 非零退出原样返回）——这些用例不种值，只验证子进程被执行。若本 provider
    /// 严格「未登记即拒」，这些用例会全部转红，与「run_with_secret 4 工具面
    /// 转绿」的目标冲突（docs/20 §3.3 / 验收判据）。故此处将 `ANY_SECRET`
    /// 视为恒可解析、值为空的匿名 secret。
    pub const ANON_SECRET: &str = "ANY_SECRET";

    /// 验收测试种子 provider。
    #[derive(Clone, Debug, Default)]
    pub struct TestSeedProvider;

    impl TestSeedProvider {
        /// 种子名清单（`COFFER_MCP_TEST_SEED_NAMES`，逗号分隔，trim 后去空）。
        fn seed_names() -> Vec<String> {
            env::var(ENV_TEST_SEED_NAMES)
                .map(|raw| {
                    raw.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        }

        /// 取 secret 值（`COFFER_MCP_TEST_SECRET_<NAME>`）；未种返回 `None`。
        /// 值为 [`SecretString`]（析构清零，ZeroizeOnDrop）。
        fn secret_value(name: &str) -> Option<SecretString> {
            env::var(format!("{ENV_TEST_SECRET_PREFIX}{name}"))
                .ok()
                .map(SecretString::from_exposed)
        }

        /// secret 是否已登记（种子清单 / 值变量命中，或等于 [`ANON_SECRET`]）。
        fn is_known(name: &str) -> bool {
            if name == ANON_SECRET {
                return true;
            }
            Self::secret_value(name).is_some() || Self::seed_names().iter().any(|n| n == name)
        }
    }

    impl SecretProvider for TestSeedProvider {
        fn list_secret_names(&self, _vault: Option<&str>) -> Result<Vec<String>, ProviderError> {
            Ok(Self::seed_names())
        }

        fn list_secrets(&self, _vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError> {
            Ok(Self::seed_names()
                .into_iter()
                .map(|name| SecretMeta {
                    name: name.clone(),
                    id: format!("test:{name}"),
                    vault: String::new(),
                    category: "test".into(),
                    updated_at: None,
                })
                .collect())
        }

        fn get_secret_metadata(&self, secret_ref: &str) -> Result<SecretMeta, ProviderError> {
            if secret_ref.is_empty() {
                return Err(ProviderError::InvalidParameter("empty secret ref".into()));
            }
            if !Self::is_known(secret_ref) {
                return Err(ProviderError::NotFound(format!(
                    "secret not found: {secret_ref}"
                )));
            }
            Ok(SecretMeta {
                name: secret_ref.into(),
                id: format!("test:{secret_ref}"),
                vault: String::new(),
                category: "test".into(),
                updated_at: None,
            })
        }

        fn run_with_secret(&self, spec: &RunSpec) -> Result<i32, ProviderError> {
            if spec.secret_ref.is_empty() {
                return Err(ProviderError::InvalidParameter("empty secret ref".into()));
            }
            if spec.cmd.is_empty() {
                return Err(ProviderError::InvalidParameter("empty command".into()));
            }
            if !Self::is_known(&spec.secret_ref) {
                return Err(ProviderError::NotFound(format!(
                    "secret not found: {}",
                    spec.secret_ref
                )));
            }

            // 注入值只在 SecretString（ZeroizeOnDrop）生命周期内存在，用后即毁。
            let value = Self::secret_value(&spec.secret_ref);
            let mut cmd = Command::new(&spec.cmd);
            cmd.args(&spec.args);
            if let Some(cwd) = &spec.cwd {
                cmd.current_dir(cwd);
            }
            if let Some(v) = &value {
                cmd.env(&spec.env_name, v.expose());
            }
            let status = cmd.status().map_err(|e| ProviderError::SubprocessFailed {
                exit_code: None,
                detail: format!("failed to spawn {}: {e}", spec.cmd),
            })?;
            Ok(status.code().unwrap_or(255))
        }
    }
}
