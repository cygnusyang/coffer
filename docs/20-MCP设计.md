# Coffer MCP 设计（Agent 凭据网关——v0.5.0-dev 分支展开）

| 项 | 内容 |
| --- | --- |
| 文档编号 | LV-HLD-020 |
| 版本 | r0.3 |
| 状态 | 待评审（TDD 前置设计，未分解实现；版本归属已裁定归 v2.0.0，D-1~D-4 待用户确认） |
| 创建日期 | 2026-09-30 |
| 作者 | dev-architect |
| 上游文档 | `10-Agent凭据域.md`（LV-SRS-010，AS-1~AS-14）、`02-概要设计.md`、`11-架构总览与模块设计.md`、`17-v0.5实现方案.md` r2.4、`KNOWN-ISSUES.md`（BUG-12） |
| 关联代码 | `core/cf-mcp/`（桩 crate，主分支 95870b7 落库） |

---

## 0. 结论先行

1. **协议 = 官方 MCP（Model Context Protocol，JSON-RPC 2.0 传输）**，不是自造 JSON-RPC。Claude Code / Codex 原生消费 MCP，用户需求「通过 MCP 访问、与 Claude Code 协作」即落在 MCP 工具面。协议层错误码用 JSON-RPC/MCP 标准码，应用层错误另登记 **7xxx 段**（docs/03 §12 现行 1xxx~6xxx 已满，7xxx 空缺）。
2. **MVP 数据源 = 1Password CLI（op）**，作为 `SecretProvider` 第一实现；Coffer 自家库为后续 provider（feature 门控）。**MCP 服务器是独立进程 `coffer mcp`，主 App 不宿主服务器**——进程边界保住 v0.4 判据②「App 运行时 0 socket」；`--uds` 上架则按 docs/10 §1.2 触发判据/措辞改写工单。
3. **依赖方向（只下不上）**：cf-mcp 单向依赖下层。MVP 只依赖 cf-domain（CfError/SecretString）；Coffer 原生 provider 经 `coffer-store` feature 依赖 cf-session→cf-store。**不复用 cf-audit 作审计轨迹**——cf-audit 是弱密码体检（FR-6），与 AS-10「Secret 使用审计轨迹」语义不符，复用即分层语义违规。
4. **MVP 工具集**：`list_secret_names` / `list_secrets`（仅元数据）/ `run_with_secret` / `get_secret_metadata`。grant/revoke/rotate/environment 系列 **absent**（权限模型与 secret 生命周期在 Coffer 现有模型中不存在，属 v2.x 完整面，见 docs/10 AS-4/AS-7）。
5. **BUG-12 本版修**（并行微任务，不占 MCP 关键路径）：S3/P1 门禁否决力，修复面是测试基建，与 MCP 零文件交集。
6. **不可逆决策 4 项需用户确认**（§8）：① MCP 协议契约/工具名（外部 API，`claude mcp add` 配置发布即冻结）；② MVP 数据源 = op（与 docs/10 AS-3「Secret 统一存 Coffer」定位冲突，MVP 实际是「网关」不是「存储」）；③ 审计轨迹存储格式；④ `--uds` 引入触发 docs/16 判据② / NFR-SEC-07 措辞改写。
7. **版本归属（已裁定 2026-09-30，用户确认）**：docs/10 §0.3 写死「Agent 凭据域归 v2.x，不占用 v0.1–v1.0.0 任何编号」——用户确认 **MCP 规划归 v2.0.0（v2.0.x）**，v0.5.0 内**不包含**此功能。处置：MCP 作为**独立 feature** 在 `feature/v0.5.0-dev` 分支上继续开发（代码先放着、不阻断 v0.5.0 发版），**不进 v0.5.0 出口判据**；归属回填 docs/10 / docs/09（v0.5.0 出口判据不含 cf-mcp，MCP 相关 commit 归 v2.0.x）。

---

## 1. 需求与范围

### 1.1 需求原文（用户 2026-09-30 原话，照录）

> 实现可以通过 MCP 访问 Coffer 的密钥，可以通过 Claude Code 等软件协作，参考 1Password 最新设计。UI 入口放到设置里面去，和 1Password 一样。

### 1.2 范围解读（照录 docs/10 AS-1/AS-4/AS-5/AS-13 相关条目）

- 定位：Secret Broker / Credential Gateway for AI Agents（AS-1）；「Agent 可以使用 Secret，但默认不能看到 Secret」（AS-3「Use Secret，而不是 Read Secret」）。
- 工具面推荐（AS-4）：list_secrets / list_secret_names / list_environments / create_environment / mount_environment / inject_environment / run_with_secret / grant_secret / revoke_secret / rotate_secret / get_secret_metadata / audit_secret_usage；**默认不提供** reveal_secret / get_password / dump_vault / export_all_secrets。
- 使用模式（AS-5）：A 环境注入 / B Run With Secret / C 临时挂载。MVP 只做 **A+B**；C（临时 .env/credential 文件）不在 MVP（见 §10 风险 5）。
- MVP（AS-13）：MCP Server + list_secret_names + run_with_secret + 权限控制 + Audit + 输出脱敏。

### 1.3 本版范围 / 非范围

| 面 | 本版（MVP） | 非本版（v2.x 完整面） |
| --- | --- | --- |
| 工具 | list_secret_names / list_secrets / run_with_secret / get_secret_metadata | grant/revoke/rotate、list/create/mount/inject_environment、audit_secret_usage |
| 数据源 | 1Password op（SecretProvider） | Coffer 自家 Secret Store（feature 门控，见 §4.5） |
| 权限模型 | 无（数据源自带：1Password 侧 vault 权限） | AS-7 Agent×Project×Env×Secret×Action 矩阵 |
| 审计 | 见 §4.6（待裁：JSONL 或延迟） | 审计入库 audit_local（cf-store 已冻结 schema，无写入 API） |
| 传输 | stdio 默认；--uds 可选（触发改写工单） | 多传输并存 / 服务发现 |

**AS-4「默认不提供」四项硬拒**：MVP 与完整版一律不暴露 reveal_secret / get_password / dump_vault / export_all_secrets。

---

## 2. 模块边界与依赖方向

### 2.1 cf-mcp 层归属

cf-mcp = **应用服务层新 crate**（lib + bin）。承载：MCP 协议收发、工具分发、SecretProvider 抽象、Redactor、CLI 入口（`coffer` bin 的 `mcp` 子命令）。

### 2.2 依赖方向（硬约束，审计口径同 docs/11 §3.3）

```
cf-mcp
 ├──(MVP 必需)──► cf-domain      CfError / secret::SecretString / item 模型
 ├──(MVP 必需)──► serde / serde_json（协议帧）
 ├──(MVP 必需)──► zeroize / hmac+sha2（replay challenge 指纹、缓冲清零）
 ├──(MVP 可选)──► cf-audit       ✗ 不复用（§2.3）
 ├──(feature: coffer-store)──► cf-session ──► cf-store ──► cf-crypto / cf-format / cf-domain
 └──✗───────────► 反向：cf-session / cf-store / cf-ffi / cf-domain 任何一侧不得引用 cf-mcp
```

- **MVP 不依赖 cf-session / cf-store**：op provider 不与 Coffer 解锁会话交互（§4.4），避免在 MVP 引入 DEK/SubKeys 链路。
- **Coffer 原生 provider（后续）**经 `coffer-store` feature 依赖 cf-session 的 `VaultSession`（复用 1001 门禁 + usecase），依赖链 `cf-mcp → cf-session → cf-store`，单向成立。
- **cf-mcp 不依赖 cf-ffi**：MCP 服务器是独立进程，走 Rust 直连（非 UniFFI）。DEK 不跨 FFI 纪律在 cf-mcp 内等价为「Secret 值不跨协议帧」。

### 2.3 关键裁定：审计轨迹**不**复用 cf-audit（分层语义）

cf-audit 职责 = 弱/重复/陈旧密码体检 + 生成器（docs/11 §4.6），**不是** AS-10 的使用审计轨迹（timestamp/agent/operation/result…）。把 MCP 使用日志塞进 cf-audit 会破坏其「离线安全检查」边界。审计轨迹归宿见 §4.6 裁定（A：cf-mcp 本地 JSONL；B：延迟；C：cf-store audit_local——该表 schema 已冻结但无写入 API）。

### 2.4 cf-mcp 内部模块划分（文件闭集）

```
core/cf-mcp/src/
├── lib.rs          // 门面：McpServer::serve(...)、工具注册表
├── protocol.rs     // MCP/JSON-RPC 帧解析、生命周期、错误码映射
├── tools.rs        // 工具分发：name → handler（list_secrets / run_with_secret / …）
├── redact.rs       // SecretRedactor（AS-11 输出脱敏）
├── audit.rs        // UsageAudit trait + 默认实现（§4.6）
├── error.rs        // McpError（7xxx 段）
├── cli.rs          // coffer mcp 参数解析（§5）
├── provider/
│   ├── mod.rs      // SecretProvider trait + 注册表 + 声明 mod op / mod coffer
│   ├── op.rs       // OpProvider（MVP）
│   └── coffer.rs   // CofferStoreProvider（feature: coffer-store 门控，骨架）
└── main.rs         // [[bin]] coffer 入口
```

---

## 3. MCP / JSON-RPC 协议规范

### 3.1 传输

| 项 | 规范 |
| --- | --- |
| 默认传输 | **stdio**：stdout = 协议帧，stderr = 日志（MCP 规范；禁 stdout 打日志）。UTF-8，**换行分隔的 JSON-RPC 2.0 消息**（MCP stdio transport 约定） |
| 可选传输 | `--uds PATH`：Unix domain socket，文件权限 **0600**、目录 **0700**；连接方 peer 凭据校验（macOS `getpeereid`）。⚠️ 上架即触发 docs/16 判据② + NFR-SEC-07 措辞改写工单（docs/10 §1.2 明确耦合） |
| 零网络 | 不引入任何 TCP/UDP 代码路径；`--uds` 为 AF_UNIX，仍属「零网络暴露」（NFR-SEC-07 语义 = 无云端/数据不出本机，docs/10 §1.2） |

### 3.2 生命周期与消息流（MCP 规范子集）

```
client ──► initialize {protocolVersion, clientInfo}
server ──► {protocolVersion, capabilities:{tools:{}}, serverInfo}
client ──► notifications/initialized
client ──► tools/list ──► server 返回工具清单（名称/描述/参数 schema，含 redact 声明）
client ──► tools/call {name, arguments} ──► server 返回 content[]（text，已 redact）
client ──► (可选) notifications/cancelled / 连接关闭 ──► server 退出
```

### 3.3 工具定义（MVP 四项）

| tool | 参数 | 返回（content[0].text，JSON） | 说明 |
| --- | --- | --- | --- |
| `list_secret_names` | `vault?` | `{"names":["OPENAI_API_KEY", …]}` | 仅名称，无元数据 |
| `list_secrets` | `vault?` | `{"secrets":[{"name","id","category","updated_at"}]}` | **仅元数据，无值** |
| `run_with_secret` | `{"secret","env_name?","cmd","args"[],"cwd"?}` | `{"exit_code":0}` | 模式 B；值只进子进程 env，见 §4.4 |
| `get_secret_metadata` | `{"secret"}` | `{"name","id","category","updated_at","allowed_actions":[]}` | 只读元数据 |

> `secret` 参数语义 = Secret 标识（MVP 对 op 即 `op://vault/item/field` 引用或 item id + field designation），**非明文值**。明文值在任何工具入参中都不接受（防 Agent 把值回传）。

### 3.4 错误码规范

**协议层（JSON-RPC/MCP 标准，冻结）**：`-32700` 解析错 / `-32600` 无效请求 / `-32601` 方法未找到 / `-32602` 无效参数 / `-32603` 内部错误；MCP 级 `-32000`~`-32099` 保留。

**应用层（新增 7xxx 段，登记 docs/03 §12）**：

| 码 | 含义 | 触发 |
| --- | --- | --- |
| 7001 | Provider 不可用（op 未装/不可执行） | provider 启动失败 |
| 7002 | 需要身份（op 未登录，OP_SESSION 缺失） | 与 1Password 未链接 |
| 7003 | Secret 不存在 / 无权限 | list/get/run 目标缺失 |
| 7004 | 子进程启动失败（spawn 失败，无退出码） | run_with_secret 的 op **无法启动**目标子进程——子进程**非零退出不是错误**，作 `Ok(exit_code)` 原样返回（mcp_acceptance 契约） |
| 7005 | 协议/参数错误 | 工具入参校验失败 |
| 7006 | 内部错误（不泄露细节） | 兜底 |

> 纪律对齐 CfError 载荷纪律（docs/03 §4.4）：7xxx 消息载荷**不得含 Secret 值或可直接降低攻击成本的信息**。错误码注册 = docs/03 §12 一行登记（docs 域，§9 G-F）。

### 3.5 Redact 规则（AS-11 落地）

1. **值不出协议**：任何 Secret 明文不进入请求/响应帧（结构性保证——tools.rs 不持有值类型）。
2. **输出 Redactor 管道**：所有 `content[0].text` 经 `SecretRedactor` 处理——已知 secret 指纹（长度 ≥ 阈值 + 前缀特征，如 `sk-`）替换为 `[COFFER_SECRET_REDACTED]`（AS-11 原文样例）。
3. **子进程输出边界（诚实声明）**：run_with_secret 启动的子进程自身输出**不受** Coffer 控制；若子进程打印了 Secret，Coffer 无法代劳脱敏（AS-11 边界，docs/10 §5 已登记此风险）——文档向用户明示。
4. **日志禁值**：`op` 子进程 stderr 默认剥离；tracing 层对携带值类型的日志禁打（沿用 L-1「带密钥材料类型禁派生 Debug」纪律延伸）。
5. **shell history / argv 禁值**：`op` 的 session token 与 Secret 引用不经 argv（见 §4.4）。
6. **M-1 补注（目标子进程 stderr 透传例外，2026-10-05）**：`run_with_secret` 启动的目标子进程**非零退出**时，其 stderr 透传到 cf-mcp 进程自身 stderr 诊断通道（`COFFER_MCP_LOG` 缺省 = stderr）——截断至 16 KiB 取末段（`MAX_FORWARDED_CHILD_STDERR`）防灌爆、**标注不脱敏**（子进程输出不受 Coffer 控制，§3.5-3 诚实边界延伸）。**成功路径与 op 层失败路径不透传**（op stderr 仅按关键字归类为稳定文案，不进错误载荷，§4.2）。即 §3.5-4「日志禁值：op 子进程 stderr 默认剥离」的**显式例外**——非零退出路径放弃剥离换取可诊断性。

### 3.6 Replay 防护

| 传输 | 威胁 | 对策 |
| --- | --- | --- |
| stdio | 无持久 token、会话短命，由消费方进程 spawn → replay 面 = 0（不存在可回放的已存凭据） | 不落盘任何 token；拒绝一切「已存会话恢复」模式 |
| --uds | 本地进程可向 socket 写入伪造/重放请求 | ① 单次 connect 生命周期；② peer 凭据校验（`getpeereid` 须为 spawn 方 PID，spawn 时经 env 下发）；③ 会话随机 challenge（spawn 时经 env 下发，`initialize` 须回显）；④ 消息 id 单调递增，乱序/重号拒绝 |

---

## 4. SecretProvider 接口与 op 实现

### 4.1 trait（冻结签名，供 §9 并行组按签名先行）

```rust
// core/cf-mcp/src/provider/mod.rs
use cf_domain::CfError; // 7xxx 映射见 §3.4

#[derive(Clone, Debug)]
pub struct SecretMeta {
    pub name: String,        // 展示名（Agent 引用的标识）
    pub id: String,          // provider 内稳定标识（op: item id）
    pub vault: String,
    pub category: String,    // op: category / 未来 Coffer: 条目模板名
    pub updated_at: Option<i64>, // unix 秒
}

#[derive(Clone, Debug)]
pub struct RunSpec {
    pub secret_ref: String,      // op://vault/item/field 或 item id + field designation
    pub env_name: String,        // 注入的环境变量名（如 OPENAI_API_KEY）
    pub cmd: String,
    pub args: Vec<String>,
    pub cwd: Option<std::path::PathBuf>,
}

#[derive(Error, Debug)]
pub enum ProviderError { /* 映射 §3.4 7xxx 码 */ }

pub trait SecretProvider: Send + Sync {
    fn list_secret_names(&self, vault: Option<&str>) -> Result<Vec<String>, ProviderError>;
    fn list_secrets(&self, vault: Option<&str>) -> Result<Vec<SecretMeta>, ProviderError>;
    fn get_secret_metadata(&self, secret_ref: &str) -> Result<SecretMeta, ProviderError>;
    fn run_with_secret(&self, spec: &RunSpec) -> Result<i32, ProviderError>; // 子进程退出码
}
```

**不变量**：trait 面**无**「返回明文值」方法——run_with_secret 把值直接注入子进程 env（op 侧由 `op run` 解析，值不进 cf-mcp 进程内存）；未来若需 Broker 内部取用（如 audit 记录指纹），经内部 `reveal_for_broker() -> SecretString`（非 trait 公共面，zeroize 保护）。

### 4.2 OpProvider（MVP）

| 项 | 设计 |
| --- | --- |
| 二进制 | `op`（1Password CLI 8+），路径 = `COFFER_OP_BIN` 环境变量，缺省 `PATH` 查找 |
| 身份 | `COFFER_OP_SESSION_TOKEN` 环境变量，**透传给 op 子进程为 `OP_SESSION`**（1Password op 读取的会话变量名）；**不经 argv、不经协议帧、不进日志**（研究结论「session token 只走环境变量」） |
| list | `op item list --vault <vault> --format json` → 解析 name/id/category（**无值**） |
| meta | `op item get <id> --vault <vault> --format json` → 解析元数据（**不取 secret 字段值**；`--fields` 白名单限定非敏感元数据） |
| run | 写临时 dotenv（**0600**）内容为 `ENV_NAME=op://vault/item/field` → `op run --env-file <tmp> -- <cmd> <args>` → **op 自行解析注入子进程 env，明文不经 cf-mcp 内存** → 立即删除 tmp（用后即毁，AS-5 模式 C 纪律同构） |
| 错误 | op 层失败 → `ProviderError` 归一（7001/7002/7003/7004/7005/7006，§3.4 表），剥离 stderr 细节（防泄露）；**目标子进程非零退出不是错误**——作退出码原样返回（mcp_acceptance 契约） |

### 4.3 环境变量约定（全部 Coffer 侧定义，文档落表）

| 变量 | 用途 | 默认 |
| --- | --- | --- |
| `COFFER_MCP_PROVIDER` | provider 选择 | `op` |
| `COFFER_OP_BIN` | op 二进制路径 | `PATH` 查找 |
| `COFFER_OP_VAULT` | 默认 vault 名 | op 首个 vault |
| `COFFER_OP_SESSION_TOKEN` | op 会话 token（透传 `OP_SESSION`） | 空（走 op 自身集成会话） |
| `COFFER_VAULT_DIR` | Coffer 库目录路径（`--provider coffer`，§4.5/§5.2） | 无（coffer 路径必填，缺 → 配置错误退出 1） |
| `COFFER_VAULT_PASSWORD` | Coffer 库解锁密码（`--provider coffer`；经 `SecretString`/ZeroizeOnDrop 承载，**不经 argv / 协议帧 / 日志**，§3.5-4 同款载荷纪律） | 无（coffer 路径必填，缺 → 配置错误退出 1） |
| `COFFER_MCP_UDS` | 非空则监听该 UDS 路径 | 空 = stdio |
| `COFFER_MCP_LOG` | 日志文件路径 | stderr |

### 4.4 明文暴露面（设计显式声明）

- run_with_secret：明文只在 **op 子进程与目标子进程之间**流转，cf-mcp 进程内存**不出现** Secret 明文（op 从自己的 vault 解密后注入）。
- list/meta：全程无值。
- 诚实边界：op 自身、目标子进程不在 Coffer 控制内（威胁面属 1Password/用户终端）。
- **blast-radius（M-1 补注，2026-10-05）**：`op run` 启动的目标子进程继承含 `OP_SESSION` 的完整环境（§4.2 `COFFER_OP_SESSION_TOKEN` 透传为 `OP_SESSION`）——若子进程打印 env 或经 `/proc` 泄露，会话 token 暴露半径含任意被注入 secret 的进程，**须视为凭据暴露半径的一部分**（KNOWN-ISSUES M-1）。目标子进程 stderr 透传例外见 §3.5-6。

### 4.5 CofferStoreProvider（feature `coffer-store`，74a4538 生产实现）

```rust
// core/cf-mcp/src/provider/coffer.rs（feature 门控生产实现，74a4538）
pub struct CofferStoreProvider { session: cf_session::VaultSession, /* … */ }
```

- 依赖链 cf-mcp → cf-session → cf-store，单向。解锁经主 App 流程（VaultSession），1001 门禁复用。
- **已实现（74a4538）**：`SecretProvider` trait 4 方法 + 8 操作（`list_environments` / `create_environment` / `mount_environment` / `inject_environment` / `grant_secret` / `revoke_secret` / `rotate_secret` / `audit_secret_usage`）同语义映射 cf-store 条目模型；`open(vault_dir, password)` 构造（open_vault + unlock）；**7xxx 码零新增**（CfError 映射：1001/1002→7002、1003→7001、1011→7003、1012/5002→7005、其余→7006）。
- **存储映射 = 可逆临时约定（U-4，待用户追认，2026-10-07 落档）**：secret = 条目（名 = 标题；值 = `Designation::Password` 字段 → Concealed → 首个有值字段）；环境容器 = `SecureNote` 条目 + `coffer:environment` 标签（字段 = NAME/VALUE 对）；`allowed_agents` = 条目 `coffer:agent:*` 标签（授权即打 / 撤销即删，幂等）；轮换戳 = `coffer:rotated:*` 标签。**标签即数据，移除即撤**——U-4 落定后整体替换为新实体、无残留脏数据（见 §8 U-4）。原「本版不实现（无 Secret/Environment/权限实体）」随 74a4538 废止——实体建模以临时标签约定先行，正式实体建模归 U-4。
- **已接入（f623eb9）**：`coffer mcp --provider coffer` 经 `coffer-store` feature 门控接线 McpServer/CLI（§5.2）——库路径 + 解锁密码走 §4.3 env 约定（`COFFER_VAULT_DIR` / `COFFER_VAULT_PASSWORD`，缺任一 → 配置错误退出 1），`--vault` 在该路径忽略；`open` 失败按 §5.3 退出码映射（7002→3 身份缺失、7001/其余→1）。23 条 mcp_acceptance 判据由门面（env-seed + 进程内状态）承载，`coffer-store` 为门控生产面（语义一致性由 coffer.rs 单测保证）。
- 启用 feature 后 workspace 依赖树新增 cf-session/cf-crypto 边，**不触碰**其他 crate（§9 互斥矩阵核对）。

### 4.6 审计轨迹（UsageAudit，AS-10）

```rust
pub trait UsageAudit: Send + Sync {
    fn record(&self, ev: AuditEvent) -> Result<(), AuditError>; // ev 无 Secret 值
}
pub struct AuditEvent { ts: i64, agent: Option<String>, user: Option<String>,
                        secret_id: String, operation: String, /* USE|ROTATE|GRANT|REVOKE */
                        target_process: Option<String>, result: bool }
```

| 方案 | 做法 | 优点 | 缺点 | 结论 |
| --- | --- | --- | --- | --- |
| **A. 本地 JSONL（建议 MVP）** | `~/Library/Application Support/Coffer/mcp-audit.jsonl`，追加写，0600，格式登记 docs/20 | 无 Coffer 解锁会话也可记（op provider 成立的前提）；可被审计工具消费 | **新持久化格式**（不可逆候选，§8） | ✅ 建议，**待用户确认** |
| B. 延迟 | 本版只做脱敏，audit trait 占位 | MVP 最小 | 违反 AS-13 MVP「Audit Log」条目；与用户「和 1Password 一样」的审计可见性期望不符 | 备选 |
| C. 入库 audit_local | cf-store 已冻结表 + 补写入 API | 随库走 | MVP（op provider）无 Coffer 会话，写不进库；且 audit_local 当前无写入者 | ❌ 本版不可行 |

---

## 5. CLI：`coffer mcp` 签名

### 5.1 二进制归属

cf-mcp 包产 `[[bin]] name = "coffer"`（沿用 cf-ffi `uniffi-bindgen` 的 bin-in-crate 先例）。未来 `coffer list/run/inject/rotate`（AS-6）扩进同一 bin 或独立 cf-cli crate（届时再裁，本版只管 `mcp` 子命令）。

### 5.2 签名

```text
coffer mcp [--provider op|coffer] [--uds PATH] [--log PATH] [--vault NAME] [--no-audit]
```

| flag | 语义 |
| --- | --- |
| `--provider op` | provider 选择（`op` 恒可用；缺省 = `$COFFER_MCP_PROVIDER`） |
| `--provider coffer` | CofferStoreProvider（**仅 feature `coffer-store` 下可用**，§4.5；关闭时 `coffer` 同任意未知 provider → 配置错误退出 1；库路径/密码走 `COFFER_VAULT_DIR` / `COFFER_VAULT_PASSWORD`，`--vault` 在该路径忽略） |
| `--uds PATH` | 监听 UDS 而非 stdio（⚠️ 触发 §3.1 改写工单） |
| `--log PATH` | 日志落文件（缺省 stderr；stdout 永为协议帧） |
| `--vault NAME` | 默认 vault（缺省 `$COFFER_OP_VAULT`；`--provider coffer` 路径忽略） |
| `--no-audit` | 关闭审计记录（缺省开启，若 §4.6 方案 A 落定） |

### 5.3 退出码

`0` 干净退出（连接关闭 / shutdown）；`1` 配置错误（未知 flag / provider 不可用）；`2` 协议致命错误（帧解析死锁态）；`3` 身份缺失（7002）。

### 5.4 注册命令（设置页「复制」输出，对齐 1Password「Connect to Claude」）

```bash
claude mcp add coffer -- coffer mcp --provider op --vault <vault>
```

用户侧前置：`op signin`（1Password 集成会话）+ `coffer` 在 PATH（随 App 分发，见 §6）。

---

## 6. macOS 设置页 MCP 入口（UI 结构建议）

### 6.1 放置与形态（对齐 1Password：设置内 Developer 区）

`SettingsView`（既有）内新增 **Section「MCP / Agent 协作」**（1Password 在设置里放 Developer 区的同构位置）：

| 控件 | 行为 | 数据 |
| --- | --- | --- |
| 开关「启用 MCP 服务器」 | 持久化配置 + 校验 coffer 二进制存在 | UserDefaults（非敏感布尔） |
| Provider 下拉 | MVP 恒「1Password CLI」，预留「Coffer 自家库」灰态 | 常量 |
| Vault 下拉 | 调 op 列 vault（`op vault list`） | 经 cf-ffi 新增只读接口或进程调用 |
| 「链接 1Password」按钮 | 引导 `op signin`（一次性；成功提示 + 可选将 token 存 Keychain） | Keychain（**不存 UserDefaults**，ThisDeviceOnly） |
| 「复制注册命令」按钮 | 拷贝 §5.4 命令 | 剪贴板 |
| 状态行 | provider 连通性 / 最近审计条数（只读） | audit 文件 tail（脱敏） |
| 「查看使用记录」入口 | 打开只读审计视图（§4.6 方案 A 落定后） | audit JSONL |

### 6.2 进程边界与构建面（关键决策）

- **主 App 不宿主 MCP 服务器**：MCP 服务器 = 独立 `coffer` 进程（由 Claude Code 经 stdio spawn，或 --uds 下由 App/launchd spawn）。主 App 只写配置、发注册命令、显示状态。**App 自身 0 socket 判据不受影响**（docs/16 判据② 测主 App PID）。
- 分发：`coffer` 二进制随 App 包内 `Contents/MacOS/` 或独立 Helper 安装并入 PATH（用户确认安装方式；对齐 1Password 把 op 作为集成组件分发的先例）。构建脚本 `tools/build_macos_app.sh` 增装配步骤（本版不落地，仅设计）。

### 6.3 UI 纪律（沿用 docs/07 §2.4 + docs/17 §6）

sheet 显式关闭出口（BUG-3/5 纪律）；op 调用慢 → `Task.detached`；明文（含 op token）即用即弃、不落 AppModel（v0.4 §6.1 切片纪律）；MCP 域新错误码 7xxx 走统一本地化映射（docs/03 §12 登记后）。

---

## 7. BUG-12 合并关系

**裁定：本版修，独立微任务（并行组 G-A），不占 MCP 关键路径。**

| 项 | 依据 |
| --- | --- |
| 性质 | 测试基建 flake（`temp_vault_dir()` pid+纳秒命名撞名，`attachment_repo.rs:29`），S3/P1（门禁否决力，BUG-4 同族） |
| 为什么本版修 | 新功能（MCP）要依赖干净门禁 `cargo test --workspace --no-fail-fast`；KNOWN-ISSUES 已定位根因与修复路径，单开小工单即可 |
| 与 MCP 文件交集 | `core/cf-store/tests/attachment_repo.rs` + 全仓同型扫描 ∩ cf-mcp/** = ∅ → 可与 MCP 并行 |
| 修复路径 | 目录名加测试名（或进程内原子计数器）消除同 pid 撞名；全仓 `tests/` 同型 `pid+nanos` 模式一并扫（KNOWN-ISSUES 原文） |
| 复验口径 | 并行满载连续多次 `cargo test --workspace --no-fail-fast` 全绿（BUG-4 同款复验口径） |

---

## 8. 不可逆决策清单（需用户确认后才落定）

> 按 docs/09 §9 纪律：存储格式、API 签名、数据迁移类决策为不可逆，标注并须人类确认。

| # | 决策 | 类型 | 为什么不可逆 | 建议 | 状态 |
| --- | --- | --- | --- | --- | --- |
| **D-1** | **MCP 协议契约与工具名**（4 工具签名、`coffer mcp` CLI 签名、7xxx 错误码表） | **API 签名** | `claude mcp add` 注册配置随文档发布后，工具名/参数/返回为外部契约，改动即破坏 Agent 端集成；7xxx 码入 docs/03 §12 即冻结 | 按 §3/§4/§5 冻结签名开发 | 🔶 **需用户确认** |
| **D-2** | **MVP 数据源 = 1Password op（Coffer 扮演网关而非存储）** | 产品定位/数据源 | docs/10 AS-3「Secret 统一存储 Coffer」与本决策冲突；一旦 Agent 端集成 op 链路，回切 Coffer 自家存储需重配所有注册 | 采用（参考 1Password 最新设计，快速可用）；CofferStoreProvider 留 feature 门控 | 🔶 **需用户确认** |
| **D-3** | **审计轨迹存储格式 = 本地 JSONL**（§4.6 方案 A） | **存储格式** | 一旦有日志即事实冻结，消费方（审计视图/工具）依赖格式 | 采用 JSONL（0600，无值）；或选方案 B 延迟 | 🔶 **需用户确认** |
| **D-4** | **`--uds` 引入**（可选传输） | 接口/判据契约 | 触发 docs/16 判据②「App 运行时 0 socket」与 NFR-SEC-07 措辞改写工单（docs/10 §1.2 明确耦合）；UDS 上架即须开改写工单 | MVP 先只发 stdio（零改写）；`--uds` 延后 | 🔶 **需用户确认**（若上架） |
| **U-4** | **Secret/Environment/权限实体存储模型**（现为 74a4538 标签承载的**可逆临时约定**） | **存储格式** | 新实体建表即事实冻结；标签约定移除须数据迁移 | 临时约定（`coffer:environment` / `coffer:agent:*` / `coffer:rotated:*` 标签即数据，移除即撤、无残留脏数据）已按 74a4538 实现，**待用户追认**后替换为新实体 | 🔶 **需用户确认** |

> 另有**非不可逆**但须声明：cf-mcp 内部模块划分（§2.4）、env 变量名（§4.3）、tool 返回字段细节、设置页控件布局——实现期可调整，不冻结。U-4 与 D-1~D-4 并列挂起，用户确认前不升正式实体建模。

---

## 9. 并行分组与任务分解（文件互斥矩阵）

### 9.1 分组

| 组 | 代号 | 文件范围（显式闭集） | 依赖 |
| --- | --- | --- | --- |
| **G-A** | bugfix-bug12 | `core/cf-store/tests/attachment_repo.rs`（+ 全仓 `pid+nanos` 同型扫描，修改范围以扫描结果为准，但**不触碰 cf-mcp/** 与 docs/20） | 无 |
| **G-B** | mcp-core | `core/cf-mcp/src/{lib.rs,protocol.rs,tools.rs,redact.rs,error.rs,audit.rs}`、`core/cf-mcp/src/provider/mod.rs`（含 trait + `mod op;` 空壳声明 + `mod coffer;` 骨架）、`core/cf-mcp/Cargo.toml`、`core/cf-mcp/tests/protocol_*.rs` | 无（按本文档 §3/§4 冻结签名） |
| **G-C** | mcp-op | `core/cf-mcp/src/provider/op.rs`、`core/cf-mcp/src/provider/coffer.rs`（骨架）、`core/cf-mcp/tests/provider_op_*.rs`、fixtures（fake `op` 脚本） | 无（按 §4 冻结 trait 签名先行；集成在 G-B 合入后，v0.4 PK2 先例） |
| **G-D** | mcp-cli | `core/cf-mcp/src/{cli.rs,main.rs}`（`[[bin]] coffer`）、CLI 集成测试 | G-B + G-C |
| **G-E** | mcp-ui | `macos/Coffer/Views/SettingsView.swift`（增 Section）、`macos/Coffer/Views/McpSettingsView.swift`（新）、`macos/Coffer/Support/McpStatus*.swift`（新）；不触 AppModel（v0.4 §6.1） | 无（UI 独立于 core；7xxx 码表登记后即可） |
| **G-F** | mcp-docs | `docs/03-详细设计.md`（§12 登记 7xxx 段）、`docs/10-Agent凭据域.md`（§0.3/§1.2 若 --uds 上架则改写）、`docs/09-版本开发计划.md`（归属回填）、`docs/KNOWN-ISSUES.md`（BUG-12 核销、MCP 域新缺陷登记）、`docs/20-MCP设计.md`（M-1/M-4/L 系列补注与 U-4 落档，本次核销批次） | 无 |
| **G-G** | mcp-e2e | `tests/acceptance_mcp.rs`（新）、`tools/run_mcp_smoke.sh`（新：fake op + stdio 帧回环）、CI 工作流 | G-D（全部落盘后） |

### 9.2 互斥核对

- G-A ∩ 其余 = ∅（cf-store/tests/** 仅 G-A 触碰）。
- G-B 与 G-C：`provider/mod.rs` 归 G-B（含 trait + `mod op;` 空壳），`provider/op.rs` 归 G-C —— **文件不重叠**；G-C 依冻结 trait 先行（先例：docs/17 §7 PK2 按冻结签名先行）。
- G-E 独占 `macos/` 相关文件；G-F 独占 docs 相关文件；G-G 独占 `tests/` 顶层与 `tools/` 新脚本。
- `core/cf-mcp/src/provider/coffer.rs` 由 G-C 承担（feature 骨架），G-B 的 `mod coffer;` 声明为占位——与 G-C 同锁。

### 9.3 合并顺序

```
G-A ∥ G-B ∥ G-C ∥ G-E ∥ G-F ──→ G-D ──→ G-G → 门禁四连 + BUG-12 复验 + D-1~D-4 用户确认回填
```

---

## 10. 风险登记

| # | 风险 | 等级 | 缓解 |
| --- | --- | --- | --- |
| 1 | `op` 命令输出形态（JSON 字段/退出码/集成会话行为）与文档不符 | 中 | G-C 开工前真机 `op` 样本实证（同 docs/17 Bitwarden 单源逆向核对先例）；fake op fixture 承载协议测试，真机冒烟放 G-G |
| 2 | `op run --env-file` 在非 tty 下不脱敏子进程输出 | 中 | 诚实边界声明（§3.5-3）；文档明示子进程输出不受 Coffer 控制 |
| 3 | D-2 数据源决策与 AS-3 定位冲突未获确认 → 返工 | 高 | 本设计 §8 D-2 显著标注，G-B/C 开发前须用户确认 |
| 4 | --uds 判据改写工单被遗漏 | 中 | §3.1 显式耦合；G-F 含改写项；MVP 默认只发 stdio 可完全规避 |
| 5 | AS-5 模式 C（临时 credential 文件）未进 MVP | 低 | 明确非范围（§1.3）；dotenv 用后即毁的 0600 临时文件已部分覆盖 |
| 6 | BUG-12 全仓同型扫描扩大修复面 | 低 | G-A 以扫描结果定界，超出 cf-store/tests/** 的命中单列登记再修 |
| 7 | 审计 JSONL（D-3）格式冻结后演进困难 | 中 | 字段集最小化（§4.6）；格式变更走 docs/03 §1 纪律（先文档后代码） |

---

## 11. 修订记录

| 修订 | 日期 | 说明 |
| --- | --- | --- |
| r0.1 | 2026-09-30 | 首版：协议/模块/CLI/UI/错误码/BUG-12 合并/不可逆决策清单/并行分组 |
| r0.2 | 2026-09-30 | **版本归属裁定（§0.7）**：用户确认 MCP 归 v2.0.0、v0.5.0 不含此功能——独立 feature 继续开发、不进 v0.5.0 出口判据。其余 D-1~D-4 仍未确认（保持可逆暂定）。 |
| r0.3 | 2026-09-30 | **§3.4 / §4.2 错误表述向实现看齐（G-F，dev-reviewer L5）**：§3.4 表 7004 由「run_with_secret 子进程非零退出」修正为「op 无法启动目标子进程（spawn 失败）」——实现（`core/cf-mcp/src/provider/op.rs` / `test_seed`）对子进程非零退出作 `Ok(exit_code)` 原样返回、非错误；7004 仅用于 spawn 阶段失败。§4.2 错误行由「op 非零退出 → 归一 7001/7002/7003」补全为 7001~7006 全段。docs/03 §12 已登记 7xxx 段（7001~7006）；缺陷登记见 KNOWN-ISSUES M-1 / M-4 / L 系列。 |
| r0.4 | 2026-10-07 | **G-F 核销批次（v2.0.0）**：KNOWN-ISSUES 核销回填——M-1/M-4/L-1/L-2/L-3 → `72e4af6`、L-7 → `7c0a217`，L-5 显式顺延 v2.1（不核销）；§3.5-6 / §4.4 M-1 blast-radius 补注（目标子进程 stderr 透传例外 + OP_SESSION 暴露半径）；§4.5 / §8 U-4 临时约定落档（74a4538 标签即数据映射，待用户追认，与 D-1~D-4 并列挂起）。 |
| r0.5 | 2026-10-07 | **G-D 接线后核销批次（v2.0.0）**：KNOWN-ISSUES L-4 核销（实现 `74a4538` + 接入 `f623eb9`，核销条件「实现 + 接入」两段齐备）；§4.3 补 `COFFER_VAULT_DIR` / `COFFER_VAULT_PASSWORD` env 约定（密码经 `SecretString`/ZeroizeOnDrop，不经 argv/协议帧/日志，§3.5-4 同款边界）；§4.5「本版未接线」→「已接入（f623eb9）」；§5.2 `--provider` 补 `coffer` 行（feature 门控，关闭时同未知 provider 退出 1，`--vault` 该路径忽略）+ 用法行与 `--vault` 行同步。 |

*文档结束。签名以本文 §3/§4/§5 为冻结契约；D-1~D-4 与 U-4 用户确认回填后升 r0.6。*
