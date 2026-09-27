# Coffer Agent 凭据域

| 项 | 内容 |
| --- | --- |
| 文档编号 | LV-SRS-010 |
| 文档修订 | r1.0 |
| 状态 | **已裁定归属，未分解**（不进入任何版本出口判据） |
| 创建日期 | 2026-09-27 |
| 发布版本归属 | **v2.x** —— 排在 v1.0.0 之后；**不占用 v0.1–v1.0.0 的任何编号** |
| 关联文档 | `01-需求分析.md` §1.2（指针）、`09-版本开发计划.md` §0 / §2 |

## 修订记录

| 文档修订 | 日期 | 变更说明 |
| --- | --- | --- |
| r1.0 | 2026-09-27 | 首版（工单 WO-11）。承载用户 2026-09-27 提供的需求原文，并记录当日的两项裁定与版本号规则。**需求正文照录，不做加工、不新增** |

---

## 0. 本文的地位（先读这一节）

### 0.1 它**不是** `01` §7 的成员

`09-版本开发计划.md` §0 的需求归属声明把需求全集**写死**为「`01-需求分析.md` §7 MoSCoW 表的 **102 个原子 ID**」。**本文的需求不进入那个表** —— 否则那句声明会**当场由真变假**，且是静默变假（没有人会去重数 102）。

因此本文**另起一层**：`01` §7 保持闭合，`09` §0 的版本表保持闭合，新域在二者之外单独立卷。`01` 只加一行指针，供读者从需求主文档找到这里。

### 0.2 编号命名空间：`AS-<n>`

本文需求使用 **`AS-`** 前缀（Agent Secrets），**不复用 `FR-<n>`**。理由：`01` 中 `FR-1`…`FR-14` 已隐含「属 `01` §7 全集」这一含义，复用会让 §2.6 的完整性判定失去可依凭的边界。`AS-` 与既有 `FR-` / `NFR-` / `X-` / `E-` / `WO-` / `WI-` 各前缀**均不冲突**。

### 0.3 本文**不**承诺的内容

- **不排具体版本号**（不写 `v2.0` / `v2.1` / `v2.2`）—— 只声明该域整体归 **v2.x**；
- **不写出口判据**、**不分解任务**、**不估工时**；
- **不动 `09` §2 各版「明确不做」清单** —— 那是按版本行组织的，本文不属于任何现有版本行。

上述三项待 v1.0.0 收敛后**另开工单**处理。

---

## 1. 两项裁定（用户 2026-09-27）

### 1.1 归属裁定

> **Agent 凭据域后置到 v1.0.0 之后，成为 v2.x。**

含义（用户经选项确认）：

- **现有 `docs/09` v0.2.0–v1.0.0 路线图完全不动**；
- 修改 `01` 的方式是**新增指针，不改写 §1.2 / §1.3**（定位与目标用户保持原样）；
- **未采纳**「Coffer 定位转向 Agent 凭据网关」这一选项。故 `01` §1.2「一个完整移除网络能力的本地密码管理器」、`01` §1.3 的四类目标用户、以及 §7 MoSCoW 中的 **Passkey（Must）** 与**自动填充 / TOTP** 均**维持原判**。

⚠️ **须特别记录**：用户提供的源文档 §1 写有「Coffer 不以替代 Apple Passwords、1Password 等传统个人密码管理器为主要目标」，§2 把「网站账号密码 / Passkey / 2FA」划归 Human Identity 并判给 Apple Passwords，§13 又把「个人密码管理 / Passkey / 浏览器密码自动填充」列为第一阶段**暂不重点实现**。**这三处与 `01` §1.2 / §1.3 / §7 直接冲突**，而用户**选择的是「后置」而非「转向」** —— 故**该冲突未被接受为决策**，仅作登记。**本节以下的需求正文照录原文，但它与 `01` 的这层冲突仍然在册，未消解。**

### 1.2 「零网络」的语义（用户原话）

> 「它是不联网的，但是通过本地的 MCP 或者是命令行来提供服务。这里指的是没有云端的服务，密码不会存在别的服务器上。」

**即：本域承诺的是「无云端 / 数据不出本机」，不是「进程间无任何通信」。本地 MCP（stdio）与 CLI 属于允许范围。**

**可核的冲突站点**（若将来改用本地 socket 而非 stdio）：`09` §2.1 的 **v0.4.0 出口判据 ②「关主窗口后 App 仍驻留，且运行时 0 socket」** 是一条**可执行判据**。

- **stdio 走管道、不起监听 → 现判据原样通过**，无需改动；
- **改用 socket 监听 → 该判据与 `01` 的 NFR-SEC-07 措辞须在同一张工单内一并改写。**

⚠️ 引用 `01` 的「**根本没有联网的能力**」（NFR-SEC-07）时**必须带上本节语义**，否则会把「无云端」误读为「无 socket」。

---

## 2. 版本号规则（用户裁定 2026-09-27）

用户给出的发布版本号形式与语义：

- 形式：**`X.Y.Z`**（用户原话举例：「三位一点」「一点零一点」「零点一」）；
- **Z（最后一位）= 修 bug**；
- **Y（中间位）= 功能**；
- **X（第一位）= 大版本**。

**本文所属的 Agent 凭据域添加了 MCP 服务，故为 `v2.x`。**

**与既有文档的关系（本次核实）**：

- 该规则与 `09` §3.1 第 2 行既有待办「**App 版本直接等于发布版本（v0.2.0 = App 0.2.0）**」**一致** —— 后者正是把 `v0.2.0` 展开为三位 `0.2.0`。本节为该既有待办补上了**位序语义**（哪一位管什么）。
- `09` §3 第 5 套词汇「发布版本号」的取值现为 `v0.1 / v0.1.1 / v0.2.0 … v1.0.0`，本规则即该套词汇的**语义定义**。

⚠️ **一处已登记、未处置的命名不一致**（不在本工单范围内）：`09` §2.1 的 **v0.1.1**（已交付）按 Z 位语义应为**修 bug**，而其实质内容是「TOTP 保留语义补强（原孤儿 T06）」+ FR-5 三态语义 + FR-6.1 归属补登记 —— 是否为「补完 v0.1 未交付的 Must」而可判为补丁，**属可争辩，登记待裁**。**不改历史命名**（改了会丢掉「当时发布的叫什么」，参见 `09` §4.2 例外 ③）。

---

## 3. 需求正文（`AS-1` … `AS-14`）

> **以下逐节照录用户 2026-09-27 提供的原文**，每条对应源文档一节。**未新增、未删减、未改写需求内容**；措辞已按文档规范做最小整理（标题层级、列表化）。**凡本文未写明者，不得据本文推断为需求。**

### AS-1 产品定位

Coffer **不以替代 Apple Passwords、1Password 等传统个人密码管理器为主要目标**。

重点解决：

> **如何让 AI Agent、CLI、自动化系统和应用安全地使用 Secret，同时尽可能不让 Secret 明文暴露给模型、配置文件、日志和用户态脚本。**

核心定位：**Secret Broker / Credential Gateway for AI Agents**。

典型使用对象：Claude Code、Codex、OpenCode、Hermes、MCP Server、n8n、Docker、CI/CD、本地开发脚本、Server / Cloud Automation。

### AS-2 凭据分层

凭据分两类。

**Human Identity** —— 主要由 Apple Passwords 等工具管理：网站账号密码、Passkey、2FA、Apple / Google 等个人账号、Wi-Fi 密码、日常个人身份凭据。

**Machine / Developer Identity** —— 由 Coffer 重点管理：API Key、Access Token、GitHub / GitLab Token、SSH Key、Database Credential、Cloud Credential、MCP Credential、CI/CD Secret、AI Model Provider Key、自动化服务账号。

> Coffer 默认**不应该**成为 AI Agent 读取用户所有个人密码的入口。

### AS-3 Secret Source of Truth

开发相关 Secret 统一存储在 Coffer。避免 Secret 散落在：`.env`、`config.yaml`、shell history、`CLAUDE.md`、`AGENTS.md`、MCP 配置文件、Git 仓库、Docker Compose、CI 脚本、Agent Context、日志文件。

**原则：Use Secret，而不是 Read Secret。**

Agent 的标准行为应为：

```
Agent → Coffer → 授权使用 Secret → 启动目标进程
```

而**不是**：

```
Agent → get_secret() → sk-xxxxxxxx → Secret 进入 LLM Context
```

> **Agent 可以使用 Secret，但默认不能看到 Secret。**

### AS-4 MCP 接口面

Coffer 提供 MCP Server。**推荐提供**：

```
list_secrets()          list_secret_names()
list_environments()     create_environment()
mount_environment()     inject_environment()
run_with_secret()
grant_secret()          revoke_secret()
rotate_secret()
get_secret_metadata()
audit_secret_usage()
```

**默认不提供**：`reveal_secret()`、`get_password()`、`dump_vault()`、`export_all_secrets()`。

若未来确需 `reveal_secret`，**必须同时满足**：显式权限、用户确认、审计日志、时间限制、Scope 限制、**默认关闭**。

### AS-5 Secret 使用模式

**模式 A —— Environment Injection**：Coffer 注入 `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GITHUB_TOKEN` 等至进程环境。**Agent 只能看到变量名，看不到对应 value。**

**模式 B —— Run With Secret**：

```bash
coffer run --secret OPENAI_API_KEY -- python app.py
```

Coffer 依次：① 获取 Secret；② 创建临时运行环境；③ 启动子进程；④ 注入 Secret；⑤ **子进程退出后销毁运行环境**。

**模式 C —— Temporary Mount**：临时创建 `.env` / credential file / `SSH_AUTH_SOCK` / cloud credential mount。**要求**：临时生成、最小文件权限、生命周期受控、用后销毁、**默认不进入 Git**、**不进入 Agent Context**。

### AS-6 CLI + MCP 双接口

**CLI** —— 用于 Terminal、Shell Script、Docker、CI/CD、本地开发：

```bash
coffer list
coffer run --env dev-llm -- claude
coffer inject --env dev-git
coffer rotate OPENAI_API_KEY
```

**MCP** —— 用于 Claude Code、Codex、OpenCode、Agent Framework、IDE Agent。

两种接口**共享**：Secret Store、Permission Engine、Audit System、Policy Engine。

### AS-7 权限模型

权限维度：

```
User → Vault → Project → Environment → Secret → Agent
```

可形成 **`Agent × Project × Environment × Secret × Action`** 权限矩阵。

示例（允许）：`Codex → gridbalance → development → OPENAI_API_KEY → USE`。
示例（拒绝）：`Codex → Personal → Apple ID → READ`。

### AS-8 Vault / Environment 建议

```
Coffer
├── Dev-LLM          OPENAI / ANTHROPIC / DEEPSEEK / DASHSCOPE / VOLCENGINE API KEY
├── Dev-Git          GITHUB_TOKEN、GITLAB_TOKEN
├── Dev-Servers      SSH Keys、DB Credential、VPS Credential
└── Automation       n8n、MCP、CI/CD、Agent Service Accounts
```

> **Automation 应作为 AI Agent 的主要授权区域。**

### AS-9 Secret 生命周期

每个 Secret 建议包含：`id` / `name` / `type` / `vault` / `project` / `environment` / `created_at` / `updated_at` / `expires_at` / `rotation_interval` / `allowed_agents` / `allowed_actions` / `last_used_at` / `last_rotated_at`。

支持：创建、禁用、删除、轮换、过期、临时授权、自动回收。

### AS-10 Audit

所有 Secret 使用行为进入审计日志，字段：`timestamp` / `agent` / `user` / `project` / `secret_id` / `operation`（USE / ROTATE / GRANT / REVOKE）/ `target_process` / `result` / `duration`。

> **原则：Audit Log 永远不记录 Secret Value。**

### AS-11 防泄漏与脱敏

必须尽可能防止 Secret 出现在：LLM Prompt、MCP Tool Result、Agent Context、Terminal Output、`stdout` / `stderr`、shell history、Application Log、Crash Dump、Git Diff、Debug Output。

对输出增加 **Secret Redaction**：`sk-abc123xxxxxxxx` → `[COFFER_SECRET_REDACTED]`。

### AS-12 核心架构

```
Claude Code / Codex / OpenCode / Hermes / n8n / CI-CD / Docker
        │
        ├── MCP
        └── CLI
              ▼
      ┌──────────────────────┐
      │       Coffer         │  Credential Gateway
      ├──────────────────────┤
      │ Policy Engine        │
      │ Permission Engine    │
      │ Secret Broker        │
      │ Environment Injector │
      │ Audit Engine         │
      │ Rotation Engine      │
      └──────────┬───────────┘
                 ▼
      ┌──────────────────────┐
      │    Secret Store      │  Dev-LLM / Dev-Git / Dev-Servers / Automation
      └──────────────────────┘
```

### AS-13 MVP（第一阶段）

第一阶段建议只完成：

1. 本地加密 Secret Store；
2. Vault / Project / Environment；
3. `coffer set/get/list` 基础管理；
4. `coffer run`；
5. Environment Injection；
6. **MCP Server**；
7. `list_secret_names`；
8. `run_with_secret`；
9. Agent 权限控制；
10. Audit Log；
11. Secret 输出脱敏。

第一阶段**暂不重点实现**：浏览器密码自动填充、Passkey、银行卡、个人密码管理、跨家庭密码共享（理由原文：这些领域已有 Apple Passwords、1Password 等成熟产品）。

### AS-14 产品原则

> **Secret should be usable without being visible.**

Coffer 的竞争重点不是「保存更多密码」，而是：**在 AI Agent 时代，为机器身份、开发凭据和自动化流程提供统一、安全、最小权限、可审计的凭据基础设施。**

---

## 4. 未决事项（登记，不裁定）

| # | 未决项 | 影响 |
| --- | --- | --- |
| U-1 | **版本号粒度**：v2.x 内部如何切分（v2.0 / v2.1 / … 各自范围） | 待 v1.0.0 收敛后另开工单 |
| U-2 | **MCP 传输方式**：stdio 还是本地 socket 监听 | 决定 `09` §2.1 的 **v0.4.0 判据 ②「运行时 0 socket」** 与 `01` 的 NFR-SEC-07 措辞是否须改写（见 §1.2） |
| U-3 | **`AS-13` MVP 的 11 项**如何展开为 `v2.x-Tnn` 任务条目 | 依赖 U-1 |
| U-4 | **Vault / Project / Environment 的存储模型**（`AS-8` / `AS-9`） | **不可逆决策**（存储格式类）—— 按 `09` §9，须人类确认后才落定 |
| U-5 | **`AS-1` / `AS-2` / `AS-13` 与 `01` §1.2 / §1.3 / §7 的定位冲突**（见 §1.1 的 ⚠️ 段） | 已在册，**未消解**。若将来要转向，须走**需求变更**流程，非本文可裁 |
| U-6 | `AS-4` 中 `grant_secret` 若作为 MCP 工具暴露，是否构成**自授权权限模型** | 见 §5 |
| U-7 | `AS-13` 第 11 项「Secret 输出脱敏」与既有 crate 的边界（脱敏在哪一层做） | 影响架构选型 |

---

## 5. 安全审查要求（强制）

本域主题即**认证与用户数据**，按项目流程门禁，**任何实现改动在合并前必须过安全清单**（`.claude/agents/coffer-reviewer.md` 与 `/dev-team` 的门禁条款）。

实现启动前须先完成的安全评审要点（**登记，不预判结论**）：

- **`grant_secret` 的自授权风险** —— 若 Agent 能通过 MCP 工具自行授予自己权限，权限模型即失效；
- **`run_with_secret` 的隐藏边界** —— 它只对 **LLM 上下文**隐藏 Secret，**不**对 Agent 所启动的**子进程**隐藏。需求措辞「Agent 可以使用 Secret，但默认不能看到 Secret」（`AS-3`）须明确「Agent」指哪一层；
- **`clientInfo` 之类的自称不是凭据**；
- **`AS-5` 模式 C** 会在磁盘上**临时生成**凭证文件（`.env`、credential file）—— 与「不进入 Git / 不进入 Agent Context」需有**可验证**的落实手段，而非仅靠约定；
- **`AS-11` 脱敏的完备性** —— 脱敏若只覆盖 MCP Tool Result，而 Agent 可从 `stderr` 或子进程读回明文，则形同虚设。

---

## 附：本域与 v0.1–v1.0.0 的关系

**无依赖、无交集、不阻塞。** 现有 `09` 的 v0.2.0（数据守得住）、v0.3.0（导入 + 体检）、v0.4.0（顺手 + 多库）、v0.5.0（Passkey，条件性）、v1.0.0（冻结与审计）**全部按原计划推进**，本域**不进入任何一版的出口判据**，也**不占用任何 `vX.Y-Tnn` 编号**。
