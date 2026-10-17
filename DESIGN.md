# DESIGN.md — Coffer UI 设计系统

> 状态：**已定稿落仓**（v2.9.0 交互优化轮设计段产出，ui-reviewer 两轮走查放行：初评 Warning 4 HIGH → 打回修 11 项 → 复评条件放行 → REV2-11 清零终审 Approve）。行为层条款（D-* 46 条定稿）即刻生效；待回填条款（P-* 6 条）按 §15 锚点触发回填；视觉层（§0.3）留占位待视觉审查轮。
> 上游依据：`docs/03-功能设计/13-v2.9.0-交互架构审查-提案.md` §6 缺口登记 G1–G10（章节骨架）、§2.4 CO 条目（现状证据）；`coffer-ui-redesign-requirements.md`（既有设计纪律，DESIGN.md 细化之、不推翻之）。
> 责任边界：本文为设计规范文档，不含任何代码改动；实现归 dev-team。
> 证据行号基于审查时点 Pro trunk（0051ac3 之后，与 docs/13 一致）；**实现时须重新核对锚点**。

---

## 0. 文档定位与关系

### 0.1 与 `coffer-ui-redesign-requirements.md` 的关系

- Requirements 是**上位前提 / 硬约束清单**（HIG 约束、窗口/侧栏/搜索/按钮 prominence/语义色/间距节奏/可访问性、原型界面清单）。DESIGN.md **细化之、不推翻之**。
- 分工：Requirements 管「**长什么样**」（结构、层级、视觉纪律）；DESIGN.md 管「**怎么表现**」（行为、状态、反馈、语义、生命周期）。两者互补，冲突时以 Requirements 的 HIG 硬约束为上位。
- Requirements 已给出的可复用纪律（DESIGN.md 直接沿用，不再重述）：
  - 主操作 `.borderedProminent` / 次操作 `.bordered` / 第三级 `.plain` 或 `.borderless`；同一界面最多一个 prominent 主按钮。
  - 语义系统色、零硬编码 hex；accent = 系统蓝单一来源。
  - `.searchable` 统一、列表/搜索无结果需空态（DESIGN.md G7 承接细化）。
  - 掩码默认 `••••`、显示/复制就地切换、显示态有时限或手动收起（DESIGN.md G6 承接细化）。
  - 间距 8/12/16/20/24、卡片圆角 10–12、发丝分隔线（**视觉层本轮不立 token 表，见 §0.3**）。

### 0.2 与 `docs/13` 的关系

- docs/13 §6 登记 10 项设计系统缺口 G1–G10；本文以 G1–G10 为章节骨架，每章给出「现状证据 → 规范条款 → 迁移指引」。
- docs/13 的 30 条问题与 8 条提案（P1–P8）是本文条款的**来源与验收口径**；lead 裁定（§5 四条）为可定稿条款的裁决依据。

### 0.3 本轮不立（占位章节）

- **视觉层**（色彩 token / 间距 token / 圆角 / 阴影 / 字体样式 / 图标规范 / 深色模式细则）本轮**不立 token 表**——交互审查明确排除视觉层，无审查证据支撑的 token 属于纸面规范。以下章节**保留占位**，待独立视觉审查轮立项后回填：
  - `§X 色彩 token（占位）`
  - `§Y 排版与间距 token（占位）`
  - `§Z 图标与视觉组件规范（占位）`
- 现有可立即沉淀的**结构性**空态/反馈模式（见 §11 组件库存量）不受影响，属行为层。

### 0.4 条款编号与可判定性约定

- 每条规范赋予编号：`D-<章>.<序>`（已定稿，可判定）或 `P-<章>.<序>`（待回填，挂对接锚点）。
- 「可判定」= 每条款附**判定方法**（检查清单式），ui-reviewer / dev-team 可按之核对是否合规。
- 编号表汇总见 §16。

---

## 1. G1 — 成功反馈规范

> 缺口：成功反馈规范缺失（docs/13 §6 G1）。上游问题：CO-02（成功反馈三形态并存，同强度操作不同反馈）；P5（产出反馈规范，反馈形态矩阵落 DESIGN.md）。

### 现状证据

- **alert 形态**：`ChangePasswordView.swift:88-97`——改密成功弹 alert「主密码已修改」→ 点「好」后 lock 回锁定页。
- **结果页形态**：`ExportView.swift:278-318`（doneBody：checkmark + 「导出完成」+ 统计 + 完成按钮）、`RestoreBackupView.swift:242-259`（恢复完成页）。
- **内联/就地状态更新形态**：`TouchIDSettingsSection.swift:140-161`（enable 成功 = 确认行收起 + 状态行 caption 翻转，无 alert 无结果页）、`McpEscrowSettingsSection.swift:119-140` 同构。
- **复制反馈（既有同构模式）**：`FieldRowView.swift:65-67` / `TotpCodeView.swift:51-52` / `RecoveryCodeSetupSheet.swift:220-223`——「已复制」内联 Label + 1.5–2s 复位。

### 规范条款

- **D-1.1（成功必反馈）** 任何用户可感知的写操作（保存/导入/导出/恢复/改密/启用/删除/复制）成功，必须有**一种**明确反馈形态，禁止静默成功。判定：grep 写路径调用点，逐一确认有成功反馈。
- **D-1.2（复制类反馈统一）** 复制动作的成功反馈统一为**内联「已复制」Label + 图标翻转**（checkmark/doc.on.doc），1.5s 后复位；不得弹 alert、不得跳结果页。判定：`FieldRowView` / `TotpCodeView` 模式为基准，新增复制入口沿用。
- **D-1.2a（恢复码复制反馈例外，已登记）** 恢复码复制沿用内联「已复制」模式，但**时长 2s + 「已复制（30 秒后自动清除）」长文案**为**已登记例外**（`RecoveryCodeSetupSheet.swift:111/220-223` 现状；ux-spec P5 §5.1 为权威，本条款与之一致）。理由：恢复码一次性纪律（FR-17.2）要求 30s 自动清除的安全提示**不可丢失**——简化为「已复制」会让用户误以为恢复码留在剪贴板无时限。判定：任何新增「复制 + 定时清除」入口，若需超 1.5s 反馈或附加清除提示文案，须对照本例外登记（P5 反馈规格为权威来源）。
- **D-1.3（内联优先）** 低干扰、可就地确认的操作（设置项 enable/disable、状态翻转）默认用**就地状态更新**（行内收尾），不弹 alert、不建结果页。判定：新增设置项开关类操作是否走内联收尾。
- **D-1.4（不静默的强度分级）** 反馈强度与操作破坏性/影响面匹配：低风险就地动作→内联；中风险流程→结果页或 alert；高风险（明文导出/批量删除）→结果页含统计与警示。判定：每类操作在 §1 矩阵中标注档位。
- **P-1.1（待回填）** 「alert vs 结果页 vs 内联」的**完整形态矩阵**（含强度阈值、各自适用操作清单、文案结构模板）——由 ui-ux 在 P5 反馈规格中定稿后回填。对接锚点：`P-1.1`。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 改密成功 | alert | 维持 alert（含后续 lock 语义，合规 D-1.4） |
| 导入/导出/恢复 | 结果页 | 维持，文案/统计结构并入 P-1.1 矩阵 |
| TouchID/MCP enable | 内联收起 | 维持（D-1.3 基准） |
| 复制（全站） | 内联已复制 | 维持（D-1.2） |
| 恢复码复制 | 内联 2s + 「（30 秒后自动清除）」 | 维持（D-1.2a 已登记例外，随 FR-17.2 一次性纪律） |
| 其余新增写路径 | 无 | 按 P-1.1 矩阵选型 |

---

## 2. G2 — 主密码确认组件

> 缺口：主密码确认组件缺失（docs/13 §6 G2）。上游问题：CO-05（三形态 × 4 处重复文案）。

### 现状证据

- 文案重复 4 处（CO-05）：
  - `TouchIDSettingsSection.swift:142`「出于安全考虑，主密码不会被保存，请重新输入一次以确认身份。」
  - `McpEscrowSettingsSection.swift:121`（同 142）
  - `RecoveryCodeSetupSheet.swift:279`（追加「，之后恢复码才会启用。」）
  - `VaultBioEnableOfferView.swift:183`「出于安全考虑，主密码不会被保存，需要重新输入一次。」
- 形态：**内联确认行**（设置页两处，`TouchIDSettingsSection.swift:140-161` / `McpEscrowSettingsSection.swift:119-140`）；**多步 sheet 一步**（`RecoveryCodeSetupSheet.swift:272-302` confirmStep）；**引导 sheet 内联**（`VaultBioEnableOfferView.swift:176-209`）。
- 纪律（docs/07 §2.4，全站一致）：密码只作参数传入、提交即清空、不落 @Published/日志；失败表单保留可重试但需重输。

### 规范条款

- **D-2.1（统一文案源）** 主密码确认提示语收敛为**单一常量**（主句固定），附加用途说明以参数/拼接附加；禁止各面手写变体。判定：grep「出于安全考虑」「重新输入」应命中唯一常量 + 附加用途处。
- **D-2.2（组件化）** 内联主密码确认行抽为可复用组件（SecureField + 取消/确认 + isEnabling + 提交即清 + 失败保留可重试）；设置页 TouchID / MCP / 恢复码确认步 / 引导 sheet 复用。判定：新增需主密码确认的面必须引用该组件，不得重写。
- **D-2.3（一次确认边界）** 同一会话内、同一操作的一次确认只发生一次；确认成功即完成该次验证，不得在同一流程内二次要求重输（除非安全门禁如改密需旧密码）。判定：逐流程核对确认次数。
- **D-2.4（密码生命周期）** 确认输入框的密码只在提交瞬间进入调用链，随即清空；不预填、不落状态、不写日志。判定：`docs/07 §2.4` 纪律，代码审查对照。
- **D-2.5（失败路径）** 确认失败（1002/1010 等）不得关闭确认面，保留可重试；错误经 ErrorPresenter 统一呈现（内联场景不得用会叠在 sheet 上失效的 alert——见现状注释纪律）。判定：失败分支走 `lastErrorMessage` → `ffiErrorAlert` 或就地呈现。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| TouchID / MCP 设置 | 内联行（文案复制） | 抽组件 + 单一文案源 |
| 恢复码确认步 | 多步 sheet 内 step | 复用确认组件 + 文案常量（附加「之后恢复码才会启用」作用途后缀） |
| 建库引导 sheet | 内联 SecureField | 复用确认组件 |
| 改密（旧密码重验证） | 表单三输入 | 不改（D-2.3 安全门禁例外，非确认面） |

---

## 3. G3 — 剪贴板自动清除单点化

> 缺口：剪贴板自动清除双实现（docs/13 §6 G3）。上游问题：CO-01；P5（ClipboardManager 增 `copyWithAutoClear(value:clearSecs:)`，恢复码固定 30s 保留为入参）。

### 现状证据

- **统一档位实现**：`Platform/Clipboard.swift:91-98`（`copyWithAutoClear`，档位 + changeCount 守卫）、`:186-200`（`clearOnLock` 锁定兜底）、`:74-76`（`clipboardUnchanged` 守卫纯函数）。
- **手写双实现**：`RecoveryCodeSetupSheet.swift:238-258`——绕过 ClipboardManager 自写 DispatchWorkItem + 固定 30s + 重复复制取消。风险：守卫漂移（ChangeCount 守卫两处各自维护）。
- **例外**：TOTP 复制走 `copyPlain`（`Clipboard.swift:100-107` 注释 FR-5.5、`TotpCodeView.swift:91-98`）；FR-5.6 序列复制 `copyPasswordThenTotp`（`Clipboard.swift:127-162`）。

### 规范条款

- **D-3.1（单点）** 所有「敏感内容写剪贴板 + 定时清除」一律经 `ClipboardManager` 单一实现；任何视图不得自写 DispatchWorkItem 清除逻辑。判定：grep `DispatchWorkItem` + `NSPasteboard` 写入，仅命中 Clipboard.swift（及经其公开 API）。
- **D-3.2（时长入参化）** `ClipboardManager` 提供带 `clearSecs:` 入参的复制 API：默认走用户档位；调用方可传固定时长（恢复码 30s 安全纪律——「从不」档位不得让恢复码永久留板）。判定：RecoveryCodeSetupSheet 迁到该 API，删除本地实现。
- **D-3.3（changeCount 守卫单点）** 清除与写入路径的 changeCount 守卫只存在于 `ClipboardManager`；锁定兜底 `clearOnLock` 覆盖全部敏感副本。判定：清除决策一律调用 `clipboardUnchanged`。
- **D-3.4（例外登记）** TOTP 验证码复制走 `copyPlain`（FR-5.5：30s 轮换自失效，清除只有摩擦）是**已裁定例外**，不得扩散到密码/恢复码等持久敏感值。判定：新增「不清除复制」入口须 lead 裁定并登记。
- **P-3.1（已回填，定稿）** 显式时长版 API 最终签名：`copyWithAutoClear(_ value: String, clearSecs: TimeInterval)`（`Platform/Clipboard.swift:104`）。语义：`clearSecs > 0` 按显式时长调度定时清除，changeCount 守卫于清除任务闭包内**局部捕获**写入时计数（不依赖单例槽位）；`clearSecs == 0` 视作「本次不清除定时路径」但保留 `clearOnLock` 锁定兜底（勿 asyncAfter(0)）；`clearOnLock` 覆盖全部敏感副本。既有 `copyWithAutoClear(_:)`（:91）委托本方法传当前用户档位。迁移落地：恢复码复制唯一入口 `RecoveryCodeSetupSheet.copyCode()`（:253-255）改走本 API，传固定 `Self.clipboardClearSecs = 30`（FR-17.2 一次性纪律，不受用户档位影响）；手写 DispatchWorkItem 路径与 `clipboardClearItem` 状态已删除（29afba3）。全仓无第二套手写自动清除。对接锚点：`P-3.1`。
- **P-2.1（已回填，定稿）** 一次性首次高亮兜底契约（P2-A，22036fa）：落盘仅「跳过」旗标 `bio_offer_skipped` / `recovery_offer_skipped`（`AppModel` @Published + didSet 落盘，对齐 clipboardClearSecs 模式）；**「已完成」不落盘**——由 `touchIDStatus` / `hasRecoveryWrap` live 派生。派生条件：`showBioSetupHighlight = bioOfferSkipped && touchIDStatus == .disabled`、`showRecoverySetupHighlight = recoveryOfferSkipped && !hasRecoveryWrap`。清除路径双通道：①对应功能启用成功（`enableTouchID` / `enableRecoveryCode` 成功清位）②完成后 live 派生自然转 false。呈现落点：`SettingsView` securitySection 条件渲染 `FirstRunSetupHighlightRow`（accent 圆点 + 「未完成设置」footnote，小组件两侧复用）。对接锚点：`P-2.1`。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 恢复码复制 | 手写 30s + 自维护守卫 | `ClipboardManager` 入参化 API（D-3.2） |
| 密码/敏感字段复制 | ClipboardManager | 维持（基准） |
| TOTP 复制 | copyPlain | 维持（例外） |

---

## 4. G4 — 关闭/完成按钮语义

> 缺口：关闭/完成按钮语义未定（docs/13 §6 G4）。上游问题：CO-06（confirmation/cancellation 混用）；REV-02（成功态无出口陷阱）。

### 现状证据

- `AuditLogView.swift:104-108`——只读查看页用 `.confirmationAction` + 「完成」。**违规**（只读页应为「关闭」+ `.cancellationAction`，Esc 生效）。
- `HistorySheet.swift:70-75`——只读列表用 `.cancellationAction` + 「关闭」（注释明示 Esc 生效，BUG-5 纪律）。**合规基准**。
- `AboutUpdateSection.swift:41-45`——关于对话框用 `.confirmationAction` + 「完成」。**违规**（无成功语义的只读对话框，应为「关闭」+ `.cancellationAction`）。
- `ExportView.swift:312-314`（doneBody）——成功收尾页「完成」+ `.borderedProminent` + `.defaultAction`。**合规基准**；`ExportView.swift:116-118` 前置步「关闭」+ `.cancelAction`（sheet 级出口，合规）。
- `RecoveryResetSheet.swift:203-223`——成功视图只有「用新密码解锁」单动作，**无关闭出口**（REV-02，Esc 不生效、无次级按钮）。

### 规范条款

- **D-4.1（语义矩阵）** 依操作语义选关闭措辞与 placement：

  | 页面类型 | 按钮 | placement | 键盘 |
  |---|---|---|---|
  | 只读查看页（审计日志/历史/关于/详情） | 「关闭」 | `.cancellationAction` | Esc 生效 |
  | 成功收尾页（导出/恢复/导入结果） | 「完成」 | `.confirmationAction`（或 prominent + `.defaultAction`） | Return |
  | 表单编辑页 | 「取消」 | `.cancelAction` | Esc |
  | 流程多步 sheet 的**中途**出口 | 「关闭」（保留状态）或「取消」（放弃） | 依丢弃语义 | Esc |

  判定：每个 sheet/窗口核对措辞、placement、键盘映射三列。
- **D-4.2（成功态必有出口）** 任何「成功收尾页」不得只有主动作——必须提供次级出口（如「稍后解锁」/「完成」），保证 Esc / 关闭可达。判定：成功页最少 1 主动作 + 1 次级出口或关闭键（REV-02 直接判据）。
- **D-4.3（语义绑定）** 措辞与行为一致：「关闭」= 不丢弃未提交状态；「取消」= 丢弃；「完成」= 流程已达终态。判定：按 D-4.1 矩阵核对。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| AuditLogView | 完成 + confirmation | 「关闭」+ cancellation（Esc） |
| AboutUpdateView | 完成 + confirmation | 「关闭」+ cancellation |
| HistorySheet | 关闭 + cancellation | 维持（基准） |
| 导出/恢复结果页 | 完成 + default | 维持（基准） |
| RecoveryResetSheet 成功视图 | 仅「用新密码解锁」 | 补「稍后解锁」次级按钮（REV-02） |

---

## 5. G5 — 长内容与截断规范

> 缺口：长内容规范不统一（docs/13 §6 G5）。上游问题：ST-03（详情标题无 lineLimit）、ST-05（字段名固定宽无 lineLimit）。

### 现状证据

- `ItemDetailView.swift:147`——详情标题 `Text(details.title).font(.title2.bold())` **无 lineLimit**，超长标题可撑坏 header 布局（ST-03）。
- `MainView.swift:243`——列表行 `Text(summary.title).lineLimit(1)`（合规）；`TrashView.swift:20` 同。
- `FieldRowView.swift:44-46,105`——字段名固定 `frame(width: 120)` **无 lineLimit**，超长字段名挤压值区（ST-05）。
- `ItemDetailView.swift:210-211`——URL `.lineLimit(1).truncationMode(.middle)`（合规基准）。
- `RestoreBackupView.swift:254-256` / `ExportView.swift:216-218`——文件路径 `.lineLimit(2).truncationMode(.middle)`（合规基准）。

### 规范条款

- **D-5.1（单行基准）** 列表行、标签、侧栏项、汇总类文本一律 `lineLimit(1)`；长内容尾截断（`.truncationMode(.tail)`）。判定：所有 List 行文本有 lineLimit。
- **D-5.2（标题限高）** 详情/弹窗标题允许最多 2 行（`lineLimit(1...2)`），不得无限生长；超长以尾部截断。判定：header 类文本均有上限。
- **D-5.3（路径/URL 中截断）** 文件路径、URL 等「结尾有语义」的内容用 `.truncationMode(.middle)`；固定行数 1–2。判定：路径类文本命中 middle。
- **D-5.4（固定宽标签）** 固定宽度标签（如字段名 120pt）必须 `lineLimit(1)` + 尾部截断（或允许值区换行时标签 2 行），不得挤压值区。判定：固定 frame 文本有 lineLimit。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 详情标题 | 无上限 | lineLimit(1...2)（D-5.2） |
| 列表行 | lineLimit(1) | 维持（基准） |
| 字段名 | 固定宽无 lineLimit | lineLimit(1) + tail（D-5.4） |
| URL / 路径 | middle + 1–2 行 | 维持（基准） |

---

## 6. G6 — 明文自动隐藏规范

> 缺口：明细明文自动隐藏缺规范（docs/13 §6 G6）。上游问题：SEC-02（reveal 后明文不自动隐藏）；SEC-03（TOTP 常显，设计决策点）。

### 现状证据

- `FieldRowView.swift:121-130`——Concealed 字段「显示」→ 明文取回存**行内局部 @State**（`:97`），「隐藏」按钮手动收回；无失焦/切 App/滚动自动收回（SEC-02）。
- `TotpCodeView.swift:33-46,91-98`——TOTP 6 位码常驻详情页，无隐藏开关；复制走 `copyPlain` 不自动清（2026-09-27 裁定，SEC-03 记录为设计决策点）。
- 锁定兜底已到位：`AppModel.lock()` → `clearOnLock()`（`Clipboard.swift:186-200`），明文 UI 状态随 phase 拆除清空（`AppModel.swift:601-618`）。

### 规范条款

- **D-6.1（明文局部存活）** 明文只存活在行内局部状态 / 调用链内，不进全局状态、不落盘；视图销毁即释放。判定：`docs/07 §2.4` 纪律 + 代码审查。
- **D-6.2（手动隐藏必提供）** 任何明文 reveal 必须就地提供「隐藏」控制（按钮），不得只有「显示」。判定：reveal 态必有对应收回入口。
- **D-6.3（锁定必收）** 锁定/切库/退出时明文 UI 与剪贴板一并回收（现有 `clearOnLock` + phase 拆除）。判定：锁定后无明文残留。
- **P-6.1（待回填）** reveal 后**自动收回触发集**（失焦 / 切 App / 滚动离开 / 超时）——SEC-02 未入 8 提案，由 ui-ux 交互规格定触发集后回填；定稿前维持手动隐藏（D-6.2）。
- **P-6.2（待回填）** TOTP 常显的**可选隐藏开关**（SEC-03 设计决策点）——连同「关窗即锁」backlog 一并评估；当前维持常显 + 面告知（P8）。对接锚点：`P-6.2`。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| Concealed 字段 | 手动隐藏（合规 D-6.2） | 维持 + P-6.1 自动收回 |
| TOTP | 常显（已裁定） | 维持 + P-6.2 评估 + 面告知 |
| 锁定回收 | 已到位 | 维持（基准） |

---

## 7. G7 — 加载 / 空 / 错误态三件套

> 缺口：三件套未全量落实（docs/13 §6 G7）。上游问题：ST-01（详情加载态，证伪）、ST-02（HealthCheck 无就地错误态）。

### 现状证据

- **良好样例**：`AuditLogView.swift:94-102`（loading / emptyState / eventList 三态齐全）、`HistorySheet.swift:59-67` 同构。
- **空态模式**：`MainView.swift:254-266`（ActiveItemList 空态：图标 40pt + headline + callout + 可选动作）、`TrashView.swift:26-38`、`AuditLogView.swift:146-157`、`HealthCheckView.swift:133-147`（allClear）。
- **缺失面**：`HealthCheckView.swift:59-71`——加载失败无就地错误态（中列空白，错误 alert 会弹但无就地态 + 重试，ST-02）。
- **详情区**：`MainView.swift:205-220`——`loadSelectedDetails` 为同步 FFI（`ItemStore.swift:49-63`），选中即回填，无闪变（ST-01 证伪）。「加载与未选中混淆」仅为理论缺口。

### 规范条款

- **D-7.1（三态齐备）** 每个数据面（列表/整页/详情 sheet）必须具备加载态、空态、数据态；整页异步加载还必须**就地错误态**（见 D-7.3）。判定：逐面核对三态分支存在。
- **D-7.2（空态模式统一）** 空态 = 图标（SF Symbol 40pt）+ 标题（headline）+ 说明（callout 次级色）+ 可选动作；杜绝裸空白。搜索无结果空态复用此模式（文案区分「暂无条目」/「无匹配结果」）。判定：所有空态命中此结构。
- **D-7.3（就地错误态）** 整页/中列异步加载失败必须**就地**呈现错误（图标 + 文案 + 重试按钮），错误 alert 只是补充，不得以弹窗代替就地态。判定：`HealthCheckView` 补就地错误态 + 重试（ST-02 直接判据）。
- **D-7.4（详情加载态豁免）** 详情区为同步 FFI（毫秒级）——**不设**加载态；「未选中」用现有占位（图标 + 「选择左侧列表中的条目查看详情」）。判定：详情区不得出现为异步而设的假加载态（ST-01）。
- **D-7.5（监视/等待态例外）** 被动监视/等待类状态（如放置区导入的「正在监视目录」）**不是 G7 空态**——页面有内容（指引卡等），仅追加：活跃指示（如 radar 图标 + 状态 caption）、不打断不弹窗（检测到目标时自动流转，无需用户确认）、可随时退出；VO 用单元素 announce 播报（如「正在监视 \<目录名\>」），不做整页 live region。判定：监视态有活跃指示 + 无打断弹窗 + 有退出出口（docs/21 放置区导入，2026-10-15）。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 审计日志 / 历史 | 三态齐全 | 维持（基准） |
| 安全体检 | 无就地错误态 | 补就地错误态 + 重试（D-7.3） |
| 列表 / 回收站空态 | 已有 | 维持（基准） |
| 详情区 | 无选中占位 | 维持（D-7.4 豁免） |

---

## 8. G8 — 批量操作反馈规范

> 缺口：批量操作反馈规范缺失（docs/13 §6 G8）。上游问题：FW-03（清空回收站遇首错即 break，部分删除后剩余保留且无聚合反馈）。

### 现状证据

- `TrashView.swift:55-64`——清空回收站 `for summary in model.items`，任一 `deleteItem` 抛错即 `handleFfiError` + `break`：**已删的删了、剩下的留着，无聚合反馈**（FW-03）。

### 规范条款

- **D-8.1（不中断继续）** 批量操作遇单条失败**不得 break 中断**——继续处理剩余条目，聚合全部结果。判定：批量循环无 `break`/`return` 吞尾。
- **D-8.2（聚合反馈）** 批量完成后反馈聚合结果：成功 N 条 / 失败 M 条；M > 0 时列出失败原因（单条失败经 ErrorPresenter 汇总呈现，不逐条弹窗）。判定：批量入口有聚合摘要。
- **D-8.3（幂等与可重试）** 部分失败后的残留项保持可重试状态（原列表仍在），用户可再次触发。判定：失败后列表状态未丢失。
- **D-8.4（预览层批量选择反馈）** **入库前**的预览层批量选择（如导入去重预览的「跳过/全部导入」切换，非 D-8.1~8.3 写批次）须满足：**即时统计反馈**（切换即时更新统计与动作按钮计数）、**状态可见 + 可逆**（被改动的行保留显式标记，可切回，未入库无副作用）、**安全默认**（批量选择的默认动作须为安全默认并明示，如默认跳过、不覆盖）、**VO 标签含当前态 + 动作**（如「重复，点按改为导入」）。判定：批量切换有即时计数更新 + 行级标记 + 安全默认明示（docs/21 放置区导入，2026-10-15）。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 清空回收站 | 首错 break 无聚合 | 继续处理 + 聚合反馈（D-8.1/8.2） |
| 批量恢复/删除（TrashView 列表） | 单条操作 | 新增批量选择时按本规范 |

---

## 9. G9 — 键盘快捷键注册规范

> 缺口：键盘快捷键注册规范缺失（docs/13 §6 G9）。上游问题：CO-03（快捷键覆盖不全 + 列表导航用隐藏按钮 hack）；P7（快捷键补齐 + 隐藏按钮迁移）。

### 现状证据

- **CommandGroup 形态（合规基准）**：`CofferApp.swift:95-115` DataCommands——⌘I 导入 CSV、⌘⇧I 导入 1PUX、⌘E 导出、⌘, 设置；`.disabled(phase != .unlocked)` 门禁。
- **隐藏按钮 hack**：`MainView.swift:299-314`——↑/↓/Enter/⌘U 以 `.hidden()` + `accessibilityHidden(true)` 按钮承载（HK-2/3/4，判据依赖此形态）。
- **缺口**（CO-03）：无 ⌘N 新建、⌘L 锁定、跨库复制、TOTP 复制键；Bitwarden/OPVault 导入无快捷键。
- **基准**：research 基线 #2（⌘F/⌘N 等标准键 `[推测惯例]`，以 Bitwarden 实测佐证，HIG 两页当日 404）。

### 规范条款

- **D-9.1（注册形态）** 快捷键优先注册到 **CommandGroup/CommandMenu**（菜单栏可见、可发现、聚焦无关）；`CommandGroup` 不可达的列表局部键（依赖选中态、仅在列表焦点上下文）才可用隐藏按钮 + `keyboardShortcut` 豁免，且必须 `.accessibilityHidden(true)`。判定：全站快捷键 grep 归属形态。
- **D-9.2（标准键补齐）** 标准命令键映射（P7 范围，竞品标准非自创）：

  | 命令 | 键 | 说明 |
  |---|---|---|
  | 新建条目 | ⌘N | 竞品标准（Bitwarden 实测） |
  | 锁定 | ⌘L | 竞品标准 |
  | 复制密码 | ⌘⇧C **+** 列表局部 Enter（两者并存） | 迁移自隐藏按钮；⌘⇧C=应用级（菜单栏可见），Enter=列表局部上下文键（选中态），与 ux-spec P7 §2.2 对齐 |
  | 导入 CSV / 1PUX | ⌘I / ⌘⇧I | 已存在 |
  | 导出 | ⌘E | 已存在 |
  | 设置 | ⌘, | 已存在 |
  | 搜索 | ⌘F（聚焦 .searchable） | 评估项 |

  判定：新增键是否可发现（菜单栏可见）+ 无全局键冲突。
- **D-9.3（禁用态纪律）** 依赖解锁会话的菜单命令 `.disabled(phase != .unlocked)`（DataCommands 已立基准）；锁定态不得留「可点但报错」的快捷键。判定：与 `DataCommands` 同纪律扩散。
- **P-9.1（待回填）** P7 实现后的**最终键表**（含冲突回归 HK-2/3/4 判据结果）回填本节；迁移完成前隐藏按钮形态维持。对接锚点：`P-9.1`。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 导入/导出/设置 | CommandMenu | 维持（基准） |
| ⌘N / ⌘L | 缺失 | P7 补齐（D-9.2） |
| ↑/↓/Enter/⌘U | 隐藏按钮 | 列表局部豁免维持，其余迁 CommandGroup（P7） |
| Bitwarden/OPVault 导入 | 无键 | P7 决定是否给键 |

---

## 10. G10 — 窗口 / 相位生命周期规范

> 缺口：窗口/相位生命周期规范缺失（docs/13 §6 G10）。上游问题：FW-02 / REV-03（设置窗口不随 phase 拆除 → 锁定态 session 依赖项吃 1001）；SEC-01（关窗驻留语义）；lead 裁定 2（锁定时关闭设置窗口）。

### 现状证据

- **主窗口（合规）**：`RootView.swift:49-64`——按 `phase` switch 拆树（booting/noVault/locked/unlocked/fatal）。
- **设置窗口（违规）**：`CofferApp.swift:72-75`——独立 Window scene id "settings" **不随 phase**；`ChangePasswordView.swift:121` 注释「设置页仅在解锁态可达」已过时（REV-03）。
- **根因**：`AppModel.swift:601-618` `lock()` 不置 `session = nil`——锁定态设置窗口 `guard let session` 仍通过 → 对已锁会话调 changePassword/TouchID/MCP enable/审计日志均吃 1001。
- **关窗驻留**：`CofferApp.swift:155-160` `applicationShouldTerminateAfterLastWindowClosed = false`（2026-09-29 裁定）——关窗后会话保持解密驻留，仅靠 auto-lock 兜底（SEC-01，用户易误判已安全）。

### 规范条款

- **D-10.1（主窗口相位门控）** 主窗口内容严格随 `phase` 切换，任何状态面不得在错误相位渲染（现有 RootView 为基准，新增 phase 分支须入此 switch）。判定：`RootView.swift:49-64` 无旁路。
- **D-10.2（设置窗口锁定态）** 锁定态**关闭设置窗口**（lead 裁定 2）；实现发现 Window scene 关闭 API 不可行时降级为「依赖 session 的行级 `.disabled(phase != .unlocked)`」+ 修 `ChangePasswordView.swift:121` 过时注释。判定：锁定后设置窗口不可达或全禁用（REV-03 直接判据）。
- **D-10.3（session 依赖门禁）** 任何依赖解锁会话的控件/窗口，其可用性必须显式绑定 phase，不得依赖「可达即解锁」假设。判定：`guard let session` 前的入口均有 phase 门禁。
- **D-10.4（关窗驻留面告知）** 关窗驻留语义（关窗 ≠ 锁定）须在设置页 / 首启引导显式告知；「关窗即锁」选项登记 backlog（P8）。判定：告知文案存在。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 主窗口 | phase 拆树 | 维持（基准） |
| 设置窗口 | 不随 phase | 锁定即关（D-10.2） |
| session 依赖行 | 无门禁 | phase 门禁 + 注释修正 |
| 关窗驻留 | 无面告知 | 设置页告知 + backlog（D-10.4） |

---

## 11. 组件库存量（本轮可沉淀的既有组件）

> 依据纪律 2（组件来自真实设计任务）。以下为**已存在并被多面复用**的组件，本轮先登记为规范组件，供 dev-team 抽取复用；不做纸面组件。

| 组件 | 现状出处（基准实现） | 说明 |
|---|---|---|
| 空态（icon + 标题 + 说明 + 可选动作） | `MainView.swift:254-266` / `AuditLogView.swift:146-157` | G7 空态模式的组件化候选 |
| 内联主密码确认行 | `TouchIDSettingsSection.swift:140-161` | G2 组件化目标（D-2.2） |
| 复制反馈 Label（已复制/checkmark） | `FieldRowView.swift:65-67` / `TotpCodeView.swift:51-52` | G1 D-1.2 |
| 密码强度条 | `PasswordStrengthSection.swift`（ChangePasswordView:64 引用） | 已组件化，维持 |
| 关闭/完成按钮（语义矩阵） | `HistorySheet.swift:70-75` / `ExportView.swift:312-314` | G4 语义基准 |
| 一次性首次高亮（首次引导兜底，lead 裁定⑤ P2-A 已纳入） | `RootView.swift:19-38`（`pendingBioOffer` / `pendingRecoveryOffer` 引导可跳过） | accent 圆点 + 「未完成设置」footnote；**触发**=引导步骤被跳过且对应功能未启用；**清除**=启用对应功能（P2-A 兜底，承接 P2 合并后跳过语义）；契约挂 UserDefaults（`bio_offer_skipped` / `recovery_offer_skipped`），P-2.1 已回填（见 G2 规范条款） |
| ffiErrorAlert（统一错误呈现） | `AppModel.lastErrorMessage` + `.ffiErrorAlert`（全仓） | 错误通道，已统一 |

---

## 12. 命名规范（骨架）

> 本节为交互层命名纪律；视觉/文件命名随 §0.3 视觉轮补充。

- **D-12.1（动词 + 宾语，禁用同义反复）** 按钮/动作文案统一「动词 + 宾语」（「修改主密码」「生成恢复码」「移入回收站」），禁止同义反复（如「更新密码按钮 vs 密码更新按钮」）。判定：新增动作文案照此。
- **D-12.2（状态与动作区分）** 状态描述（「已启用/未启用/凭据已失效」）与动作（「启用/重新启用/关闭」）分离；同一状态的三态 caption 与按钮文案不得混用。判定：TouchID/MCP/恢复码三态区照此。
- **D-12.3（错误文案单源）** 错误与警示文案统一经 `ErrorPresenter` / `lastErrorMessage` 单源，视图不自行发明可区分性文案（FR-1.4 不可区分纪律）。判定：错误呈现一律走统一通道。

---

## 13. 可访问性清单（骨架，对齐 Requirements §2 与 Apple HIG）

> 视觉细则待 §0.3 视觉轮；行为层清单本轮可判定：

- **D-13.1（VoiceOver 标签）** 图标按钮、掩码切换、复制等无文本控件必须提供 accessibility label。判定：`FieldRowView` 复制/显示/隐藏按钮、`TotpCodeView` 复制按钮有 label；新增同类必带。
- **D-13.2（隐藏按钮不可达）** 隐藏快捷键按钮 `.accessibilityHidden(true)`（现有 `MainView.swift:313` 已立），不得让 VO 读到。判定：所有 `.hidden()` 快捷键按钮同步 accessibilityHidden。
- **D-13.3（键盘路径）** 所有可点击操作可经键盘触达（Tab 序列 + 快捷键）；只读页关闭 Esc 生效（D-4.1）。判定：走查无「仅鼠标可达」动作。
- **D-13.4（不依赖颜色单通道）** 状态不以颜色为唯一通道（错误辅以图标/文案）。判定：错误态、TOTP 临近刷新（`.orange` 倒计时环）均配图标或文案。
- **D-13.5（最小点击区）** 交互元素 ≥ 24pt，目标区 ≥ 40–44pt（高对比/大光标）。判定：`.controlSize(.small)` 行内按钮外框满足。

---

## 14. 与 Apple HIG / 项目纪律一致性核对

| 核对项 | 结论 |
|---|---|
| NavigationSplitView 三栏 | 与 HIG / requirements 一致（docs/13 §1、research 基线 #1） |
| .searchable 统一搜索 | 一致（requirements 硬约束，MainView.swift:269） |
| 系统语义色 / 无第三方设计系统 | 一致（requirements §4，视觉轮细化） |
| sheet 模态梯度（HIG：就地→sheet→窗口） | **张力登记**：ItemEditView 固定 560×560 多步 sheet 与 HIG 聚焦边界不符（lead 裁定 3：登记待评估，与设置拆 pane 同批）；本轮不改 |
| 设置组织（HIG pane ≤ 5） | **待评估**：9 节单长滚动（IA-01），拆侧栏 pane 登记 backlog（lead 裁定 3 / research 基线 #5） |
| 菜单栏常驻 / 全局键 | 与 Bitwarden/1P8 基准一致（research 基线 #2/3） |

---

## 15. 待回填项登记（对接锚点清单）

| 锚点 | 内容 | 依赖方 | 触发条件 |
|---|---|---|---|
| P-1.1 | 成功反馈完整形态矩阵（强度阈值 + 操作清单 + 文案结构） | ui-ux（P5 反馈规格） | P5 定稿后回填 |
| P-2.1 | 一次性首次高亮兜底（P2-A）：accent 圆点 + 「未完成设置」footnote；触发=引导跳过且功能未启用、清除=启用对应功能；挂 `bio_offer_skipped` / `recovery_offer_skipped` UserDefaults 契约（**已回填**，见 G2 规范条款） | ui-ux（P2-A 高亮规格）/ dev-team（UserDefaults 契约） | 已回填（v2.9.0 M2+lead） |
| P-3.1 | `copyWithAutoClear(_ value: String, clearSecs: TimeInterval)` 最终签名与迁移（**已回填**，见 §3 G3 条款） | dev-team（P5 剪贴板单点化） | 已回填（v2.9.0 M5） |
| P-6.1 | reveal 后明文自动收回触发集 | ui-ux（SEC-02 交互规格） | 规格定稿后回填 |
| P-6.2 | TOTP 可选隐藏开关评估结论 | ui-ux / lead（SEC-03 backlog） | 评估完成 |
| P-9.1 | P7 快捷键最终键表 + HK-2/3/4 冲突回归 | dev-team（P7） | P7 落地后回填 |

---

## 16. 变更登记表（骨架轮）

> 本仓此前无设计系统文档（docs/13 §0：缺口 G0），本节为骨架轮全部条款的「新增」登记。后续任何条款修订在此登记「新增/变更/废弃」缘由。

| 条款 | 类型 | 缘由（上游） |
|---|---|---|
| G1–G10 全部 D-* 条款 | 新增 | docs/13 §6 缺口 G1–G10 + §2 CO/SEC/ST/FW 条目 |
| P-* 待回填条款 | 新增（占位） | 8 提案 P5/P7 或 SEC-02/03 评估项 |
| D-10.2 | 新增（已裁定） | docs/13 §5 lead 裁定 2（锁定时关闭设置窗口） |
| D-1.2a | 新增（已登记例外，评审 REV2-02） | 恢复码复制反馈 2s + 「（30 秒后自动清除）」文案例外——FR-17.2 一次性纪律，安全提示不可丢；ux-spec P5 §5.1 为权威 |
| P-2.1 | 新增（已裁定，评审 REV2-03） | docs/13 lead 裁定⑤ P2-A 一次性首次高亮兜底（跳过引导后 accent 圆点 + 「未完成设置」footnote） |
| P-3.1 | 变更（占位 → 已回填定稿） | v2.9.0 M5 回填：`copyWithAutoClear(_:clearSecs:)` 显式时长版签名 + 恢复码复制迁统一 API（固定 30s）落定，见 §3 G3 |
| P-2.1 | 变更（待定稿 → 已回填定稿） | v2.9.0 M2 落地 + lead 回填：跳过旗标 UserDefaults 契约（@Published+didSet）+「已完成」live 派生 + FirstRunSetupHighlightRow 呈现落点，见 G2 规范条款 |
| D-7.5 | 新增 | docs/21 放置区导入（v2.11.0）：监视/等待态例外条款（非 G7 空态结构） |
| D-8.4 | 新增 | docs/21 放置区导入（v2.11.0）：预览层批量选择反馈（非写批次，与 D-8.1~8.3 互补；通用化措辞已去放置区化） |
| D-18.1~18.5 | 新增（新章 §18） | docs/21 放置区导入（v2.11.0）：外部目录授权（security-scoped bookmark）五条款 |

---

## 17. 骨架轮口径小结（供 lead 汇报）

- 章节数：**10 个行为缺口章**（G1–G10）+ 组件库存量 / 命名 / 可访问性 / HIG 核对 / 待回填登记 / 变更登记等支撑章。
- 可定稿条款（D-*）：**46 条**（G1:5 / G2:5 / G3:4 / G4:3 / G5:4 / G6:3 / G7:4 / G8:3 / G9:3 / G10:4 / 命名 3 / 可访问性 5）。
- 待回填条款（P-*）：**4 条**（P-1.1、P-6.1、P-6.2、P-9.1；P-3.1 见 §3 G3、P-2.1 见 G2 规范条款，均已回填）。
- 明确**本轮不立**：视觉 token / 色彩 / 间距 / 圆角 / 阴影 / 字体样式 / 图标规范（§0.3 占位）。
- 与 ui-ux 对接锚点：§15 表（P-1.1 反馈矩阵、P-6.1 明文自动收回、P-6.2 TOTP 隐藏开关为主要交互规格接口）。

---

## 18. §18 — 外部目录授权规范（security-scoped bookmark）

> 来源：docs/21 放置区导入（v2.11.0，2026-10-15）。适用于任何「App 获得用户目录持久化访问授权」的交互（当前唯一实例 = 放置区导入放置区目录；后续同型功能直接引用本条款）。

### 规范条款

- **D-18.1（授权即同意 + 范围明示）** 授权动作本身 = 用户对「监视/使用该目录」语义的同意，**不得二次确认弹窗**；授权范围声明（只读/目标路径/用途/零网络或最小权限/可撤销五要素）必须**承载于同意界面本身**（说明卡常显 + NSOpenPanel message 重申），不得只藏在文档或设置里。判定：同意界面可见五要素声明 + grep 无第二确认弹窗。
- **D-18.2（目录授权三态原语）** 授权状态呈现为三态：**未授权**（说明 + 授权入口）/ **已授权**（目录路径可见）/ **失效**（orange 警示 + 重新授权入口）；用统一状态组件（首例 `DropzoneAuthStatusView`）渲染，多出现面（向导内 + 设置页）同源。判定：三态渲染齐备、多出现面同组件。
- **D-18.3（失效非静默）** bookmark 失效（目录移动/删除/权限变更/系统清理）必须**就地呈现**（`.stale` 态 + 重新授权入口），不得静默失败或静默降级为无授权运行。判定：失效路径有显式呈现（A-3 判据）。
- **D-18.4（单写单删 + 移除广播）** 授权凭据（bookmark）只能由**一个写入点**创建、由**一个删除点**移除（首例：向导写、设置页删）；任一出现面的移除/失效必须**广播**到其他出现面同步状态。判定：grep bookmark 写/删各单点 + 状态广播可达。
- **D-18.5（作用域 = 应用级全局）** 目录授权为**应用级路径授权**，与密码库无关——切库不产生孤儿授权、**无按库重置**；多库场景须在监视/使用面明示当前生效目录（避免「以为监视 A 实际读 B」）。判定：bookmark 不含库标识 + 使用面路径明示。

### 迁移指引

| 现存面 | 现状 | 目标态 |
|---|---|---|
| 放置区导入（v2.11.0 新增） | 本规范首例 | 按 D-18.1~18.5 实现（docs/21 判据 A-1~A-6） |

---

*ui-standard · 2026-10-12 · 本草案为 DESIGN.md 前身，证据行号基于审查时点 Pro trunk，实现时重新核对锚点。§18 由 docs/21 放置区导入设计轮沉淀（2026-10-15）。*
