# Coffer 变更记录（Changelog）

本文件为**发布版变更记录**：每个已发布版本一行「主题 + 交付要点」，对齐
docs/02-研发计划与决策/02-版本开发计划.md §0 速览表（权威版本→交付记录）。发版时由 release.yml 取本文件
当前版本段落作为 GitHub Release body（2026-10-10 用户需求：changelog 在
release 中有体现）。

格式约定：
- 顶部为**最新版本**；每个版本段以 `## vX.Y.Z` 标题开头，release.yml 按此切取。
- 版本段内两节：`### 新增/变化` 与 `### 修复/纪律`，可按实际取舍。
- 未发版但在途的版本标 `## [Unreleased]`，发版时改为 `## vX.Y.Z` 并补日期。

---

## [Unreleased]

### 修复/纪律
- **公共文档英文化（国际化运营口径）**：GitHub 默认展示的对外文档此前只有 README 是英文，其余仍是中文——国际用户从 Issue / 安全报告 / 贡献指南三个入口进来全部撞中文。本次把 `CONTRIBUTING` / `SECURITY` / `CODE_OF_CONDUCT` / `CLA` / `FEATURES` / `docs/README` / `macos/README` / `android/README` 八份改为英文默认，中文版另存同名 `*.zh.md`，两版顶部互相链接；`.github` 的 Issue / PR 模板改为纯英文（允许任何语言作答）。`docs/README.en.md` 撤销，英文索引即 `docs/README.md`。
  - 门禁从「README 单对」扩为「九对公共文档 + 四份模板」：英文页混入中文即 FAIL（行内代码、链接目标、路径式链接文字、UI 语言名「简体中文」放行），切换链接必须互指，成对文件必须同时存在。`tools/check_docs_facts.sh` ⑦，本次 16 PASS / 0 FAIL。
  - 事实修正（顺带，均以 README / 现状为准）：「无自动更新 → 安全补丁滞后」改为「自托管 OTA（opt-in + 白名单）」，与 v2.7.0 已交付事实对齐；主密码遗失条目补 FR-17 恢复通道，删除「无恢复机制」绝对化表述；零网络验证示例去掉 Android `aapt` 段（Android 端未开工）。

- **删除「多库规划」表述**：`FEATURES.md` 的「多库 | 规划 | 后续版本」行事实错误——多库 UI / 跨库复制早在 **v0.4.0 作为免费功能交付**（FR-1.2 / FR-2.10，`docs/02-研发计划与决策/01-开发计划.md` §6），该行改为 `✅ v0.4.0 已交付`。`docs/03-功能设计/20-v2.10.0-Pro商业化路线-设计.md` 两处「多库为 Pro 规划项」随之修正，并在文首补去 Pro 化作废注记。全文已无「多库规划 / 后续版本」类表述。
  - 行为未变，故不升版本号。
- **内网 GitLab 源码仓更名：coffer-pro → coffer**。Pro 版本已不存在（去 Pro 化 OS-1/OS-3），仓名随之收敛。同域下旧的免费版快照仓（2026-10-11，描述仍写「Pro 版另仓」）已删除，其提交仍在本地仓对象库中可回溯。`tools/export_ci_secrets_gitlab.sh` 默认目标仓改为 `cygnusyang/coffer`（`GITLAB_PROJECT` 仍可覆盖），`.gitlab-ci.yml` 的 OTA 双仓说明与 Release 描述文案同步去 Pro 字样。

---

## v2.13.3 — 2026-10-25

### 修复/纪律
- **BUG-35 第一阶段：导入 / 放置区预检告警英文化**。此前 37 处告警都是 Rust 侧 `format!` 出的中文整句，经 FFI 原样进 `Label(warning)`，英文界面必现中文（v2.13.0 的显式非目标）。本版把 **CSV / 放置区**这 10 个生成点改成「码 + 参数」编码（`code|param1|param2`，`core/cf-importer/src/warning.rs` 负责转义与编解码），由 Swift 侧 `ImportWarningText` 按码取本地化模板渲染，**未知码原样回退**（保证其余 importer 不受影响）。
  - 覆盖 8 类：缺失 Title / TOTP 无法解析（两档）/ 布尔列非法 / 多出列 / 公式前缀 / 重复标题 / 密码历史丢弃；中文模板与 Rust 原句逐字一致，语义与行号零变化。
  - 未改 FFI 契约（`warnings` 仍是 `Vec<String>`），避免 uniffi 绑定重生成；新增 Rust 6 条编解码单测 + Swift 16 条文案断言。
  - 测试入口收口：`run_core_error_text_tests.sh` 与新增的 `run_import_warning_text_tests.sh` 一并挂进 `tools/run_l10n_tests.sh`，消灭「有 harness 没人跑」。
  - **仍为中文（第二阶段）**：Bitwarden / OPVault / PUX 的 mapping 逐条目告警（29 处），以及放置区的 `conflictNote`（与库内同名条目用户名不同）。

---

## v2.13.2 — 2026-10-25

### 修复/纪律
- **#2 条目删除入口补齐**：此前删除只有详情页工具栏的一枚图标按钮（无文字、窗口变窄会进溢出菜单），列表右键只有「复制到其他库…」、文件菜单只有「新建条目…/锁定」、⌘⌫ 无响应 —— 用户据此判定「条目无法删除」。本版补三条对称入口：① 列表行右键：非回收站 → 「移到回收站」，回收站 → 「恢复」；② 文件菜单新增「移到回收站」+ **⌘⌫**（无选中项时置灰）；③ 详情页右键菜单补「移到回收站 / 恢复」。删除能力本身未改（仍走 `model.deleteItem(itemId:hard:)`，测试基建与回收站语义不变）。

---

## v2.13.1 — 2026-10-24

### 新增/变化
- **设置页紧凑化**：`Form.grouped` → `ScrollView` + 自绘卡片（`SettingsStyle.swift`）。实测依据：`.listRowInsets` / `.defaultMinRowHeight` / `.contentMargins(.vertical)` 在 macOS 26 的 grouped Form 上**全部无效**，`.listSectionSpacing` 直接 unavailable，唯一有效的 `.controlSize(.small)` 只能把行高 44→40 —— 用户抱怨的三项（左右留白、行高、节距）在系统 Form 下不可调。
  - 目标值（实测现状 → 现在）：卡片左右外边距 20→**12**、行 inset 10→**8**、行高 37.5/44/53→**32/36/44**、卡间距 10→**8**、页顶底 20→**12**、窗宽 480→**460**；典型节高 98pt→**71pt（−28%）**。
  - 交互语义零变化：控件数量/顺序/绑定/动作逐节清点一致；行内按钮用 `.contentShape` + `minHeight: 28` 扩命中区，**视觉尺寸不变**；卡片标题改挂容器 accessibilityLabel（页头 Text 隐藏），VoiceOver 仍可读到节名。
  - 已知取舍：放弃系统 Form 的行为集（行 hover / key-view proxy / 系统节距），无可等价 API——用户已确认接受。

### 修复/纪律
- **BUG-36 核销**：设置页内容固定 460pt 但窗口沿用旧 900pt 存档 → 卡片居中、两侧大片空白（比改造前更差）。修复：settings Window 加 `defaultSize(460, 680)` + `windowResizability(.contentSize)`；真机复测窗口收敛为 460。
- 判据文档随实现校正 3 处：`TC-SET-52` 改读 AXGroup title（自绘卡片下无节标题 StaticText）、`.lineLimit(1)` 由「零命中」降为「不新增」、`GATE-SET-5` 明确常量不算裸数字。

---

## v2.13.0 — 2026-10-24

### 新增/变化
- **多语言（简体中文 + English）**：界面文案全量英文化，语言入口在「设置 → 语言」（跟随系统 / 简体中文 / English），写 App 偏好域 `AppleLanguages`，**下一进程生效**。
  - 方案：**中文原文当 key**，只发 `en.lproj`，缺键回落键本身 → 中文侧零迁移；资源在 codesign **之前**装配（签名后加资源会破 `codesign --verify --strict`）。
  - 译文 **998 条**（00-common 33 / ui-a 356 / ui-b 399 / support 186 / errors 24）+ `InfoPlist.strings`；覆盖 52 个 View 与非视图层（AppModel / Platform / Updater / Dropzone / 菜单 / 帮助中心章节标题）。**帮助中心正文按设计 §5.7 明确不翻**（仅加一行英文说明 banner）。
  - 门禁 `tools/check_l10n.sh`：**G1–G5 硬门禁**（缺键 / 跨片重复键 / 占位符类型 / 未转义 `%` / 死键）+ **G6/G7 软报**（源码覆盖统计 / 分片条目统计）；构建期合并源分片，产物不入库。
  - 错误面：新增 `CoreErrorText`（20 个核心码）+ 复用 LicenseErrorText / TouchIDError；**已知码按码出文案、原始载荷入诊断日志；未知码保留 `code + 载荷` 兜底**（可诊断性优先，并非一律不显示载荷）。错误码 / OSStatus 一律 `%@`（Int 插值会把 1005 写成 1,005）。
  - 工程/文档随发：docs/assets 19 张 SVG 全量英文化；README 徽章 + 中英切换 + `README.en.md` + 架构图；README 下载量统计表（CI 每周自动刷新）。
- **中文可见文案仅 3 类变化**（L10N-05「中文零回归」的完整例外清单）：① 已知核心错误码弹窗（`错误 1005：corrupted container: KDF 参数非法：…` → `密码库文件已损坏，无法读取。`）；② 更新失败收尾（`…更新安装失败：更新包签名校验未通过，未做任何修改。` → `…更新包未能安装。请重新下载更新包后重试。`）；③ 安装/注册辅助进程失败的「退出码 N」提示。其余中文逐字不变，未知码文案不变。
- 已知限制（显式登记，非缺陷）：导入 / 放置区预检告警整句来自 Rust 侧（40 处 `warnings.push` 中 39 处含中文），经 `Text/Label(warning)` 直出导入页，**本版不翻**；计划 v2.13.1 按「告警码 + 参数」补齐。验收判据已为其开例外。

### 修复/纪律
- **BUG-18 核销**：cf-mcp UDS 就绪判据由「socket 文件存在」改为「connect 成功」（`src/uds.rs:481`），8 处连接点接线；6 轮全量 0 flaky。
- **BUG-19 核销**：`write_stdin_allowing_early_exit` fail-closed 收口（`tests/cli.rs:593`），调用点恢复 `expect`，消除 CI 间歇 BrokenPipe；本地 20/20。
- **设置窗误判修复**：`CofferApp` 用中文原文 `!= "设置"` 比对窗口标题，英文界面失配会让设置窗被当成主窗口（⌥⌘P 错焦）→ 改 `String(localized:)`。
- 设计文档按实施期实测修订 5 处：占位符按声明类型（`UInt32→%u` / `UInt64→%llu` / `Int32→%d`）、译文占位符不得重排、码位不用 Int 插值、`String(localized:)` 回落行为（**真插值才代入**；手写 `%-spec` 的无插值字面量等价于 `NSLocalizedString`）、字段名创建时本地化并落库（`designation` 才是语义锚点）。

### 验证
- 16 个 macOS harness **673 passed / 0 failed**；`cargo test -p cf-mcp` 两轮各 **373 passed / 0 failed** 无 flaky；全 App `swiftc -typecheck` 108 文件 **0 error / 0 warning**；完整 `build_macos_app.sh` 通过且 `codesign --verify --strict` valid。
- 运行时取证（真 .app + 998 键表）：en 下 `%lld` / `%u` / `%@` / 无插值四类均正确渲染，CoreErrorText 6 码全英文；`-AppleLanguages '(ja)'` 回落中文；全仓 **1150 个可判定占位符站点 0 类型违规**。
- 真机 AX 英文扫描**阻塞**：本机 0 codesigning identity，未做。

---
## v2.12.1 — 2026-10-24

### 修复/纪律
- **#1（S2）CodeBuddy 自动注册恒失败**（Issue #1；开关 ON 报「注册失败：无法清理旧的 coffer 注册项」）：helper 由沙盒 App 经 `open` 拉起，继承的是精简 PATH；`codebuddy` 是 `#!/usr/bin/env node` 脚本，spawn 时 `env: node: No such file or directory` → status 127，upsert 的移除步与 add 步全数失败（Claude Code 为原生 Mach-O，故同一开关正常）。修复：spawn 目标 CLI 前读其首行 shebang，若为 `/usr/bin/env <interp>` 则复用 `resolveCLIPath` 解析解释器绝对路径，把该目录**前置**进子进程 PATH 并补系统默认目录兜底（register / remove 两条路径同改，命令形状与 argv 直传安全契约不变）。新增 `SpawnEnvironment` 纯函数（shebang 解析 / PATH 去重保序）+ 8 条单测，`run_mcp_registrar_tests.sh` 208 passed / 0 failed；helper typecheck 通过，注入 PATH 后 `codebuddy mcp --help` 由 127 → exit 0。影响面：CodeBuddy 及任何脚本型（`#!/usr/bin/env …`）CLI 的自动注册/移除。

---

## v2.12.0 — 2026-10-22

### 新增/变化
- **多 AI 工具注册（P0）**：设置页「MCP / Agent 协作」新增「AI 工具」列表——Claude Code / CodeBuddy / Codex 三家自动注册（各带独立开关与状态回读），Gemini CLI / Cursor / VS Code / Windsurf / Zed 提供一键复制命令/配置。总开关 ON 注册所有已安装且启用的工具，OFF 批量移除（有已注册项时二次确认），单个工具开关独立生效。注册仍经非沙盒 helper、argv 直传无 shell 拼接；解锁走 MCP 托管，全程无密码 env。

---

## v2.11.1 — 2026-10-22

### 修复/纪律
- **BUG-33（阻断，S2/P1）**：MCP 托管解锁恒失败——CLI 读 Keychain 用的是 bundle id 改名前的旧 access group `A6DS985SJJ.app.coffer.Coffer`，而 App 自 d396fab 起把条目写入 `A6DS985SJJ.top.cygnusyang.coffer`，条目跨组不可见 → `errSecItemNotFound` → 误落 env 兜底并报「未启用 MCP 解锁托管」。修复为**新组优先、旧组兜底**：主组未命中才试 legacy，任何 `Err`（缺 entitlement / ACL / 签名）仍 fail-closed 不回落；Keychain 条目与写入路径不动（非破坏性，旧条目仍可解锁）。`cf-mcp` 新增 5 条纯逻辑单测（候选顺序 / 兜底命中 / 命中短路 / 错误不兜底 / 全未命中），`cargo test -p cf-mcp escrow` 18 passed。影响面：Claude Code / CodeBuddy / Codex 等全部 MCP 客户端。

---


### 新增/变化
- **Claude Code 插件收编进主仓**：独立仓 coffer-claude（@79d2e7b）插件整体迁入 `plugins/claude-code/`（MCP 服务器 + 2 个 skills + 登录助手，功能不变；清除本机硬编码回落路径、独立注册脚本 remove 对齐 `--scope user`），根级 `.claude-plugin/marketplace.json` 取代原自源式市场清单；安装入口变更为 `claude plugin marketplace add cygnusyang/coffer` + `claude plugin install coffer@coffer`；插件许可随主仓 AGPL-3.0（原 MIT LICENSE 不随迁）；README「与 AI 工具协同（MCP）」节新增插件安装为推荐路径，手动注册降级兜底。

---

## v2.11.0 — 2026-10-18

### 新增/变化
- **放置区导入**（v2.11.0 主特性，docs/21）：从 macOS「密码」App 导出 CSV 到授权目录（放置区），App 自动检测新导出、Safari 列映射、库内去重分类、预览后选择集导入——密码明文全程只在 core 内存解析、不跨 FFI 进 Agent/日志（R2 最强姿态）；工具栏/空态/数据菜单三处入口，向导 S0-S5 状态机 + 授权/监视/去重三组件。
- **MCP 一键注册**（docs/18 §10）：设置页「MCP / Agent 协作」开关联动——ON 自动注册（upsert）到 Claude Code、OFF 自动移除，注册经嵌入式无沙盒 helper（CofferMcpHelper.app）完成，全程无密码参与（R2）；claude 未安装时给安装引导。
- **去 Pro 化，全产品免费 + 开源（AGPL-3.0）**：set-env（写环境容器）与环境容器 App 编辑转为免费功能（pro feature 门控拆除）；仓库主仓迁 GitHub 公开开源，GitLab 转镜像；OTA 端点切 GitHub Releases（清单 URL `github.com/cygnusyang/coffer/releases/latest/download/update-manifest.json`，白名单回归 4 GitHub host）。
- **UI 测试自动化三层落地**（docs/19）：L1 放置区模型面 32/0 + L2 真样全链路 8/0 + L3 AX 黑盒 harness（19 断言），`run_ui_gate.sh` 三段汇总门禁。
- **菜单栏精简**：取消灰色状态行，状态文案并入「打开主窗口」项标题（2026-10-16 用户裁定）。
- **文档**：NASA KSC-DF-107 风格指南落档 + 试点；README 补 CLI/MCP 注册全文档（R2 stdin 取值纪律、退出码表）；全仓 MIT → AGPL-3.0；CLA v1.1。

### 修复/纪律
- **BUG-32**：菜单栏「数据」菜单解锁态恒灰——独立 Commands 结构体在 macOS 26 上 enabled 不随 phase 更新（Divider 前恒卡启动初态），内联回 App body `.commands` 修复；AX 黑盒双向（锁定 false → 解锁 true → 重锁 false）实证 + harness 断言升级（18→19）。
- **README 恢复断言事实修正**：删除「遗失 = 数据永久丢失」绝对化表述——已启用 Touch ID 解锁或已生成离线恢复码（FR-17，均 opt-in）可重设主密码。
- **OTA 嵌套 helper 验签 allowlist 补列**（`top.cygnusyang.coffer.mcpregister`，MCP 一键注册轮引入的嵌套 bundle 此前未过 UpdateTests 漏列）；UpdateTests 226/0/2 全绿。
- GitHub Actions 首跑踩出的 cli 测试 helper stdin 写入竞态（Linux BrokenPipe）修复；L3 harness 间歇 flake 加固（双锚点 + 60 轮预算 + 超时自诊断）；run_ui_gate 段状态 PIPESTATUS 假绿修复。

---

## v2.10.3 — 2026-10-15

### 新增/变化
- **OTA 下载完整性加固**：更新清单新增 zip SHA256 字段（签名覆盖），App 下载后解压前流式校验、不匹配拒装（向后兼容 v2.10.2 旧清单）；OTA 通道探针同步强制必含/格式门禁。
- **自证页事实修正**：设置 →「网络能力自证」对齐 OTA 更新豁免——声明改为「数据都在本机不上传云端 + Rust 核心依赖图零网络 + 唯一联网例外=OTA」，自证步骤断言与 entitlements/otool 实测一致（#89）。

### 修复/纪律
- cf-mcp uds 集成测试启动竞态修复（GAP-05）：等 accept-ready 而非 socket 文件存在，全量门禁 3 轮 0 flaky。
- GitLab UX issue #1/#3/#6/#7 簿记补关（v2.10.0 已落地，关闭备注附落地 commit 与判据）。

---

## v2.10.2 — 2026-10-15

### 新增/变化
- **OTA 全链路修复轮收口（BUG-23~31 统一核销）**：五次真机复测逐层实证，全链路（检查→下载→验签→替换→自动重开）真机闭环
- **零网络口径改造**：关于页/使用入门/帮助中心「不联网」改为「数据都在本地，不上传到云端，本地服务 + 本地大模型工具」（OTA 例外事实保留）

### 修复/纪律
- BUG-23 检查更新网络失败不再泄露原始 NSError；BUG-24 检查更新即时反馈（sheet 延迟呈现修正）
- BUG-25 OTA 清单迁移公开产物仓（匿名可达）；BUG-26 安装卡死（sheet 拦 terminate）；BUG-27 profile 过期 fail-fast
- BUG-28 manifest 禁用 URLCache；BUG-29 helper 启动改 open(1)+文件日志+启动路径守卫；BUG-30 三源取参兜底 --args 剥离；BUG-31 helper 剥下载产物 quarantine
- OTA 通道定时探针（CI schedule 每日）+ 可自动化集成测试（38 项）

---

## v2.10.1 — 2026-10-13

### 新增/变化
- **帮助中心**（docs/19）：完整参考面板（九章：欢迎 / 开始使用 / 日常操作 / 键盘快捷键三组 / 备份与恢复 / 安全 / MCP / 常见问题 / 故障排查），与「使用入门」并存为其超集；内容源 HelpCenterContent 静态本地文案，零网络。
- **帮助菜单根因修复**：「帮助」菜单改 `CommandGroup(replacing: .help)`，修复 AppKit 把「帮助」标题菜单当 helpMenu 注入系统搜索框、未注册 Help Book 时空菜单报错的根因；菜单新增「帮助中心…」入口（键盘快捷键… / 使用入门… / 帮助中心… 三入口并列）。

---

## v2.10.0 — 2026-10-13

### 新增/变化
- **库删除**（v2.10.0-D1）：设置「管理密码库…」新增删除库能力——输入库名确认（无密码步，防误触）；锁定态可删、删当前库后自动落位到其余库或无库首屏；删除前先走导出前置步（导出面板按目标库参数化），误删防线=墓碑式三步删除链（重命名→删 header→删目录，中断可恢复）。Core `delete_vault` 与 App UI 同版落地。
- **菜单栏图标重绘**（D2）：挂锁锁梁从圆形长弧改为椭圆上半弧+短竖直腿，视觉重心修正、梁/体比例更均衡；锁定/解锁双态区分度经几何断言测试锁定（docs/18 视觉规格）。
- **v2.9.1 顺延项全落地**（GitLab issue #1/#3/#6/#7 closed）：
  - **锁定态恢复入口**（#1）：锁定页新增低存在感「管理密码库…」链接直达恢复面板。
  - **关于页完整自我介绍**（#3）：「了解 Coffer」自述区（零网络有意设计 / MCP 走 CLI / 备份=导出+恢复）。
  - **使用入门完整版**（#6）：导入/导出/恢复/快捷键四段式指引，含锁定态恢复路径。
  - **向导内密码归一**（#7）：首启向导与建库表单密码创建逻辑归一（docs/15 A1），M-2 门控同步。
- **FRICT 快赢批**：8 条脆弱性/一致性快赢 + FRICT-14 securityCritical 禁跳过（安全纪律硬化）。
- **测试基座**：core workspace 覆盖率设施落地（cargo-llvm-cov），全 workspace 93.39%；cf-escrow-keychain 补 mock 测试接缝（release 机器码零变化），单元门禁 1408/0/9。

### 修复/纪律
- **GAP-03**：InstallHelper 测试脚本同 CN 双证书歧义——`security cms -S` 改用 `-Z <SKID>` 消歧（仅测试脚本，不影响产物）。
- **缺陷登记**：GAP-02（官方 bootstrap 缺位，LOW/P3 顺延）、GAP-04（cf-escrow-keychain 覆盖率例外 69.43%，llvm-cov 口径硬顶 ~70%）、GAP-05（cf-mcp uds 测试启动竞态 flaky，修复顺延下版）显式登记于 docs/17 §14。

---

## v2.9.2 — 2026-10-13

### 新增/变化
- **关于页「编译时间」行**：build 脚本装配时向产物 Info.plist 注入构建时刻（`CofferBuildTime`），关于页版本行下方显示「编译时间 …」；未注入的产物（如 Xcode 直跑）回退显示「开发构建」。测试时凭关于页即可辨识是哪次构建。

### 修复/纪律
- **BUG-22（HIGH/P0）导出失败：错误 2003「创建临时文件失败： Operation not permitted」**——v2.4.0 沙盒化后保存面板只授予所选文件本身写权限，导出在目标同目录创建兄弟临时文件被沙盒拦截（加密备份与 1Password 导出受影响，CSV 不受影响）。修复：权限类错误回退容器临时目录写入，再经保存面板授权的目标文件落盘；非沙盒 CLI 原子落定路径不变。

---

## v2.9.1 — 2026-10-13

### 新增/变化
- **上手门槛修复批**（GitLab issue #1/#2/#4/#5/#6，dev team 评估裁定 4 入 3 顺延）：
  - **首屏恢复备份入口**：无库首屏建库表单下新增「已有备份？从备份恢复…」，换机/重装用户不再被迫先建空库（#1）。
  - **空库双主路径**：新建库后空态提供「新建第一个条目」与「导入已有密码…」并列按钮，迁移路径不再藏在工具栏子菜单（#2）。
  - **建库强度文案用户化**：移除「zxcvbn < 3」黑话，强度不足时内联预警提示改进方向；创建门禁不变（#4）。
  - **帮助菜单**：新增「键盘快捷键…」速查面板与「使用入门…」三问最小版（忘主密码/备份/Touch ID 行为），纯本地静态呈现（#5/#6）。
- 顺延 v2.10.0（登记在 issue，保持 opened）：#3 应用自我介绍文案、#6 使用入门完整版、#7 首启密码归一（docs/15 A1 方案已定稿）、#1 锁定态恢复入口。
- **交互优化轮全量落地**（设计提案 docs/13 + 规格 docs/14，P1–P7 + B.1 免规格项）：
  - **首启引导向导**：生物识别与恢复码两个开箱 offer 合并为单一分步向导，可跳过；设置页提供首次入口高亮兜底；锁定时设置窗口自动关闭（主窗解锁态与设置窗联动）。
  - **恢复码抄写验证步**：恢复码展示页新增抄写验证——代码隐藏、无返回查看、进入验证即清剪贴板；固定 30 秒自动清除不受剪贴板档位设置影响。
  - **应用快捷键补齐**：⌘N 新建条目、⌘L 锁定、⌘⇧C 复制密码、⌘U 复制用户名、⌥⇧C 复制 TOTP。**冲突提示**：剪贴板管理、截图类工具常注册 ⌘⇧C/⌥⇧C 全局热键可能拦截；若在第三方工具侧占用同键，请在其中一处改键并保持两侧一致。
  - **导入向导壳统一**：四格式（加密备份/明文 CSV/OPVault/1Password）导入收敛到统一壳——进度、失败恢复与事务语义一致（单格式事务语义文案逐字保留）；「数据」菜单补齐 OPVault 导入入口。
  - **安全体检详情区**：体检结果从弹窗改为详情区内嵌展示，加载失败就地错误态可重试。
  - **更新流程更稳妥**：发现新版本先下载、验签通过后弹确认再安装，不再自动直接进入安装。
  - **其他交互修正**：清空回收站聚合反馈、审计日志/关于页「关闭」语义、跨库 Touch ID 弹窗指明目标库、详情标题与字段名长文本截断、锁定按钮不再被解锁请求误禁用、恢复备份失败文案不误导删除。
- **Info.plist 版本**：2.9.1（对齐 tag；2.9.0 轮内容并入本版，2.9.0 tag 未打）。
- **UI 设计轮**：启动认证流优化设计 docs/15 r0.4 定稿（A1 密码归一 + Touch ID 授权矩阵 + 摩擦全检 23 条），实现归 v2.10.0。

### 修复/纪律
- 恢复码固定 30 秒剪贴板清除与用户档位任务分槽：修复改档会误取消恢复码定时清除的回归（登记号 REV-DEV-01，dev-reviewer HIGH，已复审闭环）。
- UpdateTests 白名单断言对齐 OTA 5 host 契约（登记号 BUG-20 已核销）；TC-SEC-02/03/INST-03 依赖 Developer ID 产物为已知环境项（BUG-21，ADP 到位后自愈）。

## v2.8.2 — 2026-10-11

### 新增/变化
- **每周重签刷新版**（免费账号 7 天 profile 续窗循环）：无功能变化，CI 用刷新后的 provisioning profile 重建三资产（DMG + zip + OTA 清单）并重签。旧包 profile 已于 2026-10-11 00:56 过期，本版以新 7 天窗口发布；安装本版 DMG 后，后续可趁 App 存活期内 OTA 自更新续窗。

## v2.8.1 — 2026-10-10

### 新增/变化
- **MCP `get_secret_metadata` 出参补 `username`**（只读增强）：条目带 `Designation::Username` 字段（Email 兜底）时直出登录用户名，无则 `null`；摘要面 `list_secrets` 不解密条目、恒 `null`。R2 纪律不变：密码值永不出元数据信封。动机：agent 经 MCP 只见「条目名+密码值」形态，误判「条目结构无用户名字段」（2026-10-10 真机实证），补出参后无需 `.username` 独立条目 workaround。

## v2.8.0 — 2026-10-10

### 新增/变化
- **CLI `coffer set-env` 写子命令**（docs/03-功能设计/12-v2.8.0-环境容器写面-设计.md 契约冻结）：`--scope <owner> NAME=VALUE`
  原子写，owner 缺失自动建容器；`--id <UUID>` 兜底定位；`--unset` 删除；
  裸 NAME 走 stdin 取值（值不落 argv/stdout/日志，R2 纪律）；退出码 0/1/2/4。
- **App 环境容器编辑保护**：标签锁（保留标签 `coffer:environment`）+ 识别徽章 +
  NAME 校验告警 + 通用「添加字段」能力；三方识别统一 SecureNote + tag 双条件。
- 并发首写双守卫 + `prune_race` 只删空容器（防已提交写入硬删丢失）+ BUSY 有界重试。

## v2.7.0 — 2026-10-10

### 新增/变化
- **OTA 自研最小更新器**（docs/03-功能设计/11-v2.7.0-OTA升级-设计.md 契约冻结）：App 内「关于 → 主动升级」，设置页排除。
  固定清单 URL（`releases/latest/download/update-manifest.json`）挂 EdDSA 签名，
  只认 4 个白名单 host；更新密钥放 CI secrets（绝不落仓）。
- **安装辅助器**（`Contents/Helpers/CofferUpdater.app` 嵌套 bundle）：单缝 relaunch
  安全门 + 静态验签（C-1/C-2 双锚），替换/回滚/Keychain 不破/profile 过期拒装。
- 零网络边界维持：更新期**最小豁免** `network.client` 一项，其余 network.* 全禁。

### 修复/纪律
- CI 上传 update-manifest 显式注入 `GH_TOKEN`（裸 gh 不读 Actions GITHUB_TOKEN）。

## v2.5.1 — 2026-10-10

### 新增/变化
- **密码更新写面 FR-18 补发**（v2.5.0 tag 先切未纳入，用户裁定归 v2.5.1）：
  App 条目「更新密码」快捷动作（FR-18.1）+ CLI `coffer set-password`（FR-18.2，
  stdin 取密不进 argv/log/ps，escrow→env 兜底 fail-closed）。

## v2.5.0 — 2026-10-10

### 新增/变化
- **主密码恢复通道**：FR-17.1 生物识别重置主密码（免旧密码）+ FR-17.2 离线恢复码
  （BIP39-12，header `recovery_wrap`）+ BUG-17 可见窗口锁定态激活自动弹 Touch ID。

## v2.4.1 — 2026-10-09

### 新增/变化
- 设置页改**独立窗口 + 左上角红绿灯**（macOS 系统设置样式，红绿灯不随内容滚动、
  随时可关闭）；标题栏强制不透明；主密码强度要求常驻 UI。
- **GitHub CI 发版自动化**：tag `v*` → 门禁 + clippy + macOS 构建签名 + 自动创建 Release。

## v2.4.0 — 2026-10-09

### 新增/变化
- 浏览器扩展整体废弃收口（App 侧集成移除）；构建双渠道 → **沙盒单渠道**；
  DEK retention 层 + unlock_with_dek 裁除。

## v2.2.0 — 2026-10-07

### 新增/变化
- **MCP 解锁托管**：HKDF 派生 `mcp_key`（非主密码本身）入 Keychain escrow；
  CLI 取密回退（托管优先 → env 兜底）；设置页 provider 翻转收口。

## v2.1.0 — 2026-10-07

### 新增/变化
- MCP 缺省 provider 翻转（自家 vault 转正）；生产级随机轮换；审计日志 subscriber；
  **UDS 传输**（D-4 §3.6 防护全套）；零网络措辞全仓改写。

## v2.0.0 — 2026-10-07

### 新增/变化
- **Agent 凭据域 / MCP**：门面 8 操作真实实现 + CofferStoreProvider feature 门控
  + `coffer mcp` 接线 + L-7 有界读取 + 缺陷收敛（M-1/M-4/L-1~L-3/L-4/L-7）。

## v1.0.0 — 2026-10-05

### 新增/变化
- 冻结 + 审计轮：不新增功能；Argon2id 标定；验收标准逐条核对（判据②③ 挂 E-6 审计采购）。

## v0.7.0 — 2026-10-05

### 新增/变化
- 1PUX 导出（FR-8.2）/ opvault 导入（FR-7.3）/ 大字号（FR-12.4）/ 生成器默认参数·
  诊断·网络自证设置项（FR-14.3~14.5）/ TOTP QR 相机扫描（FR-5.3）。

## v0.6.0 — 2026-10-04

### 新增/变化
- **商业化：注册激活**：离线序列号激活（Ed25519 本地验签）、7 天试用、到期只读门禁、
  许可信息页、闭源激活模块（构建隔离）。

## v0.5.0 — （范围并入 v2.6.0）

### 说明
- Passkey **降级版**（FR-10.1/10.2/10.5/10.6）设计基准 docs/03-功能设计/05-v0.5.0-Passkey降级-实现方案.md r2.4，
  2026-10-09 用户裁定随 v2.6.0 重启（完整版随 ADP 购买）。

## v0.4.0 — （真机项移交 TC-M 清单）

### 新增/变化
- 菜单栏常驻、全局快捷键、模糊搜索、多库 UI、跨库复制、附件 UI、密码短语。

## v0.3.0 — 2026-09-28

### 新增/变化
- 1PUX 导入（含 `files/`）、预检报告、附件存储、条目历史、安全体检。

## v0.2.0 — （Swift UI 接线完成）

### 新增/变化
- 加密备份 / 恢复 / 校验、CSV 导出、改主密码、剪贴板清除配置、暴力退避。

## v0.1.1

### 新增/变化
- TOTP 语义补强：保留三态、只读配置 API、强度评估上移。

## v0.1.0

### 新增/变化
- macOS 纵切闭环：建库 / 主密码解锁 / 四类 CRUD / 搜索 / 回收站 / 复制+剪贴板清除 /
  自动锁定 / CSV 导入。
