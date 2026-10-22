# Coffer macOS UI 重设计 · 需求摘要（Requirements Brief）

> 受众：设计系统专家、原型构建师。本文件只给结论与规范，不含代码。
> 范围边界：**仅重设计 SwiftUI 界面，不触碰 Rust 内核 / UniFFI FFI**。本次先交付高保真 HTML 原型，方向确认后再改 Swift 代码。

---

## 0. 设计目标（Design Goals）

1. **原生感优先**：视觉与交互无限贴近 macOS 原生（钥匙串 / 系统设置 / 邮件），用户零学习成本。
2. **可信 > 炫技**：通过克制、留白、语义化系统色与细腻状态传递「安全 / 本地 / 零网络」的信任感，而非装饰性视觉。
3. **统一设计语言**：建立一致的间距节奏、卡片化分区、选中态 / 悬停态、空状态与图标规范，消除现有「朴素默认 SwiftUI」观感。
4. **深浅双模一等公民**：所有界面在浅色与深色下都经得起推敲，不依赖硬编码颜色。
5. **可访问性达标**：满足 macOS 辅助功能（大光标、高对比、VoiceOver 标签、最小可点击区）。

---

## 1. 五维度需求表

| 维度 | 结论 |
|------|------|
| **场景 (Surface)** | macOS 桌面 App（窗口化、三栏布局），目标 macOS 14 Sonoma+，仅 arm64。需原生窗口工具栏、侧栏、` .searchable` 搜索；同时适配浅色 / 深色模式，严格遵循 Apple HIG。 |
| **受众 (Audience)** | 重视隐私与安全的个人用户，含技术背景用户。诉求：可信、克制、不花哨；对「像系统原生」有高预期。 |
| **调性 (Tone)** | 原生 Apple 风——克制、留白充足、语义化系统色、SF Symbols 图标、细腻选中态与悬停、卡片化分区。视觉学派中最接近 **Modern Minimal**，但本质是「Apple HIG 原生」自有语言，而非第三方美学。 |
| **品牌上下文 (Brand)** | 无既有 VI / 设计规范。主色（accent）已定 = **系统蓝**（最贴近原生 macOS / 钥匙串的视觉惯性）。建议：在侧栏与锁屏以一个**克制的品牌符号**（coffer = 保险箱意象）作点缀，不喧宾夺主。 |
| **规模 (Scale)** | 多屏（9+ 界面）。原型阶段优先覆盖最高频 6 屏（锁屏、建库、主三栏、条目详情、条目编辑、安全设置）；其余 3 屏（导入、回收站、TOTP 码）给出统一规范即可。交互复杂度：静态高保真 + 关键状态（悬停 / 选中 / 掩码切换 / TOTP 倒计时 / 错误态）。 |

---

## 2. Apple HIG 必须遵守约束清单（Must-Follow）

以下为下游不可违背的硬约束，请逐条核对：

### 窗口与工具栏
- **窗口结构**：使用原生窗口（带标题栏 / 工具栏区）。主三栏界面用 `NavigationSplitView`，工具栏承载「新建 / 视图切换 / 搜索」等动作。
- **工具栏背景**：深浅色下工具栏背景与内容区有正确层级（`.toolbarBackground`），避免内容穿透。
- **最小窗口尺寸**：定义合理 min size；三栏布局在窄窗口下优雅降级（侧栏可收起 / 列表→详情切换式）。

### 侧栏（Sidebar）
- 使用 `.navigationSplitViewStyle` 的 sidebar 自适应样式；侧栏选中态使用 **系统 accent（蓝）**，不可自定义选中背景色绕过系统。
- 侧栏分组（全部条目 / 收藏 / 类别 / 回收站）用词与排序遵循系统惯例；图标用 SF Symbols 且风格一致（统一 `.regular`/`.medium` 字重）。
- 深色模式下侧栏背景由系统语义色自动处理，禁止硬编码。

### 搜索
- 主列表搜索统一走 `.searchable(text:placement:)`，搜索框置于列表列工具栏 / 导航标题，**不要**自己画一个 TextField 当搜索框。
- 搜索无结果需有空状态，而非空白。

### 按钮与强调层级（Button Prominence）
- **主操作**（解锁、创建密码库、保存）：`.buttonStyle(.borderedProminent)`，使用 accent 蓝。
- **次操作**（取消、移除）：`.buttonStyle(.bordered)`，中性色。
- **第三级 / 图标按钮**（复制、显示 / 隐藏、行内操作）：`.buttonStyle(.plain)` / `.borderless`，仅图标或轻量文字。
- 同一界面最多一个 `.borderedProminent` 主按钮，避免强调冲突。

### 颜色与深浅色
- 所有文本 / 背景 / 分隔线使用**语义系统色**：`Color.accentColor`、`Color.secondary`、`Color(.windowBackgroundColor)`、`Color(.textBackgroundColor)`、`Color(.separatorColor)`、`Color(.systemFill)` 等，**禁止**为文本和背景硬编码 hex。
- 状态色（成功 / 警告 / 错误 / 信息）用系统语义色：`Color.green/.orange/.red/.blue` 或 `Color(.systemGreen)` 系列，保证深浅色一致。
- accent = 系统蓝，通过 `.tint(.accentColor)` 或 Asset Catalog 统一设定。

### 排版与图标
- 字体使用 **SF Pro（系统字体）**，仅用文本样式（title1 / title2 / headline / body / callout / footnote / caption），不混用第三方字体。
- 图标一律 **SF Symbols**，保持字重、比例、variant（`.fill` 与否）一致。

### 间距与卡片化
- 间距节奏统一为 8 / 12 / 16 / 20 / 24 pt 体系；分区内边距一致。
- 分区使用 `.formStyle(.grouped)` 或自定义卡片：背景 `Color(.quaternarySystemFill)` / `.tertiarySystemFill`，圆角 10–12 pt，分隔用 `Color(.separatorColor)` 发丝线，不使用粗边框。

### 可访问性（Accessibility）
- 交互元素最小可点击区建议 **≥ 24 pt**；考虑辅助功能（更大光标 / 高对比）时目标区 **≥ 40–44 pt**。
- 所有图标按钮 / 掩码切换 / 复制等提供 **VoiceOver label**；列表行提供有意义的可访问性描述。
- 支持「增大文字」辅助设置（文本样式随系统动态缩放）。
- 不依赖颜色单一通道传达状态（如错误不仅靠红，辅以图标 / 文案）。

### 关键交互状态（原型必须呈现）
- **悬停（hover）**：列表行 / 按钮有细腻 hover 背景（`Color(.hover)` / 轻量 fill），非生硬反色。
- **选中（selection）**：列表行 / 侧栏项 accent 选中态。
- **掩码**：字段默认 `••••`，「显示 / 复制」就地切换，显示态有时限或手动收起。
- **TOTP**：等宽数字 + 倒计时环（进度指示），临近刷新有视觉提示。
- **错误态**：主密码错误 → 输入框红框 + 文案提示 + 轻微抖动（可选），不弹原生 alert 打断。
- **空状态**：列表 / 搜索无结果 / 回收站空，均提供图标 + 说明 + 可选动作，杜绝裸空白。

---

## 3. 原型界面清单与每屏设计重点

> 优先级：P0 = 原型必做；P1 = 给出统一规范即可。

### P0-1 · LockView（锁屏）
- 居中布局：品牌保险箱符号（克制点缀）+ 锁图标（SF Symbols `lock.shield.fill` 类）。
- 主密码 `SecureField` + 「解锁」「Touch ID 解锁」按钮（Touch ID 用对应 SF Symbol）。
- 重点：克制留白、错误态（红框 / 提示 / 抖动）、深浅色下居中卡片背景、最小窗口下的表现。

### P0-2 · VaultSetupView（建库）
- 居中图标 + 分组表单（库名、主密码 ×2、zxcvbn 强度条）+「创建密码库」。
- 重点：`.formStyle(.grouped)` 卡片化；zxcvbn 强度条用**语义色**（弱=红 / 中=橙 / 强=绿），非自定义渐变；两次密码不匹配提示；主按钮 prominence。

### P0-3 · MainView（主三栏）
- `NavigationSplitView` 三栏：侧栏（全部条目 / 收藏 / 类别 / 回收站）→ 列表（搜索 + 条目行）→ 详情。
- 重点：侧栏 accent 选中态、列表行 hover / 选中、`.searchable` 搜索框位置、工具栏（新建 / 视图）、空列表状态、深浅色 sidebar 层级。

### P0-4 · ItemDetailView（条目详情）
- `ScrollView` 分区：头部、字段、网址、标签、TOTP、信息。
- 重点：分区卡片化；字段「标签 / 值」两列对齐；掩码 `••••` + 显示 / 复制就地交互；TOTP 倒计时环；空字段优雅隐藏或占位；复制按钮 hover。

### P0-5 · ItemEditView（条目编辑）
- 固定 560×560 分组表单，按类别模板渲染字段，TOTP 三态（保留 / 替换 / 移除）。
- 重点：固定窗口尺寸下分区清晰；类别切换即时换模板；TOTP 三态 UI（保留=原值 / 替换=新输入 / 移除=清空确认）；保存（prominent）/ 取消（bordered）；字段校验（必填、URL 格式）。

### P0-6 · SecuritySettingsView（安全设置）
- 分组表单：自动锁定、Touch ID、密码生成器参数、清除数据等。
- 重点：Settings 风格 `.formStyle(.grouped)`；`Toggle` 开关语义正确；分区（常规 / 安全 / 高级）；破坏性操作（清除 / 导出）需确认态，不与普通操作同层级。

### P1-7 · ImportView（CSV 导入）
- 文件选择（拖拽 / 打开面板）+ 字段映射 + 进度 / 结果反馈。
- 规范：文件选择用系统面板样式；映射表用分组卡片；导入中显示进度，完成后给结果摘要与错误项。

### P1-8 · TrashView（回收站）
- 列表 + 恢复 / 彻底删除（批量）。
- 规范：空状态；批量选择；彻底删除走确认；与 MainView 列表视觉一致。

### P1-9 · TotpCodeView（TOTP 码）
- 大号 TOTP 码 + 倒计时环 + 复制。
- 规范：大号等宽数字（`Font.monospacedDigit`）；倒计时环用 accent；临近刷新高亮；复制一键。

---

## 4. 推荐方向（供下游直接消费）

- **建议设计系统类型**：不引入第三方品牌设计系统；以 **Apple HIG 设计令牌** 自建一套轻量 Design Tokens（语义色板、SF 文本样式比例、8/12/16/20/24 间距、圆角 10–12、发丝分隔线、按钮三层 prominence、状态色）。可参考设计系统库里的 **Modern Minimal** 作为间距 / 留白节奏的旁证，但令牌来源必须是系统语义色。
- **建议原型模板**：**macOS 窗口框原型模板**（HTML 高保真）—— 每屏外裹原生窗口 chrome（红黄绿 traffic lights + 标题栏 + 工具栏占位），内部严格按上述 HIG 约束实现。无现成「macOS App」模板时，以「dashboard / web app」结构为基底并替换为桌面窗口框架与 SwiftUI 语义组件映射。
- **特别注意事项**：
  1. accent 锁定系统蓝，全站单一来源（`.tint`），禁止局部再定义其他主色。
  2. 深浅色必须双模验证，文本 / 背景一律语义色，零硬编码。
  3. 品牌保险箱符号仅作点缀，出现在锁屏与侧栏底部等低干扰位置，不进入主操作区。
  4. 原型需覆盖关键状态（hover / selection / masked reveal / TOTP countdown / error），而非仅静态布局。
  5. 不改动 Rust 内核与 FFI 契约；UI 重设计不得假设底层 API 变化。
  6. 交付物为 HTML 高保真原型，确认方向后再映射回 SwiftUI 代码（本阶段不写 Swift）。
