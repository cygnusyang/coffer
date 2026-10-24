// SettingsView.swift —— 统一设置页（docs/09-v0.2实现方案.md §3.7，T06 设置页归位）。
//
// 原先散落在 MainView 工具栏（自动锁定 Picker）与 SecuritySettingsView
// sheet（Touch ID）的设置项统一归位到本页，按节组织：
//   ① 通用：自动锁定超时（原 MainView 工具栏 autoLockMenu 迁入）+ 语言行
//   ② 剪贴板：自动清除档位（T06 / FR-14.2）
//   ③ 备份提醒：提醒间隔档位（FR-8.5；评估逻辑 T-G 接入）
//   ④ 导入：放置区授权（v2.11.0，docs/21 §4.5：DropzoneAuthStatusView 三态
//     轻量行 + 「移除授权」，E-3 应用级授权 D-18.4/18.5）
//   ⑤ 生成器：生成器默认参数（FR-14.3，T08：GeneratorSettingsView）
//   ⑥ 安全：Touch ID 三态节（TouchIDSettingsSection，G3 自包含卡片）
//     +「修改主密码…」卡片（sheet：ChangePasswordView，FR-1.8 / TC-UI-11，T-D）
//     +「恢复码」设置区（RecoveryCodeSettingsSection，FR-17.2，G3 自包含卡片）
//   ⑦ 数据：「从备份恢复…」（T-H：RestoreBackupView）「管理密码库…」（v2.10.0 D1）
//     「审计日志…」（T-I：AuditLogView，FR-12.6）
//   ⑧ 诊断与隐私：「诊断信息…」（FR-14.4，T08：DiagnosticsView）
//     +「网络能力自证…」（FR-14.5，T08：NetworkSelfCertView）
//   ⑨ 许可：「许可…」（FR-15.7：LicenseSettingsView，许可状态 / 激活入口 /
//      机器指纹；自包含不触 AppModel，docs/03 §14）
//   ⑩ MCP / Agent 协作：MCP 入口（docs/20 §6：开关 / provider / vault /
//      复制注册命令 / 状态行；独立 McpSettingsSection，不触 AppModel）
//   关闭钮（v2.4.1 终版）：设置改独立窗口（CofferApp Window scene，id
//   "settings"），左上角红绿灯（系统设置样式）关闭——窗口标题栏自带红绿灯，
//   滚动内容时红绿灯常驻可随时关闭，无需自定义关闭控件。演进：Form 底部
//   「完成」→ 顶栏「完成」→ 右上角「✕」→ 独立窗口红绿灯
//
// v2.13.1 骨架改写（docs/03-功能设计/25-v2.13.1-设置页紧凑化-设计.md §4.2 G1）：
//   Form + formStyle(.grouped) → ScrollView + VStack + 自绘卡片。
//   为什么整页换骨架而不是调参：grouped Form 的卡片外边距 20 / 行 inset 10 在
//   macOS 26 上没有可用的公开 API 可调（设计 §3.1 逐条实验数据），要收密度只能
//   自绘。代价是放弃系统 Form 的行为集（AX 分组语义 / 行 hover / 节距 / key-view
//   proxy），由 SettingsStyle.swift 的 SettingsCard / SettingsRow 补回几何与分组
//   语义；用户已批准（设计 §6 决策 1，2026-10-24）。
//
//   **本文件只改容器与间距**：控件数量、顺序、绑定、动作一律不变（验收判据 E 组
//   逐节清点；INV-SET-2）。所有几何数字来自 SettingsMetrics，本文件不写裸值
//   （D-20.1 / GATE-SET-5）。
//
//   实际卡片顺序（12 张，判据 §7 的节标题序列以此为准；设计文本的「10 节」是
//   概念分组）：通用 / 剪贴板 / 备份提醒 / 导入 / 生成器 / 安全（Touch ID）/
//   （无标题改密卡）/ 恢复码 / 数据 / 诊断与隐私 / 许可 / MCP / Agent 协作。
//   其中「安全」「恢复码」「MCP」三张卡由各自组件自带（G3 / G4 文件），本文件只
//   负责摆放；「通用 / 剪贴板 / 备份提醒 / 导入 / 生成器 / 改密 / 数据 / 诊断 /
//   许可」的卡片与行由本文件构造。
//
// 档位哨兵语义（三者互不相同，勿混淆）：
//   - autoLockMinutes：0 = 从不（运行态；落盘为 -1，见 AppModel）
//   - clipboardClearSecs：0 = 从不（落盘同值）
//   - backupReminderDays：0 = 禁用提醒（落盘同值）

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject
    private var model: AppModel

    /// 「修改主密码」sheet（T-D：ChangePasswordView 完整改密流程）。
    @State private var showChangePassword = false
    /// 「从备份恢复」sheet（T-H：RestoreBackupView 加密备份恢复流程，FR-8.1）。
    @State private var showRestore = false
    /// 「管理密码库」sheet（v2.10.0 D1：VaultManagementView 库管理面，
    /// 设置窗源本地呈现，随 SettingsWindowHost 在 phase 离开 .unlocked 时
    /// 整窗拆除，F3）。
    @State private var showVaultManagement = false
    /// 「审计日志」sheet（T-I：AuditLogView 只读审计日志查看，FR-12.6）。
    @State private var showAuditLog = false
    /// 「许可」sheet（FR-15.7：LicenseSettingsView 许可状态 / 激活入口）。
    @State private var showLicense = false
    /// 「生成器默认参数」sheet（FR-14.3：GeneratorSettingsView，T08）。
    @State private var showGeneratorDefaults = false
    /// 「诊断信息」sheet（FR-14.4：DiagnosticsView，T08）。
    @State private var showDiagnostics = false
    /// 「网络能力自证」sheet（FR-14.5：NetworkSelfCertView，T08）。
    @State private var showNetworkSelfCert = false

    var body: some View {
        NavigationStack {
            ScrollView {
                // 节距由父容器统一施加（cardSpacing）：卡片组件本身不自带块外
                // 间距，否则「有页脚 / 无页脚」的块会算出两种节距（见
                // SettingsStyle.swift 的 SettingsCard 注释）。有页脚的节天然得到
                // footerGapBottom + cardSpacing = 14（设计 §2.1 #14）。
                VStack(alignment: .leading, spacing: SettingsMetrics.cardSpacing) {
                    generalSection
                    clipboardSection
                    backupReminderSection
                    importSection
                    generatorSection
                    securitySection
                    dataSection
                    diagnosticsSection
                    licenseSection
                    mcpSection
                }
                // 页顶 / 页底外边距（设计 §2.1 #15：20 → 12）。只写 .vertical：
                // 左右留白由 SettingsCard 自己施加 pageInset，避免水平方向出现
                // 两套值。
                .padding(.vertical, SettingsMetrics.pageInset)
            }
            .navigationTitle("设置")
            // v2.4.1：macOS 26 Liquid Glass 默认让内容延伸到玻璃透明
            // 标题栏下方、滚动时从标题栏透出（用户反馈「上面应不透明」）。
            // .toolbarBackground(.visible, for: .windowToolbar) 强制窗口
            // 标题栏/工具栏区不透明——与主窗口 .windowToolbarStyle(.unified)
            // 的实体标题栏同视觉纪律；红绿灯仍留在标题栏左上角。
            // v2.13.1：骨架换成 ScrollView 后本纪律不变（INV-SET-6 / TC-SET-63）。
            .toolbarBackground(.visible, for: .windowToolbar)
            // v2.4.1 终版：关闭由独立窗口标题栏红绿灯承担（Window scene），
            // 本页不再渲染自定义关闭控件；滚动内容时红绿灯仍常驻可随时关闭。
        }
        // 宽度固定、高度自适应（节内容随 Touch ID 内联确认行等动态展开）。
        // v2.13.1：480 → 460（设计 §2.3）。460 保住文本区 420pt 不变
        // （460 − 2×12 − 2×8 = 420 = 480 − 2×20 − 2×10），英文长文案行数零变化。
        .frame(width: SettingsMetrics.windowWidth)
        .sheet(isPresented: $showChangePassword) {
            // 修改主密码流程（FR-1.8 / TC-UI-11，T-D）：
            // 旧密码重验证 + 新密码 zxcvbn 门禁 + header 重封装（D-2）
            ChangePasswordView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showRestore) {
            // 从备份恢复流程（FR-8.1 回环，T-H）：校验 → 确认 → 恢复 →
            // openSession 引导解锁（phase = .locked 时本 sheet 树随 MainView 拆除）
            RestoreBackupView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showAuditLog) {
            // 审计日志查看（FR-12.6，T-I）：只读最近 200 条，Rust 侧倒序返回
            AuditLogView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showLicense) {
            // 许可信息（FR-15.7，docs/03 §14）：自包含，不依赖 AppModel
            // （许可域与密码库会话无关，v0.4 §6.1 切片纪律，同 McpSettingsSection）
            LicenseSettingsView()
        }
        .sheet(isPresented: $showGeneratorDefaults) {
            // 生成器默认参数（FR-14.3，T08）：编辑存档默认值，
            // 「另存为默认」经 AppModel 校验落盘（generatorDefaultsV1）。
            GeneratorSettingsView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showDiagnostics) {
            // 诊断信息（FR-14.4，T08）：只读白名单字段，消费 T03 diagnostic_summary FFI。
            DiagnosticsView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showNetworkSelfCert) {
            // 网络能力自证（FR-14.5，T08）：静态说明页，无 AppModel 依赖。
            NetworkSelfCertView()
        }
        .sheet(isPresented: $showVaultManagement) {
            // 密码库管理面（v2.10.0 D1，docs/16 §4.5 线框）：设置窗源 sheet。
            // 删当前库 → phase 离开 .unlocked → SettingsWindowHost 整窗自关
            // （F3），sheet 随窗拆除；删非当前库 → 管理面保持列表刷新。
            VaultManagementView()
                .environmentObject(model)
        }
    }

    // MARK: - 动作行（设置页里所有 Button 行的统一形态）

    /// 动作行：SettingsRow（rowHeightAction）+ 无描边 Button。
    ///
    /// 为什么不是裸 Button：走出 Form 后 Button 的 .automatic 样式在 macOS 上会
    /// 渲染成带描边的 push button（视觉上又多一个「框」，与本次目标相反）。
    /// .borderless 保持「左侧图标 + 文字、整行可点」的设置页行形态。
    ///
    /// 点击区：标签自己撑到 minimumHitTarget（28，设计 §2.2 硬下限）且
    /// contentShape 让空白区也吃点击——28 + 行内 4/4 = 36，正好是本行行高，
    /// 即整行可点，**不改视觉尺寸**（墨迹仍是原字号）。这里用 minHeight 而不是
    /// height：大字号下按内容增高、不裁切（D-20.4 / INV-SET-4）。
    /// 实测（临时探针，SettingsStyle + 本结构）：动作行 = 36.0pt、Picker 行 = 32.0pt。
    ///
    /// - Parameters:
    ///   - title: 行文案（LocalizedStringKey，走本地化表；勿换成 String 重载）。
    ///   - systemImage: 左侧图标（SF Symbol 名）。
    ///   - showsDivider: 是否画行底发丝线；**每节最后一行传 false**。
    ///   - action: 行动作（与原 Button 的动作一一对应，顺序不变）。
    private func actionRow(
        _ title: LocalizedStringKey,
        systemImage: String,
        showsDivider: Bool = true,
        action: @escaping () -> Void
    ) -> some View {
        SettingsRow(minHeight: SettingsMetrics.rowHeightAction, showsDivider: showsDivider) {
            Button(action: action) {
                Label(title, systemImage: systemImage)
                    .frame(
                        maxWidth: .infinity,
                        minHeight: SettingsMetrics.minimumHitTarget,
                        alignment: .leading
                    )
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
        }
    }

    // MARK: - ① 通用（自动锁定，原 MainView 工具栏迁入）

    private var generalSection: some View {
        SettingsCard(
            "通用",
            footer: "空闲超过所选时长后自动锁定密码库；锁定屏幕 / 休眠 / 屏保时立即锁定。"
        ) {
            SettingsRow {
                Label("自动锁定", systemImage: "timer")
            } control: {
                // 标签由左侧行标签承载，故 Picker 自带的同名标签只保留可访问语义、
                // 不重复显示（.labelsHidden() 隐藏视觉，标签仍参与 AX 命名）。
                Picker(selection: $model.autoLockMinutes) {
                    ForEach(AppModel.autoLockOptions, id: \.self) { minutes in
                        Text(minutes == 0 ? LocalizedStringKey("从不") : LocalizedStringKey("\(minutes) 分钟")).tag(minutes)
                    }
                } label: {
                    // 与左侧行标签同名：.labelsHidden() 只隐藏视觉，可访问名仍取它。
                    // **不要**再补 .accessibilityLabel(同名)：同构探针实测 AXPopUpButton
                    // 的 desc 会叠成「自动锁定, 自动锁定」，VoiceOver 读两遍（reviewer H3）。
                    // LanguageSection 的「语言」行只写 .labelsHidden()、desc 干净——
                    // 三个 Picker 与它保持一致。
                    Label("自动锁定", systemImage: "timer")
                }
                .labelsHidden()
            }

            // v2.13.0 语言选择（设计 24 §6.4）：寄生「通用」节、自动锁定之后的第二行，
            // 不新开第 11 节（DESIGN.md §14 已登记「9 节单长滚动」的 IA 张力）。
            // UI 实现在 Support 侧的 LanguageSection.swift（infra 归属），本文件只留调用，
            // 避免同一文件被两组同时改（设计 §8.4 边界 1）。
            // v2.13.1：它是本卡最后一行，由 G2 在自己文件里传 showsDivider: false。
            LanguageSection()
        }
    }

    // MARK: - ② 剪贴板（FR-14.2 五档）

    /// 选择器数据源：Rust 侧档位表 + 「从不」（0，恒排最后）。
    /// 档位经 FFI 取（clipboardClearTiers），与 Rust 校验同一来源，勿硬编码。
    private var clipboardClearOptions: [Int] {
        // 「从不」= 0，恒排最后（Clipboard.swift:69 把 0 当合法值；Rust 侧 tiers 只含 10/30/60/120）。
        // v2.13.1 改写时这行曾被漏掉 → 功能回退（reviewer C1），勿再删。
        clipboardClearTiers().map { Int($0) } + [0]
    }

    private var clipboardSection: some View {
        SettingsCard(
            "剪贴板",
            // 默认档位经 FFI 取（defaultClipboardClearSecs），勿硬编码
            footer: "复制的敏感内容在所选时长后自动从剪贴板清除；期间你复制了别的内容则不动。默认 \(Int(defaultClipboardClearSecs())) 秒。"
        ) {
            SettingsRow(showsDivider: false) {
                Label("复制后自动清除", systemImage: "doc.on.doc")
            } control: {
                Picker(selection: $model.clipboardClearSecs) {
                    ForEach(clipboardClearOptions, id: \.self) { secs in
                        Text(secs == 0 ? LocalizedStringKey("从不") : LocalizedStringKey("\(secs) 秒")).tag(secs)
                    }
                } label: {
                    Label("复制后自动清除", systemImage: "doc.on.doc")
                }
                // 不写 .accessibilityLabel(同名)：会与自带标签叠成重复 desc（reviewer H3，
                // 详由见「通用」节注释）。
                .labelsHidden()
            }
        }
    }

    // MARK: - ③ 备份提醒（FR-8.5；评估逻辑 T-G 接入）

    private var backupReminderSection: some View {
        SettingsCard(
            "备份提醒",
            footer: "距上次备份超过所选天数时提醒你备份密码库；选择「禁用」关闭提醒。"
        ) {
            SettingsRow(showsDivider: false) {
                Label("备份提醒间隔", systemImage: "bell")
            } control: {
                Picker(selection: $model.backupReminderDays) {
                    ForEach(AppModel.backupReminderOptions, id: \.self) { days in
                        Text(days == 0 ? LocalizedStringKey("禁用") : LocalizedStringKey("每 \(days) 天")).tag(days)
                    }
                } label: {
                    Label("备份提醒间隔", systemImage: "bell")
                }
                .labelsHidden()   // 同上：同名 accessibilityLabel 会叠成重复 desc（H3）
            }
        }
    }

    // MARK: - ④ 导入（v2.11.0，docs/21 §4.5 设置页节 + DESIGN.md D-18.2/18.4/18.5）

    /// 放置区授权节：DropzoneAuthStatusView 三态轻量行（compact 行内压缩，
    /// 应用级语义「此授权作用于 Coffer 应用全局」注记，E-3/D-18.5）。
    /// 「移除授权」= D-18.4 唯一删点（调 model.removeDropzoneAuthorization()
    /// 清除 bookmark + 广播，向导打开中同步回 .notAuthorized）；失效态由组件
    /// 内呈「重新授权…」回向导 S0（D-18.3 失效非静默）。
    private var importSection: some View {
        SettingsCard(
            "导入",
            footer: "放置区用于自动检测 macOS「密码」App 导出的 CSV；授权只读、可随时撤销。"
        ) {
            // 行壳（行高下限 / 发丝线 / 左右留白）归本文件，三态内容归组件
            // （v2.13.1 边界：G1 包行、G5 只提供行内内容，避免行套行）。
            // 自由布局（不是 label/control 分栏）：三态内容是多行 VStack，
            // 分栏形态的 fixedSize 会把它挤扁。行高下限取双行态 44（D-11.4），
            // 实际高度由「标题 + 路径 + 按钮」三行内容决定，下限只为兜底。
            SettingsRow(minHeight: SettingsMetrics.rowHeightTwoLine, showsDivider: false) {
                DropzoneAuthStatusView(
                    status: model.dropzoneAuthStatus,
                    // 三个入参在该组件里是 String（Text(String) 不查表，设计 F6），
                    // 故在**产生点**本地化（§5.4），不依赖组件内部怎么渲染。
                    setButtonLabel: String(localized: "设置放置区…"),
                    onSet: { model.showImportDropzone = true },
                    secondaryLabel: String(localized: "移除授权"),
                    onSecondary: { model.removeDropzoneAuthorization() },
                    scopeNote: String(localized: "此授权作用于 Coffer 应用全局"),
                    compact: true
                )
            }
        }
    }

    // MARK: - ⑤ 生成器（FR-14.3，T08）

    /// 生成器默认参数入口（FR-14.3）：编辑存档默认值，供生成器面板首次
    /// 打开预填（TC-GEN-01）；另存为默认经 AppModel 校验落盘（TC-GEN-03）。
    private var generatorSection: some View {
        SettingsCard(
            "生成器",
            footer: "设置新建条目时生成器的预填参数（长度 / 字符集 / 密码短语选项）。"
        ) {
            // T08：弹出 GeneratorSettingsView（见 body 的 showGeneratorDefaults sheet）
            actionRow("生成器默认参数…", systemImage: "wand.and.stars", showsDivider: false) {
                showGeneratorDefaults = true
            }
        }
    }

    // MARK: - ⑥ 安全（Touch ID 卡片 + 改密卡 + 恢复码卡片）

    /// 三块内容平铺在页面 VStack 里（不另加内层 VStack 包）：节距统一由外层
    /// cardSpacing 施加，否则「卡片 + 高亮行」的间距会与别处算出两个值。
    /// 卡片边界：「安全」卡与「恢复码」卡由 G3 组件自带；中间的改密卡无页头、
    /// 只有页脚（判据 §7 的 12 卡清点把这三张分开数）。
    @ViewBuilder
    private var securitySection: some View {
        // P2-A 首次高亮兜底（lead 裁定⑤，AC-2.9.0-P2A-10/13）：引导 Step1 被
        // 跳过且 Touch ID 未启用时，Touch ID 卡下方出现 accent 圆点 + 「未完成
        // 设置」footnote；启用后消失（showBioSetupHighlight live 派生）。
        TouchIDSettingsSection()
        if model.showBioSetupHighlight {
            // 缩进对齐卡片内容起点（pageInset + rowInset = 20），与行文字同列。
            FirstRunSetupHighlightRow()
                .padding(.leading, SettingsMetrics.pageInset + SettingsMetrics.rowInset)
        }

        SettingsCard(footer: "修改主密码只重新封装密码库头部，不重新加密全部条目。") {
            // T-D：弹出 ChangePasswordView（见 body 的 showChangePassword sheet）
            actionRow("修改主密码…", systemImage: "key", showsDivider: false) {
                showChangePassword = true
            }
        }

        // FR-17.2：恢复码设置区（RecoveryCodeSettingsSection 自包含，两态渲染 +
        // 生成/重生成 sheet 均位于 RecoveryCodeSetupSheet.swift，docs/31 §4.3）
        // P2-A 首次高亮兜底（AC-2.9.0-P2A-11/13）：引导 Step2 被跳过且恢复码未
        // 生成时，恢复码卡下方出现同款 footnote；启用后消失。
        RecoveryCodeSettingsSection()
        if model.showRecoverySetupHighlight {
            FirstRunSetupHighlightRow()
                .padding(.leading, SettingsMetrics.pageInset + SettingsMetrics.rowInset)
        }
    }

    // MARK: - ⑦ 数据（T-H 恢复备份 / T-I 审计日志）

    private var dataSection: some View {
        SettingsCard("数据") {
            // T-H：弹出 RestoreBackupView（见 body 的 showRestore sheet）
            actionRow("从备份恢复…", systemImage: "arrow.counterclockwise") {
                showRestore = true
            }

            // v2.10.0 D1 主入口（docs/16 §4.5 线框：与「从备份恢复… / 审计
            // 日志…」同级）：UDR-7 只读许可用户隐藏（对齐 create_vault 拒绝
            // 口径，AC-2.10.0-EN-1/EN-7）。
            if model.canManageVaults {
                // 弹出 VaultManagementView（见 body 的 showVaultManagement sheet）
                actionRow("管理密码库…", systemImage: "archivebox") {
                    showVaultManagement = true
                }
            }

            // T-I：弹出 AuditLogView（见 body 的 showAuditLog sheet）
            actionRow("审计日志…", systemImage: "list.bullet.rectangle", showsDivider: false) {
                showAuditLog = true
            }
        }
    }

    // MARK: - ⑧ 诊断与隐私（FR-14.4 诊断信息 / FR-14.5 网络自证，T08）

    /// 诊断信息 + 网络能力自证入口（T08）：前者消费 diagnostic_summary FFI
    /// 白名单字段（TC-DIAG）；后者为零网络架构静态说明页（TC-NET）。
    private var diagnosticsSection: some View {
        SettingsCard("诊断与隐私") {
            // T08：弹出 DiagnosticsView（见 body 的 showDiagnostics sheet）
            actionRow("诊断信息…", systemImage: "stethoscope") {
                showDiagnostics = true
            }

            // T08：弹出 NetworkSelfCertView（见 body 的 showNetworkSelfCert sheet）
            actionRow("网络能力自证…", systemImage: "network.slash", showsDivider: false) {
                showNetworkSelfCert = true
            }
        }
    }

    // MARK: - ⑨ 许可（FR-15.7，docs/03 §14）

    /// 独立的 LicenseSettingsView（自包含、不触 AppModel，v0.4 §6.1 切片纪律；
    /// 许可域与密码库会话无关，docs/03 §14.9）。
    private var licenseSection: some View {
        SettingsCard(
            "许可",
            footer: "查看许可状态、激活或申请序列号（开源免费版无需激活）。"
        ) {
            // FR-15.7：弹出 LicenseSettingsView（见 body 的 showLicense sheet）
            actionRow("许可…", systemImage: "checkmark.seal", showsDivider: false) {
                showLicense = true
            }
        }
    }

    // MARK: - ⑩ MCP / Agent 协作（docs/20 §6，对齐 1Password 设置内 Developer 区）

    /// 独立的 McpSettingsSection（自包含、不触 AppModel，v0.4 §6.1 切片纪律；
    /// 主 App 不宿主 MCP 服务器，docs/20 §6.2）。
    /// v2.13.1：卡片（页头 / 行 / 页脚）由该组件自带，本文件只摆放（G4）。
    private var mcpSection: some View {
        McpSettingsSection()
    }
}

// MARK: - 首次引导高亮兜底（P2-A，docs/14 §A P2 §2.5；DESIGN.md P-2.1）

/// 「未完成设置」footnote 行：accent 圆点 + 文案，作为被跳过的首启引导步骤的
/// 设置页兜底入口提示（lead 裁定⑤，AC-2.9.0-P2A-10/11）。随对应功能启用而
/// 消失（SettingsView.securitySection 按 showBioSetupHighlight /
/// showRecoverySetupHighlight 条件渲染，见上）。小组件封装，两侧复用。
///
/// v2.13.1：本行**不自带缩进**——它现在与卡片同级摆在页面 VStack 里，缩进由
/// 调用方用 pageInset + rowInset 表达（对齐卡片内容起点，不再是 Form 时代的
/// 「行 inset + 4」）。裸数字在业务文件里是静态闸门红项（D-20.1）。
struct FirstRunSetupHighlightRow: View {
    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(Color.accentColor)
                .frame(width: 6, height: 6)
            Text("未完成设置")
                .font(.footnote)
                .foregroundStyle(Color.accentColor)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("未完成设置")
    }
}
