// McpSettingsView.swift —— 统一设置页「MCP / Agent 协作」节（docs/20 §6；
// docs/29 §7.1 翻转：provider 切换放开 / coffer 转正）。
//
// 对齐 1Password 最新设计：设置内 Developer 区；「复制注册命令」对齐
// 「Connect to Claude」一键复制（docs/20 §5.4）。
//
// 进程边界（docs/20 §6.2，关键决策）：主 App 不宿主 MCP 服务器——MCP 服务器
// 是独立 `coffer` 进程（由 Claude Code 经 stdio spawn）。本页只做三件事：
//   ① 写配置：开关 / vault 名 → UserDefaults（非敏感布尔/文本，docs/20 §6.1）
//   ② 发注册命令：把 §5.4 命令复制到剪贴板
//   ③ 显示状态：本地前置探测（无 socket，docs/20 §6.3）
// 不 spawn 任何 MCP 服务器进程。
//
// v2.2.0 翻转（docs/29 §7.1/§7.3）：
//   - Provider 下拉放开切换（op / coffer 均可用，coffer 取消灰态）；
//   - provider == op：vault 文本输入 + 链接 1Password + 注册命令 op 版
//     （含 --vault，仍按 docs/20 §6.1 状态组合）；
//   - provider == coffer：显示自家库路径（只读，无会话则提示「请先打开
//     密码库」）+ 注册命令 coffer 版（-e COFFER_VAULT_DIR=，**不含密码 env**）
//     + 状态只查 coffer 二进制与托管启用；
//   - MCP 解锁托管三态节（McpEscrowSettingsSection）仅 coffer 分支呈现。
//
// v2.12.0 多 AI 工具（docs/23 §4.1）：
//   - coffer 分支的「Claude Code 注册」单行 → 「AI 工具」子节
//     （McpAgentToolsSection）：已安装的自动注册工具逐行开关（Claude Code /
//     CodeBuddy / Codex），未安装者与 copy-only 工具收进「其他工具」折叠组、
//     只给复制入口；
//   - coffer 分支的全局「复制注册命令」行删除——命令必须绑定单一 target；
//   - 总开关语义扩为批量：ON = 对已安装且用户未关闭的工具批量注册，OFF = 批量
//     移除；存在已注册工具时先确认（默认取消），移除失败不阻塞 OFF 本身。
//
// 呈现纪律（docs/20 §6.3 / docs/07 §2.4）：显式错误处理——复制失败 /
// 剪贴板失败 / op 缺失均给用户可操作提示；op token 即用即弃、不落本视图
// 状态（本版只探测 env 级会话信号，不捕获 token，见 McpStatusProbe 注释）。

import AppKit
import SwiftUI

/// 统一设置页「MCP / Agent 协作」节（docs/20 §6；docs/29 §7.1 翻转）。
/// v2.2.0 起经 `@EnvironmentObject model: AppModel` 读取会话 / 库身份
/// （vaultDirPath、vaultUUID、mcpEscrowStatus）——docs/29 §7.3 最小化注入。
struct McpSettingsSection: View {
    @EnvironmentObject
    private var model: AppModel

    /// 「启用 MCP 服务器」开关（docs/20 §6.1，持久化到 UserDefaults）。
    @State private var enabled = McpSettings.loadEnabled()
    /// 默认 vault 名（`coffer mcp --vault`，docs/20 §5.2；仅 op 分支消费）。
    @State private var vaultName = McpSettings.loadVaultName()
    /// 当前数据源（docs/29 §7.1：默认 coffer，下拉可切换）。
    @State private var provider = McpProvider.defaultProvider
    /// 就绪状态（onAppear / 开关变更 / 链接动作 / provider 切换后刷新）。
    @State private var status: McpStatus = .disabled
    /// 多 AI 工具注册状态中心（v2.12.0：每个 target 独立注册态 + helper 串行通道）。
    /// 与「AI 工具」子节共用同一实例——总开关需读 hasRegisteredTarget 决定是否弹
    /// 关闭确认（docs/23 §5.4）。
    @StateObject private var agentTools = McpAgentToolCenter()
    /// 关闭总开关前的确认（仅有已注册工具时出现；默认取消，docs/23 §5.4）。
    @State private var showDisableConfirm = false
    /// 错误弹窗（FfiErrorAlert 统一「操作失败」呈现，docs/20 §6.3）。
    @State private var errorMessage: String?
    /// 信息/引导弹窗（链接 1Password 的成功或 `op signin` 引导文案）。
    @State private var infoMessage: String?
    /// 「已复制」瞬时反馈标记（2 s 后自动熄灭）。
    @State private var copied = false

    /// 「已复制」反馈的显示时长（秒；docs/23 §7.4 STD-03：随 v2.12.0 统一 1.5 s）。
    private static let copiedFeedbackSeconds: TimeInterval = 1.5

    var body: some View {
        Group {
            mainCard

            // MCP 解锁托管（docs/29 §7.2）：coffer 分支专用——escrow 是 coffer
            // 自家库的免密码解锁通道，op 分支无此语义。
            if provider == .coffer {
                McpEscrowSettingsSection()
            }
        }
        .onAppear {
            refreshStatus()
            refreshAgentTools()
        }
        .onDisappear {
            // 离开本页：取消在飞 helper 操作，不留幽灵中间态（docs/23 N-8）。
            agentTools.cancelAll()
        }
        .ffiErrorAlert($errorMessage)
        .alert(
            "MCP / Agent 协作",
            isPresented: Binding(
                get: { infoMessage != nil },
                set: { if !$0 { infoMessage = nil } }
            )
        ) {
            Button("好", role: .cancel) {}
        } message: {
            Text(infoMessage ?? "")
        }
        .confirmationDialog(
            "关闭「启用 MCP 服务器」？",
            isPresented: $showDisableConfirm,
            titleVisibility: .visible
        ) {
            Button("关闭并移除注册", role: .destructive) {
                // 真正的落态在 enabled 的 onChange（单一路径）；此处只落意图。
                enabled = false
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("将从以下工具移除 coffer 注册项：\(agentTools.cleanupTargetNames)。移除后这些工具不再能经 MCP 访问本机密码库。MCP 解锁托管保持开启，不受影响。")
        }
    }

    /// 主节卡片（开关 / provider / vault / 命令 / 状态；docs/29 §7.1 分支）。
    ///
    /// v2.13.1（设计 25 §4.2 G3）：容器 `Section` → `SettingsCard`，行包
    /// `SettingsRow`——**只改容器与几何**，行序 / 绑定 / 动作与改造前逐项对应
    /// （验收判据 E 组「控件数量与顺序零变化」）。行高取 `SettingsMetrics`
    /// （单行 32 / 动作行 36 / 双行 44），末行不画发丝线。
    private var mainCard: some View {
        // footer 由 provider 运行时分支（String(localized:) 取值），此处转成
        // SettingsCard 的 LocalizedStringKey 入参：键仍是同一中文字面量，译文
        // 解析路径与 `Text(footerText)` 完全一致（不新增文案，l10n 零影响）。
        SettingsCard("MCP / Agent 协作", footer: LocalizedStringKey(footerText)) {
            masterToggleRow
            providerRow
            vaultRow
            // 注册命令必须绑定单一 target（docs/23 §4.1）：coffer 分支取消全局
            // 「复制注册命令」行，复制入口下沉到每个工具行；op 分支保持原样。
            if provider == .op {
                commandPreviewRow
                copyButtonRow
                linkButtonRow
            }
            statusRow
            if provider == .coffer {
                McpAgentToolsSection(
                    center: agentTools,
                    masterEnabled: enabled,
                    cofferBinaryPath: cofferBinaryPath
                )
            }
            usageLogRow
        }
    }

    // MARK: - 总开关行（docs/20 §6.1，持久化到 UserDefaults）

    /// 「启用 MCP 服务器」总开关行。单行高 32（设计 25 §2.1 #7）。
    /// 行为与改造前完全一致（在飞禁用 / 落态走 enabled 的 onChange 单一路径）。
    private var masterToggleRow: some View {
        SettingsRow {
            Toggle("启用 MCP 服务器", isOn: masterEnabledBinding)
                // H3：在飞时禁用总开关（串行通道一次一个 helper 请求；OFF 与在飞注册
                // 竞态会留下半写配置）。检测（AI 工具行 ⟳）同样受此互斥约束。
                .disabled(agentTools.busy)
                .help(agentTools.busy
                      ? String(localized: "正在处理注册操作，请稍候")
                      : String(localized: "关闭会移除全部工具的注册项"))
                .onChange(of: enabled) { _, newValue in
                    McpSettings.saveEnabled(newValue)
                    refreshStatus()
                    if newValue {
                        // 开关 ON 本身 = 批量注册（docs/23 §4.2 OFF→ON：只对已安装且
                        // 用户未关闭的工具 upsert，主形态，无需再点按钮）。
                        if provider == .coffer {
                            agentTools.activateAll(vaultDir: model.vaultDirPath,
                                                   cofferBinaryPath: cofferBinaryPath)
                        }
                    } else {
                        // OFF：best-effort 批量移除（残留项会让工具侧继续持有取密权限）。
                        // 移除失败**不阻塞 OFF 本身**：失败行按事实态渲染 + 再次清理入口。
                        if provider == .coffer {
                            agentTools.deactivateAll()
                        }
                    }
                }
        }
    }

    // MARK: - Provider 行（docs/29 §7.1：下拉放开切换，两 provider 均可用）

    /// Provider 以下拉呈现：op / coffer 均可选（docs/29 §7.1 取消灰态）；
    /// 切换即触发状态重算（provider 分流见 McpStatus.resolve）。
    private var providerRow: some View {
        SettingsRow {
            Text("数据源")
        } control: {
            Menu {
                ForEach(McpProvider.allCases, id: \.self) { option in
                    Button {
                        provider = option
                        refreshStatus()
                        // 切到 coffer → 重新探测工具与注册态（op 分支不渲染工具行，
                        // 但探测只读、无副作用；切回 coffer 时状态即刻可用）。
                        refreshAgentTools()
                    } label: {
                        if option == provider {
                            Label(option.displayName, systemImage: "checkmark")
                        } else {
                            Text(option.displayName)
                        }
                    }
                }
            } label: {
                HStack(spacing: 4) {
                    Text(provider.displayName)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption)
                }
            }
        }
    }

    // MARK: - Vault 配置项（docs/20 §5.2 / §6.1；docs/29 §7.1 分支）

    /// vault 行随 provider 分支：
    ///   - op：文本输入（`coffer mcp --vault <name>`，docs/20 §5.2）；
    ///   - coffer：只读展示当前打开库路径（AppModel.vaultDirPath），无会话
    ///     则提示「请先打开密码库」（docs/29 §7.1）。
    @ViewBuilder
    private var vaultRow: some View {
        // 两分支都用自由布局而非「标签 + 控件」分栏形态：op 分支的 TextField 与
        // coffer 分支的路径文本都需按行宽自适应（分栏形态给控件加 fixedSize，
        // 长路径会被压缩 → 违反 D-19.6 不截断）。行序与内容零变化。
        switch provider {
        case .op:
            SettingsRow {
                HStack(spacing: SettingsMetrics.labelControlGap) {
                    Text("默认保险库")
                    TextField("可选，例如 Personal", text: $vaultName)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 240)
                        .onChange(of: vaultName) { _, newValue in
                            McpSettings.saveVaultName(newValue)
                        }
                }
            }
        case .coffer:
            SettingsRow {
                HStack(spacing: SettingsMetrics.labelControlGap) {
                    Text("密码库目录")
                    Spacer(minLength: SettingsMetrics.labelControlGap)
                    if canBuildCofferCommand {
                        Text(model.vaultDirPath)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    } else {
                        Text("请先打开密码库")
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    // MARK: - 注册命令（docs/20 §5.4；docs/29 §7.1 随 provider 分支）

    /// coffer 版命令可构造性：需已打开库会话（vaultDirPath 才有效）。
    private var canBuildCofferCommand: Bool {
        provider == .coffer ? (model.session != nil && !model.vaultUUID.isEmpty) : true
    }

    /// coffer 二进制绝对路径（App 包内嵌套 bundle 优先，PATH 兜底；未找到 →
    /// 空串，复制入口据此禁用，见 canCopyRegisterCommand）。
    private var cofferBinaryPath: String {
        McpStatusProbe.cofferBinaryPath() ?? ""
    }

    /// 复制入口可用性：coffer 二进制必须可解析（两 provider 的 MCP 服务器进程
    /// 恒为 coffer，docs/20 §5.4 包内路径——未找到则命令无意义）+ coffer 分支
    /// 需已打开库会话（vaultDirPath 才有效）。
    private var canCopyRegisterCommand: Bool {
        guard !cofferBinaryPath.isEmpty else { return false }
        return canBuildCofferCommand
    }

    /// 复制不可用的引导文案（区分「未找到 coffer 二进制」与「coffer 分支未开库」）。
    private var copyDisabledHint: String {
        if cofferBinaryPath.isEmpty {
            return String(localized: "未找到 coffer 命令（App 包内或 PATH），无法生成注册命令")
        }
        return String(localized: "请先打开密码库后生成注册命令")
    }

    /// 注册命令（单一数据源：预览与复制按钮共用，所见即所得）。
    private var registerCommand: String {
        switch provider {
        case .op:
            return McpRegisterCommand.build(
                provider: provider.rawValue,
                vault: vaultName,
                cofferBinaryPath: cofferBinaryPath
            )
        case .coffer:
            return McpRegisterCommand.build(
                provider: provider.rawValue,
                vault: nil,
                vaultDirPath: model.vaultDirPath,
                cofferBinaryPath: cofferBinaryPath
            )
        }
    }

    /// 命令预览（monospaced，可手动选中复制；未找到 coffer 二进制 / coffer 无
    /// 会话时显示引导文案）。
    @ViewBuilder
    private var commandPreviewRow: some View {
        // 动作行高 36（设计 25 §2.1 #8）：命令块按行宽换行、不截断（D-5.5 ≤3 行）。
        SettingsRow(minHeight: SettingsMetrics.rowHeightAction) {
            if !canCopyRegisterCommand {
                Text(copyDisabledHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text(registerCommand)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    /// 一键复制按钮（docs/20 §6.1 / §5.4；未找到 coffer 二进制 / coffer 无
    /// 会话时禁用）。
    private var copyButtonRow: some View {
        SettingsRow(minHeight: SettingsMetrics.rowHeightAction) {
            HStack(spacing: SettingsMetrics.labelControlGap) {
                Button {
                    copyRegisterCommand()
                } label: {
                    Label(copied ? String(localized: "已复制") : String(localized: "复制注册命令"),
                          systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canCopyRegisterCommand)
                // 命中区 ≥28pt（设计 25 §2.2 / D-20.7）：只扩点击区，不改视觉尺寸。
                .frame(minHeight: SettingsMetrics.minimumHitTarget)
                .contentShape(Rectangle())
                if provider == .op && !McpSettings.hasConfiguredVault(vaultName) {
                    // 未配置 vault → 命令省略 --vault（§5.2 缺省 = $COFFER_OP_VAULT）
                    Text("未配置 vault，命令将省略 --vault")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
    }

    /// 复制到剪贴板（显式错误处理：写入失败给用户可操作提示，docs/20 §6.3）。
    private func copyRegisterCommand() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(registerCommand, forType: .string) else {
            errorMessage = String(localized: "复制失败：无法写入剪贴板，请重试。")
            return
        }
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.copiedFeedbackSeconds) {
            copied = false
        }
    }

    // MARK: - 链接 1Password（docs/20 §6.1；仅 op 分支）

    /// 「链接 1Password…」：探测 op 二进制 + 会话信号，给出就绪结果或
    /// `op signin` 引导。仅 provider == .op 时参与呈现（docs/29 §7.1：
    /// op 相关前置只 op 分支消费）；本版不内嵌交互式登录（op signin 需 TTY，
    /// 且登录令牌属敏感材料，即用即弃不落 App——docs/20 §6.3）。
    private var linkButtonRow: some View {
        SettingsRow(minHeight: SettingsMetrics.rowHeightAction) {
            Button {
                linkOnePassword()
            } label: {
                Label("链接 1Password…", systemImage: "link")
            }
            // 命中区 ≥28pt（设计 25 §2.2 / D-20.7）：只扩点击区，不改视觉尺寸。
            .frame(minHeight: SettingsMetrics.minimumHitTarget)
            .contentShape(Rectangle())
        }
    }

    private func linkOnePassword() {
        guard McpStatusProbe.isOpBinaryAvailable() else {
            errorMessage = String(localized: "未找到 1Password CLI（op）。请安装 1Password CLI 8+（developer.1password.com/docs/cli）后重新打开本页。")
            return
        }
        if McpStatusProbe.isOpSessionAvailable() {
            infoMessage = String(localized: "已检测到 1Password 会话信号。注册命令可被 coffer mcp 使用；如仍未生效，请在终端重新执行 op signin。")
        } else {
            infoMessage = String(localized: "未检测到 1Password 会话。请在终端执行以下命令完成登录后返回本页（或点状态行的刷新）：\n\nop signin\n\n1Password 集成会话由 CLI 维护，App 不保存你的登录令牌。")
        }
        refreshStatus()
    }

    // MARK: - 状态行（docs/20 §6.1 / §6.3；docs/29 §7.1 分流）

    /// 状态行：就绪度 + 手动刷新（op signin 在终端完成后无需重开设置页即可刷新）。
    private var statusRow: some View {
        // 双行行高 44（设计 25 §2.1 #9）：图标 + 两行文本 + 行尾刷新。
        SettingsRow(minHeight: SettingsMetrics.rowHeightTwoLine) {
            HStack(alignment: .top, spacing: SettingsMetrics.labelControlGap) {
                Image(systemName: statusIcon)
                    .foregroundStyle(statusColor)
                    .frame(width: 16)
                VStack(alignment: .leading, spacing: 2) {
                    Text("状态").font(.headline)
                    Text(status.label)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: SettingsMetrics.labelControlGap)
                Button {
                    refreshStatus()
                } label: {
                    Image(systemName: "arrow.clockwise")
                        // 命中区 ≥28×28pt（设计 25 §2.2 / D-20.7）：只扩点击区，不改视觉尺寸。
                        // 宽也要给——纯图标墨迹仅 13–16pt，只加 minHeight 会让可点矩形
                        // 仍是细条（reviewer H1）。
                        .frame(minWidth: SettingsMetrics.minimumHitTarget,
                               minHeight: SettingsMetrics.minimumHitTarget)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .disabled(!enabled)
                .help("刷新状态")
            }
        }
    }

    private var statusIcon: String {
        switch status {
        case .disabled: return "pause.circle"
        case .ready: return "checkmark.circle"
        case .notReady: return "exclamationmark.triangle"
        }
    }

    private var statusColor: Color {
        switch status {
        case .disabled: return .secondary
        case .ready: return .green
        case .notReady: return .orange
        }
    }

    // MARK: - AI 工具（v2.12.0 多工具注册；子节见 McpAgentToolsSection）

    /// 总开关绑定：coffer 分支关闭前先确认（docs/23 §5.4 关闭确认清单）。
    ///
    /// setter 里**不改** enabled（值不变即界面开关自动回弹），只弹确认；确认后由
    /// 「关闭并移除注册」置 false，落态统一走 enabled 的 onChange（单一路径）。
    private var masterEnabledBinding: Binding<Bool> {
        Binding(
            get: { enabled },
            set: { newValue in
                // H3 第二半：在飞（checking / registering / removing）也可能已写入
                // 半份配置，必须与「已注册」同权进确认，不得直接放行关闭。
                if !newValue, provider == .coffer,
                   agentTools.hasRegisteredTarget || agentTools.anyInFlight {
                    showDisableConfirm = true
                    return
                }
                enabled = newValue
            }
        )
    }

    /// 工具侧状态刷新（进入页面 / 切 provider 回 coffer）：probe → 逐 target check。
    /// 检测只读且恒可用（不随总开关 / 会话 / 辅助程序就绪而禁用，docs/23 STD-05）。
    private func refreshAgentTools() {
        guard provider == .coffer else { return }
        agentTools.refresh()
    }

    // MARK: - 查看使用记录（docs/20 §6.1 控件表末项）

    /// 「查看使用记录」入口：打开只读审计视图（docs/20 §4.6 方案 A 的
    /// usage audit JSONL）。审计 JSONL（D-3）待用户确认、cf-mcp 尚未落盘
    /// ——本版做禁用态占位（UI 骨架），格式落定 + 落盘后由 op 集成组
    /// （docs/20 §9 G-C/G-G）接入只读读取，本入口随之放开。
    private var usageLogRow: some View {
        // 本节最后一行：不画发丝线（否则卡片底边内侧多一条线，设计 25 §4.1）。
        SettingsRow(minHeight: SettingsMetrics.rowHeightAction, showsDivider: false) {
            HStack(spacing: SettingsMetrics.labelControlGap) {
                Button {
                    // 预留：D-3 落定后打开只读审计视图（audit JSONL tail，脱敏）
                } label: {
                    Label("查看使用记录", systemImage: "list.bullet.rectangle")
                }
                .disabled(true) // 审计 JSONL（docs/20 §4.6 方案 A / D-3）落定后放开
                // 命中区 ≥28pt（设计 25 §2.2 / D-20.7）：只扩点击区，不改视觉尺寸。
                .frame(minHeight: SettingsMetrics.minimumHitTarget)
                .contentShape(Rectangle())
                Spacer(minLength: 0)
                Text("审计记录格式待定（D-3）")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: - 刷新

    /// 重算就绪状态。探测均为本地快路径（PATH / 环境变量，见
    /// McpStatusProbe）；coffer 分支的 escrowEnabled 取自 AppModel 的
    /// mcpEscrowStatus（本方法先刷新它再组合——McpEscrowSettingsSection 的
    /// onAppear 先于父节刷新时也能拿到近实时信号）。op 真进程交互接入后
    /// 此处需改 Task.detached 包裹（§6.3 纪律）。
    private func refreshStatus() {
        model.refreshMcpEscrowStatus()
        status = McpStatus.resolve(
            provider: provider,
            enabled: enabled,
            opBinaryAvailable: McpStatusProbe.isOpBinaryAvailable(),
            cofferBinaryAvailable: McpStatusProbe.isCofferBinaryAvailable(),
            sessionAvailable: McpStatusProbe.isOpSessionAvailable(),
            escrowEnabled: model.mcpEscrowStatus == .enabled
        )
    }

    /// 节 footer 说明（docs/20 §6.2；docs/29 §7.1 随 provider 条件化——
    /// coffer 版去掉「op signin」引导，补托管说明与「换主密码不吊销托管」注记，
    /// docs/29 §5.3 三处落档之一）。
    private var footerText: String {
        switch provider {
        case .op:
            return String(localized: "让 Claude Code 等 Agent 通过 MCP 访问 1Password 中的密钥。MCP 服务器由独立的 coffer 进程运行（主 App 不内置服务器）；使用前请在终端执行 op signin（coffer 服务器随 App 分发，无需在 PATH 配置）。")
        case .coffer:
            return String(localized: "让 Claude Code 等 Agent 通过 MCP 访问本机 Coffer 密码库。MCP 服务器由独立的 coffer 进程运行（主 App 不内置服务器）；解锁走 MCP 解锁托管，注册命令不含密码 env。换主密码不影响托管；如需吊销请在本页关闭。")
        }
    }
}
