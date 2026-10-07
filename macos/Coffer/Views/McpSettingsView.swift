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
    /// 错误弹窗（FfiErrorAlert 统一「操作失败」呈现，docs/20 §6.3）。
    @State private var errorMessage: String?
    /// 信息/引导弹窗（链接 1Password 的成功或 `op signin` 引导文案）。
    @State private var infoMessage: String?
    /// 「已复制」瞬时反馈标记（2 s 后自动熄灭）。
    @State private var copied = false

    /// 「已复制」反馈的显示时长（秒）。
    private static let copiedFeedbackSeconds: TimeInterval = 2

    var body: some View {
        Group {
            mainSection

            // MCP 解锁托管（docs/29 §7.2）：coffer 分支专用——escrow 是 coffer
            // 自家库的免密码解锁通道，op 分支无此语义。
            if provider == .coffer {
                McpEscrowSettingsSection()
            }
        }
        .onAppear { refreshStatus() }
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
    }

    /// 主节（开关 / provider / vault / 命令 / 状态；docs/29 §7.1 分支）。
    private var mainSection: some View {
        Section {
            Toggle("启用 MCP 服务器", isOn: $enabled)
                .onChange(of: enabled) { _, newValue in
                    McpSettings.saveEnabled(newValue)
                    refreshStatus()
                }

            providerRow
            vaultRow
            commandPreviewRow
            copyButtonRow
            if provider == .op {
                linkButtonRow
            }
            statusRow
            usageLogRow
        } header: {
            Text("MCP / Agent 协作")
        } footer: {
            Text(footerText)
        }
    }

    // MARK: - Provider 行（docs/29 §7.1：下拉放开切换，两 provider 均可用）

    /// Provider 以下拉呈现：op / coffer 均可选（docs/29 §7.1 取消灰态）；
    /// 切换即触发状态重算（provider 分流见 McpStatus.resolve）。
    private var providerRow: some View {
        HStack {
            Text("数据源")
            Spacer()
            Menu {
                ForEach(McpProvider.allCases, id: \.self) { option in
                    Button {
                        provider = option
                        refreshStatus()
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
        switch provider {
        case .op:
            HStack {
                Text("默认保险库")
                TextField("可选，例如 Personal", text: $vaultName)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 240)
                    .onChange(of: vaultName) { _, newValue in
                        McpSettings.saveVaultName(newValue)
                    }
            }
        case .coffer:
            HStack {
                Text("密码库目录")
                Spacer()
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

    // MARK: - 注册命令（docs/20 §5.4；docs/29 §7.1 随 provider 分支）

    /// coffer 版命令可构造性：需已打开库会话（vaultDirPath 才有效）。
    private var canBuildCofferCommand: Bool {
        provider == .coffer ? (model.session != nil && !model.vaultUUID.isEmpty) : true
    }

    /// 注册命令（单一数据源：预览与复制按钮共用，所见即所得）。
    private var registerCommand: String {
        switch provider {
        case .op:
            return McpRegisterCommand.build(provider: provider.rawValue, vault: vaultName)
        case .coffer:
            return McpRegisterCommand.build(
                provider: provider.rawValue,
                vault: nil,
                vaultDirPath: model.vaultDirPath
            )
        }
    }

    /// 命令预览（monospaced，可手动选中复制；coffer 无会话时显示引导文案）。
    @ViewBuilder
    private var commandPreviewRow: some View {
        if provider == .coffer && !canBuildCofferCommand {
            Text("请先打开密码库后生成注册命令")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else {
            Text(registerCommand)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// 一键复制按钮（docs/20 §6.1 / §5.4；coffer 无会话时禁用）。
    private var copyButtonRow: some View {
        HStack {
            Button {
                copyRegisterCommand()
            } label: {
                Label(copied ? "已复制" : "复制注册命令",
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canBuildCofferCommand)
            if provider == .op && !McpSettings.hasConfiguredVault(vaultName) {
                // 未配置 vault → 命令省略 --vault（§5.2 缺省 = $COFFER_OP_VAULT）
                Text("未配置 vault，命令将省略 --vault")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    /// 复制到剪贴板（显式错误处理：写入失败给用户可操作提示，docs/20 §6.3）。
    private func copyRegisterCommand() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(registerCommand, forType: .string) else {
            errorMessage = "复制失败：无法写入剪贴板，请重试。"
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
        Button {
            linkOnePassword()
        } label: {
            Label("链接 1Password…", systemImage: "link")
        }
    }

    private func linkOnePassword() {
        guard McpStatusProbe.isOpBinaryAvailable() else {
            errorMessage = "未找到 1Password CLI（op）。请安装 1Password CLI 8+（developer.1password.com/docs/cli）后重新打开本页。"
            return
        }
        if McpStatusProbe.isOpSessionAvailable() {
            infoMessage = "已检测到 1Password 会话信号。注册命令可被 coffer mcp 使用；如仍未生效，请在终端重新执行 op signin。"
        } else {
            infoMessage = "未检测到 1Password 会话。请在终端执行以下命令完成登录后返回本页（或点状态行的刷新）：\n\nop signin\n\n1Password 集成会话由 CLI 维护，App 不保存你的登录令牌。"
        }
        refreshStatus()
    }

    // MARK: - 状态行（docs/20 §6.1 / §6.3；docs/29 §7.1 分流）

    /// 状态行：就绪度 + 手动刷新（op signin 在终端完成后无需重开设置页即可刷新）。
    private var statusRow: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: statusIcon)
                .foregroundStyle(statusColor)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text("状态").font(.headline)
                Text(status.label)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                refreshStatus()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .disabled(!enabled)
            .help("刷新状态")
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

    // MARK: - 查看使用记录（docs/20 §6.1 控件表末项）

    /// 「查看使用记录」入口：打开只读审计视图（docs/20 §4.6 方案 A 的
    /// usage audit JSONL）。审计 JSONL（D-3）待用户确认、cf-mcp 尚未落盘
    /// ——本版做禁用态占位（UI 骨架），格式落定 + 落盘后由 op 集成组
    /// （docs/20 §9 G-C/G-G）接入只读读取，本入口随之放开。
    private var usageLogRow: some View {
        HStack {
            Button {
                // 预留：D-3 落定后打开只读审计视图（audit JSONL tail，脱敏）
            } label: {
                Label("查看使用记录", systemImage: "list.bullet.rectangle")
            }
            .disabled(true) // 审计 JSONL（docs/20 §4.6 方案 A / D-3）落定后放开
            Spacer()
            Text("审计记录格式待定（D-3）")
                .font(.caption)
                .foregroundStyle(.secondary)
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
            return "让 Claude Code 等 Agent 通过 MCP 访问 1Password 中的密钥。MCP 服务器由独立的 coffer 进程运行（主 App 不内置服务器）；使用前请在终端执行 op signin，并确认 coffer 命令已在 PATH。"
        case .coffer:
            return "让 Claude Code 等 Agent 通过 MCP 访问本机 Coffer 密码库。MCP 服务器由独立的 coffer 进程运行（主 App 不内置服务器）；解锁走 MCP 解锁托管，注册命令不含密码 env。换主密码不影响托管；如需吊销请在本页关闭。"
        }
    }
}
