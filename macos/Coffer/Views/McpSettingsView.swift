// McpSettingsView.swift —— 统一设置页「MCP / Agent 协作」节（docs/20 §6）。
//
// 对齐 1Password 最新设计：设置内 Developer 区；「复制注册命令」对齐
// 「Connect to Claude」一键复制（docs/20 §5.4）。
//
// 进程边界（docs/20 §6.2，关键决策）：主 App 不宿主 MCP 服务器——MCP 服务器
// 是独立 `coffer` 进程（由 Claude Code 经 stdio spawn）。本页只做三件事：
//   ① 写配置：开关 / vault 名 → UserDefaults（非敏感布尔/文本，docs/20 §6.1）
//   ② 发注册命令：把 §5.4 命令复制到剪贴板
//   ③ 显示状态：本地前置探测（无 socket，docs/20 §6.3）
// 不 spawn 任何 MCP 服务器进程、不触 AppModel（v0.4 §6.1 切片纪律）。
//
// 呈现纪律（docs/20 §6.3 / docs/07 §2.4）：显式错误处理——复制失败 /
// 剪贴板失败 / op 缺失均给用户可操作提示；op token 即用即弃、不落本视图
// 状态（本版只探测 env 级会话信号，不捕获 token，见 McpStatusProbe 注释）。

import AppKit
import SwiftUI

/// 统一设置页「MCP / Agent 协作」节（docs/20 §6）。
/// 自包含：不依赖 AppModel（MCP 域与密码库会话无关，v0.4 §6.1 切片纪律）。
struct McpSettingsSection: View {
    /// 「启用 MCP 服务器」开关（docs/20 §6.1，持久化到 UserDefaults）。
    @State private var enabled = McpSettings.loadEnabled()
    /// 默认 vault 名（`coffer mcp --vault`，docs/20 §5.2）。
    @State private var vaultName = McpSettings.loadVaultName()
    /// 就绪状态（onAppear / 开关变更 / 链接动作后刷新）。
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
            linkButtonRow
            statusRow
            usageLogRow
        } header: {
            Text("MCP / Agent 协作")
        } footer: {
            Text(footerText)
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

    // MARK: - Provider 行（docs/20 §6.1：MVP 恒 op，Coffer 灰态预留）

    /// Provider 以下拉呈现（docs/20 §6.1 控件表「Provider 下拉」）：MVP 恒
    /// 「1Password CLI」（D-2：MVP 数据源 = op），「Coffer 自家库」灰态预留
    /// （§4.5 CofferStoreProvider，feature 门控）。下拉项均禁选——本版仅一个
    /// 可用 provider，禁选态比可用切换更诚实（§8 控件布局可调，随实现对齐
    /// §6.1 表格形态）；选中值见 label，恒为 op。
    private var providerRow: some View {
        HStack {
            Text("数据源")
            Spacer()
            Menu {
                // 当前 provider（恒选中态：MVP 无可切换项，项本身禁选）
                Button {
                } label: {
                    Label(McpProvider.op.displayName, systemImage: "checkmark")
                }
                .disabled(true)
                // 灰态预留（docs/20 §4.5 CofferStoreProvider，feature 门控）
                Button(McpProvider.coffer.displayName) {}
                    .disabled(true)
            } label: {
                HStack(spacing: 4) {
                    Text(McpProvider.op.displayName)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption)
                }
                .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Vault 配置项（docs/20 §5.2 / §6.1）

    /// Vault 以文本输入承载（`coffer mcp --vault <name>`）。「调 op 列 vault
    /// 下拉」依赖 op 真进程交互（`op vault list`），属 op 集成组（docs/20 §9
    /// G-C）经 cf-ffi 只读接口或进程调用接入，本版不占位实现（§8 布局可调）。
    private var vaultRow: some View {
        HStack {
            Text("默认保险库")
            TextField("可选，例如 Personal", text: $vaultName)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 240)
                .onChange(of: vaultName) { _, newValue in
                    McpSettings.saveVaultName(newValue)
                }
        }
    }

    // MARK: - 注册命令（docs/20 §5.4，对齐「Connect to Claude」）

    /// 注册命令（单一数据源：预览与复制按钮共用，所见即所得）。
    private var registerCommand: String {
        McpRegisterCommand.build(provider: McpProvider.op.rawValue, vault: vaultName)
    }

    /// 命令预览（monospaced，可手动选中复制）。
    private var commandPreviewRow: some View {
        Text(registerCommand)
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// 一键复制按钮（docs/20 §6.1 / §5.4）。
    private var copyButtonRow: some View {
        HStack {
            Button {
                copyRegisterCommand()
            } label: {
                Label(copied ? "已复制" : "复制注册命令",
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderedProminent)
            if !McpSettings.hasConfiguredVault(vaultName) {
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

    // MARK: - 链接 1Password（docs/20 §6.1）

    /// 「链接 1Password…」：探测 op 二进制 + 会话信号，给出就绪结果或
    /// `op signin` 引导。本版不内嵌交互式登录（op signin 需 TTY，且登录令牌
    /// 属敏感材料，即用即弃不落 App——docs/20 §6.3），以终端引导承担。
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

    // MARK: - 状态行（docs/20 §6.1 / §6.3）

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
    /// McpStatusProbe），无需 Task.detached；op 真进程交互接入后
    /// （docs/20 §9 G-C）此处需改 Task.detached 包裹（§6.3 纪律）。
    private func refreshStatus() {
        status = McpStatus.resolve(
            enabled: enabled,
            opBinaryAvailable: McpStatusProbe.isOpBinaryAvailable(),
            cofferBinaryAvailable: McpStatusProbe.isCofferBinaryAvailable(),
            sessionAvailable: McpStatusProbe.isOpSessionAvailable()
        )
    }

    /// 节 footer 说明（docs/20 §6.2：主 App 不宿主 MCP 服务器；用户前置）。
    private var footerText: String {
        "让 Claude Code 等 Agent 通过 MCP 访问 1Password 中的密钥。MCP 服务器由独立的 coffer 进程运行（主 App 不内置服务器）；使用前请在终端执行 op signin，并确认 coffer 命令已在 PATH。"
    }
}
