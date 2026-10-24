// McpEscrowSettingsSection.swift —— 设置页「MCP / Agent 协作」节内的
// MCP 解锁托管三态节（docs/29 §7.2，镜像 TouchIDSettingsSection）。
//
// 三态渲染（docs/29 §5.2 resolve，状态由 McpEscrowStatus.resolve 判定）：
//   - disabled：「启用 MCP 解锁托管」→ 内联主密码确认（D-6 同款：enable 需主
//     密码重新验证）→ enable 流程（先 Keychain 后 header，§5.2）
//   - enabled：「关闭 MCP 解锁托管」→ 二次确认 → disable 流程（先删 Keychain
//     再改 header，§5.2）
//   - stale：凭据失效提示 + 「重新启用」入口（同 enable 流程，重派生同一
//     mcp_key，幂等覆盖，§5.3）
//
// enable 反馈分支（镜像 TouchIDSettingsSection）：
//   - 取消：清空输入、退出确认行，无任何状态变更
//   - 密码错 1002：FfiError 文案经 ErrorPresenter 弹窗呈现，确认行保留可重试
//   - Keychain 失败：unexpected OSStatus 文案弹窗，header 未动（§5.2 顺序保证）
//
// 呈现细节：主密码确认采用**内联展开**而非嵌套 sheet——错误弹窗（alert）在
// macOS 上无法叠在已呈现的 sheet 之上，内联行让 1002 / Keychain 失败的反馈
// 与确认输入同处一层（TouchIDSettingsSection.swift:22-31 教训）。
//
// 依赖说明（docs/29 §7.2 偏差声明）：escrow 生命周期需要会话 / 库身份
// （vault_uuid）与 FFI 编排，必须经 @EnvironmentObject model: AppModel
// （与 Touch ID 同款）。

import SwiftUI

/// 设置页「MCP 解锁托管」三态节（docs/29 §7.2）。
struct McpEscrowSettingsSection: View {
    @EnvironmentObject
    private var model: AppModel

    /// 主密码确认行的展开状态（nil = 收起；启用与重新启用共用同一流程）。
    @State private var showPasswordPrompt = false
    /// 关闭功能前的二次确认（docs/29 §5.2：开→关需二次确认）。
    @State private var showDisableConfirm = false
    /// 主密码确认行的临时输入（D-6）：提交即清空，不落任何持久状态。
    @State private var password = ""
    /// enable 慢调用（Argon2id 约 1s）进行中标记。
    @State private var isEnabling = false

    var body: some View {
        // v2.13.1（设计 25 §4.2 G3）：容器 `Section` → `SettingsCard`，行包
        // `SettingsRow`——只改容器与几何，三态与确认行的行为逐项不变。
        SettingsCard(
            "MCP 解锁托管",
            footer: "让 coffer MCP 进程在本机免密码解锁本库。密钥只存本机钥匙串（不随 iCloud 同步）；换主密码不影响托管，如需吊销请在本页关闭。"
        ) {
            statusRow

            if showPasswordPrompt {
                passwordPromptRow
            }

            if model.mcpEscrowStatus == .stale {
                staleNoticeRow
            }
        }
        .onAppear { model.refreshMcpEscrowStatus() }
        .ffiErrorAlert($model.lastErrorMessage)
        .confirmationDialog(
            "关闭 MCP 解锁托管？",
            isPresented: $showDisableConfirm,
            titleVisibility: .visible
        ) {
            Button("关闭 MCP 解锁托管", role: .destructive) {
                Task { await model.disableMcpEscrow() }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("将删除本机钥匙串中的托管凭据并重写密码库头部。之后 coffer MCP 进程无法免密码解锁本库。")
        }
    }

    // MARK: - 行（v2.13.1 设计 25 §4.2 G3：容器改写，内容与行序不变）

    /// 状态行（标题 + 状态说明 + 右端操作）：双行行高 44（设计 25 §2.1 #9）。
    ///
    /// 发丝线只在后面还有行时画——末行画线会在卡片底边内侧多出一条线。
    private var statusRow: some View {
        SettingsRow(minHeight: SettingsMetrics.rowHeightTwoLine, showsDivider: hasRowsAfterStatus) {
            HStack(alignment: .top, spacing: SettingsMetrics.labelControlGap) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("MCP 解锁托管").font(.headline)
                    Text(statusCaption)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: SettingsMetrics.labelControlGap)
                statusActions
            }
        }
    }

    /// 状态行之后是否还有行（确认行 / stale 说明）——决定状态行是否画发丝线。
    private var hasRowsAfterStatus: Bool {
        showPasswordPrompt || model.mcpEscrowStatus == .stale
    }

    /// stale 态说明（docs/29 §5.2：Keychain 项缺失 → 引导重新启用）。
    /// 本节末行，不画发丝线。
    private var staleNoticeRow: some View {
        SettingsRow(showsDivider: false) {
            Label(
                "MCP 解锁托管凭据已失效（Keychain 条目缺失）。重新启用将重派生同一托管密钥并覆盖（幂等）；在此之前 coffer MCP 进程无法免密码解锁本库。",
                systemImage: "exclamationmark.triangle"
            )
            .font(.callout)
            .foregroundStyle(.orange)
        }
    }

    /// 状态行说明文案（三态，docs/29 §7.2）。
    private var statusCaption: String {
        switch model.mcpEscrowStatus {
        case .disabled:
            return String(localized: "已停用——coffer MCP 进程解锁本库需主密码。")
        case .enabled:
            return String(localized: "已启用——coffer MCP 进程可免密码解锁本库。")
        case .stale:
            return String(localized: "凭据已失效（需重新启用）。")
        }
    }

    /// 按态渲染的操作按钮（docs/29 §5.2 生命周期）。
    ///
    /// 命中区按 D-20.7 硬下限 28 扩（`frame(minHeight:)` + `contentShape`），
    /// **不改视觉尺寸**——与镜像实现 TouchIDSettingsSection 的 statusActions 逐项
    /// 对齐（reviewer H2：两节同一交互不得行为分叉）。取
    /// `SettingsMetrics.minimumHitTarget` 而非裸数字（INV-SET-5 几何常量单源）。
    @ViewBuilder
    private var statusActions: some View {
        switch model.mcpEscrowStatus {
        case .disabled, .stale:
            Button(model.mcpEscrowStatus == .disabled
                   ? String(localized: "启用 MCP 解锁托管")
                   : String(localized: "重新启用")) {
                showPasswordPrompt = true
            }
            .disabled(model.isBusy || showPasswordPrompt)
            .frame(minHeight: SettingsMetrics.minimumHitTarget)
            .contentShape(Rectangle())
        case .enabled:
            Button("关闭 MCP 解锁托管", role: .destructive) {
                showDisableConfirm = true
            }
            .disabled(model.isBusy)
            .frame(minHeight: SettingsMetrics.minimumHitTarget)
            .contentShape(Rectangle())
        }
    }

    // MARK: - 主密码确认行（D-6）

    /// 主密码确认行（D-6）：行内联展开，不与错误弹窗争层（见文件头教训）。
    private var passwordPromptRow: some View {
        // 发丝线只在后面还有 stale 说明时画（本节末行画线会多出一条）。
        SettingsRow(minHeight: SettingsMetrics.rowHeightTwoLine,
                    showsDivider: model.mcpEscrowStatus == .stale) {
            VStack(alignment: .leading, spacing: SettingsMetrics.labelControlGap) {
                Text("出于安全考虑，主密码不会被保存，请重新输入一次以确认身份。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    SecureField("主密码", text: $password, prompt: Text("请输入主密码"))
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 220)
                        .onSubmit(confirmEnable)
                    if isEnabling {
                        ProgressView().controlSize(.small)
                    }
                    Spacer()
                    Button("取消", role: .cancel) { cancelPrompt() }
                        .frame(minHeight: SettingsMetrics.minimumHitTarget)
                        .contentShape(Rectangle())
                    Button(confirmTitle) { confirmEnable() }
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty || isEnabling)
                        .frame(minHeight: SettingsMetrics.minimumHitTarget)
                        .contentShape(Rectangle())
                }
            }
        }
    }

    private var confirmTitle: String {
        model.mcpEscrowStatus == .stale
            ? String(localized: "重新启用") : String(localized: "启用")
    }

    private func cancelPrompt() {
        // 取消分支：仅收起确认行并清空输入，无任何状态变更
        password = ""
        showPasswordPrompt = false
    }

    private func confirmEnable() {
        guard !password.isEmpty, !isEnabling else { return }
        // 密码不落状态：拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）
        let secret = password
        password = ""
        isEnabling = true
        Task {
            let ok = await model.enableMcpEscrow(password: secret)
            isEnabling = false
            if ok {
                showPasswordPrompt = false
            }
            // 失败（1002 密码错 / Keychain 失败）：确认行保留可重试，错误文案
            // 经 lastErrorMessage → ffiErrorAlert 呈现
        }
    }
}
