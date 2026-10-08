// BrowserSettingsView.swift —— 统一设置页「浏览器集成」节（docs/31 §6.2 / §9.1 G-D）。
//
// 对齐 1Password / Bitwarden 桌面端「浏览器集成」设置：开关 + 状态行 +
// 配对确认。
//
// 本页只做四件事：
//   ① 写配置：开关 → UserDefaults（非敏感布尔，BrowserIntegrationSettings）
//   ② 触发 manifest 写入/删除 + broker spawn/kill（经 AppModel.setBrowserIntegration，
//      docs/31 §2.3 启/配对流——App 侧不宿主服务器，broker 是独立进程）
//   ③ 显示状态：本地前置探测（BrowserStatus.resolve，无 socket；就绪度 = coffer
//      二进制 + manifest 落盘，G-A3 与 escrow 解耦）
//   ④ 配对确认（docs/31 §4.2/§5.3）：显式用户批准才触发 broker 下发 PSK + 公钥
//
// 呈现纪律（docs/31 §6.2）：manifest 写入失败（含沙盒拒绝）/ broker spawn 失败
// 均显式呈现可操作文案（fail-closed）；开关失败回滚到持久化值（不保留半启用态）。
// 配对确认用**内联行**而非嵌套 sheet/alert——错误弹窗（alert）与内联确认同处
// 一层，避免 macOS alert 叠 sheet 的呈现问题（McpEscrowSettingsSection 同款教训）。

import SwiftUI

/// 统一设置页「浏览器集成」节（docs/31 §9.1 G-D）。
/// 经 `@EnvironmentObject model: AppModel` 触发 manifest/broker 编排与读取
/// broker 运行态 / 待确认配对请求（与 McpSettingsSection 同款最小化注入）。
struct BrowserSettingsSection: View {
    @EnvironmentObject
    private var model: AppModel

    /// 「启用浏览器集成」开关（UserDefaults 持久化；失败时回滚到持久化值）。
    @State private var enabled = BrowserIntegrationSettings.loadEnabled()
    /// 就绪状态（onAppear / 开关变更 / 刷新后重算）。
    @State private var status: BrowserStatus = .disabled
    /// 错误弹窗（FfiErrorAlert 统一「操作失败」呈现）。
    @State private var errorMessage: String?
    /// 开关异步编排（manifest 写/删 + broker spawn/kill）进行中标记。
    @State private var isApplying = false
    /// 配对结束态一次性提示（拒绝/超时文案，契约 §8-3「超时即拒」不静默）。
    @State private var pairingNotice: String?

    var body: some View {
        Section {
            Toggle("启用浏览器集成", isOn: $enabled)
                .disabled(isApplying)
                .onChange(of: enabled) { _, newValue in
                    applyToggle(newValue)
                }

            if enabled {
                statusRow
                brokerStateRow
                if model.pendingPairingRequest != nil {
                    pairingRow
                }
                if let notice = pairingNotice {
                    Text(notice)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("浏览器集成")
        } footer: {
            Text(footerText)
        }
        .onAppear { refreshStatus() }
        .onChange(of: model.lastPairingDismissal) { _, newValue in
            pairingNotice = Self.noticeText(for: newValue)
            if newValue != nil {
                // 一次性提示：3s 后自动清除（配对为一次一个的手动流程，极少碰撞）
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                    pairingNotice = nil
                }
            }
        }
        .ffiErrorAlert($errorMessage)
    }

    /// 配对结束态 → 文案（契约 §8-3：拒绝/超时不静默）。
    private static func noticeText(for dismissal: BrowserPairingDismissal?) -> String? {
        guard let dismissal else { return nil }
        switch dismissal {
        case .approved: return "已批准配对，扩展即将连接。"
        case .rejected: return "已拒绝配对。"
        case .cancelled(let reason): return "\(reason)，如需配对请重新发起。"
        }
    }

    // MARK: - 开关编排（docs/31 §2.3 启/配对流）

    /// 开关切换：经 AppModel 写/删 manifest + spawn/kill broker（async）。
    /// 失败 → 开关回滚到持久化值（未落盘 = 保持关闭），错误文案弹窗呈现。
    private func applyToggle(_ newValue: Bool) {
        guard !isApplying else { return }
        isApplying = true
        Task {
            let ok = await model.setBrowserIntegration(newValue)
            if !ok {
                // 回滚：loadEnabled 反映未落盘的旧值（enable 失败未 save）
                enabled = BrowserIntegrationSettings.loadEnabled()
            }
            isApplying = false
            refreshStatus()
        }
    }

    // MARK: - 状态行（docs/31 §6.2，镜像 McpStatus.resolve 纪律）

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

    // MARK: - broker 运行态（docs/31 §2.1 锁态镜像）

    private var brokerStateRow: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: brokerStateIcon)
                .foregroundStyle(brokerStateColor)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text("后台服务").font(.headline)
                Text(brokerStateLabel)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private var brokerStateLabel: String {
        switch model.browserBrokerState {
        case .stopped: return "未运行（App 解锁且集成启用后自动启动）"
        case .running(let pid): return "运行中（PID \(pid)）"
        case .failed(let detail): return detail
        }
    }

    private var brokerStateIcon: String {
        switch model.browserBrokerState {
        case .stopped: return "stop.circle"
        case .running: return "play.circle"
        case .failed: return "exclamationmark.triangle"
        }
    }

    private var brokerStateColor: Color {
        switch model.browserBrokerState {
        case .stopped: return .secondary
        case .running: return .green
        case .failed: return .orange
        }
    }

    // MARK: - 配对确认（docs/31 §4.2/§5.3：显式用户批准）

    /// 内联配对确认行：展示浏览器名 + 扩展 ID + 权限说明，用户显式批准/拒绝。
    /// 批准才触发 broker 下发 PSK + 公钥（decision 经 AppModel 转发 seam）；
    /// 密钥材料不经本视图、不进日志。
    private var pairingRow: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("配对确认").font(.headline)
            Text(pairingMessage)
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("拒绝", role: .cancel) { model.rejectPendingPairing() }
                Button("批准") { model.approvePendingPairing() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(.vertical, 4)
    }

    private var pairingMessage: String {
        guard let request = model.pendingPairingRequest else { return "" }
        let permission = request.permissionDescription.isEmpty
            ? "访问本机密码库中的已绑定凭据（仅在你显式操作时填充）"
            : request.permissionDescription
        return "\(request.browser.displayName) 上的 Coffer 扩展（ID：\(request.extensionID)）请求与本机密码库配对。\(permission)。"
    }

    // MARK: - 刷新

    /// 重算就绪状态（docs/31 §6.2）：本地快路径探测（coffer 二进制 + manifest
    /// 落盘；G-A3：就绪度与 escrow 解耦——broker 契约 = App 解锁 + stdin DEK
    /// 交付，broker 运行态由 brokerStateRow 独立呈现）。
    private func refreshStatus() {
        status = BrowserStatus.resolve(
            enabled: enabled,
            cofferBinaryAvailable: BrowserStatusProbe.isCofferBinaryAvailable(),
            manifestsInstalled: BrowserStatusProbe.allManifestsInstalled(
                homeDirectory: BrowserStatusProbe.userHomeDirectory())
        )
    }

    /// 节 footer 说明（docs/31 §6.2 / §4.1）。
    private var footerText: String {
        "让 Chrome、Edge、Firefox 上的 Coffer 扩展通过本机浏览器集成读取密码库并填充凭据。开启后 App 在解锁时启动后台服务（锁定即停止，锁态镜像）；配对需在本页显式批准。扩展 ID 与清单在首版发布前冻结（D-4）。"
    }
}
