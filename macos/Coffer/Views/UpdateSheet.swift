// UpdateSheet.swift —— OTA 更新检查/进度/结果 sheet（v2.7.0，docs/35 §2.6 / §6.3）。
//
// 只渲染 UpdaterManager.state + 调 check/install（契约 6.3 冻结接口），不碰网络/
// 验签/替换细节。按钮可用性按 state 精确禁用（UpdateCopy.buttonState 纯函数），
// checking/installing 时禁一切（含关闭，§2.6 用户裁定）。
//
// 跳过版本语义（§2.6）：updateAvailable 命中已跳过（≤ ota_skipped_version）的版本
// 时按「已是最新」呈现（effectiveState 过滤），不重复推销；「跳过此版本」把当前
// 版本记录到 UserDefaults 后关闭 sheet。

import SwiftUI

struct UpdateSheet: View {
    @EnvironmentObject
    private var model: AppModel
    /// Updater 状态机（契约 6.3）。@ObservedObject 直接观察 state，变化即重渲染
    /// （嵌套 ObservableObject 不经此方式观察不保证刷新）。
    @ObservedObject
    private var updater: UpdaterManager
    @Environment(\.dismiss)
    private var dismiss
    /// 「安装更新…」后的退出确认警示（「Coffer 将退出并更新」→ 调 install）。
    @State private var showInstallConfirm = false

    init(updater: UpdaterManager) {
        self.updater = updater
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            content
                .frame(maxWidth: .infinity, alignment: .leading)
            footer
        }
        .frame(width: 440)
        .padding()
        // checking/installing 禁一切：同时禁 ESC/点击外部关闭，防中途打断状态机
        // （依赖 check()/install() 内置硬超时，超时后回到 failed，不会永久卡死）。
        .interactiveDismissDisabled(UpdateCopy.isBusy(state))
        .alert("安装更新", isPresented: $showInstallConfirm) {
            Button("安装", role: .destructive) {
                model.installUpdate()
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("Coffer 将退出并更新到新版本，完成后自动重新打开。")
        }
    }

    /// 当前渲染状态（跳过版本过滤后）：updateAvailable 命中已跳过版本 → 按
    /// 「已是最新」呈现（§2.6，不重复推销）。
    private var state: UpdaterState {
        updater.state
    }

    private var effectiveState: UpdaterState {
        guard case let .updateAvailable(info) = state,
              !UpdateCopy.shouldPresentUpdate(version: info.version,
                                              skippedVersion: UpdateCopy.skippedVersion())
        else { return state }
        return .upToDate
    }

    // MARK: - 头部

    private var header: some View {
        HStack {
            Text(title)
                .font(.headline)
            Spacer()
        }
    }

    private var title: String {
        switch effectiveState {
        case .idle, .checking, .upToDate: return "检查更新"
        case .updateAvailable: return "发现新版本"
        case .downloading: return "下载更新"
        case .downloaded: return "准备安装"
        case .installing: return "正在安装"
        case .failed: return "更新失败"
        }
    }

    // MARK: - 内容（按 state 渲染）

    @ViewBuilder
    private var content: some View {
        switch effectiveState {
        case .idle: idleContent
        case .checking: checkingContent
        case .updateAvailable(let info): updateAvailableContent(info)
        case .upToDate: upToDateContent
        case .downloading(let progress): downloadingContent(progress)
        case .downloaded: downloadedContent
        case .installing: installingContent
        case .failed(let text): failedContent(text)
        }
    }

    private var idleContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("尚未检查更新。")
                .foregroundStyle(.secondary)
            Text("Coffer 不会在后台自动检查更新，点「检查更新」手动检查。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var checkingContent: some View {
        HStack(spacing: 12) {
            ProgressView()
            Text("正在检查更新…")
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }

    private func updateAvailableContent(_ info: UpdateInfo) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label {
                Text("发现新版本 \(info.version)")
                    .font(.headline)
            } icon: {
                Image(systemName: "arrow.down.circle")
                    .foregroundStyle(.blue)
            }
            if info.securityCritical {
                // 安全补丁：警告 + 显著提示（§2.6 裁定：不阻断使用）
                Label {
                    Text("此更新包含安全修复，建议尽快安装。")
                        .font(.callout)
                } icon: {
                    Image(systemName: "exclamationmark.shield")
                        .foregroundStyle(.orange)
                }
            }
            if let notes = info.notes, !notes.isEmpty {
                Text(notes)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("当前版本 \(UpdateCopy.appVersionText)")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
    }

    private var upToDateContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text("已是最新版本")
                    .font(.headline)
            } icon: {
                Image(systemName: "checkmark.circle")
                    .foregroundStyle(.green)
            }
            Text("当前版本 \(UpdateCopy.appVersionText)")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private func downloadingContent(_ progress: Double) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            ProgressView(value: min(max(progress, 0), 1))
            Text(UpdateCopy.progressPercentText(progress))
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    private var downloadedContent: some View {
        Label {
            Text("已下载并验证，准备安装。")
                .font(.headline)
        } icon: {
            Image(systemName: "checkmark.circle")
                .foregroundStyle(.green)
        }
    }

    private var installingContent: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                ProgressView()
                Text("正在安装…")
                    .foregroundStyle(.secondary)
            }
            Text("Coffer 将退出并更新，请稍候重新打开。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }

    private func failedContent(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text("更新失败")
                    .font(.headline)
            } icon: {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - 底部按钮（按 state 精确禁用）

    @ViewBuilder
    private var footer: some View {
        let buttons = UpdateCopy.buttonState(for: effectiveState,
                                             skippedVersion: UpdateCopy.skippedVersion())
        Divider()
        HStack(spacing: 12) {
            Spacer()
            if buttons.canSkip {
                Button("跳过此版本") { skipCurrentVersion() }
            }
            if buttons.canDownload {
                Button("下载并安装") { model.installUpdate() }
                    .keyboardShortcut(.defaultAction)
            }
            if buttons.canInstall {
                Button("安装更新…") { showInstallConfirm = true }
                    .keyboardShortcut(.defaultAction)
            }
            if buttons.canRetry {
                Button("重试") { model.checkForUpdates() }
                    .keyboardShortcut(.defaultAction)
            }
            if buttons.canCheck {
                Button("检查更新") { model.checkForUpdates() }
                    .keyboardShortcut(.defaultAction)
            }
            Button("关闭") { close() }
                .disabled(!buttons.canClose)
        }
    }

    // MARK: - 动作

    /// 显式关闭：契约 6.3 `dismiss()` 语义 = 「关面板 / 清理失败态」——仅 failed
    /// 态调用以清除失败；其余 state 不动（保留已下载包 / 进行中任务，交由状态机
    /// 继续），只关 sheet。
    private func close() {
        if case .failed = state {
            updater.dismiss()
        }
        dismiss()
    }

    /// 「跳过此版本」：本地记录跳过版本（§2.6，后续只有更新的版本才重新提示），
    /// 然后关闭 sheet。
    private func skipCurrentVersion() {
        if case let .updateAvailable(info) = state {
            UpdateCopy.recordSkippedVersion(info.version)
        }
        dismiss()
    }
}
