// RecoveryCodeSetupSheet.swift —— 恢复码设置区 + 生成/重生成 sheet（FR-17.2，
// docs/31 §4.3 Settings 生成面 / §2.4 生成语义）。
//
// 结构（结构模型 = VaultBioEnableOfferView，macos/Coffer/Views/VaultSetupView.swift）：
//   - RecoveryCodeSettingsSection：设置页「安全」节内的恢复码两态区——
//     未配置：「未启用」+「生成恢复码…」；
//     已配置：「已启用（恢复码仅在生成时显示一次）」+「重新生成…」（前置
//     确认对话框「旧恢复码将立即失效，确定重新生成？」）。
//   - RecoveryCodeSetupSheet：生成/重生成共用四步流程——
//     ① 说明屏 → ② 生成并一次性展示（大号字体 + 复制按钮，剪贴板固定 30s
//     自动清空）→ ③ 主密码确认（D-6：先验证身份再写 header）→
//     ④ enableRecoveryCode 成功关闭。
//
// 恢复码明文纪律（FR-17.2）：
//   - code 仅存本视图局部 @State，流程结束（成功/取消/关闭）即置空；不落
//     @Published、不写日志、不落盘（磁盘仅 header 的 wrap 密文）。
//   - 剪贴板固定 30s 自动清空（不受用户剪贴板档位影响——「从不」档位不得
//     让恢复码永久留在剪贴板），changeCount 守卫沿用 ClipboardManager 纪律：
//     用户期间复制别的内容则绝不误清。
//   - 主密码纪律（docs/07 §2.4，与 TouchIDSettingsSection / VaultSetupView
//     一致）：临时 @State 提交即清空，直接作方法参数传
//     AppModel.enableRecoveryCode，不落 @State 之外。
//
// 反馈：enable 失败（1002 密码错 / 数据损坏）经 lastErrorMessage →
// ffiErrorAlert 弹窗呈现，本 sheet 保留可重试（与 VaultBioEnableOfferView
// 三分支一致；错误文案不可区分纪律由 ErrorPresenter 统一保证）。

import AppKit
import SwiftUI

/// 设置页「安全」节内的恢复码两态区（FR-17.2 生成面，docs/31 §4.3）。
struct RecoveryCodeSettingsSection: View {
    @EnvironmentObject
    private var model: AppModel

    /// 生成 / 重生成 sheet 呈现（本地 @State；主密码等敏感数据不落 AppModel）。
    @State private var showSetup = false
    /// 已配置态重生成前置确认（docs/31 §2.4：重生成旧码立即失效，不可回滚）。
    @State private var showRegenerateConfirm = false

    var body: some View {
        Section {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("恢复码").font(.headline)
                    Text(statusCaption)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                statusActions
            }
        } header: {
            Text("恢复码")
        } footer: {
            Text("恢复码用于忘记主密码时重置密码库；仅在生成时显示一次，请抄写并妥善保存。")
        }
        .confirmationDialog(
            "重新生成恢复码？",
            isPresented: $showRegenerateConfirm,
            titleVisibility: .visible
        ) {
            Button("重新生成", role: .destructive) { showSetup = true }
            Button("取消", role: .cancel) {}
        } message: {
            Text("旧恢复码将立即失效，确定重新生成？")
        }
        .sheet(isPresented: $showSetup) {
            RecoveryCodeSetupSheet()
                .environmentObject(model)
        }
    }

    /// 状态行说明文案（两态，docs/31 §4.3）。
    private var statusCaption: String {
        model.hasRecoveryWrap
            ? "已启用（恢复码仅在生成时显示一次）"
            : "未启用——忘记主密码时将无法通过恢复码重置。"
    }

    /// 按态渲染的操作按钮（docs/31 §4.3）。
    @ViewBuilder
    private var statusActions: some View {
        if model.hasRecoveryWrap {
            Button("重新生成…") { showRegenerateConfirm = true }
                .disabled(model.isBusy)
        } else {
            Button("生成恢复码…") { showSetup = true }
                .disabled(model.isBusy)
        }
    }
}

/// 恢复码生成 / 重生成四步流程 sheet（FR-17.2，docs/31 §4.3 / §2.4）。
struct RecoveryCodeSetupSheet: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    /// 流程步骤（docs/31 §2.4：生成 → 展示 → 确认 → 启用）。
    private enum Step {
        case intro      // ① 说明屏
        case showCode   // ② 生成并一次性展示
        case confirm    // ③ 主密码确认
    }

    /// 剪贴板固定自动清空时长（FR-17.2：恢复码仅显示一次，不受用户档位影响）。
    private static let clipboardClearSecs: TimeInterval = 30
    /// 复制反馈「已复制」提示的展示时长。
    private static let copiedFeedbackSecs: TimeInterval = 2

    @State private var step: Step = .intro
    /// 一次性生成的恢复码（仅本视图局部；流程结束置空，FR-17.2 明文不落盘）。
    @State private var code = ""
    /// 主密码临时输入（docs/07 §2.4）：提交即清空，不落 @State 之外。
    @State private var password = ""
    /// enable 慢调用（Argon2id 约 1s）进行中标记。
    @State private var isEnabling = false
    /// 复制反馈（「已复制（30 秒后自动清除）」短暂提示）。
    @State private var showCopied = false
    /// 复制反馈提示的复位任务（随视图消失即弃）。
    @State private var copiedResetTask: Task<Void, Never>?
    /// 剪贴板 30s 自动清空任务（仅用于重复复制时取消旧任务；DispatchQueue
    /// 自身持有该 work item，视图消失后仍会到点执行，changeCount 守卫保证不误清）。
    @State private var clipboardClearItem: DispatchWorkItem?

    var body: some View {
        Group {
            switch step {
            case .intro:
                introStep
            case .showCode:
                showCodeStep
            case .confirm:
                confirmStep
            }
        }
        .padding(28)
        .frame(width: 440)
        .ffiErrorAlert($model.lastErrorMessage)
        .onDisappear { cleanup() }
    }

    // MARK: - ① 说明屏

    private var introStep: some View {
        VStack(spacing: 16) {
            Image(systemName: "key")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text(model.hasRecoveryWrap ? "重新生成恢复码" : "设置恢复码")
                .font(.title3.bold())
            Text("恢复码用于忘记主密码时重置。请抄写并妥善保存。恢复码仅显示一次。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if model.hasRecoveryWrap {
                // 重生成分支（docs/31 §2.4）：新码生效即旧码失效，不可回滚
                Text("重新生成后，旧恢复码将立即失效且无法找回。")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .multilineTextAlignment(.center)
            }

            HStack(spacing: 12) {
                Button("取消") { cancelFlow() }
                Button("开始生成") { startGenerate() }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    /// 进入步骤 ②：生成并一次性展示。生成无落盘（docs/31 §2.4 安全顺序：
    /// 先展示、用户确认后才写 header；取消则旧 wrap 不受影响）。
    private func startGenerate() {
        guard !isEnabling else { return }
        guard let generated = model.generateRecoveryCode() else {
            // 失败（nil）：AppModel 已置 lastErrorMessage；兜底补一条防空白
            if model.lastErrorMessage == nil {
                model.lastErrorMessage = "生成恢复码失败，请重试。"
            }
            return
        }
        code = generated
        step = .showCode
    }

    // MARK: - ② 生成并一次性展示

    private var showCodeStep: some View {
        VStack(spacing: 16) {
            Image(systemName: "key")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("抄写并妥善保存恢复码")
                .font(.title3.bold())
            Text("恢复码仅在生成时显示一次，请立即抄写。忘记主密码时可凭它重置密码库。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Text(code)
                .font(.system(size: 20, weight: .semibold, design: .monospaced))
                .multilineTextAlignment(.center)
                .textSelection(.enabled)
                .padding(12)
                .frame(maxWidth: .infinity)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.secondary.opacity(0.1))
                )

            Button {
                copyCode()
            } label: {
                Label(
                    showCopied
                        ? "已复制（\(Int(Self.clipboardClearSecs)) 秒后自动清除）"
                        : "复制",
                    systemImage: "doc.on.doc"
                )
            }

            HStack(spacing: 12) {
                Button("取消") { cancelFlow() }
                Button("我已抄写保存") { step = .confirm }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    /// 复制恢复码并固定 30s 自动清空（FR-17.2）。不走
    /// ClipboardManager.copyWithAutoClear：其清除时长跟随用户档位（「从不」
    /// 档位会让恢复码永久留在剪贴板，违反一次性纪律）；此处固定 30s，
    /// changeCount 守卫沿用同一纪律（用户期间复制别的内容则绝不误清）。
    private func copyCode() {
        guard !code.isEmpty else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(code, forType: .string)
        let written = pasteboard.changeCount
        // 多次复制：取消旧未到点任务，只保留最近一次（ClipboardManager 同纪律）
        clipboardClearItem?.cancel()
        clipboardClearItem = nil
        let work = DispatchWorkItem {
            let pb = NSPasteboard.general
            // changeCount 守卫：期间用户复制了自己的内容则不动（绝不误清）
            if pb.changeCount == written {
                pb.clearContents()
            }
        }
        clipboardClearItem = work
        DispatchQueue.main.asyncAfter(
            deadline: .now() + Self.clipboardClearSecs,
            execute: work
        )

        // 复制反馈提示（短暂展示后复位）
        showCopied = true
        copiedResetTask?.cancel()
        copiedResetTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(Self.copiedFeedbackSecs * 1_000_000_000))
            guard !Task.isCancelled else { return }
            showCopied = false
        }
    }

    // MARK: - ③ 主密码确认（D-6：先验证身份再写 header）

    private var confirmStep: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("确认主密码")
                .font(.title3.bold())
            Text("出于安全考虑，主密码不会被保存，请重新输入一次以确认身份，之后恢复码才会启用。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            SecureField("主密码", text: $password, prompt: Text("请输入主密码"))
                .textFieldStyle(.roundedBorder)
                .frame(width: 260)
                .onSubmit(confirmEnable)

            if isEnabling {
                ProgressView {
                    Text("正在启用…（密钥派生约需 1 秒）")
                }
            }

            HStack(spacing: 12) {
                Button("取消") { cancelFlow() }
                Button("启用恢复码") { confirmEnable() }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || isEnabling || model.isBusy)
            }
        }
    }

    // MARK: - ④ 启用

    /// 提交：主密码不落状态，拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）。
    /// 契约签名无返回（成功 = 未新增错误）；失败（1002）经 lastErrorMessage →
    /// ffiErrorAlert 呈现，本 sheet 保留可重试（需重新输入主密码）。
    private func confirmEnable() {
        guard !password.isEmpty, !isEnabling, !model.isBusy else { return }
        let secret = password
        password = ""
        isEnabling = true
        let codeToEnable = code
        Task {
            let errBefore = model.lastErrorMessage
            await model.enableRecoveryCode(password: secret, code: codeToEnable)
            isEnabling = false
            if model.lastErrorMessage == errBefore {
                // 成功：恢复码已生效（旧 wrap 已被覆盖），关闭 sheet
                finishFlow()
            }
        }
    }

    // MARK: - 流程收尾

    /// 成功关闭：清空一次性明文与主密码后关闭。剪贴板 30s 清除任务保留
    /// （由 DispatchQueue 持有，到点仍清空；changeCount 守卫保证不误清）。
    private func finishFlow() {
        cleanup()
        dismiss()
    }

    /// 取消：header 未写，旧 wrap 保持有效（docs/31 §2.4 第 6 步）；明文清空。
    private func cancelFlow() {
        cleanup()
        dismiss()
    }

    /// 清空一次性明文 / 主密码 / 反馈任务。剪贴板 30s 清除任务**不**在此
    /// 取消（须到点执行），故不归入本方法。
    private func cleanup() {
        code = ""
        password = ""
        showCopied = false
        copiedResetTask?.cancel()
        copiedResetTask = nil
    }
}
