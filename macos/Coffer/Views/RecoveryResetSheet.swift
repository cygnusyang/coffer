// RecoveryResetSheet.swift —— 忘记主密码重置 sheet（FR-17.1/17.2，docs/31 §4.2）。
//
// 从锁定页进入（LockView「忘记主密码？」）。两分支按可用性显隐：
//   - Touch ID 重置：isTouchIDSupported ∧ touchIDStatus == .enabled ∧
//     session.hasBiometricWrap()——Keychain 指纹认证由 AppModel 编排；
//   - 恢复码重置：model.hasRecoveryWrap——离线恢复码（用户持有，不落盘）。
//   两分支均不可用 → 空态文案「此密码库未配置生物识别或恢复码，无法在此重置。」
//
// 错误文案不可区分纪律（docs/31 §4.2 / FR-1.4）：两条重置路径失败统一使用
// 指定字面量，不区分「凭证错 / wrap 损坏 / header 损坏」等具体原因——
//   恢复码路径：「重置失败：恢复码无效或密码库数据损坏。」
//   Touch ID 路径：「重置失败：无法完成身份验证或密码库数据损坏。」
//
// 判定成败（契约）：model 重置方法为 async Void，失败经
// model.lastErrorMessage 呈现（与 unlock / unlockWithTouchID 同纪律）——
// 调用后 lastErrorMessage 非 nil 即失败（含空串，如用户取消认证，宁当
// 失败也不假报成功）。失败时把模型错误落诊断日志并清 nil（防止 sheet
// 关闭后残留到 LockView 的 ffiErrorAlert），转成本视图字面量呈现。
//
// 密码纪律（docs/07 §2.4，与 ChangePasswordView 一致）：新密码与恢复码
// 只在提交瞬间拷贝进 Task 闭包，随即清空 @State；失败后表单虽保留可
// 重试，但密码已清空、需重新输入——有意的安全行为，非 bug。成功视图的
// 「用新密码解锁」输入为 SecureField @State（与 LockView 主密码同形态），
// 提交即清空。不落 @Published、不写日志。
//
// 慢调用纪律：reset 两路径含 Argon2id repack（1-2 s+），AppModel 内部
// Task.detached 包裹；本地 isSubmitting 防双击（AppModel.isBusy 只读门禁
// 兜底），sheet 模态呈现期间其他操作本就被阻断。
//
// 成功 UX（docs/31 D-9）：Rust 侧不 finish_unlock（保持锁定），本视图展示
// 成功 + 「用新密码解锁」按钮（调 model.unlock，解锁成功 dismiss 回解锁页）。

import SwiftUI

struct RecoveryResetSheet: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    // MARK: - 状态

    /// Touch ID 重置分支输入（提交即清空，见文件头密码纪律）。
    @State private var bioPassword = ""
    @State private var bioConfirm = ""
    /// 恢复码重置分支输入（提交即清空，恢复码明文不落盘）。
    @State private var recoveryCode = ""
    @State private var recoveryPassword = ""
    @State private var recoveryConfirm = ""
    /// 慢调用（Argon2id repack 1-2 s+）进行中标记，防双击。
    @State private var isSubmitting = false
    /// 重置成功标记：true 后切成功视图（D-9）。
    @State private var didReset = false
    /// 重置 / 解锁失败本地文案（错误文案不可区分纪律，见文件头注释）。
    @State private var errorMessage: String?
    /// 成功视图「用新密码解锁」输入（提交即清空，同 LockView 主密码形态）。
    @State private var unlockPassword = ""
    @State private var isUnlocking = false

    /// 两条重置路径的错误文案（docs/31 §4.2 错误文案不可区分纪律，FR-1.4）：
    /// 不区分「凭证错 / wrap 损坏 / header 损坏」，统一字面量。
    private static let touchIDResetErrorText = "重置失败：无法完成身份验证或密码库数据损坏。"
    private static let recoveryResetErrorText = "重置失败：恢复码无效或密码库数据损坏。"

    // MARK: - 分支可见性

    /// Touch ID 重置分支可见性（docs/31 §4.2）：设备支持 ∧ 通道 enabled ∧
    /// header 已配 bio 封装。enabled 已含设备支持前置（TouchIDStatus.resolve），
    /// 这里再显式并 isTouchIDSupported，与 LockView 入口语义一致（防御）。
    private var showTouchIDReset: Bool {
        model.isTouchIDSupported
            && model.touchIDStatus == .enabled
            && (model.session?.hasBiometricWrap() ?? false)
    }

    /// 恢复码重置分支可见性（docs/31 §4.2）：header 已配 recovery wrap。
    private var showRecoveryReset: Bool {
        model.hasRecoveryWrap
    }

    var body: some View {
        Group {
            if didReset {
                successView
            } else if showTouchIDReset || showRecoveryReset {
                resetForm
            } else {
                emptyStateView
            }
        }
        .padding(24)
        .frame(width: 440)
        .alert("操作失败", isPresented: errorAlertPresented) {
            Button("好", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    // MARK: - 重置表单（两分支按可用性堆叠）

    @ViewBuilder
    private var resetForm: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("忘记主密码")
                .font(.headline)
            Text("可通过生物识别或恢复码重置主密码，条目数据不受影响。")
                .font(.callout)
                .foregroundStyle(.secondary)

            if showTouchIDReset {
                touchIDResetSection
            }
            if showRecoveryReset {
                if showTouchIDReset {
                    Divider()
                }
                recoveryResetSection
            }

            if isSubmitting {
                HStack {
                    Spacer()
                    ProgressView {
                        Text("正在重置…（Argon2id 派生约需 1-2 秒）")
                    }
                }
            }

            HStack {
                Spacer()
                Button("取消", role: .cancel) { dismiss() }
            }
        }
    }

    private var touchIDResetSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("使用 Touch ID 重置", systemImage: "touchid")
                .font(.headline)
            SecureField("新主密码", text: $bioPassword, prompt: Text("请输入新主密码"))
                .textFieldStyle(.roundedBorder)
            SecureField("确认新密码", text: $bioConfirm, prompt: Text("再次输入新密码"))
                .textFieldStyle(.roundedBorder)
            if bioMismatchHintVisible {
                Text("两次输入的新密码不一致。")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("用 Touch ID 重置") { submitWithBio() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmitBio)
            }
        }
    }

    private var recoveryResetSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("使用恢复码重置", systemImage: "key")
                .font(.headline)
            SecureField("恢复码", text: $recoveryCode, prompt: Text("请输入恢复码"))
                .textFieldStyle(.roundedBorder)
            SecureField("新主密码", text: $recoveryPassword, prompt: Text("请输入新主密码"))
                .textFieldStyle(.roundedBorder)
            SecureField("确认新密码", text: $recoveryConfirm, prompt: Text("再次输入新密码"))
                .textFieldStyle(.roundedBorder)
            if recoveryMismatchHintVisible {
                Text("两次输入的新密码不一致。")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("用恢复码重置") { submitWithRecovery() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmitRecovery)
            }
        }
    }

    // MARK: - 空态（两分支均不可用）

    private var emptyStateView: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.slash")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("此密码库未配置生物识别或恢复码，无法在此重置。")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("关闭", role: .cancel) { dismiss() }
                .padding(.top, 8)
        }
    }

    // MARK: - 成功视图（D-9：保持锁定，引导新密码解锁）

    private var successView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("主密码已重置，条目数据不受影响。请用新密码解锁。")
                .multilineTextAlignment(.center)
            SecureField("新主密码", text: $unlockPassword, prompt: Text("请输入新主密码"))
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)
            if isUnlocking {
                ProgressView {
                    Text("正在解锁…（Argon2id 密钥派生约需 1 秒）")
                }
            } else {
                Button("用新密码解锁") { unlockWithNewPassword() }
                    .buttonStyle(.borderedProminent)
                    .disabled(unlockPassword.isEmpty)
            }
        }
    }

    // MARK: - 提交

    private var canSubmitBio: Bool {
        !isSubmitting && !model.isBusy
            && !bioPassword.isEmpty && !bioConfirm.isEmpty
            && bioPassword == bioConfirm
    }

    private var canSubmitRecovery: Bool {
        !isSubmitting && !model.isBusy && !recoveryCode.isEmpty
            && !recoveryPassword.isEmpty && !recoveryConfirm.isEmpty
            && recoveryPassword == recoveryConfirm
    }

    private var bioMismatchHintVisible: Bool {
        !bioPassword.isEmpty && !bioConfirm.isEmpty && bioPassword != bioConfirm
    }

    private var recoveryMismatchHintVisible: Bool {
        !recoveryPassword.isEmpty && !recoveryConfirm.isEmpty
            && recoveryPassword != recoveryConfirm
    }

    private func submitWithBio() {
        guard canSubmitBio else { return }
        // 密码不落状态：拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）。
        let secret = bioPassword
        bioPassword = ""
        bioConfirm = ""
        isSubmitting = true
        errorMessage = nil
        Task {
            let ok = await runReset { await model.resetPasswordWithBio(newPassword: secret) }
            isSubmitting = false
            if ok {
                didReset = true
            } else {
                errorMessage = Self.touchIDResetErrorText
            }
        }
    }

    private func submitWithRecovery() {
        guard canSubmitRecovery else { return }
        // 密码与恢复码不落状态：拷贝进异步调用后立刻清空（docs/07 §2.4）。
        let code = recoveryCode
        let secret = recoveryPassword
        recoveryCode = ""
        recoveryPassword = ""
        recoveryConfirm = ""
        isSubmitting = true
        errorMessage = nil
        Task {
            let ok = await runReset {
                await model.resetPasswordWithRecoveryCode(newPassword: secret, code: code)
            }
            isSubmitting = false
            if ok {
                didReset = true
            } else {
                errorMessage = Self.recoveryResetErrorText
            }
        }
    }

    /// 执行一次重置调用并判定成败（契约见文件头注释）：model 重置方法为
    /// async Void，失败经 model.lastErrorMessage 呈现——调用后 lastErrorMessage
    /// 非 nil 即失败（含空串，如用户取消认证；宁当失败也不假报成功）。
    /// 失败时把模型错误落诊断日志并清 nil（防止 sheet 关闭后残留到 LockView
    /// 的 ffiErrorAlert），返回 false；成功返回 true。
    private func runReset(_ action: @escaping () async -> Void) async -> Bool {
        await action()
        if let modelError = model.lastErrorMessage {
            DiagLog.append(modelError.isEmpty ? "reset failed (empty model error text)" : modelError)
            model.lastErrorMessage = nil
            return false
        }
        return true
    }

    /// 成功视图「用新密码解锁」（docs/31 D-9）：调 model.unlock——重置保持
    /// 锁定，新密码解锁成功即切 .unlocked 并 dismiss 本 sheet；失败保留
    /// 表单并本地呈现模型文案（如「错误 1002：…」，标准解锁文案族）。
    private func unlockWithNewPassword() {
        guard !unlockPassword.isEmpty, !isUnlocking else { return }
        let secret = unlockPassword
        unlockPassword = ""
        isUnlocking = true
        errorMessage = nil
        Task {
            await model.unlock(password: secret)
            isUnlocking = false
            if let err = model.lastErrorMessage {
                model.lastErrorMessage = nil
                errorMessage = err
            } else {
                dismiss()
            }
        }
    }

    // MARK: - 错误弹窗

    /// 本地错误弹窗绑定：errorMessage 非 nil 即呈现，关闭时清空。
    private var errorAlertPresented: Binding<Bool> {
        Binding(
            get: { !(errorMessage ?? "").isEmpty },
            set: { if !$0 { errorMessage = nil } }
        )
    }
}
