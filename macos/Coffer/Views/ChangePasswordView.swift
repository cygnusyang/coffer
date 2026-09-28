// ChangePasswordView.swift —— 修改主密码 sheet（FR-1.8，docs/09 §3.7 T-D）。
//
// 流程（Rust VaultSession.changePassword）：
//   旧密码 + 新密码 + 确认新密码 → Rust 侧 zxcvbn 门禁（score < 3 → 1010，
//   先于任何文件操作）→ 旧密码重验证（错 → 1002，header 未动）→ 原子重写
//   header。D-2 重封装语义：仅重封装 header 中的 DEK，不重新加密全部条目，
//   db 内容不动；bio 封装不受影响。需解锁态（1001）；newKdf 传 nil 沿用
//   当前档位（本流程不提供改 KDF 档位）。
//
// 反馈三路（TC-UI-11）：
//   - 旧密码错 / 数据损坏：1002 一码两义，ErrorPresenter 文案直出（不写死
//     「旧密码错误」），表单保留可重试；
//   - 新密码弱（1010）：ErrorPresenter 文案直出，表单保留可重试；
//   - 成功：alert「主密码已修改，请使用新密码重新解锁」→ 点「好」后
//     dismiss 本 sheet 并 model.lock() 回锁定页（lock 顺带 clearOnLock 属
//     预期）。lock 调用时机在 alert 点击后——changePassword 返回即刻调用
//     会在 sheet 仍开着时切走锁定页。
//
// 密码纪律（docs/07 §2.4，与 TouchIDSettingsSection / VaultSetupView 一致）：
//   三个密码只在提交瞬间拷贝进 Task 闭包，随即清空 @State；失败后表单虽
//   保留可重试，但密码已被清空、需重新输入——有意的安全行为，非 bug。
//   不落 @Published、不写日志。
//
// 慢调用纪律：changePassword 约 2×Argon2id（2 s+），Task.detached 包裹；
// isBusy 互斥为本视图层 only（AppModel.isBusy 不可从视图侧置位），以本地
// submitting 防双击 + model.isBusy 只读门禁兜底。sheet 模态呈现期间设置页
// 其他操作本就被阻断。

import SwiftUI

struct ChangePasswordView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 三个密码临时输入（提交即清空，见文件头密码纪律）。
    @State private var oldPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    /// 慢调用（约 2×Argon2id，2 s+）进行中标记，防双击。
    @State private var isSubmitting = false
    /// 成功 alert（TC-UI-11 第三路）。
    @State private var showSuccess = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("修改主密码")
                .font(.headline)
            Text("修改只重新封装密码库头部，不重新加密全部条目；Argon2id 派生约需 1-2 秒。")
                .font(.callout)
                .foregroundStyle(.secondary)

            SecureField("旧密码", text: $oldPassword, prompt: Text("请输入当前主密码"))
                .textFieldStyle(.roundedBorder)
            SecureField("新密码", text: $newPassword, prompt: Text("至少包含 3 类字符或足够长度"))
                .textFieldStyle(.roundedBorder)
            SecureField("确认新密码", text: $confirmPassword, prompt: Text("再次输入新密码"))
                .textFieldStyle(.roundedBorder)

            strengthSection

            if mismatchHintVisible {
                Text("两次输入的新密码不一致。")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            HStack {
                Spacer()
                if isSubmitting {
                    ProgressView {
                        Text("正在修改…（Argon2id 派生约需 1-2 秒）")
                    }
                }
                Button("取消", role: .cancel) { cancelForm() }
                Button("修改主密码") { submit() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit)
            }
        }
        .padding(24)
        .frame(width: 420)
        .ffiErrorAlert($model.lastErrorMessage)
        .alert("主密码已修改", isPresented: $showSuccess) {
            Button("好", role: .cancel) {
                // 成功后回到锁定页（TC-UI-11）：旧密码已失效，必须用新密码
                // 重新解锁。lock 顺带 clearOnLock 属预期。
                dismiss()
                model.lock()
            }
        } message: {
            Text("请使用新密码重新解锁。")
        }
    }

    // MARK: - 强度条（展示用途；门禁在 Rust 侧 1010）

    @ViewBuilder
    private var strengthSection: some View {
        if !newPassword.isEmpty {
            let score = currentScore
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 4) {
                    ForEach(0..<5, id: \.self) { index in
                        Capsule()
                            .fill(index <= score ? strengthColor(score) : Color.secondary.opacity(0.2))
                            .frame(height: 5)
                    }
                    Text(verbatim: PasswordStrength.label(score))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let estimate = model.estimateStrength(newPassword), !estimate.warnings.isEmpty {
                    Text(estimate.warnings.joined(separator: "；"))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    /// Rust zxcvbn 估算（有会话恒可用；估算失败用本地粗估兜底，同 VaultSetupView）。
    private var currentScore: Int {
        if let estimate = model.estimateStrength(newPassword) {
            return Int(estimate.score)
        }
        return PasswordStrength.localScore(newPassword)
    }

    private func strengthColor(_ score: Int) -> Color {
        switch score {
        case 0: return .red
        case 1: return .orange
        case 2: return .yellow
        case 3: return .green
        default: return .mint
        }
    }

    // MARK: - 提交

    private var canSubmit: Bool {
        !isSubmitting && !model.isBusy
            && !oldPassword.isEmpty && !newPassword.isEmpty && !confirmPassword.isEmpty
            && newPassword == confirmPassword
    }

    private var mismatchHintVisible: Bool {
        !newPassword.isEmpty && !confirmPassword.isEmpty && newPassword != confirmPassword
    }

    private func cancelForm() {
        oldPassword = ""
        newPassword = ""
        confirmPassword = ""
        dismiss()
    }

    private func submit() {
        // 设置页仅在解锁态可达，session 必非 nil；防御性 guard 兜底。
        guard let session = model.session, canSubmit else { return }
        // 密码不落状态：拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）。
        // 失败后重试需重新输入三个密码，系有意的安全行为（与
        // TouchIDSettingsSection 一致），非 bug。
        let oldSecret = oldPassword
        let newSecret = newPassword
        oldPassword = ""
        newPassword = ""
        confirmPassword = ""
        isSubmitting = true
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    // newKdf 传 nil：沿用当前 KDF 档位（仅换主密码）
                    try session.changePassword(
                        oldPassword: oldSecret, newPassword: newSecret, newKdf: nil)
                }.value
                isSubmitting = false
                showSuccess = true
            } catch {
                isSubmitting = false
                // 1002 一码两义（旧密码错 / 数据损坏）与 1010（新密码弱）
                // 均直出 ErrorPresenter 文案，表单保留可重试。
                // 错误文案 Rust 侧已脱敏，落诊断日志与 AppModel 各错误路径同纪律。
                let errText = ErrorPresenter.text(error)
                DiagLog.append(errText)
                model.lastErrorMessage = errText
            }
        }
    }
}
