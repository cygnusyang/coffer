// UpdatePasswordSheet.swift —— 条目「更新密码」快捷动作 sheet（FR-18.1，v2.5.0）。
//
// 入口：ItemDetailView 工具栏「更新密码」按钮（不进全量编辑，意图聚焦）。
// 流程（docs/34 §4）：
//   - 「从剪贴板粘贴」主按钮（站点改密 → 复制 → 到 Coffer 一下粘贴，NSPasteboard）；
//   - 手动输入框 + PasswordStrengthSection（zxcvbn ≥ 强，同款门禁与文案）；
//   - 显示当前版本时间（「当前版本 2026-09-27」形态）；
//   - 「保存」→ UpdatePassword.makeDraft（仅改密码字段，Concealed 取回明文）
//     → model.updateItem（毫秒级同步，FR-2.9 自动 append 历史）→ 成功提示
//     「已更新 · 旧版本可在历史中回滚」→ 关闭；
//   - 取消 / 关闭不写库。
//
// 密码纪律：明文只在 @State 存活期内持有，关闭即释放；不进日志 / 断言。
// 强度门禁 = 与 PasswordStrengthSection 同款 PasswordStrength.score（zxcvbn
// ≥ 3 = 强，弱密码拒绝并给引导；文案沿用「密码强度需达到强或以上」）。

import SwiftUI
import AppKit

struct UpdatePasswordSheet: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    let details: FfiItemDetails

    /// 新密码明文（sheet 存活期内持有，关闭即释放）。
    @State private var newPassword = ""
    @State private var pasteError: String?
    /// 成功 alert（保存后展示，点「好」关闭 sheet；同 ChangePasswordView 模式）。
    @State private var showSuccess = false

    /// 当前版本时间（「当前版本 2026-09-27」形态；details.updatedAt 为 Unix 秒）。
    private var currentVersionText: String {
        let date = Date(timeIntervalSince1970: TimeInterval(details.updatedAt))
        return "当前版本 " + date.formatted(date: .abbreviated, time: .omitted)
    }

    /// 强度分（与 PasswordStrengthSection 共用 PasswordStrength.score，不漂移）。
    private var currentScore: Int {
        PasswordStrength.score(newPassword, estimate: model.estimateStrength)
    }

    /// 弱密码引导（已输入且 < 强时展示；文案沿用「密码强度需达到强或以上」）。
    private var weaknessHintVisible: Bool {
        !newPassword.isEmpty && !UpdatePassword.isStrongEnough(score: currentScore)
    }

    /// 保存门禁：非空 + 强度 ≥ 强（同时禁用保存按钮）。
    private var canSave: Bool {
        !newPassword.isEmpty && UpdatePassword.isStrongEnough(score: currentScore)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("更新密码").font(.headline)
            Text(currentVersionText)
                .font(.callout)
                .foregroundStyle(.secondary)

            // 剪贴板优先（站点改密后最快路径：粘贴 → 强度 → 保存）
            Button {
                pasteFromClipboard()
            } label: {
                Label("从剪贴板粘贴", systemImage: "doc.on.clipboard")
            }
            .buttonStyle(.bordered)

            Divider()

            SecureField("新密码", text: $newPassword, prompt: Text("粘贴或手动输入新密码"))
                .textFieldStyle(.roundedBorder)

            // zxcvbn 强度条 + 常驻要求说明（复用共享组件）
            PasswordStrengthSection(password: $newPassword)

            if weaknessHintVisible {
                Text("密码强度需达到强或以上。")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if let pasteError {
                Text(pasteError)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            HStack {
                Spacer()
                Button("取消", role: .cancel) {
                    newPassword = ""
                    dismiss()
                }
                Button("保存") { save() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSave)
            }
        }
        .padding(24)
        .frame(width: 420)
        .ffiErrorAlert($model.lastErrorMessage)
        .alert("已更新", isPresented: $showSuccess) {
            Button("好", role: .cancel) {
                newPassword = ""
                dismiss()
            }
        } message: {
            Text("旧版本可在历史中回滚。")
        }
    }

    // MARK: - 剪贴板

    private func pasteFromClipboard() {
        guard let text = NSPasteboard.general.string(forType: .string),
              !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            pasteError = "剪贴板中没有可用的文本。"
            return
        }
        // 站点复制常带尾部换行，trim 掉首尾空白防误存
        newPassword = text.trimmingCharacters(in: .whitespacesAndNewlines)
        pasteError = nil
    }

    // MARK: - 保存

    private func save() {
        // 门禁已由 canSave（保存按钮禁用）把关，此处防御性兜底。
        guard canSave else {
            model.lastErrorMessage = "密码强度需达到强或以上。"
            return
        }
        do {
            let draft = try UpdatePassword.makeDraft(
                details: details,
                newPassword: newPassword,
                concealedValue: { fieldId in
                    try model.fieldValue(itemId: details.uuid, fieldId: fieldId)
                })
            // updateItem 为毫秒级同步调用（ItemStore 纪律），不触发误触。
            try model.updateItem(itemId: details.uuid, draft: draft)
            // 明文随 sheet 关闭释放
            newPassword = ""
            showSuccess = true
        } catch {
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            model.lastErrorMessage = errText
        }
    }
}
