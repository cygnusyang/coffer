// VaultSetupView.swift —— 建库界面（无库时）。
//
// 流程：库名称 + 主密码（双输入）→ 强度条（Rust 工厂版 zxcvbn，无会话
// 依赖，建库前可用）→ 创建（Rust 侧 zxcvbn 门禁 score < 3 拒绝，错误码 1010）。

import SwiftUI

struct VaultSetupView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var name = "我的密码库"
    @State private var password = ""
    @State private var confirm = ""
    @State private var localError: String?
    @State private var isCreating = false

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 8) {
                Image(systemName: "shippingbox.circle.fill")
                    .font(.system(size: 52))
                    .foregroundStyle(.tint)
                Text("创建密码库").font(.title2.bold())
                Text("库文件保存在本机，主密码是唯一解锁凭据，遗失后无法找回。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            Form {
                TextField("库名称", text: $name)

                SecureField("主密码", text: $password)
                strengthSection
                SecureField("再次输入主密码", text: $confirm)
            }
            .formStyle(.grouped)
            .frame(maxWidth: 460)

            Button {
                create()
            } label: {
                if isCreating {
                    ProgressView().controlSize(.small).frame(width: 60)
                } else {
                    Text("创建密码库").frame(minWidth: 80)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!canSubmit)

            Text("密码强度校验在创建时执行：评分不足（zxcvbn < 3）将被拒绝。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .ffiErrorAlert($model.lastErrorMessage)
        .alert("无法创建", isPresented: Binding(
            get: { localError != nil },
            set: { if !$0 { localError = nil } }
        )) {
            Button("好", role: .cancel) {}
        } message: {
            Text(localError ?? "")
        }
    }

    // MARK: - 强度条

    @ViewBuilder
    private var strengthSection: some View {
        if !password.isEmpty {
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
                if let estimate = model.estimateStrength(password), !estimate.warnings.isEmpty {
                    Text(estimate.warnings.joined(separator: "；"))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    /// Rust 工厂版 zxcvbn（无会话依赖；门禁同源，见 PasswordStrength 仅
    /// 作为估算失败的兜底）。
    private var currentScore: Int {
        if let estimate = model.estimateStrength(password) {
            return Int(estimate.score)
        }
        return PasswordStrength.localScore(password)
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
        !isCreating && !name.trimmingCharacters(in: .whitespaces).isEmpty
            && !password.isEmpty && !confirm.isEmpty
    }

    private func create() {
        guard password == confirm else {
            localError = "两次输入的主密码不一致。"
            return
        }
        // 主密码不落状态：拷贝进异步调用后立刻清空本地输入。
        let vaultName = name.trimmingCharacters(in: .whitespaces)
        let secret = password
        password = ""
        confirm = ""
        isCreating = true
        Task {
            await model.createVault(name: vaultName, password: secret)
            isCreating = false
        }
    }
}
