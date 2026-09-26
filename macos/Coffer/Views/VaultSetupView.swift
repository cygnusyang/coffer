// VaultSetupView.swift —— 建库界面（无库时）。
//
// 流程：库名称 + 主密码（双输入）→ 强度条（Rust 工厂版 zxcvbn，无会话
// 依赖，建库前可用）→ 创建（Rust 侧 zxcvbn 门禁 score < 3 拒绝，错误码 1010）。
//
// 建库可选启用 Touch ID（docs/08 §4.1 / §9 T04）：建库成功后置位
// AppModel.pendingBioOffer（仅 Touch ID 设备），首次解锁完成后由 RootView
// 弹出 VaultBioEnableOfferView 供用户可选启用——
//   - enable 需解锁态（Rust 1001 门禁），故引导 sheet 挂在首次解锁后而非
//     建库成功即刻；
//   - D-6：密码不能预填（密码不落任何属性），UI 明确说明需重输一次；
//   - 跳过则不影响 v0.1 流程（无 Touch ID 设备该步骤根本不出现）。

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

// MARK: - 建库成功后的可选「启用 Touch ID」步骤（docs/08 §4.1 / §9 T04）

/// 建库成功并首次解锁后由 RootView 弹出的可选启用引导。
///
/// - 用户可选择跳过（「以后再说」）：清除 pendingBioOffer，进入主界面，
///   之后随时可在「安全设置」中开启——v0.1 流程零变化（T04 验收①）。
/// - 启用走 AppModel.enableTouchID（与设置页同一编排：先 Keychain 后
///   header，D-9；失败补偿删除 Keychain 项）。
/// - 反馈三分支（T04 验收③）：取消/跳过无副作用；密码错 1002 与
///   Keychain 失败经 ErrorPresenter 弹窗，引导页保留可重试。
struct VaultBioEnableOfferView: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    /// 主密码临时输入（D-6：不能预填——密码不落任何属性，无法回传给 UI）。
    @State private var password = ""
    /// enable 慢调用（Argon2id 约 1s）进行中标记。
    @State private var isEnabling = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "touchid")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("启用 Touch ID 解锁？")
                .font(.title3.bold())
            Text("以后锁定密码库时，可用 Touch ID 快速解锁。\n出于安全考虑，主密码不会被保存，需要重新输入一次。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            SecureField("主密码", text: $password, prompt: Text("请输入主密码"))
                .textFieldStyle(.roundedBorder)
                .frame(width: 260)
                .onSubmit(enable)

            if isEnabling {
                ProgressView {
                    Text("正在启用…（密钥派生约需 1 秒）")
                }
            }

            HStack(spacing: 12) {
                Button("以后再说（可在安全设置中开启）") { skip() }
                Button("启用 Touch ID") { enable() }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || isEnabling)
            }
        }
        .padding(28)
        .frame(width: 420)
        .ffiErrorAlert($model.lastErrorMessage)
    }

    /// 跳过：清除标记并关闭引导，不产生任何持久状态变更。
    private func skip() {
        password = ""
        model.pendingBioOffer = false
        dismiss()
    }

    private func enable() {
        guard !password.isEmpty, !isEnabling else { return }
        // 密码不落状态：拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）
        let secret = password
        password = ""
        isEnabling = true
        Task {
            let ok = await model.enableTouchID(password: secret)
            isEnabling = false
            if ok {
                model.pendingBioOffer = false
                dismiss()
            }
            // 失败：引导页保留可重试，错误文案经 lastErrorMessage 呈现
        }
    }
}
