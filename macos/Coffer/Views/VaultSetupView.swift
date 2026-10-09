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

    /// 是否首次建库（工作目录内尚无库，docs/15 §3.2.5 MB-1 复用微调）：
    /// 从库切换器进入时（已有库）说明文案改为「新增独立库」口径，
    /// 避免误导用户以为建库会替换当前库。默认 true 保持 noVault 现状路径。
    var isFirstVault: Bool = true

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
                Text(isFirstVault ? "创建密码库" : "新建密码库").font(.title2.bold())
                Text(isFirstVault
                     ? "库文件保存在本机，主密码是唯一解锁凭据，遗失后无法找回。"
                     : "将在本机新增一座独立密码库，与现有库互不相通；主密码是该库唯一解锁凭据，遗失后无法找回。")
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

// MARK: - 首次解锁后的可选「生成恢复码」步骤（v2.5.0 FR-17.2，决策 D-8 stretch）

/// 建库成功并首次解锁后由 RootView 弹出的可选「生成恢复码」引导（镜像
/// VaultBioEnableOfferView「稍后设置」模式，docs/31 §4.3 决策 D-8）。
///
/// - 用户可选择跳过（「以后再说」）：清除 pendingRecoveryOffer，进入主界面，
///   之后随时可在「安全设置」中开启（RecoveryCodeSettingsSection）——
///   v2.5.0 首次解锁流程零变化。
/// - 「生成恢复码」进入 RecoveryCodeSetupSheet 生成流程（说明 → 一次性展示
///   + 复制 → 主密码确认 → enable_recovery_code，docs/31 §4.3 步骤 1-4）。
///   生成流程关闭后若 hasRecoveryWrap 已置位（生成成功），引导一并收口。
///
/// 呈现时机（pendingRecoveryOffer）由 RootView 侧接线，镜像 pendingBioOffer
/// （docs/31 集成轮：M-UI-STATE 提供 AppModel 标记 + RootView sheet 挂载，
/// 解锁态才呈现、interactiveDismissDisabled）。
struct RecoveryCodeOfferSheet: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    /// 是否已进入生成流程（sheet 叠 sheet；关闭生成流程回到本引导，除非
    /// hasRecoveryWrap 已置位——见 onDismiss 收口逻辑）。
    @State private var showSetup = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "key.horizontal.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("生成恢复码？")
                .font(.title3.bold())
            Text("忘记主密码时，可用恢复码重置密码库、找回条目数据。\n恢复码仅显示一次，请抄写并妥善保存。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            HStack(spacing: 12) {
                Button("以后再说（可在安全设置中开启）") { skip() }
                Button("生成恢复码") { showSetup = true }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(28)
        .frame(width: 420)
        .ffiErrorAlert($model.lastErrorMessage)
        .sheet(isPresented: $showSetup, onDismiss: {
            // 生成流程关闭后若恢复码已启用（生成成功路径），引导一并收口；
            // 取消/放弃路径 hasRecoveryWrap 未变，引导保留可重试。
            if model.hasRecoveryWrap {
                model.pendingRecoveryOffer = false
                dismiss()
            }
        }) {
            // 初始器与 M-UI-GEN 的 RecoveryCodeSetupSheet 对齐（@EnvironmentObject，
            // 无参 + 环境对象注入，见文件内占位说明）。
            RecoveryCodeSetupSheet()
                .environmentObject(model)
        }
    }

    /// 跳过：清除标记并关闭引导，不产生任何持久状态变更。
    private func skip() {
        model.pendingRecoveryOffer = false
        dismiss()
    }
}

/// 恢复码生成流程 sheet（docs/31 §4.3 步骤 1-4）：
///   1. 说明屏：「恢复码用于忘记主密码时重置。请抄写并妥善保存。恢复码仅显示一次。」
///   2. 生成并一次性展示（大号字体 + 复制，走 ClipboardManager 自动清除）+「我已抄写保存」
///   3. 主密码确认（D-6：先验证身份再写 header）
///   4. enable_recovery_code → 成功 → 关闭
///
/// - 生成（generateRecoveryCode）无落盘（docs/31 §2.4 安全顺序）：本流程只
///   在确认主密码后才触发 enable（写 recovery_wrap 槽位）；放弃时旧 wrap 不受影响。
/// - 明文纪律（D-10）：code 仅随本 sheet 的 @State 在内存存活，sheet 关闭即随
///   视图销毁——磁盘仅 header wrap 密文；密码沿用库内纪律，拷贝进异步调用后
///   立刻清空本地输入。
///
/// ⚠️ 本地占位（v2.5.0 集成轮统一）：M-UI-GEN 并行创建
/// RecoveryCodeSetupSheet.swift，签名已对齐（@EnvironmentObject + 无参初始器，
/// 与 offer 内 `RecoveryCodeSetupSheet().environmentObject(model)` 调用一致）。
/// M-UI-GEN 版本落地后删除本占位（同名重复定义，集成轮二选一保留）。
struct RecoveryCodeSetupSheet: View {
    /// 生成流程步骤状态机：code 仅随本 sheet 内存存活（D-10）。
    enum Step {
        case intro
        case generated(String)
        case confirm(String)
    }

    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    @State private var step: Step = .intro
    /// 主密码临时输入（D-6：不能预填；拷贝进异步调用后立刻清空）。
    @State private var password = ""
    /// enable 慢调用（Argon2id 约 1s）进行中标记。
    @State private var isEnabling = false
    @State private var copiedFeedback = false

    var body: some View {
        Group {
            switch step {
            case .intro: introView
            case .generated(let code): generatedView(code)
            case .confirm(let code): confirmView(code)
            }
        }
        .padding(28)
        .frame(width: 440)
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - 步骤 1：说明屏

    private var introView: some View {
        VStack(spacing: 16) {
            Image(systemName: "key.horizontal.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("生成恢复码")
                .font(.title3.bold())
            Text("恢复码用于忘记主密码时重置密码库、找回条目数据。\n请抄写并妥善保存——恢复码仅显示一次，本机不会保存。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            HStack(spacing: 12) {
                Button("取消") { dismiss() }
                Button("生成恢复码") { generate() }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    /// 生成恢复码（Rust CSPRNG，128-bit 熵；无落盘，放弃不影响旧 wrap）。
    private func generate() {
        guard let code = model.generateRecoveryCode() else { return }
        step = .generated(code)
    }

    // MARK: - 步骤 2：一次性展示 + 复制

    private func generatedView(_ code: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "doc.on.clipboard.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("恢复码（仅显示一次）")
                .font(.title3.bold())
            Text(code)
                .font(.system(.title2, design: .monospaced).weight(.semibold))
                .textSelection(.enabled)
                .multilineTextAlignment(.center)
                .padding(14)
                .frame(maxWidth: .infinity)
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(Color.secondary.opacity(0.1)))
            Text("请抄写并妥善保存。关闭本窗口后，恢复码将无法再次查看。")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button {
                    // 敏感值走自动清除（ClipboardManager.copyWithAutoClear）——
                    // 尊重 FR-14.2 档位与 changeCount 守卫（同 FieldRowView/大字号
                    // 复制纪律）。恢复码复制后即进入剪贴板清除定时（docs/31 §4.3
                    // 「剪贴板 30s 自动清空」，以 AppModel.clipboardClearSecs 档位为准）。
                    ClipboardManager.shared.copyWithAutoClear(code)
                    copiedFeedback = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        copiedFeedback = false
                    }
                } label: {
                    Label(copiedFeedback ? "已复制" : "复制",
                          systemImage: copiedFeedback ? "checkmark" : "doc.on.doc")
                }
                Button("我已抄写保存") { step = .confirm(code) }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    // MARK: - 步骤 3：主密码确认（D-6：先验证身份再写 header）

    private func confirmView(_ code: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("确认主密码")
                .font(.title3.bold())
            Text("启用前需验证主密码身份。出于安全考虑，主密码不会被保存，需要重新输入一次。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            SecureField("主密码", text: $password, prompt: Text("请输入主密码"))
                .textFieldStyle(.roundedBorder)
                .frame(width: 260)
                .onSubmit { enable(code: code) }

            if isEnabling {
                ProgressView { Text("正在启用…（密钥派生约需 1 秒）") }
            }

            HStack(spacing: 12) {
                Button("返回") { step = .generated(code) }
                Button("启用恢复码") { enable(code: code) }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || isEnabling)
            }
        }
    }

    /// 确认主密码并写入 recovery_wrap（enable_recovery_code，写 header）。
    /// 失败（密码错 1002 等）经 ErrorPresenter 呈现，本 sheet 保留可重试。
    private func enable(code: String) {
        guard !password.isEmpty, !isEnabling else { return }
        // 密码不落状态：拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）
        let secret = password
        password = ""
        isEnabling = true
        Task {
            let ok = await model.enableRecoveryCode(password: secret, code: code)
            isEnabling = false
            if ok { dismiss() }
            // 失败：本 sheet 保留可重试，错误文案经 lastErrorMessage 呈现
        }
    }
}
