// RecoveryCodeSetupSheet.swift —— 恢复码设置区 + 生成/重生成 sheet（FR-17.2，
// docs/31 §4.3 Settings 生成面 / §2.4 生成语义）。
//
// 结构（结构模型 = VaultBioEnableOfferView，macos/Coffer/Views/VaultSetupView.swift）：
//   - RecoveryCodeSettingsSection：设置页「安全」节内的恢复码两态区——
//     未配置：「未启用」+「生成恢复码…」；
//     已配置：「已启用（恢复码仅在生成时显示一次）」+「重新生成…」（前置
//     确认对话框「旧恢复码将立即失效，确定重新生成？」）。
//   - RecoveryCodeSetupSheet：生成/重生成共用五步流程——
//     ① 说明屏 → ② 生成并一次性展示（大号字体 + 复制按钮，剪贴板固定 30s
//     自动清空）→ ②' 抄写确认（verify：随机 3 词、恢复码隐藏、进步清剪贴板，
//     SEC-04 取消单按钮直过）→ ③ 主密码确认（D-6：先验证身份再写 header）→
//     ④ enableRecoveryCode 成功关闭。
//
// 恢复码明文纪律（FR-17.2）：
//   - code 仅存本视图局部 @State，流程结束（成功/取消/关闭）即置空；不落
//     @Published、不写日志、不落盘（磁盘仅 header 的 wrap 密文）。
//   - 剪贴板固定 30s 自动清空（经 ClipboardManager.copyWithAutoClear(_:clearSecs:)，
//     P5-A 单点：不受用户档位影响——「从不」档位不得让恢复码永久留在剪贴板），
//     changeCount 守卫沿用 ClipboardManager 纪律：用户期间复制别的内容则绝不误清；
//     进 verify 步经 clearWrittenIfUnchanged 清板（REV2-05，粘贴回填被封死）。
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
    /// 返回 LocalizedStringKey：调用方是 Text(...)，而 Text(String) 不查表（F6）。
    private var statusCaption: LocalizedStringKey {
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

/// 恢复码生成 / 重生成五步流程 sheet（FR-17.2，docs/31 §4.3 / §2.4）。
///
/// A1 向导内密码归一（v2.10.0，docs/15 §2.2，偏差 D-A1）：首启引导向导 Step1
/// 已确认的主密码经 `authorizationPassword` 传入作为**一次性授权**（非预填文本、
/// 非静默自动提交）——confirm 步默认「继续」（使用刚输入的主密码）+「改为手动
/// 输入主密码」旁路（显式授权，非替用户做主）。nil = 现状路径（设置页进入，
/// 独立 SecureField，逐字文案不变）。
struct RecoveryCodeSetupSheet: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    /// A1：向导授权密码（一次性；nil = 手动输入路径）。跨步暂存由向导持有，
    /// 本视图在 confirm 提交时拷贝进调用链后清空（D-A1「提交即清」，成败均清）。
    let authorizationPassword: String?
    /// A1：授权密码被消费（confirm 提交或走旁路）后回调向导清空其跨步暂存。
    let onAuthorizationConsumed: (() -> Void)?

    init(authorizationPassword: String? = nil, onAuthorizationConsumed: (() -> Void)? = nil) {
        self.authorizationPassword = authorizationPassword
        self.onAuthorizationConsumed = onAuthorizationConsumed
    }

    /// 流程步骤（docs/31 §2.4：生成 → 展示 → 抄写确认 → 确认 → 启用）。
    private enum Step {
        case intro      // ① 说明屏
        case showCode   // ② 生成并一次性展示
        case verify     // ②' 抄写确认（随机 3 词，恢复码隐藏，SEC-04）
        case confirm    // ③ 主密码确认
    }

    /// 剪贴板固定自动清空时长（FR-17.2 一次性纪律，不受用户档位影响——恢复码
    /// 仅显示一次，「从不」档位不得让其永久留在剪贴板）。
    private static let clipboardClearSecs: TimeInterval = 30
    /// 复制反馈「已复制」提示的展示时长。
    private static let copiedFeedbackSecs: TimeInterval = 2

    @State private var step: Step = .intro
    /// 一次性生成的恢复码（仅本视图局部；流程结束置空，FR-17.2 明文不落盘）。
    @State private var code = ""
    /// 主密码临时输入（docs/07 §2.4）：提交即清空，不落 @State 之外。
    @State private var password = ""
    /// A1：用户点了「改为手动输入主密码」旁路（旁路即清向导暂存，回手动形态）。
    @State private var manualInput = false

    /// A1：是否处于授权形态（confirm 步默认「继续」而非空 SecureField）。
    private var hasAuthorization: Bool {
        authorizationPassword != nil && !manualInput
    }
    /// enable 慢调用（Argon2id 约 1s）进行中标记。
    @State private var isEnabling = false
    /// 复制反馈（「已复制（30 秒后自动清除）」短暂提示）。
    @State private var showCopied = false
    /// 复制反馈提示的复位任务（随视图消失即弃）。
    @State private var copiedResetTask: Task<Void, Never>?

    /// 验证步随机抽的 3 个词位（1-based，升序；本实例内固定，仅「重新生成」后重抽）。
    @State private var verifyPositions: [Int] = []
    /// 验证步三个输入框的词（与 verifyPositions 对齐；提交比较时归一化）。
    @State private var verifyInputs: [String] = []
    /// 验证失败就地提示标记（「与恢复码不符」橙色行）。
    @State private var showVerifyMismatch = false
    /// 「重新生成」的就地确认行展开标记（REV2-06：先确认才生成新码）。
    @State private var showRegenerateConfirmLine = false

    var body: some View {
        Group {
            switch step {
            case .intro:
                introStep
            case .showCode:
                showCodeStep
            case .verify:
                verifyStep
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
            Text(model.hasRecoveryWrap
                 ? LocalizedStringKey("重新生成恢复码")
                 : LocalizedStringKey("设置恢复码"))
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
                model.lastErrorMessage = String(localized: "生成恢复码失败，请重试。")
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
                        ? LocalizedStringKey("已复制（\(Int(Self.clipboardClearSecs)) 秒后自动清除）")
                        : LocalizedStringKey("复制"),
                    systemImage: "doc.on.doc"
                )
            }

            HStack(spacing: 12) {
                Button("取消") { cancelFlow() }
                // SEC-04：不再直过——必须先通过三词抄写验证（P6 verify 步）
                Button("我已抄写保存") { enterVerify() }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    /// 复制恢复码并固定 30s 自动清空（FR-17.2）。统一走
    /// `ClipboardManager.copyWithAutoClear(_:clearSecs:)`（P5-A 单点化，
    /// DESIGN.md D-3.1）：本次复制以固定 30s 覆盖用户档位（「从不」档位不得
    /// 让恢复码永久留在剪贴板，违反一次性纪律）；changeCount 守卫 + 锁定兜底
    /// （clearOnLock 立即清）由 ClipboardManager 单点承担，本视图不再手写
    /// 第二套清除实现。
    private func copyCode() {
        guard !code.isEmpty else { return }
        ClipboardManager.shared.copyWithAutoClear(code, clearSecs: Self.clipboardClearSecs)

        // 复制反馈提示（短暂展示后复位）
        showCopied = true
        copiedResetTask?.cancel()
        copiedResetTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(Self.copiedFeedbackSecs * 1_000_000_000))
            guard !Task.isCancelled else { return }
            showCopied = false
        }
    }

    // MARK: - ②' 抄写确认（SEC-04 / P6）

    /// 验证步：恢复码隐藏、随机 3 词对照已保存副本输入。普通非掩码 TextField
    /// （REV2-04：恢复码是用户已保存副本的对照抄写，非新输入秘密；掩码只增加
    /// 摩擦且无肩窥收益——本步不显示参考码）。摩擦门非安全门：**无次数上限 /
    /// 无失败锁定**；旁路 = 「重新生成」（就位确认行）或「取消」整体放弃。
    private var verifyStep: some View {
        VStack(spacing: 16) {
            Image(systemName: "key")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("确认抄写恢复码")
                .font(.title3.bold())
            Text("请在下方输入恢复码第 \(verifyPositions.map(String.init).joined(separator: "、")) 个词（恢复码已隐藏，请对照你保存的副本）")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            VStack(spacing: 10) {
                ForEach(0..<verifyPositions.count, id: \.self) { index in
                    HStack {
                        Text("第 \(verifyPositions[index]) 个词")
                            .font(.callout)
                            .frame(width: 96, alignment: .trailing)
                        TextField("", text: $verifyInputs[index], prompt: Text("请输入该词"))
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 200)
                    }
                }
            }

            if showVerifyMismatch {
                Text("与恢复码不符，请对照抄写内容再试。")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            if showRegenerateConfirmLine {
                // 就地确认行（REV2-06）：新码一旦生成，当前显示的旧码不可再看
                VStack(spacing: 10) {
                    Text("将重新生成新恢复码，当前显示的恢复码将无法再次查看")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.center)
                    HStack(spacing: 12) {
                        Button("取消") { showRegenerateConfirmLine = false }
                        Button("重新生成") { confirmRegenerate() }
                            .buttonStyle(.borderedProminent)
                    }
                }
            } else {
                HStack(spacing: 12) {
                    Button("取消") { cancelFlow() }
                    Button("重新生成") { showRegenerateConfirmLine = true }
                    Button("确认抄写") { submitVerify() }
                        .buttonStyle(.borderedProminent)
                        .disabled(!canSubmitVerify)
                }
            }
        }
    }

    /// 进入验证步（showCode「我已抄写保存」）：立即清除恢复码剪贴板项
    /// （REV2-05：复用 P5-A 统一清除 + changeCount 守卫——粘贴回填被显式封死，
    /// 剪贴板成为死数据）；随机抽 3 个词位（本实例内固定，仅「重新生成」后重抽）。
    private func enterVerify() {
        ClipboardManager.shared.clearWrittenIfUnchanged()
        if verifyPositions.isEmpty {
            verifyPositions = RecoveryVerifySupport.randomVerifyPositions(wordCount: RecoveryVerifySupport.recoveryWordCount(code))
        }
        verifyInputs = Array(repeating: "", count: verifyPositions.count)
        showVerifyMismatch = false
        showRegenerateConfirmLine = false
        step = .verify
    }

    /// 「确认抄写」可用性：三个输入框均非空（空任一禁用）。
    private var canSubmitVerify: Bool {
        RecoveryVerifySupport.canSubmitVerify(verifyInputs)
    }

    /// 提交验证：三词逐位比对（归一化：小写 / 折叠连续空格 / trim，大小写不敏感）。
    /// 不符 → 就地橙色提示 + 清空输入 + 保留本步（词位不变，无次数上限——摩擦门
    /// 非安全门）；全对 → 进 ③ 主密码确认步（D-6，原样保留）。
    private func submitVerify() {
        guard canSubmitVerify else { return }
        let words = code.split(whereSeparator: \.isWhitespace).map(String.init)
        for (index, position) in verifyPositions.enumerated() {
            guard position >= 1, position <= words.count,
                  RecoveryVerifySupport.normalizeRecoveryWord(words[position - 1])
                      == RecoveryVerifySupport.normalizeRecoveryWord(verifyInputs[index]) else {
                showVerifyMismatch = true
                verifyInputs = Array(repeating: "", count: verifyInputs.count)
                return
            }
        }
        showVerifyMismatch = false
        verifyInputs = Array(repeating: "", count: verifyInputs.count)
        step = .confirm
    }

    /// 「重新生成」就地确认（REV2-06）：生成新码 → 回 showCode 展示新码 → 下次
    /// 进 verify 词位重抽。旧码立即作废（恢复码一次性纪律），不可再看。
    private func confirmRegenerate() {
        guard !isEnabling else { return }
        showRegenerateConfirmLine = false
        resetVerifyState()
        startGenerate()
    }

    /// 复位验证步状态（「重新生成」确认后调用）：清词位 → 下次进 verify 重抽。
    private func resetVerifyState() {
        verifyPositions = []
        verifyInputs = []
        showVerifyMismatch = false
        showRegenerateConfirmLine = false
    }

    // 纯函数面（recoveryWordCount / normalizeRecoveryWord / canSubmitVerify /
    // randomVerifyPositions）已外置 RecoveryVerifySupport.swift（v2.9.0 基层
    // 测试化搬移，行为逐字不变）；本视图仅持有状态与调用。

    // MARK: - ③ 主密码确认（D-6：先验证身份再写 header）

    private var confirmStep: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("确认主密码")
                .font(.title3.bold())
            // A1（docs/15 §2.2，偏差 D-A1）：向导授权形态文案（复用刚输入的主密码，
            // 非预填、非静默自动提交——显式授权）；手动路径保留现状文案。
            Text(hasAuthorization
                 ? LocalizedStringKey("将使用你刚输入的主密码完成此设置，恢复码才会启用。")
                 : LocalizedStringKey("出于安全考虑，主密码不会被保存，请重新输入一次以确认身份，之后恢复码才会启用。"))
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if hasAuthorization {
                // A1 授权形态：无输入框，默认「继续」+「改为手动输入主密码」旁路。
                // 旁路即清向导暂存（防残留）+ 回手动形态（docs/15 §2.2/§2.4）。
                HStack(spacing: 12) {
                    Button("改为手动输入主密码") { switchToManualInput() }
                    Button("继续") { confirmEnable() }
                        .buttonStyle(.borderedProminent)
                        .disabled(isEnabling || model.isBusy)
                }
            } else {
                SecureField("主密码", text: $password, prompt: Text("请输入主密码"))
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 260)
                    .onSubmit(confirmEnable)

                HStack(spacing: 12) {
                    Button("取消") { cancelFlow() }
                    Button("启用恢复码") { confirmEnable() }
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty || isEnabling || model.isBusy)
                }
            }

            if isEnabling {
                ProgressView {
                    Text("正在启用…（密钥派生约需 1 秒）")
                }
            }
        }
    }

    /// A1 旁路：改用手动输入主密码——立即清向导暂存（防残留），回手动形态。
    private func switchToManualInput() {
        onAuthorizationConsumed?()
        manualInput = true
    }

    // MARK: - ④ 启用

    /// 提交：主密码不落状态，拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）。
    /// 契约签名无返回（成功 = 未新增错误）；失败（1002）经 lastErrorMessage →
    /// ffiErrorAlert 呈现，本 sheet 保留可重试（需重新输入主密码）。
    ///
    /// A1（docs/15 §2.2，偏差 D-A1）：授权形态下 `secret = authorizationPassword`
    /// （向导已确认的主密码，一次性授权）；确认提交（`enableRecoveryCode` 触发）
    /// 后立即清向导暂存（onAuthorizationConsumed），**无论成败**——Step2 含恢复码
    /// 展示/抄写/验证为分钟级流程，驻留必须收敛到「提交即清」而非「流程结束才清」。
    private func confirmEnable() {
        guard !isEnabling, !model.isBusy else { return }
        guard hasAuthorization || !password.isEmpty else { return }
        let secret = hasAuthorization ? (authorizationPassword ?? "") : password
        password = ""
        // A1：提交即清向导暂存（成败均清，不等 onDisappear）；旁路后 hasAuthorization
        // 为 false，不重复触发。
        if hasAuthorization {
            onAuthorizationConsumed?()
        }
        isEnabling = true
        let codeToEnable = code
        Task {
            let errBefore = model.lastErrorMessage
            await model.enableRecoveryCode(password: secret, code: codeToEnable)
            isEnabling = false
            if model.lastErrorMessage == errBefore {
                // 成功：恢复码已生效（旧 wrap 已被覆盖），关闭 sheet
                finishFlow()
            } else if hasAuthorization {
                // A1 失败语义（docs/15 §2.5 判据 8）：授权密码同串理论失败（数据
                // 损坏路径）→ 回「改为手动输入主密码」旁路重试（暂存已清，旁路
                // 后为手动形态）。
                manualInput = true
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

    /// 清空一次性明文 / 主密码 / 验证步词输入（部分恢复码词也算敏感残留）/
    /// 反馈任务。剪贴板 30s 清除任务**不**在此取消（须到点执行），故不归入
    /// 本方法。
    private func cleanup() {
        code = ""
        password = ""
        verifyPositions = []
        verifyInputs = []
        showVerifyMismatch = false
        showRegenerateConfirmLine = false
        showCopied = false
        copiedResetTask?.cancel()
        copiedResetTask = nil
    }
}
