// OnboardingWizard.swift —— 首启引导合并向导（v2.9.0 P2-A，docs/14 §A P2 §2）。
//
// FW-01（docs/13 §2.2）：原先建库后首次解锁**连续弹两个独立 sheet**（Touch ID
// 引导 + 恢复码引导，同会话双打断），v2.9.0 合并为**单个 sheet 向导**——最多
// 两步按置位裁剪、每步可跳过（硬约束「勿砍可跳过」），两旗标均清即自动收口。
//
// 步骤内容沿用 VaultBioEnableOfferView（Step1）/ RecoveryCodeOfferSheet
// （Step2，VaultSetupView.swift）的现有结构：图标 + 说明 + 主密码确认行
// （D-6）+ 启用/跳过、恢复码嵌套 RecoveryCodeSetupSheet 流程。**内部逻辑不改**
// （enable 编排 / 三分支反馈 / 逐字跳过文案），唯完成路径由「dismiss 关闭自身
// sheet」改为「清对应引导旗标」——dismiss 在向导容器内被拦截为步进/收口：
//   - 两旗标均清 → RootView 的 sheet 绑定 get 返回 false → 向导自动关闭；
//   - 仅 pendingBioOffer 清 → body 自动切到 Step2（pendingRecoveryOffer 仍置位）。
// 原 VaultBioEnableOfferView / RecoveryCodeOfferSheet 保持原样不动（供参考 /
// 其他调用方），本向导为其容器内镜像。
//
// 状态机（docs/14 §A P2 §2.2）：
//   [bio 置位] ─Step1─ 启用成功/跳过 → 清 pendingBioOffer → 进 Step2（若置位）
//   [recovery 置位] ─Step2─ 生成成功（hasRecoveryWrap）/跳过 → 清 pendingRecoveryOffer → 收口
//
// 步骤指示器：仅两步向导时显示「步骤 x/2」（isTwoStep 在 onAppear 快照——Step2
// 呈现时 pendingBioOffer 已清，无法再据旗标判断）；单步直出不显示（AC-2.9.0-P2A-2）。

import SwiftUI

struct OnboardingWizard: View {
    @EnvironmentObject
    private var model: AppModel

    /// 是否为两步向导（bio + recovery 同置）。onAppear 快照：Step2 呈现时
    /// pendingBioOffer 已清，不能据旗标回溯，须在此记快照决定指示器显隐。
    @State private var isTwoStep = false

    /// Step1 主密码输入 + A1 跨步暂存（docs/15 §2.2，偏差 D-A1）：Step1 启用成功
    /// 后**不再清空**，保留为「本向导会话已确认的主密码」（向导 @State，生命周期 =
    /// 向导展示期），Step2 恢复码 confirm 步作一次性授权（RecoveryCodeSetupSheet
    /// authorizationPassword）。清空时机 = confirm 提交即清 / 跳过 / onDisappear /
    /// lock 相变（全路径兜底防残留，D-A1 grep 门禁）。
    @State private var password = ""
    /// Step1 enable 慢调用（Argon2id 约 1s）进行中标记。
    @State private var isEnabling = false
    /// Step2 是否已进入恢复码生成流程（sheet 叠 sheet；关闭后 hasRecoveryWrap
    /// 置位则收口，见 onDismiss 逻辑）。
    @State private var showSetup = false

    var body: some View {
        Group {
            if model.pendingBioOffer {
                bioStep
            } else if model.pendingRecoveryOffer {
                recoveryStep
            } else {
                // 两旗标均清：RootView sheet 绑定 get 返回 false → 自动收口
                // （不需要显式 dismiss，保持展示期间单 sheet 不闪断）。
                EmptyView()
            }
        }
        .frame(width: 420)
        .ffiErrorAlert($model.lastErrorMessage)
        .onAppear {
            isTwoStep = model.pendingBioOffer && model.pendingRecoveryOffer
        }
        .onDisappear {
            // A1 兜底清空（D-A1）：向导收口（两旗标清 / lock 相变 / 视图拆除）时
            // 暂存密码必清——confirm 提交即清是主路径，此处兜底防任何残留。
            password = ""
        }
    }

    /// 步骤指示器（仅两步向导显示；文案「步骤 x/2 · 节名」）。
    private func stepIndicator(number: Int, title: String) -> some View {
        Text("步骤 \(number)/2 · \(title)")
            .font(.footnote)
            .foregroundStyle(.secondary)
    }

    // MARK: - Step 1 启用 Touch ID 解锁？

    private var bioStep: some View {
        VStack(spacing: 16) {
            if isTwoStep {
                stepIndicator(number: 1, title: "Touch ID")
            }

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
                Button("以后再说（可在安全设置中开启）") { skipBio() }
                Button("启用 Touch ID") { enable() }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || isEnabling)
            }
        }
        .padding(28)
    }

    /// 跳过 Step1（硬约束「勿砍可跳过」）：清引导旗标 + 记「跳过」（设置页
    /// 首次高亮兜底触发，AC-2.9.0-P2A-5/10），不产生任何持久状态变更。
    /// 原 VaultBioEnableOfferView 的 dismiss() 在此拦截为清旗标——pendingBioOffer
    /// 清后若 pendingRecoveryOffer 仍置位，body 自动切到 Step2；否则向导收口。
    private func skipBio() {
        password = ""
        model.pendingBioOffer = false
        model.bioOfferSkipped = true
    }

    /// 启用 Touch ID（与设置页 TouchIDSettingsSection 同一编排：先 Keychain
    /// 后 header，D-9；失败补偿删除 Keychain 项）。成功 → 清引导旗标进 Step2；
    /// bioOfferSkipped 在 AppModel.enableTouchID 成功路径清位（高亮不出现）。
    /// 失败（1002 / Keychain 失败）→ lastErrorMessage 呈现，步骤保留可重试。
    ///
    /// A1（docs/15 §2.2，偏差 D-A1）：成功路径**保留**暂存密码供 Step2 复用
    /// （不再「提交即清」）；失败 → 清暂存回 Step1 手动重输（现状可重试语义）。
    private func enable() {
        guard !password.isEmpty, !isEnabling else { return }
        let secret = password
        isEnabling = true
        Task {
            let ok = await model.enableTouchID(password: secret)
            isEnabling = false
            if ok {
                // A1：暂存密码保留（跨 Step1→Step2 复用）；每次 enable 仍独立
                // recover_dek 校验（1002 纪律不变）
                model.pendingBioOffer = false
            } else {
                // 失败：暂存密码判定不可用，清空回 Step1 手动重输（D-A1 清空路径）
                password = ""
            }
        }
    }

    // MARK: - Step 2 生成恢复码？

    private var recoveryStep: some View {
        VStack(spacing: 16) {
            if isTwoStep {
                stepIndicator(number: 2, title: "恢复码")
            }

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
                Button("以后再说（可在安全设置中开启）") { skipRecovery() }
                Button("生成恢复码") { showSetup = true }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(28)
        .sheet(isPresented: $showSetup, onDismiss: {
            // 生成流程关闭后若恢复码已启用（生成成功路径），引导一并收口；
            // 取消/放弃路径 hasRecoveryWrap 未变，Step2 保留可重试。
            if model.hasRecoveryWrap {
                model.pendingRecoveryOffer = false
            }
        }) {
            // A1（docs/15 §2.2）：Step1 已确认的暂存密码作一次性授权传入——
            // Step2 无授权密码（Step1 跳过）时回退手动形态（nil 入参，行为不变）。
            // onAuthorizationConsumed：confirm 提交即清向导暂存（成败均清）。
            RecoveryCodeSetupSheet(
                authorizationPassword: password.isEmpty ? nil : password,
                onAuthorizationConsumed: { password = "" }
            )
            .environmentObject(model)
        }
    }

    /// 跳过 Step2（硬约束「勿砍可跳过」）：清引导旗标 + 记「跳过」（设置页
    /// 恢复码区首次高亮兜底触发，AC-2.9.0-P2A-5/11），不产生任何持久状态变更。
    private func skipRecovery() {
        // A1：跳过即清暂存密码（D-A1 清空路径，防残留兜底）
        password = ""
        model.pendingRecoveryOffer = false
        model.recoveryOfferSkipped = true
    }
}
