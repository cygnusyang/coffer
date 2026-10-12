// RootView.swift —— 根视图：按 AppPhase 切换界面。
//
// 首启引导（v2.9.0 P2-A，docs/14 §A P2 §2）：建库后首次解锁把原先两个独立
// sheet（Touch ID 引导 + 恢复码引导，FW-01 双打断）合并为**单个** OnboardingWizard
// 向导容器。触发 = AppModel.showOnboarding（解锁态 ∧ 任一引导旗标置位），
// 最多两步按置位裁剪、每步可跳过；两旗标均清 → 绑定 get 返回 false → 自动收口。
// interactiveDismissDisabled 保留（结构型引导）。

import SwiftUI

struct RootView: View {
    @EnvironmentObject
    private var model: AppModel

    var body: some View {
        content
            .onAppear { model.bootstrap() }
            // 首启引导向导（P2-A）：单个 sheet 容器替代原先两个独立 sheet。
            // 步骤完成（启用/跳过）清各自旗标，全部清空即收口（get 派生）。
            // set 分支为强制关闭兜底（interactiveDismissDisabled 下仅程序路径）。
            .sheet(isPresented: Binding(
                get: { model.showOnboarding },
                set: { if !$0 { model.pendingBioOffer = false; model.pendingRecoveryOffer = false } }
            )) {
                OnboardingWizard()
                    .environmentObject(model)
                    .interactiveDismissDisabled()
            }
            // 库切换器 sheet（v0.4 FR-1.2，MB-1）：MainView 工具栏触发，
            // 挂 RootView——锁定/建库等相变发生时随视图整体切换。
            .sheet(isPresented: $model.showVaultSwitcher) {
                VaultSwitcherView()
                    .environmentObject(model)
            }
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .booting:
            ProgressView {
                Text("正在打开…")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

        case .noVault:
            VaultSetupView()

        case .locked:
            LockView()

        case .unlocked:
            MainView()

        case .fatal(let message):
            VStack(spacing: 16) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 44))
                    .foregroundStyle(.orange)
                Text("无法打开应用").font(.title2.bold())
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 480)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
    }
}
