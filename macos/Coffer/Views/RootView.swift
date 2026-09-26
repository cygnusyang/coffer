// RootView.swift —— 根视图：按 AppPhase 切换界面。
//
// 建库可选启用 Touch ID（docs/08 §4.1 / §9 T04）：解锁态下若
// pendingBioOffer 置位（建库成功 + Touch ID 设备 + 尚未处理），弹出可选
// 启用引导 sheet。跳过或无 Touch ID 设备时不出现——v0.1 流程零变化。

import SwiftUI

struct RootView: View {
    @EnvironmentObject
    private var model: AppModel

    var body: some View {
        content
            .onAppear { model.bootstrap() }
            // 建库成功后的可选「启用 Touch ID」步骤：仅在解锁态呈现
            // （enable 需解锁态，Rust 1001 门禁）。sheet 关闭（跳过/完成）
            // 即清除标记。
            .sheet(isPresented: Binding(
                get: { model.phase == .unlocked && model.pendingBioOffer },
                set: { if !$0 { model.pendingBioOffer = false } }
            )) {
                VaultBioEnableOfferView()
                    .environmentObject(model)
                    .interactiveDismissDisabled()
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
