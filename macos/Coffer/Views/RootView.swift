// RootView.swift —— 根视图：按 AppPhase 切换界面。

import SwiftUI

struct RootView: View {
    @EnvironmentObject
    private var model: AppModel

    var body: some View {
        content
            .onAppear { model.bootstrap() }
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
