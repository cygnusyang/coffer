// AboutUpdateSection.swift —— 「关于 Coffer」最小关于对话框（v2.7.0，docs/35 §2.6）。
//
// 项目此前无「关于」对话框；按 §2.6 入口裁定自建最小关于区（App 名 + 版本 +
// 「检查更新…」按钮），承载 OTA 主入口（另一入口 = 应用菜单同项；设置页明确
// 不放任何更新入口，用户裁定）。视觉对齐系统关于面板（居中式）+ 既有
// LabeledContent/设置页的字体与次级色纪律。
//
// 挂载：CofferApp.swift 的 RootView().sheet(isPresented: $model.showAbout)，由
// 应用菜单「关于 Coffer…」触发。

import SwiftUI

struct AboutUpdateView: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                // App 图标占位：无独立 icon asset，用 SF Symbol 对齐系统关于面板
                Image(systemName: "lock.shield")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)
                    .padding(.top, 8)
                VStack(spacing: 4) {
                    Text(UpdateCopy.appName)
                        .font(.title2.bold())
                    Text("版本 \(UpdateCopy.appVersionText)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                // OTA 主入口（§2.6 裁定）：版本区常驻「检查更新…」按钮
                Button("检查更新…") { model.checkForUpdates() }
                    .buttonStyle(.borderedProminent)
                    .padding(.top, 8)
            }
            .frame(width: 360, height: 220)
            .navigationTitle("关于 Coffer")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }
}
