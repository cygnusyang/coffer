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
                // 了解 Coffer 自述区（issue #3）：一句话定位每个能力，破解「全靠撞见」。
                // 纯静态文案——本机零联网 / 无云端同步是有意设计，不是缺功能。
                Divider()
                    .frame(width: 280)
                VStack(spacing: 6) {
                    Text("了解 Coffer")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("数据只存在本机、永不联网、没有云端同步——这是有意设计，不是缺功能。")
                    Text("想让 AI/自动化安全取用密码？可用 CLI 与 MCP（设置 → MCP / Agent 协作）。")
                    Text("备份：解锁后「导出」生成加密备份，换机/重装可在首屏「从备份恢复」导回。")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                // OTA 主入口（§2.6 裁定）：版本区常驻「检查更新…」按钮
                Button("检查更新…") { model.checkForUpdates() }
                    .buttonStyle(.borderedProminent)
                    .padding(.top, 8)
            }
            .frame(width: 360, height: 350)
            .navigationTitle("关于 Coffer")
            .toolbar {
                // D-4.1（CO-06）：只读查看页关闭语义——「关闭」+ .cancellationAction（Esc 生效）。
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
    }
}
