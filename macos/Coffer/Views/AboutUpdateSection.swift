// AboutUpdateSection.swift —— 「关于 Coffer」最小关于对话框（v2.7.0，docs/35 §2.6）。
//
// 项目此前无「关于」对话框；按 §2.6 入口裁定自建最小关于区（App 名 + 版本 +
// 「检查更新…」按钮），承载 OTA 主入口（设置页明确不放任何更新入口，用户裁定；
// 应用菜单「检查更新…」同项入口于 BUG-24 复测裁定 2026-10-14 移除，只留本页
// 入口）。视觉对齐系统关于面板（居中式）+ 既有
// LabeledContent/设置页的字体与次级色纪律。
//
// v2.9.2-T1（VK 关于页编译时间）：「版本」行下加「编译时间」行，便于测试时
// 区分构建——build 脚本注入产物 Info.plist 键 `CofferBuildTime`（UTC），
// Swift 侧读 Bundle，缺键/空串回退「开发构建」（UpdateCopy.buildTimeText）。
//
// v2.10.0-T5①（UX issue #3 完整版）：「了解 Coffer」自述区从三行最小版扩展为
// 全能力自我介绍——本地存储零同步 / 零网络架构（OTA 更新除外）/ Touch ID·恢复码 /
// 加密备份恢复 / MCP 协作，每条一句话定位入口（破解「全靠撞见」）。纯静态文案，
// 零网络调用、无外链（docs/10 TC-NET，AC-2.10.0-UX-5）；指引路径须与
// SettingsView 真实分节一致（设置→安全 / 设置→数据 / 设置→MCP，AC-2.10.0-UX-4）。
//
// 挂载：CofferApp.swift 的 RootView().sheet(isPresented: $model.showAbout)，由
// 应用菜单「关于 Coffer…」触发。

import SwiftUI

struct AboutUpdateView: View {
    @EnvironmentObject
    private var model: AppModel
    @Environment(\.dismiss)
    private var dismiss

    /// 编译时间展示（v2.9.2-T1）：build 注入产物 Info.plist 键 `CofferBuildTime`，
    /// 缺键/空 → UpdateCopy.buildTimeText 回退「开发构建」。
    private var buildTimeText: String {
        UpdateCopy.buildTimeText(
            Bundle.main.object(forInfoDictionaryKey: "CofferBuildTime") as? String)
    }

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
                    // 编译时间（v2.9.2-T1）：build 注入 CofferBuildTime，缺键 → 「开发构建」
                    Text("编译时间 \(buildTimeText)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                // 了解 Coffer 自述区（issue #3 完整版，v2.10.0-T5①）：一句话定位每个
                // 能力 + 入口指引，破解「全靠撞见」。纯静态文案——本机零联网 / 无
                // 云端同步是有意设计，不是缺功能（零网络纪律 docs/10 TC-NET）。
                Divider()
                    .frame(width: 280)
                VStack(spacing: 10) {
                    Text("了解 Coffer")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.primary)
                    capabilityRow(
                        icon: "internaldrive",
                        title: "本地存储 · 零同步",
                        detail: "密码只保存在本机，不连接云端、不与其他设备同步。")
                    capabilityRow(
                        icon: "wifi.slash",
                        title: "零网络架构",
                        detail: "除软件更新（OTA）外，应用不做任何网络请求。")
                    capabilityRow(
                        icon: "touchid",
                        title: "Touch ID · 恢复码",
                        detail: "生物识别解锁与忘记密码重置：设置 → 安全。")
                    capabilityRow(
                        icon: "arrow.counterclockwise",
                        title: "加密备份 · 恢复",
                        detail: "解锁后「导出」生成加密备份，换机/重装导回：设置 → 数据。")
                    capabilityRow(
                        icon: "terminal",
                        title: "MCP · Agent 协作",
                        detail: "让 AI / 自动化安全取用密码：设置 → MCP / Agent 协作。")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                // OTA 主入口（§2.6 裁定）：版本区常驻「检查更新…」按钮。
                // BUG-24 复测裁定（2026-10-14 用户）：检查阶段静默——关于页不消费
                // updater state、无原位进度条（复测否决首版 spinner 形态）；结果经
                // UpdateSheet 呈现（无新版本 → 「已是最新版本」；有新版本 → 下载
                // 进度），upToDate/下载呈现设计不动。点击仍走 model.checkForUpdates()
                // （内部 canStartCheck 防重入），按钮为纯文案入口。
                Button(UpdateCopy.checkButtonTitle) {
                    model.checkForUpdates()
                }
                .buttonStyle(.borderedProminent)
                .padding(.top, 8)
            }
            .frame(width: 360, height: 420)
            .navigationTitle("关于 Coffer")
            .toolbar {
                // D-4.1（CO-06）：只读查看页关闭语义——「关闭」+ .cancellationAction（Esc 生效）。
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
    }

    /// 自述区能力行：图标 + 标题 + 一句话定位（纯静态文案，无外链/无导航动作）。
    private func capabilityRow(icon: String, title: String, detail: String) -> some View {
        VStack(spacing: 2) {
            Label(title, systemImage: icon)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.primary)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
