// LanguageSection.swift —— 设置页「语言」行（v2.13.0，
// docs/03-功能设计/24-v2.13.0-多语言-设计.md §6.4）。
//
// 归属（设计 §8.4 边界 1）：语言入口的 **UI 实现在 impl-infra**，SettingsView.swift 归
// impl-ui-a——ui-a 只在「通用」节的自动锁定行之后加一行 LanguageSection()，不自己写
// Picker（否则 Settings 文件被两组共享）。
//
// 为什么寄生「通用」而不新开一节：macOS 13+ 系统设置把「语言与地区」放在通用之下，
// 与本页同构；且 DESIGN.md §14 已登记「9 节单长滚动」的 IA 张力，不应再加第 11 节。
//
// 交互（§6.3）：Picker 变更后**立即**提示需要重启（F10：同进程内不生效）。不静默
// 生效——静默会让用户以为切换失败。
//
// v2.13.1（docs/03-功能设计/25-v2.13.1-设置页紧凑化-设计.md §4.2 G2）：容器由
// Form 的 Section 行改为 `SettingsRow`（SettingsStyle.swift）。本节无页头页脚、
// 卡片与节距由父容器（SettingsView 的「通用」卡）承担，故本文件只产出一行。

import SwiftUI

/// 设置页的语言选择行（Picker + 重启提示）。
///
/// 自包含：不读 AppModel、不需要 environmentObject（设计 §8.2 依赖方向：infra 是
/// ui-a 的前置，反过来不行）。
struct LanguageSection: View {
    @State private var selection: AppLanguage = LanguagePreference.current
    @State private var showRestartNotice = false

    var body: some View {
        // v2.13.1（设计 25 §4.2 G2）：容器由 Form 的 Section 行改为 `SettingsRow`——
        // 骨架换 ScrollView + 自绘卡后行几何不再由系统绘制（行高 32 / 左右 inset 8）。
        // 控件、绑定、onChange、alert 全部原样，只换容器与留白。
        //
        // 本行是「通用」卡的**最后一行**（自动锁定之后，设计 25 §7 E 组清点），
        // 故 showsDivider: false——否则卡底内侧会多出一条发丝线。
        SettingsRow(showsDivider: false) {
            Label("语言", systemImage: "globe")
        } control: {
            Picker(selection: $selection) {
                ForEach(AppLanguage.allCases, id: \.self) { language in
                    // displayName 已是本地化后的展示名；用 verbatim 把「不再查表」写明
                    // （Text(String) 本来也不查 Localizable 表，设计 F6）。
                    Text(verbatim: language.displayName).tag(language)
                }
            } label: {
                Label("语言", systemImage: "globe")
            }
            // 标签由 SettingsRow 左侧渲染；labelsHidden 只隐藏 Picker 自带的重复
            // 标签，其无障碍标签仍保留（AX 侧 popup 的「语言」标题不丢，判据 E 组）。
            .labelsHidden()
        }
        .onChange(of: selection) { _, newValue in
            // apply 返回「是否需要重启」；需要才弹提示，写回同一语言不打扰用户。
            if LanguagePreference.apply(newValue) {
                showRestartNotice = true
            }
        }
        .alert("需要重新启动", isPresented: $showRestartNotice) {
            Button("好") {}
        } message: {
            Text("语言将在 Coffer 下次启动时生效。")
        }
    }
}
