// HelpContentView.swift —— 「使用入门」帮助面板（v2.9.1，GitLab issue #6）。
//
// 纯本地静态文本的三问最小版（lead 供词），帮助用户自助解决最高频的
// 三个疑问（忘记主密码 / 备份恢复 / Touch ID 不弹）。正文与 issue #3
// 自我介绍文案同源，v2.10.0 随 #3 一并定稿扩展，本版只落最小内嵌版。
//
// 零网络纪律（docs/10 TC-NET）：本视图不发起任何网络请求、不调用自动
// 更新检查、不含外链——内容全部内联为静态 Text。
//
// 挂载：CofferApp.swift 的 RootView().sheet(isPresented: $model.showHelp)，
// 由帮助菜单「使用入门…」触发。帮助无密级，锁定/解锁态均可打开。
//
// 关闭纪律（与 HistorySheet / AboutUpdateView 一致）：关闭按钮挂
// .cancellationAction（Esc 生效），无按钮时 sheet 点外部不关闭。

import SwiftUI

struct HelpContentView: View {
    @Environment(\.dismiss)
    private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    helpSection(
                        title: "忘记主密码怎么办？",
                        body: "在锁定页点「忘记主密码？」。只要你还设置了 Touch ID 或生成过恢复码，就能重置密码库并找回数据；两者都没有，则数据无法找回。\n因此请先在 设置 → 安全 里生成恢复码，未雨绸缪。"
                    )
                    helpSection(
                        title: "怎么备份数据？",
                        body: "解锁后点工具栏「导出」，即可生成一份加密备份文件。\n换机或重装后，在首屏点「从备份恢复」导回即可（该入口本版新增）。"
                    )
                    helpSection(
                        title: "Touch ID 为什么有时不弹？",
                        body: "设备不支持、功能未启用或指纹状态过期时不会出现，此时用主密码解锁即可。\n连续输错主密码进入保护期时，Touch ID 仍可用。"
                    )
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationTitle("使用入门")
            .toolbar {
                // 只读面板关闭语义：「关闭」+ .cancellationAction（Esc 生效）。
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
        .frame(width: 500, height: 420)
    }

    /// 单个问答小节：分组标题 + 正文（正文静态文案，无富文本/外链）。
    private func helpSection(title: String, body: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
            Text(body)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
