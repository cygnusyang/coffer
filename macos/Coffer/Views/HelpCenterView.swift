// HelpCenterView.swift —— 帮助中心完整参考面板（v2.10.1，docs/19 §3/§7-3）。
//
// 与「使用入门」（GettingStartedView）并存：后者为快捷 primer 子集，本面板为
// 完整参考（九章超集，docs/19 §4）。正文单一来源 = HelpCenterContent（§5 转写
// 1:1，本视图只做排版渲染，不改措辞 / 键位 / 入口路径）。
//
// 排版纪律（对齐 GettingStartedView / ShortcutsSheet）：
//   - NavigationStack + List(Section)，`.listStyle(.inset)`；固定 frame 640×620
//   - 只读面板关闭语义：「关闭」+ .cancellationAction（Esc 生效），无按钮时
//     sheet 点外部不关闭
//   - 零网络纪律（docs/19 §8）：内容为静态文本，无外链、无网络请求
//
// 挂载：CofferApp.swift 的 RootView().sheet(isPresented: $model.showHelpCenter)，
// 由帮助菜单「帮助中心…」触发（CommandGroup(replacing: .help)）。帮助无密级，
// 锁定/解锁态均可打开。可访问性：全键盘可达、VoiceOver 逐条可读（Text 行）。

import SwiftUI

struct HelpCenterView: View {
    @Environment(\.dismiss)
    private var dismiss

    var body: some View {
        NavigationStack {
            List {
                ForEach(HelpCenterContent.sections, id: \.title) { section in
                    Section(section.title) {
                        ForEach(section.rows, id: \.self) { row in
                            Text(row)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            }
            .listStyle(.inset)
            .navigationTitle("帮助中心")
            .toolbar {
                // 只读面板关闭语义：「关闭」+ .cancellationAction（Esc 生效）。
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
        .frame(width: 640, height: 620)
    }
}
