// LargePasswordSheet.swift —— FR-12.4 大字号密码抄读 sheet（v0.7，裁决 H）。
//
// 流程（docs/22 §2.3）：详情页 Concealed 密码字段「放大」→ 本 sheet 全屏
// 大字号呈现明文：单字符自适应缩放（monospaced、宽度自适应、上限 ~72pt、
// 超长换行不截断），复制按钮走既有 ClipboardManager（尊重剪贴板清除定时，
// FR-4.7 / FR-14.2 档位），显式关闭出口（docs/07 §2.4）。
//
// 明文生命周期：明文只作为本 sheet 的传入参数存活；锁定（AppModel.phase
// 离开 .unlocked）时 sheet 随会话拆除（RootView 相变拆树 + 本处 onChange
// 双保险），明文随视图销毁释放，不残留屏上（TC-FONT-05）。
//
// 零核心/FFI 变更（裁决 H：纯 SwiftUI）；无 macOS 截屏防护面（FR-12.2 仅
// Android）。不落库、无门禁（docs/22 §5：大字号无写路径）。

import AppKit
import SwiftUI

struct LargePasswordSheet: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 字段名（仅展示上下文，指示来源字段）。
    let fieldName: String
    /// 待抄读的明文密码（非空——空值在入口侧已拦截，TC-FONT-07）。
    let password: String

    /// 大字号上限（docs/22 §2.3「上限 ~72pt」）。
    static let maxFontSize: CGFloat = 72
    /// 大字号下限：仍放不下时在此字号换行（TC-FONT-06 超长不截断）。
    static let minFontSize: CGFloat = 20

    @State private var copiedFeedback = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            GeometryReader { geo in
                ScrollView {
                    Text(password)
                        .font(.system(
                            size: Self.adaptiveFontSize(password: password, width: geo.size.width),
                            weight: .regular,
                            design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(24)
                }
            }
            Divider()
            footer
        }
        .frame(minWidth: 760, minHeight: 560)
        // 锁定联动（TC-FONT-05）：phase 离开 .unlocked → 关闭 sheet。RootView
        // 相变拆树（MainView → LockView）本就会拆除本 sheet（与既有 sheet
        // 同模式）；此处 onChange 是显式双保险——任何时刻锁定都不让明文
        // 残留屏上。
        .onChange(of: model.phase) {
            if model.phase != .unlocked { dismiss() }
        }
    }

    // MARK: - 头部（显式关闭出口，docs/07 §2.4）

    private var header: some View {
        HStack(spacing: 8) {
            Text(fieldName)
                .font(.headline)
                .foregroundStyle(.secondary)
            Spacer()
            Button("关闭") { dismiss() }
                .keyboardShortcut(.cancelAction)
        }
        .padding()
    }

    // MARK: - 底部（复制走剪贴板清除定时，TC-FONT-02）

    private var footer: some View {
        HStack(spacing: 12) {
            Text("复制后按当前清除档位自动清空剪贴板")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Button {
                // 敏感值走自动清除（ClipboardManager.copyWithAutoClear）——
                // 尊重 FR-14.2 档位与 changeCount 守卫，与 FieldRowView 复制
                // 同一条纪律（TC-FONT-02）。
                ClipboardManager.shared.copyWithAutoClear(password)
                copiedFeedback = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    copiedFeedback = false
                }
            } label: {
                Label(copiedFeedback ? "已复制" : "复制密码",
                      systemImage: copiedFeedback ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    // MARK: - 字号自适应（纯函数，供自检）

    /// 单字符自适应字号：取整串密码单行能放进 width 的最大字号，夹在
    /// [minFontSize, maxFontSize]。即使 min 也放不下 → 取 min，由 Text
    /// 换行承接（TC-FONT-06 超长不截断）。width ≤ 0（布局未定）→ 保守取 min。
    static func adaptiveFontSize(password: String, width: CGFloat) -> CGFloat {
        guard width > 0 else { return Self.minFontSize }
        for size in stride(from: Self.maxFontSize, through: Self.minFontSize, by: -1) {
            if Self.singleLineWidth(password, fontSize: size) <= width {
                return size
            }
        }
        return Self.minFontSize
    }

    /// 整串密码在给定字号的单行宽度（monospaced 等宽；NSString 渲染度量覆盖
    /// CJK/emoji 组合字符宽度，与展示字体同为 SF Mono，口径一致）。
    static func singleLineWidth(_ text: String, fontSize: CGFloat) -> CGFloat {
        let font = NSFont.monospacedSystemFont(ofSize: fontSize, weight: .regular)
        let attrs: [NSAttributedString.Key: Any] = [.font: font]
        return (text as NSString).size(withAttributes: attrs).width
    }
}
