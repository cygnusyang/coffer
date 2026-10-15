// DropzoneAuthStatusView.swift —— 放置区目录授权三态组件（v2.11.0，
// docs/21 §4.1/§4.5 + DESIGN.md D-18.2/D-18.3）。
//
// 多出现面同源（向导 + 设置页）：向导 S0 全屏卡内嵌 + 设置页「导入」节轻量行
// 共用本组件渲染 `model.dropzoneAuthStatus` 三态：
//   - .notAuthorized —— 「未设置放置区」说明 + 授权入口（D-18.2 未授权态）
//   - .authorized    —— 目录路径可见（D-18.5 使用面路径明示）+ 可选次级动作
//   - .stale         —— orange 警示 + 重新授权入口（D-18.3 失效非静默）
//
// 授权范围声明（D-18.1 五要素）承载于调用方同意界面本身（向导 S0 说明卡 +
// NSOpenPanel message），本组件不重复声明——只呈现状态与入口。
//
// D-18.4：移除授权（唯一删点）只由设置页提供（onSecondary 传「移除授权」）；
// 向导内不提供删除（onSecondary 传 nil）——重新授权回 S0 走唯一写点。

import SwiftUI

struct DropzoneAuthStatusView: View {
    /// 授权三态（AppModel.dropzoneAuthStatus 派生单一真相）。
    let status: DropzoneAuthStatus
    /// 授权入口按钮文案（向导「选择放置区目录…」/ 设置页「设置放置区…」）。
    let setButtonLabel: String
    /// 授权入口动作（向导开 NSOpenPanel / 设置页触发）。
    let onSet: () -> Void
    /// 已授权态次级动作文案（设置页「移除授权」）；向导传 nil（D-18.4 唯一删点）。
    var secondaryLabel: String? = nil
    /// 已授权态次级动作（设置页移除授权）。
    var onSecondary: (() -> Void)? = nil
    /// 应用级作用域注记（设置页 E-3「此授权作用于 Coffer 应用全局」；向导不显示）。
    var scopeNote: String? = nil
    /// 轻量行模式（设置页行内压缩间距）；向导全屏卡用默认。
    var compact: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 4 : 6) {
            switch status {
            case .notAuthorized:
                notAuthorizedBody
            case .authorized(let bookmark):
                authorizedBody(bookmark)
            case .stale(let bookmark):
                staleBody(bookmark)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: 未授权（D-18.2：说明 + 授权入口）

    private var notAuthorizedBody: some View {
        VStack(alignment: .leading, spacing: compact ? 4 : 6) {
            Label("未设置放置区", systemImage: "folder.badge.questionmark")
                .font(.callout)
            if !compact {
                Text("授权后 Coffer 将自动检测该目录中的新导出 CSV。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button(setButtonLabel) { onSet() }
                .buttonStyle(.borderedProminent)
        }
    }

    // MARK: 已授权（D-18.2：目录路径可见 + 可选移除）

    private func authorizedBody(_ bookmark: DropzoneBookmark) -> some View {
        VStack(alignment: .leading, spacing: compact ? 4 : 6) {
            HStack(spacing: 8) {
                Label("放置区目录", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.callout)
                if let scopeNote {
                    Text(scopeNote)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
            Text(bookmark.url.path)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            if let secondaryLabel {
                Button(secondaryLabel) { onSecondary?() }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
            }
        }
    }

    // MARK: 失效（D-18.3：orange 警示 + 重新授权入口，不静默）

    private func staleBody(_ bookmark: DropzoneBookmark) -> some View {
        VStack(alignment: .leading, spacing: compact ? 4 : 6) {
            Label("放置区授权已失效", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .font(.callout)
            Text("该路径当前不可用：\(bookmark.url.path)")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
            Button("重新授权…") { onSet() }
                .buttonStyle(.borderedProminent)
        }
    }
}
