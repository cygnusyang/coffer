// DropzoneWatchStatusBadge.swift —— 放置区目录监视态徽章（v2.11.0，
// docs/21 §4.5 S1 + DESIGN.md D-7.5）。
//
// 监视/等待态例外条款（D-7.5）：被动监视类状态**不是 G7 空态**——页面有内容
// （指引卡等），本组件仅追加：活跃指示（radar 图标 + 状态 caption）、不打断
// 不弹窗（检测到目标时自动流转，无需用户确认）、可随时退出（壳「关闭」）。
//
// VO：单元素 announce 播报「正在监视 <目录名>」（不做整页 live region），
// 经 accessibilityElement(children: .combine) 合并为单元素。

import SwiftUI

struct DropzoneWatchStatusBadge: View {
    /// 被监视目录名（VO 播报「正在监视 <目录名>」）。
    let directoryName: String
    /// 副态 caption（W-5：切回前台但文件未落盘 → 轻提示，不打断不弹窗）。
    var hint: String? = nil

    var body: some View {
        VStack(spacing: 4) {
            Label("正在监视 \(directoryName) · 未检测到新导出", systemImage: "dot.radiowaves.left.and.right")
                .font(.callout)
                .foregroundStyle(.secondary)
            if let hint {
                Text(hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        // D-7.5 VO：单元素 announce，不做整页 live region。
        .accessibilityElement(children: .combine)
        .accessibilityLabel("正在监视 \(directoryName)")
    }
}
