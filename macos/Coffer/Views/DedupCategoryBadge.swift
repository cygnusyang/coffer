// DedupCategoryBadge.swift —— 去重分类徽章（v2.11.0，docs/21 §4.4 +
// DESIGN.md D-12.2 / D-13.4）。
//
// 三分类徽章：新增（蓝 plus）/ 重复（灰 checkmark.circle）/ 冲突（橙
// questionmark.circle）。**文本常显**（D-13.4：状态不以颜色为唯一通道），
// 颜色仅辅助。
//
// 去重匹配键 = (Title, Username, URL) 规范化三元组（docs/21 §4.4，Password
// 不作匹配键——R2 防安全反模式）；分类在 core 完成（P-4，Swift 只消费
// FfiDedupCategory 结果）。
//
// 批量切换的 VO（「重复，点按改为导入」）由 S3 预览行承载（D-8.4），本徽章
// 只作分类标识。

import SwiftUI

struct DedupCategoryBadge: View {
    /// 去重分类（core 报告，FfiDedupCategory）。
    let category: FfiDedupCategory

    var body: some View {
        // switch 结果经 Group 归一为单一视图再挂尾随修饰：ViewBuilder 对裸 switch
        // 挂尾随修饰会退回协议 View 导致无法 .font（DeleteVaultConfirmSheet 同款）。
        Group {
            switch category {
            case .new:
                Label("新增", systemImage: "plus.circle.fill")
                    .foregroundStyle(.blue)
            case .duplicate:
                Label("重复", systemImage: "checkmark.circle")
                    .foregroundStyle(.gray)
            case .conflict:
                Label("冲突", systemImage: "questionmark.circle")
                    .foregroundStyle(.orange)
            }
        }
        .font(.caption)
        .labelStyle(.titleAndIcon)
    }
}
