// FieldRowView.swift —— 详情字段行：普通字段直出，Concealed 字段默认掩码、
// 点击「显示」按需经 getFieldValue 取明文（取回即用，只存行内局部状态）。

import SwiftUI

struct FieldRowView: View {
    @EnvironmentObject
    private var model: AppModel

    let itemId: String
    let field: FfiFieldDetail

    var body: some View {
        if field.fieldType == .concealed {
            ConcealedFieldRow(itemId: itemId, field: field)
        } else {
            PlainFieldRow(field: field)
        }
    }
}

// MARK: - 普通字段行

struct PlainFieldRow: View {
    let field: FfiFieldDetail

    @State private var copiedFeedback = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(field.name)
                .foregroundStyle(.secondary)
                .frame(width: 120, alignment: .leading)
            if let value = field.value, !value.isEmpty {
                if field.fieldType == .multiline {
                    Text(value)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    Text(value)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                // 非敏感字段（用户名 / 网址 / 备注等）：普通复制，不自动清除
                Button {
                    ClipboardManager.shared.copyPlain(value)
                    copiedFeedback = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        copiedFeedback = false
                    }
                } label: {
                    Label(copiedFeedback ? "已复制" : "复制",
                          systemImage: copiedFeedback ? "checkmark" : "doc.on.doc")
                }
                .controlSize(.small)
            } else {
                Text("—")
                    .foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - 掩码字段行（FR-12.3：默认掩码，明文仅“点击显示”）

struct ConcealedFieldRow: View {
    @EnvironmentObject
    private var model: AppModel

    let itemId: String
    let field: FfiFieldDetail

    /// nil = 掩码态；非 nil = 已取回的明文（仅本行局部状态，随视图销毁释放）。
    @State private var revealed: String?
    @State private var isBusy = false
    @State private var copiedFeedback = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(field.name)
                .foregroundStyle(.secondary)
                .frame(width: 120, alignment: .leading)
            Group {
                if let revealed {
                    Text(revealed)
                        .textSelection(.enabled)
                        .font(.body.monospaced())
                } else {
                    Text("••••••••")
                        .foregroundStyle(.tertiary)
                        .font(.body.monospaced())
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if isBusy {
                ProgressView().controlSize(.mini)
            } else if revealed != nil {
                Button("隐藏") {
                    // 明文只存活在行内局部状态，隐藏即弃
                    revealed = nil
                }
                .controlSize(.small)
            } else {
                Button("显示") { reveal() }
                    .controlSize(.small)
            }

            Button {
                copyValue()
            } label: {
                Label(copiedFeedback ? "已复制" : "复制",
                      systemImage: copiedFeedback ? "checkmark" : "doc.on.doc")
            }
            .controlSize(.small)
        }
        .padding(.vertical, 2)
    }

    private func reveal() {
        guard !isBusy else { return }
        isBusy = true
        do {
            // 明文仅在此刻跨 FFI 取回，写入行内 @State；不进全局状态
            revealed = try model.fieldValue(itemId: itemId, fieldId: field.uuid) ?? ""
        } catch {
            model.handleFfiError(error)
        }
        isBusy = false
    }

    /// 复制敏感值：取回即写剪贴板（不落任何状态），30 秒后自动清除。
    private func copyValue() {
        guard !isBusy else { return }
        isBusy = true
        do {
            let value = try revealed ?? (model.fieldValue(itemId: itemId, fieldId: field.uuid) ?? "")
            ClipboardManager.shared.copyWithAutoClear(value)
            copiedFeedback = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                copiedFeedback = false
            }
        } catch {
            model.handleFfiError(error)
        }
        isBusy = false
    }
}
