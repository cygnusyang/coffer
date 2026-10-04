// FieldRowView.swift —— 详情字段行：普通字段直出，Concealed 字段默认掩码、
// 点击「显示」按需经 getFieldValue 取明文（取回即用，只存行内局部状态）。
// FR-5.6（v0.4）：密码字段的复制按钮在条目含 TOTP 时走序列复制
// （ClipboardManager.copyPasswordThenTotp，docs/15 §3.3.3）。
// FR-12.4（v0.7）：Concealed 密码字段增「放大」入口——明文按需取回后经
// onEnlarge 回调交由宿主（ItemDetailView）呈现在全屏 LargePasswordSheet。

import SwiftUI

struct FieldRowView: View {
    @EnvironmentObject
    private var model: AppModel

    let itemId: String
    let field: FfiFieldDetail
    /// FR-12.4「放大」回调：携带已取回的明文，由宿主视图呈现在全屏
    /// LargePasswordSheet。nil = 不显示放大入口（本视图复用且不需要该能力时）。
    let onEnlarge: ((String) -> Void)?

    init(itemId: String, field: FfiFieldDetail, onEnlarge: ((String) -> Void)? = nil) {
        self.itemId = itemId
        self.field = field
        self.onEnlarge = onEnlarge
    }

    var body: some View {
        if field.fieldType == .concealed {
            ConcealedFieldRow(itemId: itemId, field: field, onEnlarge: onEnlarge)
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
    /// FR-12.4「放大」回调（透传自 FieldRowView，见其 docstring）。
    let onEnlarge: ((String) -> Void)?

    init(itemId: String, field: FfiFieldDetail, onEnlarge: ((String) -> Void)? = nil) {
        self.itemId = itemId
        self.field = field
        self.onEnlarge = onEnlarge
    }

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

            // FR-12.4「放大」入口（仅宿主提供 onEnlarge 时显示；显式用户操作
            // 进入，绝不自动弹出，TC-FONT-03）。
            if onEnlarge != nil {
                Button {
                    enlarge()
                } label: {
                    Label("放大", systemImage: "text.magnifyingglass")
                }
                .controlSize(.small)
                .help("全屏大字号查看")
            }
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

    /// 复制敏感值：取回即写剪贴板（不落任何状态），按当前档位自动清除；
    /// FR-5.6 条件满足时走序列复制（见 copyWithTotpIfApplicable）。
    private func copyValue() {
        guard !isBusy else { return }
        isBusy = true
        do {
            let value = try revealed ?? (model.fieldValue(itemId: itemId, fieldId: field.uuid) ?? "")
            copyWithTotpIfApplicable(value)
            copiedFeedback = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                copiedFeedback = false
            }
        } catch {
            model.handleFfiError(error)
        }
        isBusy = false
    }

    /// FR-5.6（docs/15 §3.3.3 调用点：FieldRowView 密码复制按钮）：仅密码
    /// 字段（designation == .password）且条目含 TOTP 时走「密码 → 延迟
    /// 取码 → 验证码」序列，否则单次自动清除复制（现状）。TOTP 元数据取
    /// 自当前详情——本行由 ItemDetailView 以 currentDetails 渲染，uuid
    /// 对齐校验防错配（与本字段不是同一详情时按单次复制降级）。
    private func copyWithTotpIfApplicable(_ value: String) {
        guard field.designation == .password,
              let details = model.currentDetails,
              details.uuid == itemId,
              details.totp != nil else {
            ClipboardManager.shared.copyWithAutoClear(value)
            return
        }
        // totpProvider 延迟执行取 fresh code；闭包体内访问 @MainActor 的
        // AppModel，经 assumeIsolated 进入——ClipboardManager 保证回调只在
        // 主队列触发（与 MainView HK-3 调用点同一模式）
        ClipboardManager.shared.copyPasswordThenTotp(password: value) {
            MainActor.assumeIsolated { try? model.totpCode(itemId: itemId).code }
        }
    }

    /// FR-12.4「放大」：明文经 onEnlarge 交给宿主呈现在全屏大字号 sheet。
    /// 与 copyValue 同纪律——已显示则复用行内明文，否则按需跨 FFI 取回，
    /// 不进全局状态。明文只在 sheet 的局部状态存活，随 sheet 关闭销毁。
    /// 空值不放大（TC-FONT-07：避免空白视图）。
    private func enlarge() {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let value = try revealed ?? (model.fieldValue(itemId: itemId, fieldId: field.uuid) ?? "")
            guard !value.isEmpty else { return }
            onEnlarge?(value)
        } catch {
            model.handleFfiError(error)
        }
    }
}
