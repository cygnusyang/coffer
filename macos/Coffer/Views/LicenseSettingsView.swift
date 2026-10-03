// LicenseSettingsView.swift —— 许可信息页（FR-15.7，docs/03 §14）。
//
// 呈现纪律（docs/07 §2.4）：macOS sheet 必须有显式关闭出口（关闭按钮 +
// .keyboardShortcut(.cancelAction)——BUG-3/5 教训）；激活执行中可禁用关闭，
// 但错误 / 取消路径必须可返回（本页激活为同步快路径，错误弹窗即返回路径）。
//
// 数据来源：LicenseAssembly.shared 注入的 LicenseServicing（公开产物 =
// PermitAllLicenseService 桩，官方产物 = cf-license 真实现，docs/03 §14.9）。
// 本视图自包含：不依赖 AppModel（许可域与密码库会话无关，v0.4 §6.1 切片
// 纪律，同 McpSettingsSection）。
//
// 明文纪律（docs/03 §14.1 / §4.4）：序列号输入即用即弃——只作方法参数传入
// activate，不落任何 @State 之外的状态、不写 DiagLog、尝试结束后立即清空；
// 许可键展示只回掩码（serialMasked 由 Rust 侧计算，本视图不持有原始序列号）。
//
// 公开产物（isLicensingAvailable == false）：仅显示「本构建不含许可模块
// （全功能免费版）」（docs/03 §14.9），隐藏激活入口。

import AppKit
import SwiftUI

struct LicenseSettingsView: View {
    @Environment(\.dismiss)
    private var dismiss

    /// 注入的许可服务（装配点见 LicenseAssembly）。
    private let service: LicenseServicing = LicenseAssembly.shared

    /// 当前许可状态（onAppear / 激活成功后刷新）。
    @State private var status: LicenseStatus = .unactivated
    /// 序列号输入（明文即用即弃：不缓存、不进日志，激活后清空）。
    @State private var serial = ""
    /// 激活执行中（同步快路径，仅用于禁用关闭 / 激活按钮防双击）。
    @State private var isActivating = false
    /// 错误弹窗（本页自包含，不触 AppModel.lastErrorMessage）。
    @State private var errorMessage: String?
    /// 「已复制」瞬时反馈标记（2 s 后自动熄灭）。
    @State private var fingerprintCopied = false

    private static let copiedFeedbackSeconds: TimeInterval = 2

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("许可").font(.headline)
                Spacer()
                // 显式关闭出口（BUG-3/5 同类修复：macOS sheet 点外部不关闭、
                // 无按钮时 Esc 无效）。激活执行中禁用。
                Button("关闭") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isActivating)
            }
            .padding()

            Divider()

            Group {
                if service.isLicensingAvailable {
                    licensedContent
                } else {
                    openBuildNotice
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: 480, height: 400)
        .ffiErrorAlert($errorMessage)
        .onAppear { refreshStatus() }
    }

    // MARK: - 公开产物（全功能免费版）

    /// 公开产物：本构建不含许可模块，全功能免费（docs/03 §14.9）。
    private var openBuildNotice: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.seal")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("本构建不含许可模块（全功能免费版）")
                .font(.callout)
            Text("当前构建为开源免费版本，全部功能可用，无需激活。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
    }

    // MARK: - 官方产物（含许可模块）

    private var licensedContent: some View {
        Form {
            statusSection
            activationSection
            fingerprintSection
        }
        .formStyle(.grouped)
    }

    /// 许可状态行（docs/03 §14.9：trial / active / expired；active 只回掩码）。
    private var statusSection: some View {
        Section("许可状态") {
            Label(status.displayText, systemImage: statusIcon)
        }
    }

    /// 激活入口（FR-15.7：序列号输入 + 激活按钮）。
    private var activationSection: some View {
        Section {
            TextField("序列号", text: $serial)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .disabled(isActivating)
            HStack {
                Text("粘贴或拖入 .cofferlicense 文件中的序列号。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("激活") { doActivate() }
                    .buttonStyle(.borderedProminent)
                    .disabled(serial.isEmpty || isActivating)
            }
        } header: {
            Text("激活")
        } footer: {
            Text("激活失败时仅提示「序列号无效」（不可区分失败原因，FR-15.6）；序列号只在激活时使用，不会被保存或写入日志。")
        }
    }

    /// 机器指纹（docs/03 §14.2：供用户复制给签发方申请序列号）。
    private var fingerprintSection: some View {
        Section {
            HStack {
                Text(service.machineFingerprint())
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Button {
                    copyFingerprint()
                } label: {
                    Label(fingerprintCopied ? "已复制" : "复制",
                          systemImage: fingerprintCopied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.borderless)
            }
        } header: {
            Text("机器指纹")
        } footer: {
            Text("申请序列号时，把本机指纹提供给签发方。")
        }
    }

    // MARK: - 动作

    /// 激活（同步快路径：Ed25519 验签为微秒级，官方装配不属慢调用；
    /// 若后续实现变慢，按 §2.3 纪律改 Task.detached 包裹）。失败统一
    /// LicenseActivationError（6001）→ 统一文案，ErrorPresenter 呈现。
    private func doActivate() {
        guard !serial.isEmpty else { return }
        isActivating = true
        // 捕获局部 let，立即清空输入（即用即弃：不缓存、不进日志）
        let serialToUse = serial
        serial = ""
        do {
            status = try service.activate(serial: serialToUse)
            isActivating = false
        } catch {
            isActivating = false
            // 只呈现通用文案（6001「序列号无效」），不携带序列号任何信息
            errorMessage = ErrorPresenter.text(error)
        }
    }

    private func copyFingerprint() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        let fp = service.machineFingerprint()
        guard !fp.isEmpty, pasteboard.setString(fp, forType: .string) else {
            errorMessage = "复制失败：无法写入剪贴板，请重试。"
            return
        }
        fingerprintCopied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.copiedFeedbackSeconds) {
            fingerprintCopied = false
        }
    }

    private func refreshStatus() {
        status = service.licenseStatus()
    }

    private var statusIcon: String {
        switch status {
        case .unactivated: return "circle.dashed"
        case .trial: return "timer"
        case .active: return "checkmark.seal"
        case .expired: return "exclamationmark.triangle"
        case .unavailable: return "xmark.octagon"
        }
    }
}
