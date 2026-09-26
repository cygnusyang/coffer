// TotpCodeView.swift —— TOTP 实时验证码：每秒刷新（倒计时环）。
// 复制按钮在阶段三接入（30s 剪贴板清除一并处理）。

import SwiftUI

struct TotpCodeView: View {
    @EnvironmentObject
    private var model: AppModel

    let itemId: String
    let detail: FfiTotpDetail

    @State private var code: String?
    @State private var secsRemaining: Int = 0
    @State private var timer: Timer?

    var body: some View {
        HStack(spacing: 12) {
            // 倒计时环
            ZStack {
                Circle()
                    .stroke(.quaternary, lineWidth: 4)
                Circle()
                    .trim(from: 0, to: progress)
                    .stroke(progressColor, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .animation(.linear(duration: 1), value: secsRemaining)
                Text("\(secsRemaining)")
                    .font(.caption.monospacedDigit())
            }
            .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 2) {
                if let code {
                    Text(code)
                        .font(.title2.monospaced())
                        .textSelection(.enabled)
                } else {
                    Text("— — — — — —")
                        .font(.title2.monospaced())
                        .foregroundStyle(.tertiary)
                }
                if let issuer = detail.issuer, !issuer.isEmpty {
                    Text(issuer).font(.caption).foregroundStyle(.secondary)
                }
            }

            Button {
                copyCode()
            } label: {
                Label(copiedFeedback ? "已复制" : "复制",
                      systemImage: copiedFeedback ? "checkmark" : "doc.on.doc")
            }
            .controlSize(.small)
            .disabled(code == nil)
            Spacer()
        }
        .onAppear(perform: refresh)
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
            refresh()
        }
    }

    @State private var copiedFeedback = false

    private var progress: Double {
        guard detail.period > 0 else { return 0 }
        return Double(secsRemaining) / Double(detail.period)
    }

    private var progressColor: Color {
        secsRemaining <= 5 ? .orange : .accentColor
    }

    private func refresh() {
        do {
            let result = try model.totpCode(itemId: itemId)
            code = result.code
            secsRemaining = Int(result.secsRemaining)
        } catch {
            // TOTP 生成失败不弹窗打断浏览；显示占位并在控制台可见
            code = nil
            secsRemaining = 0
        }
    }

    /// 复制当前验证码：不触发剪贴板清除（FR-5.5）。
    /// 理由：TOTP 码 30s 自然过期、低价值，清除只有摩擦没有安全收益；
    /// 且用户复制验证码常需粘贴到别的设备/表单。主理人裁定 2026-09-27，
    /// 推翻 T05 任务书中「与密码复制一致」的口误（需求文档为准）。
    private func copyCode() {
        guard let code else { return }
        ClipboardManager.shared.copyPlain(code)
        copiedFeedback = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            copiedFeedback = false
        }
    }
}
