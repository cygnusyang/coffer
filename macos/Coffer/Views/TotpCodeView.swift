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
            Spacer()
        }
        .onAppear(perform: refresh)
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
            refresh()
        }
    }

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
}
