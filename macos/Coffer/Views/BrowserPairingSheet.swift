// BrowserPairingSheet.swift —— 配对批准前置 sheet（docs/01 FR-16.1 / docs/31 §4.2）。
//
// 扩展发起配对时 App 前置弹此 sheet（浏览器名 + 扩展 ID + 权限说明 + 批准/拒绝），
// 用户无需导航到「设置」页（用户裁定：v2.3.0 + 前置 sheet + 解锁态唤醒）。
//
// 呈现纪律：
//   - 批准是信任锚点 → interactiveDismissDisabled：只有 批准 / 拒绝 / 120s 超时
//     三出口（契约 §8-3「超时即拒」）。不允许点别处关掉。
//   - 与 BrowserSettingsView.pairingRow 同状态源（pendingPairingRequest，双呈现面
//     互斥：settings 开着时内联行兜底——macOS 同一窗口第二 sheet 被 defer，不会双 UI）。
//   - 密钥材料不经本视图、不进日志（本视图只读请求元数据）。

import SwiftUI

struct BrowserPairingSheet: View {
    @EnvironmentObject
    private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("浏览器配对").font(.headline)
            Text(pairingMessage)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("拒绝", role: .cancel) { model.rejectPendingPairing() }
                Button("批准") { model.approvePendingPairing() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(minWidth: 440)
        .interactiveDismissDisabled()
    }

    /// 批准文案（与 BrowserSettingsView.pairingMessage 同措辞；权限说明走 App 侧
    /// 常量，不由扩展/broker 供给——防伪造文案诱导，契约 §2.3）。
    private var pairingMessage: String {
        guard let request = model.pendingPairingRequest else { return "" }
        let permission = request.permissionDescription.isEmpty
            ? BrowserPairingRequest.defaultPermissionDescription
            : request.permissionDescription
        return "\(request.browser.displayName) 上的 Coffer 扩展（ID：\(request.extensionID)）请求与本机密码库配对。\(permission)。"
    }
}
