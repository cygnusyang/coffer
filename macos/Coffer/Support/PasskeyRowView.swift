// PasskeyRowView.swift —— 条目详情 Passkey 列表行（FR-10.2 / FR-10.5，docs/17 §4.4 PK3）。
//
// 私钥红线（FR-10.2）：本组件只渲染 `FfiPasskeyMeta` 的元数据字段
// （rpId / 用户名 / 创建时间 / 签名计数器 / 凭据 ID）——FFI 结构上就不存在
// 私钥读路径，UI 结构上同样没有私钥数据源（docs/18 TCB-2）。
//
// 删除纪律（FR-10.5）：走确认对话框，固定文案「删除后该网站将无法用此
// Passkey 登录」（逐字 TCB-3）；确认后调 `session.remove_passkey`（毫秒级
// DB 行操作，与 removeAttachment 同纪律直接主线程调用；Rust 1001 门禁）。
// 错误经 model.handleFfiError 分流（1001 切回锁定界面，其余 code+message 直出）。

import SwiftUI

struct PasskeyRowView: View {
    @EnvironmentObject
    private var model: AppModel

    let passkey: FfiPasskeyMeta
    /// 删除成功回调（父区据此重载列表）。
    var onDeleted: () -> Void = {}

    @State private var confirmDelete = false

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "key.fill")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(passkey.rpId)
                        .font(.callout.weight(.semibold))
                        .textSelection(.enabled)
                    if let rpName = passkey.rpName, !rpName.isEmpty {
                        Text(rpName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                if let userName = passkey.userName, !userName.isEmpty {
                    Text(userName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text("创建时间 \(Self.timestamp(passkey.createdAt)) · 签名计数器 \(passkey.signCount)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(passkey.credentialIdB64)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            Spacer()
            Button("删除", role: .destructive) { confirmDelete = true }
                .controlSize(.small)
        }
        .padding(.vertical, 2)
        .confirmationDialog(
            "删除 Passkey？此操作不可恢复。",
            isPresented: $confirmDelete,
            titleVisibility: .visible
        ) {
            Button("删除", role: .destructive) { remove() }
            Button("取消", role: .cancel) {}
        } message: {
            // FR-10.5 固定文案（docs/18 TCB-3 逐字核对）。
            Text("删除后该网站将无法用此 Passkey 登录")
        }
    }

    private static func timestamp(_ unixSecs: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(unixSecs))
            .formatted(date: .abbreviated, time: .shortened)
    }

    private func remove() {
        guard let session = model.session else { return }
        do {
            try session.removePasskey(passkeyUuid: passkey.passkeyUuid)
            onDeleted()
        } catch {
            model.handleFfiError(error)
        }
    }
}
