// NetworkSelfCertView.swift —— 网络能力自证页（FR-14.5，docs/22 §2.4；docs/23 §1.6 TC-NET）。
//
// 零网络架构声明 + 用户自证方法（TC-NET-01）。本页为**静态说明页**——只声明
// 架构事实与给出可执行的自证命令，不含任何网络探测逻辑（自证命令由用户在
// 终端自行执行；页面不替用户跑 codesign/lsof，避免 App 内出现进程/网络工具
// 调用面）。
//
// 声明与事实一致（TC-NET-04）：
//   - macos/Coffer/Coffer.entitlements 无任何 com.apple.security.network.*；
//   - 产物 otool -L 无 Network.framework / CFNetwork 等网络框架（实测为空）；
//   - tools/check_no_network.sh 断言依赖图零网络 crate（reqwest/hyper 等黑名单）；
//   - 官方产物运行时 0 socket 由 macOS 真机验证（v0.4.0 出口判据②，TC-NET-03）。

import SwiftUI

struct NetworkSelfCertView: View {
    @Environment(\.dismiss)
    private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                declarationSection
                staticSection
                runtimeSection
                dependencySection
            }
            .formStyle(.grouped)
            .navigationTitle("网络能力自证")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
        .frame(width: 520)
    }

    // MARK: - 零网络声明（TC-NET-01）

    private var declarationSection: some View {
        Section {
            Label {
                Text("本 App 不含网络权限（零网络架构）")
                    .font(.headline)
            } icon: {
                Image(systemName: "network.slash")
                    .foregroundStyle(.green)
            }
            Text("Coffer 完全离线运行：代码与依赖图均无网络能力，密码库只存在于本机，"
                 + "不会向任何服务器发送数据。以下命令可自行验证，步骤可复现。")
        }
    }

    // MARK: - 静态自证（构建产物；TC-NET-02）

    private var staticSection: some View {
        Section("静态自证（构建产物）") {
            stepRow(1, "检查沙盒权限声明：")
            commandText("codesign -d --entitlements - <Coffer.app 路径>")
            stepRow(nil, "输出中不应出现任何 com.apple.security.network.* 键。")
            stepRow(2, "检查动态链接的框架：")
            commandText("otool -L <Coffer.app>/Contents/MacOS/Coffer")
            stepRow(nil, "输出中不应有 Network.framework / CFNetwork 等网络框架。")
        }
    }

    // MARK: - 运行时自证（TC-NET-03，-a 必需）

    private var runtimeSection: some View {
        Section("运行时自证（0 socket）") {
            stepRow(1, "启动 Coffer 后查看进程 ID：")
            commandText("pgrep -x Coffer")
            stepRow(2, "检查该进程的 TCP/UDP 连接（-a 限定只查该进程）：")
            commandText("lsof -nP -iTCP -iUDP -a -p <pid>")
            stepRow(nil, "输出应为空（无任何网络连接）。")
        }
    }

    // MARK: - 依赖图自证（源码仓库内）

    private var dependencySection: some View {
        Section("依赖图自证（源码仓库）") {
            Text("在 Coffer 源码仓库执行：")
            commandText("cd core && cargo tree --workspace -e normal")
            Text("依赖中不应出现 reqwest / hyper / tokio(net) 等网络 crate；"
                 + "仓库内 tools/check_no_network.sh 自动断言此项。")
        }
    }

    // MARK: - 展示辅助

    private func stepRow(_ number: Int?, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            if let number {
                Text("\(number)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .frame(minWidth: 16, alignment: .trailing)
            }
            Text(text)
                .font(.callout)
        }
        .padding(.vertical, 1)
    }

    private func commandText(_ command: String) -> some View {
        Text(command)
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
    }
}
