// NetworkSelfCertView.swift —— 网络能力自证页（FR-14.5，docs/22 §2.4；docs/23 §1.6 TC-NET）。
//
// 零网络架构声明 + 用户自证方法（TC-NET-01）。本页为**静态说明页**——只声明
// 架构事实与给出可执行的自证命令，不含任何网络探测逻辑（自证命令由用户在
// 终端自行执行；页面不替用户跑 codesign/lsof，避免 App 内出现进程/网络工具
// 调用面）。
//
// 声明与事实一致（TC-NET-04，v2.10.3-T3 #89 对齐 OTA 豁免）：
//   - macos/Coffer/Coffer.entitlements 唯一网络权限为 network.client
//     （v2.7.0 OTA 更新豁免，docs/35 §2.2；仅访问白名单更新服务器，不发送
//     密码库数据）；network.server 或其他 network.* 均为违规；
//   - 产物 otool -L 无第三方网络库；系统框架 CFNetwork 仅被软件更新（OTA）
//     模块经 URLSession 使用（实测：CFNetwork 在、Network.framework 不在）；
//   - tools/check_no_network.sh 断言 Rust 核心依赖图零网络 crate
//     （reqwest/hyper 等黑名单）；
//   - 官方产物运行时 0 socket（常态）由 macOS 真机验证
//     （v0.4.0 出口判据②，TC-NET-03）。
//
// v2.10.0-T5⑤（FRICT-17，AC-2.10.0-FR-5）：命令块加「复制」按钮（对齐
// McpSettingsView 一键复制）——命令含 <Coffer.app 路径>/<pid> 占位符且为长
// monospaced 文本，手选复制易漏；复制按钮 + 占位符替换指引一次到位。

import SwiftUI

struct NetworkSelfCertView: View {
    @Environment(\.dismiss)
    private var dismiss

    /// FRICT-17：命令复制按钮瞬时「已复制」反馈（按命令串区分，2 s 后熄灭）。
    @State private var copiedCommand: String?

    private static let copiedFeedbackSeconds: TimeInterval = 2

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
                Text("数据都在本机，不上传云端")
                    .font(.headline)
            } icon: {
                Image(systemName: "network.slash")
                    .foregroundStyle(.green)
            }
            Text("Coffer 的密码库与全部数据只保存在本机，不上传到任何云端。"
                 + "Rust 核心与其依赖图零网络（可用 tools/check_no_network.sh 自证）；"
                 + "应用层唯一联网例外是软件更新（OTA）——仅按白名单地址访问更新服务器，"
                 + "不发送任何密码库数据。以下命令可自行验证，步骤可复现。")
        }
    }

    // MARK: - 静态自证（构建产物；TC-NET-02）

    private var staticSection: some View {
        Section("静态自证（构建产物）") {
            stepRow(1, "检查沙盒权限声明：")
            commandText("codesign -d --entitlements - <Coffer.app 路径>")
            stepRow(nil, "输出中最多允许出现一项网络权限：com.apple.security.network.client"
                     + "（软件更新豁免）；不得出现 network.server 或其他任何 "
                     + "com.apple.security.network.* 键。")
            stepRow(2, "检查动态链接的框架：")
            commandText("otool -L <Coffer.app>/Contents/MacOS/Coffer")
            stepRow(nil, "输出中不应链接第三方网络库；系统框架 CFNetwork 属预期——"
                     + "仅被软件更新（OTA）模块经 URLSession 使用，不应出现独立的 "
                     + "Network.framework。")
        }
    }

    // MARK: - 运行时自证（TC-NET-03，-a 必需）

    private var runtimeSection: some View {
        Section("运行时自证（0 socket）") {
            stepRow(1, "启动 Coffer 后查看进程 ID：")
            commandText("pgrep -x Coffer")
            stepRow(2, "检查该进程的 TCP/UDP 连接（-a 限定只查该进程）：")
            commandText("lsof -nP -iTCP -iUDP -a -p <pid>")
            stepRow(nil, "输出应为空，即无任何网络连接——软件更新（OTA）下载进行中除外。")
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
        // FRICT-17：命令块 + 复制按钮（对齐 McpSettingsView 一键复制纪律）。
        // 占位符（<Coffer.app 路径>/<pid>）由用户在终端替换——文案已含指引。
        HStack(spacing: 8) {
            Text(command)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
            Button {
                copyCommand(command)
            } label: {
                Label(
                    copiedCommand == command ? "已复制" : "复制",
                    systemImage: copiedCommand == command ? "checkmark" : "doc.on.doc")
                    .font(.caption)
                    .frame(minWidth: 44)
            }
            .controlSize(.small)
            .help("复制整条命令；<…> 占位符在终端中替换为实际路径/进程 ID")
        }
    }

    /// FRICT-17：复制命令到剪贴板 + 瞬时「已复制」反馈（2 s 熄灭）。
    private func copyCommand(_ command: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        copiedCommand = command
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.copiedFeedbackSeconds) {
            if copiedCommand == command {
                copiedCommand = nil
            }
        }
    }
}
