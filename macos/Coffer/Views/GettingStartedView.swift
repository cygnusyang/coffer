// GettingStartedView.swift —— 「使用入门」完整版帮助面板（v2.10.0-T5②，GitLab issue #6）。
//
// 替代 v2.9.1 的三问最小版 HelpContentView（该文件本版移除）：按能力分组
// 给出「建库 / 解锁 / 新建 / 导入 / 备份 / 恢复 / 快捷键 / Touch ID / 恢复码 / MCP」
// 的一行入口指引（AC-2.10.0-UX-6）。指引路径与真实入口逐一核对过：
//   - 建库：无库时首屏「创建密码库」（VaultSetupView）
//   - 解锁：锁定页主密码 / Touch ID（LockView）
//   - 新建 / 导入 / 导出：主窗工具栏 + ⌘N / ⌘I / ⌘⇧I / ⌘E（MainView / DataCommands）
//   - 备份提醒：设置 → 备份提醒（SettingsView ③）
//   - 恢复：首屏「从备份恢复…」（noVault）/ 设置 → 数据（SettingsView ⑥）/
//     锁定态「管理密码库…」→「从备份恢复…」（UX #1 管理面，T5-LOW-2 补行）
//   - 快捷键：帮助菜单「键盘快捷键…」（ShortcutsSheet）
//   - Touch ID / 恢复码：设置 → 安全（SettingsView ⑤，TouchIDSettingsSection /
//     RecoveryCodeSettingsSection）
//   - MCP：设置 → MCP / Agent 协作（SettingsView ⑨，McpSettingsSection）
//
// 零网络纪律（docs/10 TC-NET，AC-2.10.0-UX-7）：本视图不发起任何网络请求、
// 不调用自动更新检查、不含外链——内容全部内联为静态 Text。帮助无密级，
// 锁定/解锁态均可打开（CofferApp.swift 挂载处不 disabled）。
//
// 挂载：CofferApp.swift 的 RootView().sheet(isPresented: $model.showHelp)，
// 由帮助菜单「使用入门…」触发。
//
// 关闭纪律（与 HistorySheet / AboutUpdateView 一致）：关闭按钮挂
// .cancellationAction（Esc 生效），无按钮时 sheet 点外部不关闭。

import SwiftUI

struct GettingStartedView: View {
    @Environment(\.dismiss)
    private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    introSection
                    createSection
                    everydaySection
                    safetySection
                    mcpSection
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationTitle("使用入门")
            .toolbar {
                // 只读面板关闭语义：「关闭」+ .cancellationAction（Esc 生效）。
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
        }
        .frame(width: 560, height: 540)
    }

    // MARK: - 段落

    private var introSection: some View {
        section(
            title: "欢迎使用 Coffer",
            rows: [
                "Coffer 是本地密码管理器：密码只存在本机，不连接云端、不做同步（软件更新 OTA 除外）。",
            ])
    }

    private var createSection: some View {
        section(
            title: "开始使用",
            rows: [
                "建库：无密码库时首屏点「创建密码库」，设一个强主密码（3 分以上，共 4 分）。",
                "解锁：每次启动 / 锁定后，在锁定页输入主密码，或用 Touch ID 一键解锁。",
                "新建条目：解锁后点工具栏「新建」或按 ⌘N，填写名称、用户名、密码。",
            ])
    }

    private var everydaySection: some View {
        section(
            title: "日常操作",
            rows: [
                "导入：从其他密码管理器迁入——工具栏「导入」（CSV / 1Password / Bitwarden / OPVault）或 ⌘I / ⌘⇧I。",
                "导出备份：工具栏「导出」（或 ⌘E）生成加密备份文件，建议定期保存到安全位置。",
                "恢复：换机 / 重装后在首屏点「从备份恢复…」；有既有库时在 设置 → 数据 恢复，锁定态可经「管理密码库…」→「从备份恢复…」直达。",
                "快捷键：全部快捷键见帮助菜单「键盘快捷键…」（含 ⌘⇧C 复制密码、⌘U 复制用户名等）。",
            ])
    }

    private var safetySection: some View {
        section(
            title: "安全",
            rows: [
                "Touch ID：在 设置 → 安全 启用后，解锁与跨库复制可免输主密码。",
                "恢复码：忘记主密码时找回数据的唯一途径——在 设置 → 安全 生成并妥善保存，未雨绸缪。",
                "修改主密码：在 设置 → 安全 → 修改主密码…。",
            ])
    }

    private var mcpSection: some View {
        section(
            title: "MCP / Agent 协作",
            rows: [
                "让 AI / 自动化安全取用密码：在 设置 → MCP / Agent 协作 开启并注册命令行入口（CLI 与 MCP 均本机运行，零网络）。",
            ])
    }

    /// 分组小节：标题 + 多行指引（纯静态文案，无富文本/外链）。
    private func section(title: String, rows: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
            ForEach(rows, id: \.self) { row in
                Text(row)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
