// VaultManagementView.swift —— 密码库管理面（v2.10.0 D1，docs/16 §4.5 线框 /
// docs/03-功能设计/17-库删除实现接线.md §4.1）。
//
// sheet 形态，列**全库**（含当前库，行标「当前库」）→ 行内 [删除…]
// （destructive）→ DeleteVaultConfirmSheet 多步向导。三入口：
//   ① 设置「数据」区「管理密码库…」（SettingsView 本地 sheet）
//   ② 库切换 sheet 底部深链（先关切换 sheet，再从主窗弹本视图）
//   ③ LockView「管理密码库…」低存在感链接（工厂级，锁定态可管理全库）
// 后两入口挂 RootView 主窗 sheet（model.showVaultManagement）。
//
// 生命周期（UDR-4 / AC-2.10.0-LF-3）：删光全库（phase → .noVault）→ 本
// 视图一并关闭，落 VaultSetupView 空库首屏（无残留 sheet）；删非当前库 →
// 列表刷新（vaultBriefs @Published 驱动）、管理面保持打开。
// 许可降级（UDR-7 / AC-2.10.0-EN-7）：只读许可（model.canManageVaults ==
// false）→ 入口在源侧隐藏；行内 [删除…] 不渲染（本视图内不逐项报错）。
//
// v2.10.0-T5④（UX issue #1 完整版，lead r0.4 裁定，AC-2.10.0-UX-2）：管理面
// 底部加「从备份恢复…」动作——锁定态恢复入口**经本管理面可达**（工厂级恢复
// 面，RestoreBackupView 挂 CofferApp 工厂、1004 冲突语义自含），LockView 不
// 加第三个链接（低存在感链接上限 = 忘记主密码？/ 管理密码库…，R-A 裁定）；
// P2-B 主面不回归：恢复不从不锁界面的 LockView 直达，改经管理面（锁定态
// LockView → 管理密码库… → 从备份恢复…）。恢复入口不要求 canManageVaults
//（删除才受只读许可门控；恢复与 ExportView 同契约，任何许可均可用）。

import SwiftUI

struct VaultManagementView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 选中待删目标（驱动 DeleteVaultConfirmSheet 多步向导）。
    @State private var targetToDelete: FfiVaultBrief?

    /// 从备份恢复 sheet（UX #1：工厂级恢复面，行为与设置页数据节同构）。
    @State private var showRestore = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("管理密码库").font(.headline)
                Spacer()
                // 显式关闭出口 + Esc（docs/01 §2.4 sheet 纪律）。
                Button("完成") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()

            Divider()

            List {
                ForEach(model.vaultBriefs, id: \.vaultUuid) { brief in
                    managementRow(brief)
                }
            }
            .listStyle(.plain)

            Divider()

            // UX #1 锁定态恢复入口（AC-2.10.0-UX-2）：工厂级恢复面。与设置页
            // 数据节「从备份恢复…」同标签同契约（RestoreBackupView 自含 1004
            // 冲突语义）；恢复无需 canManageVaults（任何许可均可用）。
            HStack {
                Button {
                    showRestore = true
                } label: {
                    Label("从备份恢复…", systemImage: "arrow.counterclockwise")
                }
                .buttonStyle(.borderless)
                .padding(.leading, 12)
                Spacer()
            }
            .padding(.vertical, 8)
        }
        .frame(width: 480, height: 400)
        .onAppear {
            model.reloadVaultBriefs()
        }
        .onChange(of: model.phase) { _, newPhase in
            // UDR-4 生命周期：删光全库 → .noVault → 本管理面一并关闭。
            // 主窗源（model.showVaultManagement）经 binding 关；设置窗源
            // （SettingsView 本地 sheet）经 dismiss，并随 SettingsWindowHost
            // 在 phase 离开 .unlocked 时整窗拆除（F3）——双保险无残留 sheet。
            if newPhase == .noVault {
                model.showVaultManagement = false
                dismiss()
            }
        }
        .sheet(item: $targetToDelete) { brief in
            DeleteVaultConfirmSheet(target: brief)
                .environmentObject(model)
        }
        .sheet(isPresented: $showRestore) {
            // 从备份恢复流程（FR-8.1 回环，T-H）：校验 → 确认 → 恢复 →
            // openSession 引导解锁（1004 冲突语义自含，工厂级恢复）。
            RestoreBackupView()
                .environmentObject(model)
        }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - 行

    private func managementRow(_ brief: FfiVaultBrief) -> some View {
        HStack(spacing: 10) {
            // archivebox 与库切换器行同源图标（SF Symbol 无 "vault"）。
            Image(systemName: "archivebox")
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(brief.displayName)
                    .lineLimit(1)
                // masked UUID（D-5.1/5.3 长内容纪律）：prefix 8 + …
                Text(DeleteVaultPolicy.maskedUUID(brief.vaultUuid))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if brief.vaultUuid == model.vaultUUID {
                Label("当前库", systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.tint)
            }
            // UDR-7：只读许可不渲染行内删除（对齐 create_vault 拒绝口径，
            // 不在向导内逐项报错）。
            if model.canManageVaults {
                Button("删除…") { targetToDelete = brief }
                    // destructive 样式 + accessibility label（D-13.1）
                    .foregroundStyle(.red)
                    .accessibilityLabel("删除密码库 \(brief.displayName)")
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - 删除向导 sheet 的 Identifiable 适配（同 MainView category 先例）

extension FfiVaultBrief: Identifiable {
    public var id: String { vaultUuid }
}
