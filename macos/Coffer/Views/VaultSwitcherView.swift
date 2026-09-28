// VaultSwitcherView.swift —— 库切换器 sheet（v0.4 FR-1.2，MB-1）。
//
// 职责（docs/15 §3.2.1）：列出工作目录内全部库（onAppear 经
// AppModel.reloadVaultBriefs 刷新）→ 标记当前库 → 切换（switchVault：
// 单活跃会话不变量，先开新、失败安全，成功即锁旧装配新）→「新建库」
// 入口（复用 VaultSetupView，建库成功 → openSession 现状路径）。
//
// 明确不做（docs/15 §3.2.1）：删除库、库重命名、库间数据合并；多会话
// 并存（切换 = 锁旧开新，锁定态由 RootView → LockView 承担解锁引导）。
//
// UI 纪律（docs/07 §2.4）：sheet 必须提供显式关闭出口（关闭/返回按钮 +
// .keyboardShortcut(.cancelAction)，BUG-3/5 条款）；FFI 错误经
// AppModel.lastErrorMessage → .ffiErrorAlert 呈现（code+message 直出）。

import SwiftUI

struct VaultSwitcherView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 「新建密码库…」入口展开的建库表单（复用 VaultSetupView）。
    @State private var showSetup = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(showSetup ? "新建密码库" : "切换密码库").font(.headline)
                Spacer()
                // 显式关闭出口（docs/07 §2.4）：列表模式关闭 sheet；建库
                // 模式退回库列表（同一按钮承担「返回」职责，Esc 同效）。
                Button(showSetup ? "返回列表" : "关闭") {
                    if showSetup {
                        showSetup = false
                    } else {
                        dismiss()
                    }
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding()

            Divider()

            Group {
                if showSetup {
                    VaultSetupView(isFirstVault: false)
                } else {
                    vaultList
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: 480, height: showSetup ? 620 : 340)
        .onAppear {
            model.reloadVaultBriefs()
        }
        .ffiErrorAlert($model.lastErrorMessage)
        .onChange(of: model.phase) { _, newPhase in
            // 建库成功 → openSession → phase 转 .locked：关闭切换器，
            // RootView 接管（LockView 解锁引导；建库路径另有首次解锁后的
            // pendingBioOffer 引导）。切换成功路径在按钮动作内同步 dismiss，
            // 不经此处。.fatal 同样关闭：整屏错误页已接管呈现，sheet 不叠加。
            switch newPhase {
            case .locked, .unlocked, .fatal:
                dismiss()
            case .booting, .noVault:
                break
            }
        }
    }

    // MARK: - 库列表

    private var vaultList: some View {
        VStack(spacing: 0) {
            List {
                ForEach(model.vaultBriefs, id: \.vaultUuid) { brief in
                    vaultRow(brief)
                }
            }
            .listStyle(.plain)

            Divider()

            Button {
                showSetup = true
            } label: {
                Label("新建密码库…", systemImage: "plus")
            }
            .padding(.vertical, 12)
        }
    }

    private func vaultRow(_ brief: FfiVaultBrief) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "vault")
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(brief.displayName)
                    .lineLimit(1)
                Text(verbatim: brief.vaultUuid)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            if brief.vaultUuid == model.vaultUUID {
                // 当前库标记：切换按钮不出现（switchVault 内同库为防御性
                // no-op，此处 UI 层先行禁止，docs/15 §3.2.2 同口径）
                Label("当前库", systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.tint)
            } else {
                Button("切换") {
                    // 同步快路径（openVault 只读 header，见 switchVault 注释）。
                    // 成功 → 关 sheet，RootView 转入锁定解锁引导；失败 →
                    // sheet 留驻可重试，错误经本 sheet 的 ffiErrorAlert 呈现。
                    if model.switchVault(to: brief) {
                        dismiss()
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }
}
