// DeleteVaultConfirmSheet.swift —— 删除密码库多步确认向导（v2.10.0 D1，
// docs/16 §4.0 状态机 + §4.5 线框逐字对齐文案）。
//
// 步骤：Step1 目标与方式双选 → Step2 [先导出再删时] 参数化导出（C8）→
// Step3 输入库名逐字符确认 → Step4 执行 → Step5 完成反馈 + 落位引导。
//
// 确认门纪律（docs/16 §3.3 / UDR-3）：**仅输入库名逐字符确认，无任何密码
// 步**；比对前双方 trim（UDR-1）；同名库尾显 masked UUID（UDR-7）；匹配后
// [确认删除] 才可用（CF-5）；不符就地提示（CF-4）。
// 强制保数据（UDR-1 / AC-2.10.0-EX-4）：「先导出再删除」路径导出成功才放行
// Step3，导出未成功不可能被引导删除。
// 负路径（docs/16 §4.4）：删除失败 → ffiErrorAlert + 确认流留驻可重试；
// 任一环节取消 → 无任何变更（删除前无破坏性副作用）。
//
// 工厂级（六裁定 #3）：不依赖解锁会话、无密码门——锁定态/忘密库均可删。
// 删当前库由 AppModel.deleteVault 先锁旧（C5）；落位结果经 DeleteVaultLanding
// 驱动 Step5 反馈（F3：设置窗源删当前库时窗口随 phase 离开自关，Step5 主要
// 适用于锁定态深链与非当前库删除路径，落位反馈经主窗呈现）。

import SwiftUI

struct DeleteVaultConfirmSheet: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 待删目标（由管理面行内 [删除…] 传入）。
    let target: FfiVaultBrief

    /// 向导步骤状态机（docs/16 §4.0 / docs/17 §4.2）。
    enum WStep {
        case chooseMethod   // Step1
        case export         // Step2（仅先导出路径）
        case confirmName    // Step3
        case executing      // Step4
        case done(AppModel.DeleteVaultLanding)   // Step5
    }

    /// Step1 操作方式双选（默认推荐「先导出再删除」）。
    enum Method {
        case exportThenDelete
        case deleteDirectly
    }

    @State private var step: WStep = .chooseMethod
    @State private var method: Method = .exportThenDelete
    @State private var confirmText = ""
    /// Step2 导出是否成功（verified）——成功才放行 Step3（AC-2.10.0-EX-4）。
    @State private var exportSucceeded = false

    /// 目标库 masked UUID（D-5.1/5.3 + UDR-7 同名消歧）。
    private var maskedTargetUUID: String {
        DeleteVaultPolicy.maskedUUID(target.vaultUuid)
    }

    private var isNameConfirmed: Bool {
        DeleteVaultPolicy.confirmName(input: confirmText, vaultName: target.displayName)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            Group {
                switch step {
                case .chooseMethod: chooseMethodBody
                case .export: exportBody
                case .confirmName: confirmNameBody
                case .executing: executingBody
                case .done(let landing): doneBody(landing)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: 520, height: 460)
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - 顶栏（sheet 显式出口 + Esc，docs/01 §2.4）

    private var header: some View {
        HStack {
            Text(stepTitle).font(.headline)
            Spacer()
            Button("取消") { dismiss() }
                .keyboardShortcut(.cancelAction)
                .disabled(model.isBusy)
        }
        .padding()
    }

    /// 返回 LocalizedStringKey：调用方是 Text(...)，String 重载不查表（F6）。
    private var stepTitle: LocalizedStringKey {
        switch step {
        case .export: return "删除密码库 · 导出备份"
        default: return "删除密码库"
        }
    }

    // MARK: - Step1 目标与方式双选

    private var chooseMethodBody: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("目标：密码库「\(target.displayName)」（\(maskedTargetUUID)）")
                .font(.callout)
                .lineLimit(2)
            Text("将永久删除该密码库：库内全部条目、附件将一并永久删除，且无法恢复。")
                .font(.callout)
                .foregroundStyle(.secondary)

            // 双选（AC-2.10.0-EX-5）：默认选中推荐项；「直接删除」为合法清库
            // 场景（软性约束，不堵死归零需求）。
            VStack(alignment: .leading, spacing: 10) {
                radioRow(.exportThenDelete, "先导出加密备份，再删除（推荐）")
                radioRow(.deleteDirectly, "直接删除（不保留备份）")
            }

            Spacer()
            HStack {
                Spacer()
                Button("继续") {
                    switch method {
                    case .exportThenDelete: step = .export
                    case .deleteDirectly: step = .confirmName
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
    }

    private func radioRow(_ value: Method, _ label: LocalizedStringKey) -> some View {
        Button {
            method = value
        } label: {
            HStack(spacing: 8) {
                Image(systemName: method == value ? "largecircle.fill.circle" : "circle")
                Text(label)
            }
            .foregroundStyle(.primary)
        }
        .buttonStyle(.plain)
    }

    // MARK: - Step2 导出步（C8 参数化，全目标仅加密备份）

    private var exportBody: some View {
        VStack(spacing: 0) {
            ExportView(
                targetVaultDir: model.baseDir
                    .appendingPathComponent(target.vaultUuid, isDirectory: true).path,
                targetVaultName: target.displayName,
                targetVaultMaskedUUID: maskedTargetUUID,
                encryptedOnly: true,
                onExportCompleted: { exportSucceeded = true }
            )
            .environmentObject(model)

            Divider()

            HStack {
                Button("上一步") { step = .chooseMethod }
                Spacer()
                // 导出未成功不得进 Step3（AC-2.10.0-EX-4，强制保数据）；
                // 上一步回 Step1 可改选「直接删除」。
                Button("已导出，继续删除") { step = .confirmName }
                    .buttonStyle(.borderedProminent)
                    .disabled(!exportSucceeded)
            }
            .padding()
        }
    }

    // MARK: - Step3 输入库名确认（UDR-1 trim / UDR-7 masked UUID）

    private var confirmNameBody: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("请输入密码库名称以确认删除：")
                .font(.callout)
            Text("『\(target.displayName)』（\(maskedTargetUUID)）")
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(2)

            TextField("密码库名称", text: $confirmText)
                .textFieldStyle(.roundedBorder)

            // CF-4 就地提示（字面逐字）——输入非空且不匹配时展示，保留重试。
            if !confirmText.isEmpty && !isNameConfirmed {
                Text("与密码库名称不一致，请核对后重试")
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            Spacer()
            HStack {
                Spacer()
                // CF-5：库名匹配（trim 后精确）才可用；destructive 样式。
                Button("确认删除", role: .destructive) { executeDelete() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!isNameConfirmed || model.isBusy)
            }
        }
        .padding()
    }

    // MARK: - Step4 执行

    private var executingBody: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("正在删除密码库…")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 执行删除（AppModel.deleteVault：工厂级 + 先锁旧 + Keychain 双清 + 落位）。
    /// 成功 → Step5；失败 → 回 Step3 留驻可重试（错误经 ffiErrorAlert 呈现，
    /// docs/17 §3.4）。
    private func executeDelete() {
        step = .executing
        Task {
            switch await model.deleteVault(uuid: target.vaultUuid) {
            case .success(let landing):
                step = .done(landing)
            case .failure:
                step = .confirmName
            }
        }
    }

    // MARK: - Step5 完成反馈（D-1.1 成功必反馈 / D-4.1 成功收尾 / D-4.2 必有出口）

    private func doneBody(_ landing: AppModel.DeleteVaultLanding) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("密码库「\(target.displayName)」已删除")
                .font(.headline)
            Text(landingFeedback(landing))
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            HStack {
                Spacer()
                Button("完成") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .padding()
    }

    /// 落位引导文案（docs/16 §4.3 / docs/17 §4.2 Step5）：多库「已切换到
    /// 密码库「名称」，请输入主密码解锁。」/ 单库「将回到建立密码库页面。」
    /// / 删非当前库「已删除，列表已刷新」（`.sessionUnchanged`，无落位文案，
    /// lead 裁定，docs/17 §3.3）。deleteVault 只返回实际发生切换的落位，
    /// 故 switchedToMostRecent 恒对应「已切换」。
    private func landingFeedback(_ landing: AppModel.DeleteVaultLanding) -> LocalizedStringKey {
        switch landing {
        case .switchedToMostRecent(let brief):
            return "已切换到密码库「\(brief.displayName)」，请输入主密码解锁。"
        case .noVault:
            return "将回到建立密码库页面。"
        case .sessionUnchanged:
            return "已删除，列表已刷新。"
        }
    }
}
