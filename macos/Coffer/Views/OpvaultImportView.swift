// OpvaultImportView.swift —— OPVault 导入向导（FR-7.3，v0.7.0-T06）：
// 选目录 → 输入密码 → 结构预检 → 导入 → 结果页。
//
// 流程（docs/22 §2.2.3 预检语义 + docs/23 §1.2 TC-OPV-05/07）：
//   ① 选目录（NSOpenPanel，目录多选禁）：opvault 根目录；
//   ② 输入密码：1Password 主密码（UTF-8 原始字节进 PBKDF2，Rust 侧契约）；
//   ③ 结构预检 precheck_opvault：只读、**不触密码**、锁定态可预检——
//      只读目录结构 + profile.js 元数据 + KDF 参数读数（TC-OPV-05）。
//      **语义偏差必须显式标注**：结构预检不验证密码正确性，完整报告
//      （条目数 / 分类分布）需密码，由 import_opvault 解密后产出——
//      因此本页只呈现结构字段，不展示条目计数；
//   ④ 导入 import_opvault：密码错 / 数据损坏 → **2002，all-or-nothing
//      零落库**（TC-OPV-03/04，解密映射先于写入完成，失败不落任何条目）。
//      2002 在导入步经 ErrorPresenter 呈现，回密码页重试重输密码；
//   ⑤ 结果页：新建条目数 + 未导入清单（TC-OPV-11）+ 附件跳过计数
//      （out-of-scope，TC-OPV-10）。
//
// 与 CSV/1PUX 导入的关键差异（文案必须如实）：
//   - OPVault 导入是 **all-or-nothing**（任一解密/映射失败 → 2002，零落库），
//     与 CSV import_csv 同纪律，**非** 1PUX/Bitwarden 的每条目独立事务——
//     失败错误文案不得声称「部分条目可能已导入」。
//   - 预检是**结构层**预检（不触密码），与 CSV/1PUX 的完整预检语义不同，
//     偏差在本向导内显式标注（TC-OPV-05）。
//
// 密码纪律（docs/07 §2.4 主密码同源延伸）：opvault 主密码只作方法参数
// 传入，@State 仅为输入框暂存，导入发起时捕获即弃清空（LockView 同纪律）；
// 失败回密码页重输，不在任意步骤间保留。

import SwiftUI
import UniformTypeIdentifiers

struct OpvaultImportView: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    enum Step {
        /// 选 opvault 目录。
        case pickDirectory
        /// 输入 1Password 主密码。
        case password(path: String)
        /// 结构预检报告（不触密码；语义偏差显式标注）。
        case precheck(report: FfiOpvaultPrecheckReport, path: String)
        /// 导入中（all-or-nothing）。
        case importing(path: String)
        /// 结果页。
        case done(result: FfiOpvaultImportResult, path: String)
    }

    @State private var step: Step = .pickDirectory
    /// opvault 主密码输入暂存：导入发起时捕获即弃清空（见 doImport）。
    @State private var password = ""
    /// 结构预检失败的错误文案（未发生任何导入）用本地 alert，回选目录可重试。
    @State private var precheckError: String?

    /// 导入执行中（关闭按钮此时禁用，防丢结果页；导入 all-or-nothing，
    /// 失败零落库，中途关 sheet 仅丢结果页与报告，无数据风险）。
    private var isImporting: Bool {
        if case .importing = step { return true }
        return false
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("导入 1Password（OPVault）").font(.headline)
                Spacer()
                // 显式关闭出口（BUG-5 同类修复）：macOS sheet 点外部不关闭、
                // 无按钮时 Esc 无效。导入执行中禁用（同 1PUX/Bitwarden 纪律）。
                Button("关闭") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isImporting)
            }
            .padding()

            Divider()

            Group {
                switch step {
                case .pickDirectory:
                    pickDirectoryBody
                case .password(let path):
                    passwordBody(path: path)
                case .precheck(let report, let path):
                    precheckBody(report, path: path)
                case .importing:
                    importingBody
                case .done(let result, let path):
                    doneBody(result, path: path)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
        .frame(width: 560, height: 540)
        .alert("预检失败", isPresented: Binding(
            get: { precheckError != nil },
            set: { if !$0 { precheckError = nil } }
        )) {
            Button("好", role: .cancel) { step = .pickDirectory }
        } message: {
            Text(precheckError ?? "")
        }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: - ① 选目录

    private var pickDirectoryBody: some View {
        VStack(spacing: 16) {
            Image(systemName: "folder")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("选择 1Password OPVault 目录")
                .font(.callout)
            Text("OPVault 是 1Password 旧版（vault 格式）的目录归档，需输入 1Password 主密码导入。\n导入为 all-or-nothing：密码错或数据损坏不会写入任何条目。")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("选择目录…") { pickDirectory() }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func pickDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.message = "选择包含 default/profile.js 的 OPVault 根目录"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        step = .password(path: url.path)
    }

    // MARK: - ② 输入密码

    private func passwordBody(path: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("输入 1Password 主密码").font(.headline)
            Text(URL(fileURLWithPath: path).path)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .truncationMode(.middle)
            SecureField("1Password 主密码", text: $password, prompt: Text("请输入 OPVault 主密码"))
                .textFieldStyle(.roundedBorder)
            Text("结构预检不校验密码是否正确（见下一步），密码用于导入时解密条目。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            HStack {
                Button("取消") { step = .pickDirectory }
                Spacer()
                Button("预检") { runPrecheck(path: path) }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || model.isBusy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 结构预检（precheck_opvault，只读、不触密码，TC-OPV-05）：校验目录
    /// 确实是 OPVault（缺 profile.js → 2001，TC-OPV-06）并读取结构字段。
    /// 同步调用即可（纯文件只读快路径；与 CSV/1PUX 预检同纪律）。
    private func runPrecheck(path: String) {
        do {
            let report = try sessionCall { try $0.precheckOpvault(path: path) }
            step = .precheck(report: report, path: path)
        } catch {
            precheckError = ErrorPresenter.text(error)
        }
    }

    // MARK: - ③ 结构预检报告（TC-OPV-05 语义偏差显式标注）

    private func precheckBody(_ report: FfiOpvaultPrecheckReport, path: String) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("结构预检").font(.headline)
                Spacer()
                Text(URL(fileURLWithPath: path).lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    // 语义偏差显式标注（TC-OPV-05）：结构预检不触密码，
                    // 完整报告（条目/分类分布）需导入后产出
                    Label("结构预检未验证密码：仅检查目录结构与 profile 元数据；条目数、分类分布等完整报告需导入后才能呈现（密码是否正确也在此步无法得知）。",
                          systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.leading)

                    HStack(spacing: 24) {
                        statLabel("Profile", report.profileName)
                        statLabel("KDF 迭代", "\(report.iterations)")
                        statLabel("band 文件", "\(report.bandFileCount)")
                        statLabel("附件", "\(report.attachmentCount)")
                    }
                    .font(.callout)

                    if let hint = report.passwordHint, !hint.isEmpty {
                        Text("密码提示：\(hint)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if !report.otherProfiles.isEmpty {
                        Text("其他 profile（不导入）：\(report.otherProfiles.joined(separator: "、"))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if report.attachmentCount > 0 {
                        Text("检测到附件 \(report.attachmentCount) 个，本版 out-of-scope，导入时跳过并计数。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(report.warnings, id: \.self) { warning in
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Button("返回改密码") { step = .password(path: path) }
                Spacer()
                Button("开始导入") { doImport(path: path) }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || model.isBusy)
            }
        }
    }

    private func statLabel(_ title: String, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    // MARK: - ④ 导入（all-or-nothing；2002 密码错/数据损坏在导入步呈现）

    private var importingBody: some View {
        VStack(spacing: 12) {
            ProgressView()
            // 如实反映 all-or-nothing：任一解密/映射失败 → 2002，零落库
            Text("正在导入（解密 + 逐条目写入，全部成功或全部回滚）…")
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// OPVault 导入（需解锁态：锁定态 Rust 返回 1001；写路径较慢，
    /// Task.detached 包裹）。密码捕获即弃清空（LockView 同纪律）。
    /// 唯一调用点：结构预检页「开始导入」。
    /// 失败（2002 等）回密码页重输——all-or-nothing，零落库（TC-OPV-03/04），
    /// 无需「部分条目可能已导入」提示。
    private func doImport(path: String) {
        let session = model.session
        let vaultDir = model.vaultDirPath
        // 防御：入口按钮已按 password.isEmpty 禁用，此处兜底（不进 importing 态）
        guard !password.isEmpty else { return }
        let secret = password
        password = ""
        step = .importing(path: path)
        Task.detached(priority: .userInitiated) {
            do {
                let result = try session?.importOpvault(path: path, password: secret, vaultDir: vaultDir)
                await MainActor.run {
                    if let result {
                        step = .done(result: result, path: path)
                        model.reloadItems()
                    } else {
                        // 会话缺失（理论不可达：入口在解锁区）；无导入发生
                        step = .password(path: path)
                        model.lastErrorMessage = "会话不存在。"
                    }
                }
            } catch {
                await MainActor.run {
                    // 错误纪律：落 DiagLog + lastErrorMessage → .ffiErrorAlert。
                    // 2002（密码错或数据损坏）/ 1001（锁定）/ 6002/6003（只读
                    // 拒绝，TC-OPV-07）经 ErrorPresenter 直出；回密码页重输重试。
                    DiagLog.append(ErrorPresenter.text(error))
                    model.lastErrorMessage = ErrorPresenter.text(error)
                    step = .password(path: path)
                }
            }
        }
    }

    // MARK: - ⑤ 结果页（成功计数 + 未导入清单 + 附件跳过计数）

    private func doneBody(_ result: FfiOpvaultImportResult, path: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("导入完成：新建 \(result.importedItems) 条条目")
                .font(.headline)

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    // 附件 out-of-scope（TC-OPV-10）：跳过并计数，不静默
                    if result.report.attachmentCount > 0 {
                        Text("附件 \(result.report.attachmentCount) 个已跳过（本版不导入）。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    if result.report.trashedItems > 0 {
                        Text("回收站条目 \(result.report.trashedItems) 条（按归档态导入）。")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }

                    // 未导入项逐条列出（TC-OPV-11：Tombstone 等不静默）
                    if !result.report.notImported.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Label("未导入 \(result.report.notImported.count) 条", systemImage: "xmark.circle")
                                .font(.callout)
                                .foregroundStyle(.orange)
                            ForEach(result.report.notImported, id: \.uuid) { item in
                                HStack(alignment: .top, spacing: 6) {
                                    Text(item.title.isEmpty ? "（无标题）" : item.title)
                                        .font(.caption)
                                        .lineLimit(1)
                                    if !item.title.isEmpty {
                                        Text(String(item.uuid.suffix(8)))
                                            .font(.caption.monospacedDigit())
                                            .foregroundStyle(.tertiary)
                                    }
                                    Spacer()
                                }
                                Text(item.reason)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    ForEach(result.report.warnings, id: \.self) { warning in
                        Label(warning, systemImage: "info.circle")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Text(URL(fileURLWithPath: path).path)
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .lineLimit(2)
                .truncationMode(.middle)
            HStack {
                Spacer()
                Button("完成") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    // MARK: - 辅助

    private func sessionCall<R>(_ action: (VaultSession) throws -> R) throws -> R {
        guard let session = model.session else {
            throw FfiError.Coffer(code: 1001, message: "会话不存在")
        }
        return try action(session)
    }
}
