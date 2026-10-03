// CrossCopySheet.swift —— 跨库复制 sheet（v0.4 FR-2.10，MB-2）。
//
// 流程（docs/15 §3.2.3）：选目标库（排除当前库，UI 层禁止选当前库，
// §3.2.2 同口径）→ 目标库锁定则内嵌解锁步骤（目标库主密码，或目标库已
// 启用 Touch ID 时走 unlockWithBiometric——K_bio 按 vault_uuid 取，天然
// 正确）→ copyItem → 成功页显示新条目所在库 → 立即 lock() 目标会话
// （复制即锁，单活跃会话不变量回归）。
//
// 失败语义（§3.2.3）：解锁失败 1002 留在解锁步（可重试）；复制失败
// 1001/1011/5002 经 ErrorPresenter 呈现（lastErrorMessage，不经
// handleFfiError——1001 在此可能指目标库被锁，不应把源库 UI 切回锁定态），
// 目标会话立即 lock() 回归不变量后回到选库步，源库数据零影响。
//
// 状态自持（docs/15 §6.1 S2 切片：AppModel 零改动）：目标会话是本 sheet
// 的局部状态，不经 AppModel（单活跃「解锁」会话始终是 AppModel.session）。
//
// UI 纪律（docs/07 §2.4）：显式关闭出口 + .cancelAction；慢调用（目标库
// Argon2id 解锁 + copyItem）Task.detached 包裹。

import AppKit
import SwiftUI

struct CrossCopySheet: View {
    @EnvironmentObject
    private var model: AppModel

    @Environment(\.dismiss)
    private var dismiss

    /// 源条目 ID（当前会话内）。
    let sourceItemId: String
    /// 源条目标题（仅展示）。
    let sourceTitle: String

    // MARK: - 步骤状态机

    enum Step: Equatable {
        /// 选目标库。
        case pickTarget
        /// 目标库已打开（锁定态），内嵌解锁。
        case unlockTarget(vaultName: String)
        /// 复制执行中。
        case copying(targetName: String)
        /// 复制成功。
        case done(newItemUUID: String, targetName: String)
    }

    @State private var step: Step = .pickTarget
    /// 目标会话（锁定态打开，解锁 → 复制 → 即锁；sheet 任何出口兜底 lock）。
    @State private var targetSession: VaultSession?
    /// 目标库 UUID（打开目标会话时记录，与 targetSession 同生命周期）。
    @State private var targetVaultUUID: String?
    @State private var password = ""
    @State private var isBusy = false
    /// 步内错误（解锁失败 1002 留在解锁步呈现，不清空已输入流程）。
    @State private var localError: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("复制到其他库").font(.headline)
                Spacer()
                // 显式关闭出口（docs/07 §2.4 BUG-3/5 条款）：复制执行中
                // 禁用——中途关闭会丢结果页（copyItem 幂等，无数据风险，
                // 同 ImportView 单事务纪律）。
                Button("关闭") { close() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isCopying)
            }
            .padding()

            Divider()

            Group {
                switch step {
                case .pickTarget:
                    pickTargetBody
                case .unlockTarget(let targetName):
                    unlockBody(targetName)
                case .copying(let targetName):
                    VStack(spacing: 12) {
                        ProgressView()
                        Text("正在复制到「\(targetName)」…")
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                case .done(let newItemUUID, let targetName):
                    doneBody(newItemUUID, targetName: targetName)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding()
        }
        .frame(width: 480, height: 380)
        .onAppear {
            model.reloadVaultBriefs()
        }
        .onDisappear {
            // 兜底：任何出口（含 Esc / 相变拆树）都锁目标会话，复制即锁
            // 不依赖用户走「关闭」按钮（幂等，已锁再锁无害）。
            lockTargetSession()
        }
        .ffiErrorAlert($model.lastErrorMessage)
        .alert("解锁失败", isPresented: Binding(
            get: { localError != nil },
            set: { if !$0 { localError = nil } }
        )) {
            Button("好", role: .cancel) {}
        } message: {
            Text(localError ?? "")
        }
    }

    /// 是否复制执行中（关闭按钮禁用判据）。
    private var isCopying: Bool {
        if case .copying = step { return true }
        return false
    }

    // MARK: - 目标库过滤（纯函数，独立单测）

    /// 目标库候选 = 全部库排除当前库（docs/15 §3.2.2「UI 层禁止选择当前
    /// 库」；保持传入顺序，供列表稳定展示）。
    static func targetBriefs(_ briefs: [FfiVaultBrief], excluding currentUUID: String) -> [FfiVaultBrief] {
        briefs.filter { $0.vaultUuid != currentUUID }
    }

    // MARK: - 选库步

    private var pickTargetBody: some View {
        let targets = Self.targetBriefs(model.vaultBriefs, excluding: model.vaultUUID)
        return VStack(spacing: 12) {
            Text("将「\(sourceTitle)」复制到哪座库？目标库产生新条目，源条目原样保留。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            if targets.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "vault")
                        .font(.system(size: 36))
                        .foregroundStyle(.secondary)
                    Text("没有其他密码库").font(.headline)
                    Text("可从工具栏库切换器中新建一座库后再复制。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(targets, id: \.vaultUuid) { brief in
                    Button {
                        openTarget(brief)
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: "vault")
                                .foregroundStyle(.tint)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(brief.displayName).lineLimit(1)
                                Text(verbatim: brief.vaultUuid)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .buttonStyle(.plain)
                }
                .listStyle(.plain)
            }
        }
    }

    // MARK: - 解锁步

    /// 目标库是否可用 Touch ID（header 启用 + Keychain 项存在；纯读，
    /// 与 AppModel.refreshTouchIDStatus 同判定源）。
    private func targetBiometricStatus(_ target: VaultSession, targetUUID: String) -> TouchIDStatus {
        TouchIDStatus.resolve(
            headerWrapAvailable: target.hasBiometricWrap(),
            keychainItemExists: BiometricKeychain().itemExists(vaultUUID: targetUUID),
            sessionOpen: true
        )
    }

    private func unlockBody(_ targetName: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "lock")
                .font(.system(size: 40))
                .foregroundStyle(.tint)
            Text("解锁「\(targetName)」").font(.title3.bold())
            Text("复制前需解锁目标库；解锁后的会话只在复制期间使用，完成即锁。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            SecureField("目标库主密码", text: $password, prompt: Text("请输入目标库主密码"))
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)
                .onSubmit(unlockWithPassword)

            if isBusy {
                ProgressView {
                    Text("正在解锁…（密钥派生约需 1 秒）")
                }
            }

            HStack(spacing: 12) {
                // 目标库已启用 Touch ID → 生物识别入口（K_bio 按
                // vault_uuid 取，天然定位目标库凭据，docs/15 §3.2.3）
                if let target = targetSession, let targetUUID = targetVaultUUID,
                   targetBiometricStatus(target, targetUUID: targetUUID) == .enabled {
                    Button {
                        unlockWithBiometric()
                    } label: {
                        Label("Touch ID", systemImage: "touchid")
                    }
                    .disabled(isBusy)
                }
                Button("解锁并复制") {
                    unlockWithPassword()
                }
                .buttonStyle(.borderedProminent)
                .disabled(password.isEmpty || isBusy)
            }
        }
        .padding(28)
    }

    // MARK: - 成功页

    private func doneBody(_ newItemUUID: String, targetName: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("已复制到「\(targetName)」").font(.title3.bold())
            Text("源条目原样保留；目标库新条目 UUID：")
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(verbatim: newItemUUID)
                .font(.caption)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
                .padding(8)
                .background(RoundedRectangle(cornerRadius: 6).fill(.quaternary))
            Button("完成") { close() }
                .buttonStyle(.borderedProminent)
        }
        .padding(28)
    }

    // MARK: - 动作

    /// 打开目标会话（openVault 只读 header 不做 KDF，快路径，与
    /// AppModel.switchVault 同口径；失败 → lastErrorMessage 留在选库步）。
    private func openTarget(_ brief: FfiVaultBrief) {
        guard !isBusy else { return }
        do {
            let opened = try model.factory.openVault(baseDir: model.baseDir.path,
                                                     vaultUuid: brief.vaultUuid)
            targetSession = opened
            targetVaultUUID = brief.vaultUuid
            password = ""
            step = .unlockTarget(vaultName: brief.displayName)
        } catch {
            model.lastErrorMessage = ErrorPresenter.text(error)
        }
    }

    /// 目标库主密码解锁（Argon2id 慢调用，Task.detached）→ 成功即复制。
    /// 密码只作参数传入，拷贝进 Task 闭包用后即弃，不落任何属性。
    private func unlockWithPassword() {
        guard let target = targetSession, !isBusy, !password.isEmpty else { return }
        let secret = password
        password = ""
        runTargetUnlock {
            _ = try target.unlock(password: secret) // 返回 FfiVaultInfo，复制页无需
        }
    }

    /// 目标库 Touch ID 解锁：Keychain 自有单次认证（read 带全新 LAContext +
    /// localizedReason，弹窗即认证——与 AppModel.unlockWithTouchID 完全同构，
    /// docs/08 §7.2；此为局部实现——AppModel 的同名编排绑定当前会话，S2 切片
    /// 不改 AppModel）→ FFI unlockWithBiometric → 复制页。
    ///
    /// PL-5 修复：删除本 sheet 侧 evaluatePolicy 预认证——旧路径「预认证 +
    /// read 再认证」在 macOS 26 上稳定双弹（KNOWN-ISSUES PL-5），删除后
    /// Keychain read 成为唯一弹窗（弹窗次数 = 1，与主解锁路径同构）。
    /// 错误呈现同步改由 read 的错误分道驱动（取消静默 / 瞬时温和 / 持久 4002，
    /// 见 presentUnlockBiometricError）。
    private func unlockWithBiometric() {
        guard let target = targetSession, let targetUUID = targetVaultUUID, !isBusy else { return }
        isBusy = true
        Task {
            do {
                // 认证即弹窗（read 自带全新 LAContext + localizedReason）；
                // 读取失败 → 4002 降级文案（docs/08 §4.1），不改目标库 header
                let kBio = try BiometricKeychain().read(vaultUUID: targetUUID)
                try await Task.detached(priority: .userInitiated) {
                    _ = try target.unlockWithBiometric(kBio: kBio) // 返回 FfiVaultInfo，复制页无需
                }.value
                startCopy()
            } catch {
                presentUnlockBiometricError(error)
            }
            isBusy = false
        }
    }

    /// 解锁成功后的公共续段：切复制页 → 慢调用 copyItem → 即锁目标会话。
    private func startCopy() {
        guard let src = model.session, let target = targetSession,
              let targetUUID = targetVaultUUID, let brief = model.vaultBriefs.first(where: { $0.vaultUuid == targetUUID })
        else {
            presentStepError("内部错误：目标会话状态缺失，已取消复制。")
            lockTargetSession()
            step = .pickTarget
            return
        }
        let targetName = brief.displayName
        step = .copying(targetName: targetName)
        let itemId = sourceItemId
        Task.detached(priority: .userInitiated) {
            // copyItem：src/dst 锁定 → 1001；src 条目不存在 → 1011；
            // 校验失败 → 5002（docs/15 §3.2.2 契约）。
            let result = Result { try src.copyItem(itemId: itemId, dst: target) }
            // 复制即锁（§3.2.3）：成功或失败都立即锁目标会话——
            // 单活跃会话不变量回归不依赖后续 UI 路径。
            target.lock()
            await MainActor.run {
                switch result {
                case .success(let newUUID):
                    step = .done(newItemUUID: newUUID, targetName: targetName)
                case .failure(let error):
                    // 源库数据零影响（内核 Err 路径孤儿清理已有测试）；
                    // 经 lastErrorMessage 呈现，回选库步可重试
                    model.lastErrorMessage = ErrorPresenter.text(error)
                    step = .pickTarget
                }
            }
        }
    }

    /// 目标库解锁编排公共体：busy 标记 + Task.detached（Argon2id 约 1s）
    /// → 成功 startCopy；失败呈现于解锁步（1002 留在解锁步，§3.2.3）。
    private func runTargetUnlock(_ unlock: @escaping () throws -> Void) {
        isBusy = true
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try unlock()
                }.value
                startCopy()
            } catch {
                presentStepError(ErrorPresenter.text(error))
            }
            isBusy = false
        }
    }

    /// 步内错误（解锁失败 1002 / Keychain 4002 等）：呈现后留在当前步，
    /// 不经 lastErrorMessage（避免与复制步错误混流），不推进状态机。
    private func presentStepError(_ text: String) {
        DiagLog.append(text)
        localError = text
    }

    /// 目标库 Touch ID 解锁错误呈现——与 AppModel.unlockWithTouchID 同一分道
    /// （TouchIDUnlockPresentation.resolve，docs/08 §7.3/§7.6，PL-5/PL-7）：
    ///   - 用户取消 → 静默（不写 localError，避免空白「解锁失败」框）
    ///   - authFailed 瞬时（isBiometricsAvailable=false）→ 温和文案
    ///   - itemNotFound / authFailed 持久 → 4002
    ///   - 其余（unexpected / FfiError 1002 等）→ ErrorPresenter.text 照常
    /// 均留在解锁步可重试（§3.2.3）。
    private func presentUnlockBiometricError(_ error: Error) {
        switch TouchIDUnlockPresentation.resolve(
            error: error,
            biometryAvailable: BiometricKeychain.isBiometricsAvailable()
        ) {
        case .silent:
            DiagLog.append("CrossCopy 目标库 Touch ID 解锁已取消（用户取消认证，静默，docs/08 §7.6）")
        case .text(let text):
            presentStepError(text)
        case .fallback:
            presentStepError(ErrorPresenter.text(error))
        }
    }

    /// 锁定目标会话并清引用（复制即锁兜底；幂等）。
    private func lockTargetSession() {
        targetSession?.lock()
        targetSession = nil
        targetVaultUUID = nil
    }

    /// 关闭 sheet（显式出口 + 成功页「完成」共用）。目标会话锁由
    /// onDisappear 兜底，这里只推进 dismiss。
    private func close() {
        dismiss()
    }
}
