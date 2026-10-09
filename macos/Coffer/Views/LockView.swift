// LockView.swift —— 解锁界面。
//
// 错误提示只按 FfiError code+message 直出（1002 = 密码错 / 数据损坏，不区分）。
//
// Touch ID（docs/08 §7.2 / §9 T04）：isTouchIDSupported ∧ touchIDStatus ==
// .enabled 时显示「使用 Touch ID 解锁」按钮（docs/08 §8 第一行：无 Touch ID
// 设备 / 停用态 / stale 态均无按钮，主密码路径原样）。isBusy 互斥与主密码
// 解锁共用（AppModel 内部统一守卫，本视图再加本地 isUnlocking 防双击）。
//
// 解锁失败退避倒计时（FR-12.5 / T-J）：lockBackoffDeadline 非 nil 时在密码
// 框下方显示剩余秒数（TimelineView 本地倒数，不跨桥），「解锁」按钮禁用——
// 门禁期内强试必得 1002，按钮禁用是 UX 防呆，Rust 门禁（backoff.rs gate）
// 仍是强制层。**Touch ID 按钮不禁用**：unlock_with_biometric 完全豁免退避
//（不门禁也不计数，vault.rs 单测裁定），豁免的意义即密码连续打错的正常
// 用户仍可用生物识别解锁，禁用它反而违背豁免设计。1002 原始弹窗行为不变。
//
// 忘记主密码重置入口（FR-17.1/17.2，docs/31 §4.2）：Touch ID 按钮下方次级
// 按钮「忘记主密码？」→ RecoveryResetSheet（两分支按可用性在 sheet 内
// 显隐，空态由 sheet 自处理——入口不做可用性预判，避免死胡同由 sheet 呈现）。

import SwiftUI

struct LockView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var password = ""
    @State private var isUnlocking = false
    /// 忘记主密码重置 sheet 呈现开关（FR-17.1/17.2，docs/31 §4.2）。
    @State private var showRecoveryReset = false

    /// Touch ID 按钮显隐（docs/08 §8 降级矩阵）：设备支持 ∧ 功能已启用。
    /// stale 态不显示——Touch ID 必然失败（4002），直接引导主密码。
    private var showTouchIDButton: Bool {
        model.isTouchIDSupported && model.touchIDStatus == .enabled
    }

    /// 退避门禁期内（FR-12.5）：仅禁用主密码解锁（onSubmit 同防）。
    /// Touch ID 不受影响——unlock_with_biometric 豁免退避（vault.rs 裁定），
    /// 门禁期恰是正常用户改用生物识别的窗口，禁用即违背豁免设计。
    /// 非 nil 即禁用（剩余秒数归零时 AppModel 会清 nil，见 TimelineView）。
    private var isBackoffBlocked: Bool {
        model.lockBackoffDeadline != nil
    }

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "lock.circle")
                .font(.system(size: 52))
                .foregroundStyle(.secondary)
            Text(model.vaultName.isEmpty ? "密码库已锁定" : model.vaultName)
                .font(.title2.bold())

            SecureField("主密码", text: $password, prompt: Text("请输入主密码"))
                .textFieldStyle(.roundedBorder)
                .frame(width: 280)
                .onSubmit(unlock)

            // 退避倒计时条（FR-12.5）：仅在门禁期内挂载（deadline 非 nil），
            // 每秒本地倒数——剩余秒数已在 1002 时读一次 FFI 换算成截止
            // 时刻，这里不再轮询。归零即异步清 deadline：按钮恢复可用、
            // 本视图整体卸载（TimelineView 不常驻计时）。
            if model.lockBackoffDeadline != nil {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    backoffCountdown(at: context.date)
                }
            }
            if isUnlocking {
                ProgressView {
                    Text("正在解锁…（Argon2id 密钥派生约需 1 秒）")
                }
            } else {
                VStack(spacing: 10) {
                    Button("解锁") { unlock() }
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty || isBackoffBlocked)
                    if showTouchIDButton {
                        Button {
                            unlockWithTouchID()
                        } label: {
                            Label("使用 Touch ID 解锁", systemImage: "touchid")
                        }
                        .buttonStyle(.bordered)
                        // 仅 isUnlocking：门禁期不禁用 Touch ID（豁免裁定，
                        // 见本文件头注释）——bio 解锁成功即清退避
                        .disabled(isUnlocking)
                    }
                    // 忘记主密码入口（FR-17.1/17.2，docs/31 §4.2）：Touch ID
                    // 按钮下方次级形态；点击呈现 RecoveryResetSheet（两分支
                    // 按可用性在 sheet 内显隐，空态由 sheet 自处理——入口
                    // 不做可用性预判，避免死胡同由 sheet 呈现文案引导）。
                    Button("忘记主密码？") { showRecoveryReset = true }
                        .buttonStyle(.bordered)
                        .disabled(isUnlocking)
                }
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .ffiErrorAlert($model.lastErrorMessage)
        .sheet(isPresented: $showRecoveryReset) {
            RecoveryResetSheet()
        }
    }

    /// 倒计时条内容（TimelineView 每秒求值）：剩余 > 0 显示提示；归零时
    /// 经 `.task(id:)` 清 deadline（不在视图更新周期内直接改 @Published），
    /// 复核逻辑在 AppModel.clearBackoffIfExpired——清 nil 后本视图整体
    /// 卸载，按钮恢复可用。
    @ViewBuilder
    private func backoffCountdown(at date: Date) -> some View {
        if let deadline = model.lockBackoffDeadline {
            let remaining = max(0, Int(deadline.timeIntervalSince(date)))
            Group {
                if remaining > 0 {
                    Label("尝试次数过多，\(remaining) 秒后再试",
                          systemImage: "clock.badge.exclamationmark")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
            }
            .task(id: remaining) {
                if remaining == 0 {
                    model.clearBackoffIfExpired()
                }
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty, !isUnlocking, !isBackoffBlocked else { return }
        // 主密码不落状态：拷贝进异步调用后立刻清空本地输入。
        let secret = password
        password = ""
        isUnlocking = true
        Task {
            await model.unlock(password: secret)
            isUnlocking = false
        }
    }

    /// Touch ID 解锁（docs/08 §7.2 时序；编排细节在 AppModel.unlockWithTouchID）。
    /// isBusy 互斥与主密码解锁共用：AppModel 内部 guard isBusy；本地
    /// isUnlocking 兜底防双击。退避门禁期内同样防呆（Rust 侧 bio 豁免
    /// 门禁，禁用只为界面一致性——主密码被门禁时单开 Touch ID 通道易困惑）。
    private func unlockWithTouchID() {
        guard !isUnlocking, !isBackoffBlocked else { return }
        isUnlocking = true
        Task {
            await model.unlockWithTouchID()
            isUnlocking = false
        }
    }
}
