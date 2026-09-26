// LockView.swift —— 解锁界面。
//
// 错误提示只按 FfiError code+message 直出（1002 = 密码错 / 数据损坏，不区分）。
//
// Touch ID（docs/08 §7.2 / §9 T04）：isTouchIDSupported ∧ touchIDStatus ==
// .enabled 时显示「使用 Touch ID 解锁」按钮（docs/08 §8 第一行：无 Touch ID
// 设备 / 停用态 / stale 态均无按钮，主密码路径原样）。isBusy 互斥与主密码
// 解锁共用（AppModel 内部统一守卫，本视图再加本地 isUnlocking 防双击）。

import SwiftUI

struct LockView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var password = ""
    @State private var isUnlocking = false

    /// Touch ID 按钮显隐（docs/08 §8 降级矩阵）：设备支持 ∧ 功能已启用。
    /// stale 态不显示——Touch ID 必然失败（4002），直接引导主密码。
    private var showTouchIDButton: Bool {
        model.isTouchIDSupported && model.touchIDStatus == .enabled
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

            if isUnlocking {
                ProgressView {
                    Text("正在解锁…（Argon2id 密钥派生约需 1 秒）")
                }
            } else {
                VStack(spacing: 10) {
                    Button("解锁") { unlock() }
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty)
                    if showTouchIDButton {
                        Button {
                            unlockWithTouchID()
                        } label: {
                            Label("使用 Touch ID 解锁", systemImage: "touchid")
                        }
                        .buttonStyle(.bordered)
                        .disabled(isUnlocking)
                    }
                }
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .ffiErrorAlert($model.lastErrorMessage)
    }

    private func unlock() {
        guard !password.isEmpty, !isUnlocking else { return }
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
    /// isUnlocking 兜底防双击。
    private func unlockWithTouchID() {
        guard !isUnlocking else { return }
        isUnlocking = true
        Task {
            await model.unlockWithTouchID()
            isUnlocking = false
        }
    }
}
