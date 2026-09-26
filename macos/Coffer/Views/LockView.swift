// LockView.swift —— 解锁界面。
//
// 错误提示只按 FfiError code+message 直出（1002 = 密码错 / 数据损坏，不区分）。

import SwiftUI

struct LockView: View {
    @EnvironmentObject
    private var model: AppModel

    @State private var password = ""
    @State private var isUnlocking = false

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
                Button("解锁") { unlock() }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty)
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
}
