// TouchIDSettingsSection.swift —— 统一设置页中的 Touch ID 节
//（docs/09-v0.2实现方案.md §3.7，T06 设置页归位）。
//
// 由原 SecuritySettingsView（docs/08 §7.5）整体抽出为独立 Section，公共行为
// 不变：三态渲染、内联主密码确认、enable/disable 流程与反馈分支全部沿用。
//
// Touch ID 三态渲染（docs/08 §9 T04 验收②，状态由 TouchIDStatus.resolve 判定）：
//   - disabled：「启用 Touch ID 解锁」→ 内联主密码确认（D-6：enable 需主密码
//     重新验证）→ enable 流程（先 Keychain 后 header，D-9）
//   - enabled ：「关闭 Touch ID 解锁」→ 二次确认 → disable 流程（先删 Keychain
//     再改 header，D-9 反向）
//   - stale   ：凭据失效提示 + 「重新启用」入口（同 enable 流程，生成新 K_bio）
//
// enable 反馈三分支（docs/08 §9 T04 验收③）：
//   - 取消：清空输入、退出确认行，无任何状态变更
//   - 密码错 1002：FfiError 文案经 ErrorPresenter 弹窗呈现，确认行保留可重试
//   - Keychain 失败：unexpected OSStatus 文案弹窗，header 未动（D-9 顺序保证）
//
// 降级（docs/08 §8 第一行 / §7.5）：isTouchIDSupported=false 时渲染不可用
// 说明兜底（原工具栏入口按此隐藏；统一设置页常驻可达，故兜底分支保留）。
//
// 呈现细节：主密码确认采用**内联展开**而非嵌套 sheet——错误弹窗（alert）在
// macOS 上无法叠在已呈现的 sheet 之上，内联行让 1002 / Keychain 失败的反馈
// 与确认输入同处一层，避免双重呈现冲突。

import SwiftUI

/// 统一设置页「安全」节：Touch ID 三态（docs/08 §7.5，T06 从原
/// SecuritySettingsView 原样迁入）。
struct TouchIDSettingsSection: View {
    @EnvironmentObject
    private var model: AppModel

    /// 主密码确认行的展开状态（nil = 收起；启用与重新启用共用同一流程）。
    @State private var showPasswordPrompt = false
    /// 关闭功能前的二次确认（docs/08 §7.5：开→关需二次确认）。
    @State private var showDisableConfirm = false
    /// 主密码确认行的临时输入（D-6）：提交即清空，不落任何持久状态。
    @State private var password = ""
    /// enable 慢调用（Argon2id 约 1s）进行中标记。
    @State private var isEnabling = false

    var body: some View {
        Group {
            if model.isTouchIDSupported {
                touchIDSection
            } else {
                // 兜底分支：无 Touch ID 设备直接打开设置页时给出说明。
                // header 用「安全」而非原「Touch ID 解锁」：对齐统一设置页的
                // 节结构命名（本节位于「④ 安全」下），有意变更非笔误。
                Section("安全") {
                    Label("当前设备不支持生物识别解锁。", systemImage: "touchid")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .onAppear { model.refreshTouchIDStatus() }
        .ffiErrorAlert($model.lastErrorMessage)
        .confirmationDialog(
            "关闭 Touch ID 解锁？",
            isPresented: $showDisableConfirm,
            titleVisibility: .visible
        ) {
            Button("关闭 Touch ID 解锁", role: .destructive) {
                Task { await model.disableTouchID() }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("将删除本机保存的解锁凭据并重写密码库。之后需输入主密码解锁。")
        }
    }

    // MARK: - Touch ID 状态节

    @ViewBuilder
    private var touchIDSection: some View {
        Section {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Touch ID 解锁").font(.headline)
                    Text(statusCaption)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                statusActions
            }

            if showPasswordPrompt {
                passwordPromptRow
            }

            if model.touchIDStatus == .stale {
                // stale 态说明（docs/08 §4.1：指纹集变更 → 引导重新启用）
                Label(
                    "生物识别凭据已失效（可能因指纹变更）。重新启用将生成新凭据；在此之前 Touch ID 解锁不可用，请使用主密码解锁。",
                    systemImage: "exclamationmark.triangle"
                )
                .font(.callout)
                .foregroundStyle(.orange)
            }
        } header: {
            Text("安全")
        } footer: {
            Text("Touch ID 只是解锁快捷方式：主密码仍是唯一解锁凭据，遗失后无法找回。")
        }
    }

    /// 状态行说明文案（三态，docs/08 §7.5）。
    private var statusCaption: String {
        switch model.touchIDStatus {
        case .disabled:
            return "已停用——锁定后需输入主密码。"
        case .enabled:
            return "已启用——锁定时可用 Touch ID 快速解锁。"
        case .stale:
            return "凭据已失效（需重新启用）。"
        }
    }

    /// 按态渲染的操作按钮（docs/08 §7.5 / §9 T04）。
    @ViewBuilder
    private var statusActions: some View {
        switch model.touchIDStatus {
        case .disabled, .stale:
            Button(model.touchIDStatus == .disabled ? "启用 Touch ID 解锁" : "重新启用") {
                showPasswordPrompt = true
            }
            .disabled(model.isBusy || showPasswordPrompt)
        case .enabled:
            Button("关闭 Touch ID 解锁", role: .destructive) {
                showDisableConfirm = true
            }
            .disabled(model.isBusy)
        }
    }

    // MARK: - 主密码确认行（D-6）

    private var passwordPromptRow: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("出于安全考虑，主密码不会被保存，请重新输入一次以确认身份。")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack {
                SecureField("主密码", text: $password, prompt: Text("请输入主密码"))
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 220)
                    .onSubmit(confirmEnable)
                if isEnabling {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                Button("取消", role: .cancel) { cancelPrompt() }
                Button(confirmTitle) { confirmEnable() }
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty || isEnabling)
            }
        }
        .padding(.vertical, 4)
    }

    private var confirmTitle: String {
        model.touchIDStatus == .stale ? "重新启用" : "启用"
    }

    private func cancelPrompt() {
        // 取消分支（T04 验收③）：仅收起确认行并清空输入，无任何状态变更
        password = ""
        showPasswordPrompt = false
    }

    private func confirmEnable() {
        guard !password.isEmpty, !isEnabling else { return }
        // 密码不落状态：拷贝进异步调用后立刻清空本地输入（docs/07 §2.4）
        let secret = password
        password = ""
        isEnabling = true
        Task {
            let ok = await model.enableTouchID(password: secret)
            isEnabling = false
            if ok {
                showPasswordPrompt = false
            }
            // 失败（取消 / 1002 密码错 / Keychain 失败）：确认行保留可重试，
            // 错误文案经 lastErrorMessage → ffiErrorAlert 呈现（T04 验收③）
        }
    }
}
