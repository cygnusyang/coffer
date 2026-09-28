// SettingsView.swift —— 统一设置页（docs/09-v0.2实现方案.md §3.7，T06 设置页归位）。
//
// 原先散落在 MainView 工具栏（自动锁定 Picker）与 SecuritySettingsView
// sheet（Touch ID）的设置项统一归位到本页，按节组织：
//   ① 通用：自动锁定超时（原 MainView 工具栏 autoLockMenu 迁入）
//   ② 剪贴板：自动清除档位（T06 / FR-14.2）
//   ③ 备份提醒：提醒间隔档位（FR-8.5；评估逻辑 T-G 接入）
//   ④ 安全：Touch ID 三态节（原样迁入 TouchIDSettingsSection）
//     + 「修改主密码…」入口（sheet 占位，T-D 接入）
//   ⑤ 数据：「从备份恢复…」「审计日志…」占位（T-H / T-I 接入）
//   ⑥ 完成：显式退出（原 SecuritySettingsView BUG-3 修正沿用）
//
// 档位哨兵语义（三者互不相同，勿混淆）：
//   - autoLockMinutes：0 = 从不（运行态；落盘为 -1，见 AppModel）
//   - clipboardClearSecs：0 = 从不（落盘同值）
//   - backupReminderDays：0 = 禁用提醒（落盘同值）

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject
    private var model: AppModel

    /// 关闭本 sheet（BUG-3：显式退出口，任何状态下都能离开本页）。
    @Environment(\.dismiss)
    private var dismiss

    /// 「修改主密码」sheet（占位，T-D 替换为完整改密流程）。
    @State private var showChangePassword = false
    /// 「从备份恢复」sheet（占位，T-H 接入加密备份恢复流程）。
    @State private var showRestore = false
    /// 「审计日志」sheet（占位，T-I 接入 FR-12.6 审计日志查看）。
    @State private var showAuditLog = false

    var body: some View {
        NavigationStack {
            Form {
                generalSection
                clipboardSection
                backupReminderSection
                securitySection
                dataSection
                doneSection
            }
            .formStyle(.grouped)
            .navigationTitle("设置")
        }
        // 宽度固定、高度自适应（节内容随 Touch ID 内联确认行等动态展开）
        .frame(width: 480)
        .sheet(isPresented: $showChangePassword) {
            // 占位视图：T-D 替换为修改主密码流程（旧密码重验证 + 新密码 zxcvbn 门禁）
            placeholderSheet(title: "修改主密码", taskTag: "T-D")
        }
        .sheet(isPresented: $showRestore) {
            // 占位视图：T-H 替换为加密备份恢复流程（FR-8.1）
            placeholderSheet(title: "从备份恢复", taskTag: "T-H")
        }
        .sheet(isPresented: $showAuditLog) {
            // 占位视图：T-I 替换为审计日志查看（FR-12.6）
            placeholderSheet(title: "审计日志", taskTag: "T-I")
        }
    }

    // MARK: - ① 通用（自动锁定，原 MainView 工具栏迁入）

    private var generalSection: some View {
        Section {
            Picker(selection: $model.autoLockMinutes) {
                ForEach(AppModel.autoLockOptions, id: \.self) { minutes in
                    Text(minutes == 0 ? "从不" : "\(minutes) 分钟").tag(minutes)
                }
            } label: {
                Label("自动锁定", systemImage: "timer")
            }
        } header: {
            Text("通用")
        } footer: {
            Text("空闲超过所选时长后自动锁定密码库；锁定屏幕 / 休眠 / 屏保时立即锁定。")
        }
    }

    // MARK: - ② 剪贴板（FR-14.2 五档）

    /// 选择器数据源：Rust 侧档位表 + 「从不」（0，恒排最后）。
    /// 档位经 FFI 取（clipboardClearTiers），与 Rust 校验同一来源，勿硬编码。
    private var clipboardClearOptions: [Int] {
        clipboardClearTiers().map { Int($0) } + [0]
    }

    private var clipboardSection: some View {
        Section {
            Picker(selection: $model.clipboardClearSecs) {
                ForEach(clipboardClearOptions, id: \.self) { secs in
                    Text(secs == 0 ? "从不" : "\(secs) 秒").tag(secs)
                }
            } label: {
                Label("复制后自动清除", systemImage: "doc.on.doc")
            }
        } header: {
            Text("剪贴板")
        } footer: {
            // 默认档位经 FFI 取（defaultClipboardClearSecs），勿硬编码
            Text("复制的敏感内容在所选时长后自动从剪贴板清除；期间你复制了别的内容则不动。默认 \(Int(defaultClipboardClearSecs())) 秒。")
        }
    }

    // MARK: - ③ 备份提醒（FR-8.5；评估逻辑 T-G 接入）

    private var backupReminderSection: some View {
        Section {
            Picker(selection: $model.backupReminderDays) {
                ForEach(AppModel.backupReminderOptions, id: \.self) { days in
                    Text(days == 0 ? "禁用" : "每 \(days) 天").tag(days)
                }
            } label: {
                Label("备份提醒间隔", systemImage: "bell")
            }
        } header: {
            Text("备份提醒")
        } footer: {
            Text("距上次备份超过所选天数时提醒你备份密码库；选择「禁用」关闭提醒。")
        }
    }

    // MARK: - ④ 安全（Touch ID 原样迁入 + 改密入口占位）

    @ViewBuilder
    private var securitySection: some View {
        TouchIDSettingsSection()

        Section {
            Button {
                showChangePassword = true
            } label: {
                Label("修改主密码…", systemImage: "key")
            }
            // T-D 接入前弹出占位 sheet（见 body 末尾 placeholderSheet）
        } footer: {
            Text("修改主密码只重新封装密码库头部，不重新加密全部条目。")
        }
    }

    // MARK: - ⑤ 数据（T-H / T-I 占位）

    private var dataSection: some View {
        Section("数据") {
            Button {
                showRestore = true
            } label: {
                Label("从备份恢复…", systemImage: "arrow.counterclockwise")
            }
            // T-H 接入前弹出占位 sheet

            Button {
                showAuditLog = true
            } label: {
                Label("审计日志…", systemImage: "list.bullet.rectangle")
            }
            // T-I 接入前弹出占位 sheet
        }
    }

    // MARK: - ⑥ 完成

    private var doneSection: some View {
        Section {
            HStack {
                Spacer()
                Button("完成") { dismiss() }
                    .buttonStyle(.borderedProminent)
                Spacer()
            }
        }
    }

    // MARK: - 占位 sheet

    /// T-D / T-H / T-I 接入前的占位 sheet 内容。
    private func placeholderSheet(title: String, taskTag: String) -> some View {
        VStack(spacing: 10) {
            Text(title).font(.headline)
            Text("该功能尚未开放（\(taskTag) 接入）。")
                .foregroundStyle(.secondary)
        }
        .padding(30)
        .frame(width: 320)
    }
}
