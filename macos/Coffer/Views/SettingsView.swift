// SettingsView.swift —— 统一设置页（docs/09-v0.2实现方案.md §3.7，T06 设置页归位）。
//
// 原先散落在 MainView 工具栏（自动锁定 Picker）与 SecuritySettingsView
// sheet（Touch ID）的设置项统一归位到本页，按节组织：
//   ① 通用：自动锁定超时（原 MainView 工具栏 autoLockMenu 迁入）
//   ② 剪贴板：自动清除档位（T06 / FR-14.2）
//   ③ 备份提醒：提醒间隔档位（FR-8.5；评估逻辑 T-G 接入）
//   ④ 导入：放置区授权（v2.11.0，docs/21 §4.5：DropzoneAuthStatusView 三态
//     轻量行 + 「移除授权」，E-3 应用级授权 D-18.4/18.5）
//   ⑤ 生成器：生成器默认参数（FR-14.3，T08：GeneratorSettingsView）
//   ⑥ 安全：Touch ID 三态节（原样迁入 TouchIDSettingsSection）
//     + 「修改主密码…」入口（sheet：ChangePasswordView，FR-1.8 / TC-UI-11，T-D）
//     + 「恢复码」设置区（RecoveryCodeSettingsSection，FR-17.2）
//   ⑦ 数据：「从备份恢复…」（T-H：RestoreBackupView）「审计日志…」（T-I：AuditLogView，FR-12.6）
//   ⑧ 诊断与隐私：「诊断信息…」（FR-14.4，T08：DiagnosticsView）
//     + 「网络能力自证…」（FR-14.5，T08：NetworkSelfCertView）
//   ⑨ 许可：「许可…」（FR-15.7：LicenseSettingsView，许可状态 / 激活入口 /
//      机器指纹；自包含不触 AppModel，docs/03 §14）
//   ⑩ MCP / Agent 协作：MCP 入口（docs/20 §6：开关 / provider / vault /
//      复制注册命令 / 状态行；独立 McpSettingsSection，不触 AppModel）
//   关闭钮（v2.4.1 终版）：设置改独立窗口（CofferApp Window scene，id
//   "settings"），左上角红绿灯（系统设置样式）关闭——窗口标题栏自带红绿灯，
//   滚动内容时红绿灯常驻可随时关闭，无需自定义关闭控件。演进：Form 底部
//   「完成」→ 顶栏「完成」→ 右上角「✕」→ 独立窗口红绿灯
//
// 档位哨兵语义（三者互不相同，勿混淆）：
//   - autoLockMinutes：0 = 从不（运行态；落盘为 -1，见 AppModel）
//   - clipboardClearSecs：0 = 从不（落盘同值）
//   - backupReminderDays：0 = 禁用提醒（落盘同值）

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject
    private var model: AppModel

    /// 「修改主密码」sheet（T-D：ChangePasswordView 完整改密流程）。
    @State private var showChangePassword = false
    /// 「从备份恢复」sheet（T-H：RestoreBackupView 加密备份恢复流程，FR-8.1）。
    @State private var showRestore = false
    /// 「管理密码库」sheet（v2.10.0 D1：VaultManagementView 库管理面，
    /// 设置窗源本地呈现，随 SettingsWindowHost 在 phase 离开 .unlocked 时
    /// 整窗拆除，F3）。
    @State private var showVaultManagement = false
    /// 「审计日志」sheet（T-I：AuditLogView 只读审计日志查看，FR-12.6）。
    @State private var showAuditLog = false
    /// 「许可」sheet（FR-15.7：LicenseSettingsView 许可状态 / 激活入口）。
    @State private var showLicense = false
    /// 「生成器默认参数」sheet（FR-14.3：GeneratorSettingsView，T08）。
    @State private var showGeneratorDefaults = false
    /// 「诊断信息」sheet（FR-14.4：DiagnosticsView，T08）。
    @State private var showDiagnostics = false
    /// 「网络能力自证」sheet（FR-14.5：NetworkSelfCertView，T08）。
    @State private var showNetworkSelfCert = false

    var body: some View {
        NavigationStack {
            Form {
                generalSection
                clipboardSection
                backupReminderSection
                importSection
                generatorSection
                securitySection
                dataSection
                diagnosticsSection
                licenseSection
                mcpSection
            }
            .formStyle(.grouped)
            .navigationTitle("设置")
            // v2.4.1：macOS 26 Liquid Glass 默认让 Form 内容延伸到玻璃透明
            // 标题栏下方、滚动时从标题栏透出（用户反馈「上面应不透明」）。
            // .toolbarBackground(.visible, for: .windowToolbar) 强制窗口
            // 标题栏/工具栏区不透明——与主窗口 .windowToolbarStyle(.unified)
            // 的实体标题栏同视觉纪律；红绿灯仍留在标题栏左上角。
            .toolbarBackground(.visible, for: .windowToolbar)
            // v2.4.1 终版：关闭由独立窗口标题栏红绿灯承担（Window scene），
            // 本页不再渲染自定义关闭控件；滚动内容时红绿灯仍常驻可随时关闭。
        }
        // 宽度固定、高度自适应（节内容随 Touch ID 内联确认行等动态展开）
        .frame(width: 480)
        .sheet(isPresented: $showChangePassword) {
            // 修改主密码流程（FR-1.8 / TC-UI-11，T-D）：
            // 旧密码重验证 + 新密码 zxcvbn 门禁 + header 重封装（D-2）
            ChangePasswordView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showRestore) {
            // 从备份恢复流程（FR-8.1 回环，T-H）：校验 → 确认 → 恢复 →
            // openSession 引导解锁（phase = .locked 时本 sheet 树随 MainView 拆除）
            RestoreBackupView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showAuditLog) {
            // 审计日志查看（FR-12.6，T-I）：只读最近 200 条，Rust 侧倒序返回
            AuditLogView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showLicense) {
            // 许可信息（FR-15.7，docs/03 §14）：自包含，不依赖 AppModel
            // （许可域与密码库会话无关，v0.4 §6.1 切片纪律，同 McpSettingsSection）
            LicenseSettingsView()
        }
        .sheet(isPresented: $showGeneratorDefaults) {
            // 生成器默认参数（FR-14.3，T08）：编辑存档默认值，
            // 「另存为默认」经 AppModel 校验落盘（generatorDefaultsV1）。
            GeneratorSettingsView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showDiagnostics) {
            // 诊断信息（FR-14.4，T08）：只读白名单字段，消费 T03 diagnostic_summary FFI。
            DiagnosticsView()
                .environmentObject(model)
        }
        .sheet(isPresented: $showNetworkSelfCert) {
            // 网络能力自证（FR-14.5，T08）：静态说明页，无 AppModel 依赖。
            NetworkSelfCertView()
        }
        .sheet(isPresented: $showVaultManagement) {
            // 密码库管理面（v2.10.0 D1，docs/16 §4.5 线框）：设置窗源 sheet。
            // 删当前库 → phase 离开 .unlocked → SettingsWindowHost 整窗自关
            // （F3），sheet 随窗拆除；删非当前库 → 管理面保持列表刷新。
            VaultManagementView()
                .environmentObject(model)
        }
    }

    // MARK: - ① 通用（自动锁定，原 MainView 工具栏迁入）

    private var generalSection: some View {
        Section {
            Picker(selection: $model.autoLockMinutes) {
                ForEach(AppModel.autoLockOptions, id: \.self) { minutes in
                    Text(minutes == 0 ? LocalizedStringKey("从不") : LocalizedStringKey("\(minutes) 分钟")).tag(minutes)
                }
            } label: {
                Label("自动锁定", systemImage: "timer")
            }

            // v2.13.0 语言选择（设计 24 §6.4）：寄生「通用」节、自动锁定之后的第二行，
            // 不新开第 11 节（DESIGN.md §14 已登记「9 节单长滚动」的 IA 张力）。
            // UI 实现在 Support 侧的 LanguageSection.swift（infra 归属），本文件只留调用，
            // 避免同一文件被两组同时改（设计 §8.4 边界 1）。
            LanguageSection()
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
                    Text(secs == 0 ? LocalizedStringKey("从不") : LocalizedStringKey("\(secs) 秒")).tag(secs)
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
                    Text(days == 0 ? LocalizedStringKey("禁用") : LocalizedStringKey("每 \(days) 天")).tag(days)
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

    // MARK: - ④ 导入（v2.11.0，docs/21 §4.5 设置页节 + DESIGN.md D-18.2/18.4/18.5）

    /// 放置区授权节：DropzoneAuthStatusView 三态轻量行（compact 行内压缩，
    /// 应用级语义「此授权作用于 Coffer 应用全局」注记，E-3/D-18.5）。
    /// 「移除授权」= D-18.4 唯一删点（调 `model.removeDropzoneAuthorization()`
    /// 清除 bookmark + 广播，向导打开中同步回 .notAuthorized）；失效态由组件
    /// 内呈「重新授权…」回向导 S0（D-18.3 失效非静默）。
    private var importSection: some View {
        Section {
            DropzoneAuthStatusView(
                status: model.dropzoneAuthStatus,
                // 三个入参在该组件里是 String（Text(String) 不查表，设计 F6），
                // 故在**产生点**本地化（§5.4），不依赖组件内部怎么渲染。
                setButtonLabel: String(localized: "设置放置区…"),
                onSet: { model.showImportDropzone = true },
                secondaryLabel: String(localized: "移除授权"),
                onSecondary: { model.removeDropzoneAuthorization() },
                scopeNote: String(localized: "此授权作用于 Coffer 应用全局"),
                compact: true
            )
        } header: {
            Text("导入")
        } footer: {
            Text("放置区用于自动检测 macOS「密码」App 导出的 CSV；授权只读、可随时撤销。")
        }
    }

    // MARK: - ⑤ 生成器（FR-14.3，T08）

    /// 生成器默认参数入口（FR-14.3）：编辑存档默认值，供生成器面板首次
    /// 打开预填（TC-GEN-01）；另存为默认经 AppModel 校验落盘（TC-GEN-03）。
    private var generatorSection: some View {
        Section {
            Button {
                showGeneratorDefaults = true
            } label: {
                Label("生成器默认参数…", systemImage: "wand.and.stars")
            }
            // T08：弹出 GeneratorSettingsView（见 body 的 showGeneratorDefaults sheet）
        } header: {
            Text("生成器")
        } footer: {
            Text("设置新建条目时生成器的预填参数（长度 / 字符集 / 密码短语选项）。")
        }
    }

    // MARK: - ⑥ 安全（Touch ID 原样迁入 + 改密入口占位）

    @ViewBuilder
    private var securitySection: some View {
        // P2-A 首次高亮兜底（lead 裁定⑤，AC-2.9.0-P2A-10/13）：引导 Step1 被
        // 跳过且 Touch ID 未启用时，Touch ID 节下方出现 accent 圆点 + 「未完成
        // 设置」footnote；启用后消失（showBioSetupHighlight live 派生）。
        VStack(alignment: .leading, spacing: 4) {
            TouchIDSettingsSection()
            if model.showBioSetupHighlight {
                FirstRunSetupHighlightRow()
            }
        }

        Section {
            Button {
                showChangePassword = true
            } label: {
                Label("修改主密码…", systemImage: "key")
            }
            // T-D：弹出 ChangePasswordView（见 body 的 showChangePassword sheet）
        } footer: {
            Text("修改主密码只重新封装密码库头部，不重新加密全部条目。")
        }

        // FR-17.2：恢复码设置区（RecoveryCodeSettingsSection 自包含，两态渲染 +
        // 生成/重生成 sheet 均位于 RecoveryCodeSetupSheet.swift，docs/31 §4.3）
        // P2-A 首次高亮兜底（AC-2.9.0-P2A-11/13）：引导 Step2 被跳过且恢复码未
        // 生成时，恢复码区下方出现同款 footnote；启用后消失。
        VStack(alignment: .leading, spacing: 4) {
            RecoveryCodeSettingsSection()
            if model.showRecoverySetupHighlight {
                FirstRunSetupHighlightRow()
            }
        }
    }

    // MARK: - ⑦ 数据（T-H 恢复备份 / T-I 审计日志）

    private var dataSection: some View {
        Section("数据") {
            Button {
                showRestore = true
            } label: {
                Label("从备份恢复…", systemImage: "arrow.counterclockwise")
            }
            // T-H：弹出 RestoreBackupView（见 body 的 showRestore sheet）

            // v2.10.0 D1 主入口（docs/16 §4.5 线框：与「从备份恢复… / 审计
            // 日志…」同级）：UDR-7 只读许可用户隐藏（对齐 create_vault 拒绝
            // 口径，AC-2.10.0-EN-1/EN-7）。
            if model.canManageVaults {
                Button {
                    showVaultManagement = true
                } label: {
                    Label("管理密码库…", systemImage: "archivebox")
                }
                // 弹出 VaultManagementView（见 body 的 showVaultManagement sheet）
            }

            Button {
                showAuditLog = true
            } label: {
                Label("审计日志…", systemImage: "list.bullet.rectangle")
            }
            // T-I：弹出 AuditLogView（见 body 的 showAuditLog sheet）
        }
    }

    // MARK: - ⑧ 诊断与隐私（FR-14.4 诊断信息 / FR-14.5 网络自证，T08）

    /// 诊断信息 + 网络能力自证入口（T08）：前者消费 diagnostic_summary FFI
    /// 白名单字段（TC-DIAG）；后者为零网络架构静态说明页（TC-NET）。
    private var diagnosticsSection: some View {
        Section {
            Button {
                showDiagnostics = true
            } label: {
                Label("诊断信息…", systemImage: "stethoscope")
            }
            // T08：弹出 DiagnosticsView（见 body 的 showDiagnostics sheet）

            Button {
                showNetworkSelfCert = true
            } label: {
                Label("网络能力自证…", systemImage: "network.slash")
            }
            // T08：弹出 NetworkSelfCertView（见 body 的 showNetworkSelfCert sheet）
        } header: {
            Text("诊断与隐私")
        }
    }

    // MARK: - ⑨ 许可（FR-15.7，docs/03 §14）

    /// 独立的 LicenseSettingsView（自包含、不触 AppModel，v0.4 §6.1 切片纪律；
    /// 许可域与密码库会话无关，docs/03 §14.9）。
    private var licenseSection: some View {
        Section {
            Button {
                showLicense = true
            } label: {
                Label("许可…", systemImage: "checkmark.seal")
            }
            // FR-15.7：弹出 LicenseSettingsView（见 body 的 showLicense sheet）
        } header: {
            Text("许可")
        } footer: {
            Text("查看许可状态、激活或申请序列号（开源免费版无需激活）。")
        }
    }

    // MARK: - ⑩ MCP / Agent 协作（docs/20 §6，对齐 1Password 设置内 Developer 区）

    /// 独立的 McpSettingsSection（自包含、不触 AppModel，v0.4 §6.1 切片纪律；
    /// 主 App 不宿主 MCP 服务器，docs/20 §6.2）。
    private var mcpSection: some View {
        McpSettingsSection()
    }
}

// MARK: - 首次引导高亮兜底（P2-A，docs/14 §A P2 §2.5；DESIGN.md P-2.1）

/// 「未完成设置」footnote 行：accent 圆点 + 文案，作为被跳过的首启引导步骤的
/// 设置页兜底入口提示（lead 裁定⑤，AC-2.9.0-P2A-10/11）。随对应功能启用而
/// 消失（SettingsView.securitySection 按 showBioSetupHighlight /
/// showRecoverySetupHighlight 条件渲染，见上）。小组件封装，两侧复用。
struct FirstRunSetupHighlightRow: View {
    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(Color.accentColor)
                .frame(width: 6, height: 6)
            Text("未完成设置")
                .font(.footnote)
                .foregroundStyle(Color.accentColor)
        }
        .padding(.leading, 4)
        .padding(.top, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("未完成设置")
    }
}
