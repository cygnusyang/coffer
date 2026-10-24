// ImportWizardShell.swift —— 共享导入向导壳（v2.9.0 P3，docs/14 §A P3 §2/§5/§6）。
//
// 收敛四格式导入向导（CSV/1PUX/Bitwarden/OPVault）重复的脚手架部分
// （头部/尺寸/选文件/导入中/结果页骨架/预检失败 alert/统计标签），
// 消除 ~1200 行重复。**报告正文仍按格式私有**——各向导以内容闭包注入
// 私有 body（报告差异天然巨大，强行统一反会抹平语义，docs/14 P3 §2）。
//
// 硬约束（docs/14 P3 §1/§3，lead 采纳评语）：四格式事务语义差异
// （CSV/OPVault all-or-nothing vs 1PUX/Bitwarden 每条目独立）必须保留
// 为壳配置/文案参数，**逐字保留**。transactionSemantics 驱动事务语义
// 分类，importingCopy / failureSuffix / doneFooter 一律以各格式逐字覆盖
// 值为准（CSV 与 OPVault 同为 all-or-nothing 但 importing 文案不同）。
//
// 结构：
//   - ImportScaffold（非泛型命名空间）：共享子件（选文件/导入中/结果页
//     骨架 + statLabel/failureList/pathLine）——非泛型，四格式可直接引用；
//   - ImportWizardShell<Content>（泛型容器）：头部（title + 「关闭」）+
//     Divider + 尺寸 + 预检失败 alert，内容闭包由各格式注入。
//
// 各向导消费方式：
//   ImportWizardShell(config:isImporting:onClose:precheckError:
//   onPrecheckErrorDismiss:) { <格式私有 Step switch> }
//   —— 格式在内容闭包里自持状态机（Step 枚举 + 预检/导入逻辑），
//      importing/done/选文件骨架用 ImportScaffold 静态子件。
//   OPVault 扩展步骤（password/precheck）为格式私有，不进壳。

import SwiftUI
import UniformTypeIdentifiers

// MARK: - 事务语义（P3 硬约束参数化落点）

/// 四格式导入事务语义（docs/14 §A P3 §3 对照表，lead 硬约束不抹平）。
/// CSV/OPVault = 单事务 all-or-nothing（失败零落库）；1PUX/Bitwarden =
/// 每条目独立事务（中途失败已导入条目保留）。驱动失败追加文案的期望
/// 默认（defaultFailureSuffix），各格式仍可逐字覆盖。
enum TransactionSemantics {
    /// 单事务：全部成功或全部回滚（CSV / OPVault）。
    case allOrNothing
    /// 每条目独立事务：已完成的条目保留（1PUX / Bitwarden）。
    case perItem

    /// 默认失败追加文案：all-or-nothing 一律空（零落库不得声称部分导入）；
    /// per-item 提示重试将重复新建（AC-2.9.0-P3-2 / P3T-5）。
    var defaultFailureSuffix: String {
        switch self {
        case .allOrNothing:
            return ""
        case .perItem:
            // String(localized:)：本值是**文案**而非数据，且由 Text(failureSuffix) 消费——
            // Text(String) 不查表（设计 24 F6 / §5.4「本地化发生在 String 的产生点」）。
            return String(localized: "\n注意：导入为每条目独立事务，部分条目可能已导入，重试将重复新建。")
        }
    }
}

// MARK: - 导入失败定向恢复

/// 导入失败后的恢复方向（AC-2.9.0-P3-5 / P3T-8，值域 ∈ {回选文件, 回报告页,
/// 回密码页}）。各格式 Step 类型不同，具体导航在格式侧实现；本枚举声明
/// 恢复方向并与事务语义互斥约束（per-item 恒 .backToReport，all-or-nothing
/// 恒 .backToPick / .backToPassword）。
enum ImportFailureRecovery {
    /// 回选文件/选目录（CSV，与预检失败同路）。
    case backToPick
    /// 回报告页（保留 lastReport，可重试；1PUX/Bitwarden）。
    case backToReport
    /// 回密码页（重输密码；OPVault）。
    case backToPassword
}

// MARK: - 数据列表分隔符

/// 数据列表分隔符（中文全角「、」「；」/ 英文半角 ", " "; "）。
///
/// 为什么不放进译表：纯符号键违反设计 24 §5.1 规则 4（空串与纯符号不入表）；而被
/// 连接的**全是数据**——条目名、字段名、列名、目录名——按 §5.5「文案 vs 数据分界」
/// 绝不能进译表。所以语言差异只能落在拼接处的标点上。
///
/// 判据用 LanguagePreference.launchLanguage（与 .lproj 解析同一来源），不用
/// Locale.current：后者不是本 App 的语言权威（设计 §6.5 的 L1 层）。
enum CopyListSeparator {
    /// 并列清单分隔（「条目 A、条目 B」）。
    static var comma: String {
        LanguagePreference.launchLanguage == .en ? ", " : "、"
    }

    /// 同一行内并列短句分隔（「缺标题行；未识别列」）。
    static var semicolon: String {
        LanguagePreference.launchLanguage == .en ? "; " : "；"
    }
}

// MARK: - 格式配置

/// 单格式导入向导配置（docs/14 §A P3 §2/§3）。除报告正文外的一切壳参数
/// 均由配置驱动；逐字文案以本结构体各字段覆盖值为准（迁移基线对照表）。
struct ImportFormatConfig {
    /// 头部标题（逐字）。
    let title: String
    /// 选文件步图标 SF Symbol（逐字）。
    let icon: String
    /// 选文件标题（逐字）。
    let pickTitle: String
    /// 选文件说明（逐字）。
    let pickDescription: String
    /// 选文件按钮文案（「选择文件…」/「选择目录…」，逐字）。
    let pickButtonLabel: String
    /// 窗口尺寸（width × height）。
    let windowWidth: CGFloat
    let windowHeight: CGFloat
    /// 预检失败 alert 标题（逐字）。
    let precheckErrorAlertTitle: String
    /// 事务语义（P3 硬约束：CSV/OPVault = allOrNothing，1PUX/Bitwarden =
    /// perItem，不得抹平）。
    let transactionSemantics: TransactionSemantics
    /// 导入中进度文案（逐字覆盖，一律以此值为准）。
    let importingCopy: String
    /// 导入失败追加文案（逐字；all-or-nothing 必须为空串——零落库不得声称
    /// 部分导入，AC-2.9.0-P3T-5 反断言）。
    let failureSuffix: String
    /// 结果页单事务行（仅 CSV 有；1PUX/Bitwarden/OPVault 为 nil，逐字）。
    let doneFooter: String?
    /// 导入失败定向恢复策略。
    let failureRecovery: ImportFailureRecovery
    /// NSOpenPanel 目录选择配置（OPVault canChooseDirectories = true）。
    let canChooseDirectories: Bool
    /// 允许的文件类型（目录选择时留空 = 全部允许）。
    let allowedContentTypes: [UTType]
    /// NSOpenPanel 提示文案。
    let panelMessage: String
}

// MARK: - 共享子件（非泛型命名空间）

/// 导入向导共享脚手架子件（docs/14 §A P3 §2「共享子件」）：选文件/导入中/
/// 结果页骨架 + statLabel / failureList / pathLine。非泛型命名空间，四格式
/// 直接以 `ImportScaffold.xxx` 引用。报告正文仍是各格式私有 body，不进本
/// 命名空间。
enum ImportScaffold {
    /// 选文件/选目录步骨架（图标 + 标题 + 说明 + 选择按钮）。
    static func pickBody(
        config: ImportFormatConfig,
        onPick: @escaping () -> Void
    ) -> some View {
        VStack(spacing: 16) {
            Image(systemName: config.icon)
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text(config.pickTitle)
                .font(.callout)
            Text(config.pickDescription)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(config.pickButtonLabel) { onPick() }
                .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 导入进度步骨架（ProgressView + 逐字 importingCopy）。
    static func importingBody(_ importingCopy: String) -> some View {
        VStack(spacing: 12) {
            ProgressView()
            Text(importingCopy)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 结果页骨架（checkmark.circle + 结果页头部 + 可空单事务行 + 特有区 +
    /// 路径行 + 「完成」默认键）。特有区（删源警示/抽样核对/passkey 计数/
    /// 附件清单等）由各格式以 extra 闭包私有注入。
    static func doneSkeleton<Extra: View>(
        count: UInt32,
        doneFooter: String?,
        path: String,
        onDone: @escaping () -> Void,
        @ViewBuilder extra: () -> Extra
    ) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("导入完成：新建 \(count) 条条目")
                .font(.headline)
            if let doneFooter {
                Text(doneFooter)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            extra()
            pathLine(path)
            Spacer()
            HStack {
                Spacer()
                Button("完成") { onDone() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    /// 长路径行（AC-2.9.0-P3-9：lineLimit(2) / truncationMode(.middle)）。
    static func pathLine(_ path: String) -> some View {
        Text(URL(fileURLWithPath: path).path)
            .font(.caption2)
            .foregroundStyle(.tertiary)
            .lineLimit(2)
            .truncationMode(.middle)
    }

    /// 统计标签（计数版）。
    ///
    /// title 用 LocalizedStringKey 而不是 String：形参写 String 时 Text(title) 走
    /// Text(String) —— 不查表（设计 24 F6），调用点又没有包 String(localized:) 的话
    /// 就是典型的「有译文但不生效」。签名定成 LocalizedStringKey 后，调用点直接传中文字面量
    /// 即可自动查表，谁也漏不了。
    static func statLabel(_ title: LocalizedStringKey, _ count: UInt32) -> some View {
        VStack(spacing: 2) {
            Text("\(count)").font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    /// 统计标签（Int 计数版，经 UInt32 收敛）。
    static func statLabel(_ title: LocalizedStringKey, _ count: Int) -> some View {
        statLabel(title, UInt32(max(0, count)))
    }

    /// 统计标签（字符串值版，OPVault Profile/KDF 迭代等）。
    static func statLabel(_ title: LocalizedStringKey, _ value: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    /// 未导入/失败条目清单（title + uuid 后缀 + reason，共享 1PUX/OPVault
    /// notImported 形态）。`emptyTitleFallback` 非 nil 时标题为空显示兜底并
    /// 隐藏 uuid 后缀（OPVault：结构层无密码时标题不可知）；nil 时原样直出
    /// （1PUX：desktop 导出标题恒有兜底，仍显示 uuid 后缀）。
    static func failureList<Element>(
        _ items: [Element],
        id: KeyPath<Element, String>,
        title: KeyPath<Element, String>,
        reason: KeyPath<Element, String>,
        emptyTitleFallback: String? = nil
    ) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(items, id: id) { item in
                let itemTitle = item[keyPath: title]
                let titleText = itemTitle.isEmpty ? (emptyTitleFallback ?? itemTitle) : itemTitle
                HStack(alignment: .top, spacing: 6) {
                    Text(titleText)
                        .font(.caption)
                        .lineLimit(1)
                    if emptyTitleFallback == nil || !itemTitle.isEmpty {
                        Text(String(item[keyPath: id].suffix(8)))
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                }
                Text(item[keyPath: reason])
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - 共享向导壳

/// 共享导入向导壳（docs/14 §A P3 §5 线框）：头部（title + 「关闭」，导入
/// 执行中禁用）+ Divider + 格式私有内容 + 尺寸 + 预检失败 alert。
/// 内容闭包由各格式自持状态机（Step switch），导入中/结果页/选文件骨架
/// 用 ImportScaffold 静态子件构建。
struct ImportWizardShell<Content: View>: View {
    let config: ImportFormatConfig
    /// 导入执行中（「关闭」禁用，防丢结果页；per-item 格式丢结果页无法判断
    /// 已导入多少，维持禁用——docs/14 P3 §6）。
    let isImporting: Bool
    /// 「关闭」动作（各格式 dismiss()）。
    let onClose: () -> Void
    /// 预检失败错误文案（nil = 不呈现；OK 回选文件/选目录）。
    let precheckError: Binding<String?>
    /// 预检失败 alert「好」动作（回 pick/pickDirectory）。
    let onPrecheckErrorDismiss: () -> Void
    /// 格式私有状态机内容（Step switch）。
    @ViewBuilder
    let content: () -> Content

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding()
        }
        .frame(width: config.windowWidth, height: config.windowHeight)
        .alert(config.precheckErrorAlertTitle, isPresented: Binding(
            get: { precheckError.wrappedValue != nil },
            set: { if !$0 { precheckError.wrappedValue = nil } }
        )) {
            Button("好", role: .cancel) { onPrecheckErrorDismiss() }
        } message: {
            Text(precheckError.wrappedValue ?? "")
        }
    }

    /// 头部：标题 + 显式关闭出口（全步骤可见——macOS sheet 点外部不关闭、
    /// 无按钮时 Esc 无效，必须提供退出，BUG-6 修复）。导入执行中禁用。
    private var header: some View {
        HStack {
            Text(config.title).font(.headline)
            Spacer()
            Button("关闭") { onClose() }
                .keyboardShortcut(.cancelAction)
                .disabled(isImporting)
        }
        .padding()
    }
}
