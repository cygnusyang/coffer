// SettingsStyle.swift —— 设置页局部几何契约 + 共享卡片 / 行组件（v2.13.1，任务 19 G0）。
//
// 上游：docs/03-功能设计/25-v2.13.1-设置页紧凑化-设计.md §2.1（目标数值表）/
//       §4.1（组件契约）/ §5.1（判据）；DESIGN.md §20 D-20.1~D-20.7。
//
// 为什么需要这个文件（设计 §3.2 代价 4）：设置页骨架由 `Form(.grouped)` 改为
// `ScrollView + VStack` + 自绘卡片后，行高 / 左右留白 / 节距 / 圆角不再由系统
// 绘制，全部变成数字。若允许各业务节各写一套 `padding(.horizontal, 12)`，密度
// 必然逐步漂移，用户抱怨的「太框」会在半年后重新长回来。因此本文件立两条纪律：
//   ① 数值唯一定义在 `SettingsMetrics`（业务文件裸数字命中数必须为 0，D-20.1）；
//   ② 卡必须走 `SettingsCard`、行必须走 `SettingsRow`（G1–G5 遵守）。
//
// 边界（设计 §6.1 决策 2）：这些常量是「设置页局部几何契约」，**不入设计系统
// token 层**（不解除 D-11.6 / §0.3 视觉层占位）。未来视觉轮建间距 / 圆角 token
// 表时，本节数值回填为对 token 的引用，不另立一套。
//
// 零依赖纪律（设计 §4.1 硬约束）：不引用 AppModel、不调 FFI、不取
// `@EnvironmentObject` → 本文件可单独 `swiftc -typecheck`，也是 §5.1 布局探针
// （纯 SwiftUI 宿主）不需要解锁库、不需要 TCC 授权的前提。
//
// 只用系统语义色、禁 hex（D-11.6 / D-20.5）：卡片填充 = `primary` 3% 叠在页
// 背景上（探针实测明暗两态逐通道 Δ 均 = 6，落在 D-20.5 的 [3,12]；不用
// `.quaternary` 是因为它实测 Δ=25，明显重于系统卡片的 6–7），描边取系统发丝线
// 同源色 `NSColor.separatorColor`。

import AppKit
import SwiftUI

// MARK: - 几何契约（唯一数值源，D-20.1）

/// 设置页几何契约。单位 pt。
///
/// 注释里的「现状 → 目标」取自设计 §2.1 数值表的实测值（macOS 26 grouped
/// `Form` 基线：卡片外边距 20、行 inset 10、行高 37.5/44/53、节距 10）。
///
/// **这些数只作用于设置页**（`SettingsView` 及其子节），不是全站间距 token。
enum SettingsMetrics {
    /// 窗口内容宽（D-20.2）。480 → 460。
    ///
    /// 为什么是 460 而不是更窄的 440：卡片外边距 20→12、行 inset 10→8 之后，
    /// 文本区 = 460 − 2×12 − 2×8 = **420pt**，与改造前（480 − 2×20 − 2×10）
    /// 完全相同 → 英文长文案行数零变化（D-19.6「不得以截断换取整齐」）。
    /// 退到 440 会把文本区压到 400pt，且让设置页打开的 5 个 480pt sheet 比
    /// 父窗宽 40pt（设计 §2.3）。
    static let windowWidth: CGFloat = 460

    /// 页顶 / 页底外边距，同时是卡片左右外边距（设计 §4.1 注释）。
    /// 左右：20 → 12，让卡片宽 460 − 24 = 436（D-20.2）。
    static let pageInset: CGFloat = 12

    /// 卡片圆角。系统实测 12.5–13 → 取 DESIGN §0.1「卡片圆角 10–12」上界 12。
    static let cardRadius: CGFloat = 12

    /// 卡到卡（无页头页脚）。10 → 8（8 节奏）。
    ///
    /// 由父容器 `VStack(spacing: cardSpacing)` 承担——本文件的两个组件都**不**
    /// 自带块外间距，否则「有页脚」的块会与「无页脚」的块算出两种节距。
    static let cardSpacing: CGFloat = 8

    /// 行左右 inset，也是发丝线的左右 inset（D-20.5：两者必须一致）。
    /// 10 → 8：行内容起点 = 12（卡片边）+ 8 = 20pt（D-20.2 判据）。
    static let rowInset: CGFloat = 8

    /// 单行行高下限（Picker / Toggle 行）：37.5 → 32。
    /// 恰为 D-11.4「单行态 ≥32」下界，不是新造数值。
    static let rowHeightSingle: CGFloat = 32

    /// 动作行（Button）行高下限：44 → 36。
    /// 依据：24pt `.bordered` 控件 + 上下各 6pt 呼吸（设计 §2.2），且 ≥28
    /// 点击区硬下限（D-20.7 把「整行可点」的判定量从 D-13.5 的 40–44 细化为行高）。
    static let rowHeightAction: CGFloat = 36

    /// 双行行高下限（图标 + 两行文本 + 开关）：53 → 44（D-11.4「双行态 ≥44」下界）。
    static let rowHeightTwoLine: CGFloat = 44

    /// 页头文本 → 卡片上沿。11.5 → 6。
    static let headerGap: CGFloat = 6

    /// 卡片下沿 → 页脚文本。12 → 6。
    static let footerGapTop: CGFloat = 6

    /// 页脚文本 → 卡块底（下一个节距由 `cardSpacing` 叠加）。
    ///
    /// 取值 6 而非 8：设计 §2.1 #14 的目标「页脚文本 → 下一节 = **14**」与同表
    /// 典型节高分解 `36 + (6 + 15 + 6 + 8) = 71` 都要求「页脚底 6 + 节距 8」；
    /// §4.1 草案行曾写 8，与之相加会得 16，与本表冲突，故按数值表取 6，
    /// 并把最终值单独暴露为 `footerToNextSection`，避免下游各自心算。
    static let footerGapBottom: CGFloat = 6

    /// 页脚文本 → 下一节（卡片或下一个页头）的总留白，设计 §2.1 #14：27 → 14。
    /// = `footerGapBottom` + `cardSpacing`；跨 G0/G1 的验收断言直接比这个值。
    static let footerToNextSection: CGFloat = 14

    /// 最小点击区硬下限（设计 §2.2：本次改版不得低于 28，D-20.7）。
    /// `SettingsRow` 在 `init` 里强制 `max(minHeight, minimumHitTarget)`：
    /// 下游就算传 20 也拿不到 20 的行。
    static let minimumHitTarget: CGFloat = 28

    // MARK: 组件内部派生量

    /// 行内容上下留白。设计数值表未列，属 `SettingsRow` 内部实现量。
    ///
    /// 取 4 而不是 6：24pt 控件 + 4/4 = 32，正好落在设计 §2.2「22–24 控件 + 上下
    /// 各 4–6」下界，默认字号下**不把 32/36/44 顶高**（32 仍由 minHeight 决定）；
    /// 大字号时这 8pt 是文字与卡片圆角之间的呼吸量，防「贴边」观感。
    static let rowContentInset: CGFloat = 4

    /// 标签与右侧控件的间距，取 8 节奏（与 `rowInset` 同族）。
    static let labelControlGap: CGFloat = 8
}

// MARK: - 卡片

/// 设置页紧凑卡片：一节一卡（设计 §4.1）。
///
/// 固定结构（顺序不可换）：
/// 可选页头 → `headerGap` → 卡片（圆角 `cardRadius`、语义填充 + 发丝描边、
/// 左右 `rowInset`）→ `footerGapTop` → 可选页脚 → `footerGapBottom`。
///
/// **垂直内边距为 0**：32/36/44 是「含上下留白」的行高（设计 §2.2），再叠一层
/// 卡内 padding 会顶破目标值；垂直呼吸由 `SettingsRow.rowContentInset` 承担。
///
/// **节间距不在本组件内**：父容器用 `VStack(alignment: .leading, spacing:
/// SettingsMetrics.cardSpacing)` 组织（无页脚的节）——有页脚的节会由
/// `footerGapBottom + cardSpacing` 自然得到 `footerToNextSection = 14`。
/// 若哪天需要「有页脚 / 无页脚」两种节距同时成立又不想让块自带外边距，
/// 改这里而不是在各业务节加 `.padding`（D-20.1 静态闸门）。
///
/// 无障碍：卡片 `accessibilityElement(children: .contain)` + 页头作文本分组
/// label，复刻 `Form` 的分组语义（设计 §7-R3 / §5.2-5）。页头文字本身
/// `accessibilityHidden`，避免 VoiceOver 把同一句话播两遍。
///
/// 用法：
/// ```swift
/// SettingsCard("通用", footer: "空闲超过所选时长后自动锁定密码库。") {
///     SettingsRow { Label("自动锁定", systemImage: "timer") } control: { … }
/// }
/// ```
struct SettingsCard<Content: View>: View {
    private let title: LocalizedStringKey?
    private let footer: LocalizedStringKey?
    private let content: Content

    /// - Parameters:
    ///   - title: 节标题（`.subheadline.weight(.semibold)` + `.secondary`）。
    ///     传 `nil` 表示该节无页头（如「安全」节的连续卡）。
    ///   - footer: 节说明（`.caption` + `.secondary`）。长文案整段换行、不截断
    ///     （D-19.6）；不得为了塞下而加 `lineLimit`。
    ///   - content: 卡内内容，通常是一串 `SettingsRow`。
    init(
        _ title: LocalizedStringKey? = nil,
        footer: LocalizedStringKey? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.footer = footer
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let title {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, SettingsMetrics.headerGap)
                    // 左缘对齐行内容（pageInset + rowInset = 20）：卡片自身左右
                    // 外边距 12 + 本 padding 8 = 与行内文字同一竖线。旧 grouped
                    // Form 是「节标题与行内容同为 30」的对齐，换成自绘卡后若不补
                    // 这 8pt，节标题会比正文更靠左 8pt（reviewer N1）。
                    .padding(.horizontal, SettingsMetrics.rowInset)
                    // 页头同时是卡片的分组 label（见 card 的 accessibilityLabel），
                    // 这里隐藏文字本身，避免重复播报。
                    .accessibilityHidden(true)
            }

            card

            if let footer {
                Text(footer)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, SettingsMetrics.footerGapTop)
                    .padding(.bottom, SettingsMetrics.footerGapBottom)
                    // 与页头同一竖线（N1）；页脚文本可用宽因此 420 → 404，
                    // 设计 §2.3 已实测 380 / 366pt 下英文段落行数不变，无截断风险。
                    .padding(.horizontal, SettingsMetrics.rowInset)
            }
        }
        // 卡片左右外边距（D-20.2）：由本组件统一施加，业务节不再写 padding。
        .padding(.horizontal, SettingsMetrics.pageInset)
    }

    /// 卡片填充：`primary` 3% 叠加在页背景上。
    ///
    /// 为什么不直接用 `.quaternary`：本机探针实测 `.quaternary` 在白底上渲染
    /// #E6E6E6（单通道 Δ=25），超出 D-20.5 的「卡片填充 vs 页背景 Δ ∈ [3,12]」，
    /// 也比系统 grouped Form 的实测卡片（#F8F8F8 / Δ 6–7）明显重。3% 实测
    /// 明暗两态均为 Δ=6（浅色 #F9F9F9 / 深色 #242424 对 #1E1E1E），与系统观感
    /// 同档——语义色 + 无 hex（D-11.6）。
    private static var fill: Color {
        Color.primary.opacity(0.03)
    }

    /// 卡片面：填充 + 描边 + 行左右 inset + 分组语义。
    private var cardSurface: some View {
        VStack(alignment: .leading, spacing: 0) {
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, SettingsMetrics.rowInset)
        .background(
            RoundedRectangle(cornerRadius: SettingsMetrics.cardRadius, style: .continuous)
                .fill(Self.fill)
        )
        .overlay(
            RoundedRectangle(cornerRadius: SettingsMetrics.cardRadius, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1)
        )
    }

    @ViewBuilder
    private var card: some View {
        if let title {
            cardSurface
                .accessibilityElement(children: .contain)
                .accessibilityLabel(title)
        } else {
            cardSurface
                .accessibilityElement(children: .contain)
        }
    }
}

// MARK: - 行

/// 设置页行（设计 §4.1）：行高是**下限**不是定高（D-20.4）。
///
/// 两种形态：
/// - **标签 + 右侧控件**（`label:control:`）：标签占弹性宽、长文案先换行不截断；
///   控件取固有尺寸（`.fixedSize`）→ 不换行、不被压缩。这是设置行的默认形态。
/// - **自由布局**（`content:`）：调用方自行排版整行（如「图标 + 两行文本 + 开关」
///   或整行一个 `Picker`），行只负责高度下限、点击区与发丝线。
///
/// 行高语义：32（单行）/ 36（动作）/ 44（双行）都只是 `minHeight`；
/// `fixedSize(horizontal: false, vertical: true)` + 无 `lineLimit` 保证大字号下
/// 按内容增高、不裁切（D-20.4 / 设计 §7-R1）。**不得**改成 `.frame(height:)`。
///
/// 发丝线：默认在行底画一条，左右与行内容对齐（卡片已 inset `rowInset`，故
/// 本组件不再加水平 padding）。**每节最后一行必须传 `showsDivider: false`**，
/// 否则卡片底边内侧会多出一条线。
///
/// 用法：
/// ```swift
/// SettingsRow { Label("自动锁定", systemImage: "timer") } control: {
///     Picker("", selection: $model.autoLockMinutes) { … }.labelsHidden()
/// }
/// ```
struct SettingsRow<Label: View, Control: View>: View {
    private let minHeight: CGFloat
    private let showsDivider: Bool
    private let label: Label
    private let control: Control
    /// `true` = 标签/控件分栏（控件不换行）；`false` = 自由布局。
    private let isSplitLayout: Bool

    /// 自由布局形态：整行内容由调用方排版。
    ///
    /// - Parameters:
    ///   - minHeight: 行高下限，取 `rowHeightSingle` / `rowHeightAction` /
    ///     `rowHeightTwoLine`；低于 `minimumHitTarget`（28）时按 28 兜底。
    ///   - showsDivider: 是否在行底画发丝线；每节最后一行传 `false`。
    ///   - content: 整行内容。
    init(
        minHeight: CGFloat = SettingsMetrics.rowHeightSingle,
        showsDivider: Bool = true,
        @ViewBuilder content: () -> Label
    ) where Control == EmptyView {
        self.minHeight = max(minHeight, SettingsMetrics.minimumHitTarget)
        self.showsDivider = showsDivider
        self.label = content()
        self.control = EmptyView()
        self.isSplitLayout = false
    }

    /// 标签 + 右侧控件形态（设置行默认形态）。
    ///
    /// - Parameters:
    ///   - minHeight: 行高下限，见自由布局形态。
    ///   - showsDivider: 是否在行底画发丝线；每节最后一行传 `false`。
    ///   - label: 左侧标签，占弹性宽、可换行。
    ///   - control: 右侧控件（Toggle / Picker / Button / 状态词），取固有尺寸，不换行。
    init(
        minHeight: CGFloat = SettingsMetrics.rowHeightSingle,
        showsDivider: Bool = true,
        @ViewBuilder label: () -> Label,
        @ViewBuilder control: () -> Control
    ) {
        self.minHeight = max(minHeight, SettingsMetrics.minimumHitTarget)
        self.showsDivider = showsDivider
        self.label = label()
        self.control = control()
        self.isSplitLayout = true
    }

    var body: some View {
        rowContent
            .padding(.vertical, SettingsMetrics.rowContentInset)
            .frame(maxWidth: .infinity, minHeight: minHeight, alignment: .leading)
            .overlay(alignment: .bottom) {
                if showsDivider {
                    Divider()
                }
            }
    }

    @ViewBuilder
    private var rowContent: some View {
        if isSplitLayout {
            HStack(spacing: SettingsMetrics.labelControlGap) {
                label
                    // 弹性宽 + 纵向不压缩：长文案（尤其中英混排）先换行，不截断（D-19.6）。
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                control
                    // 固有尺寸：右侧控件不换行、不被标签挤压（设计 §4.1 / §5.2-1）。
                    .fixedSize()
            }
        } else {
            label
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
