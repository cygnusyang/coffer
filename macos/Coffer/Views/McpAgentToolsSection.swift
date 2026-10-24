// McpAgentToolsSection.swift —— 设置页「MCP / Agent 协作」节内的「AI 工具」子块
// （docs/23 v2.12.0 §4.1 / §5 / §6；取代 v2.11.0 的单行「Claude Code 注册」）。
//
// 结构与设计对齐（docs/23 §4.1 第 5–7 项）：
//   ① 子标题「AI 工具」+ 恒可用刷新（probe → 对已安装的自动注册目标逐个 check）；
//   ② 主组：已安装的自动注册工具（Claude Code / CodeBuddy / Codex），行序固定
//      （Claude Code → CodeBuddy → Codex，不随状态重排，避免交互中行跳动）；
//   ③ 折叠组「其他工具（N）」：未安装的自动注册工具 + 5 家 copy-only，每行只有
//      「复制命令 / 复制配置」（无开关 = 无授权面）。
//
// 状态归属（docs/23 §3.2）：每个 target 独立一份注册态（McpAgentToolState），与
// 总开关（用户批量意图）分离——总开关 OFF 只禁用工具开关，事实态照常渲染
// （REV-01：批量移除失败时注册项仍在，不得画成「先打开总开关」）。「是否安装」
// 来自 probe 结论（installed），独立于注册态。
//
// 串行纪律（docs/23 §11.3）：helper 一次只能处理一个请求（固定名 config /
// result 文件），所有操作经 McpAgentToolCenter 的单任务通道；在飞时其余行的
// 开关与动作禁用（沿用 v2.11.0 registrationTask 模式）。
//
// 复制反馈（D-1.2）：行内「复制命令 → 已复制」1.5 s 复位，不弹窗（docs/23 §7.4
// 把既有 2 s 统一改为 1.5 s）。

import AppKit
import SwiftUI

/// 单个 AI 工具的注册态（事实态；docs/23 §6.1 主表）。
///
/// 「未安装」不进本枚举：它来自 probe 结论（McpAgentToolCenter.installed），
/// 与注册态正交——同一工具可以先未安装、装好后重新检测转为正常注册态。
/// 「辅助程序缺失」同样不占一个态：由 McpAgentToolCenter.helperAvailable 表达
/// 节级横幅与行内文案（docs/23 §6.1 表末行 checkFailed 的 helper 缺失变体）。
enum McpAgentToolState: Equatable {
    /// 未检查（初值；未安装 / helper 不可用时也停在此态，行内文案另行表达）
    case idle
    /// 检查中（进入页面 / 点刷新）
    case checking
    /// 注册中
    case registering
    /// 移除中
    case removing
    /// 已注册（携带读回的 COFFER_VAULT_DIR，供与当前库比对）
    case registered(vaultDir: String?)
    /// 未注册（check 结论）
    case notRegistered
    /// 失败（携带用户可读文案；注册与移除语境由文案自身区分）
    case failed(String)
}

/// 每个工具的开关意图持久化（键非敏感布尔，沿用 McpSettings 纪律）。
///
/// 键形 mcp_target_enabled_<rawValue>；缺失 = true（lead 裁定 2026-10-22：
/// 已安装工具默认开启，与 docs/23 §4.2「新工具默认 OFF」的安全默认相反，
/// 按 lead 口径以本实现为准）。
enum McpAgentToolPreferences {
    /// 键前缀（后接 target.rawValue）。
    static let enabledKeyPrefix = "mcp_target_enabled_"

    /// 单个工具的开关键。
    static func enabledKey(for target: McpAgentTarget) -> String {
        enabledKeyPrefix + target.rawValue
    }

    /// 读开关意图（键不存在 → true：默认开启）。
    static func isEnabled(_ target: McpAgentTarget) -> Bool {
        UserDefaults.standard.object(forKey: enabledKey(for: target)) as? Bool ?? true
    }

    /// 存开关意图。
    static func setEnabled(_ value: Bool, for target: McpAgentTarget) {
        UserDefaults.standard.set(value, forKey: enabledKey(for: target))
    }
}

/// 多工具注册协调器（App 侧，docs/23 §11.3 串行通道）。
///
/// 单一在飞任务：新触发取消旧任务（沿用 v2.11.0 registrationTask 模式），
/// helper 调用严格串行；busy 期间视图禁用其余行的开关与动作。
@MainActor
final class McpAgentToolCenter: ObservableObject {
    /// 各自动注册目标的注册态（缺省 = idle）。
    @Published private(set) var states: [McpAgentTarget: McpAgentToolState] = [:]
    /// probe 结论：本机已安装的自动注册目标。
    @Published private(set) var installed: Set<McpAgentTarget> = []
    /// 是否已拿到 probe 结论（未拿到前不渲染空态——否则进页面瞬间会闪一下空态）。
    @Published private(set) var hasProbed = false
    /// probe 失败但辅助程序可用（M2：不得静默当作「未安装」渲染，节顶给横幅 + 行落失败）。
    @Published private(set) var probeFailed = false
    /// 注册辅助程序可用性（probe 命中 helperMissing 即置 false）。
    @Published private(set) var helperAvailable = true
    /// 是否有 helper 操作在飞（视图据此禁用其余行控件）。
    @Published private(set) var busy = false

    /// 注册协调器（写入容器 tmp 固定 config → open 启嵌入式 helper → 轮询 result）。
    private let registrar = McpRegistrar()
    /// 当前在飞任务（新触发取消旧任务）。
    private var task: Task<Void, Never>?
    /// 在飞任务令牌（旧任务收尾时不得把新任务的 busy 打回 false）。
    private var activeToken: UUID?

    // MARK: - 派生查询

    /// 是否至少有一个工具处于已注册态（总开关 OFF 前需确认，docs/23 §5.4）。
    var hasRegisteredTarget: Bool {
        states.values.contains { state in
            if case .registered = state { return true }
            return false
        }
    }

    /// 是否有在飞操作（checking / registering / removing）。
    ///
    /// H3 第二半：总开关 OFF 时，在飞的注册可能已经写了一半配置，必须一并纳入
    /// 关闭确认，不能因为 hasRegisteredTarget 还是 false 就直接放行关闭。
    var anyInFlight: Bool {
        states.values.contains { state in
            switch state {
            case .checking, .registering, .removing: return true
            case .idle, .registered, .notRegistered, .failed: return false
            }
        }
    }

    /// 关闭确认清单（可能已写入的目标：已注册 + 在飞），行序固定。
    var cleanupTargetNames: String {
        McpAgentTarget.autoRegisterTargets
            .filter { target in
                switch states[target] {
                case .registered, .registering, .checking, .removing: return true
                default: return false
                }
            }
            .map(\.displayName)
            .joined(separator: "、")
    }

    /// 单目标当前态（缺省 idle）。
    func state(for target: McpAgentTarget) -> McpAgentToolState {
        states[target] ?? .idle
    }

    // MARK: - 对外操作

    /// 进入页面 / 点刷新：先 probe 已安装目标，再对已安装者逐个 check（串行）。
    ///
    /// 检测恒可用（docs/23 §4.1 STD-05）：不因总开关 OFF / 无会话而禁用——探测
    /// 只读、不改任何配置。
    func refresh() {
        run { [weak self] in
            guard let self else { return }
            for target in McpAgentTarget.autoRegisterTargets {
                self.states[target] = .checking
            }
            guard await self.probeStep() else {
                // helper 不可用 → 行内文案由 helperAvailable 表达；helper 可用但
                // 探测失败 → 必须显式落失败（M2：不得把 installed 当「未安装」渲染，
                // 也不得静默留在转圈态，docs/23 §6.3 REV-02）。
                self.markProbeFailure()
                return
            }
            for target in McpAgentTarget.autoRegisterTargets where self.installed.contains(target) {
                await self.checkStep(target)
            }
            for target in McpAgentTarget.autoRegisterTargets where !self.installed.contains(target) {
                self.states[target] = .idle
            }
        }
    }

    /// 总开关 ON：对「已安装且用户未关闭」的自动注册目标串行注册
    /// （docs/23 §4.2 OFF→ON 批量 upsert）。
    func activateAll(vaultDir: String, cofferBinaryPath: String) {
        guard !vaultDir.isEmpty, !cofferBinaryPath.isEmpty else { return }
        let preferred = McpAgentTarget.autoRegisterTargets.filter { McpAgentToolPreferences.isEnabled($0) }
        guard !preferred.isEmpty else { return }
        run { [weak self] in
            guard let self else { return }
            if self.installed.isEmpty {
                // 冷启动直接拨总开关：probe 结论还没回来，先补一次探测；探测失败
                // 中止批量（M2：不得静默 0 注册），由节顶横幅 + 行内失败态提示。
                guard await self.probeStep() else {
                    self.markProbeFailure()
                    return
                }
            }
            for target in preferred where self.installed.contains(target) {
                await self.registerStep(target, vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath)
            }
        }
    }

    /// 总开关 OFF：串行移除**可能已写入**的自动注册目标，完成后按事实重新 check。
    ///
    /// 目标快照（docs/23 §5.4 REV-04）：registered / registering / checking —— 在飞
    /// 的注册可能已经写了一半配置，必须一并清理；先取消在飞并等它真正退出（helper
    /// 的 config/result 是固定名，不能与移除并发），再逐个移除。
    ///
    /// 移除结果**不当结论**（H3）：结束后重新 probe + check，以配置文件事实回填，
    /// 避免「remove 报成功但条目仍在」或反之被当成最终态。
    func deactivateAll() {
        let targets = McpAgentTarget.autoRegisterTargets.filter { target in
            switch states[target] {
            case .registered, .registering, .checking, .removing: return true
            default: return false
            }
        }
        guard !targets.isEmpty else { return }
        let previous = task
        previous?.cancel()
        run { [weak self] in
            guard let self else { return }
            _ = await previous?.value
            for target in targets {
                await self.removeStep(target)
            }
            // 事实态回填（不信任本次 remove 的返回值）。
            guard await self.probeStep() else {
                self.markProbeFailure()
                return
            }
            for target in McpAgentTarget.autoRegisterTargets where self.installed.contains(target) {
                await self.checkStep(target)
            }
            for target in McpAgentTarget.autoRegisterTargets where !self.installed.contains(target) {
                self.states[target] = .idle
            }
        }
    }

    /// probe 失败后的统一收尾（M2）：helper 缺失 → 清在飞态交给行内 helperAvailable
    /// 文案；helper 可用 → 每行落 failed 并抬起 probeFailed 横幅（不伪造「未安装」）。
    private func markProbeFailure() {
        guard helperAvailable else {
            for target in McpAgentTarget.autoRegisterTargets {
                discardIfInFlight(target)
            }
            return
        }
        for target in McpAgentTarget.autoRegisterTargets {
            states[target] = .failed(String(localized: "工具探测失败，请点刷新重试"))
        }
    }

    /// 单行开关 ON：注册该目标（upsert，覆盖历史 COFFER_VAULT_DIR）。
    func register(target: McpAgentTarget, vaultDir: String, cofferBinaryPath: String) {
        guard !vaultDir.isEmpty, !cofferBinaryPath.isEmpty else { return }
        run { [weak self] in
            guard let self else { return }
            await self.registerStep(target, vaultDir: vaultDir, cofferBinaryPath: cofferBinaryPath)
        }
    }

    /// 单行开关 OFF / 「再次清理」：移除该目标的 coffer 注册项（单目标无确认，D-6）。
    func remove(target: McpAgentTarget) {
        run { [weak self] in
            guard let self else { return }
            await self.removeStep(target)
        }
    }

    /// 离开设置页 / 关窗：取消在飞任务并清在飞态（docs/23 N-8：不保留幽灵结果，
    /// 重进页面重新 check；注册项不因离开被改动）。
    func cancelAll() {
        task?.cancel()
        task = nil
        activeToken = nil
        busy = false
        for target in McpAgentTarget.autoRegisterTargets {
            discardIfInFlight(target)
        }
    }

    // MARK: - 串行通道

    /// 单任务通道：取消在飞任务 → 记令牌 → 执行（令牌未变才收 busy）。
    private func run(_ operation: @escaping @MainActor () async -> Void) {
        task?.cancel()
        let token = UUID()
        activeToken = token
        busy = true
        task = Task {
            await operation()
            if activeToken == token { busy = false }
        }
    }

    // MARK: - 单步（helper 一次一个请求）

    /// probe：探测本机已安装的自动注册目标。返回 false = 探测未成功（helper 缺失
    /// 或 result 异常），调用方不得据 installed 判断「未安装」。
    private func probeStep() async -> Bool {
        do {
            let result = try await registrar.probeInstalledTargets()
            guard !Task.isCancelled else { return false }
            helperAvailable = true
            probeFailed = false
            installed = Set((result.installedTargets ?? []).compactMap(McpAgentTarget.init(rawValue:)))
            hasProbed = true
            return true
        } catch is CancellationError {
            return false
        } catch {
            guard !Task.isCancelled else { return false }
            helperAvailable = !isHelperMissing(error)
            probeFailed = helperAvailable
            installed = []
            hasProbed = true
            return false
        }
    }

    /// check：只读目标配置文件（不改任何配置）。
    private func checkStep(_ target: McpAgentTarget) async {
        states[target] = .checking
        do {
            let result = try await registrar.checkRegistered(target: target)
            guard !Task.isCancelled else { return }
            states[target] = result.registered
                ? .registered(vaultDir: result.vaultDir)
                : .notRegistered
        } catch is CancellationError {
            discardIfInFlight(target)
        } catch {
            guard !Task.isCancelled else { return }
            states[target] = .failed(
                failureText(error, fallback: String(format: String(localized: "检查注册状态失败：无法读取 %@ 配置。"),
                                                     target.displayName))
            )
        }
    }

    /// register：写入注册项（upsert）。返回是否确认已注册。
    @discardableResult
    private func registerStep(_ target: McpAgentTarget, vaultDir: String,
                              cofferBinaryPath: String) async -> Bool {
        states[target] = .registering
        do {
            let result = try await registrar.register(target: target, vaultDir: vaultDir,
                                                     cofferBinaryPath: cofferBinaryPath)
            guard !Task.isCancelled else { return false }
            if result.success && result.registered {
                states[target] = .registered(vaultDir: result.vaultDir)
                return true
            }
            states[target] = .failed(McpRegistrar.errorMessage(for: result.code, target: target))
            return false
        } catch is CancellationError {
            discardIfInFlight(target)
            return false
        } catch {
            guard !Task.isCancelled else { return false }
            states[target] = .failed(
                failureText(error, fallback: String(localized: "注册失败，请重试或用「复制命令」手动注册。"))
            )
            return false
        }
    }

    /// remove：移除注册项。返回是否确认已移除。
    @discardableResult
    private func removeStep(_ target: McpAgentTarget) async -> Bool {
        states[target] = .removing
        do {
            let result = try await registrar.remove(target: target)
            guard !Task.isCancelled else { return false }
            if result.success {
                states[target] = .notRegistered
                return true
            }
            states[target] = .failed(McpRegistrar.removeErrorMessage(for: result.code, target: target))
            return false
        } catch is CancellationError {
            discardIfInFlight(target)
            return false
        } catch {
            guard !Task.isCancelled else { return false }
            states[target] = .failed(
                failureText(error, fallback: String(localized: "移除失败，请重试。")
                    + McpRegistrar.manualCleanupCommand(target: target))
            )
            return false
        }
    }

    // MARK: - 小工具

    /// 在飞态被取消后回到 idle（不留幽灵转圈；重进页面会重新 check）。
    private func discardIfInFlight(_ target: McpAgentTarget) {
        switch states[target] {
        case .checking, .registering, .removing:
            states[target] = .idle
        default:
            break
        }
    }

    /// 辅助程序缺失判定（节级横幅 + 禁用全部注册动作的唯一依据）。
    private func isHelperMissing(_ error: Error) -> Bool {
        guard let registrarError = error as? McpRegistrar.RegistrarError,
              case .helperMissing = registrarError else { return false }
        return true
    }

    /// 显式错误文案（LocalizedError 优先，缺省用调用方兜底句）。
    private func failureText(_ error: Error, fallback: String) -> String {
        guard let description = (error as? LocalizedError)?.errorDescription,
              !description.isEmpty else { return fallback }
        return description
    }
}

/// 设置页「AI 工具」子块（docs/23 §4.1 第 5–7 项；挂在 MCP / Agent 协作节内）。
///
/// 只呈现与转发：状态由 McpAgentToolCenter 持有（父节共享同一实例，总开关需读
/// hasRegisteredTarget 决定是否弹关闭确认）。
struct McpAgentToolsSection: View {
    @EnvironmentObject
    private var model: AppModel

    /// 状态中心（父节持有，总开关与工具行共用）。
    @ObservedObject var center: McpAgentToolCenter
    /// 总开关（节级「启用 MCP 服务器」）：OFF 时工具开关禁用，事实态照常渲染。
    let masterEnabled: Bool
    /// coffer 二进制绝对路径（复制命令用；空串 = 未找到，复制入口禁用）。
    let cofferBinaryPath: String

    /// 「其他工具」折叠组展开态（空态时自动展开，docs/23 §5.3）。
    @State private var showOthers = false
    /// 已复制反馈的目标（1.5 s 后复位，D-1.2 就地反馈）。
    @State private var copiedTarget: McpAgentTarget?
    /// 复制失败提示（写入剪贴板失败给可操作文案，docs/20 §6.3）。
    @State private var errorMessage: String?

    /// 「已复制」反馈的显示时长（秒；docs/23 §7.4 STD-03 统一 1.5 s）。
    private static let copiedFeedbackSeconds: TimeInterval = 1.5
    /// 图标槽基准宽（D-11.4：随字号放大，不写死固定 frame）。
    @ScaledMetric(relativeTo: .callout) private var iconSlotWidth: CGFloat = 16

    var body: some View {
        Group {
            headerRow

            if !center.helperAvailable {
                Label("注册组件不可用，仅支持复制命令", systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            } else if center.probeFailed {
                // M2：探测失败必须显式提示，不得静默按「未安装」渲染。
                Label("工具探测失败，请点刷新重试", systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

            if showsEmptyState {
                // 一个都没装：主组位置显示空态（docs/23 §5.3），工具行退到折叠组。
                emptyState
            } else {
                // 行序固定不重排（docs/23 §4.1）：未安装的行留在原位显示「未安装」，
                // 开关禁用但复制入口可用——不让行在会话中途迁移位置。
                ForEach(McpAgentTarget.autoRegisterTargets, id: \.self) { target in
                    autoTargetRow(target)
                }
            }

            otherToolsGroup
        }
        .onChange(of: showsEmptyState) { _, isEmpty in
            // 落到空态 → 自动展开「其他工具」（copy-only 是空态下唯一可行路径，
            // docs/23 §5.3）；有工具时保持默认收起（§4.1 第 7 项）。
            if isEmpty { showOthers = true }
        }
        .ffiErrorAlert($errorMessage)
    }

    // MARK: - 子标题 + 刷新

    /// 子标题「AI 工具」+ 恒可用刷新（docs/23 §4.1 STD-05：检测不因总开关 / 无会话
    /// / 辅助程序缺失而禁用——否则用户失败后失去唯一自救路径）。
    private var headerRow: some View {
        HStack {
            Text("AI 工具").font(.headline)
            Spacer()
            Button {
                center.refresh()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            // 检测本身不受总开关 / 会话限制（STD-05），但 helper 串行是一次一个请求，
            // 在飞时禁用（H3：避免与在飞注册撞固定名 config/result）。
            .disabled(center.busy)
            .help(center.busy
                  ? String(localized: "正在处理注册操作，请稍候")
                  : String(localized: "重新检测工具与注册状态"))
            .accessibilityLabel("重新检测工具与注册状态")
        }
    }

    // MARK: - 空态（docs/23 §5.3 / D-7.2a：节内嵌变体，24pt 图标 + 单个 bordered 动作）

    private var emptyState: some View {
        VStack(spacing: 6) {
            Image(systemName: "circle.dashed")
                .font(.system(size: 24))
                .foregroundStyle(.secondary)
            Text("未检测到 AI 工具").font(.headline)
            Text("安装 Claude Code、CodeBuddy 或 Codex 后重新检测，即可一键注册；其他工具可手动复制配置。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("重新检测") { center.refresh() }
                .buttonStyle(.bordered)
                .disabled(center.busy)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

    // MARK: - 自动注册工具行（MCP 工具行组件，DESIGN.md D-11.1）

    /// 主组行：状态图标 + 名称 / 状态词 + 次文案 + 行尾开关（名称与状态词同级
    /// .body，D-11.2；状态词不截断，D-11.8）。
    private func autoTargetRow(_ target: McpAgentTarget) -> some View {
        let presentation = presentation(for: target)
        return HStack(alignment: .top, spacing: 8) {
            statusIconSlot(presentation)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text(target.displayName)
                        .font(.body)
                        .lineLimit(2)
                        .truncationMode(.tail)
                    Text(presentation.statusWord)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: true, vertical: false)
                        .layoutPriority(1)
                }
                if !presentation.detail.isEmpty {
                    Text(presentation.detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .help(presentation.detail)
                }
                actionsRow(target, presentation: presentation)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(accessibilityLabel(for: target, presentation: presentation))
            Spacer(minLength: 12)
            Toggle("", isOn: intentBinding(for: target))
                .labelsHidden()
                .toggleStyle(.switch)
                .disabled(!canToggle(target))
                .help(toggleHelp(for: target))
                .accessibilityLabel("\(target.displayName) 注册开关")
        }
    }

    /// 图标槽：在飞三态只放一个 mini ProgressView（D-11.3，不叠加状态符号）。
    @ViewBuilder
    private func statusIconSlot(_ presentation: RowPresentation) -> some View {
        if let icon = presentation.icon {
            Image(systemName: icon)
                .foregroundStyle(presentation.color)
                .frame(width: iconSlotWidth)
                .accessibilityHidden(true)
        } else {
            ProgressView()
                .controlSize(.mini)
                .frame(width: iconSlotWidth)
                .accessibilityHidden(true)
        }
    }

    /// 行内动作（≤2 个，.borderless + .controlSize(.small)，D-11.5）。
    @ViewBuilder
    private func actionsRow(_ target: McpAgentTarget, presentation: RowPresentation) -> some View {
        if presentation.showsCopy || presentation.showsRepair || presentation.showsUpdate {
            HStack(spacing: 8) {
                if presentation.showsRepair, let title = presentation.repairTitle {
                    // H2：清理（再次清理/再次移除）不走授权链，总开关 OFF 时仍可用；
                    // 重试注册属于授权动作，仍需总开关 ON。
                    Button(title) { repair(target, title: title) }
                        .buttonStyle(.borderless)
                        .controlSize(.small)
                        .disabled(title == Self.cleanupActionTitle ? !canCleanup : !canOperate)
                }
                if presentation.showsUpdate {
                    Button("更新为当前库") {
                        center.register(target: target, vaultDir: model.vaultDirPath,
                                        cofferBinaryPath: cofferBinaryPath)
                    }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .disabled(!canOperate)
                }
                if presentation.showsCopy {
                    Button(copiedTarget == target ? String(localized: "已复制") : copyTitle(for: target)) {
                        copyCommand(for: target)
                    }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
                    .disabled(cofferBinaryPath.isEmpty || model.vaultDirPath.isEmpty)
                }
            }
        }
    }

    // MARK: - 折叠组「其他工具」（未安装自动工具 + copy-only）

    /// 空态判定：probe 已回、辅助程序可用、且一个自动工具都没装。
    /// （辅助程序不可用时保留工具行，让每行显示「无法读取注册状态」+ 复制入口。）
    private var showsEmptyState: Bool {
        center.hasProbed && center.helperAvailable && !center.probeFailed && center.installed.isEmpty
    }

    /// 折叠组成员：常态 = 固定 5 家 copy-only；空态（主组已换成空态块，未安装的
    /// 自动工具无处呈现）= 3 个自动工具 + 5 家 copy-only，保证复制入口不丢。
    private var otherTargets: [McpAgentTarget] {
        showsEmptyState
            ? McpAgentTarget.autoRegisterTargets + McpAgentTarget.copyOnlyTargets
            : McpAgentTarget.copyOnlyTargets
    }

    private var otherToolsGroup: some View {
        DisclosureGroup(isExpanded: $showOthers) {
            ForEach(otherTargets, id: \.self) { target in
                otherToolRow(target)
            }
        } label: {
            Text("其他工具（\(otherTargets.count)）")
                .font(.callout)
        }
    }

    /// 折叠组行：无开关（无授权面），只有复制入口。
    private func otherToolRow(_ target: McpAgentTarget) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "circle.dashed")
                .foregroundStyle(.secondary)
                .frame(width: iconSlotWidth)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(target.displayName)
                    .font(.callout)
                Text(target.isAutoRegister
                     ? String(localized: "未安装，安装后点刷新")
                     : String(localized: "仅手动配置，复制后粘贴到该工具的 MCP 配置中"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer(minLength: 8)
            Button(copiedTarget == target ? String(localized: "已复制") : copyTitle(for: target)) {
                copyCommand(for: target)
            }
            .buttonStyle(.borderless)
            .controlSize(.small)
            .disabled(cofferBinaryPath.isEmpty || model.vaultDirPath.isEmpty)
        }
        .accessibilityElement(children: .combine)
        // 三元里的字面量各自成键：占位符位是数据（工具名），后缀是文案（设计 §5.4）。
        // 用「显式模板 + String(format:)」：占位符类型（%@）直接写在源码里，与 .strings 键
        // 逐字对应，不必按插值表达式反推类型（Int / UInt32 / UInt64 → %lld / %u / %llu，
        // 见 §4 规则 2）。与纯插值写法等价，见设计 §5.4.1 规则 2。
        .accessibilityLabel(target.isAutoRegister
                            ? String(format: String(localized: "%@，未安装"), target.displayName)
                            : String(format: String(localized: "%@，仅手动配置"), target.displayName))
    }

    // MARK: - 行呈现派生

    /// 清理动作标题（与 H2 的 canCleanup 门控配对，避免两处字面量漂移）。
    private static let cleanupActionTitle = String(localized: "再次清理")

    /// 行呈现（图标 / 颜色 / 状态词 / 次文案 / 可用动作），单点派生避免各处散落分支。
    private struct RowPresentation {
        let icon: String?
        let color: Color
        let statusWord: String
        let detail: String
        let showsCopy: Bool
        let showsRepair: Bool
        let repairTitle: String?
        let showsUpdate: Bool
    }

    private func presentation(for target: McpAgentTarget) -> RowPresentation {
        if !center.helperAvailable {
            return RowPresentation(
                icon: "questionmark.circle", color: .secondary,
                statusWord: String(localized: "无法读取注册状态"),
                detail: String(localized: "注册组件不可用，重装 Coffer 后重新检测；期间可复制命令手动配置"),
                showsCopy: true, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        }
        if center.probeFailed {
            // 探测失败：installed 为空不代表未安装，必须显式落「未知」。
            return RowPresentation(
                icon: "questionmark.circle", color: .secondary,
                statusWord: String(localized: "探测失败"),
                detail: String(localized: "工具探测失败，请点刷新重试"),
                showsCopy: true, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        }
        if !center.installed.contains(target) {
            return RowPresentation(
                icon: "circle.dashed", color: .secondary,
                statusWord: String(localized: "未安装"),
                detail: String(localized: "安装后点刷新"),
                showsCopy: true, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        }
        switch center.state(for: target) {
        case .idle:
            return RowPresentation(
                icon: "circle", color: .secondary,
                statusWord: masterEnabled ? String(localized: "未检查") : String(localized: "未启用"),
                detail: masterEnabled
                    ? String(localized: "点右上角刷新检查注册状态")
                    : String(localized: "打开「启用 MCP 服务器」后自动注册"),
                showsCopy: true, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        case .checking:
            return RowPresentation(
                icon: nil, color: .secondary,
                statusWord: String(localized: "正在检查注册状态…"), detail: "",
                showsCopy: false, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        case .registering:
            return RowPresentation(
                icon: nil, color: .secondary,
                statusWord: String(localized: "正在注册…"), detail: "",
                showsCopy: false, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        case .removing:
            return RowPresentation(
                icon: nil, color: .secondary,
                statusWord: String(localized: "正在移除注册项…"), detail: "",
                showsCopy: false, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        case .registered(let registeredDir):
            let mismatched = isMismatched(registeredDir)
            return RowPresentation(
                icon: mismatched ? "exclamationmark.triangle" : "checkmark.circle",
                color: mismatched ? .orange : .green,
                statusWord: mismatched
                    ? String(localized: "已注册到其他库") : String(localized: "已注册"),
                detail: mismatched
                    ? String(format: String(localized: "注册目录与当前密码库不一致：%@"),
                             registeredDir ?? "")
                    : String(localized: "可经 MCP 访问本机密码库"),
                showsCopy: true, showsRepair: false, repairTitle: nil, showsUpdate: mismatched
            )
        case .notRegistered:
            return RowPresentation(
                icon: "circle", color: .secondary,
                statusWord: masterEnabled
                    ? String(localized: "未注册") : String(localized: "未启用"),
                detail: masterEnabled
                    ? String(localized: "打开开关即自动注册")
                    : String(localized: "打开「启用 MCP 服务器」后自动注册"),
                showsCopy: true, showsRepair: false, repairTitle: nil, showsUpdate: false
            )
        case .failed(let message):
            // 失败保持用户意图（docs/23 §6.2）：开关仍 ON，动作给「重试注册」；但
            // **总开关 OFF 时一律给「再次清理」**（H2）：此时用户意图就是「全部停用」，
            // 残留项仍能读库，重试注册被 canOperate 禁用会让这行彻底没有出口。
            let wantsEnabled = McpAgentToolPreferences.isEnabled(target)
            let retryPossible = wantsEnabled && masterEnabled
            return RowPresentation(
                icon: "exclamationmark.triangle", color: .orange,
                statusWord: wantsEnabled
                    ? String(localized: "注册失败") : String(localized: "移除失败"),
                detail: message,
                showsCopy: true, showsRepair: true,
                repairTitle: retryPossible
                    ? String(localized: "重试注册") : Self.cleanupActionTitle,
                showsUpdate: false
            )
        }
    }

    /// 注册目录与当前库不一致（切库后提示「已注册到其他库」，docs/23 N-5）。
    private func isMismatched(_ registeredDir: String?) -> Bool {
        guard let registeredDir, !registeredDir.isEmpty, !model.vaultDirPath.isEmpty else { return false }
        return registeredDir != model.vaultDirPath
    }

    // MARK: - 开关

    /// 行开关意图：显示值 = 总开关门控后的持久意图（总开关 OFF 时全部显示 OFF，
    /// 但不清持久意图——总开关再 ON 时恢复各自选择，docs/23 §4.2）。
    private func intentBinding(for target: McpAgentTarget) -> Binding<Bool> {
        Binding(
            get: { masterEnabled && McpAgentToolPreferences.isEnabled(target) },
            set: { newValue in
                McpAgentToolPreferences.setEnabled(newValue, for: target)
                if newValue {
                    center.register(target: target, vaultDir: model.vaultDirPath,
                                    cofferBinaryPath: cofferBinaryPath)
                } else {
                    center.remove(target: target)
                }
            }
        )
    }

    /// 动作可用性：总开关 ON + 辅助程序可用 + 在飞串行锁 + 已打开密码库（授权链）。
    private var canOperate: Bool {
        masterEnabled && center.helperAvailable && !center.busy && !model.vaultDirPath.isEmpty
    }

    /// 清理可用性（H2）：**不含总开关**。总开关 OFF 后的残留注册项仍能读库，若
    /// 清理入口随开关一起禁用，用户既看不到出路、也留着仍在生效的授权。
    private var canCleanup: Bool {
        center.helperAvailable && !center.busy && !model.vaultDirPath.isEmpty
    }

    /// 开关可用性：动作可用 + 该工具已安装（未安装行仍可复制命令，但不能注册）。
    private func canToggle(_ target: McpAgentTarget) -> Bool {
        canOperate && center.installed.contains(target)
    }

    /// 开关禁用原因（VoiceOver / 悬停提示）。
    private func toggleHelp(for target: McpAgentTarget) -> String {
        if !masterEnabled { return String(localized: "打开「启用 MCP 服务器」后可用") }
        if !center.helperAvailable { return String(localized: "注册组件不可用，仅支持复制命令") }
        if center.busy { return String(localized: "正在处理上一个操作，请稍候") }
        if model.vaultDirPath.isEmpty { return String(localized: "请先打开密码库") }
        if !center.installed.contains(target) {
            return String(format: String(localized: "未检测到 %@，安装后点刷新"), target.displayName)
        }
        return String(localized: "注册到该 AI 工具")
    }

    /// 失败行动作：按钮标题即动作（「重试注册」= 注册，「再次清理」= 移除），
    /// 二者门控不同（canOperate / canCleanup），故不做二次推断。
    private func repair(_ target: McpAgentTarget, title: String) {
        if title == Self.cleanupActionTitle {
            center.remove(target: target)
        } else {
            center.register(target: target, vaultDir: model.vaultDirPath,
                            cofferBinaryPath: cofferBinaryPath)
        }
    }

    /// 行内 AX 读全名 + 状态 + 次文案（D-13.6：截断处仍需读到完整内容）。
    private func accessibilityLabel(for target: McpAgentTarget, presentation: RowPresentation) -> String {
        presentation.detail.isEmpty
            ? "\(target.displayName)，\(presentation.statusWord)"
            : "\(target.displayName)，\(presentation.statusWord)，\(presentation.detail)"
    }

    // MARK: - 复制

    /// 复制按钮文案：CLI 型给「复制命令」，配置型（Windsurf / Zed 的 JSON 片段）
    /// 给「复制配置」（lead 裁定 R-3 区分两词）。
    private func copyTitle(for target: McpAgentTarget) -> String {
        switch target {
        case .claudeCode, .codeBuddy, .codex, .geminiCLI, .cursor, .vscode:
            return String(localized: "复制命令")
        case .windsurf, .zed:
            return String(localized: "复制配置")
        }
    }

    /// 复制该工具的注册命令 / 配置片段（命令构造单源：McpAgentTarget.copyCommand）。
    private func copyCommand(for target: McpAgentTarget) {
        let command = target.copyCommand(vaultDir: model.vaultDirPath,
                                        cofferBinaryPath: cofferBinaryPath)
        guard !command.isEmpty else {
            errorMessage = String(format: String(localized: "无法生成 %@ 的配置：未找到 coffer 命令或密码库目录。"),
                                  target.displayName)
            return
        }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(command, forType: .string) else {
            errorMessage = String(localized: "复制失败：无法写入剪贴板，请重试。")
            return
        }
        copiedTarget = target
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.copiedFeedbackSeconds) {
            if copiedTarget == target { copiedTarget = nil }
        }
    }
}
