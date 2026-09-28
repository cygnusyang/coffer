// HealthCheckView.swift —— 安全体检页（FR-6.2/6.3/6.4/6.5/6.6/6.7，v0.3.0-T05 T-D）。
//
// 只读语义：本视图只调 `VaultSession.healthReport(nowSecs:)`（Rust 侧全量
// 解密 + 启发式扫描），不做任何写入。healthReport 需解锁态（Rust 1001 门禁）
// ——入口在侧栏（仅解锁区可达），View 内仍 guard session 兜底。
//
// now_secs 注入纪律：必须传真实时钟（Int64(Date().timeIntervalSince1970)）。
// 陈旧判定 = now - updated_at，传 0 会让全部条目瞬间判 stale（FR-6.4 失真）。
//
// 加载纪律：healthReport 全量解密较慢（条目多时可达秒级），与全仓慢调用
// 一致用 Task.detached 包裹（AuditLogView / AppModel.unlock 同模式）。
//
// 错误纪律（与 AuditLogView 一致）：错误文案经 ErrorPresenter 直出，
// 落 DiagLog + model.lastErrorMessage → .ffiErrorAlert。
//
// 诚实声明（FR-6.5 / FR-6.7）：泄露检测为离线启发式（本地字典/规则），
// 不覆盖真实泄露事件——零网络原则，页脚固定 caption 展示。

import SwiftUI

// MARK: - 本地化映射（纯函数，便于将来单测）

extension FfiLeakRule {
    /// 泄露规则中文名（UI 展示用）。
    var displayName: String {
        // 与绑定 enum 全 case 对齐（无 default：Rust 侧新增变体时此处
        // 编译报错，强制补映射——同 AuditLogView 纪律）。
        switch self {
        case .dictionaryExact: return "字典精确命中"
        case .leetNormalized: return "变体变形命中"
        case .birthdayPattern: return "生日模式"
        case .keyboardSequence: return "键盘序列"
        }
    }
}

extension FfiLeakConfidence {
    /// 置信度中文名（UI 展示用）。
    var displayName: String {
        switch self {
        case .high: return "高"
        case .medium: return "中"
        case .low: return "低"
        }
    }
}

// MARK: - 视图

struct HealthCheckView: View {
    @EnvironmentObject
    private var model: AppModel

    /// 体检报告（nil = 尚未加载完成）。
    @State private var report: FfiHealthReport?
    /// 首次加载进行中标记。
    @State private var isLoading = true

    var body: some View {
        Group {
            if isLoading {
                ProgressView("正在体检…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let report {
                reportList(report)
            }
        }
        .navigationTitle("安全体检")
        .task { await loadReport() }
        .ffiErrorAlert($model.lastErrorMessage)
    }

    // MARK: 报告列表

    @ViewBuilder
    private func reportList(_ report: FfiHealthReport) -> some View {
        List {
            Section {
                summaryCard(report.summary)
            }
            if report.summary.totalFindings == 0 {
                Section {
                    allClear
                }
            } else {
                duplicateSection(report.duplicateGroups)
                weakUrlSection(report.httpUrlItems)
                staleSection(report.staleItems)
                leakSection(report.leakSuspects)
                missingTotpSection(report.missingTotpItems)
            }
            Section {
                // FR-6.5 诚实声明：页脚固定 caption，任何体检结果下都展示。
                Text("泄露检测为离线启发式（本地字典/规则），不覆盖真实泄露事件——零网络原则")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .listStyle(.inset)
    }

    /// 六格汇总卡（FR-6.7）：重复组 / 弱 URL / 陈旧 / 泄露嫌疑 / 无 2FA / 总计。
    private func summaryCard(_ summary: FfiHealthSummary) -> some View {
        Grid(alignment: .center, horizontalSpacing: 12, verticalSpacing: 14) {
            GridRow {
                summaryCell(summary.duplicateGroupCount, label: "重复组", symbol: "square.on.square")
                summaryCell(summary.weakUrlCount, label: "弱 URL", symbol: "link")
                summaryCell(summary.staleCount, label: "陈旧密码", symbol: "clock.arrow.circlepath")
            }
            GridRow {
                summaryCell(summary.leakSuspectCount, label: "泄露嫌疑", symbol: "exclamationmark.shield")
                summaryCell(summary.missingTotpCount, label: "无 2FA", symbol: "lock.open")
                summaryCell(summary.totalFindings, label: "总计", symbol: "list.bullet")
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
    }

    private func summaryCell(_ count: UInt32, label: String, symbol: String) -> some View {
        VStack(spacing: 4) {
            Text("\(count)")
                .font(.title2.weight(.semibold))
                .monospacedDigit()
                .foregroundStyle(count > 0 ? Color.primary : Color.secondary)
            Label(label, systemImage: symbol)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }

    /// 空报告友好态。
    private var allClear: some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 40))
                .foregroundStyle(.green)
            Text("未发现安全问题")
                .font(.headline)
            Text("各类启发式检查均未命中，建议定期回来看看。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
    }

    // MARK: 五个发现区（空区不渲染，数字看汇总卡）

    @ViewBuilder
    private func duplicateSection(_ groups: [FfiDuplicateGroupFinding]) -> some View {
        if !groups.isEmpty {
            Section("重复密码") {
                ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                    // 组行点击跳组内第一个条目。
                    findingRow(title: group.titles.joined(separator: "、"),
                               caption: "组内 \(group.itemIds.count) 个条目共用同一密码",
                               symbol: "square.on.square") {
                        if let first = group.itemIds.first {
                            jump(to: first)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func weakUrlSection(_ items: [FfiItemFinding]) -> some View {
        if !items.isEmpty {
            Section("弱 URL") {
                ForEach(items, id: \.itemId) { finding in
                    findingRow(title: finding.title,
                               caption: "URL 使用 http:// 明文协议",
                               symbol: "link") {
                        jump(to: finding.itemId)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func staleSection(_ items: [FfiStaleFinding]) -> some View {
        if !items.isEmpty {
            Section("陈旧密码") {
                ForEach(items, id: \.itemId) { finding in
                    findingRow(title: finding.title,
                               caption: "\(finding.daysSinceUpdate) 天未改",
                               symbol: "clock.arrow.circlepath") {
                        jump(to: finding.itemId)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func leakSection(_ items: [FfiLeakFinding]) -> some View {
        if !items.isEmpty {
            Section("泄露嫌疑") {
                ForEach(items, id: \.itemId) { finding in
                    findingRow(title: finding.title,
                               caption: "\(finding.rule.displayName) · 置信度\(finding.confidence.displayName)",
                               symbol: "exclamationmark.shield") {
                        jump(to: finding.itemId)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func missingTotpSection(_ items: [FfiItemFinding]) -> some View {
        if !items.isEmpty {
            Section("无 2FA 提示") {
                ForEach(items, id: \.itemId) { finding in
                    findingRow(title: finding.title,
                               caption: "未配置两步验证（TOTP）",
                               symbol: "lock.open") {
                        jump(to: finding.itemId)
                    }
                }
            }
        }
    }

    /// 发现行通用样式：图标 + 标题 + 说明 caption，整行可点击跳转。
    private func findingRow(title: String, caption: String, symbol: String,
                            action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: symbol)
                    .foregroundStyle(.secondary)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    Text(caption)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .buttonStyle(.plain)
        .padding(.vertical, 2)
    }

    // MARK: - 跳转

    /// 跳转条目：先切走体检页（防中栏仍渲染本视图时自吞选中事件），
    /// 再选中条目（didSet 自动 loadSelectedDetails）。
    ///
    /// 静默降级：条目在报告生成后已被删除时（getItem 必报错），切换过滤
    /// 触发的同步 reloadItems 之后在活动列表中找不到该 ID，此处直接返回，
    /// 不发起选中、不弹错误（报告快照与实时列表的固有竞态，保持简单）。
    private func jump(to itemId: String) {
        // sidebarFilter didSet 同步执行 reloadItems，返回后 items 即为最新。
        model.sidebarFilter = .all
        guard model.items.contains(where: { $0.uuid == itemId }) else { return }
        model.selectedItemID = itemId
    }

    // MARK: - 加载

    private func loadReport() async {
        // 侧栏入口仅解锁区可达，session 必非 nil；防御性 guard 兜底
        // （1001 场景不应发生，发生即按错误呈现）。
        guard let session = model.session else {
            isLoading = false
            let errText = "内部错误：安全体检需解锁后查看。"
            DiagLog.append(errText)
            model.lastErrorMessage = errText
            return
        }
        do {
            // now_secs 传真实时钟（见文件头注释）；局部捕获避免 detached
            // 闭包跨 actor 访问 MainActor 属性。
            let now = Int64(Date().timeIntervalSince1970)
            let fetched = try await Task.detached(priority: .userInitiated) {
                try session.healthReport(nowSecs: now)
            }.value
            report = fetched
        } catch {
            // 错误文案 Rust 侧已脱敏，直出并落诊断日志（同 AuditLogView）。
            let errText = ErrorPresenter.text(error)
            DiagLog.append(errText)
            model.lastErrorMessage = errText
        }
        isLoading = false
    }
}
