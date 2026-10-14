// UpdateCopy.swift —— OTA 更新 UI 的纯逻辑辅助（v2.7.0，docs/35 §2.6 / §6.1 / §6.3）。
//
// 与 View 解耦：版本比较、跳过版本语义、state → 按钮可用性、下载 URL 信任校验、
// 进度/文案映射均为纯函数，便于 standalone swiftc 测试（不依赖 SwiftUI / AppModel
// / 网络），测试见 Tests/UpdateUITests。
//
// 依赖类型：UpdaterState / UpdateInfo 来自 Updater 模块（docs/35 §6.3 契约冻结签名，
// 组 A 实现）。本文件只 import Foundation——测试进程用同签名 stub 编译
// （Tests/UpdateUITests/main.swift 内定义），不含 Updater 实现。
//
// §2.6 关键裁定（本文件承载的语义）：
//   - 入口只有「关于 Coffer」对话框「检查更新…」按钮 + 应用菜单同项；设置页不放
//     任何更新入口；不做后台静默检查（主动触发，零网络姿态）。
//   - 「跳过此版本」本地记录（Preferences），只有严格更新的版本才重新提示。

import Foundation

/// OTA 更新 UI 的纯逻辑辅助（见文件头注释）。
enum UpdateCopy {
    // MARK: - 版本比较（CFBundleShortVersionString 点分数字语义，如 2.7.0）

    /// 点分版本比较：按「.」分段逐段数值比较，一侧耗尽视同 0（"2.7" == "2.7.0"）。
    /// 段非数值（如预发布 "2.7.0-beta.1" 的 "beta"）按 semver 约定：预发布 < 正式版
    /// （两侧同段都非数值时回退字符串比较）。
    ///
    /// - Returns: .orderedAscending（a < b）/ .orderedSame / .orderedDescending。
    static func compareVersions(_ a: String, _ b: String) -> ComparisonResult {
        let aParts = a.split(separator: ".").map(String.init)
        let bParts = b.split(separator: ".").map(String.init)
        let count = max(aParts.count, bParts.count)
        for index in 0..<count {
            let aPart = index < aParts.count ? aParts[index] : nil
            let bPart = index < bParts.count ? bParts[index] : nil
            // 一侧已耗尽（nil）→ 视同「0」参与比较；仅当段文本非数值时才落到
            // .none（即该段存在但不是数字）。
            switch (Int(aPart ?? "0"), Int(bPart ?? "0")) {
            case let (aNum?, bNum?):
                if aNum < bNum { return .orderedAscending }
                if aNum > bNum { return .orderedDescending }
            case (.none, .some):
                // a 侧非数值段 vs b 侧数值/耗尽：a 为预发布标记（如 beta.1）→ a < b
                return .orderedAscending
            case (.some, .none):
                return .orderedDescending
            case (.none, .none):
                // 两侧同段都非数值 → 字符串比较（如 alpha < beta）
                let result = aPart!.compare(bPart!)
                if result != .orderedSame { return result }
            }
        }
        return .orderedSame
    }

    // MARK: - 跳过版本持久化（§2.6「跳过此版本」：本地记录，后续版本才重新提示）

    /// 「跳过此版本」记录键（UserDefaults；非密钥材料，仅版本号文本）。
    static let skippedVersionDefaultsKey = "ota_skipped_version"

    /// 读当前跳过版本（nil = 未跳过任何版本）。
    static func skippedVersion() -> String? {
        UserDefaults.standard.string(forKey: skippedVersionDefaultsKey)
    }

    /// 记录跳过版本（「跳过此版本」按钮动作；单调地板，更新版本自动覆盖旧记录）。
    static func recordSkippedVersion(_ version: String) {
        UserDefaults.standard.set(version, forKey: skippedVersionDefaultsKey)
    }

    /// 清除跳过记录（FRICT-14，AC-2.10.0-FR-9「恢复显示跳过的更新」入口动作）：
    /// 误点「跳过此版本」后可反悔——现状全仓无清除路径，误点即永久隐藏含安全
    /// 补丁的版本，不可逆。
    static func clearSkippedVersion() {
        UserDefaults.standard.removeObject(forKey: skippedVersionDefaultsKey)
    }

    /// 该版本是否应呈现「可更新」提示（§2.6 跳过语义）：
    /// 已跳过的版本与不高于它的版本（≤ skipped）不再呈现——手动检查命中时按
    /// 「已是最新」处理（不重复推销）；只有严格更新的版本（> skipped）才重新提示。
    /// 无跳过记录（nil）恒呈现。
    static func shouldPresentUpdate(version: String, skippedVersion: String?) -> Bool {
        guard let skippedVersion else { return true }
        return compareVersions(version, skippedVersion) == .orderedDescending
    }

    // MARK: - 下载 URL 信任校验（§2.2 应用层白名单的 UI 侧防线）

    /// 应用层白名单 4 host（docs/35 §6.2 契约冻结，勿增删）。
    static let allowedDownloadHosts: Set<String> = [
        "api.github.com",
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ]

    /// 仅 HTTPS + host ∈ 白名单 才视为可信任的更新下载 URL（UI 侧防线：
    /// 展示/外链前校验；真正的下载与验签防线在 Updater 模块）。
    /// host 全小写精确比较，防后缀混淆（"github.com.evil.example.com" 不在白名单）。
    static func isTrustedDownloadURL(_ url: URL?) -> Bool {
        guard let url,
              url.scheme?.lowercased() == "https",
              let host = url.host?.lowercased() else { return false }
        return allowedDownloadHosts.contains(host)
    }

    // MARK: - state → 按钮可用性（§2.6 按 state 精确禁用）

    /// 交互中（checking/installing）→ 禁一切按钮（含关闭）。
    static func isBusy(_ state: UpdaterState) -> Bool {
        switch state {
        case .checking, .installing: return true
        default: return false
        }
    }

    /// sheet 交互式关闭是否应被禁止（.interactiveDismissDisabled）：
    /// checking/downloading 拦（防中途打断状态机，§2.6）；**.installing 放开**——
    /// App 即将经 NSApp.terminate 退出，此时 SwiftUI 会把 quit 请求当作 sheet 的
    /// 交互式关闭尝试并取消整个终止流程（AppKit userCanceledErr，BUG-26 真机
    /// 三重实证），installing 拦交互关闭无意义且有害。
    static func blocksInteractiveDismiss(_ state: UpdaterState) -> Bool {
        switch state {
        case .checking, .downloading: return true
        default: return false
        }
    }

    /// install() 返回后的收尾计划（BUG-26）：.installing（helper 已请求拉起、本
    /// 进程即将退出）→ 程序化关闭更新 sheet 后 0.5s 终止；其余状态（.failed 等）
    /// → 留在前台呈现错误，不动 sheet 不终止。AppModel.installUpdate 据此刻画
    /// 行为；纯函数供测试断言「先关 sheet、再 terminate」的时序决策。
    enum InstallDismissPlan {
        /// 关更新 sheet（程序化 dismiss 不受 interactiveDismissDisabled 拦截）→
        /// asyncAfter(updaterTerminateDelay) → NSApp.terminate。
        case dismissThenTerminate
        /// 非 .installing：留在前台呈现错误。
        case none
    }

    static func installDismissPlan(state: UpdaterState) -> InstallDismissPlan {
        if case .installing = state { return .dismissThenTerminate }
        return .none
    }

    /// 该 state 下是否可发起一次新的检查（checking/downloading/installing 中禁止
    /// 重复触发；其余状态允许手动复查）。
    static func canStartCheck(_ state: UpdaterState) -> Bool {
        switch state {
        case .checking, .downloading, .installing: return false
        default: return true
        }
    }

    /// 渲染快照（视图绑定用；纯函数，注入跳过版本避免 UserDefaults 依赖）。
    static func buttonState(for state: UpdaterState, skippedVersion: String?) -> UpdateButtonState {
        switch state {
        case .idle:
            return UpdateButtonState(canCheck: true, canDownload: false, canSkip: false,
                                     canInstall: false, canRetry: false, canClose: true)
        case .checking:
            return UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                     canInstall: false, canRetry: false, canClose: false)
        case .updateAvailable(let info):
            let present = shouldPresentUpdate(version: info.version, skippedVersion: skippedVersion)
            // FRICT-14（AC-2.10.0-FR-9）：securityCritical 版本**禁用「跳过」**——
            // 安全补丁若可被「跳过此版本」永久藏掉（误点即不可逆），漏洞暴露窗口
            // 无限拉长；禁跳过 + 「恢复显示跳过的更新」入口（§7 OP6② 必改项）。
            return UpdateButtonState(canCheck: false, canDownload: present,
                                     canSkip: present && !info.securityCritical,
                                     canInstall: false, canRetry: false, canClose: true)
        case .upToDate:
            return UpdateButtonState(canCheck: true, canDownload: false, canSkip: false,
                                     canInstall: false, canRetry: false, canClose: true)
        case .downloading:
            return UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                     canInstall: false, canRetry: false, canClose: true)
        case .downloaded:
            return UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                     canInstall: true, canRetry: false, canClose: true)
        case .installing:
            return UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                     canInstall: false, canRetry: false, canClose: false)
        case .failed:
            return UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                     canInstall: false, canRetry: true, canClose: true)
        }
    }

    // MARK: - 文案映射

    /// 下载进度 → 百分比文案（0...1 越界钳制到 0...100）。
    static func progressPercentText(_ progress: Double) -> String {
        let clamped = min(max(progress, 0), 1)
        return "\(Int((clamped * 100).rounded()))%"
    }

    /// App 展示名（Bundle；非 App bundle 环境（如测试进程）→ 回退 "Coffer"）。
    static var appName: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? "Coffer"
    }

    /// App 版本（CFBundleShortVersionString；非 App bundle 环境 → "—"）。
    static var appVersionText: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
    }

    /// 编译时间展示文案（v2.9.2-T1，docs/35 §2.6 关于页扩展）：build 脚本注入
    /// 产物 Info.plist 的 `CofferBuildTime`（UTC，格式 `%Y-%m-%d %H:%M UTC`）。
    /// nil / 空白 → 「开发构建」（本机 swiftc 直编、测试进程或未注入键的运行）。
    static func buildTimeText(_ raw: String?) -> String {
        guard let raw,
              !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return "开发构建"
        }
        return raw
    }

    // MARK: - 检查网络失败（BUG-23：UI 短文案 + 错误码，完整错误只进 DiagLog）

    /// 更新检查网络失败错误码（BUG-23，用户裁定 2026-10-14）：检查失败 UI 呈现
    /// 短文案 + 本错误码（绝不带原始 NSError），完整错误记 DiagLog。
    static let checkNetworkErrorCode = "OTA-E-2001"

    /// BUG-23 复测修正（用户裁定 2026-10-14）：UI 呈现的检查网络失败短文案——
    /// 一句内 + 错误码可见，绝不带原始 NSError（「报错的时候我们还是有问题
    /// 的，但是要给出错误码，不用给出大段的错误信息」）；完整错误仍只进 DiagLog
    /// （checkNetworkFailureLogLine）。供 UpdateSheet failedContent 呈现 + 重试。
    static func checkNetworkFailureMessage() -> String {
        "检查更新失败（\(checkNetworkErrorCode)）"
    }

    /// BUG-23：manifest 拉取层网络失败 → 落 DiagLog 的诊断行——含错误码、完整 NSError
    /// 原文、failing URL（URLError 自带优先，否则入参兜底）、domain+code、底层错误。
    /// 纯函数（Foundation only），供 UpdateUITests 断言；UpdaterManager.check 捕获
    /// fetchManifest 抛错后调用 `DiagLog.append` 落盘。
    static func checkNetworkFailureLogLine(error: Error, url: URL) -> String {
        let ns = error as NSError
        let failingURL = ns.userInfo[NSURLErrorFailingURLStringErrorKey] as? String
            ?? url.absoluteString
        let underlying = ns.userInfo[NSUnderlyingErrorKey].map { String(describing: $0) } ?? "—"
        return "\(checkNetworkErrorCode) 更新检查网络失败（\(url.absoluteString)）："
            + "\(String(describing: error))"
            + " | failingURL=\(failingURL)"
            + " | domain=\(ns.domain) code=\(ns.code)"
            + " | underlying=\(underlying)"
    }

    // MARK: - 更新入口文案（BUG-24 复测裁定，2026-10-14）

    /// 关于页「检查更新…」按钮标题：纯文案入口。BUG-24 复测裁定：检查阶段静默，
    /// 按钮不消费 updater state、无原位进度条——区别于 checkingFeedbackText，
    /// 不存在「按钮文案 → 进行中反馈」的切换。
    static let checkButtonTitle = "检查更新…"

    /// UpdateSheet `.checking` 呈现的进行中文案。检查结果一律经 UpdateSheet 呈现
    /// （About 静默；UpdateSheet 呈现正在检查 / 已是最新 / 下载进度），单一事实源。
    static let checkingFeedbackText = "正在检查更新…"

    /// UpdateSheet `.upToDate` 呈现文案：无新版本 → 告诉用户当前是最新版本
    /// （BUG-24 复测裁定：upToDate 呈现设计不动）。
    static let upToDateText = "已是最新版本"

    // MARK: - 检查触发呈现计划（BUG-24 复测「sheet 延迟呈现修正」，2026-10-14）

    /// 关于页触发「检查更新…」时 UpdateSheet 的呈现计划。双 `.sheet` 挂同一
    /// RootView，关于在屏时 UpdateSheet 不叠加（docs/01 BUG-24 根因）——About
    /// 在屏时须等它真正关闭（onDismiss）再呈现，绝不与关闭同事务同发（SwiftUI
    /// 可能丢弃第二个 sheet 呈现）。纯决策（Foundation only），供 UpdateUITests
    /// 断言 + AppModel.checkForUpdates 消费。
    static func checkPresentationPlan(
        canStartCheck: Bool,
        aboutVisible: Bool
    ) -> UpdateCheckPresentationPlan {
        if canStartCheck {
            return aboutVisible ? .presentAfterAboutDismiss : .presentNow
        }
        return aboutVisible ? .revealByClosingAbout : .none
    }
}

/// 检查触发时 UpdateSheet 呈现决策（checkPresentationPlan 的返回值）。
enum UpdateCheckPresentationPlan: Equatable {
    /// 检查/下载/安装已在飞且 About 不在屏：无动作（UpdateSheet 已挂载或已关）。
    case none
    /// 检查/下载/安装已在飞但 About 在屏：只关 About，露出已挂载的 UpdateSheet。
    case revealByClosingAbout
    /// About 不在屏：直接开 UpdateSheet 并开始检查。
    case presentNow
    /// About 在屏：关 About，在 onDismiss 回调里再开 UpdateSheet + 开始检查。
    case presentAfterAboutDismiss
}

/// UpdateSheet 各交互按钮的可用性快照（纯函数派生；Equatable 供测试断言）。
struct UpdateButtonState: Equatable {
    let canCheck: Bool
    let canDownload: Bool
    let canSkip: Bool
    let canInstall: Bool
    let canRetry: Bool
    let canClose: Bool
}
