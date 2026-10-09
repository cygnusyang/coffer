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
            return UpdateButtonState(canCheck: false, canDownload: present, canSkip: present,
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
