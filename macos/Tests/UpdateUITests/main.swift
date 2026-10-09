// UpdateUITests/main.swift —— OTA 更新 UI 纯逻辑单元测试
// （v2.7.0，docs/35 §2.6 / §6.1 / §6.3）。
//
// 被测单元 Support/UpdateCopy.swift（版本比较 / 跳过版本语义 / state→按钮可用性 /
// 下载 URL 信任校验 / 进度文案）。纯函数无 IO；跳过版本 UserDefaults 读写是薄
// 封装，测试内显式 set/removeObject。
//
// 依赖类型 UpdaterState / UpdateInfo 为契约 6.3 冻结签名的同形 stub（组 A 的
// UpdaterManager 实现未合入前，测试进程内定义，编译不含 Updater 实现）。
//
// 编译运行：tools/run_update_ui_tests.sh

import Foundation

// MARK: - 契约 6.3 stub（冻结签名，组 A UpdaterManager 同形）

struct UpdateInfo: Equatable {
    let version: String
    let minimumVersion: String
    let downloadUrl: URL
    let cdHash: String
    let buildTime: Date
    let securityCritical: Bool
    let notes: String?
}

enum UpdaterState: Equatable {
    case idle
    case checking
    case updateAvailable(UpdateInfo)
    case upToDate
    case downloading(Double)
    case downloaded
    case installing
    case failed(String)
}

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0

func check(_ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(name)")
    } else {
        failures.append("\(name) \(detail)")
        print("FAIL  \(name)  \(detail)")
    }
}

// MARK: - 夹具

func makeInfo(version: String, critical: Bool = false, notes: String? = nil) -> UpdateInfo {
    UpdateInfo(
        version: version,
        minimumVersion: "2.6.0",
        downloadUrl: URL(string: "https://github.com/cygnusyang/coffer/releases/download/\(version)/Coffer-\(version).zip")!,
        cdHash: "abc123",
        buildTime: Date(timeIntervalSince1970: 1_760_000_000),
        securityCritical: critical,
        notes: notes)
}

// MARK: - 版本比较（TC-OTA-UI-01）

do {
    check("compareVersions: 相等 2.7.0 == 2.7.0",
          UpdateCopy.compareVersions("2.7.0", "2.7.0") == .orderedSame)
    check("compareVersions: 缺失段视为 0（2.7 == 2.7.0）",
          UpdateCopy.compareVersions("2.7", "2.7.0") == .orderedSame)
    check("compareVersions: 主版本递增 1.0 < 2.0",
          UpdateCopy.compareVersions("1.0", "2.0") == .orderedAscending)
    check("compareVersions: 次版本递增 2.7.0 < 2.8.0",
          UpdateCopy.compareVersions("2.7.0", "2.8.0") == .orderedAscending)
    check("compareVersions: 修订段 2.7.1 > 2.7.0",
          UpdateCopy.compareVersions("2.7.1", "2.7.0") == .orderedDescending)
    check("compareVersions: 数字分段（2.10 > 2.9，防字符串序陷阱）",
          UpdateCopy.compareVersions("2.10.0", "2.9.0") == .orderedDescending)
    check("compareVersions: 预发布 < 正式版（2.7.0-beta.1 < 2.7.0）",
          UpdateCopy.compareVersions("2.7.0-beta.1", "2.7.0") == .orderedAscending)
    check("compareVersions: 对称性（2.7.0 > 2.7.0-beta.1）",
          UpdateCopy.compareVersions("2.7.0", "2.7.0-beta.1") == .orderedDescending)
}

// MARK: - 跳过版本语义（TC-OTA-UI-02）

do {
    check("shouldPresentUpdate: 无跳过记录 → 呈现",
          UpdateCopy.shouldPresentUpdate(version: "2.7.0", skippedVersion: nil))
    check("shouldPresentUpdate: 等于跳过版本 → 不呈现（已跳过不重复推销）",
          !UpdateCopy.shouldPresentUpdate(version: "2.7.0", skippedVersion: "2.7.0"))
    check("shouldPresentUpdate: 低于跳过版本 → 不呈现",
          !UpdateCopy.shouldPresentUpdate(version: "2.7.0", skippedVersion: "2.7.1"))
    check("shouldPresentUpdate: 严格更新版本 → 重新提示",
          UpdateCopy.shouldPresentUpdate(version: "2.7.1", skippedVersion: "2.7.0"))
}

// MARK: - 跳过版本持久化（UserDefaults 薄封装，TC-OTA-UI-03）

do {
    let key = UpdateCopy.skippedVersionDefaultsKey
    UserDefaults.standard.removeObject(forKey: key)
    defer { UserDefaults.standard.removeObject(forKey: key) }
    check("skippedVersion: 未记录 → nil", UpdateCopy.skippedVersion() == nil)
    UpdateCopy.recordSkippedVersion("2.7.0")
    check("recordSkippedVersion: 记录后读回", UpdateCopy.skippedVersion() == "2.7.0")
    UpdateCopy.recordSkippedVersion("2.7.1")
    check("recordSkippedVersion: 更新版本覆盖旧记录（单调地板）",
          UpdateCopy.skippedVersion() == "2.7.1")
}

// MARK: - 下载 URL 信任校验（§2.2 / §6.2 白名单，TC-OTA-UI-04）

do {
    let trusted = URL(string: "https://github.com/cygnusyang/coffer/releases/download/v2.7.0/Coffer-v2.7.0.zip")!
    check("isTrustedDownloadURL: github.com https → 信任",
          UpdateCopy.isTrustedDownloadURL(trusted))
    let cdn = URL(string: "https://objects.githubusercontent.com/some/path/asset")!
    check("isTrustedDownloadURL: objects.githubusercontent.com → 信任",
          UpdateCopy.isTrustedDownloadURL(cdn))
    let releaseAssets = URL(string: "https://release-assets.githubusercontent.com/x/y")!
    check("isTrustedDownloadURL: release-assets.githubusercontent.com → 信任",
          UpdateCopy.isTrustedDownloadURL(releaseAssets))
    let http = URL(string: "http://github.com/coffer.zip")!
    check("isTrustedDownloadURL: http → 拒绝（强制 HTTPS）",
          !UpdateCopy.isTrustedDownloadURL(http))
    let evil = URL(string: "https://evil.example.com/coffer.zip")!
    check("isTrustedDownloadURL: 非白名单 host → 拒绝",
          !UpdateCopy.isTrustedDownloadURL(evil))
    let suffix = URL(string: "https://github.com.evil.example.com/coffer.zip")!
    check("isTrustedDownloadURL: 白名单后缀混淆 → 拒绝",
          !UpdateCopy.isTrustedDownloadURL(suffix))
    check("isTrustedDownloadURL: nil → 拒绝",
          !UpdateCopy.isTrustedDownloadURL(nil))
}

// MARK: - state → 按钮可用性（TC-OTA-UI-05）

do {
    check("buttonState idle: 可检查 + 可关闭",
          UpdateCopy.buttonState(for: .idle, skippedVersion: nil)
            == UpdateButtonState(canCheck: true, canDownload: false, canSkip: false,
                                 canInstall: false, canRetry: false, canClose: true))
    check("buttonState checking: 禁一切（含关闭）",
          UpdateCopy.buttonState(for: .checking, skippedVersion: nil)
            == UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                 canInstall: false, canRetry: false, canClose: false))
    check("buttonState upToDate: 可检查 + 可关闭",
          UpdateCopy.buttonState(for: .upToDate, skippedVersion: nil)
            == UpdateButtonState(canCheck: true, canDownload: false, canSkip: false,
                                 canInstall: false, canRetry: false, canClose: true))
    check("buttonState updateAvailable: 可下载 + 可跳过",
          UpdateCopy.buttonState(for: .updateAvailable(makeInfo(version: "2.7.0")), skippedVersion: nil)
            == UpdateButtonState(canCheck: false, canDownload: true, canSkip: true,
                                 canInstall: false, canRetry: false, canClose: true))
    check("buttonState updateAvailable + 已跳过同版本: 不再推销",
          UpdateCopy.buttonState(for: .updateAvailable(makeInfo(version: "2.7.0")), skippedVersion: "2.7.0")
            == UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                 canInstall: false, canRetry: false, canClose: true))
    check("buttonState updateAvailable + 新版本 > 跳过版本: 重新推销",
          UpdateCopy.buttonState(for: .updateAvailable(makeInfo(version: "2.7.1")), skippedVersion: "2.7.0")
            == UpdateButtonState(canCheck: false, canDownload: true, canSkip: true,
                                 canInstall: false, canRetry: false, canClose: true))
    check("buttonState downloading: 可关闭、不可下载/检查",
          UpdateCopy.buttonState(for: .downloading(0.5), skippedVersion: nil)
            == UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                 canInstall: false, canRetry: false, canClose: true))
    check("buttonState downloaded: 可安装 + 可关闭",
          UpdateCopy.buttonState(for: .downloaded, skippedVersion: nil)
            == UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                 canInstall: true, canRetry: false, canClose: true))
    check("buttonState installing: 禁一切（含关闭）",
          UpdateCopy.buttonState(for: .installing, skippedVersion: nil)
            == UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                 canInstall: false, canRetry: false, canClose: false))
    check("buttonState failed: 可重试 + 可关闭",
          UpdateCopy.buttonState(for: .failed("网络错误"), skippedVersion: nil)
            == UpdateButtonState(canCheck: false, canDownload: false, canSkip: false,
                                 canInstall: false, canRetry: true, canClose: true))
}

// MARK: - 可否发起新检查（AppModel.checkForUpdates guard，TC-OTA-UI-06）

do {
    check("canStartCheck idle → true", UpdateCopy.canStartCheck(.idle))
    check("canStartCheck checking → false", !UpdateCopy.canStartCheck(.checking))
    check("canStartCheck downloading → false", !UpdateCopy.canStartCheck(.downloading(0.3)))
    check("canStartCheck installing → false", !UpdateCopy.canStartCheck(.installing))
    check("canStartCheck updateAvailable → true（可复查）",
          UpdateCopy.canStartCheck(.updateAvailable(makeInfo(version: "2.7.0"))))
    check("canStartCheck upToDate → true", UpdateCopy.canStartCheck(.upToDate))
    check("canStartCheck downloaded → true", UpdateCopy.canStartCheck(.downloaded))
    check("canStartCheck failed → true", UpdateCopy.canStartCheck(.failed("x")))
}

// MARK: - isBusy（TC-OTA-UI-07）

do {
    check("isBusy checking → true", UpdateCopy.isBusy(.checking))
    check("isBusy installing → true", UpdateCopy.isBusy(.installing))
    check("isBusy downloading → false", !UpdateCopy.isBusy(.downloading(0.5)))
    check("isBusy idle → false", !UpdateCopy.isBusy(.idle))
    check("isBusy upToDate → false", !UpdateCopy.isBusy(.upToDate))
}

// MARK: - 进度文案（TC-OTA-UI-08）

do {
    check("progressPercentText 0 → 0%", UpdateCopy.progressPercentText(0) == "0%")
    check("progressPercentText 0.5 → 50%", UpdateCopy.progressPercentText(0.5) == "50%")
    check("progressPercentText 1 → 100%", UpdateCopy.progressPercentText(1) == "100%")
    check("progressPercentText 1.5 越界 → 100%", UpdateCopy.progressPercentText(1.5) == "100%")
    check("progressPercentText -1 越界 → 0%", UpdateCopy.progressPercentText(-1) == "0%")
    check("progressPercentText 0.334 → 33%", UpdateCopy.progressPercentText(0.334) == "33%")
}

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
