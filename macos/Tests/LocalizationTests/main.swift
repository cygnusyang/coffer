// LocalizationTests/main.swift —— 语言偏好与回退链纯逻辑单测（v2.13.0）。
//
// 目标判据（本文件顶注即规格，docs/03-功能设计/24-v2.13.0-多语言-设计.md）：
//   §1 resolve —— 「是否被显式设置」的判定（F11）：无值 = 跟随系统；第三语言
//      （ja/fr）不得被误判成任何具体语言，否则 Picker 会显示错值并覆盖用户选择。
//   §2 storageValue —— 三态 → 偏好域值；.system 必须是「移除键」(nil) 而不是空数组。
//   §3 requiresRestart —— F10：同进程内不生效，切换与启动快照不同即须提示重启。
//   §4 effective —— L1 语言级回退链：偏好 → 本地化列表（精确/前缀）→
//      CFBundleDevelopmentRegion → 列表首个（§6.5）。**不存在**键级跨语言回落。
//   §5 current —— F11 的反向哨兵：本测试二进制没有 app 偏好域，必须返回 .system；
//      若实现改回 UserDefaults.object(forKey:) 会读到全局域系统语言而变红。
//
// 被测单元 macos/Coffer/Support/LanguagePreference.swift（Foundation-only，不碰
// SwiftUI），与 MenuStatusText / MenuIconGeometry 同一选编模式。
//
// .strings 解析与占位符校验（G1–G4）不在 Swift 侧重复实现：那是 tools/check_l10n.sh
// 的职责，由 tools/run_l10n_tests.sh 用夹具（fixtures/）逐类跑负向用例覆盖。

import Foundation

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

// MARK: - §1 resolve（显式值判定，F11）

check("无值(nil) → 跟随系统",
      LanguagePreference.resolve(explicitLanguages: nil) == .system)
check("空数组 → 跟随系统",
      LanguagePreference.resolve(explicitLanguages: []) == .system)
check("[en] → .en",
      LanguagePreference.resolve(explicitLanguages: ["en"]) == .en)
check("[en-US] → .en（区域后缀不影响）",
      LanguagePreference.resolve(explicitLanguages: ["en-US"]) == .en)
check("[zh-Hans] → .zhHans",
      LanguagePreference.resolve(explicitLanguages: ["zh-Hans"]) == .zhHans)
check("[zh-Hans-CN] → .zhHans",
      LanguagePreference.resolve(explicitLanguages: ["zh-Hans-CN"]) == .zhHans)
check("[ja] → 跟随系统（不覆盖第三语言）",
      LanguagePreference.resolve(explicitLanguages: ["ja"]) == .system)
check("[fr] → 跟随系统（不覆盖第三语言）",
      LanguagePreference.resolve(explicitLanguages: ["fr"]) == .system)
check("首元素优先：[en, zh-Hans] → .en",
      LanguagePreference.resolve(explicitLanguages: ["en", "zh-Hans"]) == .en)
check("首元素优先：[zh-Hans, en] → .zhHans",
      LanguagePreference.resolve(explicitLanguages: ["zh-Hans", "en"]) == .zhHans)

// MARK: - §2 storageValue（三态 → 偏好域值）

check(".system → nil（移除键，不写空数组）",
      LanguagePreference.storageValue(for: .system) == nil)
check(".en → [en]",
      LanguagePreference.storageValue(for: .en) == ["en"])
check(".zhHans → [zh-Hans]",
      LanguagePreference.storageValue(for: .zhHans) == ["zh-Hans"])
check("往返：storageValue 后再 resolve 保持原值（.en）",
      LanguagePreference.resolve(explicitLanguages: LanguagePreference.storageValue(for: .en)) == .en)
check("往返：storageValue 后再 resolve 保持原值（.zhHans）",
      LanguagePreference.resolve(explicitLanguages: LanguagePreference.storageValue(for: .zhHans)) == .zhHans)
check("往返：.system 的 nil 解析回跟随系统",
      LanguagePreference.resolve(explicitLanguages: LanguagePreference.storageValue(for: .system)) == .system)

// MARK: - §3 requiresRestart（F10：同进程内不生效）

check("同语言 → 不需要重启",
      LanguagePreference.requiresRestart(from: .en, to: .en) == false)
check("en → zh-Hans → 需要重启",
      LanguagePreference.requiresRestart(from: .en, to: .zhHans) == true)
check("跟随系统 → en → 需要重启",
      LanguagePreference.requiresRestart(from: .system, to: .en) == true)
check("zh-Hans → 跟随系统 → 需要重启",
      LanguagePreference.requiresRestart(from: .zhHans, to: .system) == true)

// MARK: - §4 effective（L1 语言级回退链，§6.5）

check("英文偏好命中 en.lproj",
      LanguagePreference.effective(preferred: ["en"], available: ["en"], developmentRegion: "zh_CN") == .en)
check("zh-Hans-CN 前缀命中开发区域（无 zh lproj 时仍解析为中文）",
      LanguagePreference.effective(preferred: ["zh-Hans-CN"], available: ["en"], developmentRegion: "zh_CN") == .zhHans)
check("日语用户回退中文而非英文（AC-L10N-07：dev region 生效）",
      LanguagePreference.effective(preferred: ["ja"], available: ["en"], developmentRegion: "zh_CN") == .zhHans)
check("无 dev region 时日语用户落到列表首个（en）",
      LanguagePreference.effective(preferred: ["ja"], available: ["en"], developmentRegion: nil) == .en)
check("无偏好时按 dev region 解析",
      LanguagePreference.effective(preferred: [], available: ["en"], developmentRegion: "zh_CN") == .zhHans)
check("本地化列表为空时仍回退源语言",
      LanguagePreference.effective(preferred: ["ja"], available: [], developmentRegion: "zh_CN") == .zhHans)
check("无 dev region 且列表为空 → 源语言兜底",
      LanguagePreference.effective(preferred: ["ja"], available: [], developmentRegion: nil) == .zhHans)
check("偏好在支持列表里没有对应项时不误选（fr → dev region）",
      LanguagePreference.effective(preferred: ["fr"], available: ["en"], developmentRegion: "zh_CN") == .zhHans)
check("语言标识识别：EN 大小写不敏感",
      LanguagePreference.language(forIdentifier: "EN") == .en)
check("语言标识识别：zh_CN",
      LanguagePreference.language(forIdentifier: "zh_CN") == .zhHans)
check("语言标识识别：ja 不可识别",
      LanguagePreference.language(forIdentifier: "ja") == nil)

// MARK: - §5 current（F11 反向哨兵）

// 本测试二进制没有 app 偏好域（无 CFBundleIdentifier），current 必须是「跟随系统」。
// 若实现改回 UserDefaults.standard.object(forKey: "AppleLanguages")，会读到全局域的
// 系统语言（中文机器即 zh-Hans），这条立刻变红——这正是 F11 要防的坑。
check("无 app 偏好域 → current 为跟随系统",
      LanguagePreference.current == .system,
      "实际 \(LanguagePreference.current)")

// launchLanguage 是快照常量：必须是三态之一，且多次读取稳定（F10 的同进程语义）。
let launchFirst = LanguagePreference.launchLanguage
check("launchLanguage 取值稳定（快照常量）",
      launchFirst == LanguagePreference.launchLanguage)
check("launchLanguage 必须是三态之一",
      AppLanguage.allCases.contains(launchFirst))
check("AppLanguage 三态齐全（Picker 顺序：跟随系统/简体中文/English）",
      AppLanguage.allCases == [.system, .zhHans, .en])
check("displayName 均非空",
      AppLanguage.allCases.allSatisfy { !$0.displayName.isEmpty })


// MARK: - H4：F11 的可测哨兵（app 域才算显式，全局域不算）

check("显式 app 域 [en] → .en",
      LanguagePreference.explicitLanguage(appDomain: ["AppleLanguages": ["en"]]) == .en)
check("显式 app 域 [zh-Hans] → .zhHans",
      LanguagePreference.explicitLanguage(appDomain: ["AppleLanguages": ["zh-Hans"]]) == .zhHans)
check("app 域无 AppleLanguages → nil（跟随系统）",
      LanguagePreference.explicitLanguage(appDomain: ["Other": 1]) == nil)
check("app 域为 nil → nil（即使系统/全局域是 en，也不算显式选择）",
      LanguagePreference.explicitLanguage(appDomain: nil) == nil)
check("显式但不受支持的语言 [ja] → nil（回落跟随系统，而非误判为某语言）",
      LanguagePreference.explicitLanguage(appDomain: ["AppleLanguages": ["ja"]]) == nil)

// MARK: - 汇总

print("----")
print("\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    print("ALL RED:\n" + failures.map { "  - \($0)" }.joined(separator: "\n"))
    exit(1)
}
print("ALL GREEN")
