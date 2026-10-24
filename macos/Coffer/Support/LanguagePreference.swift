// LanguagePreference.swift —— 语言偏好的读 / 写 / 三态模型（v2.13.0，
// docs/03-功能设计/24-v2.13.0-多语言-设计.md §6）。
//
// 模型（§6.1）：三态，值与 AppleLanguages 对齐——跟随系统 / zh-Hans / en。
// 存储（§6.2，D-9 方案 A）：**单源 = App 自己偏好域的 AppleLanguages**。这与 macOS
// 13+「系统设置 → 语言与地区 → 应用程序」写的是同一个键，因此两处天然一致：不用
// 迁移、也不会出现「自建键说跟随系统、AppleLanguages 说 en」这种二源打架。
//
// 两条实测事实必须留在代码里，否则会踩回去（设计 F9–F11）：
//   F11 读：**不能**用 UserDefaults.standard.object(forKey: "AppleLanguages")。
//        无 app 域值时它会读到**全局域**的系统语言，于是「用户显式选了简体中文」与
//        「跟随系统（系统恰好是中文）」看起来完全一样，Picker 永远显示「简体中文」
//        而不是「跟随系统」。判定「是否被显式设置」只能读 persistentDomain(forName:)：
//        没有该键时返回 nil，而 CFPreferencesCopyAppValue 会回落全局域。
//   F10 生效时机：写入后**当前进程不生效**（系统在进程启动时缓存了 .lproj 解析结果，
//        连新建的 Bundle(path:) 实例也按旧语言解析）。所以 apply 的返回值是「是否
//        需要重启才能生效」，UI 必须如实告知，不能假装已经切换。
//
// 分层：本文件只用 Foundation（+ CFPreferences），不碰 SwiftUI，因此可进 swiftc
// 选编单测（macos/Tests/LocalizationTests，tools/run_l10n_tests.sh）——与
// MenuStatusText / MenuIconGeometry 同一模式。

import Foundation

/// App 内语言三态（值域与 AppleLanguages 对齐）。
enum AppLanguage: String, CaseIterable {
    /// 跟随系统（app 偏好域里没有 AppleLanguages 键）。
    case system
    /// 简体中文。不需要 zh-Hans.lproj：中文由 key 回落承担（设计 §4.2）。
    case zhHans = "zh-Hans"
    /// English。
    case en = "en"

    /// 选择器展示名（自身也需要本地化：中文「跟随系统」/ 英文 "System"）。
    /// en 固定写 "English"——语言名称按自称惯例，不参与翻译（设计 §5.6 专名不译）。
    var displayName: String {
        switch self {
        case .system:
            return String(localized: "跟随系统")
        case .zhHans:
            return String(localized: "简体中文")
        case .en:
            return "English"
        }
    }
}

/// 语言偏好的唯一读写入口（纯逻辑部分全部是静态纯函数，便于单测）。
enum LanguagePreference {

    /// App 偏好域里的键名。与系统设置「应用程序语言」同一底层（F9）。
    static let appleLanguagesKey = "AppleLanguages"

    // MARK: - 纯逻辑（零偏好域依赖，可独立单测）

    /// 把「显式写入的 AppleLanguages 数组」解析为三态。
    ///
    /// - nil / 空数组 → .system（app 域没有该键 = 跟随系统）
    /// - 首元素 en 开头 → .en；zh 开头 → .zhHans
    /// - 其它值 → .system：用户在系统设置里选了第三语言（如 ja）时**不覆盖、
    ///   不误显示**，仍按系统走（设计 §6.2 末段）。
    static func resolve(explicitLanguages: [String]?) -> AppLanguage {
        guard let first = explicitLanguages?.first else { return .system }
        if first.hasPrefix("en") { return .en }
        if first.hasPrefix("zh") { return .zhHans }
        return .system
    }

    /// 三态 → 要写入偏好域的值。.system 返回 nil = **移除该键**。
    ///
    /// 注意不能写空数组：空数组会被系统当成「支持语言列表为空」，与「没设置过」
    /// 语义不同，会让 App 落到开发语言而不是走系统语言。
    static func storageValue(for language: AppLanguage) -> [String]? {
        switch language {
        case .system:
            return nil
        case .zhHans:
            return [AppLanguage.zhHans.rawValue]
        case .en:
            return [AppLanguage.en.rawValue]
        }
    }

    /// 语言切换后是否需要重启才生效（F10：同进程内不生效）。
    ///
    /// 判据 = 与**启动快照**是否相同：写入的值就是本次进程已在用的语言时不需要重启；
    /// 不同则必须重启。.system 与具体语言之间的比较无法得知系统语言，按「需要重启」
    /// 处理（保守：宁可多提示一次，也不要静默告诉用户已切换）。
    static func requiresRestart(from launch: AppLanguage, to next: AppLanguage) -> Bool {
        launch != next
    }

    /// 语言级（L1）解析：用户偏好 → bundle 本地化列表（精确 → 语言前缀）→
    /// CFBundleDevelopmentRegion → 列表首个（设计 §6.5）。
    ///
    /// 这是「选哪个 .lproj」这一层。键级（L2）**不存在跨语言回落**：所选 .lproj 里缺
    /// key 就直接用 key 本身（F2），所以这里绝不能实现「查 en 失败再查 zh」——那是
    /// 多余且错误的行为（§6.5 末段）。
    ///
    /// - Parameters:
    ///   - preferred: 用户偏好列表（AppleLanguages，已按优先级排序）。
    ///   - available: bundle 的本地化列表（Bundle.main.localizations）。
    ///   - developmentRegion: CFBundleDevelopmentRegion（本仓恒为 zh_CN）。
    static func effective(preferred: [String],
                          available: [String],
                          developmentRegion: String?) -> AppLanguage {
        // F3：开发区域会被无条件注入 bundle 本地化列表，并决定「用户语言不在支持
        // 列表」时回退到谁。删掉它，日法用户会落到英文而非中文——违背中文优先。
        var supported = available
        if let dev = developmentRegion, !dev.isEmpty, !supported.contains(dev) {
            supported.append(dev)
        }
        for identifier in preferred {
            if let matched = matchedLanguage(for: identifier, in: supported) {
                return matched
            }
        }
        if let dev = developmentRegion, let language = language(forIdentifier: dev) {
            return language
        }
        for identifier in supported {
            if let language = language(forIdentifier: identifier) {
                return language
            }
        }
        // 最终兜底 = 源语言。中文永远显示中文（无论系统是什么语言）。
        return .zhHans
    }

    /// 语言标识 → 三态；无法识别（ja / fr…）返回 nil，由调用方继续回退。
    static func language(forIdentifier identifier: String) -> AppLanguage? {
        let lower = identifier.lowercased()
        if lower.hasPrefix("en") { return .en }
        if lower.hasPrefix("zh") { return .zhHans }
        return nil
    }

    /// 在支持的本地化列表里为该标识找匹配：先精确（忽略大小写与 - _ 差异），
    /// 再退化到语言前缀（zh-Hans-CN 命中 zh-Hans）。
    private static func matchedLanguage(for identifier: String,
                                       in supported: [String]) -> AppLanguage? {
        let normalized = identifier.replacingOccurrences(of: "_", with: "-").lowercased()
        if let exact = supported.first(where: {
            $0.replacingOccurrences(of: "_", with: "-").lowercased() == normalized
        }) {
            return language(forIdentifier: exact)
        }
        let code = normalized.split(separator: "-").first.map(String.init) ?? normalized
        if let prefixed = supported.first(where: { candidate in
            let lowered = candidate.replacingOccurrences(of: "_", with: "-").lowercased()
            return (lowered.split(separator: "-").first.map(String.init) ?? lowered) == code
        }) {
            return language(forIdentifier: prefixed)
        }
        return nil
    }

    // MARK: - 偏好域读写

    /// 当前**用户显式选择**的语言（app 偏好域）。
    ///
    /// 用 persistentDomain 是硬要求（F11）：只有它能区分「显式写了 en」与「没写过、
    /// 全局域恰好是 en」。
    static var current: AppLanguage {
        resolve(explicitLanguages: explicitAppDomainLanguages())
    }

    /// 本次进程启动时实际生效的语言（快照常量）。
    ///
    /// 含义是「现在屏幕上这套文案是哪种语言」，不是「偏好里存了什么」：写入新偏好后
    /// 它不会变，直到下次启动（F10）。用于把「要不要重启」如实告诉用户。
    static var launchLanguage: AppLanguage {
        launchSnapshot
    }

    private static let launchSnapshot: AppLanguage = {
        let bundle = Bundle.main
        return effective(preferred: bundle.preferredLocalizations,
                         available: bundle.localizations,
                         developmentRegion: bundle.infoDictionary?["CFBundleDevelopmentRegion"] as? String)
    }()

    /// 写入语言偏好，返回「是否需要重启才能生效」（true = UI 必须提示重启）。
    ///
    /// 不在 app bundle 内运行（单元测试二进制、CLI）时没有 bundle id，写入是空操作，
    /// 此时返回 false——什么都没写，自然也不需要重启。生产路径由 Info.plist 的
    /// CFBundleIdentifier 保证非 nil。
    @discardableResult
    static func apply(_ language: AppLanguage) -> Bool {
        guard let bundleID = Bundle.main.bundleIdentifier else { return false }
        write(appleLanguages: storageValue(for: language), bundleID: bundleID)
        return requiresRestart(from: launchLanguage, to: language)
    }

    /// 读 app 域里的 AppleLanguages（没写过 → nil）。
    private static func explicitAppDomainLanguages() -> [String]? {
        guard let bundleID = Bundle.main.bundleIdentifier else { return nil }
        return UserDefaults.standard.persistentDomain(forName: bundleID)?[appleLanguagesKey] as? [String]
    }

    /// 写 app 域（F9 的实测路径：CFPreferencesSetAppValue + Synchronize）。
    private static func write(appleLanguages: [String]?, bundleID: String) {
        if let values = appleLanguages {
            CFPreferencesSetAppValue(appleLanguagesKey as CFString,
                                     values as CFArray,
                                     bundleID as CFString)
        } else {
            // 「跟随系统」= 删除该键（写 nil），不是写空数组。
            CFPreferencesSetAppValue(appleLanguagesKey as CFString, nil, bundleID as CFString)
        }
        CFPreferencesAppSynchronize(bundleID as CFString)
    }
}
