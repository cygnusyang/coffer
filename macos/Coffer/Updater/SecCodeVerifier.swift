// SecCodeVerifier.swift —— 下载产物验签（docs/35 §6.3 三级：DR 主锚 +
// TeamID/identifier 复核 + 清单 CDHash 次锚；沿用 P-S spike 裁定
// coffer-v230-ps-spike-seccode-ruling：TeamID 主、CDHash 次，CDHash 用
// kSecCodeInfoUnique；H-3 修复补 §2.3 第 3 级嵌套 Contents/Helpers 验签）。
//
// 验签范围：.app 顶层（DR + TeamID/identifier + CDHash）+ 嵌套
// Contents/Helpers/*.app（DR anchor+TeamID + identifier ∈ 期望集合 + TeamID，
// H-3）。外层签名本身也密封嵌套 cdhash（探针实证），嵌套验签为纵深防线。

import Foundation
import Security

/// 产物验签协议（注入点：UpdateTests 用 stub 驱动 install 状态机；生产用
/// `SecCodeVerifierAdapter`）。
protocol ProductVerifying {
    func verifyApp(at url: URL, expectedCdHash: String) throws
}

/// 生产验签适配器：转发到 `SecCodeVerifier`（三级：DR + TeamID/identifier + CDHash）。
struct SecCodeVerifierAdapter: ProductVerifying {
    func verifyApp(at url: URL, expectedCdHash: String) throws {
        try SecCodeVerifier.verifyApp(at: url, expectedCdHash: expectedCdHash)
    }
}

/// 产物验签（纯逻辑，依赖 Security framework；可对已签名产物测试）。
enum SecCodeVerifier {
    /// 团队 ID（Apple Development 证书，docs/35 §1；P-S spike 主锚）。
    static let teamID = "A6DS985SJJ"
    /// 期望 bundle identifier（契约 6.1 appId 同值）。
    static let expectedIdentifier = "app.coffer.Coffer"
    /// 嵌套 Contents/Helpers 的期望 identifier 集合（契约 §2.3 第 3 级，H-3）：
    /// 嵌套 coffer.app 与 CofferUpdater.app（对照 build_macos_app.sh 3.5/3.6
    /// 装配的 CFBundleIdentifier 值）。
    static let expectedHelperIdentifiers: Set<String> = [
        "app.coffer.Coffer",
        "app.coffer.Coffer.updater",
    ]

    /// 验签显式错误（fail-closed：任何一级不过即拒装）。
    enum VerificationError: Error, LocalizedError {
        /// 无法基于路径创建静态代码对象（非 bundle / 不可读）。
        case cannotCreateCode(OSStatus)
        /// DR 需求字符串非法（代码缺陷，不应发生）。
        case invalidRequirement(OSStatus)
        /// DR 验签不过（签名缺失 / 链不可信 / 非官方签名）。
        case signatureInvalid(OSStatus)
        /// 无法读取签名信息。
        case cannotReadSigningInfo(OSStatus)
        /// 签名信息缺 `kSecCodeInfoUnique`。
        case missingCdHash
        /// bundle identifier 不匹配。
        case identifierMismatch(String)
        /// TeamID 不匹配。
        case teamIDMismatch(String?)
        /// CDHash 不匹配（expected, actual）——「合法签名但非官方构建」防线。
        case cdHashMismatch(expected: String, actual: String)
        /// Contents/Helpers 下无任何可验签的嵌套 bundle（伪造无嵌套；§2.3 第 3 级，H-3）。
        case nestedHelperMissing
        /// 嵌套 helper 验签失败（path, detail；H-3）。
        case nestedHelperInvalid(path: String, detail: String)

        var errorDescription: String? {
            switch self {
            case .cannotCreateCode(let status):
                return "无法读取待安装应用的签名信息（OSStatus \(status)）。"
            case .invalidRequirement(let status):
                return "验签需求字符串无效（OSStatus \(status)）。"
            case .signatureInvalid(let status):
                return "应用签名校验失败（OSStatus \(status)）。"
            case .cannotReadSigningInfo(let status):
                return "无法读取应用签名信息（OSStatus \(status)）。"
            case .missingCdHash:
                return "应用签名信息缺少 CDHash，已拒绝安装。"
            case .identifierMismatch(let id):
                return "应用标识符「\(id)」与预期 \(expectedIdentifier) 不符，已拒绝安装。"
            case .teamIDMismatch(let id):
                return "应用团队 ID「\(id ?? "（无）")」与预期 \(teamID) 不符，已拒绝安装。"
            case .cdHashMismatch:
                return "应用 CDHash 与更新清单不符，已拒绝安装（可能非官方构建）。"
            case .nestedHelperMissing:
                return "更新包缺少内置安装辅助程序，已拒绝安装。"
            case .nestedHelperInvalid(let path, let detail):
                return "内置安装辅助程序验签失败（\(path)）：\(detail)，已拒绝安装。"
            }
        }
    }

    /// DR 需求字符串：Apple 通用锚 + bundle identifier + 叶证书 OU = TeamID
    /// （主锚，跨更新稳定；与 P-S spike 裁定一致）。
    static var designatedRequirementString: String {
        "anchor apple generic and identifier \"\(expectedIdentifier)\" "
            + "and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// 嵌套 helper 的 DR：anchor apple generic + 叶证书 OU = TeamID，**不含
    /// identifier**——嵌套有两个合法 identifier（coffer.app / CofferUpdater.app），
    /// identifier 由代码级集合复核（`expectedHelperIdentifiers`）兜底。
    static var helperDesignatedRequirementString: String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// 对 .app 做三级验签：① DR（anchor apple generic + identifier + OU）
    /// ② TeamID/identifier 复核 ③ kSecCodeInfoUnique 比对清单 cdHash
    /// ④（H-3）嵌套 Contents/Helpers/*.app 逐一验签（§2.3 第 3 级）。
    ///
    /// - Parameters:
    ///   - url: 待验签 .app 的 URL（下载解压后路径）。
    ///   - expectedCdHash: 清单声明的 cdHash（hex，kSecCodeInfoUnique 语义）。
    /// - Throws: `VerificationError`。
    static func verifyApp(at url: URL, expectedCdHash: String) throws {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            throw VerificationError.cannotCreateCode(createStatus)
        }

        // ① DR 主锚
        var requirement: SecRequirement?
        let reqStatus = SecRequirementCreateWithString(
            designatedRequirementString as CFString, [], &requirement)
        guard reqStatus == errSecSuccess, let req = requirement else {
            throw VerificationError.invalidRequirement(reqStatus)
        }
        let validityStatus = SecStaticCodeCheckValidity(code, [], req)
        guard validityStatus == errSecSuccess else {
            throw VerificationError.signatureInvalid(validityStatus)
        }

        // ② TeamID/identifier 复核 + ③ CDHash 次锚
        var info: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        guard infoStatus == errSecSuccess, let dict = info as? [String: Any] else {
            throw VerificationError.cannotReadSigningInfo(infoStatus)
        }

        let identifier = dict[kSecCodeInfoIdentifier as String] as? String ?? ""
        guard identifier == expectedIdentifier else {
            throw VerificationError.identifierMismatch(identifier)
        }
        let team = dict[kSecCodeInfoTeamIdentifier as String] as? String
        guard team == teamID else {
            throw VerificationError.teamIDMismatch(team)
        }

        let actual = try cdHashHex(of: url)
        guard actual.caseInsensitiveCompare(expectedCdHash) == .orderedSame else {
            throw VerificationError.cdHashMismatch(expected: expectedCdHash, actual: actual)
        }

        // ④（H-3）嵌套 Contents/Helpers/*.app 逐一验签（§2.3 第 3 级）
        try verifyNestedHelpers(in: url)
    }

    /// 对 `.app` 的 `Contents/Helpers/*.app` 逐一验签（契约 §2.3 第 3 级，H-3）。
    /// 任一嵌套 bundle 未签名 / 异 TeamID / identifier 不在期望集合 → 抛错拒装
    /// （fail-closed）；无 Helpers 目录或其中无任何 .app = 「伪造无嵌套」→ 拒装。
    /// 外层签名本身也密封嵌套 cdhash（探针实证），本函数为纵深防线（testable，
    /// 可对合成目录直调）。
    static func verifyNestedHelpers(in appURL: URL) throws {
        let helpersDir = appURL.appendingPathComponent("Contents/Helpers")
        let fm = FileManager.default
        var nested: [URL] = []
        if fm.fileExists(atPath: helpersDir.path) {
            let contents = (try? fm.contentsOfDirectory(
                at: helpersDir, includingPropertiesForKeys: nil)) ?? []
            nested = contents.filter { $0.pathExtension == "app" }
        }
        guard !nested.isEmpty else {
            throw VerificationError.nestedHelperMissing
        }
        for helper in nested {
            try verifyNestedHelper(at: helper)
        }
    }

    /// 对单个嵌套 helper 验签：DR（anchor + TeamID）→ identifier ∈ 期望集合 →
    /// TeamID 复核。任一步不过即抛错（路径带进错误便于定位）。
    private static func verifyNestedHelper(at helper: URL) throws {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(helper as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            throw VerificationError.nestedHelperInvalid(
                path: helper.path, detail: "无法读取签名信息（OSStatus \(createStatus)）")
        }
        var requirement: SecRequirement?
        let reqStatus = SecRequirementCreateWithString(
            helperDesignatedRequirementString as CFString, [], &requirement)
        guard reqStatus == errSecSuccess, let req = requirement else {
            throw VerificationError.invalidRequirement(reqStatus)
        }
        let validityStatus = SecStaticCodeCheckValidity(code, [], req)
        guard validityStatus == errSecSuccess else {
            throw VerificationError.nestedHelperInvalid(
                path: helper.path, detail: "签名校验失败（OSStatus \(validityStatus)）")
        }
        var info: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        guard infoStatus == errSecSuccess, let dict = info as? [String: Any] else {
            throw VerificationError.nestedHelperInvalid(
                path: helper.path, detail: "无法读取签名信息（OSStatus \(infoStatus)）")
        }
        let identifier = dict[kSecCodeInfoIdentifier as String] as? String ?? ""
        guard expectedHelperIdentifiers.contains(identifier) else {
            throw VerificationError.identifierMismatch(identifier)
        }
        let team = dict[kSecCodeInfoTeamIdentifier as String] as? String
        guard team == teamID else {
            throw VerificationError.teamIDMismatch(team)
        }
    }

    /// 读取产物的 `kSecCodeInfoUnique`（CDHash，20 字节 sha256 截断），hex 小写。
    /// 与 `codesign -dv --verbose=4` 的 `CDHash=` 输出一致（probe 实证）。
    static func cdHashHex(of url: URL) throws -> String {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            throw VerificationError.cannotCreateCode(createStatus)
        }
        var info: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        guard infoStatus == errSecSuccess, let dict = info as? [String: Any] else {
            throw VerificationError.cannotReadSigningInfo(infoStatus)
        }
        guard let unique = dict[kSecCodeInfoUnique as String] as? Data else {
            throw VerificationError.missingCdHash
        }
        return unique.map { String(format: "%02x", $0) }.joined()
    }
}
