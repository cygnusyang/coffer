// UpdateManifest.swift —— 更新清单 schema v1（docs/35 §6.1，契约冻结）。
//
// 解析（Codable）+ 显式校验（schemaVersion / appId / 必需字段），全部失败
// 路径显式报错（拒装）。signature 为必需字段（验签在 ManifestVerifier）。
// sha256 为可选字段（v2.10.3 T1，docs/01 下载完整性加固）：存在且非空即须与
// 下载 zip 字节一致（校验在 UpdaterManager.download，见 UpdateChecksum.swift）；
// 缺省或空串跳过（向后兼容 v2.10.2 旧清单）。字段随 canonical JSON 一并被签名
// 覆盖（去 signature 后的完整 dict）。

import Foundation

/// 更新清单（schema v1，字段与契约 6.1 逐一对应）。
struct UpdateManifest: Codable, Equatable {
    /// 当前识别的 schema 版本（契约 6.1：恒 1，不识别即拒装）。
    static let currentSchemaVersion = 1
    /// 恒 `top.cygnusyang.coffer`；不匹配即拒装（契约 6.1）。
    static let expectedAppId = "top.cygnusyang.coffer"

    let schemaVersion: Int
    let appId: String
    let version: String
    let minimumVersion: String
    /// RFC3339 构建时间（驱动 profile TTL 校验，§2.3；字符串原样参与 canonical）。
    let buildTime: String
    let downloadUrl: String
    let cdHash: String
    let securityCritical: Bool
    let notes: String?
    /// 下载 zip 的 SHA256（v2.10.3 T1，可选：缺省/空串跳过校验，向后兼容旧清单；
    /// 存在且非空时下载后解压前强制比对，不匹配拒装——见 UpdateChecksum.swift）。
    /// 随 canonical JSON 被签名覆盖（去 signature 后的完整 dict，契约 6.1）。
    let sha256: String?
    /// base64 Ed25519 签名（canonical(除 signature 外全字段 JSON)，契约 6.1）。
    let signature: String

    /// 清单解析与合法性显式错误（fail-closed：任何不满足即拒装）。
    enum ParseError: Error, LocalizedError {
        /// 非 JSON / 结构损坏 / 字段类型不匹配。
        case invalidJSON(String)
        /// 缺少必需字段（键名）。
        case missingField(String)
        /// schemaVersion ≠ 当前识别版本。
        case unsupportedSchemaVersion(Int)
        /// appId 与 `top.cygnusyang.coffer` 不匹配。
        case wrongAppId(String)

        var errorDescription: String? {
            switch self {
            case .invalidJSON(let detail):
                return String(localized: "更新清单格式无效：\(detail)")
            case .missingField(let key):
                return String(localized: "更新清单缺少必需字段：\(key)。")
            case .unsupportedSchemaVersion(let v):
                return String(localized: "更新清单 schema 版本 \(String(v)) 不受支持，已拒绝安装。")
            case .wrongAppId(let id):
                return String(localized: "更新清单 appId「\(id)」与本应用不匹配，已拒绝安装。")
            }
        }
    }

    /// 解析并校验清单（fail-closed：非 JSON / 缺字段 / schema ≠ 1 / appId
    /// 不匹配一律抛错）。
    static func parse(_ data: Data) throws -> UpdateManifest {
        let manifest: UpdateManifest
        do {
            manifest = try JSONDecoder().decode(UpdateManifest.self, from: data)
        } catch let error as DecodingError {
            throw decodeError(from: error)
        } catch {
            throw ParseError.invalidJSON("\(error)")
        }
        guard manifest.schemaVersion == currentSchemaVersion else {
            throw ParseError.unsupportedSchemaVersion(manifest.schemaVersion)
        }
        guard manifest.appId == expectedAppId else {
            throw ParseError.wrongAppId(manifest.appId)
        }
        return manifest
    }

    /// 把 Codable 解码错误映射为缺字段/非法 JSON（保留字段名，便于定位）。
    private static func decodeError(from error: DecodingError) -> ParseError {
        switch error {
        case .keyNotFound(let key, _):
            return .missingField(key.stringValue)
        case .valueNotFound(let type, let context):
            // 字段存在但为 null / 缺非可选值：优先用编码路径键名定位
            let key = context.codingPath.first?.stringValue ?? "\(type)"
            return .missingField(key)
        case .typeMismatch(_, let context),
             .dataCorrupted(let context):
            let path = context.codingPath.map { $0.stringValue }.joined(separator: ".")
            return .invalidJSON(path.isEmpty ? "\(error)" : String(localized: "字段 \(path)"))
        @unknown default:
            return .invalidJSON("\(error)")
        }
    }
}
