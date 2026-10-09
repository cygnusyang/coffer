// UpdateManifest.swift —— 更新清单 schema v1（docs/35 §6.1，契约冻结）。
//
// 解析（Codable）+ 显式校验（schemaVersion / appId / 必需字段），全部失败
// 路径显式报错（拒装）。signature 为必需字段（验签在 ManifestVerifier）。

import Foundation

/// 更新清单（schema v1，字段与契约 6.1 逐一对应）。
struct UpdateManifest: Codable, Equatable {
    /// 当前识别的 schema 版本（契约 6.1：恒 1，不识别即拒装）。
    static let currentSchemaVersion = 1
    /// 恒 `app.coffer.Coffer`；不匹配即拒装（契约 6.1）。
    static let expectedAppId = "app.coffer.Coffer"

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
    /// base64 Ed25519 签名（canonical(前 9 字段 JSON)，契约 6.1）。
    let signature: String

    /// 清单解析与合法性显式错误（fail-closed：任何不满足即拒装）。
    enum ParseError: Error, LocalizedError {
        /// 非 JSON / 结构损坏 / 字段类型不匹配。
        case invalidJSON(String)
        /// 缺少必需字段（键名）。
        case missingField(String)
        /// schemaVersion ≠ 当前识别版本。
        case unsupportedSchemaVersion(Int)
        /// appId 与 `app.coffer.Coffer` 不匹配。
        case wrongAppId(String)

        var errorDescription: String? {
            switch self {
            case .invalidJSON(let detail):
                return "更新清单格式无效：\(detail)"
            case .missingField(let key):
                return "更新清单缺少必需字段：\(key)。"
            case .unsupportedSchemaVersion(let v):
                return "更新清单 schema 版本 \(v) 不受支持，已拒绝安装。"
            case .wrongAppId(let id):
                return "更新清单 appId「\(id)」与本应用不匹配，已拒绝安装。"
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
            return .invalidJSON(path.isEmpty ? "\(error)" : "字段 \(path)")
        @unknown default:
            return .invalidJSON("\(error)")
        }
    }
}
