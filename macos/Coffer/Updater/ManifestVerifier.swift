// ManifestVerifier.swift —— 清单 canonical JSON + Ed25519 验签（docs/35 §6.1，契约冻结）。
//
// canonical JSON 约定（契约 6.1 关键）：被签名内容 = 去除 `signature` 字段后的
// JSON，序列化 = JSONSerialization + `.sortedKeys` + `.withoutEscapingSlashes`
// （无缩进）。签名侧（CI 工具 sign_update_manifest.sh，组 C）与验签侧（本文件）
// 用同一 `canonicalJSONData` 函数保证字节一致。

import Foundation
import CryptoKit

/// 清单验签（纯逻辑，可独立测试）。
enum ManifestVerifier {
    /// 更新签名验证公钥（base64 Ed25519 原始公钥 32 字节，契约 6.1）。
    ///
    /// ⚠️ **占位公钥**：CI 首次生成更新密钥对后必须替换（docs/35 §2.3 更新密钥
    /// 在 CI secrets；对应私钥只在 CI，永不落仓）。占位私钥已本地生成后丢弃，
    /// 保证常量是合法 Ed25519 公钥（解析不失败）；测试全部注入自生成临时公钥，
    /// 不依赖本常量值。
    static let cofferUpdatePublicKeyBase64 = "68TycH3avKtzM3UMPdHfEq87pNQbfJiMwgFvK+OnM+I="

    /// 验签显式错误（fail-closed：任何失败即拒装）。
    enum VerificationError: Error, LocalizedError {
        /// 清单非 JSON / 结构损坏。
        case invalidJSON
        /// 缺 `signature` 字段。
        case missingSignature
        /// 公钥 base64 非法或不是合法 Ed25519 公钥。
        case invalidPublicKey
        /// 签名 base64 非法。
        case invalidSignatureData
        /// Ed25519 验签不通过（清单被篡改 / 非官方签名）。
        case signatureMismatch

        var errorDescription: String? {
            switch self {
            case .invalidJSON:
                return "更新清单格式无效，无法验签。"
            case .missingSignature:
                return "更新清单缺少签名，已拒绝。"
            case .invalidPublicKey:
                return "更新验签公钥无效。"
            case .invalidSignatureData:
                return "更新清单签名数据无效。"
            case .signatureMismatch:
                return "更新清单签名校验失败，已拒绝安装。"
            }
        }
    }

    /// canonical JSON（契约 6.1，双侧同实现）：sortedKeys + withoutEscapingSlashes，
    /// 无缩进。CI 签名工具与 App 验签侧共用此函数保证字节一致。
    static func canonicalJSONData(_ dict: [String: Any]) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: dict,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }

    /// 对完整清单 JSON 做验签：解析 dict → 取 signature → canonical(去 signature)
    /// → Ed25519 verify。任何一步失败即抛错（fail-closed）。
    ///
    /// - Parameters:
    ///   - data: 完整清单 JSON 字节（含 signature 字段）。
    ///   - publicKeyBase64: 验证公钥（默认硬编码常量；测试注入自生成公钥）。
    /// - Returns: 验签是否通过（true）。
    /// - Throws: `VerificationError`。
    static func verify(manifestJSONData data: Data, publicKeyBase64: String = cofferUpdatePublicKeyBase64) throws -> Bool {
        guard let raw = try? JSONSerialization.jsonObject(with: data),
              var dict = raw as? [String: Any] else {
            throw VerificationError.invalidJSON
        }
        guard let signatureBase64 = dict["signature"] as? String, !signatureBase64.isEmpty else {
            throw VerificationError.missingSignature
        }
        dict.removeValue(forKey: "signature")
        let canonical = try canonicalJSONData(dict)

        guard let publicKeyData = Data(base64Encoded: publicKeyBase64),
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData) else {
            throw VerificationError.invalidPublicKey
        }
        guard let signature = Data(base64Encoded: signatureBase64) else {
            throw VerificationError.invalidSignatureData
        }
        guard publicKey.isValidSignature(signature, for: canonical) else {
            throw VerificationError.signatureMismatch
        }
        return true
    }
}
