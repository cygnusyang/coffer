#!/usr/bin/env swift
// tools/sign_update_manifest.swift —— OTA 更新清单签名 helper（docs/35 §6.1 契约）。
//
// 由组 C 的 sign_update_manifest.sh 调用（不单独使用）。从环境变量读取清单字段
// 与 Ed25519 私钥，按 canonical JSON 约定（JSONSerialization + .sortedKeys +
// .withoutEscapingSlashes，无缩进）序列化**除 signature 外的字段**并签名，最后
// 输出含 signature 的完整清单（同样 canonical 序列化，便于 diff 与审计）。
//
// ⚠️ canonical JSON 是双侧契约（docs/35 §6.1）：验签侧（组 A 的 Updater）必须用
// 与本文件 canonicalJSON() 完全相同的序列化方式（同 options、同字段集合、同类型
// 表示：schemaVersion 用 Int、securityCritical 用 Bool、字符串原样）对「去除
// signature 后的字段」重新序列化再验签，才能字节级一致。集成轮 lead 协调组 A
// 对齐本函数。
//
// 输入（环境变量）：
//   UPDATE_SIGNING_KEY_BASE64  必填，Ed25519 私钥原始种子（32 字节）的 base64
//   MF_VERSION / MF_MINIMUM_VERSION / MF_BUILD_TIME / MF_DOWNLOAD_URL / MF_CDHASH
//                              必填
//   MF_SECURITY_CRITICAL       可选，"true"/"false"，默认 "false"
//   MF_NOTES                   可选发布说明；空串则省略该字段
//
// ⚠️ 私钥只经环境变量传入，本工具不打印、不回显、不落盘私钥；stdout 仅输出最终
// 清单，stderr 仅输出错误诊断。
//
// 边界校验（fail fast）：cdHash 必须为 40 位 hex（kSecCodeInfoUnique = 20 字节，
// 与 extract_cdhash.sh 契约一致）；downloadUrl 必须为 https://；必填字段非空。
// 校验失败即 fail()（stderr 一句原因 + 非零退出，无堆栈噪音），不静默降级——
// 错误值会直接导致 OTA 验签失败。
import Foundation
import CryptoKit

let env = ProcessInfo.processInfo.environment

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("sign_update_manifest.swift: " + message + "\n").utf8))
    exit(1)
}

func required(_ name: String) -> String {
    guard let v = env[name], !v.isEmpty else {
        fail("缺少必填环境变量 \(name)")
    }
    return v
}

// --- 契约固定字段（docs/35 §6.1，冻结，不可由调用方改写）---
let schemaVersion: Int = 1
let appId: String = "app.coffer.Coffer"

// --- 读入可变字段 + 边界校验 ---
let version = required("MF_VERSION")
let minimumVersion = required("MF_MINIMUM_VERSION")
let buildTime = required("MF_BUILD_TIME")
let downloadUrl = required("MF_DOWNLOAD_URL")
let cdHash = required("MF_CDHASH").lowercased()

// cdHash 校验：kSecCodeInfoUnique = 20 字节 → 40 位 hex（与 extract_cdhash.sh 输出契约一致）。
guard cdHash.count == 40, cdHash.allSatisfy({ $0.isHexDigit }) else {
    fail("MF_CDHASH 必须为 40 位 hex（收到 \(cdHash.count) 字符）")
}
// downloadUrl 强制 https（契约 downloadUrl 语义 = https URL）。
guard downloadUrl.hasPrefix("https://") else {
    fail("MF_DOWNLOAD_URL 必须为 https:// URL")
}

let securityCritical: Bool = {
    guard let raw = env["MF_SECURITY_CRITICAL"], !raw.isEmpty else { return false }
    guard let b = Bool(raw) else {
        fail("MF_SECURITY_CRITICAL 须为 true/false（收到 \(raw)）")
    }
    return b
}()

var fields: [String: Any] = [
    "schemaVersion": schemaVersion,
    "appId": appId,
    "version": version,
    "minimumVersion": minimumVersion,
    "buildTime": buildTime,
    "downloadUrl": downloadUrl,
    "cdHash": cdHash,
    "securityCritical": securityCritical,
]
if let notes = env["MF_NOTES"], !notes.isEmpty {
    fields["notes"] = notes
}

// --- canonical JSON（docs/35 §6.1 契约：双侧同实现，App 验签须用同一序列化）---
func canonicalJSON(_ obj: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes])
}

// --- Ed25519 签名（私钥经环境变量传入，绝不打日志）---
guard let keyB64 = env["UPDATE_SIGNING_KEY_BASE64"], !keyB64.isEmpty else {
    fail("缺少环境变量 UPDATE_SIGNING_KEY_BASE64（Ed25519 私钥 32 字节 base64）")
}
guard let keyData = Data(base64Encoded: keyB64), keyData.count == 32 else {
    fail("UPDATE_SIGNING_KEY_BASE64 解码失败或非 32 字节 Ed25519 种子")
}

do {
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
    // 签名对象 = 去除 signature 字段后的 canonical JSON（契约 §6.1）。
    let payload = try canonicalJSON(fields)
    let signature = try privateKey.signature(for: payload)

    fields["signature"] = signature.base64EncodedString()
    let finalData = try canonicalJSON(fields)
    guard let out = String(data: finalData, encoding: .utf8) else {
        fail("canonical JSON 输出编码失败")
    }
    FileHandle.standardOutput.write(Data((out + "\n").utf8))
} catch {
    fail("签名/序列化失败：\(error)")
}
