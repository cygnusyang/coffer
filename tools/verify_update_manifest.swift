#!/usr/bin/env swift
// tools/verify_update_manifest.swift —— OTA 更新清单验签 helper（探针用，只读，无 secret）。
//
// 与 sign_update_manifest.swift 共用同一 canonical JSON 契约（docs/35 §6.1）：
// JSONSerialization + [.sortedKeys, .withoutEscapingSlashes]、无缩进，对「去除
// signature 后的字段」重新序列化，再用 Ed25519 公钥验签——签名侧与验签侧必须
// 字节级一致。本文件不持有任何密钥，只接收公钥入参（探针匿名只读纪律）。
//
// 用法：
//   swift tools/verify_update_manifest.swift <manifest.json> <公钥base64>
//     <manifest.json>  必填，待验清单文件路径（run_ota_probe.sh 步骤 ① 落盘）
//     <公钥base64>     必填，Ed25519 公钥 raw 32 字节的 base64。与
//                      ManifestVerifier.swift 的 cofferUpdatePublicKeyBase64 必须
//                      一致（run_ota_probe.sh 从 App 源码自动提取并传入，杜绝双源
//                      漂移——密钥轮换只改一处，另一处未跟即验签失败 → 探针告警）。
// v2.10.3 T1（探针强化）：新清单必须含 sha256 字段且为 64 位 hex 小写（下载完整性
// 前置校验的声明源）；缺字段/格式非法 → 退出码 1（与验签失败同门禁，防发布侧漏传）。
// 退出码：0 = 验签通过（stdout 一行 VERIFY=VALID）；1 = 验签失败 / 清单损坏 /
//   sha256 缺字段或格式非法 / canonical 重建失败；2 = 用法错误 / 解析错误。
import Foundation
import CryptoKit

func fail(_ code: Int32, _ message: String) -> Never {
    FileHandle.standardError.write(Data(("verify_update_manifest.swift: " + message + "\n").utf8))
    exit(code)
}

let args = CommandLine.arguments
guard args.count == 3 else {
    fail(2, "用法：verify_update_manifest.swift <manifest.json> <公钥base64>")
}
let manifestPath = args[1]
let pubB64 = args[2]

guard let raw = FileManager.default.contents(atPath: manifestPath),
      let obj = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
    fail(2, "无法读取或解析清单：\(manifestPath)")
}
guard let sigB64 = obj["signature"] as? String, !sigB64.isEmpty,
      let signature = Data(base64Encoded: sigB64), signature.count == 64 else {
    fail(1, "清单缺少 signature 字段或非 Ed25519 签名（64 字节）")
}
guard let pubData = Data(base64Encoded: pubB64), pubData.count == 32,
      let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubData) else {
    fail(2, "公钥 base64 解码失败或非 32 字节 Ed25519 公钥")
}

// T1（v2.10.3）：新清单必须含 sha256（下载 zip 完整性声明源），且 64 位 hex 小写。
guard let sha256 = obj["sha256"] as? String, !sha256.isEmpty else {
    fail(1, "清单缺少 sha256 字段（v2.10.3 T1 起新清单必须含下载 zip 的 SHA256）")
}
guard sha256.count == 64, sha256.allSatisfy({ $0.isHexDigit }),
      sha256.lowercased() == sha256 else {
    fail(1, "清单 sha256 字段格式非法：须 64 位 hex 小写（收到 \(sha256.count) 字符）")
}

// canonical 重建（契约：去除 signature 字段后重新序列化）。
var payload = obj
payload.removeValue(forKey: "signature")
let canonical: Data
do {
    canonical = try JSONSerialization.data(
        withJSONObject: payload, options: [.sortedKeys, .withoutEscapingSlashes])
} catch {
    fail(1, "canonical JSON 重建失败：\(error)")
}

if publicKey.isValidSignature(signature, for: canonical) {
    FileHandle.standardOutput.write(Data("VERIFY=VALID\n".utf8))
    exit(0)
}
fail(1, "Ed25519 验签失败（公钥与清单签名不匹配或清单被篡改）")
