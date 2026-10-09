#!/usr/bin/env swift
// tools/derive_update_public_key.swift —— 从 Ed25519 私钥 seed 派生公钥（H-2 公钥一致性核查）。
//
// 被 derive_update_public_key.sh 调用（不单独使用）。输入 = 环境变量
// UPDATE_SIGNING_KEY_BASE64（Ed25519 私钥原始 32 字节 seed 的 base64，CI secret）；
// 输出 = 对应公钥（raw 32 字节）的 base64，写 stdout。与 sign_update_manifest.swift
// 使用同一派生逻辑（Curve25519.Signing.PrivateKey.rawRepresentation），保证派生
// 结果与签名侧公钥一致。
//
// ⚠️ 私钥纪律：私钥只经环境变量读入，本工具不打印、不回显、不落盘私钥；stdout
// 仅输出公钥 base64（公钥非机密，H-2 核查日志允许出现）。失败即 exit 1
// （stderr 一句原因），不静默。
import Foundation
import CryptoKit

let env = ProcessInfo.processInfo.environment

guard let keyB64 = env["UPDATE_SIGNING_KEY_BASE64"], !keyB64.isEmpty else {
    FileHandle.standardError.write(
        Data("derive_update_public_key.swift: 缺少环境变量 UPDATE_SIGNING_KEY_BASE64\n".utf8))
    exit(1)
}
guard let keyData = Data(base64Encoded: keyB64), keyData.count == 32 else {
    FileHandle.standardError.write(
        Data("derive_update_public_key.swift: UPDATE_SIGNING_KEY_BASE64 解码失败或非 32 字节 Ed25519 种子\n".utf8))
    exit(1)
}
do {
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
    let pubB64 = privateKey.publicKey.rawRepresentation.base64EncodedString()
    FileHandle.standardOutput.write(Data((pubB64 + "\n").utf8))
} catch {
    FileHandle.standardError.write(Data("derive_update_public_key.swift: 公钥派生失败：\(error)\n".utf8))
    exit(1)
}
