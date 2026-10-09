#!/usr/bin/env bash
# tools/derive_update_public_key.sh —— 从 Ed25519 私钥 seed 派生公钥（H-2 公钥一致性核查）。
#
# 用途：release.yml 的「更新验签公钥一致性核查」步骤调用，把 CI secret
# UPDATE_SIGNING_KEY_BASE64（Ed25519 私钥 32 字节 seed base64）对应的公钥派生出来，
# 供与源码常量 ManifestVerifier.cofferUpdatePublicKeyBase64 比对（防占位符泄漏/漂移，
# dev-reviewer H-2，v2.7.0）。
#
# 输入：UPDATE_SIGNING_KEY_BASE64（环境变量，必填；CI secret，Ed25519 私钥 base64）
# 输出：对应公钥（raw 32 字节）的 base64，写 stdout；诊断走 stderr。
#
# ⚠️ 私钥纪律：私钥只经环境变量传入（CI secret），本脚本与 Swift helper 不打印、
# 不回显、不落盘私钥。输出仅含公钥 base64（公钥非机密）。
#
# 用法：
#   UPDATE_SIGNING_KEY_BASE64=... ./tools/derive_update_public_key.sh
# 退出码：0 = 成功（stdout 为公钥 base64）；非 0 = 失败（stderr 为原因）。
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SWIFT_HELPER="${SCRIPT_DIR}/derive_update_public_key.swift"

if [ ! -f "$SWIFT_HELPER" ]; then
    echo "ERROR: 缺少 helper：$SWIFT_HELPER（应随本脚本同在 tools/ 下）" >&2
    exit 1
fi

# 私钥 secret 缺失即 fail（值不回显）。
if [ -z "$(printenv UPDATE_SIGNING_KEY_BASE64)" ]; then
    echo "ERROR: 环境变量 UPDATE_SIGNING_KEY_BASE64 未设置（Ed25519 私钥 base64；生成指导见 tools/sign_update_manifest.sh 头部注释）" >&2
    exit 1
fi

if ! command -v swift >/dev/null 2>&1; then
    echo "ERROR: 未找到 swift（需要完整 Xcode / CLT 以加载 CryptoKit）" >&2
    exit 1
fi

# 私钥经环境变量透传给 helper，不落盘、不回显；stdout 仅公钥 base64。
swift "$SWIFT_HELPER" || {
    echo "ERROR: derive_update_public_key.swift 执行失败（见其上 stderr；注意私钥绝不回显）" >&2
    exit 1
}
