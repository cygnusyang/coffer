#!/usr/bin/env bash
# run_keychain_tests.sh —— BiometricKeychain 单元测试（docs/08 §9 T03 验收①）。
#
# 在真 Keychain 上跑 save/read/delete 往返 + DuplicateItem 覆盖 + delete 幂等；
# 无 Touch ID 机器走 requireBiometry=false 测试路径（docs/08 T03 验收①
# 「无 accessControl 的测试路径」）；无 Keychain 环境（CI 沙盒）探针失败时
# 整体 SKIP（exit 0，见 main.swift 探针逻辑）。
#
# 用法：./tools/run_keychain_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# 只编译被测单元 + 测试入口（不依赖 CoreBindings / Rust 静态库）
swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Tests/KeychainTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Platform/BiometricKeychain.swift" \
  -o "${OUT_DIR}/KeychainTests"

"${OUT_DIR}/KeychainTests"
