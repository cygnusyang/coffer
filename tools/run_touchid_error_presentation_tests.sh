#!/usr/bin/env bash
# run_touchid_error_presentation_tests.sh —— Touch ID 解锁错误呈现分道纯函数
# 单元测试（PL-5：CrossCopySheet 与主解锁路径错误呈现一致；docs/08 §7.3/§7.6）。
#
# 被测单元 TouchIDUnlockPresentation.resolve（Support/TouchIDError.swift）
# 是纯函数：无 IO / 无 FFI / 无 Keychain 依赖（文件零 CoreBindings 依赖，
# TouchIDError 已自 ErrorPresenter.swift 拆出以获得独立可测性），任何环境
# （含 CI 沙盒）均可运行，不设 SKIP 路径（同 run_touchid_auth_failure_tests.sh
# 纪律）。
#
# 依赖 BiometricKeychainError（BiometricKeychain.swift）与
# TouchIDAuthFailure.disposition（TouchIDAuthFailure.swift），一并编译。
#
# 用法：./tools/run_touchid_error_presentation_tests.sh
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
  "${ROOT_DIR}/macos/Tests/TouchIDErrorPresentationTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/TouchIDError.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/TouchIDAuthFailure.swift" \
  "${ROOT_DIR}/macos/Coffer/Platform/BiometricKeychain.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/DiagLog.swift" \
  -o "${OUT_DIR}/TouchIDErrorPresentationTests"

"${OUT_DIR}/TouchIDErrorPresentationTests"
