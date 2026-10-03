#!/usr/bin/env bash
# run_touchid_auth_failure_tests.sh —— Touch ID 解锁失败瞬时/持久分道纯函数
# 单元测试（PL-7，2026-10-03 用户反馈）。
#
# 被测单元 TouchIDAuthFailure.disposition（Support/TouchIDAuthFailure.swift）
# 是纯函数：无 IO / 无 FFI / 无 Keychain 依赖，任何环境（含 CI 沙盒）均可
# 运行，不设 SKIP 路径（同 run_touchid_status_tests.sh 纪律）。
#
# 用法：./tools/run_touchid_auth_failure_tests.sh
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
  "${ROOT_DIR}/macos/Tests/TouchIDAuthFailureTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/TouchIDAuthFailure.swift" \
  -o "${OUT_DIR}/TouchIDAuthFailureTests"

"${OUT_DIR}/TouchIDAuthFailureTests"
