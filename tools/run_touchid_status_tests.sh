#!/usr/bin/env bash
# run_touchid_status_tests.sh —— Touch ID 三态判定纯函数单元测试
# （docs/08 §9 T04 验收②）。
#
# 被测单元 TouchIDStatus.resolve（Support/TouchIDStatus.swift）是纯函数：
# 无 IO / 无 FFI / 无 Keychain 依赖，任何环境（含 CI 沙盒）均可运行，
# 不设 SKIP 路径。
#
# 用法：./tools/run_touchid_status_tests.sh
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
  "${ROOT_DIR}/macos/Tests/TouchIDStatusTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/TouchIDStatus.swift" \
  -o "${OUT_DIR}/TouchIDStatusTests"

"${OUT_DIR}/TouchIDStatusTests"
