#!/usr/bin/env bash
# run_recovery_verify_tests.sh —— 恢复码验证步纯函数单元测试（v2.9.0 基层测试化）。
#
# 被测单元 RecoveryVerifySupport（macos/Coffer/Support/RecoveryVerifySupport.swift）
# 是纯函数命名空间：无 IO / 无 FFI / 无 SwiftUI / 无 libcf_ffi.a 依赖，任何环境
# （含 CI 沙盒）均可运行，不设 SKIP 路径。
#
# 与 run_touchid_status_tests.sh / run_update_tests.sh 的差异：本脚本只编译
# RecoveryVerifySupport.swift + main.swift 两个文件（比 UpdateTests 更轻——不链
# Security/CryptoKit/Combine framework，无网络/产物依赖），覆盖 AC-2.9.0-P6-3/4/5
# 与 recoveryWordCount 的纯函数面（AC 映射见 main.swift 顶部）。
#
# 用法：./tools/run_recovery_verify_tests.sh
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
  "${ROOT_DIR}/macos/Coffer/Support/RecoveryVerifySupport.swift" \
  "${ROOT_DIR}/macos/Tests/RecoveryVerifyTests/main.swift" \
  -o "${OUT_DIR}/RecoveryVerifyTests"

"${OUT_DIR}/RecoveryVerifyTests"
