#!/usr/bin/env bash
# run_auto_prompt_biometric_tests.sh —— 启动自动 Touch ID 引导判定纯函数
# 单元测试（用户 2026-10-03 裁定 feat：单库 + Touch ID 可用 → 启动不经点击
# 直接弹指纹认证框）。
#
# 被测单元 AutoPromptBiometric.shouldAutoPromptBiometric
# （Support/AutoPromptBiometric.swift）是纯函数：无 IO / 无 FFI / 无 Keychain
# 依赖，任何环境（含 CI 沙盒）均可运行，不设 SKIP 路径。
#
# 用法：./tools/run_auto_prompt_biometric_tests.sh
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
  "${ROOT_DIR}/macos/Tests/AutoPromptBiometricTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/TouchIDStatus.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/AutoPromptBiometric.swift" \
  -o "${OUT_DIR}/AutoPromptBiometricTests"

"${OUT_DIR}/AutoPromptBiometricTests"
