#!/usr/bin/env bash
# run_core_error_text_tests.sh —— 核心错误码文案映射单元测试（v2.13.0，设计 24 §7.4 / D-10）。
#
# 被测单元 Support/CoreErrorText.swift 是纯逻辑：零 IO / 零 FFI / 零 CoreBindings 依赖
# （同 run_license_status_tests.sh 纪律），任何环境（含 CI 沙盒）均可运行，不设 SKIP 路径。
#
# 与多语言门禁的分工：tools/check_l10n.sh 校验「文案资源」的格式与占位符（G1–G5），
# 本脚本校验「码 → 文案」这张表的完整性（漏码 / 越界映射 / 单一来源），二者互补。
#
# 用法：./tools/run_core_error_text_tests.sh
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
  "${ROOT_DIR}/macos/Tests/CoreErrorTextTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/CoreErrorText.swift" \
  -o "${OUT_DIR}/CoreErrorTextTests"

"${OUT_DIR}/CoreErrorTextTests"
