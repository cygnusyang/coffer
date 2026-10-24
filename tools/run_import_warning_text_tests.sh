#!/usr/bin/env bash
# run_import_warning_text_tests.sh —— 导入告警「码 + 参数」→ 文案单元测试（BUG-35 第一阶段）。
#
# 被测单元 Support/ImportWarningText.swift 是纯逻辑：零 IO / 零 FFI / 零 CoreBindings 依赖
# （同 run_core_error_text_tests.sh 纪律），任何环境（含 CI 沙盒）均可运行，不设 SKIP 路径。
#
# 与多语言门禁的分工：tools/check_l10n.sh 校验「文案资源」的格式与占位符（G1–G5），
# 本脚本校验「码 + 参数 → 整句」的解码与渲染（转义往返 / 未知码原样返回 / 逐字文案），
# 二者互补：门禁管英文，本脚本管中文口径与解码正确性。
#
# 用法：./tools/run_import_warning_text_tests.sh
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
  "${ROOT_DIR}/macos/Tests/ImportWarningTextTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/ImportWarningText.swift" \
  -o "${OUT_DIR}/ImportWarningTextTests"

"${OUT_DIR}/ImportWarningTextTests"
