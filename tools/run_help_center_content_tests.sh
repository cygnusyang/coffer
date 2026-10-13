#!/usr/bin/env bash
# run_help_center_content_tests.sh —— 帮助中心正文完整性断言单元测试（v2.10.1，
# docs/19 §5 转写回归点）。
#
# 被测单元 HelpCenterContent（macos/Coffer/Views/HelpCenterContent.swift）是纯
# 数据命名空间：struct HelpSection + enum HelpCenterContent，仅依赖 Foundation，
# 无 AppKit / SwiftUI / FFI，任何环境（含 CI 沙盒）均可运行，不设 SKIP 路径
# （对齐 run_menu_icon_geometry_tests.sh）。
#
# 覆盖 docs/19 §5 结构：11 个 Section 的标题顺序 + 条目数（§5.4 键盘快捷键 3 组），
# AC 映射见 macos/Tests/HelpCenterContentTests/main.swift 顶部。
#
# 用法：./tools/run_help_center_content_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# 只编译被测单元 + 测试入口（纯 Foundation，无 AppKit/FFI 依赖）
swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Coffer/Views/HelpCenterContent.swift" \
  "${ROOT_DIR}/macos/Tests/HelpCenterContentTests/main.swift" \
  -o "${OUT_DIR}/HelpCenterContentTests"

"${OUT_DIR}/HelpCenterContentTests"
