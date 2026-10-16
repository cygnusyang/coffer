#!/usr/bin/env bash
# run_menu_status_text_tests.sh —— 菜单栏文案纯函数单元测试（v2.11.0，2026-10-16
# 用户裁定回归哨兵：菜单栏取消永久 disabled 状态行，状态文案并入打开项标题）。
#
# 被选编单元：MenuStatusText（macos/Coffer/Support/MenuStatusText.swift，纯
# Foundation）+ AppPhase（macos/Coffer/AppPhase.swift，纯 Foundation，W1a 独立
# 文件）——零 AppKit/SwiftUI/FFI 依赖，任何环境（含 CI 沙盒）均可运行，不设
# SKIP 路径（run_menu_icon_geometry_tests.sh 同模式）。
#
# 覆盖 §1 openTitle 七断言（状态并入打开项，五相兜底）+ §2 statusLine 五相
# 文案回归（抽出零语义变化）。AC 映射见 macos/Tests/MenuStatusTextTests/main.swift
# 顶部。
#
# 用法：./tools/run_menu_status_text_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Coffer/AppPhase.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/MenuStatusText.swift" \
  "${ROOT_DIR}/macos/Tests/MenuStatusTextTests/main.swift" \
  -o "${OUT_DIR}/MenuStatusTextTests"

"${OUT_DIR}/MenuStatusTextTests"
