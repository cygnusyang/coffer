#!/usr/bin/env bash
# run_menu_icon_geometry_tests.sh —— 菜单栏图标几何断言单元测试（v2.10.0 D2，
# docs/18 §8.5 LOW-2 实现回归点）。
#
# 被测单元 MenuIconGeometry（macos/Coffer/Support/MenuIconGeometry.swift）是
# 纯几何命名空间：Foundation + CoreGraphics，无 AppKit / SwiftUI / FFI 依赖，
# 任何环境（含 CI 沙盒）均可运行，不设 SKIP 路径（对齐 run_recovery_verify_tests.sh）。
#
# 覆盖 docs/18 §4 参数表终值（绝对值）+ §5.1 纵向结构守恒 + §8.5 LOW-2
# 两几何断言（抬离 ≥0.18×glyph / 路径梁/体 ≤0.7），AC 映射见
# macos/Tests/MenuIconGeometryTests/main.swift 顶部。
#
# 用法：./tools/run_menu_icon_geometry_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# 只编译被测单元 + 测试入口（Foundation + CoreGraphics，无 AppKit/FFI 依赖）
swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Coffer/Support/MenuIconGeometry.swift" \
  "${ROOT_DIR}/macos/Tests/MenuIconGeometryTests/main.swift" \
  -o "${OUT_DIR}/MenuIconGeometryTests"

"${OUT_DIR}/MenuIconGeometryTests"
