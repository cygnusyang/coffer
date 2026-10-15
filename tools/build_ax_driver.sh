#!/usr/bin/env bash
# build_ax_driver.sh —— 编译 L3 AX 黑盒驱动器（docs/19 §5.1/§5.4）。
#
# 形态：swiftc 直接编译（无 xcodeproj，与 build_macos_app.sh 同管线决策）。
# 输出**固定路径** macos/build/axdriver/UIAXDriver —— TCC 按「路径」记录授权
# （swiftc 无签名二进制），输出必须固定，不能 mktemp，否则路径变化 → 授权失效重弹
# （docs/19 §5.4；该固定路径是 §9 不可逆决策 3 的授权锚点）。
#
# 用法：
#   ./tools/build_ax_driver.sh          # 产物 → macos/build/axdriver/UIAXDriver
#
# 能力面 / 子命令契约见 macos/Tests/UIAXTests/main.swift 头注。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC="${ROOT_DIR}/macos/Tests/UIAXTests/main.swift"
OUT_DIR="${ROOT_DIR}/macos/build/axdriver"
OUT="${OUT_DIR}/UIAXDriver"

[[ -f "${SRC}" ]] || { echo "ERROR: 缺少驱动器源码: ${SRC}" >&2; exit 1; }

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装 Xcode CLT 并 xcode-select --install。" >&2; exit 1; }

mkdir -p "${OUT_DIR}"

# AX 依赖：ApplicationServices（AXUIElement 系列）+ AppKit（NSRunningApplication /
# NSWorkspace）。Foundation 隐式链入。
swiftc \
    -O \
    "${SRC}" \
    -framework ApplicationServices \
    -framework AppKit \
    -o "${OUT}"

echo "OK: ${OUT}"
