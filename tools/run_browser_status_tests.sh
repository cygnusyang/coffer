#!/usr/bin/env bash
# run_browser_status_tests.sh —— 浏览器集成 App 侧纯逻辑单元测试
# （docs/31 §6.2 / §9.1 G-D）。
#
# 被测单元 BrowserStatus.resolve / BrowserManifest（json/write/delete）/
# BrowserBroker（spawn/kill）均为纯逻辑 + 显式本地 I/O（临时根目录注入 /
# /bin/sleep 假进程）：无 AppKit / 无 CoreBindings / 无网络，任何环境可运行。
#
# 说明：broker 生命周期测试用 /bin/sleep 假进程验证 spawn/kill 机制本身；
# 真 `coffer browser-broker` 子命令需 G-A/G-B 二进制 → 合并期验收项
# （见 G-D 任务记录）。
#
# 用法：./tools/run_browser_status_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# 只编译被测单元 + 测试入口（不依赖 CoreBindings / Rust 静态库 / AppKit）
swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Tests/BrowserStatusTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/BrowserStatus.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/BrowserStatusProbe.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/McpStatusProbe.swift" \
  "${ROOT_DIR}/macos/Coffer/Platform/BrowserIntegration.swift" \
  -o "${OUT_DIR}/BrowserStatusTests"

"${OUT_DIR}/BrowserStatusTests"
