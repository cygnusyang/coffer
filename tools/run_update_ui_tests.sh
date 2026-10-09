#!/usr/bin/env bash
# run_update_ui_tests.sh —— OTA 更新 UI 纯逻辑单元测试
# （v2.7.0，docs/35 §2.6 / §6.3）。
#
# 被测单元 Support/UpdateCopy.swift 是纯逻辑（版本比较 / 跳过版本语义 /
# state→按钮可用性 / 下载 URL 信任校验 / 进度文案），不依赖 SwiftUI / AppModel /
# Updater 实现。依赖类型 UpdaterState / UpdateInfo 用契约 6.3 同签名 stub
# （Tests/UpdateUITests/main.swift 内定义），swiftc 直编即可，任何环境（含 CI
# 沙盒）可运行，不设 SKIP 路径。
#
# 用法：./tools/run_update_ui_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# 只编译被测单元 + 测试入口（不依赖 CoreBindings / Rust 静态库 / Updater 实现）
swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Coffer/Support/UpdateCopy.swift" \
  "${ROOT_DIR}/macos/Tests/UpdateUITests/main.swift" \
  -o "${OUT_DIR}/UpdateUITests"

"${OUT_DIR}/UpdateUITests"
