#!/usr/bin/env bash
# run_dropzone_bookmark_tests.sh —— 放置区授权 bookmark 存取/失效/配对单测
# （docs/04-测试与验收/18-v2.11.0验收判据骨架.md §4：A-3/A-4/A-5 + E-3 三态数据面；
# 上游 docs/21a §3.2）。
#
# 被测单元 = DropzoneBookmarkStore（Foundation + 注入式 UserDefaults）。
# 使用真实临时目录（创建/删除/rmdir/chmod 场景），非沙盒 harness 下 security-scoped
# bookmark 创建/解析与 startAccessing 均实证可用（2026-10-16）。无 FFI / 无 App 依赖。
#
# 用法：./tools/run_dropzone_bookmark_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Coffer/Dropzone/DropzoneBookmarkStore.swift" \
  "${ROOT_DIR}/macos/Tests/DropzoneBookmarkTests/main.swift" \
  -o "${OUT_DIR}/DropzoneBookmarkTests"

"${OUT_DIR}/DropzoneBookmarkTests"
