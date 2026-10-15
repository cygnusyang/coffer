#!/usr/bin/env bash
# run_dropzone_fingerprint_tests.sh —— 放置区「已导入过/已忽略」元数据指纹单测
# （docs/04-测试与验收/18-v2.11.0验收判据骨架.md §4：W-3/W-6/S-4；上游 docs/21a §2.3）。
#
# 被测单元 = DropzoneFingerprintStore（纯 Foundation，注入式 UserDefaults），
# 无 FFI / 无 App 依赖，任何环境可运行。swiftc 编译服务文件 + 测试主体。
#
# 用法：./tools/run_dropzone_fingerprint_tests.sh
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
  "${ROOT_DIR}/macos/Coffer/Dropzone/DropzoneFingerprintStore.swift" \
  "${ROOT_DIR}/macos/Tests/DropzoneFingerprintTests/main.swift" \
  -o "${OUT_DIR}/DropzoneFingerprintTests"

"${OUT_DIR}/DropzoneFingerprintTests"
