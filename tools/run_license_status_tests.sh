#!/usr/bin/env bash
# run_license_status_tests.sh —— 许可域纯逻辑单元测试（FR-15，docs/03 §12/§14）。
#
# 被测单元（Support/LicenseServicing.swift + Support/LicenseError.swift）均为
# 纯逻辑：零 IO / 零 FFI / 零 CoreBindings 依赖（同
# run_touchid_error_presentation_tests.sh 纪律），任何环境（含 CI 沙盒）均可
# 运行，不设 SKIP 路径。
#
# 用法：./tools/run_license_status_tests.sh
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
  "${ROOT_DIR}/macos/Tests/LicenseStatusTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/LicenseServicing.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/LicenseError.swift" \
  -o "${OUT_DIR}/LicenseStatusTests"

"${OUT_DIR}/LicenseStatusTests"
