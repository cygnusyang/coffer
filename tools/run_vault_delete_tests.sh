#!/usr/bin/env bash
# run_vault_delete_tests.sh —— 库删除向导/管理面纯函数策略的 Swift 侧自动化验收
# （v2.10.0 D1，AC-2.10.0-CF-2 / DL-5 / EN-7 自动段；docs/03-功能设计/17 §4 B3）。
#
# 编译 CoreBindings（cf_ffi.swift）+ Support/{LicenseServicing,DeleteVaultPolicy}.swift
# + 测试主体，链接 release libcf_ffi.a（与 App 同一来源的绑定与静态库）。被测
# 单元为纯函数（无 IO / 无 FFI / 无 Keychain 依赖），任何环境均可运行。
#
# 用法：./tools/run_vault_delete_tests.sh
# 前置：core/target/release/libcf_ffi.a 已构建（先跑 tools/build_swift_bindings.sh）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

LIB_DIR="${ROOT_DIR}/core/target/release"
[[ -f "${LIB_DIR}/libcf_ffi.a" ]] || { echo "ERROR: 缺 ${LIB_DIR}/libcf_ffi.a，先跑 tools/build_swift_bindings.sh。" >&2; exit 1; }

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  -import-objc-header "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffiFFI.h" \
  "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffi.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/LicenseServicing.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/LicenseError.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/DeleteVaultPolicy.swift" \
  "${ROOT_DIR}/macos/Tests/VaultDeleteTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/VaultDeleteTests"

"${OUT_DIR}/VaultDeleteTests"
