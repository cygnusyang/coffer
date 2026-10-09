#!/usr/bin/env bash
# run_update_password_tests.sh —— 条目「更新密码」快捷动作（FR-18.1，v2.5.0）
# 的 Swift 侧自动化验收。
#
# 编译 CoreBindings（cf_ffi.swift）+ Support/UpdatePassword.swift + 测试主体，
# 链接 release libcf_ffi.a（与 App 同一来源的绑定与静态库）。测试自恢复环境：
# 临时库产物 mktemp 目录进程内删除，无外部状态。
#
# 用法：./tools/run_update_password_tests.sh
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
  "${ROOT_DIR}/macos/Coffer/Support/UpdatePassword.swift" \
  "${ROOT_DIR}/macos/Tests/UpdatePasswordTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/UpdatePasswordTests"

"${OUT_DIR}/UpdatePasswordTests"
