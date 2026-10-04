#!/usr/bin/env bash
# run_generator_defaults_tests.sh —— 生成器默认参数 + 诊断 FFI 的 Swift 侧自动化验收
# （docs/22 §2.4；docs/23 §1.4 TC-GEN / §1.5 TC-DIAG Swift 侧部分）。
#
# 编译 CoreBindings（cf_ffi.swift）+ Support/GeneratorDefaults.swift + 测试主体，
# 链接 release libcf_ffi.a（与 App 同一来源的绑定与静态库）。测试自恢复环境：
# UserDefaults 原值保存并恢复；临时库产物 mktemp 目录进程内删除。
#
# 用法：./tools/run_generator_defaults_tests.sh
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
  "${ROOT_DIR}/macos/Coffer/Support/GeneratorDefaults.swift" \
  "${ROOT_DIR}/macos/Tests/GeneratorDefaultsTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/GeneratorDefaultsTests"

"${OUT_DIR}/GeneratorDefaultsTests"
