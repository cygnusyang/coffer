#!/usr/bin/env bash
# run_official_license_adapter_tests.sh —— 官方许可适配纯映射单元测试（FR-15）。
#
# 前置：官方构建产物已就绪（Task 4b 验证路径）：
#   1. core/vendor/license 已 bootstrap（tools/bootstrap_official_license.sh）
#   2. CoreBindings 已按 `--features official-license` 生成
#      （tools/build_swift_bindings.sh 官方模式），即含 cf_assemble.swift
#      （LicenseService / FfiLicenseStatus / LicenseError 绑定）
#   3. core/target/release/libcf_ffi.a 已按官方 feature 链接
#
# 被测单元（OfficialLicenseService.swift 的纯映射）：不调 FFI、零 Keychain /
# 零指纹副作用，可安全在进程内运行。绑定枚举（LicenseError / FfiLicenseStatus）
# 是纯 Swift 枚举，构造即测——链接静态库仅为满足绑定文件的未引用符号。
#
# 用法：./tools/run_official_license_adapter_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINDINGS_DIR="${ROOT_DIR}/macos/Coffer/CoreBindings"
SUPPORT_DIR="${ROOT_DIR}/macos/Coffer/Support"
RELEASE_LIB="${ROOT_DIR}/core/target/release/libcf_ffi.a"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

command -v swiftc >/dev/null 2>&1 || die "未找到 swiftc，请安装完整版 Xcode。"
[[ -f "${BINDINGS_DIR}/cf_assemble.swift" ]] || die "缺少 cf_assemble.swift——需官方模式绑定（Task 4b）。请先 bootstrap + 官方模式跑 build_swift_bindings.sh。"
[[ -f "${RELEASE_LIB}" ]] || die "缺少 libcf_ffi.a——需官方 feature 的 release 静态库。"

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# -D OFFICIAL_LICENSE：编译官方适配（OfficialLicenseService.swift 整体 #if 门控）。
# -import-objc-header 单一组合头（UniffiBridging.h #include 两个 FFI 头）：
#   swiftc 只认最后一个 bridging header，两个头并列传会被覆盖（实测），故用一个
#   组合头；-I BINDINGS_DIR 供组合头里的 #include "cf_*FFI.h" 解析（clang 侧）。
swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  -D OFFICIAL_LICENSE \
  -import-objc-header "${SUPPORT_DIR}/UniffiBridging.h" \
  -I "${BINDINGS_DIR}" \
  "${ROOT_DIR}/macos/Tests/OfficialLicenseAdapterTests/main.swift" \
  "${SUPPORT_DIR}/LicenseServicing.swift" \
  "${SUPPORT_DIR}/LicenseError.swift" \
  "${SUPPORT_DIR}/OfficialLicenseService.swift" \
  "${BINDINGS_DIR}/cf_ffi.swift" \
  "${BINDINGS_DIR}/cf_assemble.swift" \
  -L "${ROOT_DIR}/core/target/release" \
  -lcf_ffi \
  -o "${OUT_DIR}/OfficialLicenseAdapterTests"

"${OUT_DIR}/OfficialLicenseAdapterTests"
