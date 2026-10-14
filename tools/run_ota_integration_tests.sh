#!/usr/bin/env bash
# run_ota_integration_tests.sh —— OTA 链路可自动化部分集成测试（任务 #70 第一层）。
#
# 锁定的契约（docs/35 §6.4 r0.4）在**真实签名产物**上验：helper 子进程
# 「等待→备份→替换→relaunch gate→result 握手」全流程。与 run_install_helper_tests.sh
# （T1-T19，helper 单元面，mini 假包）互补：本测试用 macos/build/Coffer.app（真实
# bundle 结构 + embedded.provisionprofile）做载荷，把 helper 契约绑定到真实产物上。
#
# 编译两块：
#   1. helper 测试构建（macos/Coffer/Installer/*.swift，**不加** -D
#      COFFER_UPDATER_PRODUCTION → 锚读 env COFFER_UPDATER_TEST_ANCHOR，可注入目标
#      路径；relaunch 用 COFFER_UPDATER_TEST_FAKE_RELAUNCH 桩隔离 open）
#   2. 测试 harness（macos/Tests/OTAIntegrationTests/main.swift，纯 Foundation，
#      经子进程 ditto/PlistBuddy/codesign/security 构造现场，直接 exec helper）
#
# 硬边界：全链路「真机 /Applications 替换 + relaunch」不进自动化（R2 约束，依赖
# 用户解锁）——relaunch 用 fake 桩断言 gate 通过；open(1) 真实 relaunch 归 BUG-29
# 真机核销判据（docs/01）。本脚本不打真服务器（无网络），不改 OTAEndpointPolicy。
#
# 前置（缺失即测试自身显式 SKIP，不算 fail）：签名产物存在 + Apple Development
# 签名身份存在。
#
# 兼容 bash 3.2（macOS 自带 /bin/bash）。
#
# 用法：./tools/run_ota_integration_tests.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# 允许外部注入 helper 源码目录（与 run_install_helper_tests.sh 同款接缝）。
HELPER_SRC_DIR="${COFFER_HELPER_SRC_DIR:-${ROOT_DIR}/macos/Coffer/Installer}"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

ARCH="$(uname -m)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/coffer-ota-int.XXXXXX")"
HELPER_BIN="${TMP_ROOT}/coffer-update"
HARNESS_BIN="${TMP_ROOT}/OTAIntegrationTests"

cleanup() { rm -rf "${TMP_ROOT}"; }
trap cleanup EXIT

# ---- 编译 helper 测试构建（不加 -D COFFER_UPDATER_PRODUCTION）----
# -framework Security 供 SecStaticCodeCheckValidity（C-1 静态验签，真实产物重签载荷必需）。
compile_helper() {
  local sources=()
  while IFS= read -r f; do
    sources+=("${f}")
  done < <(find "${HELPER_SRC_DIR}" -name '*.swift' | sort)
  if [[ ${#sources[@]} -eq 0 ]]; then
    echo "ERROR: ${HELPER_SRC_DIR} 无 Swift 源文件。" >&2
    exit 1
  fi
  swiftc -O -swift-version 5 -target "${ARCH}-apple-macos14.0" \
    -framework Security \
    "${sources[@]}" -o "${HELPER_BIN}" \
    || { echo "ERROR: helper 测试构建编译失败。" >&2; exit 1; }
}

# ---- 编译 harness（纯 Foundation，子进程构造现场 + 直接 exec helper）----
compile_harness() {
  swiftc -O -swift-version 5 -target "${ARCH}-apple-macos14.0" \
    "${ROOT_DIR}/macos/Tests/OTAIntegrationTests/main.swift" \
    -o "${HARNESS_BIN}" \
    || { echo "ERROR: OTAIntegrationTests harness 编译失败。" >&2; exit 1; }
}

compile_helper
compile_harness
echo "编译完成: helper=${HELPER_BIN} harness=${HARNESS_BIN}"

# 真实签名产物路径 + helper 二进制经 env 传 harness（产物/身份缺失 → harness 显式 SKIP）。
COFFER_UPDATE_ARTIFACT_PATH="${ROOT_DIR}/macos/build/Coffer.app" \
  COFFER_OTA_HELPER_BIN="${HELPER_BIN}" \
  "${HARNESS_BIN}"
