#!/usr/bin/env bash
# run_1pux_real_sample_acceptance.sh —— 685 条真实 1PUX 样本判据补验（v0.3.0 出口判据①）。
#
# 判据来源：docs/06 r2.1 M0-③（685 条：001=login×683、004×1、112×1，
# 无附件；004/112 歧义按 E-4 保守降级进 Notes）。
#
# 纪律：
#   - 真实样本不入库（.local-samples/ 被 git 忽略，仅本机在位）；
#   - 测试建库工作目录为 mktemp 临时目录，进程内 defer 删除 +
#     本脚本 trap 二次保险，绝不触碰 ~/Library/Containers/app.coffer.Coffer/
#     （测试进程内有前缀断言，命中即拒绝执行）；
#   - 样本缺失/为空 → 明确报错退出并提示来源。
#
# 用法：./tools/run_1pux_real_sample_acceptance.sh [--probe]
#   --probe 透传给测试进程：只跑预检并打印全部实际值，不断言
#   （用于冻结断言口径前的实测核对）。
# 环境变量：COFFER_1PUX_SAMPLE 覆盖样本路径（默认仓库 .local-samples/real-export-20260602.1pux）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

SAMPLE_PATH="${COFFER_1PUX_SAMPLE:-${ROOT_DIR}/.local-samples/real-export-20260602.1pux}"
if [[ ! -f "${SAMPLE_PATH}" ]]; then
  echo "ERROR: 真实 1PUX 样本不存在：${SAMPLE_PATH}" >&2
  echo "       样本不入库（git 忽略），默认应在本机 .local-samples/real-export-20260602.1pux，" >&2
  echo "       或用环境变量 COFFER_1PUX_SAMPLE 指定其他路径。" >&2
  exit 2
fi
[[ -s "${SAMPLE_PATH}" ]] || { echo "ERROR: 样本为空：${SAMPLE_PATH}" >&2; exit 2; }

LIB_DIR="${ROOT_DIR}/core/target/release"
[[ -f "${LIB_DIR}/libcf_ffi.a" ]] || { echo "ERROR: 缺 ${LIB_DIR}/libcf_ffi.a，先跑 tools/build_swift_bindings.sh。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/coffer-1pux-accept.XXXXXX")"
trap 'rm -rf "${OUT_DIR}" "${WORK_DIR}"' EXIT

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  -import-objc-header "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffiFFI.h" \
  "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffi.swift" \
  "${ROOT_DIR}/macos/Tests/PuxRealSampleTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/PuxRealSampleTests"

# 透传 --probe（若提供）；工作目录（临时建库处）作为第二个参数传入。
EXTRA_ARGS=()
if [[ "${1:-}" == "--probe" ]]; then
  EXTRA_ARGS+=(--probe)
fi

"${OUT_DIR}/PuxRealSampleTests" "${SAMPLE_PATH}" "${WORK_DIR}" ${EXTRA_ARGS+"${EXTRA_ARGS[@]}"}
