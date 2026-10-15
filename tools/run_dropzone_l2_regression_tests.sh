#!/usr/bin/env bash
# run_dropzone_l2_regression_tests.sh —— L2 真样全链路回归 harness
# （docs/19 §4.4，macos/Tests/DropzoneRealSampleRegressionTests/main.swift）。
#
# 定位：对合成 fixture（真实列头 + 假密码，tests/fixtures/csv/
# dropzone_passwords_headers.csv）跑全链路断言——列映射无未映射列 / 空库全 new /
# 导入 importedRows + listItems 落库标题逐字 / 重导全 duplicate / 文件漂移
# fail-closed 零落库。走真实 core 逻辑（FFI precheckDropzone/importDropzone/
# listItems），临时建库（PuxRealSampleTests 骨架）。
#
# J-5 联动（docs/19 §4.3）：真样采样**只做一次**（人工）——
#   ./tools/run_dropzone_j5_sample.sh   # 在 .local-samples/ 记非敏感四核对项（git 忽略）
#   人工核对四项（列头/菜单名/默认文件名 Passwords.csv/重复导出命名）→ 核销
#   P-2 provisional / J-5 发版门禁；本 harness 对合成样本**永久自动回归**。
#   J-5 核销前 fixture 列头保持 provisional（docs/19 §4.3 不可逆标注）。
#
# 纪律：
#   - 合成 fixture 假密码（R2 安全）；FfiDropzonePrecheck/Row 类型层无密码字段；
#   - 测试建库工作目录 mktemp + 进程内前缀拦截（绝不触碰
#     ~/Library/Containers/top.cygnusyang.coffer/ 真实库），trap 二次保险；
#   - 测试文件改动单独 commit（逐文件 add，无 Co-Authored-By，不 push）。
#
# 用法：./tools/run_dropzone_l2_regression_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

FIXTURE_PATH="${ROOT_DIR}/tests/fixtures/csv/dropzone_passwords_headers.csv"
if [[ ! -f "${FIXTURE_PATH}" ]]; then
  echo "ERROR: 合成 fixture 不存在：${FIXTURE_PATH}" >&2
  exit 2
fi
[[ -s "${FIXTURE_PATH}" ]] || { echo "ERROR: fixture 为空：${FIXTURE_PATH}" >&2; exit 2; }

LIB_DIR="${ROOT_DIR}/core/target/release"
[[ -f "${LIB_DIR}/libcf_ffi.a" ]] || { echo "ERROR: 缺 ${LIB_DIR}/libcf_ffi.a，先跑 tools/build_swift_bindings.sh。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/coffer-l2-dropzone.XXXXXX")"
trap 'rm -rf "${OUT_DIR}" "${WORK_DIR}"' EXIT

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  -import-objc-header "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffiFFI.h" \
  "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffi.swift" \
  "${ROOT_DIR}/macos/Tests/DropzoneRealSampleRegressionTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/DropzoneRealSampleRegressionTests"

"${OUT_DIR}/DropzoneRealSampleRegressionTests" "${FIXTURE_PATH}" "${WORK_DIR}"
