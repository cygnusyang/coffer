#!/usr/bin/env bash
# run_dropzone_import_model_tests.sh —— L1 DropzoneImportModel RED→GREEN harness
# （docs/04-测试与验收/19-UI测试自动化分层设计.md §3.3 FFI-linked 形态 +
# docs/18 IT-12/14/15/16/18/19/20/21/22/28 模型面映射）。
#
# 被测单元：`DropzoneImportModel`（w1a 抽取，macos/Coffer/Dropzone/DropzoneImportModel.swift）
# + 依赖 `DropzoneImportContext.swift`/`DirectoryWatching.swift`。
# 形态：swiftc + cf_ffi.swift + `libcf_ffi.a`（release）+ 临时建库 + 合成 CSV +
# 内存 context stub + FakeWatcher + 注入式真实 store（docs/19 §3.3 方案 A）。
#
# RED 基线（先红后绿，docs/18 §3 core 同款）：模型三文件未落地 → swiftc 编译红
# （file not found / cannot find type）为**合法 RED 基线**；w1a 落地后转绿。
#
# 纪律：
#   - 临时建库工作目录 mktemp + 进程内前缀拦截（绝不触碰
#     ~/Library/Containers/top.cygnusyang.coffer/ 真实库）；
#   - 只读生产代码；测试文件改动单独 commit（逐文件 add，无 Co-Authored-By）。
#
# 用法：./tools/run_dropzone_import_model_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

LIB_DIR="${ROOT_DIR}/core/target/release"
[[ -f "${LIB_DIR}/libcf_ffi.a" ]] || { echo "ERROR: 缺 ${LIB_DIR}/libcf_ffi.a，先跑 tools/build_swift_bindings.sh。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/coffer-dzmodel.XXXXXX")"
trap 'rm -rf "${OUT_DIR}" "${WORK_DIR}"' EXIT

# w1a 模型三文件（RED 基线：未落地则 swiftc 在此处编译红）
MODEL_SRC="${ROOT_DIR}/macos/Coffer/Dropzone/DropzoneImportModel.swift"
CTX_SRC="${ROOT_DIR}/macos/Coffer/Dropzone/DropzoneImportContext.swift"
WATCH_SRC="${ROOT_DIR}/macos/Coffer/Dropzone/DirectoryWatching.swift"
# AppPhase（w1a/lead 已按 tester 报告迁出 AppModel.swift 至独立轻量文件，纯 Foundation）；
# DropzoneImportContext 协议引用之，harness 编译须含本文件。
APP_PHASE_SRC="${ROOT_DIR}/macos/Coffer/AppPhase.swift"

# model 依赖的 ErrorPresenter 链（真实实现，非 shim）：ErrorPresenter + 其四
# 依赖均为 Foundation/Security/LocalAuthentication-only，可 standalone 编译。
ERROR_PRESENTER_SRC="${ROOT_DIR}/macos/Coffer/Support/ErrorPresenter.swift"
ERROR_DEPS=(
  "${ROOT_DIR}/macos/Coffer/Support/TouchIDError.swift"
  "${ROOT_DIR}/macos/Coffer/Support/UpdatePassword.swift"
  "${ROOT_DIR}/macos/Coffer/Support/LicenseError.swift"
  "${ROOT_DIR}/macos/Coffer/Platform/BiometricKeychain.swift"
  "${ROOT_DIR}/macos/Coffer/Support/DiagLog.swift"
  "${ROOT_DIR}/macos/Coffer/Support/TouchIDAuthFailure.swift"
)

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  -import-objc-header "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffiFFI.h" \
  "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffi.swift" \
  "${MODEL_SRC}" "${CTX_SRC}" "${WATCH_SRC}" "${APP_PHASE_SRC}" \
  "${ROOT_DIR}/macos/Coffer/Dropzone/DropzoneFingerprintStore.swift" \
  "${ROOT_DIR}/macos/Coffer/Dropzone/DropzoneBookmarkStore.swift" \
  "${ROOT_DIR}/macos/Coffer/Dropzone/DropzoneDirectoryWatcher.swift" \
  "${ERROR_PRESENTER_SRC}" "${ERROR_DEPS[@]}" \
  "${ROOT_DIR}/macos/Tests/DropzoneImportModelTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/DropzoneImportModelTests"

"${OUT_DIR}/DropzoneImportModelTests" "${WORK_DIR}"
