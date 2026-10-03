#!/usr/bin/env bash
# build_swift_bindings.sh —— 生成 macOS Swift 绑定（UniFFI，幂等可重复执行）。
#
# 做三件事：
#   1. cargo build -p cf-ffi --release
#      （产出 staticlib  libcf_ffi.a  → Xcode 静态链接；
#        产出 cdylib    libcf_ffi.dylib → uniffi-bindgen 提取绑定元数据）
#   2. 用 crate 内置 uniffi-bindgen（--features bindgen-cli，版本与 runtime 锁死，
#      docs/07 R-1）从 cdylib 提取生成 Swift 绑定，输出到 macos/Coffer/CoreBindings/
#   3. 校验生成物齐全并打印 Xcode 侧接入摘要
#
# 官方模式（OFFICIAL_LICENSE=1，Task 2/3/4b）：
#   启用 feature `official-license` 构建并生成两个 namespace 的绑定：
#   cf_ffi.swift（CofferApp + installOfficialLicense）+ cf_assemble.swift
#   （LicenseService / FfiLicenseStatus / LicenseError）。前置要求
#   core/vendor/license 已 bootstrap（tools/bootstrap_official_license.sh）——
#   未 bootstrap 直接报错，防止用占位 stub 生成残缺绑定。
#
# 用法：
#   ./tools/build_swift_bindings.sh            # 公开模式（默认，TC-BLD-02）
#   OFFICIAL_LICENSE=1 ./tools/build_swift_bindings.sh   # 官方模式
# 依赖：cargo（rustup）、Xcode CLT（swiftc / swift-driver，仅第 3 步的下游编译需要）
#
# 生成后可用冒烟测试验证 Swift 链路（macos/Coffer/SmokeTest/main.swift）：
#   swiftc -O \
#     macos/Coffer/SmokeTest/main.swift \
#     macos/Coffer/CoreBindings/cf_ffi.swift \
#     -import-objc-header macos/Coffer/CoreBindings/cf_ffiFFI.h \
#     -L core/target/release -lcf_ffi \
#     -o /tmp/coffer_smoke_test && /tmp/coffer_smoke_test
set -euo pipefail

# ---- 路径锚定：脚本位于仓库 tools/ 下，不依赖调用方 CWD ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# Cargo 工作区根在 core/（仓库根不含 Cargo.toml）
CORE_DIR="${ROOT_DIR}/core"
FFI_DIR="${CORE_DIR}/cf-ffi"
TARGET_DIR="${CORE_DIR}/target"
OUT_DIR="${ROOT_DIR}/macos/Coffer/CoreBindings"

CDYLIB="${TARGET_DIR}/release/libcf_ffi.dylib"
STATICLIB="${TARGET_DIR}/release/libcf_ffi.a"

step() { printf '\n==> %s\n' "$1"; }
die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

# ---- 模式开关：官方 / 公开（默认） ----
# OFFICIAL_LICENSE=1 → --features official-license 构建 + 双 namespace 绑定；
# 前置：tools/bootstrap_official_license.sh 已跑（stub 已被真源覆盖）。
OFFICIAL_LICENSE="${OFFICIAL_LICENSE:-0}"
if [[ "${OFFICIAL_LICENSE}" == "1" ]]; then
  # stub 未提交（首次任务提交时才会入库），bootstrap 状态只能按磁盘内容判定：
  # 占位 stub 的 src/lib.rs 含「占位替身」标记，真源覆盖后不含。
  if grep -rq "占位替身" "${CORE_DIR}/vendor/license/cf-assemble/src" 2>/dev/null; then
    die "core/vendor/license 仍是占位 stub——先跑 tools/bootstrap_official_license.sh 再进官方模式。"
  fi
  CARGO_FEATURES="--features official-license"
else
  CARGO_FEATURES=""
fi

# ---- 环境预检（失败时给可执行的修复指引） ----
# rustup 默认装在 ~/.cargo/bin，cron / CI 等非交互 shell 可能没有它，兜底加载
if ! command -v cargo >/dev/null 2>&1; then
  # shellcheck disable=SC1091
  [[ -f "${HOME}/.cargo/env" ]] && source "${HOME}/.cargo/env"
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi
command -v cargo >/dev/null 2>&1 \
  || die "未找到 cargo。请安装 rustup：https://rustup.rs 后重试。"

step "1/3 cargo build -p cf-ffi --release ${CARGO_FEATURES}"
(cd "${CORE_DIR}" && cargo build -p cf-ffi --release ${CARGO_FEATURES}) \
  || die "cargo build 失败——先在 ${CORE_DIR} 下跑 'cargo build -p cf-ffi --release ${CARGO_FEATURES}' 看完整错误。"

[[ -f "${CDYLIB}" ]]    || die "cdylib 未产出：${CDYLIB}（检查 cf-ffi/Cargo.toml 的 crate-type 是否含 cdylib）"
[[ -f "${STATICLIB}" ]] || die "staticlib 未产出：${STATICLIB}（检查 cf-ffi/Cargo.toml 的 crate-type 是否含 staticlib）"

step "2/3 uniffi-bindgen generate --library（内置 bin，--features bindgen-cli）"
mkdir -p "${OUT_DIR}"
# 幂等：清掉上一轮生成物再生成，避免 namespace 改名后残留旧文件
rm -f "${OUT_DIR}"/*.swift "${OUT_DIR}"/*.h

(cd "${CORE_DIR}" && cargo run -p cf-ffi --features bindgen-cli --bin uniffi-bindgen -- \
    generate --library "${CDYLIB}" --language swift --out-dir "${OUT_DIR}") \
  || die "uniffi-bindgen 生成失败——检查 cdylib 是否包含 scaffolding（setup_scaffolding!）。"

# ---- 生成物校验：<ns>.swift + <ns>FFI.h（ns 由 setup_scaffolding! 派生） ----
# 官方模式（--library 双 namespace）产物：cf_ffi.{swift,FFI.h,FFI.modulemap}
# + cf_assemble.{swift,FFI.h,FFI.modulemap}；公开模式仅 cf_ffi.*。
if [[ "${OFFICIAL_LICENSE}" == "1" ]]; then
  [[ -f "${OUT_DIR}/cf_ffi.swift" ]]        || die "官方模式缺 cf_ffi.swift，检查 ${OUT_DIR}"
  [[ -f "${OUT_DIR}/cf_ffiFFI.h" ]]         || die "官方模式缺 cf_ffiFFI.h，检查 ${OUT_DIR}"
  [[ -f "${OUT_DIR}/cf_assemble.swift" ]]   || die "官方模式缺 cf_assemble.swift（LicenseService 绑定），检查 ${OUT_DIR}"
  [[ -f "${OUT_DIR}/cf_assembleFFI.h" ]]    || die "官方模式缺 cf_assembleFFI.h，检查 ${OUT_DIR}"
  SWIFT_FILE="${OUT_DIR}/cf_ffi.swift + ${OUT_DIR}/cf_assemble.swift"
  HEADER_FILE="${OUT_DIR}/cf_ffiFFI.h + ${OUT_DIR}/cf_assembleFFI.h"
else
  [[ -f "${OUT_DIR}/cf_ffi.swift" ]] || die "公开模式缺 cf_ffi.swift，检查 ${OUT_DIR}"
  [[ -f "${OUT_DIR}/cf_ffiFFI.h" ]]  || die "公开模式缺 cf_ffiFFI.h，检查 ${OUT_DIR}"
  SWIFT_FILE="${OUT_DIR}/cf_ffi.swift"
  HEADER_FILE="${OUT_DIR}/cf_ffiFFI.h"
fi

step "3/3 完成 ✅"
echo "  模式        : $([[ "${OFFICIAL_LICENSE}" == "1" ]] && echo '官方（official-license）' || echo '公开（PermitAll，TC-BLD-02）')"
echo "  Swift 绑定 : ${SWIFT_FILE}"
echo "  C 头文件   : ${HEADER_FILE}"
echo "  静态库     : ${STATICLIB}"
echo
echo "Xcode 接入摘要："
echo "  1. 把 ${OUT_DIR} 拖进工程（Swift 绑定文件设为编译源、FFI 头文件建模块）"
echo "  2. 链接设置：OTHER_LDFLAGS += -lcf_ffi ；LIBRARY_SEARCH_PATHS += ${TARGET_DIR}/release"
echo "  3. 重新生成只需重跑本脚本，产物路径不变"
