#!/usr/bin/env bash
# restore_corebindings_public.sh —— 把 macos/Coffer/CoreBindings/ 恢复为公开仓
# 提交的公开模式绑定，并逐字节核验与 git HEAD 一致（官方 FFI 表面保护纪律）。
#
# 背景（lead 裁定 2026-10-04，披露边界不由构建产物隐式决定）：
#   官方 app 构建（bootstrap + OFFICIAL_LICENSE=1 build_macos_app.sh）会重生成
#   CoreBindings：
#     ① cf_ffi.swift / cf_ffiFFI.h 被官方版覆盖（M 态，含 installOfficialLicense）
#     ② 新增未跟踪 cf_assemble.{swift,FFI.h,FFI.modulemap}——从私有 crate 生成的
#        官方许可 FFI 表面（LicenseService / FfiLicenseStatus / LicenseError）。
#   cf_assemble.* 随仓提交 = 把官方许可 API 源码面公开到公开仓，披露边界不应由
#   构建产物隐式决定。官方构建产物视为 build artifact 永不入库；公开仓 CoreBindings
#   只保持公开模式版本。`git restore` 只还原 tracked、**不清未跟踪残留**；本脚本
#   两步都做：
#     git restore --staged --worktree -- macos/Coffer/CoreBindings  # 还原 tracked
#     git clean -fd -- macos/Coffer/CoreBindings                    # 删除未跟踪官方绑定
#   之后用 `git diff --quiet HEAD` + `git status --porcelain` 逐字节核验。
#
# 用法：
#   ./tools/restore_corebindings_public.sh              # 恢复 + 核验（未净则非零退出）
#   ./tools/restore_corebindings_public.sh --check      # 只核验，不恢复（防回归检查）
#
# 官方构建脚本（build_macos_app.sh 官方模式）在 EXIT trap 中调用本脚本，
# 保证官方 app 构建结束（无论成败）CoreBindings == git HEAD（公开模式版本）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINDINGS_DIR="macos/Coffer/CoreBindings"
BINDINGS_PATH="${ROOT_DIR}/${BINDINGS_DIR}"

CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=1
fi

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

[[ -d "${BINDINGS_PATH}" ]] || die "CoreBindings 目录不存在：${BINDINGS_PATH}"
git -C "${ROOT_DIR}" rev-parse --verify --quiet HEAD >/dev/null \
  || die "无法读取 git HEAD（裸 clone 前无 HEAD？）"

if [[ "${CHECK_ONLY}" == "0" ]]; then
  # 还原 tracked 公开绑定（M 态 → 提交态，--staged 兜底已 `git add` 的官方绑定），
  # 再清未跟踪官方绑定残留
  git -C "${ROOT_DIR}" restore --staged --worktree -- "${BINDINGS_DIR}" \
    || die "git restore 失败（tracked 绑定无法还原）"
  git -C "${ROOT_DIR}" clean -fd -- "${BINDINGS_DIR}" \
    || die "git clean 失败（未跟踪官方绑定残留无法清除）"
fi

# ---- 逐字节核验：tracked 与 HEAD 一致 + 无任何未跟踪文件 ----
if ! git -C "${ROOT_DIR}" diff --quiet HEAD -- "${BINDINGS_DIR}"; then
  die "CoreBindings 与 git HEAD 不一致（tracked 有改动，疑似官方绑定残留）：
  $(git -C "${ROOT_DIR}" status --short -- "${BINDINGS_DIR}")"
fi
UNTRACKED="$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=all -- "${BINDINGS_DIR}")"
if [[ -n "${UNTRACKED}" ]]; then
  die "CoreBindings 存在未跟踪文件（官方绑定残留）：
${UNTRACKED}"
fi

printf 'CoreBindings/ 与 git HEAD 逐字节一致 ✓\n'
