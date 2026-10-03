#!/usr/bin/env bash
# restore_license_vendor_stub.sh —— 把 core/vendor/license/ 恢复为公开仓提交的
# 占位 stub，并逐字节核验与 git HEAD 一致（私有内容保护纪律）。
#
# 背景（发版回归前阻断项，reviewer L3 实证）：
#   官方构建（bootstrap + --features official-license）会临时把私有仓真实源码
#   覆盖进 core/vendor/license/。若构建结束后不恢复，工作树会留下
#   ① tracked stub 文件被改成真源的 M 态、② 14+ 个未跟踪真源文件——
#   一次 `git add` 失误即把私有代码泄漏进公开仓提交。
#   `git restore` 只还原 tracked 文件、**不清未跟踪残留**；本脚本两步都做：
#     git restore --staged --worktree -- core/vendor/license  # 还原 tracked stub
#                                                            #（M 态→提交态，含已 add）
#     git clean -fd -- core/vendor/license                    # 删除未跟踪真源残留
#   之后用 `git diff --quiet HEAD` + `git status --porcelain` 逐字节核验。
#
# 用法：
#   ./tools/restore_license_vendor_stub.sh              # 恢复 + 核验（未净则非零退出）
#   ./tools/restore_license_vendor_stub.sh --check      # 只核验，不恢复（防回归检查）
#
# 官方构建脚本（build_swift_bindings.sh 官方模式）在 EXIT trap 中调用本脚本，
# 保证构建结束（无论成败）vendor 区 == git HEAD。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENDOR_DIR="${ROOT_DIR}/core/vendor/license"

CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=1
fi

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

[[ -d "${VENDOR_DIR}" ]] || die "vendor 目录不存在：${VENDOR_DIR}"
git -C "${ROOT_DIR}" rev-parse --verify --quiet HEAD >/dev/null \
  || die "无法读取 git HEAD（裸 clone 前无 HEAD？）"

if [[ "${CHECK_ONLY}" == "0" ]]; then
  # 还原 tracked stub（M 态 → 提交态，--staged 兜底已 `git add` 的真源），
  # 再清未跟踪真源残留
  git -C "${ROOT_DIR}" restore --staged --worktree -- core/vendor/license \
    || die "git restore 失败（tracked 文件无法还原）"
  git -C "${ROOT_DIR}" clean -fd -- core/vendor/license \
    || die "git clean 失败（未跟踪残留无法清除）"
fi

# ---- 逐字节核验：tracked 与 HEAD 一致 + 无任何未跟踪文件 ----
if ! git -C "${ROOT_DIR}" diff --quiet HEAD -- core/vendor/license; then
  die "core/vendor/license 与 git HEAD 不一致（tracked 有改动，疑似私有源码残留）：
  $(git -C "${ROOT_DIR}" status --short -- core/vendor/license)"
fi
UNTRACKED="$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=all -- core/vendor/license)"
if [[ -n "${UNTRACKED}" ]]; then
  die "core/vendor/license 存在未跟踪文件（私有源码残留）：
${UNTRACKED}"
fi

printf 'vendor/license/ 与 git HEAD 逐字节一致 ✓\n'
