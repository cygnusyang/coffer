#!/usr/bin/env bash
# bootstrap_official_license.sh —— 官方构建前把私有仓许可 crate 覆盖到 vendor 目录。
#
# 背景（Cargo 急切路径校验，TC-BLD-02）：
#   公开仓随仓库提交 `core/vendor/license/{cf-assemble,cf-license,cf-keychain}`
#   的**占位 stub**（空 lib）——保证裸 clone 离线可解析路径依赖（Cargo 对 path
#   依赖的 manifest 是急切校验的，路径不存在即构建失败）。官方构建（feature
#   `official-license`）前必须运行本脚本，把私有仓（coffer-license）的真实源码
#   复制覆盖 stub。
#
# 复制内容：每个 crate 的 Cargo.toml + src/（不含 .git / 测试夹具等无关文件）。
# 复制后的真实 crate 以 `*.workspace = true` 继承**公开仓**工作区依赖
# （cf-domain / uniffi / ed25519-dalek 等），与公开仓既有 crates 同包统一——
# 无重复 cf-domain 冲突（私有仓内已验证该继承机制，见其 vendored cf-domain 先例）。
#
# 幂等：可重复执行；重复执行即重新覆盖为最新私有仓源码。
#
# ⚠️ 安全边界：本脚本只覆盖工作树文件。**严禁把 vendor/license/ 下被覆盖后的
# 真实源码提交进公开仓**。私有仓代码（cf-license 判定器 / cf-keychain 真实
# Keychain / cf-assemble 装配壳）只以 path 引用方式参与构建，永不进入公开仓提交。
# 恢复 stub 统一走 tools/restore_license_vendor_stub.sh（git restore + git clean
# 两步，逐字节核验与 HEAD 一致）——`git restore` 只还原 tracked、**不清未跟踪
# 真源残留**，必须补 `git clean -fd core/vendor/license`。
#
# 用法：
#   ./tools/bootstrap_official_license.sh                 # 只覆盖真源；构建后自行
#                                                         #   跑 restore_license_vendor_stub.sh
#   ./tools/bootstrap_official_license.sh -- <构建命令>   # 生命周期模式：覆盖 → 执行构建 →
#                                                         #   EXIT trap 无论成败恢复 stub
#   PRIVATE_REPO=/path/to/coffer-license ./tools/bootstrap_official_license.sh
#
# 生命周期模式示例（官方冒烟，构建结束自动恢复）：
#   ./tools/bootstrap_official_license.sh -- \
#     bash tools/build_swift_bindings.sh
# 说明：build_swift_bindings.sh 官方模式自身也装了同样的 EXIT trap（公共咽喉），
# 本脚本的生命周期模式让「复制→构建→恢复」成为单条命令，双保险。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENDOR_DIR="${ROOT_DIR}/core/vendor/license"

# 私有仓（coffer-license）定位：PRIVATE_REPO 环境变量优先；否则在候选路径里
# 取第一个存在的——本仓库同目录的兄弟仓（主仓 checkout 形态）、git 主工作树
# 同目录的兄弟仓（worktree 形态，如 /tmp/coffer-v060-dev 的 git 主仓在
# ~/work/github/coffer）、以及 ~/work/github 下的常规布局。
PRIVATE_REPO="${PRIVATE_REPO:-}"
if [[ -z "${PRIVATE_REPO}" ]]; then
  MAIN_REPO="$(git -C "${ROOT_DIR}" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2; exit}')"
  for candidate in \
    "${ROOT_DIR}/../coffer-license" \
    "$(dirname "${MAIN_REPO}")/coffer-license" \
    "${HOME}/work/github/coffer-license"; do
    if [[ -n "${candidate}" && -d "${candidate}/crates/cf-assemble" ]]; then
      PRIVATE_REPO="${candidate}"
      break
    fi
  done
fi

step() { printf '\n==> %s\n' "$1"; }
die()  { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

# ---- 生命周期模式：`-- <构建命令>` 解析 ----
# `--` 之后的参数作为单条构建命令执行；执行结束（无论成败）EXIT trap 恢复
# vendor/license/ 为占位 stub 并逐字节核验（reviewer L3 阻断项修复）。
# _rc 保留构建原始退出码：restore 失败强制 1，restore 成功不得掩盖构建失败。
BUILD_CMD=()
if [[ "${1:-}" == "--" ]]; then
  shift
  BUILD_CMD=("$@")
  if [[ ${#BUILD_CMD[@]} -eq 0 ]]; then
    die "-- 之后必须跟构建命令，如：./tools/bootstrap_official_license.sh -- bash tools/build_swift_bindings.sh"
  fi
  trap '_rc=$?; bash "${SCRIPT_DIR}/restore_license_vendor_stub.sh" || _rc=1; exit "${_rc}"' EXIT
fi

# ---- 校验私有仓结构与三个 crate 齐全 ----
[[ -d "${PRIVATE_REPO}" ]] || die "私有仓不存在：${PRIVATE_REPO}（用 PRIVATE_REPO=/path 覆盖）"
for crate in cf-assemble cf-license cf-keychain; do
  [[ -d "${PRIVATE_REPO}/crates/${crate}" ]] \
    || die "私有仓缺少 crate：${PRIVATE_REPO}/crates/${crate}"
done

step "1/2 覆盖 vendor/license/ 为私有仓真实源码（私有仓：${PRIVATE_REPO}）"
for crate in cf-assemble cf-license cf-keychain; do
  src="${PRIVATE_REPO}/crates/${crate}"
  dst="${VENDOR_DIR}/${crate}"
  mkdir -p "${dst}/src"
  cp "${src}/Cargo.toml" "${dst}/Cargo.toml"
  cp -R "${src}/src/." "${dst}/src/"
  printf '  覆盖 %s\n' "${crate}"
done

if [[ ${#BUILD_CMD[@]} -gt 0 ]]; then
  step "2/3 执行构建命令：${BUILD_CMD[*]}"
  # 构建结束 EXIT trap 自动恢复 vendor/license/ 为 stub；失败也恢复。
  "${BUILD_CMD[@]}" || die "构建命令失败（exit $?），vendor/license/ 已由 EXIT trap 恢复为 stub"
else
  step "2/2 验证"
  echo "  vendor/license/ 现在是真实源码（含闭源逻辑）。"
  echo "  官方构建：cd core && cargo build -p cf-ffi --features official-license"
  echo
  echo "  ⚠️  构建结束后必须恢复 stub（两步，缺一不可）："
  echo "      git restore core/vendor/license"
  echo "      git clean -fd core/vendor/license"
  echo "      或一键核验恢复：bash tools/restore_license_vendor_stub.sh"
fi
