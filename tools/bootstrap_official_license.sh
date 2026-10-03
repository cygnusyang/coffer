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
# 真实源码提交进公开仓**——提交前必须恢复 stub（`git checkout -- core/vendor/`
# 或 `git restore core/vendor/license`）。私有仓代码（cf-license 判定器 /
# cf-keychain 真实 Keychain / cf-assemble 装配壳）只以 path 引用方式参与构建，
# 永不进入公开仓提交。
#
# 用法：
#   ./tools/bootstrap_official_license.sh                 # 私有仓默认路径
#   PRIVATE_REPO=/path/to/coffer-license ./tools/bootstrap_official_license.sh
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

step "2/2 验证"
echo "  vendor/license/ 现在是真实源码（含闭源逻辑）。"
echo "  官方构建：cd core && cargo build -p cf-ffi --features official-license"
echo
echo "  ⚠️  提交公开仓前必须恢复 stub：git restore core/vendor/license"
