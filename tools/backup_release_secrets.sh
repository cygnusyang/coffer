#!/usr/bin/env bash
# backup_release_secrets.sh —— 把发布所需的 4 个 CI secret 备份进 Coffer 库（环境容器）。
#
# 背景（运营门槛 T3-3.5）：bus factor = 1 的最大风险不是代码，是**发布材料只在一个人手上**。
# 本脚本把「重建发布」所需的材料收进 Coffer 的环境容器 `coffer-release`：本地加密、不上云。
#
# 纪律（R2）：值只经 stdin 传入 CLI，**不落 argv / 不落 stdout / 不落日志**；脚本只回显变量名。
#
# 用法：
#   ./tools/backup_release_secrets.sh --dry-run     # 只打印计划，不写入、不读任何值
#   ./tools/backup_release_secrets.sh               # 交互式：逐项取值并写入
#
# 取值来源：
#   APPLE_PROVISIONING_PROFILE_BASE64  ← 自动：macos/build/*.provisionprofile
#   APPLE_CERT_P12_BASE64              ← 交互：p12 路径（可用 tools/export_ci_secrets.sh 生成）
#   APPLE_CERT_PASSWORD                ← 交互：隐藏输入
#   UPDATE_SIGNING_KEY_BASE64          ← 交互：隐藏输入（只存于 GitHub Secrets，无法导出）
#
# 恢复（换机器 / 交接）：打开 Coffer → 条目「coffer-release」（带 coffer:environment 标签）
#   → 逐项复制到 GitHub → Settings → Secrets and variables → Actions。
#   注意：CLI 故意**不提供**读出秘密的能力（R2），恢复必须人工复制。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCOPE="coffer-release"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

# coffer CLI 必须从 App 内路径运行（签名绑定），与 README 一致
COFFER_BIN="/Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer"
[[ -x "${COFFER_BIN}" ]] || die "未找到 Coffer CLI：${COFFER_BIN}（先把 App 装到 /Applications）"

put() {  # put <NAME>  值经 stdin 传入
  local name="$1"
  if [[ "${DRY_RUN}" == "1" ]]; then
    cat >/dev/null   # 消费掉 stdin，不写入
    printf 'DRY  would write %s → 容器 %s\n' "${name}" "${SCOPE}"
    return 0
  fi
  if "${COFFER_BIN}" set-env --scope "${SCOPE}" "${name}" >/dev/null 2>&1; then
    printf 'OK   %s 已写入容器 %s\n' "${name}" "${SCOPE}"
  else
    printf 'FAIL %s 写入失败（是否已解锁？托管是否启用？）\n' "${name}" >&2
    return 1
  fi
}

step "1/4 APPLE_PROVISIONING_PROFILE_BASE64（自动）"
PROFILE="$(ls "${ROOT_DIR}"/macos/build/*.provisionprofile 2>/dev/null | head -1)"
[[ -n "${PROFILE}" ]] || die "未找到 provisioning profile：先跑 ./tools/make_provisioning_profile.sh"
printf '来源：%s（到期时间见 plutil 或 make 脚本输出）\n' "${PROFILE}"
base64 -i "${PROFILE}" | put APPLE_PROVISIONING_PROFILE_BASE64 || die "写入失败"

step "2/4 APPLE_CERT_P12_BASE64（交互）"
if [[ "${DRY_RUN}" == "1" ]]; then
  printf 'DRY  需要你提供 p12 路径（可用 ./tools/export_ci_secrets.sh 导出）\n'
else
  read -r -p 'p12 文件路径：' P12_PATH
  [[ -f "${P12_PATH}" ]] || die "p12 不存在：${P12_PATH}"
  base64 -i "${P12_PATH}" | put APPLE_CERT_P12_BASE64 || die "写入失败"
fi

step "3/4 APPLE_CERT_PASSWORD（交互，隐藏输入）"
if [[ "${DRY_RUN}" == "1" ]]; then
  printf 'DRY  需要隐藏输入 p12 导出密码\n'
else
  read -r -s -p 'p12 导出密码：' CERT_PW; echo
  printf '%s' "${CERT_PW}" | put APPLE_CERT_PASSWORD || die "写入失败"
  unset CERT_PW
fi

step "4/4 UPDATE_SIGNING_KEY_BASE64（交互，隐藏输入）"
printf '提示：该值只存在于 GitHub Secrets；若已丢失，换新密钥会使旧版本无法验签新清单。\n'
if [[ "${DRY_RUN}" == "1" ]]; then
  printf 'DRY  需要隐藏输入 OTA Ed25519 私钥（base64）\n'
else
  read -r -s -p 'OTA 签名私钥（base64）：' OTA_KEY; echo
  printf '%s' "${OTA_KEY}" | put UPDATE_SIGNING_KEY_BASE64 || die "写入失败"
  unset OTA_KEY
fi

step "完成"
if [[ "${DRY_RUN}" == "1" ]]; then
  printf '（dry-run：未写入任何值。去掉 --dry-run 执行真实备份）\n'
else
  printf '备份已写入 Coffer 容器 %s（条目带 coffer:environment 标签，App 内可见）。\n' "${SCOPE}"
  printf '仍需：① 确认 4 项都在 ② 定期复核 ③ 另外保留一份离线副本（避免 Coffer 库本身成为单点）。\n'
fi
