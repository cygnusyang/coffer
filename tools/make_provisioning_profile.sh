#!/usr/bin/env bash
# make_provisioning_profile.sh —— 生成/刷新 app.coffer.Coffer 的 Mac App Development
# 描述文件（provisioning profile）。（BUG-2 方案 A.2，见 docs/KNOWN-ISSUES.md）
#
# 背景：macOS 数据保护钥匙串的访问组列表完全由 keychain-access-groups
# entitlement 构建（TN3137），而该 entitlement 属受限权限，**必须经
# provisioning profile 授权**——仅 Apple Development 真证书签名不够，
# 缺 profile 时进程 spawn 即被 SIGKILL（`open` 报 launchd error 163）。
#
# 免费（个人）团队的限制：
#   - profile 需把本机 Mac 注册为开发设备（本脚本以
#     -allowProvisioningDeviceRegistration 自动完成，Apple ID 免费账号即可）
#   - profile 有效期仅 7 天 → 过期后重跑本脚本刷新，再重跑 build_macos_app.sh
#
# 产物：macos/build/app.coffer.Coffer.provisionprofile（供 build_macos_app.sh
# 嵌入 Contents/embedded.provisionprofile；位于 gitignore 的 macos/build/ 内，
# 含设备注册信息，不入库）。
#
# 用法：./tools/make_provisioning_profile.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_PROFILE="${ROOT_DIR}/macos/build/app.coffer.Coffer.provisionprofile"
STORE="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

command -v xcodebuild >/dev/null 2>&1 || die "未找到 xcodebuild，请安装完整版 Xcode。"

step "1/2 xcodebuild 自动签名构建（注册本机 Mac + 生成 profile，需 Xcode 已登录 Apple ID）"
xcodebuild -project "${ROOT_DIR}/tools/profilegen/ProfileGen.xcodeproj" \
  -scheme ProfileGen -configuration Debug \
  -destination 'platform=macOS' \
  -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
  build >/dev/null || die "profile 生成失败：请确认 Xcode → Settings → Accounts 已登录 Apple ID（免费账号即可）。"

step "2/2 提取 app.coffer.Coffer 的最新 profile"
[[ -d "${STORE}" ]] || die "未找到 profile 存储（${STORE}）。"
LATEST=""
while IFS= read -r -d '' f; do
  # 只取授权了 keychain-access-groups 且对应 app.coffer.Coffer 的 profile
  if security cms -D -i "${f}" 2>/dev/null | grep -q 'app.coffer.Coffer' \
    && security cms -D -i "${f}" 2>/dev/null | grep -q 'keychain-access-groups'; then
    if [[ -z "${LATEST}" || "${f}" -nt "${LATEST}" ]]; then
      LATEST="${f}"
    fi
  fi
done < <(find "${STORE}" -name '*.provisionprofile' -print0)
[[ -n "${LATEST}" ]] || die "存储中无 app.coffer.Coffer 的有效 profile。"

mkdir -p "$(dirname "${OUT_PROFILE}")"
cp "${LATEST}" "${OUT_PROFILE}"

EXPIRE=$(security cms -D -i "${OUT_PROFILE}" 2>/dev/null | grep -A1 ExpirationDate | tail -1 | sed 's/.*<date>\(.*\)<\/date>.*/\1/')
printf '完成 ✅\n  profile: %s\n  来源  : %s\n  到期  : %s（免费账号 7 天，过期重跑本脚本）\n' \
  "${OUT_PROFILE}" "${LATEST}" "${EXPIRE}"
