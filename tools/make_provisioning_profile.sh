#!/usr/bin/env bash
# make_provisioning_profile.sh —— 生成/刷新 top.cygnusyang.coffer 的 Mac App Development
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
# 产物：macos/build/top.cygnusyang.coffer.provisionprofile（供 build_macos_app.sh
# 嵌入 Contents/embedded.provisionprofile；位于 gitignore 的 macos/build/ 内，
# 含设备注册信息，不入库）。
#
# Developer ID 形态（v2.14.0）：
#   对外分发（公证）需要 **Mac Team Direct** profile —— 实测 Developer ID 签名但
#   不带 profile 时，带 keychain-access-groups 的进程在 spawn 门被 AMFI 拒绝
#   （launchd error 163）。该 profile 由 Xcode 以 `-exportArchive`（method=
#   developer-id）自动签发并嵌入导出产物，本脚本再从产物中提取。有效期 18 年
#   （TimeToLive 6570 天），无需周期刷新。
#
# 用法：
#   ./tools/make_provisioning_profile.sh                  # Mac Team Development（7 天）
#   ./tools/make_provisioning_profile.sh --developer-id   # Mac Team Direct（Developer ID，18 年）
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-development}"
if [[ "${MODE}" == "--developer-id" ]]; then
  OUT_PROFILE="${ROOT_DIR}/macos/build/top.cygnusyang.coffer.developerid.provisionprofile"
elif [[ "${MODE}" == "development" || -z "${MODE}" ]]; then
  OUT_PROFILE="${ROOT_DIR}/macos/build/top.cygnusyang.coffer.provisionprofile"
else
  printf 'ERROR: 未知参数 %s（可选 --developer-id）\n' "${MODE}" >&2; exit 2
fi
STORE="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

command -v xcodebuild >/dev/null 2>&1 || die "未找到 xcodebuild，请安装完整版 Xcode。"

if [[ "${MODE}" == "--developer-id" ]]; then
  # Developer ID 形态：archive（开发签名）→ exportArchive（method=developer-id）。
  # 导出的 .app 内嵌的就是 Xcode 为该 App ID 签发的 Mac Team Direct profile，
  # 本脚本直接提取该文件，避免在多个 profile 里猜哪个是 Direct 版。
  ARCHIVE="${ROOT_DIR}/macos/build/ProfileGen.xcarchive"
  EXPORT_DIR="${ROOT_DIR}/macos/build/ProfileGen-export"
  EXPORT_PLIST="${ROOT_DIR}/macos/build/exportOptions-developerid.plist"
  rm -rf "${ARCHIVE}" "${EXPORT_DIR}"
  mkdir -p "${ROOT_DIR}/macos/build"
  cat > "${EXPORT_PLIST}" <<'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>developer-id</string>
  <key>signingStyle</key><string>automatic</string>
</dict></plist>
PLIST_EOF

  step "1/2 archive（开发签名）"
  xcodebuild -project "${ROOT_DIR}/tools/profilegen/ProfileGen.xcodeproj" \
    -scheme ProfileGen -configuration Release \
    -archivePath "${ARCHIVE}" archive -allowProvisioningUpdates >/dev/null \
    || die "archive 失败：请确认 Xcode → Settings → Accounts 已登录 Apple ID，且已有 Developer ID Application 证书。"

  step "2/2 exportArchive（method=developer-id，签发 Mac Team Direct profile）"
  xcodebuild -exportArchive -archivePath "${ARCHIVE}" -exportPath "${EXPORT_DIR}" \
    -exportOptionsPlist "${EXPORT_PLIST}" -allowProvisioningUpdates >/dev/null \
    || die "导出失败：Developer ID 导出需要 Developer ID Application 证书与 Mac Team Direct profile 权限。"
  EMBEDDED="${EXPORT_DIR}/ProfileGen.app/Contents/embedded.provisionprofile"
  [[ -f "${EMBEDDED}" ]] || die "导出产物未内嵌 profile（${EMBEDDED}）。"
  mkdir -p "$(dirname "${OUT_PROFILE}")"
  cp "${EMBEDDED}" "${OUT_PROFILE}"
  rm -rf "${ARCHIVE}" "${EXPORT_DIR}"
else
step "1/2 xcodebuild 自动签名构建（注册本机 Mac + 生成 profile，需 Xcode 已登录 Apple ID）"
xcodebuild -project "${ROOT_DIR}/tools/profilegen/ProfileGen.xcodeproj" \
  -scheme ProfileGen -configuration Debug \
  -destination 'platform=macOS' \
  -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
  build >/dev/null || die "profile 生成失败：请确认 Xcode → Settings → Accounts 已登录 Apple ID（免费账号即可）。"

step "2/2 提取 top.cygnusyang.coffer 的最新 profile"
[[ -d "${STORE}" ]] || die "未找到 profile 存储（${STORE}）。"
LATEST=""
while IFS= read -r -d '' f; do
  # 只取授权了 keychain-access-groups 且对应 top.cygnusyang.coffer 的 profile
  if security cms -D -i "${f}" 2>/dev/null | grep -q 'top.cygnusyang.coffer' \
    && security cms -D -i "${f}" 2>/dev/null | grep -q 'keychain-access-groups'; then
    if [[ -z "${LATEST}" || "${f}" -nt "${LATEST}" ]]; then
      LATEST="${f}"
    fi
  fi
done < <(find "${STORE}" -name '*.provisionprofile' -print0)
[[ -n "${LATEST}" ]] || die "存储中无 top.cygnusyang.coffer 的有效 profile。"

mkdir -p "$(dirname "${OUT_PROFILE}")"
cp "${LATEST}" "${OUT_PROFILE}"
fi

EXPIRE=$(security cms -D -i "${OUT_PROFILE}" 2>/dev/null | grep -A1 ExpirationDate | tail -1 | sed 's/.*<date>\(.*\)<\/date>.*/\1/')
printf '完成 ✅\n  profile: %s\n  类型  : %s\n  到期  : %s\n' \
  "${OUT_PROFILE}" "${MODE}" "${EXPIRE}"
