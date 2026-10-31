#!/usr/bin/env bash
# notarize_app.sh —— 对 Developer ID 签名的 Coffer.app 做公证（notarytool）并装订票据。
#
# 前置：
#   1) 产物由 DISTRIBUTION=developer-id ./tools/build_macos_app.sh 构建（Hardened
#      Runtime + 安全时间戳 + Mac Team Direct profile）；
#   2) 公证凭据已存进钥匙串 profile（一次性）：
#        xcrun notarytool store-credentials coffer-notary \
#          --apple-id <APPLE_ID> --team-id A6DS985SJJ --password <APP_SPECIFIC_PASSWORD>
#      （或 --key <.p8> --key-id <KEY_ID> --issuer <ISSUER_ID> 用 App Store Connect API Key）
#
# 做四件事：公证 .app → 装订 → 公证 DMG → 装订，最后 spctl 复核。
#
# 用法：
#   ./tools/notarize_app.sh                 # 默认钥匙串 profile = coffer-notary
#   NOTARY_PROFILE=foo ./tools/notarize_app.sh
#   TAG=v2.14.0 ./tools/notarize_app.sh     # 显式指定 DMG 版本号（CI 用）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${ROOT_DIR}/macos/build/Coffer.app"
BUILD_DIR="${ROOT_DIR}/macos/build"
NOTARY_PROFILE="${NOTARY_PROFILE:-coffer-notary}"
IDENTITY="${NOTARY_IDENTITY:-Developer ID Application}"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

[[ -d "${APP_DIR}" ]] || die "缺少 ${APP_DIR}：先跑 DISTRIBUTION=developer-id ./tools/build_macos_app.sh。"

# ---- 0 前置校验：必须真是 Developer ID + Hardened Runtime ----
step "0/5 前置校验（Developer ID 签名 + Hardened Runtime）"
AUTHORITY="$(codesign -dv --verbose=2 "${APP_DIR}" 2>&1 | awk -F'Authority=' '/Authority=Developer ID Application/{print $2; exit}')"
[[ -n "${AUTHORITY}" ]] || die "产物不是 Developer ID 签名（当前：$(codesign -dv "${APP_DIR}" 2>&1 | grep Authority | head -1)）。公证只接受 Developer ID。"
codesign -dv --verbose=4 "${APP_DIR}" 2>&1 | grep -q 'flags=.*runtime' \
  || die "缺少 Hardened Runtime（--options runtime），公证会被拒。请用 DISTRIBUTION=developer-id 构建。"
codesign --verify --deep --strict "${APP_DIR}" || die "签名校验失败。"
printf '签名身份: %s\n' "${AUTHORITY}"

# ---- 1 打 zip（notarytool 提交载体）----
step "1/5 打包待公证 zip"
ZIP="${BUILD_DIR}/Coffer-notarize.zip"
rm -f "${ZIP}"
/usr/bin/ditto -c -k --keepParent --sequesterRsrc "${APP_DIR}" "${ZIP}" \
  || die "ditto 打包失败。"

# ---- 2 提交公证（等待结果）----
step "2/5 notarytool submit（profile=${NOTARY_PROFILE}，等待结果）"
SUBMIT_JSON="${BUILD_DIR}/notarize-app.json"
if ! xcrun notarytool submit "${ZIP}" --keychain-profile "${NOTARY_PROFILE}" \
      --wait --output-format json > "${SUBMIT_JSON}" 2>"${BUILD_DIR}/notarize-app.err"; then
  cat "${BUILD_DIR}/notarize-app.err" >&2 || true
  cat "${SUBMIT_JSON}" >&2 || true
  die "公证提交失败：凭据缺失时先跑 xcrun notarytool store-credentials ${NOTARY_PROFILE} …（见本脚本头部说明）。"
fi
STATUS="$(plutil -extract status raw -o - "${SUBMIT_JSON}" 2>/dev/null || true)"
SUB_ID="$(plutil -extract id raw -o - "${SUBMIT_JSON}" 2>/dev/null || true)"
if [[ "${STATUS}" != "Accepted" ]]; then
  xcrun notarytool log "${SUB_ID}" --keychain-profile "${NOTARY_PROFILE}" 2>&1 | tail -40 >&2 || true
  die "公证未通过（status=${STATUS:-unknown}，id=${SUB_ID:-?}）：上面是 Apple 的拒绝原因日志。"
fi
printf '公证通过：id=%s\n' "${SUB_ID}"

# ---- 3 装订票据到 .app ----
step "3/5 staple（.app）"
xcrun stapler staple "${APP_DIR}" || die "staple .app 失败。"
xcrun stapler validate "${APP_DIR}" >/dev/null || die "staple 校验失败。"

# ---- 4 DMG：制作 → 签名 → 公证 → 装订 ----
step "4/5 DMG 制作与公证"
TAG="${TAG:-}" "${SCRIPT_DIR}/make_dmg.sh" || die "make_dmg.sh 失败。"
VERSION="${TAG:-$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${APP_DIR}/Contents/Info.plist")}"
VERSION="v${VERSION#v}"
DMG="${BUILD_DIR}/Coffer-${VERSION}.dmg"
[[ -f "${DMG}" ]] || die "未找到 DMG：${DMG}"
codesign --force --sign "${IDENTITY}" --timestamp "${DMG}" || die "DMG 签名失败。"
if ! xcrun notarytool submit "${DMG}" --keychain-profile "${NOTARY_PROFILE}" \
      --wait --output-format json > "${BUILD_DIR}/notarize-dmg.json" 2>&1; then
  cat "${BUILD_DIR}/notarize-dmg.json" >&2 || true
  die "DMG 公证提交失败。"
fi
DMG_STATUS="$(plutil -extract status raw -o - "${BUILD_DIR}/notarize-dmg.json" 2>/dev/null || true)"
[[ "${DMG_STATUS}" == "Accepted" ]] || die "DMG 公证未通过（status=${DMG_STATUS:-unknown}）。"
xcrun stapler staple "${DMG}" || die "staple DMG 失败。"

# ---- 5 复核 ----
step "5/5 Gatekeeper 复核"
spctl -a -vv "${APP_DIR}" 2>&1 || die "spctl 拒绝 .app（公证/装订未生效）。"
spctl -a -vv -t open --context context:primary-signature "${DMG}" 2>&1 || true

step "完成 ✅"
printf '  App : %s\n  DMG : %s\n  公证: %s（已装订，离线可验）\n' "${APP_DIR}" "${DMG}" "${SUB_ID}"
