#!/usr/bin/env bash
# make_dmg.sh —— 将 macos/build/Coffer.app 打包为「拖拽安装」DMG（hdiutil，零第三方依赖）。
#
# 背景（2026-10-10 用户需求）：GitHub Release 需发布 DMG 安装包（docs/04 §443
# 早有预期 ".dmg / .zip 可分发的公证版本"）。当前签名体系 = 免费账号 Apple
# Development 证书 + 无 Developer ID、无公证（docs/35 §0 长期目标 ADP），故
# DMG 与现有 zip 同级分发模型：内部 .app 已是方案 A（Apple Development）签名，
# DMG 本身不签名不公证（与 zip 一致，无 ADP 前 Gatekeeper 均需用户右键打开）。
#
# 重要边界：**zip 仍是 OTA 唯一更新载体**（docs/35 §6.1 契约，App 只认 zip
# 下载解压覆盖，update-manifest.json 的 downloadUrl 恒指 Coffer-<TAG>.zip）。
# 本脚本产物仅供**人类手动安装**（挂载 → 拖 Coffer.app 到 Applications），
# 与 zip 并存、互不替代——release.yml 同时上传两者。
#
# 用法：
#   ./tools/make_dmg.sh               # → macos/build/Coffer-<版本>.dmg（版本读 Info.plist）
#   TAG=v2.8.0 ./tools/make_dmg.sh    # → macos/build/Coffer-v2.8.0.dmg（CI 用，显式 tag）
#
# 产物：macos/build/Coffer-<TAG>.dmg（内含 Coffer.app + Applications 软链，
# 挂载后拖拽安装体验）。兼容 bash 3.2（macOS 自带 /bin/bash，对齐 build_macos_app.sh）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${ROOT_DIR}/macos/build/Coffer.app"
BUILD_DIR="${ROOT_DIR}/macos/build"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

[[ -d "${APP_DIR}" ]] || die "缺少 Coffer.app（${APP_DIR}）：请先运行 ./tools/build_macos_app.sh 构建签名产物。"

# 版本优先取显式 TAG（CI 传 GITHUB_REF_NAME=v2.8.0），否则读产物 Info.plist。
if [[ -n "${TAG:-}" ]]; then
  VERSION="${TAG}"
else
  VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "${APP_DIR}/Contents/Info.plist" 2>/dev/null || true)"
  [[ -n "${VERSION}" ]] || die "无法确定版本：请设 TAG=<tag> 或确认 Info.plist 含 CFBundleShortVersionString。"
  VERSION="v${VERSION#v}"
fi

DMG_PATH="${BUILD_DIR}/Coffer-${VERSION}.dmg"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/coffer-dmg.XXXXXX")"
trap 'rm -rf "${STAGE}"' EXIT

step "打包 DMG（拖拽安装：Coffer.app + Applications 软链）→ ${DMG_PATH}"
cp -R "${APP_DIR}" "${STAGE}/Coffer.app"
# 软链 /Applications：挂载后用户可见「Applications」文件夹，拖入即安装。
ln -s /Applications "${STAGE}/Applications"

# hdiutil 零依赖制作只读压缩 DMG（UDZO）。-ov 覆盖既有同名产物（CI 重跑容忍）。
# 注：免费账号下 DMG 不签名不公证（与 zip 同级，见头部注释）。
hdiutil create \
  -volname "Coffer" \
  -srcfolder "${STAGE}" \
  -ov \
  -format UDZO \
  "${DMG_PATH}" >/dev/null || die "hdiutil 创建 DMG 失败。"

# 挂载自检：确认 DMG 内容与 .app 签名完整性（可读性门禁，防空包/坏包上架）。
MOUNT_POINT="$(mktemp -d "${TMPDIR:-/tmp}/coffer-dmg-mnt.XXXXXX")"
trap 'hdiutil detach "${MOUNT_POINT}" >/dev/null 2>&1 || true; rm -rf "${STAGE}" "${MOUNT_POINT}"' EXIT
hdiutil attach "${DMG_PATH}" -mountpoint "${MOUNT_POINT}" -nobrowse >/dev/null \
  || die "DMG 挂载自检失败。"
[[ -d "${MOUNT_POINT}/Coffer.app" ]] || die "DMG 自检：缺少 Coffer.app。"
[[ -L "${MOUNT_POINT}/Applications" ]] || die "DMG 自检：缺少 Applications 软链。"
codesign --verify --strict "${MOUNT_POINT}/Coffer.app" \
  || die "DMG 自检：内部 Coffer.app 签名校验失败。"
hdiutil detach "${MOUNT_POINT}" >/dev/null 2>&1 || true

ls -lh "${DMG_PATH}"
step "完成 ✅ DMG 就绪（人类手动安装包；OTA 仍走 zip，见 docs/35 §6.1）"
echo "  DMG : ${DMG_PATH}"
