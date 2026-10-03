#!/usr/bin/env bash
# build_macos_app.sh —— 一条命令从源码构建可启动的 Coffer.app（T05 v0.1）。
#
# 工程决策（docs/07 §7 T05）：本机无 xcodegen；手写 project.pbxproj 脆弱且
# 需要维护 Xcode 版本兼容。故采用 **swiftc + Info.plist 直出 .app bundle**：
#   - 无 Xcode 工程依赖，CI / 任意装有 Xcode CLT 的机器可复现
#   - 链接 release 静态库 libcf_ffi.a + UniFFI 生成 Swift 绑定
#   - Apple Development 证书 codesign + App Sandbox entitlements（方案 A，
#     见 docs/KNOWN-ISSUES.md BUG-2；ad-hoc 签名创建 Keychain 条目必报 -34018）
#   - 嵌入 Mac App Development provisioning profile（方案 A.2：keychain-access-groups
#     属受限 entitlement，须经 profile 授权；profile 由 make_provisioning_profile.sh 生成）
#
#   免费账号的 Apple Development 证书约 1 年有效，过期后重新运行本脚本
#   重签即可（本地构建无 notarization 依赖）。
#
# 用法：
#   ./tools/build_macos_app.sh                    # 产物 → macos/build/Coffer.app
#   ./tools/build_macos_app.sh --rebuild-bindings # 强制重跑 build_swift_bindings.sh
#
# 验收（docs/07 §7 T05 ⑤）：
#   codesign -d --entitlements - macos/build/Coffer.app   # 确认无 network.*
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORE_TARGET="${ROOT_DIR}/core/target"
SRC_DIR="${ROOT_DIR}/macos/Coffer"
APP_DIR="${ROOT_DIR}/macos/build/Coffer.app"

REBUILD_BINDINGS=0
if [[ "${1:-}" == "--rebuild-bindings" ]]; then
  REBUILD_BINDINGS=1
fi

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

command -v swiftc >/dev/null 2>&1 || die "未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。"

# ---- 1/4 Rust 静态库 + Swift 绑定 ----
if [[ ! -f "${CORE_TARGET}/release/libcf_ffi.a" || ! -f "${SRC_DIR}/CoreBindings/cf_ffi.swift" || "${REBUILD_BINDINGS}" == "1" ]]; then
  step "1/4 生成 Rust 静态库与 Swift 绑定（build_swift_bindings.sh）"
  "${ROOT_DIR}/tools/build_swift_bindings.sh" || die "绑定生成失败。"
else
  step "1/4 复用已有 libcf_ffi.a 与 CoreBindings（--rebuild-bindings 可强制重生成）"
fi

# ---- 2/4 编译 Swift 源 → 可执行文件 ----
step "2/4 swiftc 编译（SwiftUI 壳 + UniFFI 绑定，链接静态库）"
mkdir -p "${APP_DIR}/Contents/MacOS"

SOURCES=()
while IFS= read -r f; do
  SOURCES+=("${f}")
done < <(find "${SRC_DIR}" -name '*.swift' ! -path '*SmokeTest*' ! -path '*CoreBindings*' | sort)
SOURCES+=("${SRC_DIR}/CoreBindings/cf_ffi.swift")

printf '编译 %d 个 Swift 源文件\n' "${#SOURCES[@]}"

swiftc -O \
  -swift-version 5 \
  -target arm64-apple-macos14.0 \
  -parse-as-library \
  -import-objc-header "${SRC_DIR}/CoreBindings/cf_ffiFFI.h" \
  "${SOURCES[@]}" \
  -L "${CORE_TARGET}/release" \
  -lcf_ffi \
  -o "${APP_DIR}/Contents/MacOS/Coffer" \
  || die "swiftc 编译失败。"

# ---- 3/4 组装 bundle ----
step "3/4 组装 Coffer.app bundle"
# 先建 Contents/Resources：icns 拷贝目标目录须先存在（全新 build 目录首次
# 构建时 Resources 尚不存在，若后建则 cp 失败中止——v0.6.0 批次发现）
mkdir -p "${APP_DIR}/Contents/Resources"
cp "${SRC_DIR}/Info.plist" "${APP_DIR}/Contents/Info.plist"
if [[ -f "${SRC_DIR}/Resources/Coffer.icns" ]]; then
  cp "${SRC_DIR}/Resources/Coffer.icns" "${APP_DIR}/Contents/Resources/Coffer.icns"
fi
printf 'APPL????' > "${APP_DIR}/Contents/PkgInfo"

# ---- 4/4 签名（Apple Development 证书 + App Sandbox entitlements + profile）----
step "4/4 codesign（Apple Development 证书 + entitlements + provisioning profile）"
IDENTITY=$(security find-identity -v -p codesigning \
  | awk -F'"' '/Apple Development/{print $2; exit}')
[[ -n "${IDENTITY}" ]] || die "未找到 codesigning 身份（方案 A 要求 Apple Development 证书，BUG-2）：请在 Xcode → Settings → Accounts 登录 Apple ID 并生成证书后重试。不回退 ad-hoc。"
printf '签名身份: %s\n' "${IDENTITY}"

# keychain-access-groups 是受限 entitlement，必须嵌入 provisioning profile
# 授权，否则进程 spawn 即被 SIGKILL（BUG-2 方案 A.2）。
PROFILE="${ROOT_DIR}/macos/build/app.coffer.Coffer.provisionprofile"
if [[ ! -f "${PROFILE}" ]]; then
  die "缺少 provisioning profile（${PROFILE}）：请先运行 ./tools/make_provisioning_profile.sh 生成（免费账号 profile 7 天有效，过期需重跑刷新）。"
fi
cp "${PROFILE}" "${APP_DIR}/Contents/embedded.provisionprofile"

codesign --force --sign "${IDENTITY}" \
  --entitlements "${SRC_DIR}/Coffer.entitlements" \
  "${APP_DIR}" || die "codesign 失败。"

codesign --verify --strict "${APP_DIR}" || die "签名校验失败。"

step "完成 ✅"
echo "  App : ${APP_DIR}"
echo "  启动: open ${APP_DIR}"
echo "  核查签名与零网络权限: codesign -dv --entitlements - ${APP_DIR}"
