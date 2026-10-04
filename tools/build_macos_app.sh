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
# 官方模式（OFFICIAL_LICENSE=1，Task 4c）：
#   透传 OFFICIAL_LICENSE 给 build_swift_bindings.sh（--features official-license
#   + 双 namespace 绑定），编译双绑定文件、加 -D OFFICIAL_LICENSE 编译宏
#   （官方适配 OfficialLicenseService.swift 与 AppModel bootstrap 装配点由该宏
#   门控）。前置：tools/bootstrap_official_license.sh 已跑。
#   OFFICIAL_LICENSE=1 ./tools/build_macos_app.sh --rebuild-bindings
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
# 官方模式开关（Task 3/4c）：透传 build_swift_bindings.sh + 双 namespace 编译
OFFICIAL_LICENSE="${OFFICIAL_LICENSE:-0}"
if [[ "${OFFICIAL_LICENSE}" == "1" ]]; then
  # 官方 FFI 表面保护纪律（lead 裁定 2026-10-04）：官方 app 构建会重生成
  # CoreBindings（cf_ffi.swift 被官方版覆盖 M 态 + 新增未跟踪 cf_assemble.*——
  # 私有 crate 生成的官方许可 FFI 表面）。披露边界不由构建产物隐式决定：
  # 官方构建产物 = build artifact 永不入库，公开仓 CoreBindings 只保持公开模式
  # 版本。trap 装在本脚本（官方 app 构建的收口处：构建 / 签名全程结束后恢复），
  # build_swift_bindings.sh 不动（它生成后 Swift 编译还要用 cf_assemble.swift）。
  # _rc 保留构建原始退出码：restore 失败强制 1，restore 成功不得掩盖构建失败。
  trap '_rc=$?; bash "${SCRIPT_DIR}/restore_corebindings_public.sh" || _rc=1; exit "${_rc}"' EXIT
fi

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

command -v swiftc >/dev/null 2>&1 || die "未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。"

# ---- 1/4 Rust 静态库 + Swift 绑定 ----
if [[ ! -f "${CORE_TARGET}/release/libcf_ffi.a" || ! -f "${SRC_DIR}/CoreBindings/cf_ffi.swift" || "${REBUILD_BINDINGS}" == "1" ]]; then
  step "1/4 生成 Rust 静态库与 Swift 绑定（build_swift_bindings.sh，OFFICIAL_LICENSE=${OFFICIAL_LICENSE}）"
  OFFICIAL_LICENSE="${OFFICIAL_LICENSE}" "${ROOT_DIR}/tools/build_swift_bindings.sh" || die "绑定生成失败。"
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

CLANG_INCLUDES=()
if [[ "${OFFICIAL_LICENSE}" == "1" ]]; then
  # 官方模式：LicenseService 绑定（cf_assemble.swift）+ 适配宏。
  # bridging header 用 Support/UniffiBridging.h（组合头 #include 两个 FFI 头）——
  # swiftc 只认最后一个 -import-objc-header，两个头并列传会被后一个覆盖（实测）。
  [[ -f "${SRC_DIR}/CoreBindings/cf_assemble.swift" ]] || die "官方模式缺 cf_assemble.swift——先跑 OFFICIAL_LICENSE=1 tools/build_swift_bindings.sh。"
  SOURCES+=("${SRC_DIR}/CoreBindings/cf_assemble.swift")
  COMPILE_DEFS+=("-D" "OFFICIAL_LICENSE")
  IMPORT_HEADERS=("-import-objc-header" "${SRC_DIR}/Support/UniffiBridging.h")
  # -I 供组合头里的 #include "cf_*FFI.h" 解析（clang 侧）
  CLANG_INCLUDES+=("-I" "${SRC_DIR}/CoreBindings")
else
  IMPORT_HEADERS=("-import-objc-header" "${SRC_DIR}/CoreBindings/cf_ffiFFI.h")
fi

printf '编译 %d 个 Swift 源文件%s\n' "${#SOURCES[@]}" "$([[ "${OFFICIAL_LICENSE}" == "1" ]] && echo '（官方模式）' || echo '（公开模式）')"

# bash 3.2 + set -u 下空数组 "${arr[@]}" 展开报 unbound variable（macOS 自带 /bin/bash），
# 故下方用 ${arr[@]+"${arr[@]}"} 守卫：数组非空才展开（bash 3.2 兼容写法）。
swiftc -O \
  -swift-version 5 \
  -target arm64-apple-macos14.0 \
  -parse-as-library \
  "${IMPORT_HEADERS[@]}" \
  ${CLANG_INCLUDES[@]+"${CLANG_INCLUDES[@]}"} \
  ${COMPILE_DEFS[@]+"${COMPILE_DEFS[@]}"} \
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
