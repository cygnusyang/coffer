#!/usr/bin/env bash
# build_macos_app.sh —— 一条命令从源码构建可启动的 Coffer.app（T05 v0.1）。
#
# 工程决策（docs/07 §7 T05）：本机无 xcodegen；手写 project.pbxproj 脆弱且
# 需要维护 Xcode 版本兼容。故采用 **swiftc + Info.plist 直出 .app bundle**：
#   - 无 Xcode 工程依赖，CI / 任意装有 Xcode CLT 的机器可复现
#   - 链接 release 静态库 libcf_ffi.a + UniFFI 生成 Swift 绑定
#   - ad-hoc codesign + App Sandbox entitlements（零 network.* 权限）
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
cp "${SRC_DIR}/Info.plist" "${APP_DIR}/Contents/Info.plist"
mkdir -p "${APP_DIR}/Contents/Resources"
printf 'APPL????' > "${APP_DIR}/Contents/PkgInfo"

# ---- 4/4 签名（ad-hoc + App Sandbox entitlements）----
step "4/4 ad-hoc codesign（App Sandbox，无 network.* 权限）"
codesign --force --sign - \
  --entitlements "${SRC_DIR}/Coffer.entitlements" \
  "${APP_DIR}" || die "codesign 失败。"

codesign --verify --strict "${APP_DIR}" || die "签名校验失败。"

step "完成 ✅"
echo "  App : ${APP_DIR}"
echo "  启动: open ${APP_DIR}"
echo "  核查零网络权限: codesign -d --entitlements - ${APP_DIR}"
