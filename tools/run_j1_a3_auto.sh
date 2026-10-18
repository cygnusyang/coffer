#!/usr/bin/env bash
# run_j1_a3_auto.sh —— J-1（唤起 Passwords.app）+ A-3（bookmark 失效语义）全自动核销
# 固化版（docs/04-测试与验收/18-v2.11.0验收判据骨架.md §6 RT-01/RT-06，2026-10-18 首跑全绿）。
#
# 定位：两条原本「需用户配合」的真机判据，经 test seam 家族（docs/19 §5.3 lead 批准
# 纪律，与 testBaseDir / debugDisableTouchID 同族）改为**零键鼠注入**的后台自动核销：
#   - J-1: `--test-open-passwords` 直启 → AppDelegate 走产品同链
#          PasswordsAppLauncher.open()（NSWorkspace.open 无参数纯 URL，BUG-30 类坑豁免）
#   - A-3: `--test-open-dropzone-wizard` 直启 → 解锁后 MainView 自动打开放置区向导
#          sheet + `coffer.debugAuthorizeDropzonePath` 让向导 onAppear 自动走
#          authorize(url:)（与「选择放置区目录…」按钮同码路，跳过仅 NSOpenPanel 手势；
#          目标限定 App 自有容器内目录）。
#
# 断言（轴向证据：AX 文本锚点 + shell 文件操作）：
#   A3-00 自动授权 S0→S1；A3a 改名失效；A3b chmod 000 失效；A3c 删除失效；
#   A3d-1 跨重启 bookmark 持久；A3d-2 跨重启且目录已删 → notAuthorized（非幽灵授权）。
#
# 轴向判别坑（2026-10-18 实证，勿回退）：
#   - 壳标题「从 macOS 密码 App 导入」在任何 step 都存在，**不能**当状态判据；
#     S0 正文锚点用「你的钥匙串密码」，S1 用「监视仅在向导打开期间」。
#   - press 用 press-all（LockView 按钮与同名菜单项混排；press1 可能先命中静态文本）。
#   - A3d-2 必须先删 `coffer.debugAuthorizeDropzonePath`：目录已删时 seam 会走
#     save 失败落 S0-E（authFailed），掩盖产品真路径（真机无此键 → S0 notAuthorized）。
#
# R2 / 卫生纪律：
#   - 测试密码只走 env COFFER_TEST_PASSWORD（driver type 与 UIAXHarness create 同源）；
#   - 测试库/放置区目录 = 沙盒容器内固定路径（沙盒禁 /tmp，docs/19 §5.3）；
#   - 用完必清（trap）：terminate App + 删 four debug defaults + rm -rf 测试目录；
#   - argv 不含密码。
#
# 用法：COFFER_TEST_PASSWORD=<密码> ./tools/run_j1_a3_auto.sh
#   前置：macos/build/Coffer.app 已构建、macos/build/axdriver/UIAXDriver 可用、
#         AX 已授权、GUI 会话已解锁。
#   退出码：0 全绿；1 有 FAIL；2 环境/建库错误；3 A-3 前置态不明。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_PATH="${ROOT_DIR}/macos/build/Coffer.app"
DRIVER="${ROOT_DIR}/macos/build/axdriver/UIAXDriver"
FFI_SWIFT="${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffi.swift"
FFI_H="${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffiFFI.h"
HARNESS_SRC="${ROOT_DIR}/macos/Tests/UIAXHarness/main.swift"
BUNDLE_ID=top.cygnusyang.coffer
TEST_DIR="${HOME}/Library/Containers/${BUNDLE_ID}/Data/Library/CofferJ1A3Test"
A3DIR="${HOME}/Library/Containers/${BUNDLE_ID}/Data/Library/CofferA3Dir"
PASSWORD="${COFFER_TEST_PASSWORD:?need env COFFER_TEST_PASSWORD（R2：密码只走 env）}"

[[ -x "${APP_PATH}/Contents/MacOS/Coffer" ]] || { echo "ERROR: App 未构建：${APP_PATH}" >&2; exit 2; }
[[ -x "${DRIVER}" ]] || { echo "ERROR: UIAXDriver 缺失：${DRIVER}" >&2; exit 2; }

FAILS=0
pass() { echo "$1-PASS $2"; }
fail() { echo "$1-FAIL $2"; FAILS=$((FAILS + 1)); }

cleanup() {
  osascript -e 'tell application "Passwords" to quit' >/dev/null 2>&1
  killall Coffer 2>/dev/null; sleep 1; pkill -9 -x Coffer 2>/dev/null
  defaults delete "${BUNDLE_ID}" coffer.testBaseDir 2>/dev/null
  defaults delete "${BUNDLE_ID}" lastVaultUUID 2>/dev/null
  defaults delete "${BUNDLE_ID}" debugDisableTouchID 2>/dev/null
  defaults delete "${BUNDLE_ID}" coffer.debugAuthorizeDropzonePath 2>/dev/null
  rm -rf "${TEST_DIR}" "${A3DIR}" "${A3DIR}.stale" "${OUT:-}" 2>/dev/null
}
trap cleanup EXIT

# ================= J-1：直启 + seam 唤起 Passwords.app =================
echo "=== J-1（seam 直启，无 GUI 交互）==="
killall Coffer 2>/dev/null; sleep 1
pgrep -x Passwords >/dev/null && { osascript -e 'tell application "Passwords" to quit' >/dev/null 2>&1; sleep 2; }
"${APP_PATH}/Contents/MacOS/Coffer" --test-open-passwords >/dev/null 2>&1 &
sleep 6
if pgrep -x Passwords >/dev/null; then
  pass J1 "沙盒 App 内唤起 Passwords.app 成功（走产品同链 PasswordsAppLauncher.open）"
else
  fail J1 "未检测到 Passwords.app"
fi
osascript -e 'tell application "Passwords" to quit' >/dev/null 2>&1
killall Coffer 2>/dev/null; sleep 1

# ================= A-3：seam 自动授权 + 失效语义 =================
echo "=== A-3（seam 自动授权，AX+shell 断言）==="
OUT=$(mktemp -d)
swiftc -O -swift-version 5 -target "$(uname -m)"-apple-macos14.0 \
  -import-objc-header "${FFI_H}" "${FFI_SWIFT}" "${HARNESS_SRC}" \
  -L "${ROOT_DIR}/core/target/release" -lcf_ffi -o "${OUT}/UIAXHarness" || exit 2

rm -rf "${TEST_DIR}" "${A3DIR}"; mkdir -p "$(dirname "${TEST_DIR}")" "${A3DIR}"
echo seed > "${A3DIR}/README.txt"
CREATE_OUT=$(COFFER_TEST_PASSWORD="${PASSWORD}" "${OUT}/UIAXHarness" create "${TEST_DIR}")
VUUID=$(echo "${CREATE_OUT}" | awk -F'\t' '$1=="VAULTUUID"{print $2; exit}')
[[ -n "${VUUID}" ]] || { echo "FATAL 建库失败（无 VAULTUUID）" >&2; exit 2; }
defaults write "${BUNDLE_ID}" debugDisableTouchID -bool true
defaults write "${BUNDLE_ID}" coffer.testBaseDir -string "${TEST_DIR}"
defaults write "${BUNDLE_ID}" lastVaultUUID -string "${VUUID}"
defaults write "${BUNDLE_ID}" coffer.debugAuthorizeDropzonePath -string "${A3DIR}"

unlock_flow() {
  "${APP_PATH}/Contents/MacOS/Coffer" --test-open-dropzone-wizard >/dev/null 2>&1 &
  for i in $(seq 1 30); do
    "${DRIVER}" find "请输入主密码" >/dev/null 2>&1 && break
    sleep 1
  done
  COFFER_TEST_PASSWORD="${PASSWORD}" "${DRIVER}" type "请输入主密码"
  sleep 1
  "${DRIVER}" press "解锁" >/dev/null 2>&1
}

wait_anchor() {
  local q="$1" tries="${2:-20}"
  for i in $(seq 1 "${tries}"); do
    "${DRIVER}" find "${q}" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

open_wizard_state() {
  for i in $(seq 1 25); do
    "${DRIVER}" find "你的钥匙串密码" >/dev/null 2>&1 && return 0
    "${DRIVER}" find "监视仅在向导打开期间" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

unlock_flow
if open_wizard_state; then
  :
else
  echo "DBG-窗口: $("${DRIVER}" windows 2>/dev/null | head -3 | tr '\n' ';')"
  "${DRIVER}" find "解锁" | head -3
  echo "A3-00-FAIL 向导 sheet 未出现"; exit 3
fi
if wait_anchor "监视仅在向导打开期间" 15; then
  pass A3-00 "seam 自动授权成功（S0 → S1）"
elif "${DRIVER}" find "你的钥匙串密码" >/dev/null 2>&1; then
  fail A3-00 "向导已开但停在 S0（自动授权未生效）"
  defaults read "${BUNDLE_ID}" coffer.debugAuthorizeDropzonePath 2>/dev/null
else
  fail A3-00 "向导态不明"
fi

echo "--- A-3a 改名 → 失效检测 ---"
mv "${A3DIR}" "${A3DIR}.stale"; sleep 3
if wait_anchor "你的钥匙串密码" 15 && "${DRIVER}" find "不可用" >/dev/null 2>&1; then
  pass A3a "改名后向导回 S0 且失效提示（非静默）"
else
  fail A3a "未回 S0 或无失效提示"
fi
mv "${A3DIR}.stale" "${A3DIR}"; sleep 3

echo "--- A-3b chmod 000 → 失效检测 ---"
chmod 000 "${A3DIR}"; sleep 3
if wait_anchor "你的钥匙串密码" 15 && "${DRIVER}" find "不可用" >/dev/null 2>&1; then
  pass A3b "chmod 后向导回 S0 且失效提示"
else
  fail A3b "未回 S0 或无失效提示"
fi
chmod 755 "${A3DIR}"; sleep 3

echo "--- A-3c 删除 → 会话内 .stale 回 S0 ---"
# 口径（lead 裁定 2026-10-16）：会话内失效呈 .stale；跨重启删除才是 .notAuthorized
# （A3d-2）。两者都落 S0 授权页，区别仅入口文案。
rm -rf "${A3DIR}"; sleep 3
if wait_anchor "你的钥匙串密码" 15; then
  pass A3c "删除后向导回 S0（失效非静默）"
else
  fail A3c "未回 S0"
fi

echo "--- A-3d 跨重启持久性（重建目录 → 重启 → 断言非幽灵）---"
mkdir -p "${A3DIR}"; echo seed > "${A3DIR}/README.txt"
killall Coffer 2>/dev/null; sleep 2
unlock_flow
if open_wizard_state && "${DRIVER}" find "监视仅在向导打开期间" >/dev/null 2>&1; then
  pass A3d-1 "bookmark 跨重启持久（同路径重建后自动授权态恢复）"
else
  fail A3d-1 "重启后未恢复授权态"
fi
killall Coffer 2>/dev/null; sleep 2
rm -rf "${A3DIR}"
defaults delete "${BUNDLE_ID}" coffer.debugAuthorizeDropzonePath 2>/dev/null
unlock_flow
if wait_anchor "你的钥匙串密码" 20; then
  if "${DRIVER}" find "选择放置区目录" >/dev/null 2>&1; then
    pass A3d-2 "重启+目录已删 → S0 notAuthorized（非幽灵授权）"
  else
    fail A3d-2 "回 S0 但非 notAuthorized 入口（疑似 stale 态）"
  fi
elif "${DRIVER}" find "监视仅在向导打开期间" >/dev/null 2>&1; then
  fail A3d-2 "仍呈已授权（幽灵授权）"
else
  fail A3d-2 "向导态不明"
fi

echo "=== DONE（FAIL=${FAILS}）==="
[[ "${FAILS}" -eq 0 ]] || exit 1
