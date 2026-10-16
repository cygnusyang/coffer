#!/usr/bin/env bash
# run_l3_ax_harness.sh —— L3 AX 黑盒 harness（docs/04-测试与验收/19-UI测试自动化分层设计.md
# §5.6/§5.7，W4 交付）。
#
# 被测面：成品 App（macos/build/Coffer.app）黑盒 AX。覆盖 IT-01（锁定态三入口 disabled /
# 解锁可点）、W-2（锁定停摆 fail-closed）。**不覆盖**（登记待做，见 docs/18 §5.x）：
# S0 授权 NSOpenPanel 真流程（spike ② 前置）、S1-S5（S5 删源警示文案 / IT-28 全流程）。
#
# 架构：
#   - UIAXDriver（macos/build/axdriver/UIAXDriver，W3b 交付）= AX 能力面，只读/驱动；
#   - UIAXHarness（macos/Tests/UIAXHarness/main.swift，本脚本动态编译）= FFI 建库编排层；
#   - 本脚本 = 编排：preflight → 建库/预置 defaults → 启动 → 断言 → 清理（finally）。
#
# R2 / 卫生纪律：
#   - 测试密码只走 env COFFER_TEST_PASSWORD（driver type 与 UIAXHarness create 同源）；
#   - 测试库/测试放置区目录 = 容器内固定路径（沙盒禁 /tmp，docs/19 §5.3）；
#   - 用完必清（finally/trap）：terminate App + 删三键 defaults + rm -rf 测试目录；
#   - argv 不含密码；所有 `type` 值走 env。
#
# 用法：COFFER_TEST_PASSWORD=<密码> ./tools/run_l3_ax_harness.sh
#   退出码：0 全绿；1 有断言失败；2 环境错误；3 App 未构建/未运行；5 AX 未授权；
#           6 屏幕锁定（needs unlocked GUI session，需解锁后重跑）
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="/tmp/coffer-ui-gate"
mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/l3-ax-harness-$(date +%Y%m%d-%H%M%S).log"

# 输出同时落盘（供 run_ui_gate.sh 汇总读取）
exec > >(tee -a "${LOG}") 2>&1

BUNDLE_ID="top.cygnusyang.coffer"
CONTAINER_DIR="$HOME/Library/Containers/${BUNDLE_ID}"
TEST_DIR="${CONTAINER_DIR}/Data/Library/CofferL3Test"
DROPZONE_DIR="${CONTAINER_DIR}/Data/Library/CofferL3Dropzone"
APP_PATH="${ROOT_DIR}/macos/build/Coffer.app"
DRIVER="${ROOT_DIR}/macos/build/axdriver/UIAXDriver"
DRIVER_SRC="${ROOT_DIR}/macos/Tests/UIAXTests/main.swift"
BUILD_AX_DRIVER="${ROOT_DIR}/tools/build_ax_driver.sh"
HARNESS_SRC="${ROOT_DIR}/macos/Tests/UIAXHarness/main.swift"
FFI_SWIFT="${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffi.swift"
FFI_H="${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffiFFI.h"
FFI_LIB="${ROOT_DIR}/core/target/release/libcf_ffi.a"
FIXTURE="${ROOT_DIR}/tests/fixtures/csv/dropzone_passwords_headers.csv"

PASSWORD="${COFFER_TEST_PASSWORD:-}"

# 断言汇总
ASSERT_PASS=0
ASSERT_FAIL=0
FAILURES=()
pass() { ASSERT_PASS=$((ASSERT_PASS + 1)); echo "PASS  $1  $2"; }
fail() { ASSERT_FAIL=$((ASSERT_FAIL + 1)); FAILURES+=("$1  $2  $3"); echo "FAIL  $1  $2  $3"; }

# 目标 App 终止 + 等待进程消失（cfprefsd 缓存：先退再写 defaults）
terminate_app() {
  killall Coffer 2>/dev/null
  for _ in $(seq 1 20); do
    pgrep -x Coffer >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  # 强杀兜底（正常不会到）
  pkill -9 -x Coffer 2>/dev/null
  sleep 1
}

# 清理：terminate + 删三键 defaults + 删测试目录（finally 语义，R2 卫生）
cleanup() {
  terminate_app
  defaults delete "${BUNDLE_ID}" coffer.testBaseDir 2>/dev/null
  defaults delete "${BUNDLE_ID}" lastVaultUUID 2>/dev/null
  defaults delete "${BUNDLE_ID}" debugDisableTouchID 2>/dev/null
  defaults delete "${BUNDLE_ID}" dropzone.bookmark.data 2>/dev/null
  rm -rf "${TEST_DIR}" "${DROPZONE_DIR}"
}
trap cleanup EXIT

# 等待谓词成立（$1 描述，$2 秒数上限，$3+ 命令；退出码 0=谓词在时限内成立）
wait_for() {
  local desc="$1" max="$2"
  shift 2
  local waited=0
  while (( waited < max )); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
    waited=$((waited + 1))
  done
  echo "TIMEOUT 等待 ${desc}（${max}s）"
  return 1
}

# 激活 App（open 对已运行实例=activate）。AX 内容/占位符只在 App 前台时完整暴露——
# 锁定相变后窗口重建期间须先激活再断言（W2-03 实证：不激活则 SecureField 占位不曝光）。
activate_app() {
  open "${APP_PATH}"
  sleep 2
}

# MARK: - 环境与前置检查

echo "================ L3 AX 黑盒 harness ================"
echo "日志：${LOG}"

# 0. 测试密码（R2：只走 env）
if [[ -z "${PASSWORD}" ]]; then
  echo "ERROR  缺 env COFFER_TEST_PASSWORD（R2：测试密码只走 env，与 driver type 同源）" >&2
  exit 2
fi

# 1. 前置依赖在位
[[ -d "${APP_PATH}" ]] || { echo "ERROR  缺 ${APP_PATH}（先 tools/build_macos_app.sh --channel developer-id）" >&2; exit 3; }
command -v swiftc >/dev/null 2>&1 || { echo "ERROR  未找到 swiftc" >&2; exit 2; }
[[ -f "${FFI_LIB}" ]] || { echo "ERROR  缺 ${FFI_LIB}（先 tools/build_swift_bindings.sh）" >&2; exit 2; }
[[ -f "${HARNESS_SRC}" ]] || { echo "ERROR  缺 ${HARNESS_SRC}" >&2; exit 2; }

# 2. AX driver 产物在位（TCC 授权锚点固定路径，缺失则编译）
if [[ ! -x "${DRIVER}" ]]; then
  echo "NOTE  编译 AX driver → ${DRIVER}（TCC 固定路径，docs/19 §5.4）"
  [[ -x "${BUILD_AX_DRIVER}" ]] || { echo "ERROR  缺 ${BUILD_AX_DRIVER}" >&2; exit 2; }
  "${BUILD_AX_DRIVER}" || { echo "ERROR  driver 编译失败" >&2; exit 2; }
fi

# 3. 编译 UIAXHarness 编排层（mktemp，trap 后 rm）
HARNESS_OUT="$(mktemp -d)"
trap 'rm -rf "${HARNESS_OUT}"; cleanup' EXIT
ARCH="$(uname -m)"
swiftc -O -swift-version 5 -target "${ARCH}-apple-macos14.0" \
  -import-objc-header "${FFI_H}" \
  "${FFI_SWIFT}" "${HARNESS_SRC}" \
  -L "${ROOT_DIR}/core/target/release" -lcf_ffi \
  -o "${HARNESS_OUT}/UIAXHarness" || { echo "ERROR  UIAXHarness 编译失败" >&2; exit 2; }
HARNESS="${HARNESS_OUT}/UIAXHarness"

# MARK: - PREFLIGHT（docs/19 §5.7 三检 + 锁定态门禁，fail-closed）

# PRE-01 AX 授权（TCC）
"${DRIVER}" trusted >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
  echo "ERROR  辅助功能 TCC 未授权：系统设置→隐私与安全性→辅助功能→勾选 UIAXDriver（docs/19 §5.4 固定路径锚点）"
  exit 5
fi
pass "TC-L3-PRE-01" "AX 辅助功能已授权（AXIsProcessTrusted）"

# PRE-02 屏幕锁定态门禁（docs/19 §5.7：frontmost=loginwindow + CGSSessionScreenIsLocked=true）
if ioreg -n Root -d1 -a 2>/dev/null | grep -q '"CGSSessionScreenIsLocked" = true'; then
  echo "ABORT  needs unlocked GUI session——macOS 屏幕已锁定，AX 树塌缩为 proxy 不可测；请解锁屏幕后重跑（预期行为非缺陷）"
  exit 6
fi
pass "TC-L3-PRE-02" "GUI 会话已解锁（CGSSessionScreenIsLocked != true）"

# MARK: - SETUP：建测试库 + 预置 defaults + 启动 App

terminate_app

echo "--- 建测试库（容器内路径，${TEST_DIR}）---"
rm -rf "${TEST_DIR}"
mkdir -p "$(dirname "${TEST_DIR}")"
CREATE_OUT="$(COFFER_TEST_PASSWORD="${PASSWORD}" "${HARNESS}" create "${TEST_DIR}")"
CREATE_RC=$?
echo "${CREATE_OUT}"
if [[ ${CREATE_RC} -ne 0 ]]; then
  echo "ERROR  建测试库失败（见上）" >&2
  exit 2
fi
VAULT_UUID="$(echo "${CREATE_OUT}" | awk -F'\t' '$1=="VAULTUUID"{print $2; exit}')"
[[ -n "${VAULT_UUID}" ]] || { echo "ERROR  未取到 VAULTUUID" >&2; exit 2; }
echo "测试库 uuid=${VAULT_UUID}"

defaults write "${BUNDLE_ID}" debugDisableTouchID -bool true
defaults write "${BUNDLE_ID}" coffer.testBaseDir -string "${TEST_DIR}"
defaults write "${BUNDLE_ID}" lastVaultUUID -string "${VAULT_UUID}"

echo "--- 启动 App ---"
open "${APP_PATH}"
if ! wait_for "Coffer 进程启动" 15 pgrep -x Coffer; then
  echo "ERROR  App 未启动" >&2
  exit 3
fi
if ! wait_for "AX 窗口出现" 20 "${DRIVER}" windows; then
  echo "ABORT  App 已启动但无 AX 窗口——可能 GUI 会话异常；重试或检查屏幕锁定态" >&2
  exit 6
fi

# PRE-03 目标窗口存在（kAXWindowsAttribute 含真实 AXWindow，非 proxy——窗口塌缩即锁定/异常信号）
if ! "${DRIVER}" windows 2>/dev/null | grep -q '^WINDOW' && "${DRIVER}" windows 2>/dev/null | grep -q 'AXWindow'; then
  echo "ERROR  目标窗口缺失/塌缩为 AXApplication proxy" >&2
  exit 6
fi
pass "TC-L3-PRE-03" "目标窗口存在（role=AXWindow）"

# PRE-04 content 元素非空 + 首启到达锁定态（LockView）。§5.7 第 3 检的意图是排除
# 窗口塌缩（零 content）；本 harness 首启目标恒为 LockView，其 SecureField 即为
# content 证据。窗口先于内容渲染、内容曝光依赖 App 前台（实测）——轮询内每次先激活
# 再查（open 已运行实例=activate），并取**双锚点**（占位 find 或结构性 AXSecureTextField
# role/subrole，同 W2-03 加固）。间歇 AX 曝光缝隙（W2-03 同款，11:20/11:32 两轮实证）
# 预算 60 轮；超时自诊断后 fail-closed：屏幕锁定/异常态。
LOCKVIEW_UP=0
for _ in $(seq 1 60); do
  open "${APP_PATH}" >/dev/null 2>&1
  sleep 1
  if "${DRIVER}" find "请输入主密码" >/dev/null 2>&1 \
     || "${DRIVER}" tree 2>/dev/null | awk -F'\t' '$3=="AXSecureTextField" || $4=="AXSecureTextField"{f=1} END{exit !f}'; then
    LOCKVIEW_UP=1; break
  fi
done
if (( LOCKVIEW_UP )); then
  pass "TC-L3-PRE-04" "主窗口 content 非空（首启锁定态 LockView 呈现）"
else
  APP_ALIVE=no; pgrep -x Coffer >/dev/null 2>&1 && APP_ALIVE=yes
  WIN_INFO="$("${DRIVER}" windows 2>/dev/null | grep '^WINDOW' | tr '\n' ';')"
  echo "ERROR  启动后未到锁定态（60 轮无 content；app 存活=${APP_ALIVE} 窗口=${WIN_INFO:-<none>}）——屏幕锁定/异常态（fail-closed）" >&2
  exit 6
fi
echo "--- 已到锁定态 ---"

# MARK: - TEST IT-01（E-1）：锁定态三处入口 disabled（D-10.3 不可达 + 可靠信号）

if "${DRIVER}" find "请输入主密码" >/dev/null 2>&1; then
  pass "TC-L3-IT01-01" "锁定态 LockView 呈现（AXSecureTextField + 解锁入口）"
else
  fail "TC-L3-IT01-01" "锁定态 LockView 呈现" "未找到「请输入主密码」"
fi

# 锁定态主界面结构性不可达：空态「导入已有密码…」不应在 AX 树（MainView 未渲染，D-10.3）
if "${DRIVER}" find "导入已有密码" >/dev/null 2>&1; then
  fail "TC-L3-IT01-02" "锁定态主界面入口不可达" "锁定态仍可寻「导入已有密码…」（MainView 泄漏）"
else
  pass "TC-L3-IT01-02" "锁定态主界面入口不可达（空态「导入已有密码…」absent）"
fi

# 锁定态「锁定 Coffer」disabled（可靠 phase 信号；数据 CommandMenu 项 AX enabled 恒 false 为已知 quirk，见 docs/18）
if "${DRIVER}" enabled "锁定 Coffer" 2>/dev/null | grep -q '^ENABLED	false'; then
  pass "TC-L3-IT01-03" "锁定态「锁定 Coffer」disabled（phase != .unlocked 可靠信号）"
else
  fail "TC-L3-IT01-03" "锁定态「锁定 Coffer」disabled" "ENABLED 非 false"
fi

# 锁定态数据菜单「从 macOS 密码 App…」结构性存在（菜单栏锚点；enabled 恒 false 为 SwiftUI CommandMenu AX quirk）
if "${DRIVER}" find "从 macOS 密码" >/dev/null 2>&1; then
  pass "TC-L3-IT01-04" "锁定态数据菜单「从 macOS 密码 App…」存在（结构性锚点）"
else
  fail "TC-L3-IT01-04" "锁定态数据菜单「从 macOS 密码 App…」存在" "未找到菜单项"
fi

# MARK: - TEST 解锁（type env 密码 + 解锁按钮 enabled false→true → press）

echo "--- 解锁 ---"
COFFER_TEST_PASSWORD="${PASSWORD}" "${DRIVER}" type "请输入主密码" >/dev/null 2>&1
sleep 1
if "${DRIVER}" enabled "解锁" 2>/dev/null | grep -q '^ENABLED	true'; then
  pass "TC-L3-UNL-01" "密码注入后「解锁」按钮 enabled false→true"
else
  fail "TC-L3-UNL-01" "密码注入后「解锁」按钮 enabled false→true" "ENABLED 非 true"
fi
"${DRIVER}" press "解锁" >/dev/null 2>&1
if ! wait_for "解锁后 LockView 消失（请输入主密码 absent）" 15 sh -c "! ${DRIVER} find '请输入主密码' >/dev/null 2>&1"; then
  fail "TC-L3-UNL-02" "解锁成功（LockView 消失）" "10s 内仍在锁定态"
else
  pass "TC-L3-UNL-02" "解锁成功（LockView 消失）"
fi
if ! wait_for "主窗口「全部条目」出现" 10 "${DRIVER}" find "全部条目"; then
  fail "TC-L3-UNL-03" "解锁后主界面「全部条目」" "未找到"
else
  pass "TC-L3-UNL-03" "解锁后主界面「全部条目」呈现"
fi

# MARK: - TEST IT-01（E-1）：解锁态入口可点

if "${DRIVER}" enabled "锁定 Coffer" 2>/dev/null | grep -q '^ENABLED	true'; then
  pass "TC-L3-IT01-05" "解锁态「锁定 Coffer」enabled（phase == .unlocked）"
else
  fail "TC-L3-IT01-05" "解锁态「锁定 Coffer」enabled" "ENABLED 非 true"
fi
if "${DRIVER}" find "导入已有密码" >/dev/null 2>&1; then
  pass "TC-L3-IT01-06" "解锁态空态「导入已有密码…」呈现（入口可达）"
else
  fail "TC-L3-IT01-06" "解锁态空态「导入已有密码…」呈现" "未找到"
fi

# 设置「设置放置区…」按钮可点 → 向导 S0 打开（AXPress 于 SwiftUI Button 有效；Menu/CommandMenu 项无效，已实证）
echo "--- 打开设置 + 向导 ---"
"${DRIVER}" press "设置" >/dev/null 2>&1
sleep 1
if ! "${DRIVER}" find "设置放置区" >/dev/null 2>&1; then
  fail "TC-L3-IT01-07" "解锁态设置窗「设置放置区…」可达" "未找到（设置窗未开？）"
else
  pass "TC-L3-IT01-07" "解锁态设置窗「设置放置区…」可达"
fi
"${DRIVER}" press "设置放置区" >/dev/null 2>&1
if wait_for "向导 S0 打开（从 macOS 密码 App 导入你的钥匙串密码）" 10 "${DRIVER}" find "从 macOS 密码 App 导入你的钥匙串密码"; then
  pass "TC-L3-IT01-08" "解锁态放置区入口可触发（向导 S0 打开）"
else
  fail "TC-L3-IT01-08" "解锁态放置区入口可触发（向导 S0 打开）" "向导未打开"
fi

# MARK: - TEST W-2（锁定停摆 fail-closed）：向导打开中锁库

echo "--- W-2：向导打开中锁库 ---"
# 前置：向导 S0 确在打开（IT01-08 之后）。激活 App 使主窗口前台——工具栏「锁定」
# 按钮只在主窗口可见/前台时暴露于 AX 树（settings 前台时 press 只命中惰性菜单项，
# 不触发锁），activate 后 press 才确定命中。
activate_app
"${DRIVER}" press "锁定" >/dev/null 2>&1
# 屏幕锁定护栏：锁定动作后若 OS 屏锁（「锁定屏幕」项被误触），检测并中止
if ioreg -n Root -d1 -a 2>/dev/null | grep -q '"CGSSessionScreenIsLocked" = true'; then
  echo "ERROR  W-2 锁定动作触发 OS 屏幕锁定，中止（需解锁后重跑）"
  exit 6
fi
if ! wait_for "向导 sheet 消失（S0 文案 absent）" 12 sh -c "! ${DRIVER} find '从 macOS 密码 App 导入你的钥匙串密码' >/dev/null 2>&1"; then
  fail "TC-L3-W2-01" "向导打开中锁库 → 向导 sheet 消失（fail-closed 拆树）" "S0 文案仍在"
else
  pass "TC-L3-W2-01" "向导打开中锁库 → 向导 sheet 消失（fail-closed 拆树）"
fi
if ! wait_for "设置窗关闭（P2-B）" 8 sh -c "! ${DRIVER} find '设置放置区' >/dev/null 2>&1"; then
  fail "TC-L3-W2-02" "锁库 → 设置窗关闭（phase 离 .unlocked 自关，P2-B）" "设置窗仍在"
else
  pass "TC-L3-W2-02" "锁库 → 设置窗关闭（phase 离 .unlocked 自关，P2-B）"
fi
# W2-03：锁库后窗口重建为 LockView。实测相变终态常 2-5s 内复现、间歇更久（lead 复跑
# 与本地复跑合计 4 次 60s+ 未现 AX 内容——冷启动 PRE-04 同款，自恢复非崩溃：若 App
# 崩溃，40 次 `open` 会重启新实例并呈 LockView，而未现即证 App 存活但 AX 未曝 LockView）。
# 双脆弱：① 窗口重建/内容曝光时间可变（间歇性，疑似瞬时 AX 曝光缝隙或主线程暂歇）；
# ② SecureField 占位「请输入主密码」只在 App 前台时曝光（frontmost 依赖）。
# 加固：轮询内**每次先激活再查**（open 已运行实例=activate）；**双锚点**任一命中即判
# LockView 复现——语义锚（占位 find）+ 结构性锚（AXSecureTextField，role 或 subrole；
# 元素存在不依赖前台占位曝光；锁定态独有——解锁态主内容无 SecureField，且 W2-01/02
# 已证向导/设置窗拆除，无其他 SecureField 源）；预算 60 轮（~2min+ 覆盖间歇曝光缝隙）。
# 超时自诊断（归因残留项）：报 App 存活/窗口枚举/App 进程响应——区分瞬时曝光缝隙
# （环境/测试侧，自恢复）与主线程暂歇（生产侧，需 coder 核）。登记 docs/18 §9。
LOCKVIEW_BACK=0
for _ in $(seq 1 60); do
  open "${APP_PATH}" >/dev/null 2>&1
  sleep 1
  if "${DRIVER}" find "请输入主密码" >/dev/null 2>&1 \
     || "${DRIVER}" tree 2>/dev/null | awk -F'\t' '$3=="AXSecureTextField" || $4=="AXSecureTextField"{f=1} END{exit !f}'; then
    LOCKVIEW_BACK=1; break
  fi
done
if (( LOCKVIEW_BACK )); then
  pass "TC-L3-W2-03" "锁库后 LockView 复现（真实 phase 相变）"
else
  APP_ALIVE=no; pgrep -x Coffer >/dev/null 2>&1 && APP_ALIVE=yes
  WIN_INFO="$("${DRIVER}" windows 2>/dev/null | grep '^WINDOW' | tr '\n' ';')"
  fail "TC-L3-W2-03" "锁库后 LockView 复现（真实 phase 相变）" "60 轮未到锁定态（app 存活=${APP_ALIVE} 窗口=${WIN_INFO:-<none>}）"
fi

# MARK: - 汇总

echo "--------------------------------------------------"
echo "结果：${ASSERT_PASS} passed / ${ASSERT_FAIL} failed"
if (( ASSERT_FAIL > 0 )); then
  for f in "${FAILURES[@]}"; do echo "  FAILED: ${f}"; done
  exit 1
fi
echo "ALL GREEN（L3 子集：IT-01 + W-2；S1-S5/S5 文案/IT-28 登记待做，docs/18 §5.x）"
