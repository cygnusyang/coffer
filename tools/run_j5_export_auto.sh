#!/usr/bin/env bash
# run_j5_export_auto.sh —— J-5 导出流程自动驱动（Passwords.app → 放置区 CSV）
# 固化版（docs/04-测试与验收/18-v2.11.0验收判据骨架.md §6 RT-05，2026-10-18 实证）。
#
# 定位：把「Passwords.app 导出所有密码」这条原本纯手工的真机探针拆成
# **AX 自动驱动 + 单点人工 Touch ID**：
#   - 菜单「文件 → 将所有密码导出至文件…」与警告 sheet「导出密码…」由
#     UIAXDriver 经 AX 树自动点击（目标进程用 --pid 指向 Passwords）
#   - 系统认证弹窗（LocalAuthenticationRemoteService）**只留 Touch ID 一次**
#     给用户——这是物理授权环节，无法也不应自动化
#   - 之后的保存面板是进程外 XPC 组件（com.apple.appkit.xpc.openAndSavePanelService），
#     不经 App AX 树、AX 不可达；用 CGEvent 键盘注入按 Return 以默认名落盘
#     （⌘⇧G 会落进面板文件名输入框，2026-10-18 实测，勿再尝试路径导航）
#   - 重名导出弹**替换确认**（不自动改名）；本脚本按 Escape 取消，不覆盖既有文件
#
# 输出纪律（R2 红线）：只打印列头行与行数；**绝不读取/打印任何数据行**。
# 采样落盘沿用 tools/run_dropzone_j5_sample.sh --header-only 口径（可选串联）。
# 导出文件默认**用后即删**；--keep 保留并提示用户自行处置。
#
# 用法：./tools/run_j5_export_auto.sh [--out-dir 目录] [--keep] [--timeout 秒]
#   前置：Passwords.app 可启动、Touch ID 可用、AX 已授权（系统设置→隐私与安全性
#         →辅助功能），macos/build/axdriver/UIAXDriver 已构建。
#   退出码：0 成功；2 环境错误；4 等待 Touch ID 超时；5 保存面板未出现/未落盘；
#          6 重名确认（未覆盖，用户需先处置同名文件）。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DRIVER="${ROOT_DIR}/macos/build/axdriver/UIAXDriver"
OUT_DIR="${HOME}/Downloads"
KEEP=0
TIMEOUT=180

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --keep)    KEEP=1; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    *) echo "ERROR: 未知参数 $1" >&2; exit 2 ;;
  esac
done

[[ -x "${DRIVER}" ]] || { echo "ERROR: UIAXDriver 缺失：${DRIVER}" >&2; exit 2; }

SAY() { printf '\n>>> %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 2; }

# ---- 0. 启动/激活 Passwords.app ----
osascript -e 'tell application "Passwords" to activate' 2>/dev/null || \
  open -a Passwords || die "无法启动 Passwords.app"
PW_PID=""
for i in $(seq 1 20); do
  PW_PID="$(pgrep -x Passwords | head -1)"
  [[ -n "${PW_PID}" ]] && break
  sleep 1
done
[[ -n "${PW_PID}" ]] || die "Passwords.app 未运行"
sleep 2
D() { "${DRIVER}" "$@"; }

# ---- 1. 文件菜单 → 将所有密码导出至文件… ----
SAY "打开「文件」菜单"
D --pid "${PW_PID}" press "文件" >/dev/null 2>&1 || die "无法点击「文件」菜单（AX 未授权？）"
sleep 1
D --pid "${PW_PID}" press "将所有密码导出至文件…" >/dev/null 2>&1 || \
  die "未找到菜单项「将所有密码导出至文件…」（系统版本菜单名变化？）"

# ---- 2. 警告 sheet → 导出密码… ----
SAY "确认导出警告 sheet"
OK=0
for i in $(seq 1 15); do
  D --pid "${PW_PID}" find "导出密码…" >/dev/null 2>&1 && { OK=1; break; }
  sleep 1
done
[[ "${OK}" -eq 1 ]] || die "导出确认 sheet 未出现"
D --pid "${PW_PID}" press "导出密码…" >/dev/null 2>&1

# ---- 3. 等待用户 Touch ID（唯一人工点）----
SAY "请按 Touch ID 完成系统认证（${TIMEOUT}s 超时）"
PANEL_BEFORE="$(pgrep -f openAndSavePanelService | wc -l | tr -d ' ')"
WAITED=0
PANEL_READY=0
while [[ "${WAITED}" -lt "${TIMEOUT}" ]]; do
  PANEL_NOW="$(pgrep -f openAndSavePanelService | wc -l | tr -d ' ')"
  if [[ "${PANEL_NOW}" -gt "${PANEL_BEFORE}" ]]; then PANEL_READY=1; break; fi
  sleep 2; WAITED=$((WAITED + 2))
done
if [[ "${PANEL_READY}" -eq 0 ]]; then
  echo "TIMEOUT: 未检测到保存面板（Touch ID 未完成或认证被取消）" >&2
  exit 4
fi
sleep 2

# ---- 4. 保存面板：键盘 Return 以默认名落盘（面板为 XPC 进程外，AX 不可达）----
SAY "保存面板出现，Return 以默认名保存"
D key "Return" >/dev/null 2>&1
sleep 3

# 重名：系统会弹替换确认；Escape 两次取消而非覆盖（不破坏既有文件）。
if D --pid "${PW_PID}" find "替换" >/dev/null 2>&1 || \
   D find "替换" >/dev/null 2>&1; then
  SAY "检测到重名替换确认 → 取消（不覆盖既有文件）"
  D key "Escape" >/dev/null 2>&1; sleep 1; D key "Escape" >/dev/null 2>&1
  echo "NOTE: 目标目录已有同名导出；请先移走/删除后重跑。" >&2
  exit 6
fi

# ---- 5. 定位落盘文件（默认名随系统语言本地化，中文=密码.csv）----
# 只认 5 分钟内新出现的「*密码*.csv / Passwords*.csv」，不猜固定路径。
NEW_CSV=""
for i in $(seq 1 15); do
  NEW_CSV="$(find "${OUT_DIR}" -maxdepth 3 -type f \( -name '密码*.csv' -o -name 'Passwords*.csv' \) \
             -mmin -5 2>/dev/null | head -1)"
  [[ -n "${NEW_CSV}" ]] && break
  sleep 1
done
[[ -n "${NEW_CSV}" ]] || { echo "FAIL: 未在 ${OUT_DIR} 找到新导出 CSV" >&2; exit 5; }

# ---- 6. 只读列头 + 行数（R2：绝不触碰数据行内容）----
HEADER="$(head -n 1 "${NEW_CSV}")"
ROWS="$(( $(wc -l < "${NEW_CSV}") - 1 ))"
echo
echo "=== J-5 导出摘要（非敏感）==="
echo "文件：${NEW_CSV}"
echo "列头：${HEADER}"
echo "数据行数：${ROWS}（不读取行内容）"

if [[ "${KEEP}" -eq 1 ]]; then
  echo "保留导出文件：${NEW_CSV}（请自行处置，勿粘贴任何数据行）"
else
  rm -f "${NEW_CSV}"
  echo "已删除导出文件（R2 卫生）"
fi
echo "=== DONE ==="
