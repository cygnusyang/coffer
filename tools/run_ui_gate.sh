#!/usr/bin/env bash
# run_ui_gate.sh —— UI 测试自动化汇总门禁（L1 + L2 + L3，docs/19 §7.2 W4 交付）。
#
# 三层（docs/19 §2 分层设计）：
#   L1  模型面 RED→GREEN：run_dropzone_import_model_tests.sh（docs/19 §3.3）
#   L2  真样全链路回归：run_dropzone_l2_regression_tests.sh（docs/19 §4.4）
#   L3  AX 黑盒 harness：run_l3_ax_harness.sh（docs/19 §5.6，IT-01 + W-2 子集）
#
# 语义：
#   - 每段独立跑，逐段短摘要 + 退出码；**任一段红 → 整体 exit 1**（后续段仍执行，
#     汇总三段状态后判定，便于一次看清全部红点）；
#   - 全量日志 → /tmp/coffer-ui-gate/（每段 + 汇总），只回显短摘要；
#   - --skip-l3：跳过 L3（AX 依赖：辅助功能 TCC 授权 + 解锁 GUI 会话 + 成品 App +
#     固定测试密码；无该环境时 L3 段红，用本旗标剔除，不拉低 L1/L2 门禁口径）。
#
# R2 / 卫生：
#   - L3 测试密码只走 env COFFER_TEST_PASSWORD（本脚本透传，绝不落 argv/日志）；
#   - L1/L2 用 mktemp 临时库自清（各自 trap）；L3 自 trap 清理容器内测试目录 +
#     defaults 三键 + terminate App（run_l3_ax_harness.sh finally 语义）；
#   - 本脚本不触碰任何真实用户库。
#
# 注意：目标 bash 3.2（macOS 默认），**禁用关联数组**（bash 4+ 特性），
# 段注册用 case 分发（与仓内其余 gate 脚本一致）。
#
# 用法：
#   ./tools/run_ui_gate.sh [--skip-l3]     # COFFER_TEST_PASSWORD 缺省从 env 透传
#   退出码：0 全绿；1 有段红；2 L3 未 skip 且缺密码；127 段脚本缺失/不可执行。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

GATE_DIR="/tmp/coffer-ui-gate"
mkdir -p "${GATE_DIR}"
GATE_LOG="${GATE_DIR}/ui-gate-$(date +%Y%m%d-%H%M%S).log"
GATE_RUN_LOG="${GATE_DIR}/ui-gate-run.log"   # 固定名，供外层复查

SKIP_L3=0
for a in "$@"; do
  case "${a}" in
    --skip-l3) SKIP_L3=1 ;;
    -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "WARN  未知参数忽略：${a}（仅支持 --skip-l3）" >&2 ;;
  esac
done

# L3 密码透传门禁（R2：只走 env，透传给 L3，绝不写进任何日志文件）
if (( ! SKIP_L3 )) && [[ -z "${COFFER_TEST_PASSWORD:-}" ]]; then
  echo "ERROR  跑 L3 需 env COFFER_TEST_PASSWORD（R2：测试密码只走 env；或用 --skip-l3 剔除）" >&2
  exit 2
fi

# 段脚本路径（case 分发，规避 bash 3.2 无关联数组）
section_script() {
  case "$1" in
    L1) echo "${ROOT_DIR}/tools/run_dropzone_import_model_tests.sh" ;;
    L2) echo "${ROOT_DIR}/tools/run_dropzone_l2_regression_tests.sh" ;;
    L3) echo "${ROOT_DIR}/tools/run_l3_ax_harness.sh" ;;
    *) echo "" ;;
  esac
}

# 执行单段：0 绿；1 断言红；2-6 环境红（统一归红档）；127 缺失
run_section() {
  local name="$1" log="$2" script rc=0
  script="$(section_script "${name}")"
  [[ -n "${script}" && -x "${script}" ]] || { echo "MISSING  ${name} 段脚本缺失/不可执行：${script:-<unknown>}"; return 127; }
  if [[ "${name}" == "L3" ]]; then
    # L3 密码经 env 透传；--skip-l3 已在上游拦截
    COFFER_TEST_PASSWORD="${COFFER_TEST_PASSWORD}" "${script}" >"${log}" 2>&1
  else
    "${script}" >"${log}" 2>&1
  fi
}

run_section_gated() {
  local name="$1" log rc=0
  if [[ "${name}" == "L3" ]] && (( SKIP_L3 )); then
    echo "SKIP   L3 段（--skip-l3）"
    return 0
  fi
  log="${GATE_DIR}/${name}-$(date +%Y%m%d-%H%M%S).log"
  run_section "${name}" "${log}" || rc=$?
  case "${rc}" in
    0)   echo "PASS   [${name}] 绿（$(section_script "${name}" | sed 's#.*/##')）——日志 ${log}" ;;
    127) echo "FAIL   [${name}] MISSING（脚本缺失/不可执行）——日志 ${log}" ;;
    *)   echo "FAIL   [${name}] 红（exit ${rc}）——日志 ${log}" ;;
  esac
  return "${rc}"
}

echo "================ UI 测试自动化汇总门禁 ================"
echo "运行目录：${ROOT_DIR}"
echo "全量日志：${GATE_LOG}（各段独立日志亦在 ${GATE_DIR}/）"
[[ ${SKIP_L3} -eq 1 ]] && echo "L3 段：--skip-l3 跳过（AX 依赖环境缺省）"
echo "----------------------------------------------"

: > "${GATE_RUN_LOG}"
RC_L1=0; RC_L2=0; RC_L3=0
{
  echo "### L1 模型面（run_dropzone_import_model_tests.sh）"
  run_section_gated L1 || RC_L1=$?
} | tee -a "${GATE_RUN_LOG}"
{
  echo "### L2 真样全链路回归（run_dropzone_l2_regression_tests.sh）"
  run_section_gated L2 || RC_L2=$?
} | tee -a "${GATE_RUN_LOG}"
{
  echo "### L3 AX 黑盒 harness（run_l3_ax_harness.sh）"
  run_section_gated L3 || RC_L3=$?
} | tee -a "${GATE_RUN_LOG}"

# 摘要
echo "----------------------------------------------"
echo "结果摘要："
echo "  L1 模型面    : $([[ ${RC_L1} -eq 0 ]] && echo PASS || echo "FAIL (exit ${RC_L1})")"
echo "  L2 全链路    : $([[ ${RC_L2} -eq 0 ]] && echo PASS || echo "FAIL (exit ${RC_L2})")"
if (( SKIP_L3 )); then
  echo "  L3 AX 黑盒   : SKIP（--skip-l3）"
else
  echo "  L3 AX 黑盒   : $([[ ${RC_L3} -eq 0 ]] && echo PASS || echo "FAIL (exit ${RC_L3})")"
fi
echo "日志：${GATE_LOG}（运行记录 ${GATE_RUN_LOG}）"
cp "${GATE_RUN_LOG}" "${GATE_LOG}"

if [[ ${RC_L1} -eq 0 && ${RC_L2} -eq 0 && (${SKIP_L3} -eq 1 || ${RC_L3} -eq 0) ]]; then
  echo "UI GATE ALL GREEN"
  exit 0
fi
echo "UI GATE RED（见上各段退出码与日志）"
exit 1
