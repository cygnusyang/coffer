#!/usr/bin/env bash
# run_dropzone_j5_sample.sh —— J-5 真样采样探针（docs/19 §4.1 / docs/18 §6 RT-05）
#
# 定位：J-5 为发版门禁（未过则 P-2 列映射 provisional 不得发版）。本脚本在用户
# 一次 Touch ID 导出「所有密码」后，对放置区的真实导出 CSV 做**本地一次性**
# 采样，只出【非敏感】摘要：
#   - 列头快照（J-5 四核对项之一，docs/19 §4.2 列头非敏感）
#   - 数据行数（含/不含密码单元格计数——只计数，绝不打印密码值）
#   - 「导出所有密码」菜单名 / 默认文件名 / 重复导出命名 = 用户在导出瞬间观察，
#     脚本以 checklist 模板回显由用户填写（非从文件推导）
#
# R2 红线（硬性）：
#   - stdout/日志/对话里**永不出现密码值**；Password 列只统计非空单元格数；
#   - 输出落 .local-samples/j5-sample-<date>.txt（.gitignore:81 已忽略，不入库）；
#   - 真样文件本身永不入库、不复制、不移动（只读采样）。
#
# 用法：./tools/run_dropzone_j5_sample.sh [真实导出 CSV 路径]
#   路径缺省用环境变量 COFFER_J5_SAMPLE，再缺省查放置区默认名
#   （~/Downloads/coffer-import/密码.csv；2026-10-18 J-5 实样：默认名随系统
#   语言本地化，中文环境为 密码.csv）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SAMPLE="${1:-${COFFER_J5_SAMPLE:-${HOME}/Downloads/coffer-import/密码.csv}}"
if [[ ! -f "${SAMPLE}" ]]; then
  echo "ERROR: 真实导出不存在：${SAMPLE}" >&2
  echo "       请先在 Passwords.app 手动导出「所有密码」+ Touch ID 验证后，把文件路径作为参数传入。" >&2
  exit 2
fi
[[ -s "${SAMPLE}" ]] || { echo "ERROR: 导出为空：${SAMPLE}" >&2; exit 2; }

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${ROOT_DIR}/.local-samples"
OUT_FILE="${OUT_DIR}/j5-sample-${STAMP}.txt"
mkdir -p "${OUT_DIR}"

# 只读安全门禁：本脚本绝不修改真样（对照只读；不复制/移动/删除）。
# 列头快照（第一行，非敏感——J-5 四核对项之一）：
HEADER="$(head -n 1 "${SAMPLE}")"

# 密码列位置（从表头定位 Password 列；无则 -1）。列序号从 1 起（awk 字段序）。
PW_COL="$(echo "${HEADER}" | awk -F',' '{for(i=1;i<=NF;i++) if($i=="Password"){print i; exit}}')"
if [[ -z "${PW_COL}" ]]; then
  echo "WARN: 表头未找到 Password 列——采样仅记录列头与行数，密码计数跳过。" >&2
  PW_COL="-1"
fi

# 数据行数（减去表头；Passwords.app 导出为简单 CSV，行=记录，无内嵌换行——
# 若发现内嵌引号换行本计数偏大，属已知局限，仅在本地采样文本标注，不影响 J-5 列头核对）。
TOTAL_ROWS="$(( $(wc -l < "${SAMPLE}") - 1 ))"

# 密码单元格计数：第 PW_COL 列非空单元格数（awk 按逗号分列；密码含逗号时该行
# 计数值会偏——本地采样只求量级核对，J-5 核心是列头与命名，不打印值即可）。
PW_FILLED="$(tail -n +2 "${SAMPLE}" | awk -F',' -v c="${PW_COL}" 'c>0 && $c!="" {n++} END{print n+0}')"

cat > "${OUT_FILE}" <<EOF
# J-5 真样采样记录（${STAMP}）——本地一次性，gitignored，不入库
# 源文件：${SAMPLE}（仅只读采样，未复制/移动/删除）
# 采样人：用户本机（一次 Touch ID 导出）

## J-5 四核对项
# ① 列头快照（非敏感）：
${HEADER}
# ② 数据行数：${TOTAL_ROWS}
# ③ 密码列（Password）非空单元格数：${PW_FILLED}（只计数，值不落任何输出）
# ④ 导出瞬间观察（非从文件推导）；2026-10-18 实样已核销：
#    - 菜单名实样：「将所有密码导出至文件…」
#    - 默认文件名实样：密码.csv（随系统语言本地化）
#    - 重复导出实样：默认名不变，系统弹替换确认（不自动改名）

## P-2 provisional 锚定
# 本列头如与 tests/fixtures/csv/dropzone_passwords_headers.csv 不符 → 更新 fixture
# + 复核 dropzone.rs apply_header_aliases（docs/18 §8 采 (a)）→ 重跑 L2。
EOF

echo "=== J-5 采样摘要（非敏感）==="
echo "列头：${HEADER}"
echo "行数：${TOTAL_ROWS}"
echo "Password 列非空：${PW_FILLED}（只计数，不打印值）"
echo "完整记录（含四核对 checklist）：${OUT_FILE}"
