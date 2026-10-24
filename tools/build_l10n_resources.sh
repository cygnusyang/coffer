#!/usr/bin/env bash
# build_l10n_resources.sh —— 把译文源分片合并并装配进 .app（v2.13.0，设计 24 §4.4）。
#
# 为什么分片（设计 §4.3）：Localizable.strings 是单一表（SwiftUI 的 Text 没有指定
# table 的入口），产物必须一个文件；但**源**若也一个文件，四组实现会写同一个文件
# → 文件级冲突，文件范围互斥与「可并行」都成纸面承诺。故：源分片各写各的
# （文件级互斥成立），构建期按文件名序 cat 合并（产物可复现），跨片重复键由
# check_l10n.sh G2 硬失败暴露。产物 en.lproj/Localizable.strings **不入库**。
#
# 用法：
#   ./tools/build_l10n_resources.sh macos/build/Coffer.app
#
# 前置：目标 .app 的 Contents/Resources 已存在（build_macos_app.sh 3/4 已建）。
# 纪律：本脚本自身也跑一遍格式与重复键校验（调用 check_l10n.sh --resources-only），
# 独立调用时不会产出半残的译表——plutil -lint 不过的 .strings 会让整表静默失效
# （所有 key 回落中文，英文界面全中文且**无报错**，设计 G1）。
#
# 环境变量（与 check_l10n.sh 同源，供夹具测试覆盖）：
#   L10N_LOCALIZATION_DIR  默认 macos/Coffer/Resources/Localization
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
step() { printf '\n==> %s\n' "$1"; }

if [[ $# -ne 1 ]]; then
  die "用法: $0 <APP_DIR>（例: macos/build/Coffer.app）"
fi
APP_DIR="$1"
[[ -d "${APP_DIR}/Contents/Resources" ]] || die "目标的 Contents/Resources 不存在：${APP_DIR}/Contents/Resources（须先完成 bundle 组装）"

LOCALIZATION_DIR="${L10N_LOCALIZATION_DIR:-${ROOT_DIR}/macos/Coffer/Resources/Localization}"
EN_SRC_DIR="${LOCALIZATION_DIR}/en"
INFO_SRC="${LOCALIZATION_DIR}/InfoPlist.strings"
DEST_DIR="${APP_DIR}/Contents/Resources/en.lproj"

step "装配本地化资源（en.lproj，签名前）"

# ---- 1. 门禁：格式 / 重复键 / 占位符（调用同一套规则，不重复实现）----
L10N_LOCALIZATION_DIR="${LOCALIZATION_DIR}" "${SCRIPT_DIR}/check_l10n.sh" --resources-only \
  || die "本地化门禁失败（格式 / 重复键 / 占位符），未装配任何资源。"

# ---- 2. 合并：文件名序（bash 3.2 无 mapfile，用 glob 的字典序）----
SHARDS=()
for f in "${EN_SRC_DIR}"/*.strings; do
  [[ -e "$f" ]] || die "译文源分片目录为空：${EN_SRC_DIR}"
  SHARDS+=("$f")
done
[[ ${#SHARDS[@]} -gt 0 ]] || die "译文源分片目录为空：${EN_SRC_DIR}"

TMP_FILE="$(mktemp "${TMPDIR:-/tmp}/coffer-l10n.XXXXXX")"
trap 'rm -f "${TMP_FILE}"' EXIT
{
  printf '/* 本文件由 tools/build_l10n_resources.sh 生成，勿手改。\n'
  printf ' * 源：macos/Coffer/Resources/Localization/en/*.strings（按文件名序合并）。\n'
  printf ' * 键 = 中文原文；值 = 英文译文（设计 24 §4.3 / §4.6）。\n'
  printf ' */\n'
  first=1
  for f in "${SHARDS[@]}"; do
    if [[ ${first} -eq 1 ]]; then first=0; else printf '\n'; fi
    # 去掉分片自带的 BOM（若误存带 BOM，合并后会污染整个产物）
    sed '1s/^\xEF\xBB\xBF//' "$f"
    # 分片末尾没有换行时补一个，避免两条合并成一行（.strings 语法错）
    if [[ -n "$(tail -c 1 "$f")" ]]; then printf '\n'; fi
  done
} > "${TMP_FILE}"

# ---- 3. 产物格式校验（合并不是拼字符串就完事：语法错整表静默失效）----
plutil -lint "${TMP_FILE}" >/dev/null \
  || die "合并后的 Localizable.strings 未通过 plutil -lint（分片单独合法但合并结果非法）。"

# ---- 4. 落盘（先清旧目录：删分片后旧产物若残留，会留下已不存在的译文）----
[[ -e "${DEST_DIR}" ]] && rm -r "${DEST_DIR}"
mkdir -p "${DEST_DIR}"
cp "${TMP_FILE}" "${DEST_DIR}/Localizable.strings" || die "写入 en.lproj/Localizable.strings 失败。"
cp "${INFO_SRC}" "${DEST_DIR}/InfoPlist.strings" || die "拷贝 InfoPlist.strings 失败。"

ENTRY_COUNT="$(grep -c '^[[:space:]]*\"' "${DEST_DIR}/Localizable.strings" || true)"
printf '分片 %d 个 → %s\n' "${#SHARDS[@]}" "${DEST_DIR}/Localizable.strings"
printf '条目 %s 条（.strings 行计数，不含注释）\n' "${ENTRY_COUNT}"
