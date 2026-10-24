#!/usr/bin/env bash
# run_l10n_tests.sh —— 多语言基础设施测试入口（v2.13.0）。
#
# 两段，缺一不可：
#   1. Swift 纯逻辑单测（macos/Tests/LocalizationTests/main.swift + Support/
#      LanguagePreference.swift）：偏好读取优先级 / L1 回退链 / 原子往返。
#   2. 门禁夹具负向用例（fixtures/）：.strings 解析与占位符校验在 tools/check_l10n.sh
#      里（python3 实现，不进 Swift 侧重写一遍）。每类错误都必须 exit 非 0——
#      占位符写错在运行时**全部静默**（设计 F8），门禁报不出来等于没做。
#
# 用法：./tools/run_l10n_tests.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURES="${ROOT_DIR}/macos/Tests/LocalizationTests/fixtures"

FAILED=0
PASSED=0

pass() { PASSED=$((PASSED + 1)); printf 'PASS  %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf 'FAIL  %s\n' "$1"; }

command -v swiftc >/dev/null 2>&1 || { printf 'ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。\n' >&2; exit 1; }

# ---- 1. Swift 纯逻辑单测 ----
printf '== 1. Swift 纯逻辑单测（LanguagePreference）==\n'
ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

if swiftc -O -swift-version 5 -target "${ARCH}-apple-macos14.0" \
    "${ROOT_DIR}/macos/Coffer/Support/LanguagePreference.swift" \
    "${ROOT_DIR}/macos/Tests/LocalizationTests/main.swift" \
    -o "${OUT_DIR}/LocalizationTests"; then
  "${OUT_DIR}/LocalizationTests" || FAILED=$((FAILED + 1))
else
  fail "swiftc 编译 LocalizationTests"
fi

# ---- 2. 门禁夹具（负向用例必须红，正向用例必须绿）----
printf '\n== 2. check_l10n.sh 夹具用例 ==\n'

# expect_case <说明> <夹具目录> <期望退出码> <输出必须包含的片段>
expect_case() {
  local name="$1" dir="$2" want_rc="$3" want_msg="$4"
  local work out rc
  work="$(mktemp -d)"
  cp -R "${FIXTURES}/base/." "${work}/"
  cp -R "${FIXTURES}/${dir}/." "${work}/"

  if out="$(L10N_LOCALIZATION_DIR="${work}" "${SCRIPT_DIR}/check_l10n.sh" --resources-only 2>&1)"; then
    rc=0
  else
    rc=$?
  fi
  rm -rf "${work}"

  if [[ "${rc}" -ne "${want_rc}" ]]; then
    fail "${name}：期望 exit ${want_rc}，实得 ${rc}"
    printf '%s\n' "${out}" | sed 's/^/      /'
    return
  fi
  if [[ -n "${want_msg}" ]] && ! printf '%s' "${out}" | grep -q -- "${want_msg}"; then
    fail "${name}：exit ${rc} 正确但输出不含「${want_msg}」"
    printf '%s\n' "${out}" | sed 's/^/      /'
    return
  fi
  pass "${name}（exit ${rc}）"
}

expect_case "缺占位符必须失败"   missing-placeholder 1 "占位符数量不一致"
expect_case "多占位符必须失败"   extra-placeholder   1 "占位符数量不一致"
expect_case "类型不符必须失败（%d vs %lld）" type-mismatch 1 "占位符不匹配"
expect_case "重复键必须失败"     duplicate-key       1 "重复键"
expect_case "未转义 % 必须失败"  unescaped-percent   1 "未转义百分号"
expect_case "合法译文必须通过"   valid               0 "硬门禁全绿"
expect_case "缺 InfoPlist 相机文案必须失败" missing-camera 1 "NSCameraUsageDescription"

# ---- 3. 真实译表（仓库内 en 分片）必须通过 ----
printf '\n== 3. 仓库真实译表 ==\n'
if out="$("${SCRIPT_DIR}/check_l10n.sh" 2>&1)"; then
  pass "仓库译表通过全量门禁（G1–G5）"
else
  fail "仓库译表未通过全量门禁"
  printf '%s\n' "${out}" | sed 's/^/      /'
fi

# ---- 汇总 ----
printf -- '----\n'
printf '%d passed / %d failed\n' "${PASSED}" "${FAILED}"
if [[ "${FAILED}" -ne 0 ]]; then
  printf 'ALL RED\n'
  exit 1
fi
printf 'ALL GREEN\n'
