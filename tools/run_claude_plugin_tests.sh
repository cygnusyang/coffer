#!/usr/bin/env bash
# run_claude_plugin_tests.sh —— Claude Code 插件收编静态完整性测试
# （plugins/claude-code/ + 根级 .claude-plugin/marketplace.json，task-001 / Phase 2）。
#
# 被测对象为静态文件（清单 JSON / 脚本文本 / README / SKILL.md），无编译、无
# FFI、无网络，任何环境均可运行。唯一可选项：claude CLI 存在时追加
# `claude plugin validate --strict` 两项；不存在则输出 SKIP，不计 FAIL。
#
# 断言范围说明：`coffer-claude` / `/Users/cygnus` 残留检查仅限 plugins/claude-code/
# 目录——主仓 README 修订注记与 docs 追认表**故意**提及来源仓名，不在收编净度
# 断言范围内。
#
# 用法：./tools/run_claude_plugin_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PLUGIN_DIR="${ROOT_DIR}/plugins/claude-code"
PLUGIN_JSON="${PLUGIN_DIR}/.claude-plugin/plugin.json"
MARKETPLACE_JSON="${ROOT_DIR}/.claude-plugin/marketplace.json"
MAIN_README="${ROOT_DIR}/README.md"
PLUGIN_README="${PLUGIN_DIR}/README.md"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# MARK: - 断言与汇总（对齐 macos/Tests/*/main.swift 惯例）

pass_count=0
fail_count=0
skip_count=0
failures=()

check() {
  # check <用例名> <命令...>：命令退出 0 即 PASS
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    pass_count=$((pass_count + 1))
    echo "PASS  ${name}"
  else
    fail_count=$((fail_count + 1))
    failures+=("${name}")
    echo "FAIL  ${name}"
  fi
}

# MARK: - 辅助函数

# json_get <file> <python 表达式（顶层对象为 d）>：解析失败/取值失败打印哨兵值
json_get() {
  python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)
try:
    v = eval(sys.argv[2], {"d": d})
    print(v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
except Exception:
    print("__PARSE_ERROR__")
' "$1" "$2" 2>/dev/null || echo "__PARSE_ERROR__"
}

# json_eq <file> <表达式> <期望值>
json_eq() {
  [[ "$(json_get "$1" "$2")" == "$3" ]]
}

# frontmatter_has <file>：首部 frontmatter 同时含 name: 与 description:
frontmatter_has() {
  local f="$1"
  [[ "$(head -n 1 "${f}")" == "---" ]] || return 1
  local fm
  fm="$(awk 'NR==1{next} /^---[[:space:]]*$/{exit} {print}' "${f}")"
  grep -q '^name:' <<<"${fm}" && grep -q '^description:' <<<"${fm}"
}

# no_residue：plugins/claude-code/ 无来源仓名与本机绝对路径残留
no_residue() {
  ! grep -rn -e 'coffer-claude' -e '/Users/cygnus' "${PLUGIN_DIR}"
}

# MARK: - 1. 结构完整性

required_files=(
  ".claude-plugin/plugin.json"
  "bin/coffer-login"
  "bin/coffer-setup"
  "scripts/coffer-launch.sh"
  "scripts/coffer-login.mjs"
  "scripts/coffer-mcp-setup.sh"
  "skills/coffer-credentials/SKILL.md"
  "skills/coffer-setup/SKILL.md"
  "README.md"
)
for rel in "${required_files[@]}"; do
  check "结构：plugins/claude-code/${rel} 存在" test -f "${PLUGIN_DIR}/${rel}"
done
check "结构：.claude-plugin/marketplace.json（仓库根级市场清单）存在" \
  test -f "${MARKETPLACE_JSON}"

# MARK: - 2. 可执行位

check "可执行位：bin/coffer-login" test -x "${PLUGIN_DIR}/bin/coffer-login"
check "可执行位：bin/coffer-setup" test -x "${PLUGIN_DIR}/bin/coffer-setup"
check "可执行位：scripts/coffer-launch.sh" test -x "${PLUGIN_DIR}/scripts/coffer-launch.sh"

# MARK: - 3. plugin.json 合法性

check "plugin.json：JSON 可解析（${PLUGIN_JSON}）" \
  json_eq "${PLUGIN_JSON}" 'd["name"]' "coffer"
check "plugin.json：license == AGPL-3.0" \
  json_eq "${PLUGIN_JSON}" 'd["license"]' "AGPL-3.0"
check "plugin.json：homepage == https://github.com/cygnusyang/coffer" \
  json_eq "${PLUGIN_JSON}" 'd["homepage"]' "https://github.com/cygnusyang/coffer"
check "plugin.json：repository == https://github.com/cygnusyang/coffer" \
  json_eq "${PLUGIN_JSON}" 'd["repository"]' "https://github.com/cygnusyang/coffer"
check "plugin.json：mcpServers.coffer.command == \${CLAUDE_PLUGIN_ROOT}/scripts/coffer-launch.sh" \
  json_eq "${PLUGIN_JSON}" 'd["mcpServers"]["coffer"]["command"]' '${CLAUDE_PLUGIN_ROOT}/scripts/coffer-launch.sh'

# MARK: - 4. 根级 marketplace.json

check "marketplace.json：JSON 可解析（${MARKETPLACE_JSON}）" \
  json_eq "${MARKETPLACE_JSON}" 'd["name"]' "coffer"
check "marketplace.json：plugins[0].name == coffer" \
  json_eq "${MARKETPLACE_JSON}" 'd["plugins"][0]["name"]' "coffer"
check "marketplace.json：plugins[0].source == ./plugins/claude-code" \
  json_eq "${MARKETPLACE_JSON}" 'd["plugins"][0]["source"]' "./plugins/claude-code"

# MARK: - 5. 收编净度（仅限 plugins/claude-code/）

check "收编净度：plugins/claude-code/ 无 coffer-claude 与 /Users/cygnus 残留" no_residue

# MARK: - 6. setup 脚本修复点

check "coffer-mcp-setup.sh：remove 行带 --scope user" \
  grep -Fq "claude mcp remove coffer --scope user" "${PLUGIN_DIR}/scripts/coffer-mcp-setup.sh"
check "coffer-mcp-setup.sh：add 行带 --scope user" \
  grep -Fq "claude mcp add coffer --scope user" "${PLUGIN_DIR}/scripts/coffer-mcp-setup.sh"

# MARK: - 7. 安装命令一致性

check "插件 README：含 marketplace add cygnusyang/coffer" \
  grep -Fq "claude plugin marketplace add cygnusyang/coffer" "${PLUGIN_README}"
check "插件 README：含 install coffer@coffer" \
  grep -Fq "claude plugin install coffer@coffer" "${PLUGIN_README}"
check "主仓 README：含 marketplace add cygnusyang/coffer" \
  grep -Fq "claude plugin marketplace add cygnusyang/coffer" "${MAIN_README}"
check "主仓 README：含 install coffer@coffer" \
  grep -Fq "claude plugin install coffer@coffer" "${MAIN_README}"

# MARK: - 8. SKILL.md frontmatter

check "SKILL.md（coffer-credentials）：frontmatter 含 name: 与 description:" \
  frontmatter_has "${PLUGIN_DIR}/skills/coffer-credentials/SKILL.md"
check "SKILL.md（coffer-setup）：frontmatter 含 name: 与 description:" \
  frontmatter_has "${PLUGIN_DIR}/skills/coffer-setup/SKILL.md"

# MARK: - 9. 语法检查

check "语法：sh -n 两个 .sh" \
  sh -n "${PLUGIN_DIR}/scripts/coffer-launch.sh" "${PLUGIN_DIR}/scripts/coffer-mcp-setup.sh"
check "语法：bash -n bin/coffer-setup" \
  bash -n "${PLUGIN_DIR}/bin/coffer-setup"
check "语法：node --check coffer-login.mjs" \
  node --check "${PLUGIN_DIR}/scripts/coffer-login.mjs"

# MARK: - 10. claude CLI 校验（有条件执行，缺失则 SKIP 不判 FAIL）

if command -v claude >/dev/null 2>&1; then
  check "claude CLI：plugin validate --strict plugins/claude-code" \
    claude plugin validate --strict "${PLUGIN_DIR}"
  check "claude CLI：plugin validate --strict 仓库根（marketplace）" \
    claude plugin validate --strict "${ROOT_DIR}"
else
  skip_count=2
  echo "SKIP  claude CLI 未安装，跳过 plugin validate --strict（插件目录 + 仓库根，共 2 项）"
fi

# MARK: - 汇总

echo "--------------------------------------------------"
echo "结果：${pass_count} passed / ${fail_count} failed${skip_count:+（SKIP ${skip_count}，不计 FAIL）}"
if (( fail_count > 0 )); then
  printf '  FAILED: %s\n' "${failures[@]}"
  exit 1
fi
echo "ALL GREEN"
