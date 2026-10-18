#!/bin/bash
# Coffer 合流前门禁四连（docs/14 §4 / docs/09 §4）
#
# 用法:
#   ./tools/run_gate.sh                     # 全量门禁（发版节点用）
#   ./tools/run_gate.sh --changed [BASE]    # 增量门禁（开发期用）：只跑受影响的 crate
#   ./tools/run_gate.sh --skip-build        # 跳过构建/签名（可与上两者组合）
#   ./tools/run_gate.sh --print-crates      # 打印增量模式会选的 crate（调试用）
#
# 增量口径：改动文件 → 所属 crate → 其**反向依赖闭包**（依赖它的 crate 一并跑），
# 避免跨 crate 隐式耦合漏测。
# - 仅文档/工具改动：改跑文档事实核查，摘要显式标注「未跑测试/构建」
# - 非 crate 的代码改动（macos/**、core 顶层配置等）：回退全量，不静默跳过
# - crate 选择工具故障（cargo metadata / python3 不可用）：回退全量并告警，绝不折算成通过
# BASE 缺省为 `git merge-base HEAD origin/main`，取不到则用 HEAD（只含工作树改动）。
#
# 输出: 全量日志落盘 /tmp/coffer-gate-<ts>-<pid>.log，stdout 只给摘要
# 纪律: 在仓库根执行；各步独立检查退出码，规避管道吞退出码（假绿）
set -u
cd "$(dirname "$0")/.."
LOG="/tmp/coffer-gate-$(date +%H%M%S)-$$.log"
: > "$LOG"
START_TS="$(date +%s)"

CARGO="cargo"
command -v cargo >/dev/null 2>&1 || { [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"; CARGO="$HOME/.cargo/bin/cargo"; }

SKIP_BUILD=0
CHANGED=0
PRINT_CRATES=0
BASE=""
for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --changed) CHANGED=1 ;;
    --print-crates) CHANGED=1; PRINT_CRATES=1 ;;
    -*) echo "未知参数：$arg" >&2; exit 2 ;;
    *) BASE="$arg" ;;
  esac
done

R_TEST=0; R_CLIPPY=0; R_BUILD=0; R_SIGN=0
R_DOCS=0
TEST_SUM="SKIP"; CLIPPY_SUM="SKIP"; DOCS_SUM="SKIP"
run_step() { # run_step <名> <命令...>；退出码回传
  local name="$1"; shift
  echo "==> $name" >> "$LOG"
  "$@" >> "$LOG" 2>&1
  return $?
}

sum_test() {
  grep -E "^test result" "$LOG" | sed -E 's/.*ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored.*/\1 \2 \3/' \
    | awk '{p+=$1; f+=$2; i+=$3} END {print p" passed / "f" failed / "i" ignored"}'
}

# 注意：cargo 门禁须在 core/ 下跑（仓库根无 Cargo.toml，实跑直接报错——docs/14 教训）；
# build/codesign 以仓库根为基准。
run_in_core() { (cd core && "$@"); return $?; }

# ---- 增量：变更集与受影响 crate ----
CHANGED_FILES=""
if [ "$CHANGED" -eq 1 ]; then
  if [ -z "$BASE" ]; then
    BASE="$(git merge-base HEAD origin/main 2>/dev/null || true)"
    [ -z "$BASE" ] && BASE="HEAD"
  fi
  if ! git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null; then
    echo "GATE: ❌ 基线不可解析：${BASE}" >&2
    exit 2
  fi
  CHANGED_FILES="$(mktemp)"
  trap 'rm -f "$CHANGED_FILES"' EXIT
  if ! git diff --name-only "$BASE" > "$CHANGED_FILES" 2>>"$LOG" \
     || ! git ls-files --others --exclude-standard >> "$CHANGED_FILES" 2>>"$LOG" \
     || ! sort -u -o "$CHANGED_FILES" "$CHANGED_FILES"; then
    echo "GATE: ❌ 变更集收集失败（BASE=${BASE}），详见 ${LOG}" >&2
    exit 2
  fi
fi

# 输出空格分隔包名；空串 = 确无 crate 归属变更；__FAIL__ = 工具故障（调用方回退全量）
select_crates() {
  local meta out rc
  meta="$(mktemp)"
  if ! (cd core && "$CARGO" metadata --no-deps --format-version 1) > "$meta" 2>>"$LOG"; then
    rm -f "$meta"
    echo "__FAIL__"
    return 0
  fi
  out="$(python3 - "$meta" "$CHANGED_FILES" "$(pwd)" 2>>"$LOG" <<'PY'
import json, os, sys
meta_path, changed_path, root = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    meta = json.load(open(meta_path))
except Exception as e:
    print(f"crates-select: 解析 cargo metadata 失败: {e}", file=sys.stderr)
    print("__FAIL__")
    sys.exit(0)
packages = meta.get("packages", [])
dir_of = {}
for p in packages:
    # cargo metadata 输出的 manifest_path 已是绝对路径
    dir_of[os.path.dirname(os.path.abspath(p["manifest_path"]))] = p["name"]
changed = [os.path.abspath(os.path.join(root, line.strip()))
           for line in open(changed_path) if line.strip()]
direct = set()
for d, name in dir_of.items():
    prefix = d + os.sep
    if any(c == d or c.startswith(prefix) for c in changed):
        direct.add(name)
if not direct:
    print("")
    sys.exit(0)
# 反向依赖闭包：谁依赖我，谁也要跑
deps = {p["name"]: {d["name"] for d in p.get("dependencies", [])} for p in packages}
internal = set(deps)
for name in deps:
    deps[name] &= internal
closure = set(direct)
changed_flag = True
while changed_flag:
    changed_flag = False
    for name, ds in deps.items():
        if name not in closure and ds & closure:
            closure.add(name)
            changed_flag = True
print(" ".join(sorted(closure)))
PY
)"
  rc=$?
  rm -f "$meta"
  if [ $rc -ne 0 ] || [ -z "$out" ]; then
    [ $rc -ne 0 ] && echo "__FAIL__" || echo ""
    return 0
  fi
  echo "$out"
}

# 仅文档/工具改动 → 文档核查；其余非 crate 改动 → 回退全量
only_docs=1
if [ "$CHANGED" -eq 1 ]; then
  while IFS= read -r f; do
    case "$f" in
      docs/*|*.md|.github/*|.gitlab-ci.yml|.gitlab/*|CHANGELOG*|tools/*|LICENSE*|.gitignore|.gitattributes|\
      .codex/*|.omc/*|.playwright-mcp/*|.claude/*|.vscode/*) ;;
      *) only_docs=0; break ;;
    esac
  done < "$CHANGED_FILES"
fi

CRATE_ARGS=""
run_full=0
DOCS_ONLY=0
MODE="全量"

if [ "$PRINT_CRATES" -eq 1 ]; then
  CRATE_ARGS="$(select_crates)"
  if [ "$CRATE_ARGS" = "__FAIL__" ]; then
    echo "❌ crate 选择失败（详见 ${LOG}）" >&2
    exit 2
  fi
  echo "${CRATE_ARGS:-（无 crate 变更）}"
  exit 0
fi

if [ "$CHANGED" -eq 1 ]; then
  CRATE_ARGS="$(select_crates)"
  if [ "$CRATE_ARGS" = "__FAIL__" ]; then
    echo "==> 增量：crate 选择失败，回退全量门禁（详见 ${LOG}）" | tee -a "$LOG"
    CRATE_ARGS=""
    run_full=1
    MODE="全量（crate 选择失败回退）"
  elif [ -z "$CRATE_ARGS" ] && [ "$only_docs" -eq 1 ]; then
    echo "==> 增量模式（BASE=${BASE}）：仅文档/工具改动，改跑文档事实核查" | tee -a "$LOG"
    run_step "check_docs_facts" ./tools/check_docs_facts.sh
    R_DOCS=$?
    DOCS_SUM=$([ $R_DOCS -eq 0 ] && echo OK || echo FAIL)
    SKIP_BUILD=1
    DOCS_ONLY=1
    MODE="增量（仅文档/工具，未跑测试/构建）"
  elif [ -z "$CRATE_ARGS" ]; then
    echo "==> 增量：存在非 crate 代码改动，回退全量门禁" | tee -a "$LOG"
    run_full=1
    MODE="全量（非 crate 代码变更回退）"
  else
    echo "==> 增量模式（BASE=${BASE}）：受影响 crate = ${CRATE_ARGS}" | tee -a "$LOG"
    # shellcheck disable=SC2086
    PKG_ARGS=""
    for p in $CRATE_ARGS; do PKG_ARGS="$PKG_ARGS -p $p"; done
    run_step "cargo test --workspace" run_in_core $CARGO test $PKG_ARGS --no-fail-fast; R_TEST=$?
    TEST_SUM="$(sum_test)"
    run_step "cargo clippy" run_in_core $CARGO clippy $PKG_ARGS --all-targets -- -D warnings; R_CLIPPY=$?
    CLIPPY_SUM=$([ $R_CLIPPY -eq 0 ] && echo OK || echo FAIL)
    MODE="增量（受影响 crate：$(echo $CRATE_ARGS | wc -w | tr -d ' ') 个）"
  fi
else
  run_full=1
fi

if [ "$run_full" -eq 1 ]; then
  run_step "cargo test --workspace" run_in_core $CARGO test --workspace --no-fail-fast; R_TEST=$?
  TEST_SUM="$(sum_test)"
  run_step "cargo clippy" run_in_core $CARGO clippy --all-targets -- -D warnings; R_CLIPPY=$?
  CLIPPY_SUM=$([ $R_CLIPPY -eq 0 ] && echo OK || echo FAIL)
fi

BUILD_SUM="SKIP"
if [ "$SKIP_BUILD" -eq 0 ]; then
  run_step "build_macos_app" ./tools/build_macos_app.sh; R_BUILD=$?
  run_step "codesign" codesign --verify --strict macos/build/Coffer.app; R_SIGN=$?
  BUILD_SUM="build=$([ $R_BUILD -eq 0 ] && echo OK || echo FAIL) codesign=$([ $R_SIGN -eq 0 ] && echo OK || echo FAIL)"
fi

mark() { [ $1 -eq 0 ] && echo "OK" || echo "FAIL"; }
ELAPSED=$(( $(date +%s) - START_TS ))
echo "----------------------------------------"
echo "mode   : ${MODE}"
[ "$CHANGED" -eq 1 ] && echo "base   : ${BASE}"
[ "$DOCS_SUM" != "SKIP" ] && echo "docs   : ${DOCS_SUM}"
echo "test   : ${TEST_SUM:-SKIP}（exit=$([ "$TEST_SUM" = "SKIP" ] && echo SKIP || mark $R_TEST)）"
echo "clippy : ${CLIPPY_SUM}"
echo "build  : ${BUILD_SUM}"
echo "耗时   : ${ELAPSED}s"
echo "log    : $LOG"
if [ $((R_TEST + R_CLIPPY + R_BUILD + R_SIGN + R_DOCS)) -eq 0 ]; then
  if [ "$DOCS_ONLY" -eq 1 ]; then
    echo "GATE: ✅ 文档核查通过（本次未跑测试/构建）"
  else
    echo "GATE: ✅ 全绿"
  fi
  exit 0
else
  echo "GATE: ❌ 有失败（详见 ${LOG} ）"; exit 1
fi
