#!/bin/bash
# Coffer 合流前门禁四连（docs/14 §4 / docs/09 §4）
# 用法: ./tools/run_gate.sh [--skip-build]
# 输出: 全量日志落盘 /tmp/coffer-gate-<ts>.log，stdout 只给摘要
# 纪律: 在仓库根执行；各步独立检查退出码，规避管道吞退出码（假绿）
set -u
cd "$(dirname "$0")/.."
LOG="/tmp/coffer-gate-$(date +%H%M%S).log"
: > "$LOG"

CARGO="cargo"
command -v cargo >/dev/null 2>&1 || { [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"; CARGO="$HOME/.cargo/bin/cargo"; }

R_TEST=0; R_CLIPPY=0; R_BUILD=0; R_SIGN=0
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

run_step "cargo test --workspace" run_in_core $CARGO test --workspace --no-fail-fast; R_TEST=$?
run_step "cargo clippy" run_in_core $CARGO clippy --all-targets -- -D warnings; R_CLIPPY=$?

BUILD_SUM="SKIP"
if [ "${1:-}" != "--skip-build" ]; then
  run_step "build_macos_app" ./tools/build_macos_app.sh; R_BUILD=$?
  run_step "codesign" codesign --verify --strict macos/build/Coffer.app; R_SIGN=$?
  BUILD_SUM="build=$([ $R_BUILD -eq 0 ] && echo OK || echo FAIL) codesign=$([ $R_SIGN -eq 0 ] && echo OK || echo FAIL)"
fi

mark() { [ $1 -eq 0 ] && echo "OK" || echo "FAIL"; }
echo "----------------------------------------"
echo "test   : $(sum_test)（exit=$(mark $R_TEST)）"
echo "clippy : $(mark $R_CLIPPY)"
echo "build  : $BUILD_SUM"
echo "log    : $LOG"
if [ $((R_TEST + R_CLIPPY + R_BUILD + R_SIGN)) -eq 0 ]; then
  echo "GATE: ✅ 全绿"; exit 0
else
  echo "GATE: ❌ 有失败（详见 $LOG）"; exit 1
fi
