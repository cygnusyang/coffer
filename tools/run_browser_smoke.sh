#!/usr/bin/env bash
# run_browser_smoke.sh —— v2.3.0 浏览器链验收冒烟（docs/32 §1.6 G-T）。
#
# 构建 `coffer` bin + cf-browser lib → 编译并运行 `tests/acceptance_browser.rs`
# （独立二进制，rustc 链 cf-browser rlib）→ 断言：
#   - ② 层外门禁 fail-closed：browser-agent（非签名父进程）→ 8001，先于接触 broker；
#   - 真 E2E：解锁态 get_entries 往返（fixture 逐字段）+ 锁态 get_secret → broker_locked
#     + lock 干净退出 0；
#   - 明文不泄：我写入链路的协议行（握手 hex / 密文帧）不落 broker 日志，origin 明文不落日志。
#
# 诚实边界（docs/32 §7）：真 `扩展→browser-agent→UDS→broker` 全链须真签名浏览器父进程
# （② 层无 env 跳过 seam）→ 真机清单项（docs/32 §2-2）；broker vault 接线前的 8005/8007/
# capture_save 判据为 merge-time 挂起项。本冒烟只断言 G-B 版 broker 可达的验收面。
#
# 自包含：在仓库根执行，内部 cd 到 core/ 构建；日志落盘 /tmp/coffer-browser-smoke-<ts>.log
# （stdout 只给摘要）。
#
# 用法：./tools/run_browser_smoke.sh [--product <Coffer.app 路径>]
#   --product：指向 G-E 装配产物 Coffer.app，则用嵌套 bundle 内 coffer 二进制
#              （Contents/Helpers/coffer.app/Contents/MacOS/coffer）；缺省用 core/debug。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORE_DIR="${ROOT_DIR}/core"

LOG="/tmp/coffer-browser-smoke-$(date +%Y%m%d-%H%M%S).log"
: > "$LOG"

# cargo 定位（非交互 shell 的 PATH 无 cargo，docs 教训）
CARGO="cargo"
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  CARGO="$HOME/.cargo/bin/cargo"
fi

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
fail() { say "ERROR: $*"; exit 1; }

# ---- 解析 --product（可选）----
PRODUCT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --product)
      [ $# -ge 2 ] || fail "--product 缺路径"
      PRODUCT="$2"; shift 2
      ;;
    *) fail "未知参数: $1（支持 --product <Coffer.app>）" ;;
  esac
done

# ---- 定位 coffer 二进制 ----
if [ -n "${PRODUCT}" ]; then
  COFFER_BIN="${PRODUCT}/Contents/Helpers/coffer.app/Contents/MacOS/coffer"
  say "==> 使用 G-E 装配产物：${COFFER_BIN}"
  [ -x "${COFFER_BIN}" ] || fail "产物 coffer 二进制不可执行：${COFFER_BIN}"
else
  COFFER_BIN="${CORE_DIR}/target/debug/coffer"
  say "==> build coffer bin（debug）"
  ( cd "${CORE_DIR}" && "${CARGO}" build -p cf-mcp --bin coffer --offline ) >> "$LOG" 2>&1 \
    || fail "cargo build 失败（详见 ${LOG}）"
  [ -x "${COFFER_BIN}" ] || fail "coffer 二进制未构建：${COFFER_BIN}"
fi

# ---- 构建 cf-browser lib（acceptance 链接用 rlib）----
( cd "${CORE_DIR}" && "${CARGO}" build -p cf-browser --offline ) >> "$LOG" 2>&1 \
  || fail "cargo build -p cf-browser 失败（详见 ${LOG}）"

# 直接依赖 rlib（mtime 最新 = 最近一次一致构建产物）
newest_rlib() { # $1 = crate 名（libNAME-*.rlib 的 NAME）
  ls -t "${CORE_DIR}"/target/debug/deps/lib"$1"-*.rlib 2>/dev/null | head -1
}
CF_BROWSER_RLIB="$(newest_rlib cf_browser)"
SERDE_JSON_RLIB="$(newest_rlib serde_json)"
[ -n "${CF_BROWSER_RLIB}" ] && [ -n "${SERDE_JSON_RLIB}" ] \
  || fail "cf-browser / serde_json rlib 缺失（详见 ${LOG}）"

OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

compile_acceptance() {
  PATH="$HOME/.cargo/bin:$PATH" rustc --edition 2021 --crate-type bin \
    -L "dependency=${CORE_DIR}/target/debug/deps" \
    --extern "cf_browser=${CF_BROWSER_RLIB}" \
    --extern "serde_json=${SERDE_JSON_RLIB}" \
    "${ROOT_DIR}/tests/acceptance_browser.rs" \
    -o "${OUT_DIR}/acceptance_browser" >> "$LOG" 2>&1
}

say "==> 编译 acceptance_browser.rs"
if ! compile_acceptance; then
  # serde/serde_core 多 feature 变体歧义（cf-browser 各构建面产生多份 rlib）→
  # 定向 clean 消除歧义后以一致 feature 集重建（一次性成本；docs/32 §1.6 注记）。
  say "    首次编译失败，定向 clean 消除 serde 变体歧义后重试（详见 ${LOG}）"
  ( cd "${CORE_DIR}" && "${CARGO}" clean -p cf-browser -p serde_json -p serde \
      -p serde_core -p cf-domain -p cf-crypto ) >> "$LOG" 2>&1
  ( cd "${CORE_DIR}" && "${CARGO}" build -p cf-browser --offline ) >> "$LOG" 2>&1 \
    || fail "clean 后重建 cf-browser 失败（详见 ${LOG}）"
  CF_BROWSER_RLIB="$(newest_rlib cf_browser)"
  SERDE_JSON_RLIB="$(newest_rlib serde_json)"
  compile_acceptance || fail "acceptance 编译仍失败（详见 ${LOG}）"
fi

# ---- 运行 ----
say "==> 运行 acceptance_browser（coffer = ${COFFER_BIN}）"
TMP_ACCEPT="$(mktemp -d)"
if ! "${OUT_DIR}/acceptance_browser" "${COFFER_BIN}" "${TMP_ACCEPT}" | tee -a "$LOG"; then
  fail "acceptance_browser 断言失败（详见 ${LOG}）"
fi
rm -rf "${TMP_ACCEPT}"

say "----------------------------------------"
say "browser smoke: 构建 + ② 层外门禁 8001 + get_entries 往返 + 锁态 8003 + lock 退出 0"
say "              + 链路/日志无明文 —— 全部通过"
say "log   : ${LOG}"
say "SMOKE: OK"
