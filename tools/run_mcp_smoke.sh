#!/usr/bin/env bash
# run_mcp_smoke.sh —— `coffer mcp` 端到端冒烟（docs/20 §3/§5，G-G）。
#
# 构建 `coffer` bin → spawn `coffer mcp --provider op`（fake op fixture 驱动，D-2
# 缺省已翻转为 coffer、需 $COFFER_VAULT_DIR，冒烟显式选 op 保自包含）→ 握手 +
# tools/call → 断言：
#   - stdout 永为协议帧（§3.1：首帧是 JSON-RPC 2.0，含 serverInfo.name=coffer）；
#   - tools/call 往返返回 fixture secret 名（§3.3），且 stdout **无明文值**（§3.5-1）；
#   - 干净 EOF → 退出码 0（§5.3）；
#   - stderr 无协议帧（日志只走 stderr，不污染协议通道，§3.1）。
#
# 自包含：在仓库根执行，内部 cd 到 core/ 构建；fake op fixture 随测试文件分发。
# 日志落盘：/tmp/coffer-mcp-smoke-<ts>.log（stdout 只给摘要）。
#
# 用法：./tools/run_mcp_smoke.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORE_DIR="${ROOT_DIR}/core"

LOG="/tmp/coffer-mcp-smoke-$(date +%Y%m%d-%H%M%S).log"
: > "$LOG"

# cargo 定位（非交互 shell 的 PATH 无 cargo，docs 教训）
CARGO="cargo"
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  CARGO="$HOME/.cargo/bin/cargo"
fi

FAKE_OP="${CORE_DIR}/cf-mcp/tests/fixtures/op/op"
COFFER_BIN="${CORE_DIR}/target/debug/coffer"

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
fail() { say "ERROR: $*"; exit 1; }

say "==> build coffer bin"
( cd "${CORE_DIR}" && "${CARGO}" build -p cf-mcp --bin coffer ) >> "$LOG" 2>&1 \
  || fail "cargo build 失败（详见 ${LOG}）"
[ -x "${COFFER_BIN}" ] || fail "coffer 二进制未构建：${COFFER_BIN}"
[ -x "${FAKE_OP}" ] || fail "fake op fixture 不可执行：${FAKE_OP}"

# 临时目录：FIFO 作 stdin，文件作 stdout/stderr
TMP="$(mktemp -d)"
STDOUT_F="${TMP}/stdout"
STDERR_F="${TMP}/stderr"
STDIN_FIFO="${TMP}/stdin.fifo"
mkfifo "${STDIN_FIFO}"

COFFER_PID=""
cleanup() {
  # 兜底：冒烟中断时保证子进程无残留（kill + wait）
  if [ -n "${COFFER_PID}" ] && kill -0 "${COFFER_PID}" 2>/dev/null; then
    kill "${COFFER_PID}" 2>/dev/null || true
    wait "${COFFER_PID}" 2>/dev/null || true
  fi
  exec 9>&- 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

say "==> spawn coffer mcp"
COFFER_OP_BIN="${FAKE_OP}" "${COFFER_BIN}" mcp --provider op < "${STDIN_FIFO}" > "${STDOUT_F}" 2> "${STDERR_F}" &
COFFER_PID=$!
# 打开 FIFO 写端：coffer 启动后阻塞读 stdin 直到我们写 / 关闭
exec 9>"${STDIN_FIFO}"

# 等待进程就绪（最多 5s：stdout 出首帧或进程退出）
for _ in $(seq 1 50); do
  [ -s "${STDOUT_F}" ] || ! kill -0 "${COFFER_PID}" 2>/dev/null && break
  sleep 0.1
done
kill -0 "${COFFER_PID}" 2>/dev/null || fail "coffer 启动即退出（stderr 见 ${STDERR_F}）"

# —— 握手 + 一次 tools/call（§3.2 生命周期；EOF 干净退出 §5.3）——
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' >&9
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&9
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_secret_names","arguments":{}}}' >&9
exec 9>&-   # EOF

wait "${COFFER_PID}"
COFFER_EXIT=$?
COFFER_PID=""
say "==> coffer 退出码：${COFFER_EXIT}"
[ "${COFFER_EXIT}" -eq 0 ] || fail "期望干净退出 0（§5.3），实得 ${COFFER_EXIT}（stdout 见 ${STDOUT_F}）"

# —— 断言协议帧（§3.1 stdout 永为协议帧，首帧 JSON-RPC 2.0 + serverInfo）——
FRAME_COUNT=0
FIRST_FRAME=""
ALL_PROTOCOL=true
HAS_INIT=false
HAS_NAMES=false
HAS_PLAINTEXT=false
while IFS= read -r line; do
  FRAME_COUNT=$((FRAME_COUNT + 1))
  [ -n "${FIRST_FRAME}" ] || FIRST_FRAME="${line}"
  case "${line}" in
    *'"jsonrpc":"2.0"'*) ;;
    *) ALL_PROTOCOL=false ;;
  esac
  case "${line}" in *'"serverInfo"'*'"name":"coffer"'*) HAS_INIT=true ;; esac
  case "${line}" in *'OPENAI_API_KEY'*) HAS_NAMES=true ;; esac
  case "${line}" in *'fixture-secret-value-'*) HAS_PLAINTEXT=true ;; esac
done < "${STDOUT_F}"
[ -n "${FIRST_FRAME}" ] || fail "stdout 无任何帧"
case "${FIRST_FRAME}" in
  *'"jsonrpc":"2.0"'*) ;;
  *) fail "stdout 首帧非 JSON-RPC 2.0 协议帧：${FIRST_FRAME}" ;;
esac
[ "${ALL_PROTOCOL}" = true ] || fail "stdout 出现非 JSON-RPC 2.0 行（§3.1，见 ${STDOUT_F}）"
[ "${HAS_INIT}" = true ] || fail "首帧缺 initialize 契约（serverInfo.name=coffer）：${FIRST_FRAME}"
[ "${HAS_NAMES}" = true ] || fail "tools/call 未返回 fixture secret 名（stdout 见 ${STDOUT_F}）"
[ "${HAS_PLAINTEXT}" = false ] || fail "stdout 出现明文值（§3.5-1，见 ${STDOUT_F}）"
[ "${FRAME_COUNT}" -ge 2 ] || fail "stdout 帧数不足（期望 ≥2 帧，实得 ${FRAME_COUNT}）"
if grep -q '"jsonrpc"' "${STDERR_F}"; then
  fail "stderr 出现协议帧（§3.1：stdout 永为协议帧，stderr 只做日志）"
fi

# —— 协议致命路径（L-7 / §5.3 退出码 2）：超限行 → 7005 拒收帧 + 退出码 2 ——
say "==> 协议致命路径：超限行 → 7005 + 退出码 2"
STDOUT2_F="${TMP}/stdout2"
STDERR2_F="${TMP}/stderr2"
STDIN_FIFO2="${TMP}/stdin2.fifo"
mkfifo "${STDIN_FIFO2}"
COFFER_OP_BIN="${FAKE_OP}" "${COFFER_BIN}" mcp --provider op < "${STDIN_FIFO2}" > "${STDOUT2_F}" 2> "${STDERR2_F}" &
COFFER_PID=$!
exec 9>"${STDIN_FIFO2}"

# 等待进程就绪（同首段：stdout 出内容或进程退出，最多 5s）
for _ in $(seq 1 50); do
  [ -s "${STDOUT2_F}" ] || ! kill -0 "${COFFER_PID}" 2>/dev/null && break
  sleep 0.1
done
kill -0 "${COFFER_PID}" 2>/dev/null || fail "coffer 启动即退出（stderr 见 ${STDERR2_F}）"

# 超限行（64KB+1，无需换行：第 65537 字节即触发 TooLong）。不把 64KB 字符串
# 内联进命令行（/dev/zero 生成）。coffer 检测超限即写 7005 并退出 → 残余写入
# EPIPE 属预期，用 `|| true` 容忍（SIGPIPE 由子进程承接，脚本不退）。
{ head -c $((64 * 1024 + 1)) /dev/zero | tr '\0' 'x' >&9; } 2>/dev/null || true
exec 9>&-   # EOF

# wait 退出码非零（coffer 按 §5.3 以 2 退出）——用 || 捕获，避免 set -e 中断
wait "${COFFER_PID}" && OVER_EXIT=0 || OVER_EXIT=$?
COFFER_PID=""
say "==> 协议致命退出码：${OVER_EXIT}"
[ "${OVER_EXIT}" -eq 2 ] || fail "期望协议致命退出码 2（§5.3），实得 ${OVER_EXIT}（stdout 见 ${STDOUT2_F}）"
grep -q '"code":7005' "${STDOUT2_F}" || fail "stdout 须含 7005 拒收帧（L-7，见 ${STDOUT2_F}）"
grep -q '"id":null' "${STDOUT2_F}" || fail "7005 拒收帧 id 恒 null（帧同步不可恢复，见 ${STDOUT2_F}）"

say "----------------------------------------"
say "smoke: 构建 + 握手 + tools/call + 退出码 0 全部通过（${FRAME_COUNT} 帧协议帧）"
say "      + 协议致命路径 7005 + 退出码 2 通过"
say "log   : ${LOG}"
say "SMOKE: OK"
