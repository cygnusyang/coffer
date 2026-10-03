#!/usr/bin/env bash
# run_clipboard_tier_tests.sh —— 剪贴板五档 + 真实库回环 自动化验收
# （TC-UI-01~04 接口级替代执行，2026-09-28 验收批次）。
#
# 与 run_touchid_status_tests.sh 的差异：本测试链 UniFFI 绑定与 Rust 静态库
# （档位表/默认值经 FFI 取内核同源），并驱动真实 NSPasteboard 与真实定时器。
# 测试自恢复环境：UserDefaults 档位原值、剪贴板原内容、临时目录产物。
#
# 用法：./tools/run_clipboard_tier_tests.sh [--vault-dir <库工作目录>]
#   --vault-dir 可选：提供则追加「真实库 导出→校验→恢复」回环段
#   （默认真实路径：~/Library/Containers/app.coffer.Coffer/Data/Documents/Coffer）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

LIB_DIR="${ROOT_DIR}/core/target/release"
[[ -f "${LIB_DIR}/libcf_ffi.a" ]] || { echo "ERROR: 缺 ${LIB_DIR}/libcf_ffi.a，先跑 tools/build_swift_bindings.sh。" >&2; exit 1; }

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  -import-objc-header "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffiFFI.h" \
  "${ROOT_DIR}/macos/Coffer/CoreBindings/cf_ffi.swift" \
  "${ROOT_DIR}/macos/Coffer/Platform/Clipboard.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/DiagLog.swift" \
  "${ROOT_DIR}/macos/Tests/ClipboardTierTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/ClipboardTierTests"

# T8 真实库回环段改为显式 opt-in（2026-09-29 回归批，BUG-10）：
# 1) docs/14 §5 明令测试/脚本禁止指向 App 沙盒真实库路径——本脚本默认自动
#    追加 --vault-dir 指向该路径的旧行为与之冲突；
# 2) 该段在本机两次复现 open() 挂起（无人值守不可执行）；
# 3) 真实库导出/恢复回环涉及用户真实数据，应显式授权后执行。
# 用法：./tools/run_clipboard_tier_tests.sh [--vault-dir <库工作目录>]
#   不传 --vault-dir 时跳过 T8（打印 SKIP），其余段不受影响。
DEFAULT_VAULT_DIR="${HOME}/Library/Containers/app.coffer.Coffer/Data/Documents/Coffer"
ARGS=()

# BUG-10 复发协议（docs/KNOWN-ISSUES.md BUG-10，2026-10-03 加固）：
# 真实库回环 T8 二进制外层套 timeout，防无人值守在 listVaults 的 open() 上
# 再挂 6 分钟（2026-09-29 两次复现，仅无人值守环境出现）。超时打印警示行并
# SKIP（不算 FAIL、不阻断后续段）。疑似复发时按协议取四件套证据：
#   ① /usr/bin/sample <pid> 2（栈）  ② 同路径 ls（对照）
#   ③ 新编译无关二进制同路径对照（区分按路径 vs 按客户端介导）
#   ④ 无人值守状态记录（GUI 会话/屏幕锁定）。
# 超时值：正常全流程实测 81.5s（26 项 ALL GREEN，2026-10-03 本机），默认
# 240s ≈ 3 倍余量（兼顾负载/慢机）；可用环境变量 T8_TIMEOUT_SECS 覆盖。
# 缺 GNU coreutils（timeout 命令不存在）时降级为无超时直跑并打印提示。
T8_TIMEOUT_SECS="${T8_TIMEOUT_SECS:-240}"

run_t8_with_timeout() {
  if ! command -v timeout >/dev/null 2>&1; then
    echo "WARN  未找到 timeout（GNU coreutils），T8 段无超时保护，无人值守仍可能挂起" >&2
    "${OUT_DIR}/ClipboardTierTests" "${ARGS[@]+"${ARGS[@]}"}" "$@"
    return
  fi
  # 注意：timeout 的非零退出（超时 124 / 测试失败）必须经 `|| status=$?` 捕获——
  # 直接裸跑会触发 set -e 提前退出；用 `if timeout; then` 包裹则 $? 会变成 if
  # 语句的 0 而非 timeout 的 124（WARN 永不打、真实失败被静默吞掉）。
  local status=0
  timeout "${T8_TIMEOUT_SECS}" "${OUT_DIR}/ClipboardTierTests" "${ARGS[@]+"${ARGS[@]}"}" "$@" || status=$?
  if [[ $status -eq 0 ]]; then
    return
  fi
  if [[ $status -eq 124 ]]; then
    echo "WARN  BUG-10 疑似复发：T8 段超时被跳过，按 KNOWN-ISSUES BUG-10 复发协议取证（timeout ${T8_TIMEOUT_SECS}s）" >&2
    return 0
  fi
  # 非超时退出：保留原退出码（测试失败/异常），脚本按既有语义结束
  exit "$status"
}

run_t8_with_timeout "$@"
