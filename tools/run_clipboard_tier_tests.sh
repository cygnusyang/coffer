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
"${OUT_DIR}/ClipboardTierTests" "${ARGS[@]+"${ARGS[@]}"}" "$@"
