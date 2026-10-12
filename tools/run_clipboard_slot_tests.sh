#!/usr/bin/env bash
# run_clipboard_slot_tests.sh —— 剪贴板分槽/守卫行为单元测试（v2.9.0 基层测试化）。
#
# 被测单元 ClipboardManager（macos/Coffer/Platform/Clipboard.swift）的显式时长版
# copyWithAutoClear(_:clearSecs:) / updateClearInterval 分槽（REV-DEV-01）/
# clearOnLock / changeCount 守卫。驱动真实 NSPasteboard + 真实 DispatchQueue.main
# 定时器（显式短时长 0.5~0.8s 控制总运行时长 ≈6.5s），测试自恢复剪贴板原内容。
#
# 与 run_clipboard_tier_tests.sh 的差异：本脚本只测分槽/守卫行为面（AC-2.9.0-P5-2/
# 6/7/8/9 + REV-DEV-01），不跑档位五档（TC-UI 系列）与真实库回环（T8 需 --vault-dir），
# 不重排 10/30/60/120 长档位时序——总时长分钟级 → 秒级。编译清单照抄：CoreBindings
# 绑定两个文件 + Clipboard.swift + DiagLog.swift + main.swift + libcf_ffi.a
# （档位表/默认值经 FFI 取内核同源，尽管本组用例不读档位）。
#
# 用法：./tools/run_clipboard_slot_tests.sh
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
  "${ROOT_DIR}/macos/Tests/ClipboardSlotTests/main.swift" \
  -L "${LIB_DIR}" -lcf_ffi \
  -o "${OUT_DIR}/ClipboardSlotTests"

"${OUT_DIR}/ClipboardSlotTests"
