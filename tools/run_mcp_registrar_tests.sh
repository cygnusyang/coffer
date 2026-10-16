#!/usr/bin/env bash
# run_mcp_registrar_tests.sh —— MCP 一键注册 helper 纯逻辑单元测试
# （CofferMcpHelper.app：RegisterCommandBuilder 命令结构 + McpRegisterRequest
# 配置校验 + 与 App 侧 McpRegisterCommand.buildArgs 同构一致性）。
#
# 被测单元（McpRegisterHelper/*.swift + Support/McpStatusConfig.swift）均为纯函数 /
# 纯数据结构：无 IO / 无 FFI / 无进程依赖，任何环境（含 CI 沙盒）均可运行，
# 不设 SKIP 路径（同 run_mcp_status_tests.sh）。
#
# 用法：./tools/run_mcp_registrar_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc，请安装完整版 Xcode 并 xcode-select --install。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

# 只编译被测单元 + 测试入口（helper 纯逻辑 + App 侧命令构造单源 + Registrar 纯函数；
# 不含 main.swift 的 IO 路径——spawn / claude resolve / 结果读写归装配产物实测，
# standalone 不测 IO。DiagLog 为 Foundation-only 共享诊断，App/测试双侧同文）
swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  "${ROOT_DIR}/macos/Tests/McpRegistrarTests/main.swift" \
  "${ROOT_DIR}/macos/Coffer/McpRegisterHelper/RegisterRequest.swift" \
  "${ROOT_DIR}/macos/Coffer/McpRegisterHelper/RegisterCommand.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/McpStatusConfig.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/McpRegistrar.swift" \
  "${ROOT_DIR}/macos/Coffer/Support/DiagLog.swift" \
  -o "${OUT_DIR}/McpRegistrarTests"

"${OUT_DIR}/McpRegistrarTests"
