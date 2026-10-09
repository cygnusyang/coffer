#!/usr/bin/env bash
# run_update_tests.sh —— v2.7.0 OTA 组 A（Updater 核心）Swift 侧自动化验收。
#
# 编译 macos/Coffer/Updater/*.swift + macos/Tests/UpdateTests/main.swift，
# **不链接 libcf_ffi.a**（本组纯 Swift，无 Rust 依赖）；链接 Security /
# CryptoKit / Combine / AppKit（NSWorkspace，§6.4 r0.4 LaunchServices 启动）
# framework。测试不联网（网络层经协议注入 stub）。
#
# 用法：./tools/run_update_tests.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v swiftc >/dev/null 2>&1 || { echo "ERROR: 未找到 swiftc。" >&2; exit 1; }

ARCH="$(uname -m)"
OUT_DIR="$(mktemp -d)"
trap 'rm -rf "${OUT_DIR}"' EXIT

UPDATER_DIR="${ROOT_DIR}/macos/Coffer/Updater"
[[ -d "${UPDATER_DIR}" ]] || { echo "ERROR: 缺 ${UPDATER_DIR}" >&2; exit 1; }

# shellcheck disable=SC2207
SOURCES=( "${UPDATER_DIR}"/*.swift "${ROOT_DIR}/macos/Tests/UpdateTests/main.swift" )

swiftc -O \
  -swift-version 5 \
  -target "${ARCH}-apple-macos14.0" \
  -framework Security \
  -framework CryptoKit \
  -framework Combine \
  -framework AppKit \
  "${SOURCES[@]}" \
  -o "${OUT_DIR}/UpdateTests"

# 已签名产物路径经 env 传给测试（TC-SEC / TC-INST-03；产物缺失则测试显式 SKIP）。
COFFER_UPDATE_ARTIFACT_PATH="${ROOT_DIR}/macos/build/Coffer.app" \
  "${OUT_DIR}/UpdateTests"
