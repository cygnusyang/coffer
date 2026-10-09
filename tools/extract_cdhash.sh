#!/usr/bin/env bash
# tools/extract_cdhash.sh —— 从已签名 .app 提取 CDHash（= kSecCodeInfoUnique，hex）。
#
# OTA 更新清单（docs/35 §6.1）的 cdHash 字段语义 = 产物 kSecCodeInfoUnique
# （验签次锚；P-S spike 裁定：DR/TeamID 主锚、CDHash 次锚）。本工具从
# `codesign -dv --verbose=4` 的 CDHash= 行提取 40 位 hex——已实证与
# SecCodeCopySigningInformation(kSecCodeInfoUnique) 返回的 20 字节一致
# （2026-10-10，macos/build/Coffer.app 实测，hex 同值）。
#
# 健壮性说明：CDHash= 行在 codesign 输出中自 Xcode 6 起格式稳定
# （`CDHash=<40 hex>`）；老/新 Xcode 的差异体现在其它辅助行
# （CandidateCDHashFull/CMSDigest 等，均为 64 hex 全量哈希，**不是**
# kSecCodeInfoUnique），不影响本行解析。若目标产物格式异常（CDHash= 行缺失
# 或长度非 40），脚本明确失败并附 codesign 原始输出供诊断，绝不静默降级为
# 错误值（错误值会直接导致 OTA 验签次锚失配）。
#
# 用法：
#   tools/extract_cdhash.sh [APP_PATH]     # 默认 macos/build/Coffer.app
#   CDHASH="$(tools/extract_cdhash.sh)"    # stdout 只输出 40 位 hex，可管道
#
# 退出码：0 = 成功；1 = 提取失败（诊断信息走 stderr）。
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_PATH="${1:-${ROOT_DIR}/macos/build/Coffer.app}"

if [ ! -d "$APP_PATH" ]; then
    echo "ERROR: 未找到目标 .app：$APP_PATH" >&2
    exit 1
fi

# codesign -dv 失败即目标未签名/损坏（返回非零并输出诊断到 stderr）。
OUT="$(codesign -dv --verbose=4 "$APP_PATH" 2>&1)" || {
    echo "ERROR: codesign -dv 执行失败（目标可能未签名或损坏）：$APP_PATH" >&2
    exit 1
}

# 提取首个 CDHash=<40 hex> 并统一小写（kSecCodeInfoUnique 十六进制为小写）。
# grep -oE 保证 bash/zsh/macOS 兼容（不用 -P）。
CDHASH="$(printf '%s\n' "$OUT" | grep -oE 'CDHash=[0-9a-fA-F]{40}' | head -1 | sed 's/^CDHash=//' | tr 'A-F' 'a-f')"

if [ -z "$CDHASH" ]; then
    echo "ERROR: 未在 codesign 输出中找到 CDHash=<40hex> 行（kSecCodeInfoUnique 应为 20 字节）：" >&2
    printf '%s\n' "$OUT" >&2
    exit 1
fi

printf '%s\n' "$CDHASH"
