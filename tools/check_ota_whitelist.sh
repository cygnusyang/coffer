#!/usr/bin/env bash
# tools/check_ota_whitelist.sh —— OTA 白名单防漂移检查（docs/35 §6.2 + §2.2 三道锁第 2 锁）。
#
# 契约（docs/35 §6.2，冻结）：Updater 模块所有网络代码只允许连接 4 个白名单
# host（api.github.com / github.com / objects.githubusercontent.com /
# release-assets.githubusercontent.com），且强制 HTTPS。所有网络代码只在
# Swift 侧（Updater 模块），Rust 依赖图由 check_no_network.sh 把关。
#
# 本脚本是**静态检查**：扫描 macos/Coffer/Updater/*.swift，断言其中出现的 host
# （https:// URL 的权威部分 + allowedHosts 类集合的字面量）全部 ∈ 白名单，
# 且无 http://（非 HTTPS）URL。
# ⚠️ 边界声明：静态检查 ≠ 运行时证明。本脚本只证明「源码中写死的 host 均白名单」；
# 运行时的 URLSession delegate 强制校验（host ∈ 白名单 + 强制 HTTPS）由
# Updater 模块实现，在集成轮/真机验证（docs/35 §2.2 第 2 锁、§4 开放点）。
#
# 用法：
#   tools/check_ota_whitelist.sh [SRC_DIR]   # 默认 macos/Coffer/Updater
#
# 退出码：
#   0 = PASS（所有出现 host 均白名单 + 无 http://）
#   1 = FAIL（出现白名单外 host 或非 HTTPS URL）
#   2 = 源缺失（Updater 目录不存在或其中无 .swift 文件）——不假绿也不误红，
#       由调用方决定如何处理（CI 集成后源应已存在）。
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${1:-${ROOT_DIR}/macos/Coffer/Updater}"

# 契约白名单（docs/35 §6.2，冻结）：只允许这 4 个 host，逐个精确匹配。
WHITELIST="api.github.com github.com objects.githubusercontent.com release-assets.githubusercontent.com"

if [ ! -d "$SRC_DIR" ]; then
    echo "SKIP: Updater 源目录不存在（${SRC_DIR}）——组 A 尚未落地或路径变更，无法执行白名单检查（不假绿也不误红，退出码 2）" >&2
    exit 2
fi

# 目录存在但无 .swift 文件同样视为源缺失（可能目录刚建/为空）。
SWIFT_FILES="$(find "$SRC_DIR" -name '*.swift' -type f | sort)"
if [ -z "$SWIFT_FILES" ]; then
    echo "SKIP: ${SRC_DIR} 下没有 .swift 文件，无法执行白名单检查（不假绿也不误红，退出码 2）" >&2
    exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
URL_HOSTS="$TMP_DIR/url_hosts"
LITERAL_HOSTS="$TMP_DIR/literal_hosts"

# ---- 提取 1：https:// URL 的权威部分 host（含端口则剥端口，统一小写去重）----
# grep -ohE 跨文件输出每个匹配；正则只捕获权威部分（host[:port]），不进入路径。
find "$SRC_DIR" -name '*.swift' -type f -exec \
  grep -ohE 'https://[a-zA-Z0-9._-]+' {} + 2>/dev/null \
  | sed 's#^https://##' \
  | sed 's/:[0-9][0-9]*$//' \
  | tr 'A-Z' 'a-z' \
  | sort -u > "$URL_HOSTS"

# ---- 提取 2：allowedHosts 类集合的字面量 host ----
# 仅扫描提及 host 白名单语义的行（allowedHosts/whitelist/allowList，大小写不敏感），
# 并带上其后的声明上下文（-A 15：host 集合逐行书写时各元素在后续行），
# 再从中提取引号内点分主机名字面量，避免误抓任意字符串常量。
# 注意：BSD grep 下 -o 优先于 -A，故上下文提取与字面量提取分两步（先 -A 后 -o）。
find "$SRC_DIR" -name '*.swift' -type f -exec \
  grep -hiEA 15 'allowedHosts|whitelist|allowList' {} + 2>/dev/null \
  | grep -ohE '"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"' \
  | tr -d '"' \
  | tr 'A-Z' 'a-z' \
  | sort -u > "$LITERAL_HOSTS"

# ---- 提取 3：非 HTTPS URL（http://）——契约强制 HTTPS，出现即违规 ----
# 注意：https:// 中的 "http" 后跟 "s" 而非 ":"，不会被本正则误判。
HTTP_URLS="$(find "$SRC_DIR" -name '*.swift' -type f -exec grep -ohE 'http://[a-zA-Z0-9._-]+' {} + 2>/dev/null | sort -u || true)"

is_whitelisted() {
    local h="$1"
    # $(...) 输出在 zsh 下默认分词，与 bash 行为一致（参考 check_no_network.sh 注记）。
    for w in $(printf '%s\n' "$WHITELIST"); do
        [ "$h" = "$w" ] && return 0
    done
    return 1
}

FAIL=0

# 检查 URL host（提取 1）
if [ -s "$URL_HOSTS" ]; then
    while IFS= read -r h; do
        [ -n "$h" ] || continue
        if ! is_whitelisted "$h"; then
            echo "FAIL: Updater 源码出现白名单外 host（https:// URL）：$h" >&2
            FAIL=1
        fi
    done < "$URL_HOSTS"
else
    echo "WARN: Updater 源码中未发现任何 https:// URL 字面量（若构造 URL 方式非字面量，请人工复核）"
fi

# 检查 allowedHosts 字面量（提取 2）
if [ -s "$LITERAL_HOSTS" ]; then
    while IFS= read -r h; do
        [ -n "$h" ] || continue
        if ! is_whitelisted "$h"; then
            echo "FAIL: allowedHosts 类集合出现白名单外 host：$h" >&2
            FAIL=1
        fi
    done < "$LITERAL_HOSTS"
fi

# 检查非 HTTPS URL（提取 3）
if [ -n "$HTTP_URLS" ]; then
    echo "FAIL: Updater 源码出现非 HTTPS（http://）URL——契约强制 HTTPS：" >&2
    printf '%s\n' "$HTTP_URLS" | sed 's/^/    /' >&2
    FAIL=1
fi

echo "==> 扫描源：${SRC_DIR}"
echo "    https:// URL host（去重）：$(tr '\n' ' ' < "$URL_HOSTS")"
echo "    allowedHosts 字面量（去重）：$(tr '\n' ' ' < "$LITERAL_HOSTS")"
echo "    非 HTTPS URL：${HTTP_URLS:-无}"

if [ "$FAIL" -eq 1 ]; then
    echo "==> 结果：FAIL（白名单外 host / 非 HTTPS，见上；白名单见 docs/35 §6.2）"
    exit 1
fi

# 正向告警：两种提取都为空，扫描疑似未抓到有效内容（仅 WARN，不 fail）。
SEEN="$(cat "$URL_HOSTS" "$LITERAL_HOSTS" 2>/dev/null | sort -u)"
if [ -z "$SEEN" ]; then
    echo "WARN: 未提取到任何 host，扫描疑似无效——请人工确认 Updater 网络代码形态"
fi

echo "==> 结果：PASS（所有出现 host 均 ∈ 白名单，且无 http://）"
echo "    本结果仅证明静态源码 host 均白名单；运行时强制校验由 Updater 实现（docs/35 §2.2 第 2 锁）。"
exit 0
