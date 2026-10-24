#!/usr/bin/env bash
# tools/check_docs_facts.sh —— 文档事实核查（三队协议 §3.2 / 文档影响清单的自动化兜底）。
#
# 检查项：
#   ① README「子命令一览」与 core/cf-mcp/src/cli.rs 头注子命令集合一致
#   ② Info.plist 版本与 CHANGELOG 最新版本段一致（开发期漂移记 WARN）
#   ③ docs 导航与协作适配中的相对链接可达
#   ④ Coffer.entitlements 仅含 OTA 最小网络豁免 network.client，且含 keychain-access-groups
#   ⑤ OTA host 白名单（复用 check_ota_whitelist.sh）
#   ⑥ README 中的 App 内 CLI 路径与构建脚本产物路径一致（记 WARN）
#
# 边界：本脚本只做静态事实核查，不证明运行时行为。运行时零网络与 OTA 通道由
# run_gate.sh / run_ota_probe.sh 与真机判据证明。
#
# 退出码：0 = 无 FAIL（可有 WARN）；1 = 至少一项 FAIL。
# 日志：默认 /tmp/coffer-docs-facts-<HHMMSS>.log；stdout 只给摘要与逐项结论。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG="${DOCS_FACTS_LOG:-/tmp/coffer-docs-facts-$(date +%H%M%S).log}"
: >"$LOG"

FAILED=0
WARNED=0
PASSED=0

pass() { echo "PASS $*" | tee -a "$LOG"; PASSED=$((PASSED + 1)); }
warn() { echo "WARN $*" | tee -a "$LOG"; WARNED=$((WARNED + 1)); }
fail() { echo "FAIL $*" | tee -a "$LOG"; FAILED=$((FAILED + 1)); }
log() { echo "$*" >>"$LOG"; }

cd "$ROOT_DIR" || { echo "FAIL 无法进入仓库根：$ROOT_DIR" >&2; exit 1; }

# ---------- ① README 子命令 vs CLI 源码 ----------
check_subcommands() {
    local readme="README.md" src="core/cf-mcp/src/cli.rs"
    if [ ! -f "$readme" ] || [ ! -f "$src" ]; then
        warn "① 跳过：缺少 $readme 或 $src"
        return
    fi
    local readme_names src_names
    readme_names="$(awk '/^### 子命令一览/{f=1;next} f&&/^### /{exit} f' "$readme" \
        | sed -nE 's/^\| `([a-z0-9-]+)`.*/\1/p' | sort -u)"
    # 只取头注「## 子命令」小节，避免把 provider 列表误当子命令（coffer/op）。
    src_names="$(awk '/^\/\/! ## 子命令/{f=1;next} f&&/^\/\/! ## /{exit} f' "$src" \
        | sed -nE 's/^\/\/! - `([a-z0-9-]+)`.*/\1/p' | sort -u)"
    if [ -z "$readme_names" ] || [ -z "$src_names" ]; then
        warn "① 跳过：未能从 README 或 CLI 源码提取子命令集合"
        return
    fi
    local missing_in_readme missing_in_src
    missing_in_readme="$(comm -23 <(printf '%s\n' "$src_names") <(printf '%s\n' "$readme_names"))"
    missing_in_src="$(comm -13 <(printf '%s\n' "$src_names") <(printf '%s\n' "$readme_names"))"
    if [ -n "$missing_in_readme" ]; then
        fail "① README 缺少源码已有子命令：$(echo "$missing_in_readme" | tr '\n' ' ')"
    fi
    if [ -n "$missing_in_src" ]; then
        fail "① README 列出源码不存在的子命令：$(echo "$missing_in_src" | tr '\n' ' ')"
    fi
    if [ -z "$missing_in_readme" ] && [ -z "$missing_in_src" ]; then
        pass "① README 子命令与 CLI 源码一致（$(echo "$readme_names" | tr '\n' ' ')）"
    fi
}

# ---------- ② 版本一致性 ----------
check_version() {
    local plist="macos/Coffer/Info.plist" changelog="CHANGELOG.md"
    if [ ! -f "$plist" ] || [ ! -f "$changelog" ]; then
        warn "② 跳过：缺少 $plist 或 $changelog"
        return
    fi
    local plist_ver cl_ver
    plist_ver="$(awk '/<key>CFBundleShortVersionString<\/key>/{getline; gsub(/.*<string>|<\/string>.*/,""); print; exit}' "$plist")"
    cl_ver="$(grep -E '^## v[0-9]+\.[0-9]+\.[0-9]+' "$changelog" | head -1 | sed -E 's/^## v([0-9.]+).*/\1/')"
    if [ -z "$plist_ver" ] || [ -z "$cl_ver" ]; then
        warn "② 跳过：未能解析版本（plist='${plist_ver}' changelog='${cl_ver}'）"
        return
    fi
    if [ "$plist_ver" = "$cl_ver" ]; then
        pass "② 版本一致：$plist_ver"
    else
        warn "② 版本漂移：Info.plist=${plist_ver}，CHANGELOG 最新=${cl_ver}（发版前须 bump 一致）"
    fi
}

# ---------- ③ 相对链接 ----------
broken_links() {
    local file="$1" base target path
    base="$(dirname "$file")"
    grep -oE '\]\([^)]+\)' "$file" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//' | while IFS= read -r target; do
        case "$target" in
            http://*|https://*|mailto:*|\#*) continue ;;
        esac
        path="${target%%#*}"
        [ -z "$path" ] && continue
        if [ ! -e "$base/$path" ]; then
            printf '%s -> %s\n' "$file" "$target"
        fi
    done
}

check_links() {
    local files=("docs/README.md" "docs/00-协作适配.md" "README.md")
    local f broken total=0
    for f in "${files[@]}"; do
        [ -f "$f" ] || continue
        broken="$(broken_links "$f")"
        if [ -n "$broken" ]; then
            while IFS= read -r line; do
                fail "③ 链接不可达：$line"
                total=$((total + 1))
            done <<<"$broken"
        fi
    done
    if [ "$total" -eq 0 ]; then
        pass "③ 导航相对链接全部可达"
    fi
}

# ---------- ④ entitlements ----------
check_entitlements() {
    local ent="macos/Coffer/Coffer.entitlements"
    if [ ! -f "$ent" ]; then
        warn "④ 跳过：缺少 $ent"
        return
    fi
    local other
    other="$(grep -oE 'com\.apple\.security\.network\.[a-zA-Z.]+' "$ent" \
        | sort -u | grep -vx 'com.apple.security.network.client' || true)"
    if [ -n "$other" ]; then
        fail "④ entitlements 存在白名单外网络项：$(echo "$other" | tr '\n' ' ')"
    elif ! grep -q 'com.apple.security.network.client' "$ent"; then
        fail "④ entitlements 缺少 OTA 最小豁免 network.client"
    else
        pass "④ 网络 entitlement 仅 network.client（OTA 最小豁免）"
    fi
    if grep -q 'keychain-access-groups' "$ent"; then
        pass "④ keychain-access-groups 存在"
    else
        fail "④ entitlements 缺少 keychain-access-groups（D-6 escrow 必要项）"
    fi
}

# ---------- ⑤ OTA 白名单 ----------
check_ota() {
    local out rc
    out="$(./tools/check_ota_whitelist.sh 2>&1)"
    rc=$?
    log "⑤ check_ota_whitelist.sh rc=$rc"
    log "$out"
    case "$rc" in
        0) pass "⑤ OTA host 白名单通过" ;;
        2) warn "⑤ OTA 源目录缺失，白名单检查跳过（rc=2）" ;;
        *) fail "⑤ OTA host 白名单失败（rc=${rc}）：$(echo "$out" | tail -1)" ;;
    esac
}

# ---------- ⑥ README App 内 CLI 路径 ----------
check_cli_path() {
    local readme="README.md" build="tools/build_macos_app.sh"
    if [ ! -f "$readme" ] || [ ! -f "$build" ]; then
        warn "⑥ 跳过：缺少 $readme 或 $build"
        return
    fi
    if grep -q 'Contents/Helpers/coffer.app' "$readme"; then
        if grep -q 'Helpers/coffer.app' "$build"; then
            pass "⑥ README 的 App 内 CLI 路径与构建脚本一致"
        else
            warn "⑥ README 写了 Contents/Helpers/coffer.app，但构建脚本未见同名产物路径"
        fi
    fi
}

check_subcommands
check_version
check_links
check_entitlements
check_ota
check_cli_path

echo "----------------------------------------"
echo "DOCS_FACTS: ${PASSED} PASS / ${WARNED} WARN / ${FAILED} FAIL"
echo "log: ${LOG}"
if [ "$FAILED" -eq 0 ]; then
    exit 0
fi
exit 1
