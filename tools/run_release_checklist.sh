#!/usr/bin/env bash
# tools/run_release_checklist.sh —— 发版前检查清单（把 lead 的人工核对脚本化）。
#
# 用法：
#   tools/run_release_checklist.sh v2.12.0 [--with-gate] [--online]
#
# 检查项（默认离线）：
#   ① 工作树干净（脏树记 WARN，不阻断——CI 检出树为干净）
#   ② tag 形态 vX.Y.Z
#   ③ Info.plist CFBundleShortVersionString == tag 版本（FAIL）
#   ④ CHANGELOG 存在非空版本段（FAIL）
#   ⑤ provisioning profile 存在且未过期；<48h 记 WARN（BUG-27 纪律）
#   ⑥ OTA 验签公钥一致性：env UPDATE_SIGNING_KEY_BASE64 可派生时比对源码常量；
#      未提供 env 记 WARN（CI 必须提供）
#   ⑦ OTA host 白名单
#   ⑧ 文档事实核查（check_docs_facts.sh）
#   ⑨ 已构建产物存在时：签名有效 + entitlement 仅 network.client
#   --with-gate：追加 tools/run_gate.sh 全量门禁
#   --online：追加 GitHub secrets 名称存在性 + GitLab protected tag（只读名称，不取值）
#
# 退出码：0 = 无 FAIL；1 = 至少一项 FAIL。
# 日志：/tmp/coffer-release-check-<HHMMSS>.log。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG="${RELEASE_CHECK_LOG:-/tmp/coffer-release-check-$(date +%H%M%S).log}"
: >"$LOG"

TAG=""
WITH_GATE=0
ONLINE=0
for arg in "$@"; do
    case "$arg" in
        --with-gate) WITH_GATE=1 ;;
        --online) ONLINE=1 ;;
        -*) echo "未知参数：$arg" >&2; exit 2 ;;
        *) TAG="$arg" ;;
    esac
done

FAILED=0
WARNED=0
PASSED=0
pass() { echo "PASS $*" | tee -a "$LOG"; PASSED=$((PASSED + 1)); }
warn() { echo "WARN $*" | tee -a "$LOG"; WARNED=$((WARNED + 1)); }
fail() { echo "FAIL $*" | tee -a "$LOG"; FAILED=$((FAILED + 1)); }
log() { echo "$*" >>"$LOG"; }

cd "$ROOT_DIR" || { echo "FAIL 无法进入仓库根：$ROOT_DIR" >&2; exit 1; }

if [ -z "$TAG" ]; then
    echo "用法：$0 vX.Y.Z [--with-gate] [--online]" >&2
    exit 2
fi
if ! printf '%s' "$TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    fail "① tag 形态非法：$TAG（期望 vX.Y.Z）"
    VERSION=""
else
    VERSION="${TAG#v}"
    pass "① tag 形态：$TAG"
fi

# ① 工作树
if git rev-parse --git-dir >/dev/null 2>&1; then
    DIRTY="$(git status --porcelain | head -20)"
    if [ -n "$DIRTY" ]; then
        warn "② 工作树不干净（$(printf '%s\n' "$DIRTY" | wc -l | tr -d ' ') 项，前 20 见下）"
        log "$DIRTY"
    else
        pass "② 工作树干净"
    fi
else
    warn "② 非 git 仓库，跳过工作树检查"
fi

# ③ 版本一致
PLIST="macos/Coffer/Info.plist"
if [ -n "$VERSION" ] && [ -f "$PLIST" ]; then
    PLIST_VER="$(awk '/<key>CFBundleShortVersionString<\/key>/{getline; gsub(/.*<string>|<\/string>.*/,""); print; exit}' "$PLIST")"
    if [ "$PLIST_VER" = "$VERSION" ]; then
        pass "③ Info.plist 版本 = $VERSION"
    else
        fail "③ Info.plist 版本=${PLIST_VER}，tag 版本=${VERSION}（发版前必须 bump 一致）"
    fi
else
    fail "③ 缺少 $PLIST 或版本无法解析"
fi

# ④ CHANGELOG 版本段
if [ -f "CHANGELOG.md" ] && [ -n "$TAG" ]; then
    BODY="$(awk -v t="${TAG}" '
        $0 ~ "^## " t "([[:space:]]|$)" { in_section=1; next }
        in_section && /^## / { exit }
        in_section { print }
    ' CHANGELOG.md)"
    if [ -n "$(printf '%s' "$BODY" | tr -d '[:space:]')" ]; then
        pass "④ CHANGELOG 含非空版本段：$TAG"
    else
        fail "④ CHANGELOG.md 缺少版本段 \"## $TAG\" 或内容为空"
    fi
else
    fail "④ 缺少 CHANGELOG.md"
fi

# ⑤ provisioning profile 有效期
PROFILE="macos/build/top.cygnusyang.coffer.provisionprofile"
if [ -f "$PROFILE" ]; then
    TMP_PLIST="$(mktemp)"
    if security cms -D -i "$PROFILE" >"$TMP_PLIST" 2>>"$LOG"; then
        EXP="$(/usr/libexec/PlistBuddy -c 'Print :ExpirationDate' "$TMP_PLIST" 2>/dev/null || true)"
        if [ -z "$EXP" ]; then
            warn "⑤ profile 存在但无法解析 ExpirationDate"
        else
            # 优先 plutil 的 ISO 8601（UTC），回退 PlistBuddy 的 asctime 形态。
            EXP_ISO="$(plutil -extract ExpirationDate raw "$TMP_PLIST" 2>/dev/null || true)"
            EXP_EPOCH=""
            if [ -n "$EXP_ISO" ]; then
                EXP_EPOCH="$(date -j -f '%Y-%m-%dT%H:%M:%SZ' "$EXP_ISO" '+%s' 2>/dev/null || true)"
            fi
            [ -n "$EXP_EPOCH" ] || EXP_EPOCH="$(LC_ALL=C date -j -f '%a %b %d %H:%M:%S %Z %Y' "$EXP" '+%s' 2>/dev/null || true)"
            [ -n "$EXP_ISO" ] && EXP="$EXP_ISO"
            NOW_EPOCH="$(date '+%s')"
            if [ -z "$EXP_EPOCH" ]; then
                warn "⑤ 无法解析过期时间：$EXP"
            elif [ "$EXP_EPOCH" -le "$NOW_EPOCH" ]; then
                fail "⑤ provisioning profile 已过期：$EXP（重跑 tools/make_provisioning_profile.sh）"
            elif [ $((EXP_EPOCH - NOW_EPOCH)) -lt 172800 ]; then
                warn "⑤ provisioning profile 剩余不足 48h：$EXP（BUG-27 纪律，先刷新再发版）"
            else
                pass "⑤ provisioning profile 有效期至 $EXP"
            fi
        fi
    else
        fail "⑤ 无法解码 provisioning profile：$PROFILE"
    fi
    rm -f "$TMP_PLIST"
else
    warn "⑤ 未找到 profile：$PROFILE（CI 会注入；本地发版前需生成）"
fi

# ⑥ OTA 公钥一致性
if [ -n "${UPDATE_SIGNING_KEY_BASE64:-}" ]; then
    DERIVED="$(./tools/derive_update_public_key.sh 2>>"$LOG" || true)"
    SRC_PUB="$(grep -hoE 'cofferUpdatePublicKeyBase64 *= *"[A-Za-z0-9+/=]+"' \
        macos/Coffer/Updater/ManifestVerifier.swift | head -1 \
        | grep -oE '"[^"]+"' | tr -d '"' || true)"
    if [ -z "$DERIVED" ] || [ -z "$SRC_PUB" ]; then
        fail "⑥ 无法派生公钥或读取源码常量（DERIVED='${DERIVED}' SRC='${SRC_PUB}'）"
    elif [ "$DERIVED" = "$SRC_PUB" ]; then
        pass "⑥ OTA 公钥一致：$DERIVED"
    else
        fail "⑥ OTA 公钥不一致：派生=${DERIVED} 源码=${SRC_PUB}"
    fi
else
    warn "⑥ 未提供 UPDATE_SIGNING_KEY_BASE64，跳过 OTA 公钥核查（CI 发版必须提供）"
fi

# ⑦ OTA 白名单
OTA_OUT="$(./tools/check_ota_whitelist.sh 2>&1)"
OTA_RC=$?
log "⑦ check_ota_whitelist.sh rc=$OTA_RC"
log "$OTA_OUT"
case "$OTA_RC" in
    0) pass "⑦ OTA host 白名单通过" ;;
    2) warn "⑦ OTA 源目录缺失，白名单检查跳过（rc=2）" ;;
    *) fail "⑦ OTA host 白名单失败（rc=$OTA_RC）" ;;
esac

# ⑧ 文档事实
DOCS_OUT="$(./tools/check_docs_facts.sh 2>&1)"
DOCS_RC=$?
log "⑧ check_docs_facts.sh rc=$DOCS_RC"
log "$DOCS_OUT"
if [ "$DOCS_RC" -eq 0 ]; then
    pass "⑧ 文档事实核查通过（$(printf '%s\n' "$DOCS_OUT" | grep '^DOCS_FACTS:' | tail -1)）"
else
    fail "⑧ 文档事实核查失败（详见 ${LOG}）"
fi

# ⑨ 已构建产物签名与 entitlement
APP="macos/build/Coffer.app"
if [ -d "$APP" ]; then
    if codesign --verify --strict "$APP" 2>>"$LOG"; then
        ENT="$(codesign -d --entitlements - "$APP" 2>&1)"
        OTHER="$(printf '%s\n' "$ENT" | grep -oE 'com\.apple\.security\.network\.[a-zA-Z.]+' \
            | grep -vx 'com.apple.security.network.client' || true)"
        if [ -n "$OTHER" ]; then
            fail "⑨ 产物存在白名单外 network.* entitlement：$OTHER"
        elif printf '%s\n' "$ENT" | grep -q 'com.apple.security.network.client'; then
            pass "⑨ 产物签名有效，网络 entitlement 仅 network.client"
        else
            fail "⑨ 产物缺少 OTA 最小豁免 network.client"
        fi
    else
        fail "⑨ 产物签名校验失败：$APP"
    fi
else
    warn "⑨ 未找到 ${APP}，跳过签名/entitlement 检查（CI 构建后自动覆盖）"
fi

# --with-gate
if [ "$WITH_GATE" -eq 1 ]; then
    echo "==> 追加全量门禁 tools/run_gate.sh（日志见 ${LOG}）" | tee -a "$LOG"
    ./tools/run_gate.sh >>"$LOG" 2>&1
    GATE_RC=$?
    if [ "$GATE_RC" -eq 0 ]; then
        pass "⑩ 全量门禁通过"
    else
        fail "⑩ 全量门禁失败（rc=$GATE_RC）"
    fi
fi

# --online
if [ "$ONLINE" -eq 1 ]; then
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        SECRETS="$(gh secret list --repo cygnusyang/coffer 2>/dev/null | awk '{print $1}')"
        MISSING=""
        for s in APPLE_CERT_P12_BASE64 APPLE_CERT_PASSWORD APPLE_PROVISIONING_PROFILE_BASE64 UPDATE_SIGNING_KEY_BASE64; do
            printf '%s\n' "$SECRETS" | grep -qx "$s" || MISSING="$MISSING $s"
        done
        if [ -n "$MISSING" ]; then
            fail "⑪ GitHub secrets 缺失：$MISSING"
        else
            pass "⑪ GitHub 四个发版 secret 名称齐全"
        fi
    else
        warn "⑪ gh 未认证，跳过 GitHub secrets 检查"
    fi

    if command -v glab >/dev/null 2>&1; then
        TAGS="$(glab api projects/:id/protected_tags 2>/dev/null \
            | python3 -c 'import sys,json; print("\n".join(t.get("name","") for t in json.load(sys.stdin)))' 2>/dev/null || true)"
        if printf '%s\n' "$TAGS" | grep -qx 'v\*'; then
            pass "⑪ GitLab protected tag 规则 v* 存在"
        elif [ -n "$TAGS" ]; then
            fail "⑪ GitLab protected tag 缺少 v*（当前：$(printf '%s' "$TAGS" | tr '\n' ' ')）"
        else
            warn "⑪ 无法读取 GitLab protected tags（跳过）"
        fi
    else
        warn "⑪ glab 不存在，跳过 GitLab protected tag 检查"
    fi
fi

echo "----------------------------------------"
echo "RELEASE_CHECK(${TAG:-未指定}): ${PASSED} PASS / ${WARNED} WARN / ${FAILED} FAIL"
echo "log: ${LOG}"
if [ "$FAILED" -eq 0 ]; then
    exit 0
fi
exit 1
