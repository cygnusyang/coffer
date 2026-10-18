#!/usr/bin/env bash
# tools/run_ota_probe.sh —— OTA 通道定时探针（docs/35 §6 通道健康，只读匿名，无 secret）。
#
# 定时匿名探测公开产物仓 OTA 通道健康，主动抓 DDNS 漂移 / GitLab 配置漂移等环境
# 故障（BUG-25 类：通道静默断开，用户不点「检查更新」就发现不了），不携带任何
# secret，可安全跑在无敏感变量的定时任务（CI schedule / launchd）上。
#
# 三道检查，任一失败即告警（明确错误信息 + 非零退出码）：
#   ① permalink 清单可达：跟随重定向后必须最终 200（302→200），JSON 可解析、
#      必需字段齐全（schemaVersion/appId/version/minimumVersion/buildTime/
#      downloadUrl/cdHash/securityCritical/signature/**sha256**，sha256 自 v2.10.3
#      T1 起为必含项）、cdHash 为 40 位 hex、**sha256 为 64 位 hex 小写**。
#   ② zip Range 探测：manifest.downloadUrl 前 64 字节必须 206/200 且 PK\x03\x04
#      魔数（zip 可读）。
#   ③ manifest 签名可验：canonical JSON 契约 + Ed25519（verify_update_manifest.
#      swift），公钥从 App 源码 ManifestVerifier.swift 的 cofferUpdatePublicKeyBase64
#      自动提取——单源，密钥轮换只改一处而另一处未跟 → 验签失败 → 探针告警。
#      （sha256 字段存在性/格式亦在 verify helper 内复核，双保险。）
#
# 另：manifest.version 若落在占位区间（≥99.x，如 v99.99.99 冒烟/测试 release）则
# 打 WARNING（不硬失败）——通道健康但「最新版」指向非生产版本，生产 App 点检查会
# 误报可升级，属发布侧问题，探针如实标注供人工处置。
#
# 环境变量（全部可选，均有默认）：
#   OTA_PROBE_MANIFEST_URL   待探 manifest 的 permalink URL（默认 97 公开仓 permalink；
#                            RED 测试可指向故意坏掉的端点）
#   OTA_PROBE_REPO_ROOT      仓库根（默认本脚本上级目录；用于找 ManifestVerifier.swift
#                            提取公钥 + 定位 swift helper）
#   OTA_PROBE_LOG            完整诊断日志路径（默认 ${TMPDIR:-/tmp}/ota-probe.log）
#   OTA_PROBE_STRICT_VERSION =1 时把「manifest.version >= 99.x 占位 release」从
#                            WARNING 升级为硬失败（通道健康但最新版非生产版本，需要
#                            探针转红直到发布侧修正时用；默认 0 = 仅告警）。
# 退出码：0 = 全部通过；非 0 = 至少一道检查失败（告警信号）。
#
# 实现注意（bash 解析器坑，dev-tester 实证 2026-10-14）：`$(...)` 内反斜杠续行的
# 闭合 `)"` 之后若**紧跟**另一段 heredoc-in-`$()`，bash 的 heredoc 预读书签会错乱
# 导致「looking for matching )」解析失败。本脚本两处都规避：curl 的 `$()` 单行不
# 续行；python 步用独立 heredoc 落盘再 `cat` 读回（不用 heredoc-in-`$()`）。
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="${OTA_PROBE_REPO_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LOG="${OTA_PROBE_LOG:-${TMPDIR:-/tmp}/ota-probe.log}"
MANIFEST_URL="${OTA_PROBE_MANIFEST_URL:-https://github.com/cygnusyang/coffer/releases/latest/download/update-manifest.json}"

MANIFEST_VERIFIER_SRC="$REPO_ROOT/macos/Coffer/Updater/ManifestVerifier.swift"
VERIFY_HELPER="$SCRIPT_DIR/verify_update_manifest.swift"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ota-probe.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

MANIFEST_FILE="$WORKDIR/update-manifest.json"
ZIP_HEAD="$WORKDIR/zip-head.bin"
CHECK_OUT="$WORKDIR/manifest-check.txt"

log() { printf '%s\n' "$*" >>"$LOG"; }
note() { log "$*"; printf '%s\n' "$*"; }

note "=== OTA probe $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
note "manifest URL: $MANIFEST_URL"
note "repo root:    $REPO_ROOT"

# 前置依赖检查（fail fast，不静默）。
for c in curl python3 swift; do
    command -v "$c" >/dev/null 2>&1 || { note "ERROR: 缺少依赖 ${c}（需 macOS runner / CLT）"; exit 1; }
done
[ -f "$VERIFY_HELPER" ] || { note "ERROR: 缺少验签 helper：$VERIFY_HELPER"; exit 1; }
[ -f "$MANIFEST_VERIFIER_SRC" ] || { note "ERROR: 找不到 App 验签源码（公钥单源）：$MANIFEST_VERIFIER_SRC"; exit 1; }

FAILED=0

# ---------- ① permalink 清单可达（302→200 + 字段齐全） ----------
note "--- ① permalink manifest 可达 ---"
HTTP_INFO="$(curl -fsSL --max-time 30 -o "$MANIFEST_FILE" -w '%{http_code} %{num_redirects}' "$MANIFEST_URL" 2>>"$LOG")"
CURL_RC=$?
FINAL_CODE="${HTTP_INFO%% *}"
NUM_REDIR="${HTTP_INFO##* }"
if [ $CURL_RC -ne 0 ]; then
    note "ERROR ①: curl 拉清单失败（rc=${CURL_RC}）。通道可能断（DDNS 漂移 / 配置漂移，BUG-25 类）"
    FAILED=1
else
    note "① OK: 跟随 $NUM_REDIR 次重定向，最终 HTTP $FINAL_CODE"
    # JSON 字段 + cdHash 形状 + downloadUrl 提取 + 版本占位告警（python3 一次性完成；
    # 独立 heredoc 落盘再读回，规避 heredoc-in-$() 的 bash 解析坑，见文件头注释）。
    OTA_PROBE_MANIFEST_FILE="$MANIFEST_FILE" python3 - >"$CHECK_OUT" 2>>"$LOG" <<'PYEOF'
import json, os, sys
def die(msg, code):
    print(msg)              # 落 stdout → 探针 note 直接展示
    print(msg, file=sys.stderr)  # 落 stderr → LOG 留存
    sys.exit(code)
p = os.environ["OTA_PROBE_MANIFEST_FILE"]
try:
    d = json.load(open(p))
except Exception as e:
    die("JSONERR " + str(e), 1)
if not isinstance(d, dict):
    die("NOT_DICT: 响应非 JSON 对象（字段校验需 dict）", 5)
req = ["schemaVersion","appId","version","minimumVersion","buildTime","downloadUrl","cdHash","securityCritical","signature","sha256"]
missing = [k for k in req if k not in d or d[k] in (None, "")]
if missing:
    die("MISSING " + ",".join(missing), 2)
cd = d["cdHash"]
if len(cd) != 40 or not all(c in "0123456789abcdefABCDEF" for c in cd):
    die("CDHASH_INVALID " + cd, 3)
sha = d["sha256"]
# T1（v2.10.3）：sha256 必含（新清单必须有）+ 64 位 hex 小写（App 比对期望值为小写，
# 大写会误拒合法包；探针作发布侧防漂移门禁）
if len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
    die("SHA256_INVALID " + sha, 6)
if not str(d["downloadUrl"]).startswith("https://"):
    die("URL_NOT_HTTPS", 4)
major = int(d["version"].split(".")[0]) if d["version"].split(".")[0].isdigit() else 0
print("OK version=%s appId=%s cdHash=%s sha256=%s" % (d["version"], d["appId"], cd, sha))
print("DOWNLOAD_URL=%s" % d["downloadUrl"])
print("PLACEHOLDER=%s" % ("yes" if major >= 99 else "no"))
PYEOF
    PY_RC=$?
    if [ $PY_RC -ne 0 ]; then
        note "ERROR ①: 清单内容校验失败（rc=${PY_RC}）：$(tail -1 "$CHECK_OUT")"
        FAILED=1
    else
        PY_OUT="$(cat "$CHECK_OUT")"
        DOWNLOAD_URL="$(echo "$PY_OUT" | sed -n 's/^DOWNLOAD_URL=//p')"
        note "① OK: 清单字段齐全（version=$(echo "$PY_OUT" | sed -n 's/^OK version=\([^ ]*\).*/\1/p'), appId=$(echo "$PY_OUT" | sed -n 's/.*appId=\([^ ]*\).*/\1/p'), sha256=$(echo "$PY_OUT" | sed -n 's/.*sha256=\([^ ]*\).*/\1/p')）"
        if echo "$PY_OUT" | grep -q '^PLACEHOLDER=yes'; then
            if [ "${OTA_PROBE_STRICT_VERSION:-0}" = "1" ]; then
                note "ERROR ①: manifest.version >= 99.x（疑似冒烟/占位 release），且 OTA_PROBE_STRICT_VERSION=1 → 硬失败"
                FAILED=1
            else
                note "WARNING ①: manifest.version >= 99.x（疑似冒烟/占位 release）。通道健康但「最新版」非生产版本，生产 App 点检查会误报可升级——请人工确认发布侧"
            fi
        fi
    fi
fi

# ---------- ② zip Range 探测（downloadUrl 前 64 字节 + PK 魔数） ----------
if [ $FAILED -eq 0 ]; then
    note "--- ② zip Range 探测 ---"
    # -L 必加：GitHub Releases 资产 URL 先 302 到 objects.githubusercontent.com，
    # 不跟随重定向则落盘为空（魔数判定必红）。v2.11.0 端点切 GitHub 后实证。
    ZIP_INFO="$(curl -fsSL --max-time 30 -r 0-63 -o "$ZIP_HEAD" -w '%{http_code}' "$DOWNLOAD_URL" 2>>"$LOG")"
    ZIP_RC=$?
    if [ $ZIP_RC -ne 0 ]; then
        note "ERROR ②: zip Range 探测失败（rc=$ZIP_RC, HTTP=${ZIP_INFO:-n/a}）。downloadUrl 指向的资源不可读（缺件/改名/漂移）"
        FAILED=1
    else
        MAGIC="$(od -An -tx1 -N4 "$ZIP_HEAD" 2>/dev/null | tr -d ' \n')"
        SIZE="$(wc -c <"$ZIP_HEAD" | tr -d ' ')"
        if [ "$MAGIC" != "504b0304" ]; then
            note "ERROR ②: 响应头 4 字节魔数=${MAGIC}（应为 504b0304 = PK..），非 zip"
            FAILED=1
        else
            note "② OK: Range 探测 HTTP ${ZIP_INFO}，$SIZE 字节，PK 魔数正确"
        fi
    fi
fi

# ---------- ③ manifest 签名可验（canonical + Ed25519，App 同款公钥） ----------
if [ $FAILED -eq 0 ]; then
    note "--- ③ manifest 签名可验 ---"
    PUBKEY="$(grep -o 'cofferUpdatePublicKeyBase64 = "[^"]*"' "$MANIFEST_VERIFIER_SRC" | head -1 | sed -n 's/.*"\([^"]*\)"/\1/p')"
    if [ -z "$PUBKEY" ]; then
        note "ERROR ③: 无法从 ManifestVerifier.swift 提取公钥常量（源码结构漂移）"
        FAILED=1
    else
        VERIFY_OUT="$(swift "$VERIFY_HELPER" "$MANIFEST_FILE" "$PUBKEY" 2>>"$LOG")"
        VERIFY_RC=$?
        if [ $VERIFY_RC -ne 0 ]; then
            note "ERROR ③: manifest 验签失败（rc=${VERIFY_RC}）。签名与公钥不匹配 / 清单被篡改 / 密钥轮换未同步"
            FAILED=1
        else
            note "③ OK: Ed25519 验签通过（${VERIFY_OUT}；公钥=App 单源 cofferUpdatePublicKeyBase64）"
        fi
    fi
fi

# ---------- 汇总 ----------
if [ $FAILED -eq 0 ]; then
    note "PROBE_RESULT=PASS"
    exit 0
fi
note "PROBE_RESULT=FAIL（详见 ${LOG}）"
exit 1
