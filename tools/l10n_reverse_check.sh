#!/usr/bin/env bash
# l10n_reverse_check.sh —— 反向覆盖检查（源码 → 译表）：清「有文案但没键」的存量。
#
# 与 tools/check_l10n.sh 的分工（评审 H2）：
#   - G6 是增量闸门：只扫它认识的调用形状，新增一行 LocalizedStringKey("…") 它看不见；
#   - 本脚本是存量清查：不看形状，取「所有含 CJK 的字面量」求差集，因此能自愈。
#     代价是要人判断「文案 vs 数据/日志」，故只作软脚本，不进硬门禁。
#
# 信噪比（评审缺陷 2）：诊断调用（DiagLog.append / print / NSLog / assert / fatalError /
# precondition / logFailure 等）里的字面量单独分桶，只统计不阻断（设计 24 §2 把日志
# 列为范围外）。跨行调用靠「上一条有内容的代码行」判定（注释/空行不冲掉上下文）。
#
# 用法（须放在 tools/ 下，否则 ROOT_DIR 会解成 //）：
#   tools/l10n_reverse_check.sh            # 分桶统计 + 列出待修
#   tools/l10n_reverse_check.sh --quiet    # 只在有待修项时输出
# 退出码：0 = 无待修；1 = 有非诊断上下文的未命中（软：调用方决定是否阻断）
#
# 环境变量覆盖（夹具测试用）：L10N_LOCALIZATION_DIR / L10N_SOURCE_DIR / L10N_EXCEPTIONS_FILE
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

LOCALIZATION_DIR="${L10N_LOCALIZATION_DIR:-${ROOT_DIR}/macos/Coffer/Resources/Localization}"
SOURCE_DIR="${L10N_SOURCE_DIR:-${ROOT_DIR}/macos/Coffer}"
EXCEPTIONS_FILE="${L10N_EXCEPTIONS_FILE:-${ROOT_DIR}/tools/l10n_exceptions.txt}"

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

python3 - "${LOCALIZATION_DIR}" "${SOURCE_DIR}" "${EXCEPTIONS_FILE}" "${QUIET}" <<'PY'
import fnmatch
import os
import re
import sys

loc_dir, src_dir, exc_file, quiet = sys.argv[1:5]
quiet = quiet == "1"
CJK = re.compile("[\u4e00-\u9fff]")

DIAG_CALLS = ("DiagLog.append(", "print(", "NSLog(", "assert(", "assertionFailure(",
              "fatalError(", "precondition(", "preconditionFailure(", "logFailure(")
SKIP_DIRS = ("CoreBindings", "Installer", "McpRegisterHelper", "SmokeTest", "Tests")


def parse_strings(path):
    text = open(path, encoding="utf-8").read()
    n = len(text)

    def skip(i):
        while i < n:
            if text.startswith("/*", i):
                j = text.find("*/", i + 2)
                i = n if j < 0 else j + 2
            elif text.startswith("//", i):
                j = text.find("\n", i + 2)
                i = n if j < 0 else j
            elif text[i] in " \t\r\n":
                i += 1
            else:
                break
        return i

    def readq(i):
        i += 1
        buf = []
        while i < n:
            c = text[i]
            if c == "\\" and i + 1 < n:
                e = text[i + 1]
                buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(e, e))
                i += 2
                continue
            if c == '"':
                return "".join(buf), i + 1
            buf.append(c)
            i += 1
        return "".join(buf), i

    out = {}
    i = 0
    while True:
        i = skip(i)
        if i >= n:
            break
        key, i = readq(i)
        i = skip(i)
        if i < n and text[i] == "=":
            i = skip(i + 1)
            val, i = readq(i)
            i = skip(i)
            if i < n and text[i] == ";":
                i += 1
            out[key] = val
        else:
            break
    return out


tbl = {}
for name in sorted(os.listdir(os.path.join(loc_dir, "en"))):
    if name.endswith(".strings"):
        for k in parse_strings(os.path.join(loc_dir, "en", name)):
            tbl.setdefault(k, name)

SPEC_RE = re.compile("%(?:\\d+\\$)?[-+ 0#']*\\d*(?:\\.\\d+)?(?:hh|h|ll|l|q|L|z|t|j)?[@dDiuUxXoOfFeEgGcCsSpaA]")


def norm(s):
    """折叠占位符：源码 \\(expr) 与表内 %lld/%u/%@/%% 归一成同形（类型不参与比对）。"""
    out, i, n = [], 0, len(s)
    while i < n:
        if s.startswith("\\(", i):
            depth, j = 0, i + 1
            while j < n:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append("\x00")
            i = j + 1
            continue
        if s.startswith("%%", i):
            out.append("%")
            i += 2
            continue
        m = SPEC_RE.match(s, i)
        if m:
            out.append("\x00")
            i = m.end()
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


tbl_norm = set(norm(k) for k in tbl)

exempt = []
if os.path.isfile(exc_file):
    for raw in open(exc_file, encoding="utf-8"):
        body = raw.split("#", 1)[0].strip()
        if body and ":" in body:
            g, p = body.split(":", 1)
            exempt.append((g.strip(), p.strip()))


def pct_form(s):
    """把 \(expr) 折成 %?（check_l10n.sh G6 的写法），用于兼容两侧口径。"""
    out, i, n = [], 0, len(s)
    while i < n:
        if s.startswith("\\(", i):
            depth, j = 0, i + 1
            while j < n:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append("%?")
            i = j + 1
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def is_exempt(rel, key):
    """exceptions 的模式按文件头约定 = 源码字面量原文；同时兼容 G6 的 %? 归一化写法，
    这样一份清单在两个脚本里行为一致（评审实测的格式陷阱）。"""
    alt = pct_form(key)
    return any(fnmatch.fnmatch(rel, g) and (p == "*" or p == key or p == alt) for g, p in exempt)


def scan_swift(text):
    """引号感知扫描，返回 [(行, 字面量原文, 本行代码前缀, 上一条有内容行)]。

    - 只有字符串外 的 // 与 /* */ 才算注释（否则 otpauth:// / https:// 被吞）；
    - 遇到 \\( 整段捕获到配对右括号（内部允许嵌套括号与字符串），避免内层引号截断；
    - 注释行/空行不覆盖「上一条有内容行」，跨行诊断调用仍可判定。
    """
    rows = []
    i, n, line = 0, len(text), 1
    in_str = in_blk = False
    buf = []
    start = 1
    prefix = []
    prev_code = ""

    def roll():
        cur = "".join(prefix)
        return cur if cur.strip() else prev_code

    while i < n:
        c = text[i]
        if in_blk:
            if text.startswith("*/", i):
                in_blk = False
                i += 2
            else:
                if c == "\n":
                    line += 1
                    prev_code, prefix = roll(), []
                i += 1
            continue
        if in_str:
            if c == "\\" and i + 1 < n and text[i + 1] == "(":
                depth, j, inner = 0, i + 1, False
                while j < n:
                    ch = text[j]
                    if inner:
                        if ch == "\\":
                            j += 2
                            continue
                        if ch == '"':
                            inner = False
                        j += 1
                        continue
                    if ch == '"':
                        inner = True
                    elif ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                buf.append(text[i:j + 1])
                i = j + 1
                continue
            if c == "\\" and i + 1 < n:
                buf.append(c)
                buf.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                rows.append((start, "".join(buf), "".join(prefix), prev_code))
                in_str = False
                buf = []
                prefix.append('"')
                i += 1
                continue
            if c == "\n":
                line += 1
                prev_code, prefix = roll(), []
            buf.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            in_blk = True
            i += 2
            continue
        if c == '"':
            in_str = True
            start = line
            buf = []
            i += 1
            continue
        if c == "\n":
            line += 1
            prev_code, prefix = roll(), []
            i += 1
            continue
        prefix.append(c)
        i += 1
    return rows


def unescape(s):
    """还原 \\n \\t \\r \\" 与 \\\\；但 \\( 是插值标记，必须原样保留。"""
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            e = s[i + 1]
            if e == "(":
                out.append("\\(")
                i += 2
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(e, e))
            i += 2
            continue
        out.append(s[i])
        i += 1
    return "".join(out)


def is_diag(ctx):
    return any(call in ctx for call in DIAG_CALLS)


pending, diag = [], []
for dirpath, dirs, files in os.walk(src_dir):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for name in sorted(files):
        if not name.endswith(".swift"):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, src_dir)
        for lineno, rawlit, prefix, prev in scan_swift(open(path, encoding="utf-8").read()):
            if not CJK.search(rawlit):
                continue
            key = unescape(rawlit)
            if key in tbl or norm(key) in tbl_norm or is_exempt(rel, key):
                continue
            item = "%s:%d  %s" % (rel, lineno, key.replace("\n", "\\n"))
            (diag if is_diag(prefix + " " + prev) else pending).append(item)

seen, uniq = set(), []
for item in pending:
    body = item.split("  ", 1)[1]
    if body not in seen:
        seen.add(body)
        uniq.append(item)

if not quiet:
    print("== l10n 反向覆盖检查（表 %d 键）==" % len(tbl))
    print("   诊断面未命中（DiagLog/print/assert…，设计 §2 范围外，不阻断）: %d 条" % len(diag))
    print("   非诊断面未命中（需人工分类：文案→补键；数据→登记例外）: %d 条" % len(uniq))

if uniq:
    print("-" * 56)
    for item in uniq:
        print("   " + item)
    print("-" * 56)
    print("提示：确认为文案 → 补进对应分片；确认为数据/非语言 → 加进 tools/l10n_exceptions.txt。")
    sys.exit(1)

if not quiet:
    print("OK：非诊断面未命中为 0")
sys.exit(0)
PY
