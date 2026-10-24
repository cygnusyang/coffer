#!/usr/bin/env bash
# check_l10n.sh —— 多语言静态门禁（v2.13.0，docs/03-功能设计/24-v2.13.0-多语言-设计.md §4.5）。
#
# 硬门禁失败 → exit 1（构建中止）；软报只输出清单，不阻断（渐进翻译）。
#
#   G1 每个分片存在且 plutil -lint 通过；UTF-8 无 BOM；合并后非空
#   G2 跨分片无重复键（同键同值也报，强制归一到 00-common）
#   G3 每条 "key" = "value" 的 printf 占位符数量/类型一致，且无未转义 %
#   G4 en/InfoPlist.strings 存在、lint 通过、含 NSCameraUsageDescription
#   G5 已声明键（tools/l10n_keys_allow.txt）必须能在源码中找到出处，否则「死键」
#   G6 源码字面量键 vs en 键集 → 未翻译清单 + 覆盖率（软）
#   G7 输出分片归属统计（软）
#
# 为什么 G3 必须是硬的：占位符写错（%d vs %lld / 漏占位符 / 多占位符）在运行时
# **全部静默**（不崩不报，只是显示错值或丢值，设计 F8）。静态检查是唯一能拦住
# 它们的地方，且零假阳性（只看 .strings 自身）。G6 相反：源侧键抽取靠正则 +
# 插值类型推断，必然有假阳性，只报数不进硬门禁（设计 §4.5「G6 的诚实边界」）。
#
# 依赖：bash 3.2（macOS 自带）+ python3（系统自带）+ plutil（系统自带）。无第三方。
#
# 用法：
#   ./tools/check_l10n.sh                  # 全量门禁（G1–G7）
#   ./tools/check_l10n.sh --resources-only # 只跑 G1–G4（不看源码；供
#                                          # build_l10n_resources.sh 与夹具测试复用）
#
# 环境变量覆盖（夹具测试用，均带仓库内默认值）：
#   L10N_LOCALIZATION_DIR  默认 macos/Coffer/Resources/Localization
#   L10N_SOURCE_DIR        默认 macos/Coffer
#   L10N_ALLOW_FILE        默认 tools/l10n_keys_allow.txt
#   L10N_EXCEPTIONS_FILE   默认 tools/l10n_exceptions.txt
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RESOURCES_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --resources-only) RESOURCES_ONLY=1; shift ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'ERROR: 未知参数: %s（可用: --resources-only）\n' "$1" >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { printf 'ERROR: 未找到 python3（系统自带，装 Xcode CLT 即有）。\n' >&2; exit 2; }
command -v plutil >/dev/null 2>&1 || { printf 'ERROR: 未找到 plutil。\n' >&2; exit 2; }

LOCALIZATION_DIR="${L10N_LOCALIZATION_DIR:-${ROOT_DIR}/macos/Coffer/Resources/Localization}"
SOURCE_DIR="${L10N_SOURCE_DIR:-${ROOT_DIR}/macos/Coffer}"
ALLOW_FILE="${L10N_ALLOW_FILE:-${ROOT_DIR}/tools/l10n_keys_allow.txt}"
EXCEPTIONS_FILE="${L10N_EXCEPTIONS_FILE:-${ROOT_DIR}/tools/l10n_exceptions.txt}"

printf '== check_l10n.sh（设计 24 §4.5 G1–G7）==\n'
printf '资源目录: %s\n' "${LOCALIZATION_DIR}"
[[ "${RESOURCES_ONLY}" == "1" ]] && printf '模式: --resources-only（只跑 G1–G4）\n'

python3 - "${LOCALIZATION_DIR}" "${SOURCE_DIR}" "${ALLOW_FILE}" "${EXCEPTIONS_FILE}" "${RESOURCES_ONLY}" <<'PY'
import fnmatch
import os
import re
import subprocess
import sys

localization_dir, source_dir, allow_file, exceptions_file, resources_only = sys.argv[1:6]
resources_only = resources_only == "1"

# 设计 §4.1 的 5 个分片：文件名序 = 合并序 = 归属。缺一个 = 某组译文静默消失，
# 故按硬门禁要求全部存在（只留注释的空骨架合法，见 §4.3）。
SHARDS = [
    "00-common.strings",
    "10-ui-a.strings",
    "20-ui-b.strings",
    "30-support.strings",
    "40-errors.strings",
]

errors = []
warnings = []
report = []


def err(gate, msg):
    errors.append("[%s] %s" % (gate, msg))


def warn(gate, msg):
    warnings.append("[%s] %s" % (gate, msg))


class ParseError(Exception):
    pass


# ---------------------------------------------------------------- .strings 解析

def _skip_trivia(text, i, line):
    """跳过空白与注释，返回 (i, line)。"""
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ParseError("第 %d 行：段注释 /* 未闭合" % line)
            line += text.count("\n", i, j)
            i = j + 2
        elif text.startswith("//", i):
            j = text.find("\n", i + 2)
            i = n if j < 0 else j
        else:
            break
    return i, line


def _parse_quoted(text, i, line):
    r"""解析一个带引号字符串，返回 (已解转义的值, 新位置, 新行号)。

    只解 \" \\ \n \t \r U+XXXX；**保留** % 序列原样——占位符校验要看原文。
    """
    if i >= len(text) or text[i] != '"':
        raise ParseError("第 %d 行：期望以引号开头的键或值" % line)
    i += 1
    out = []
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            return "".join(out), i + 1, line
        if c == "\n":
            raise ParseError("第 %d 行：字符串未闭合（跨行）" % line)
        if c == "\\":
            if i + 1 >= n:
                raise ParseError("第 %d 行：字符串以反斜杠结尾" % line)
            e = text[i + 1]
            if e == "n":
                out.append("\n")
            elif e == "t":
                out.append("\t")
            elif e == "r":
                out.append("\r")
            elif e in '"\\':
                out.append(e)
            elif e == "U":
                hexpart = text[i + 2:i + 6]
                if len(hexpart) < 4 or not re.match(r"^[0-9A-Fa-f]{4}$", hexpart):
                    raise ParseError("第 %d 行：U 转义需要 4 位十六进制" % line)
                out.append(chr(int(hexpart, 16)))
                i += 4
            else:
                raise ParseError("第 %d 行：未知转义 \\%s" % (line, e))
            i += 2
            continue
        out.append(c)
        i += 1
    raise ParseError("第 %d 行：字符串未闭合（到文件尾）" % line)


def parse_strings(path):
    """解析 old-style plist（.strings），返回 [(key, value, line)]。"""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("非 UTF-8 编码：%s" % exc)
    entries = []
    i, line = _skip_trivia(text, 0, 1)
    n = len(text)
    while i < n:
        key, i, line = _parse_quoted(text, i, line)
        i, line = _skip_trivia(text, i, line)
        if i >= n or text[i] != "=":
            raise ParseError("第 %d 行：键 %s 后缺等号" % (line, key))
        i, line = _skip_trivia(text, i + 1, line)
        value, i, line = _parse_quoted(text, i, line)
        i, line = _skip_trivia(text, i, line)
        if i >= n or text[i] != ";":
            raise ParseError("第 %d 行：键 %s 的值后缺分号" % (line, key))
        i, line = _skip_trivia(text, i + 1, line)
        entries.append((key, value, line))
    return entries


# ------------------------------------------------------------ 占位符扫描（G3 核心）

# printf 转换规格：(位置索引)?(标志)*(宽度)?(.精度)?(长度修饰)?(转换符)
SPEC_RE = re.compile(r"%(?:(\d+)$)?([-+ 0#']*)(\d+)?(?:\.(\d+))?(hh|h|ll|l|q|L|z|t|j)?([@dDiuUxXoOfFeEgGcCsSpaA])")


def scan_placeholders(s):
    """返回 (tokens, bare_offsets)。

    token = (是否位置参数, 类型串)；类型串保留长度修饰，故 %d 不等于 %lld（F8 的静默坑）。
    """
    tokens = []
    bare = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] != "%":
            i += 1
            continue
        if s.startswith("%%", i):
            i += 2
            continue
        m = SPEC_RE.match(s, i)
        if not m:
            bare.append(i)
            i += 1
            continue
        idx, _flags, _width, _prec, length, conv = m.groups()
        tokens.append((idx is not None, (length or "") + conv))
        i = m.end()
    return tokens, bare


def normalize_for_matching(s):
    """把任意占位符/转义 %% 折叠成一个标记，用于 G6 的启发式键比对。"""
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "%":
            if s.startswith("%%", i):
                out.append("%")
                i += 2
                continue
            if s.startswith("%?", i):
                out.append("?")
                i += 2
                continue
            m = SPEC_RE.match(s, i)
            if m:
                out.append("?")
                i = m.end()
                continue
        out.append(s[i])
        i += 1
    return "".join(out)


# ---------------------------------------------------------------- G1 分片存在与格式

shard_entries = []   # [(shard_name, entries)]
for shard in SHARDS:
    path = os.path.join(localization_dir, "en", shard)
    if not os.path.isfile(path):
        err("G1", "缺分片：%s" % path)
        continue
    with open(path, "rb") as fh:
        head = fh.read(3)
    if head == b"\xef\xbb\xbf":
        err("G1", "%s 带 UTF-8 BOM（设计 §4.6 要求无 BOM）" % shard)
        continue
    lint = subprocess.run(["plutil", "-lint", path], capture_output=True, text=True)
    if lint.returncode != 0:
        err("G1", "%s plutil -lint 失败：%s" % (shard, (lint.stdout + lint.stderr).strip()))
        continue
    try:
        entries = parse_strings(path)
    except ParseError as exc:
        err("G1", "%s 语法错误：%s" % (shard, exc))
        continue
    shard_entries.append((shard, entries))

total_entries = sum(len(e) for _, e in shard_entries)
if shard_entries and total_entries == 0 and not errors:
    err("G1", "合并后为空：所有分片都没有条目（英文界面会全中文且无报错）")

# G7：分片归属统计（软）
for shard, entries in shard_entries:
    report.append("[G7] %-20s %3d 条" % (shard, len(entries)))
report.append("[G7] %-20s %3d 条" % ("合计", total_entries))

# ---------------------------------------------------------------- G2 跨分片重复键

seen = {}
for shard, entries in shard_entries:
    for key, _value, line in entries:
        seen.setdefault(key, []).append("%s:%d" % (shard, line))
for key, places in sorted(seen.items()):
    if len(places) > 1:
        err("G2", "重复键 %s（%s）：同键同值也须归一到 00-common" % (key, "、".join(places)))

# ---------------------------------------------------------------- G3 占位符一致性

for shard, entries in shard_entries:
    for key, value, line in entries:
        where = "%s:%d" % (shard, line)
        if not value.strip():
            err("G3", "%s 键 %s 的译文为空" % (where, key))
            continue
        key_tokens, key_bare = scan_placeholders(key)
        val_tokens, val_bare = scan_placeholders(value)

        # 纯字面量（两侧都无占位符）不做 printf 校验：按设计 §5.1 K4，只有带插值的
        # 键才把源码里的 % 转义成 %%；纯 Text("完成率 100%") 的键就是原文。
        if not key_tokens and not val_tokens:
            continue

        if key_bare:
            err("G3", "%s 键 %s 含未转义百分号（带插值的键必须写成双百分号）" % (where, key))
        if val_bare:
            err("G3", "%s 键 %s 的译文含未转义百分号：%s" % (where, key, value))
        if key_bare or val_bare:
            continue

        if len(key_tokens) != len(val_tokens):
            err("G3", "%s 键 %s 占位符数量不一致：键 %d 个 / 译文 %d 个（键 %s → 值 %s）"
                % (where, key, len(key_tokens), len(val_tokens), key, value))
            continue

        key_types = [t for _, t in key_tokens]
        val_types = [t for _, t in val_tokens]
        # 译文用位置参数（如 1 号参数）时允许重排——printf 语义上安全；否则顺序即
        # 参数序，重排会把值填到错误位置（与 F8「多占位符填垃圾值」同族的静默错误）。
        if any(p for p, _ in val_tokens) or any(p for p, _ in key_tokens):
            key_cmp, val_cmp = sorted(key_types), sorted(val_types)
        else:
            key_cmp, val_cmp = key_types, val_types
        if key_cmp != val_cmp:
            err("G3", "%s 键 %s 占位符不匹配：键 %s / 译文 %s（键 %s → 值 %s）"
                % (where, key, key_types, val_types, key, value))

# ---------------------------------------------------------------- G4 InfoPlist.strings

info_plist_strings = os.path.join(localization_dir, "InfoPlist.strings")
if not os.path.isfile(info_plist_strings):
    err("G4", "缺 en/InfoPlist.strings（英文用户会看到中文权限弹窗，系统弹窗不参与表回落）")
else:
    lint = subprocess.run(["plutil", "-lint", info_plist_strings], capture_output=True, text=True)
    if lint.returncode != 0:
        err("G4", "InfoPlist.strings plutil -lint 失败：%s" % (lint.stdout + lint.stderr).strip())
    else:
        try:
            info_entries = parse_strings(info_plist_strings)
        except ParseError as exc:
            err("G4", "InfoPlist.strings 语法错误：%s" % exc)
            info_entries = []
        camera = [v for k, v, _l in info_entries if k == "NSCameraUsageDescription"]
        if not camera:
            err("G4", "InfoPlist.strings 缺 NSCameraUsageDescription（TOTP 扫描权限弹窗）")
        elif not camera[0].strip():
            err("G4", "InfoPlist.strings 的 NSCameraUsageDescription 为空")

# ------------------------------------------------------------ G5 死键（声明键须有出处）

def read_list(path):
    """读行式清单：跳过空行与 # 注释，返回 [(行内容, 行号)]。"""
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            out.append((stripped, lineno))
    return out


def swift_sources(root):
    for dirpath, _dirnames, filenames in os.walk(root):
        if any(seg in dirpath for seg in ("CoreBindings", "Installer", "McpRegisterHelper", "Tests")):
            continue
        for name in filenames:
            if name.endswith(".swift"):
                yield os.path.join(dirpath, name)


allow_entries = read_list(allow_file)
en_keys = set(k for _s, entries in shard_entries for k, _v, _l in entries)

if not resources_only:
    # 声明键 = 允许清单里的键；它们必须仍能在源码中找到出处，否则是「死键」
    # （文案改了/删了，清单没人清，久了没人敢删——设计 §4.5 G5）。
    source_blob = []
    for path in swift_sources(source_dir):
        try:
            with open(path, encoding="utf-8") as fh:
                source_blob.append((path, fh.read()))
        except UnicodeDecodeError:
            warn("G5", "源码非 UTF-8，跳过：%s" % path)
    if not source_blob:
        err("G5", "源码目录下未找到 .swift：%s" % source_dir)

    for key, lineno in allow_entries:
        tokens, _bare = scan_placeholders(key)
        if tokens:
            # 插值键：把占位符还原成 Swift 插值形态，粗略匹配源码里的插值字面量。
            parts = []
            i = 0
            for m in re.finditer(r"%(?:\d+$)?[-+ 0#']*\d*(?:\.\d+)?(?:hh|h|ll|l|q|L|z|t|j)?[@dDiuUxXoOfFeEgGcCsSpaA]|%%|%\?", key):
                parts.append(re.escape(key[i:m.start()]))
                parts.append(r"\\\([^)]*\)" if m.group(0) != "%%" else "%")
                i = m.end()
            parts.append(re.escape(key[i:]))
            pattern = re.compile("".join(parts))
            hits = [p for p, text in source_blob if pattern.search(text)]
        else:
            needle = '"%s"' % key
            hits = [p for p, text in source_blob if needle in text]
        if not hits:
            err("G5", "死键：l10n_keys_allow.txt:%d 声明的 %s 在源码中找不到出处" % (lineno, key))

    # 声明的键若不在 en 表里，等于清单挂着一条永远不会生效的豁免。
    for key, lineno in allow_entries:
        if key not in en_keys:
            err("G5", "缺键：l10n_keys_allow.txt:%d 声明的 %s 不在 en 译表中" % (lineno, key))

# ---------------------------------------------------------------- G6 覆盖率（软）

if not resources_only:
    exceptions = read_list(exceptions_file)
    exempt_pairs = []
    for raw, lineno in exceptions:
        body = raw.split("#", 1)[0].strip()
        if not body:
            continue
        if ":" not in body:
            warn("G6", "l10n_exceptions.txt:%d 格式应为 文件:模式（%s）" % (lineno, raw))
            continue
        globpart, pattern = body.split(":", 1)
        exempt_pairs.append((globpart.strip(), pattern.strip()))

    def is_exempt(relpath, key, raw=None):
        # H2 修复：l10n_exceptions.txt 文件头约定「模式填源码字面量原文」，
        # 而匹配侧历史上只比归一化后的 `%?` 形式 —— 照文件头写的人会被当成没写。
        # 现在两者都认：先比原文，再比归一化形式。
        for globpart, pattern in exempt_pairs:
            if not fnmatch.fnmatch(relpath, globpart):
                continue
            if pattern == "*" or pattern == key or (raw is not None and pattern == raw):
                return True
        return False

    # 抽取面（H2 修复）：
    #   - 加左边界 (?<![A-Za-z0-9_]) —— 否则 `statLabel("…")` 会被 `Label` 分支子串命中，
    #     制造「已覆盖」的假绿（v2.13.1 审查中 statLabel 家族就栽在这条）。
    #   - 补 LocalizedStringKey / LabeledContent / ProgressView / Section / confirmationDialog：
    #     这几个入口此前完全不被抽取，导致 H1 的 4 条缺键只能靠人工发现。
    LITERAL_PATTERNS = [
        re.compile(r'(?<![A-Za-z0-9_])(?:Text|Button|Label|Toggle|LabeledContent|ProgressView|Section|LocalizedStringKey|confirmationDialog)\s*\(\s*"((?:[^"\\]|\\.)*)"'),
        re.compile(r'String\s*\(\s*localized:\s*"((?:[^"\\]|\\.)*)"'),
        re.compile(r'\.(?:navigationTitle|help|alert)\s*\(\s*"((?:[^"\\]|\\.)*)"'),
    ]
    allow_keys = set(k for k, _ in allow_entries)
    en_norm = set(normalize_for_matching(k) for k in en_keys)

    candidates = {}
    for path, text in source_blob:
        rel = os.path.relpath(path, source_dir)
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat in LITERAL_PATTERNS:
                for m in pat.finditer(line):
                    lit = m.group(1)
                    key = lit.replace('\\"', '"').replace("\\\\", "\\")
                    raw_key = key          # 例外文件里的「源码字面量原文」形式
                    key = re.sub(r"\\\([^)]*\)", "%?", key)
                    if not key.strip():
                        continue
                    if not re.search(r"[\u4e00-\u9fff]", key):
                        continue   # 已是英文/符号，不需要翻译
                    if key in allow_keys or is_exempt(rel, key, raw_key):
                        continue
                    candidates.setdefault(key, "%s:%d" % (rel, lineno))

    translated = [k for k in candidates if normalize_for_matching(k) in en_norm]
    missing = sorted(k for k in candidates if normalize_for_matching(k) not in en_norm)
    total = len(candidates)
    pct = (100.0 * len(translated) / total) if total else 100.0
    report.append("[G6] 源码字面量键 %d 条（去重），已翻 %d 条，覆盖率 %.1f%%"
                  % (total, len(translated), pct))
    if missing:
        report.append("[G6] 未翻译前 20 条（软报，不阻断）：")
        for key in missing[:20]:
            report.append("       %s  %s" % (candidates[key], key))
        if len(missing) > 20:
            report.append("       …… 其余 %d 条省略" % (len(missing) - 20))

# ---------------------------------------------------------------- 输出

for line in report:
    print(line)
for line in warnings:
    print("WARN  " + line)
for line in errors:
    print("ERROR " + line)

print("-" * 56)
if errors:
    print("FAIL：%d 项硬门禁未通过（构建应中止）" % len(errors))
    sys.exit(1)
print("OK：硬门禁全绿%s" % ("（--resources-only：未跑 G5/G6）" if resources_only else "（G1–G5；G6/G7 为软报）"))
sys.exit(0)
PY
