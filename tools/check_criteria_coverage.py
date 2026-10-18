#!/usr/bin/env python3
"""check_criteria_coverage.py —— 验收判据 → 测试覆盖核对。

判据来源：`docs/04-测试与验收/*验收判据*.md` 的表格行。判定键取行内的判据 ID
（`A-1` / `FR-5.3` / `AC-2.10.0-EN-1` / `IT-01` …），无判据 ID 时取 `TC-*` 用例 ID；
同一行/同一判据的多处出现合并为一条，避免重复计数与结论冲突。

覆盖来源只用**测试代码**（`tests/`、`macos/**/Tests/`、含 `#[test]`/`#[cfg(test)]` 的文件），
且只取函数名与注释/签名行——不含 fixture 数据、生产代码与 `vendor/`。

三级判定：
- COVERED   —— 测试函数名或测试文件注释中出现判据 ID（原文或归一化形态）
- TRACE     —— 判据行指明了仓库中存在的测试载体文件，且该文件内出现该 ID
- UNCOVERED —— 两者皆无

验证方式含「真机 / 走查 / 手动 / 审读 / 人工」且不含自动化关键词 → MANUAL（不计未覆盖）。

退出码：0 = 无未覆盖；1 = 存在未覆盖且指定 --strict；2 = 工具不可用（判据文档缺失/解析为 0 行）。
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs" / "04-测试与验收"

CRIT_ID_RE = re.compile(
    r"^((?:AC|FR|IT|UT|RT|GATE|EN|UX|J|A|W|T|D)-[0-9][0-9A-Za-z.\-]*)"
)
TC_ID_RE = re.compile(r"^TC-[A-Za-z0-9][A-Za-z0-9-]*$")

MANUAL_WORDS = ("真机", "走查", "手动", "审读", "人工")
AUTO_WORDS = ("单测", "集成", "UITest", "自动化")
AUTO_ASCII_RE = re.compile(r"(?<![A-Za-z])(AX|E2E)(?![A-Za-z])")

FN_RE = re.compile(r"\b(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
CARRIER_REF_RE = re.compile(r"[A-Za-z0-9_\-./]+\.(?:sh|rs|swift|py)")


def latest_doc() -> Path | None:
    """取编号最大的验收判据文档（只认文件名含「验收判据」的 md）。"""
    if not DOCS_DIR.is_dir():
        return None
    docs = list(DOCS_DIR.glob("*验收判据*.md"))

    def number(p: Path) -> int:
        m = re.match(r"(\d+)", p.name)
        return int(m.group(1)) if m else -1

    return max(docs, key=number) if docs else None


def clean_cell(cell: str) -> str:
    """去掉 markdown 加粗/反引号，便于 ID 识别。"""
    return cell.strip().strip("*`").strip()


def ids_in_cell(cell: str, pattern: re.Pattern[str]) -> list[str]:
    """单元格内可能用 `/` 并列多个 ID（如 `W-3/W-4`）。"""
    out: list[str] = []
    for part in clean_cell(cell).split("/"):
        m = pattern.match(part.strip())
        if m:
            out.append(m.group(1) if m.groups() else m.group(0))
    return out


def variants(alias: str) -> list[str]:
    """原文与归一化形态：AC-2.10.0-EN-1 → ac-2.10.0-en-1 / ac2_10_0_1 / ac2100en1。"""
    low = alias.lower()
    forms = {
        low,
        low.replace(".", "_").replace("-", ""),
        low.replace(".", "").replace("-", ""),
    }
    return [f for f in forms if f]


def token_hit(variant: str, text: str) -> bool:
    """按词边界匹配，避免 a3 命中 sha3、w1 命中 w11 这类子串假阳性。"""
    return re.search(r"(?<![a-z0-9])" + re.escape(variant) + r"(?![a-z0-9])", text) is not None


def method_cells(cells: list[str], key_cells: set[int]) -> str:
    """优先取含验证方式关键词的单元格；没有则退回整行。"""
    picked = [
        c
        for i, c in enumerate(cells)
        if i not in key_cells
        and (any(w in c for w in MANUAL_WORDS) or any(w in c for w in AUTO_WORDS) or AUTO_ASCII_RE.search(c))
    ]
    return " ".join(picked) if picked else " ".join(c for i, c in enumerate(cells) if i not in key_cells)


def parse_criteria(doc: Path) -> list[dict]:
    """返回 [{key, aliases, method, lineno}]；同一行的多个判据 ID 各成一条。"""
    out: list[dict] = []
    for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue

        crit: list[str] = []
        crit_cells: set[int] = set()
        for i, cell in enumerate(cells[:3]):
            found = ids_in_cell(cell, CRIT_ID_RE)
            if found:
                crit.extend(found)
                crit_cells.add(i)

        tc: list[str] = []
        tc_cells: set[int] = set()
        for i, cell in enumerate(cells[:4]):
            found = ids_in_cell(cell, TC_ID_RE)
            if found:
                tc.extend(found)
                tc_cells.add(i)

        if not crit and not tc:
            continue
        keys = crit or tc
        key_cell_ids = crit_cells | tc_cells
        method = method_cells(cells, key_cell_ids)
        aliases = tuple(dict.fromkeys(crit + tc))
        for key in keys:
            out.append({"key": key, "aliases": aliases, "method": method, "lineno": lineno})
    return out


def is_manual(method: str) -> bool:
    has_manual = any(w in method for w in MANUAL_WORDS)
    has_auto = any(w in method for w in AUTO_WORDS) or AUTO_ASCII_RE.search(method) is not None
    return has_manual and not has_auto


def test_file_filter(path: Path, text: str) -> bool:
    p = path.as_posix().lower()
    if "/vendor/" in p or "/target/" in p or "/.build/" in p:
        return False
    if "/tests/" in p:
        return True
    return path.suffix == ".rs" and ("#[test]" in text or "#[cfg(test)]" in text)


def collect_test_corpus() -> tuple[set[str], str]:
    """返回 (测试函数名集合, 测试文件注释/签名行文本)；不含 fixture 数据与生产代码。"""
    names: set[str] = set()
    lines: list[str] = []
    for base in (ROOT / "core", ROOT / "macos"):
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in {".rs", ".swift"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if not test_file_filter(path, text):
                continue
            names.update(n.lower() for n in FN_RE.findall(text))
            for raw in text.splitlines():
                s = raw.strip()
                if s.startswith("//") or s.startswith("#[") or s.startswith("@") or "fn " in s:
                    lines.append(s.lower())
    return names, "\n".join(lines)


def collect_carriers() -> dict[str, Path]:
    """测试载体文件索引：文件名与仓库相对路径 → 路径。"""
    index: dict[str, Path] = {}
    for base in (ROOT / "tools", ROOT / "core", ROOT / "macos"):
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix not in {".sh", ".rs", ".swift", ".py"}:
                continue
            rel = path.relative_to(ROOT).as_posix()
            if re.search(r"test|harness", path.name, re.IGNORECASE) or "/tests/" in rel.lower():
                index.setdefault(path.name, path)
                index.setdefault(rel, path)
    return index


def trace_hit(method: str, aliases: tuple[str, ...], carriers: dict[str, Path]) -> str | None:
    """判据行提到的载体文件存在，且文件内容确实引用了该判据 ID。"""
    for ref in CARRIER_REF_RE.findall(method):
        path = carriers.get(ref) or carriers.get(ref.rsplit("/", 1)[-1])
        if path is None:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if any(token_hit(v, text) for a in aliases for v in variants(a)):
            return ref
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="验收判据 → 测试覆盖核对")
    parser.add_argument("--doc", type=Path, default=None, help="判据文档（默认取编号最大的 *验收判据*.md）")
    parser.add_argument("--strict", action="store_true", help="存在未覆盖时退出码 1")
    parser.add_argument("--list", action="store_true", help="逐条打印 COVERED/TRACE/MANUAL/UNCOVERED")
    args = parser.parse_args()

    doc = args.doc or latest_doc()
    if doc is None or not doc.is_file():
        print("CRITERIA: 未找到判据文档（docs/04-测试与验收/*验收判据*.md）", file=sys.stderr)
        return 2

    criteria = parse_criteria(doc)
    if not criteria:
        print(f"CRITERIA: {doc} 中未解析到判据行（首列判据 ID 或 TC-* ID）", file=sys.stderr)
        return 2

    # 同一判据可能出现在汇总表与明细表：按判定键合并，别名取并集
    groups: dict[str, dict] = {}
    for row in criteria:
        g = groups.setdefault(row["key"], {"aliases": set(), "methods": [], "lineno": row["lineno"]})
        g["aliases"].update(row["aliases"])
        g["methods"].append(row["method"])

    names, corpus = collect_test_corpus()
    carriers = collect_carriers()
    covered = traced = manual = 0
    uncovered: list[str] = []
    for key, g in groups.items():
        method = " || ".join(g["methods"])
        if is_manual(method):
            manual += 1
            if args.list:
                print(f"MANUAL    {key}")
            continue
        alias_variants = [v for a in g["aliases"] for v in variants(a)]
        if any(token_hit(v, name) for v in alias_variants for name in names) or any(
            token_hit(v, corpus) for v in alias_variants
        ):
            covered += 1
            if args.list:
                print(f"COVERED   {key}")
            continue
        ref = trace_hit(method, tuple(g["aliases"]), carriers)
        if ref:
            traced += 1
            if args.list:
                print(f"TRACE     {key}  ({ref})")
            continue
        uncovered.append(key)
        if args.list:
            print(f"UNCOVERED {key}  ({doc.name}:{g['lineno']})")

    print("----------------------------------------")
    print(
        f"CRITERIA({doc.name}): {len(groups)} 条，"
        f"{covered} 覆盖 / {traced} 载体 / {len(uncovered)} 未覆盖 / {manual} 人工"
    )
    if uncovered:
        print("未覆盖：" + " ".join(uncovered))
    if uncovered and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
