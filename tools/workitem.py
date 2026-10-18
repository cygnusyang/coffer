#!/usr/bin/env python3
"""workitem.py —— 任务板（docs/00-WORK-ITEMS.md）命令行维护。

本文件是通用版 ~/.claude/teams/scripts/workitem.py 的仓库内副本（CI 与协作者需要），
改动须两侧同步；任务板数据与协议适配留在本仓。

协议见 ~/.claude/teams/PROTOCOL.md。任务板是唯一 claim 入口：
未 claim 不得开工；同一文件同一时间只允许一个 owner。

用法：
  python3 tools/workitem.py list [--status pending]
  python3 tools/workitem.py add --id TASK-12 --type TASK --title "..." \
      [--owner NAME] [--files "path/**"] [--criteria "docs/..."] [--evidence "..."]
  python3 tools/workitem.py claim TASK-12 --owner dev-coder-ui [--files "path/**"]
  python3 tools/workitem.py status TASK-12 done --evidence "commit abc123"
  python3 tools/workitem.py done TASK-12 --evidence "log=/tmp/x.log exit=0"
  python3 tools/workitem.py check

状态：pending / in_progress / blocked / done / accepted
退出码：0 成功；1 校验失败或操作非法；2 用法错误。
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
from pathlib import Path

BOARD = Path(__file__).resolve().parent.parent / "docs" / "00-WORK-ITEMS.md"
HEADER = ["ID", "类型", "标题", "Owner", "状态", "files 范围", "判据/锚点", "关闭证据"]
STATUSES = {"pending", "in_progress", "blocked", "done", "accepted"}
ID_RE = re.compile(r"^\s*`?(TASK|BUG|GAP|UX|FR|DOC)-\d+`?\s*$")
EMPTY = "-"


def read_lines(board: Path) -> list[str]:
    if not board.exists():
        sys.exit(f"ERROR: 任务板不存在：{board}")
    return board.read_text(encoding="utf-8").splitlines()


def split_row(line: str) -> list[str]:
    parts = re.split(r"(?<!\\)\|", line.strip())
    return [p.strip().replace("\\|", "|") for p in parts[1:-1]]


def join_row(cells: list[str]) -> str:
    return "| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |"


def find_rows(lines: list[str]) -> list[tuple[int, list[str], str]]:
    rows = []
    for idx, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        cells = split_row(line)
        if cells and ID_RE.match(cells[0].strip("`")):
            rows.append((idx, cells, cells[0].strip("`")))
    return rows


def load_board(board: Path) -> tuple[list[str], list[tuple[int, list[str], str]]]:
    lines = read_lines(board)
    rows = find_rows(lines)
    for _, cells, _ in rows:
        if len(cells) != len(HEADER):
            sys.exit(
                f"ERROR: 任务板列数异常（期望 {len(HEADER)}，实际 {len(cells)}）："
                f"{join_row(cells)}"
            )
    return lines, rows


def locate(rows: list[tuple[int, list[str], str]], item_id: str) -> tuple[int, list[str]]:
    for idx, cells, rid in rows:
        if rid == item_id:
            return idx, cells
    sys.exit(f"ERROR: 任务板中找不到 {item_id}")


def write_lines(board: Path, lines: list[str]) -> None:
    board.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_list(args: argparse.Namespace) -> int:
    _, rows = load_board(args.board)
    shown = 0
    for _, cells, _ in rows:
        if args.status and cells[4] != args.status:
            continue
        print(" | ".join(cells))
        shown += 1
    print(f"--- {shown} 项 ---")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    lines, rows = load_board(args.board)
    if any(rid == args.id for _, _, rid in rows):
        sys.exit(f"ERROR: {args.id} 已存在")
    if not ID_RE.match(args.id):
        sys.exit(f"ERROR: ID 形态非法：{args.id}（须为 TASK/BUG/GAP/UX/FR/DOC-数字）")
    if args.status not in STATUSES:
        sys.exit(f"ERROR: 状态非法：{args.status}")
    cells = [
        args.id,
        args.type or args.id.split("-")[0],
        args.title,
        args.owner or EMPTY,
        args.status,
        args.files or EMPTY,
        args.criteria or EMPTY,
        args.evidence or EMPTY,
    ]
    new_line = join_row(cells)
    insert_at = rows[-1][0] + 1 if rows else None
    if insert_at is None:
        for idx, line in enumerate(lines):
            if re.match(r"^\|\s*-{3,}", line):
                insert_at = idx + 1
                break
    if insert_at is None:
        sys.exit("ERROR: 找不到任务板表格分隔行，拒绝写入")
    lines.insert(insert_at, new_line)
    write_lines(args.board, lines)
    print(f"ADDED {args.id}")
    return 0


def cmd_claim(args: argparse.Namespace) -> int:
    lines, rows = load_board(args.board)
    idx, cells = locate(rows, args.id)
    owner, status = cells[3], cells[4]
    if status in {"done", "accepted"}:
        sys.exit(f"ERROR: {args.id} 已完成（{status}），不能 claim")
    if status in {"in_progress", "blocked"} and owner not in (EMPTY, args.owner):
        sys.exit(f"ERROR: {args.id} 已被 {owner} claim；停止并联系占用者")
    cells[3] = args.owner
    cells[4] = "in_progress"
    if args.files:
        cells[5] = args.files
    lines[idx] = join_row(cells)
    write_lines(args.board, lines)
    print(f"CLAIMED {args.id} -> {args.owner}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    lines, rows = load_board(args.board)
    idx, cells = locate(rows, args.id)
    if args.new_status not in STATUSES:
        sys.exit(f"ERROR: 状态非法：{args.new_status}")
    if args.new_status in {"done", "accepted", "blocked"} and not args.evidence:
        sys.exit(f"ERROR: {args.new_status} 必须附 --evidence（done=关闭证据；accepted=理由+目标版本；blocked=原因+解除条件）")
    cells[4] = args.new_status
    if args.evidence:
        cells[7] = args.evidence
    lines[idx] = join_row(cells)
    write_lines(args.board, lines)
    print(f"STATUS {args.id} -> {args.new_status}")
    return 0


def cmd_done(args: argparse.Namespace) -> int:
    args.new_status = "done"
    return cmd_status(args)


EMPTY_TOKENS = {"", "-", "—", "–"}


def split_scopes(cell: str) -> list[str]:
    """把 files 单元格拆成若干路径/glob。

    逗号、分号、空白分隔；花括号内的逗号（`core/{a,b}/src`）不拆。
    """
    if cell.strip() in EMPTY_TOKENS:
        return []
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in cell:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        if ch in ",; \t\n" and depth == 0:
            if buf:
                out.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if buf:
        out.append("".join(buf))
    return [s for s in out if s not in EMPTY_TOKENS]


def literal_prefix(pattern: str) -> str:
    """取第一个通配符之前的字面前缀，用于保守判定两个范围是否可能重叠。"""
    pattern = pattern.strip().lstrip("./")
    cut = [pattern.find(c) for c in "*?[" if c in pattern]
    return pattern[: min(cut)] if cut else pattern


def expand_braces(pattern: str) -> list[str]:
    """`core/{a,b}/src` → [`core/a/src`, `core/b/src`]。"""
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    out: list[str] = []
    for alt in m.group(1).split(","):
        out.extend(expand_braces(pattern[: m.start()] + alt + pattern[m.end():]))
    return out


def _overlap(a: str, b: str) -> bool:
    pa, pb = literal_prefix(a), literal_prefix(b)
    # `**`、`*`、`*.rs` 这类从根开始的范围与任何范围都可能重叠
    if not pa or not pb:
        return True
    if a == b:
        return True
    # 通配符可能落在目录中间（`core/cf-*/src` × `core/cf-domain/src`）
    if fnmatch.fnmatch(pb.rstrip("/"), a) or fnmatch.fnmatch(pa.rstrip("/"), b):
        return True
    # 前缀本身可能是词中截断（`core/cf-*` 的前缀 `core/cf-`、`docs/0*.md` 的 `docs/0`），
    # 此时不能要求 `/` 边界，否则 `core/cf-*/src` × `core/cf-mcp/src/uds.rs` 会漏判。
    return pa.startswith(pb) or pb.startswith(pa)


def scopes_conflict(a: str, b: str) -> bool:
    """保守判定两个范围是否可能改到同一文件（宁可误报，不可漏报）。"""
    return any(_overlap(x, y) for x in expand_braces(a) for y in expand_braces(b))


def cmd_conflicts(args: argparse.Namespace) -> int:
    """列出声明的 files 范围之间的冲突；同一文件同一时间只允许一个 owner。"""
    _, rows = load_board(args.board)
    active = []
    for _, cells, rid in rows:
        status = cells[4]
        if not args.all and status != "in_progress":
            continue
        scopes = split_scopes(cells[5])
        if scopes:
            active.append((rid, cells[3], scopes))

    parent = {rid: rid for rid, _, _ in active}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    conflicts: list[str] = []
    for i in range(len(active)):
        for j in range(i + 1, len(active)):
            rid_a, owner_a, scopes_a = active[i]
            rid_b, owner_b, scopes_b = active[j]
            # 协议约束的是「同一文件不得有两个 owner」；同一 owner 的多个范围不是冲突
            if owner_a == owner_b and owner_a not in EMPTY_TOKENS:
                continue
            hits = [
                (sa, sb)
                for sa in scopes_a
                for sb in scopes_b
                if scopes_conflict(sa, sb)
            ]
            if hits:
                conflicts.append(
                    f"CONFLICT {rid_a}({owner_a}) × {rid_b}({owner_b}): "
                    + ", ".join(f"{sa} ∩ {sb}" for sa, sb in hits)
                )
                ra, rb = find(rid_a), find(rid_b)
                if ra != rb:
                    parent[rb] = ra

    groups: dict[str, list[str]] = {}
    for rid, owner, _ in active:
        groups.setdefault(find(rid), []).append(f"{rid}({owner})")
    serial = [" + ".join(v) for v in groups.values() if len(v) > 1]
    parallel = [v[0] for v in groups.values() if len(v) == 1]

    for line in conflicts:
        print(line)
    for g in serial:
        print(f"SERIAL   {g}")
    for p in parallel:
        print(f"PARALLEL {p}")
    print(
        f"CONFLICTS: {len(active)} 个进行中工作项，{len(conflicts)} 对冲突，"
        f"{len(serial)} 个串行组 / {len(parallel)} 个可并行"
    )
    if conflicts and args.strict:
        return 1
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    _, rows = load_board(args.board)
    errors: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for _, cells, rid in rows:
        if rid in seen:
            errors.append(f"{rid}: ID 重复")
        seen.add(rid)
        owner, status, files, evidence = cells[3], cells[4], cells[5], cells[7]
        if status not in STATUSES:
            errors.append(f"{rid}: 状态非法 `{status}`")
        if status in {"in_progress", "blocked", "done", "accepted"} and owner == EMPTY:
            errors.append(f"{rid}: {status} 必须指定 Owner")
        if status in {"done", "accepted", "blocked"} and evidence == EMPTY:
            errors.append(f"{rid}: {status} 必须填写关闭证据/理由")
        if status == "in_progress" and files == EMPTY:
            warnings.append(f"{rid}: in_progress 未声明 files 范围")
    for err in errors:
        print(f"ERROR {err}")
    for warn in warnings:
        print(f"WARN  {warn}")
    print(f"WORKITEMS: {len(rows)} 项，{len(errors)} ERROR / {len(warnings)} WARN")
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="任务板维护（docs/00-WORK-ITEMS.md）")
    p.add_argument("--board", type=Path, default=BOARD, help="任务板路径")
    sub = p.add_subparsers(dest="command", required=True)

    pl = sub.add_parser("list", help="列出工作项")
    pl.add_argument("--status", choices=sorted(STATUSES))
    pl.set_defaults(func=cmd_list)

    pa = sub.add_parser("add", help="新增工作项")
    pa.add_argument("--id", required=True)
    pa.add_argument("--type", choices=["TASK", "BUG", "GAP", "UX", "FR", "DOC"])
    pa.add_argument("--title", required=True)
    pa.add_argument("--owner")
    pa.add_argument("--status", default="pending", choices=sorted(STATUSES))
    pa.add_argument("--files")
    pa.add_argument("--criteria")
    pa.add_argument("--evidence")
    pa.set_defaults(func=cmd_add)

    pc = sub.add_parser("claim", help="认领工作项")
    pc.add_argument("id")
    pc.add_argument("--owner", required=True)
    pc.add_argument("--files")
    pc.set_defaults(func=cmd_claim)

    ps = sub.add_parser("status", help="更新状态")
    ps.add_argument("id")
    ps.add_argument("new_status", choices=sorted(STATUSES))
    ps.add_argument("--evidence")
    ps.set_defaults(func=cmd_status)

    pd = sub.add_parser("done", help="标记完成（= status done）")
    pd.add_argument("id")
    pd.add_argument("--evidence", required=True)
    pd.set_defaults(func=cmd_done)

    pk = sub.add_parser("check", help="校验任务板完整性")
    pk.set_defaults(func=cmd_check)

    pf = sub.add_parser("conflicts", help="检查进行中工作项的 files 范围冲突")
    pf.add_argument("--all", action="store_true", help="含非 in_progress 项")
    pf.add_argument("--strict", action="store_true", help="存在冲突时退出码 1")
    pf.set_defaults(func=cmd_conflicts)
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
