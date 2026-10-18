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
    if status == "done":
        sys.exit(f"ERROR: {args.id} 已完成，不能 claim")
    if status == "in_progress" and owner not in (EMPTY, args.owner):
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
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
