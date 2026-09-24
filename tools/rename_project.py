#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rename_project.py —— 项目代号与 crate 前缀的整体改名工具

用途
    一次性替换：项目代号、crate 前缀、仓库占位名，覆盖
      · 所有文本文件的内容（文档、治理文件、Cargo.toml、Rust 源码、脚本）
      · Rust 代码中的 crate 引用（lv_crypto → cf_crypto）

    注意：**crate 目录名的重命名不在本脚本内**（用 git mv 更干净，能保留历史）。

用法
    # 1. 先干跑，看清会改哪些文件、各改多少处
    python3 tools/rename_project.py --name Coffer --prefix cf --dry-run

    # 2. 确认无误后执行
    python3 tools/rename_project.py --name Coffer --prefix cf --apply

设计要点
    · 替换按「长串优先」排序，避免短串先命中导致二次替换
    · 每个模式先统计总数，任何一处为 0 都会告警（防止旧名拼错导致静默失败）
    · 排除 .git / target / __pycache__ 等目录与二进制文件
    · dry-run 与 apply 走同一条代码路径，避免"看到的"和"改掉的"不一致
"""

import argparse
import pathlib
import sys

# 当前（旧）标识 —— 若项目再次改名，改这里即可
OLD_NAME_PASCAL = "LocalVault"
OLD_NAME_LOWER = "localvault"
OLD_REPO_SLACE = "mypassword"
OLD_PREFIX = "lv"

SKIP_DIRS = {".git", "target", "__pycache__", "node_modules", ".venv", "venv",
             "build", "DerivedData", ".gradle"}
SKIP_EXTS = {".1pux", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".so",
             ".a", ".dylib", ".bin", ".ico", ".woff", ".woff2", ".ttf"}

TEXT_EXTS = {".md", ".toml", ".rs", ".py", ".txt", ".yml", ".yaml", ".json",
             ".gitignore", ".xml", ".kt", ".swift", ".sh", ""}


def build_patterns(new_name: str, new_prefix: str) -> list[tuple[str, str]]:
    """构造替换对，按「长串优先」排序。"""
    lower = new_name.lower()
    pairs = [
        # 1. 项目代号（大小写两种形式）
        (OLD_NAME_PASCAL, new_name),
        (OLD_NAME_LOWER, lower),
        # 2. 仓库占位名
        (OLD_REPO_SLACE, lower),
        # 3. crate 前缀：包名/目录名用连字符
        (f"{OLD_PREFIX}-", f"{new_prefix}-"),
        # 4. crate 前缀：Rust 代码引用用下划线
        (f"{OLD_PREFIX}_", f"{new_prefix}_"),
        # 5. PascalCase 前缀：类型名前缀，如 LvCryptoError → CfCryptoError
        #    ⚠️ 这一条最容易漏。首次改名时就漏了它，导致 LvCryptoError 未被替换 ——
        #    因为 "Lv" 既不等于 "lv-" 也不等于 "lv_"，前 4 条模式全都匹配不上。
        (OLD_PREFIX.capitalize(), new_prefix.capitalize()),
        # 6. 全大写前缀（常量、环境变量等，若存在）
        (f"{OLD_PREFIX.upper()}_", f"{new_prefix.upper()}_"),
    ]
    # 长串优先：防止 "lv-" 先在 "lv-crypto" 中命中而影响后续判断
    return sorted(pairs, key=lambda p: -len(p[0]))


def iter_text_files(root: pathlib.Path):
    # 跳过脚本自身 —— 它持有旧名映射常量，若被自己替换就会失去改名能力
    me = pathlib.Path(__file__).resolve()
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.resolve() == me:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_EXTS:
            continue
        if p.suffix.lower() not in TEXT_EXTS and p.suffix:
            continue
        yield p


def main():
    ap = argparse.ArgumentParser(description="项目代号与 crate 前缀整体改名")
    ap.add_argument("--name", required=True, help="新项目代号（PascalCase，如 Coffer）")
    ap.add_argument("--prefix", required=True, help="新 crate 前缀（小写字母，如 cf）")
    ap.add_argument("--root", default=".", help="仓库根目录（默认当前目录）")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true", help="只报告，不写盘")
    g.add_argument("--apply", action="store_true", help="执行替换")
    args = ap.parse_args()

    if not args.prefix.isalpha() or not args.prefix.islower():
        sys.exit(f"前缀必须是小写字母：{args.prefix!r}")

    root = pathlib.Path(args.root).resolve()
    patterns = build_patterns(args.name, args.prefix)

    print(f"仓库根目录：{root}")
    print(f"新代号：{args.name}    新前缀：{args.prefix}- / {args.prefix}_")
    print()
    print("替换规则（按长串优先）：")
    for old, new in patterns:
        print(f"  {old!r:20s} → {new!r}")
    print()

    totals = {old: 0 for old, _ in patterns}
    changed: list[tuple[pathlib.Path, dict[str, int]]] = []

    for p in iter_text_files(root):
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        new_text = text
        per_file = {}
        for old, new in patterns:
            n = new_text.count(old)
            if n:
                per_file[old] = n
                totals[old] += n
                new_text = new_text.replace(old, new)
        if per_file:
            changed.append((p.relative_to(root), per_file))
            if args.apply:
                p.write_text(new_text, encoding="utf-8")

    print(f"命中文件：{len(changed)} 个")
    print()
    for rel, per_file in changed:
        detail = ", ".join(f"{k}×{v}" for k, v in per_file.items())
        print(f"  {str(rel):46s} {detail}")

    print()
    print("合计：")
    for old, total in totals.items():
        flag = "" if total else "   ⚠ 未命中 —— 请确认旧名是否写对"
        print(f"  {old!r:20s} {total} 处{flag}")

    print()
    if args.apply:
        print("✅ 已写入。请随后执行：")
        print("   · git mv core/lv-<x> core/<prefix>-<x>   重命名 11 个 crate 目录")
        print("   · 重命名仓库目录本身")
        print("   · grep 复查旧标识残留")
    else:
        print("（dry-run，未写盘。确认无误后加 --apply 执行）")


if __name__ == "__main__":
    main()
