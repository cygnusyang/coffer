#!/usr/bin/env python3
"""tools/update_download_stats.py —— 生成 README「下载量」表格（GitHub Release 资产累计下载数）。

口径（GitHub 能力边界，勿过度承诺）：
  - 数据源 = GitHub REST API `repos/{owner}/{repo}/releases` 的 assets[].download_count，
    是**累计下载次数**（含 OTA 自动更新的下载），不是去重用户数；
  - 无按天 / 按地区 / 按平台拆分（GitHub 不提供；traffic API 只有 14 天 views/clones
    且需 owner token，不适合公开 README）；
  - DMG 口径≈新装，ZIP 口径≈OTA 自动更新（更新清单随 zip 一并计）。

用法：
  python3 tools/update_download_stats.py                 # 就地刷新 README.md
  python3 tools/update_download_stats.py --repo a/b --file README.md
  GITHUB_TOKEN=... python3 tools/update_download_stats.py  # 提高 API 配额（可选）

幂等：表内容无变化时不写文件、不改 mtime，退出码 0（CI 靠 git diff 判断是否需要提交）。
实现纪律：只用标准库（CI 镜像无需装依赖）；失败即非 0 退出，绝不写半张表。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

DEFAULT_REPO = "cygnusyang/coffer"
DEFAULT_FILE = "README.md"
START_MARKER = "<!-- downloads:start"
END_MARKER = "<!-- downloads:end -->"
API_TEMPLATE = "https://api.github.com/repos/{repo}/releases?per_page=100"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="生成 README 下载量表格")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO),
                        help="owner/name（默认取 GITHUB_REPOSITORY 或 %(default)s）")
    parser.add_argument("--file", default=DEFAULT_FILE, help="目标 Markdown 文件（默认 %(default)s）")
    parser.add_argument("--today", default=None, help="覆盖「最后更新」日期（YYYY-MM-DD，测试用）")
    return parser.parse_args()


def fetch_releases(repo: str, token: str | None) -> list[dict]:
    request = urllib.request.Request(
        API_TEMPLATE.format(repo=repo),
        headers={"Accept": "application/vnd.github+json", "User-Agent": "coffer-download-stats"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"ERROR: GitHub API 返回 {error.code}（{repo}）：{error.reason}") from error
    except urllib.error.URLError as error:
        raise SystemExit(f"ERROR: 无法访问 GitHub API：{error.reason}") from error


def count_suffix(assets: dict[str, int], suffix: str) -> int:
    return sum(count for name, count in assets.items() if name.lower().endswith(suffix))


def render_table(releases: list[dict], today: str) -> str:
    """渲染表格块（含首尾 marker）；无资产时给一行占位。"""
    rows: list[str] = []
    total_dmg = total_zip = 0
    for release in releases:
        if release.get("draft"):
            continue
        assets = {a.get("name", ""): a.get("download_count", 0) for a in release.get("assets", [])}
        if not assets:
            continue
        dmg = count_suffix(assets, ".dmg")
        zipped = count_suffix(assets, ".zip")
        total_dmg += dmg
        total_zip += zipped
        published = (release.get("published_at") or "")[:10] or "—"
        tag = release.get("tag_name") or "—"
        rows.append(f"| {tag} | {published} | {dmg} | {zipped} | {dmg + zipped} |")

    lines = [
        f"{START_MARKER}（由 tools/update_download_stats.py 自动生成，勿手改） -->",
        "",
        f"_最后更新：{today}（来源：GitHub Release 资产累计下载次数，含 OTA 自动更新）_",
        "",
    ]
    if rows:
        lines += [
            "| 版本 | 发布时间 | DMG（新装） | ZIP（OTA 更新） | 合计 |",
            "| --- | --- | ---: | ---: | ---: |",
            *rows,
            f"| **总计** | — | **{total_dmg}** | **{total_zip}** | **{total_dmg + total_zip}** |",
        ]
    else:
        lines.append("_暂无下载数据。_")
    lines += ["", END_MARKER]
    return "\n".join(lines)


def splice(document: str, block: str) -> str:
    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        re.DOTALL,
    )
    if not pattern.search(document):
        raise SystemExit(
            f"ERROR: 未找到 marker（{START_MARKER} … {END_MARKER}），请在目标文件中先放置占位块。"
        )
    return pattern.sub(lambda _match: block, document, count=1)


def main() -> int:
    args = parse_args()
    today = args.today or _dt.date.today().isoformat()
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    block = render_table(fetch_releases(args.repo, token), today)

    with open(args.file, "r", encoding="utf-8") as handle:
        document = handle.read()
    updated = splice(document, block)
    if updated == document:
        print(f"{args.file}：下载量无变化，跳过写入")
        return 0
    with open(args.file, "w", encoding="utf-8") as handle:
        handle.write(updated)
    print(f"{args.file}：下载量表格已刷新")
    return 0


if __name__ == "__main__":
    sys.exit(main())
