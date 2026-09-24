#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inspect_1pux.py —— 安全地探查 1PUX 的结构骨架

用途
    为 Coffer 的 1PUX 导入器校准 `categoryUuid` → 条目类型 的映射表，
    并核对 details / sections / fields 的实际结构。

设计原则（重要）
    默认模式下，本工具**绝不输出任何用户内容**——
    不输出标题、用户名、密码、URL、备注、自定义字段名、section 标题。

    它只输出「结构」：
      · 键名        （如 overview / details / loginFields —— 1Password 的内部结构名）
      · designation （如 username / password / totp —— 1Password 的内部标识）
      · type        （如 string / concealed / url —— 1Password 的内部类型名）
      · 计数与长度区间

    为什么这些可以输出：它们是 1Password 的**格式定义**，对所有人一样，
    不携带你的任何信息。而凡是「你自己填进去的内容」，一个都不碰。

用法
    # 安全模式（推荐）：输出 Markdown 报告，可直接粘贴
    python3 inspect_1pux.py /path/to/export.1pux

    # 输出 JSON
    python3 inspect_1pux.py /path/to/export.1pux --format json

    # 仅用于「专门为测试创建的样本」：按标题前缀输出标题，用于建立映射
    #   ⚠️ 不要对真实数据用这个开关
    python3 inspect_1pux.py /path/to/test.1pux --titles-matching TEST-

退出码
    0 = 成功；1 = 失败（文件不存在 / 格式不对 / 结构异常）

重要提醒
    1PUX 是**未加密**的明文导出。跑完本工具后请立即删除源文件。
"""

import argparse
import hashlib
import json
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

SAFE_LOAD_BYTES = 400 * 1024 * 1024  # 超过此大小给出提示（仍然尝试，但会慢）


# ---------------------------------------------------------------- 读取

def read_1pux(path: Path):
    """读取 1PUX，返回 (attributes, data, data_size, attachment_names)。"""
    if not path.exists():
        raise SystemExit(f"文件不存在：{path}")

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if "export.data" not in names:
                raise SystemExit(
                    "这不是有效的 1PUX：压缩包内找不到 export.data。\n"
                    "请确认导出格式选的是「1Password Unencrypted Export (.1pux)」，"
                    "而不是 CSV 或 1PIF。"
                )

            attrs = {}
            if "export.attributes" in names:
                try:
                    attrs = json.loads(z.read("export.attributes").decode("utf-8"))
                except Exception:
                    attrs = {"_note": "export.attributes 无法解析"}

            info = z.getinfo("export.data")
            if info.file_size > SAFE_LOAD_BYTES:
                print(
                    f"提示：export.data 解压后约 {info.file_size/1048576:.0f} MB，"
                    f"解析可能需要一些时间与内存。\n",
                    file=sys.stderr,
                )

            try:
                data = json.loads(z.read("export.data").decode("utf-8"))
            except json.JSONDecodeError as e:
                raise SystemExit(f"export.data 不是合法 JSON：{e}")

            files = [
                n for n in names
                if n.startswith("files/") and not n.endswith("/") and "." in n
            ]
    except zipfile.BadZipFile:
        raise SystemExit(
            "这不是有效的 ZIP 压缩包。1PUX 本身是 ZIP，若打不开说明文件损坏或不完整。"
        )

    return attrs, data, info.file_size, files


def file_fingerprint(path: Path, chunk: int = 1 << 20) -> str:
    """只取文件内容哈希的前 16 位，用于标注「本次校准依据哪份样本」。"""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()[:16]


# ---------------------------------------------------------------- 分析

def analyze(data: dict, files: list, titles_matching: str | None):
    """把 1PUX 折叠成「结构统计」，过程中不保留任何字段值。"""
    cats = defaultdict(lambda: {
        "count": 0,
        "overview_keys": Counter(),
        "details_keys": Counter(),
        "designations": Counter(),
        "field_types": Counter(),
        "name_lens": [],
        "section_title_lens": [],
        "states": Counter(),
        "attachments": 0,
        "totp": 0,
        "titles": Counter() if titles_matching else None,
    })

    vault_types = Counter()
    vault_item_counts = []
    accounts = 0
    sample_prefix = (titles_matching or "").strip()

    for acc in data.get("accounts", []) or []:
        accounts += 1
        for v in acc.get("vaults", []) or []:
            vattrs = v.get("attrs") or {}
            items = v.get("items") or []
            vault_types[str(vattrs.get("type", "?"))] += 1
            vault_item_counts.append(len(items))

            for item in items:
                cu = str(item.get("categoryUuid", "?"))
                c = cats[cu]
                c["count"] += 1

                ov = item.get("overview") or {}
                if isinstance(ov, dict):
                    for k in ov:
                        c["overview_keys"][k] += 1

                dt = item.get("details") or {}
                if isinstance(dt, dict):
                    for k in dt:
                        c["details_keys"][k] += 1

                c["states"][str(item.get("state", "?"))] += 1
                if item.get("file"):
                    c["attachments"] += 1

                # 仅用于测试样本：按标题前缀取标题
                if sample_prefix and c["titles"] is not None:
                    t = ov.get("title") if isinstance(ov, dict) else None
                    if isinstance(t, str) and t.startswith(sample_prefix):
                        c["titles"][t] += 1

                # 收集字段（loginFields + sections[].fields）
                fields = []
                if isinstance(dt, dict):
                    lf = dt.get("loginFields")
                    if isinstance(lf, list):
                        fields.extend(x for x in lf if isinstance(x, dict))
                    for sec in (dt.get("sections") or []):
                        if not isinstance(sec, dict):
                            continue
                        st = sec.get("title")
                        if isinstance(st, str):
                            c["section_title_lens"].append(len(st))
                        for f in (sec.get("fields") or []):
                            if isinstance(f, dict):
                                fields.append(f)

                for f in fields:
                    d = f.get("designation")
                    if isinstance(d, str) and d:
                        c["designations"][d] += 1
                    t = f.get("type")
                    if isinstance(t, str) and t:
                        c["field_types"][t] += 1
                    nm = f.get("name")
                    if isinstance(nm, str):
                        c["name_lens"].append(len(nm))

                    blob = f"{d or ''} {t or ''}".lower()
                    if "totp" in blob or "otp" in blob:
                        c["totp"] += 1

    ext = Counter()
    for n in files:
        ext[Path(n).suffix.lower().lstrip(".")] += 1

    return {
        "accounts": accounts,
        "vault_types": vault_types,
        "vault_item_counts": vault_item_counts,
        "cats": cats,
        "attachment_files": len(files),
        "attachment_ext": ext,
    }


def infer_category(c) -> str:
    """按字段结构猜测条目类别。仅作线索，最终以 1Password 界面为准。"""
    ds = {k.lower() for k in c["designations"]}
    ts = {k.lower() for k in c["field_types"]}
    dk = {k.lower() for k in c["details_keys"]}

    # 顺序重要：先认特征最强的（Login / 卡 / 身份），再落到纯备注类
    if "username" in ds and "password" in ds:
        return "疑似 Login"
    if "creditcardnumber" in ts or "monthyear" in ts or "cvv" in ts:
        return "疑似 Credit Card"
    if "address" in ts or "address" in ds:
        return "疑似 Identity"
    if "password" in ds and "username" not in ds:
        return "疑似 Password"
    if "notesplain" in dk and not ds:
        return "疑似 Secure Note"
    if any("key" in x for x in ds | ts):
        return "疑似 SSH Key"
    if not ds and not ts:
        return "无字段结构（需人工确认）"
    return "—"


def rng(vals):
    if not vals:
        return "—"
    return f"{min(vals)}–{max(vals)}" if min(vals) != max(vals) else str(min(vals))


# ---------------------------------------------------------------- 渲染

def render_md(rep, attrs, data_size, fp, path, titles_matching):
    L = []
    A = L.append

    A("# 1PUX 结构探查报告")
    A("")
    A("> 安全模式：本报告**不含任何字段值**。只有键名、类型名、计数与长度区间。")
    A("")

    A("## 1. 样本标识")
    A("")
    A(f"- 源文件名：`{path.name}`（未输出完整路径）")
    A(f"- 内容指纹（sha256 前 16 位）：`{fp}`")
    A(f"- 导出格式版本：`{attrs.get('version', '未知')}`")
    A(f"- 格式描述：`{attrs.get('description', '未知')}`")
    A(f"- 导出时间戳：`{attrs.get('createdAt', '未知')}`")
    A(f"- export.data 解压后大小：{data_size/1048576:.2f} MB")
    A("")

    A("## 2. 总览")
    A("")
    A("| 项 | 值 |")
    A("| --- | --- |")
    A(f"| 账号数 | {rep['accounts']} |")
    A(f"| 保险库数 | {sum(rep['vault_types'].values())} |")
    A(f"| 条目总数 | {sum(c['count'] for c in rep['cats'].values())} |")
    A(f"| 不同 categoryUuid 数 | {len(rep['cats'])} |")
    A(f"| 附件文件数 | {rep['attachment_files']} |")
    vt = ", ".join(f"{k}:{v}" for k, v in sorted(rep["vault_types"].items()))
    A(f"| 保险库类型分布（P=个人 E=共享 U=自建） | {vt or '—'} |")
    if rep["attachment_ext"]:
        ae = ", ".join(f"{k}:{v}" for k, v in rep["attachment_ext"].most_common())
        A(f"| 附件扩展名分布 | {ae} |")
    A("")

    A("## 3. categoryUuid 分布（← 本次校准的核心）")
    A("")
    A("| categoryUuid | 条目数 | 结构线索 |")
    A("| --- | --- | --- |")
    for cu, c in sorted(rep["cats"].items()):
        A(f"| `{cu}` | {c['count']} | {infer_category(c)} |")
    A("")
    A("**请对照 1Password 界面确认上表的「结构线索」是否正确。**")
    A("")

    A("## 4. 各 categoryUuid 的结构明细")
    A("")
    for cu, c in sorted(rep["cats"].items()):
        A(f"### categoryUuid = `{cu}`（{c['count']} 条）")
        A("")
        A(f"- overview 键：{', '.join(sorted(c['overview_keys'])) or '—'}")
        A(f"- details 键：{', '.join(sorted(c['details_keys'])) or '—'}")
        A(f"- 状态分布：{', '.join(f'{k}:{v}' for k, v in sorted(c['states'].items()))}")
        A(f"- designation：{', '.join(f'{k}({v})' for k, v in c['designations'].most_common()) or '—'}")
        A(f"- 字段 type：{', '.join(f'{k}({v})' for k, v in c['field_types'].most_common()) or '—'}")
        A(f"- 字段 name 长度区间：{rng(c['name_lens'])}")
        A(f"- section 标题长度区间：{rng(c['section_title_lens'])}")
        A(f"- 带附件：{c['attachments']} 条；含 TOTP：{c['totp']} 条")

        # 仅在测试样本模式下输出标题
        if c["titles"]:
            A(f"- **标题（测试样本模式）**：{', '.join(c['titles'].keys())}")
        A("")

    A("## 5. 下一步")
    A("")
    A("把本报告整份发给我，即可完成 `categoryUuid` 映射表的校准。")
    A("")
    A("**完成后请立即删除源 `.1pux` 文件**——它是未加密的明文导出。")
    A("")
    return "\n".join(L)


def render_json(rep, attrs, data_size, fp, path):
    return json.dumps({
        "source_filename": path.name,
        "fingerprint_sha256_16": fp,
        "export_attributes": attrs,
        "export_data_size_bytes": data_size,
        "accounts": rep["accounts"],
        "vault_types": dict(rep["vault_types"]),
        "attachment_files": rep["attachment_files"],
        "attachment_ext": dict(rep["attachment_ext"]),
        "categories": {
            cu: {
                "count": c["count"],
                "inferred": infer_category(c),
                "overview_keys": sorted(c["overview_keys"]),
                "details_keys": sorted(c["details_keys"]),
                "states": dict(c["states"]),
                "designations": dict(c["designations"]),
                "field_types": dict(c["field_types"]),
                "name_len_min": min(c["name_lens"]) if c["name_lens"] else None,
                "name_len_max": max(c["name_lens"]) if c["name_lens"] else None,
                "attachments": c["attachments"],
                "totp": c["totp"],
            }
            for cu, c in sorted(rep["cats"].items())
        },
    }, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- 入口

def main():
    ap = argparse.ArgumentParser(
        description="安全地探查 1PUX 的结构骨架（默认不输出任何字段值）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", help="1PUX 文件路径")
    ap.add_argument("--format", choices=["md", "json"], default="md", help="输出格式（默认 md）")
    ap.add_argument(
        "--titles-matching",
        metavar="PREFIX",
        default=None,
        help="【仅用于测试样本】输出以该前缀开头的条目标题，用于建立映射。"
             "⚠️ 不要对真实数据使用。",
    )
    args = ap.parse_args()

    path = Path(args.path).expanduser().resolve()

    if args.titles_matching:
        print(
            "⚠️  已启用 --titles-matching：将输出匹配前缀的条目标题。\n"
            "    请确认这是专门创建的测试样本，而非你的真实密码库。\n",
            file=sys.stderr,
        )

    attrs, data, data_size, files = read_1pux(path)
    fp = file_fingerprint(path)
    rep = analyze(data, files, args.titles_matching)

    if args.format == "md":
        print(render_md(rep, attrs, data_size, fp, path, args.titles_matching))
    else:
        print(render_json(rep, attrs, data_size, fp, path))


if __name__ == "__main__":
    main()
