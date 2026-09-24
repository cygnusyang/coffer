#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_test_sample.py —— 生成用于测试的合成 1PUX 样本

⚠️ 必须理解的一件事
    本脚本生成的 `categoryUuid` 是**占位值，不是真实的 1Password 数值**。
    真实的 categoryUuid 必须用 `tools/inspect_1pux.py` 对真实样本校准后才能确定，
    且严禁猜测（见 `docs/03-详细设计.md` §6.4.2）。

    本样本的用途是：
      · 测试导入器的解析、字段映射、冲突策略等**逻辑本身**
      · 测试边界情况（空值、超长文本、Unicode、emoji、特殊字符）
    它不是、也不能作为映射表的校准依据。

覆盖范围
    · 全部 22 个条目类型各一条
    · 边界条目：空字段值、超长备注、emoji 与组合字符、含引号与换行的字段值
    · 附件（内联引用）
    · 归档态与回收站态
    · 多个保险库（P / U / E 三种类型）

用法
    python3 make_test_sample.py [输出路径]
    默认输出到 ../tests/fixtures/sample_coverage.1pux
"""

import json
import sys
import zipfile
from pathlib import Path

# 占位 categoryUuid —— 故意用 9xx 段，避免与真实值混淆
PLACEHOLDER_BASE = 900

# 每个条目类型：(类型名, 占位偏移, 字段列表[(designation, name, type, value)])
# type 取值参考 1Password 的字段类型：T=text P=password U=url E=email N=number
#   D=date M=monthyear A=address C=creditcardnumber O=otp B=bool
TYPES = [
    ("Login", [
        ("username", "username", "T", "user@example.com"),
        ("password", "password", "P", "P@ssw0rd-测试-🔐"),
    ]),
    ("Password", [
        ("password", "password", "P", "only-a-password-123"),
    ]),
    ("ApiCredential", [
        ("username", "username", "T", "api-user"),
        ("credential", "credential", "P", "sk_live_abcdef123456"),
        ("hostname", "hostname", "U", "https://api.example.com"),
    ]),
    ("Server", [
        ("username", "username", "T", "root"),
        ("password", "password", "P", "srv-pw"),
        ("url", "URL", "U", "ssh://10.0.0.1"),
    ]),
    ("Database", [
        ("type", "type", "T", "PostgreSQL"),
        ("server", "server", "T", "db.internal"),
        ("port", "port", "N", "5432"),
        ("username", "username", "T", "app"),
        ("password", "password", "P", "db-pw"),
    ]),
    ("CreditCard", [
        ("ccnum", "number", "C", "4111111111111111"),
        ("cvv", "verification number", "P", "123"),
        ("expiry", "expiry date", "M", "203012"),
        ("cardholder", "cardholder name", "T", "ZHANG SAN"),
    ]),
    ("Membership", [
        ("group", "group", "T", "健身房"),
        ("memberid", "member ID", "T", "M-000123"),
        ("pin", "PIN", "P", "4321"),
    ]),
    ("Passport", [
        ("issuingcountry", "issuing country", "T", "China"),
        ("number", "number", "T", "E12345678"),
        ("fullname", "full name", "T", "张三"),
        ("nationality", "nationality", "T", "CHN"),
    ]),
    ("SoftwareLicense", [
        ("version", "version", "T", "2026.1"),
        ("licensekey", "license key", "P", "AAAA-BBBB-CCCC-DDDD"),
        ("registeredemail", "registered email", "E", "user@example.com"),
    ]),
    ("OutdoorLicense", [
        ("wildlife", "approved wildlife", "T", "deer"),
        ("quota", "maximum quota", "N", "2"),
        ("state", "state", "T", "青海"),
    ]),
    ("SecureNote", [
        ("notesPlain", "notesPlain", "T", "这是一段保密备注。\n含换行与 emoji 🎯"),
    ]),
    ("WirelessRouter", [
        ("basestationname", "base station name", "T", "TP-LINK-AX6000"),
        ("basestationpassword", "base station password", "P", "router-admin-pw"),
        ("networkname", "network name", "T", "home-wifi"),
        ("networkpassword", "network password", "P", "wifi-pw-2026"),
    ]),
    ("BankAccount", [
        ("routing", "routing number", "T", "021000021"),
        ("account", "account number", "T", "000123456789"),
        ("pin", "PIN", "P", "9999"),
    ]),
    ("DriverLicense", [
        ("number", "license number", "T", "110101199001011234"),
        ("fullname", "full name", "T", "张三"),
        ("expiry", "expiry date", "D", "2030-01-01"),
    ]),
    ("Identity", [
        ("firstname", "first name", "T", "三"),
        ("lastname", "last name", "T", "张"),
        ("address", "address", "A", "北京市海淀区某某路 1 号"),
        ("email", "email", "E", "user@example.com"),
        ("phone", "phone", "T", "+86 138 0000 0000"),
    ]),
    ("RewardProgram", [
        ("company", "company name", "T", "某航空"),
        ("membername", "member name", "T", "张三"),
        ("memberid", "member ID", "T", "FF-889900"),
    ]),
    ("Document", [
        ("filename", "filename", "T", "扫描件.pdf"),
    ]),
    ("EmailAccount", [
        ("username", "username", "T", "user@example.com"),
        ("server", "server", "T", "imap.example.com"),
        ("port", "port", "N", "993"),
        ("authtype", "authentication", "T", "password"),
        ("password", "password", "P", "mail-pw"),
    ]),
    ("SocialSecurityNumber", [
        ("name", "name", "T", "张三"),
        ("number", "number", "T", "123-45-6789"),
    ]),
    ("MedicalRecord", [
        ("date", "date", "D", "2026-03-15"),
        ("location", "location", "T", "某医院"),
        ("professional", "healthcare professional", "T", "李医生"),
        ("reason", "reason for visit", "T", "常规体检"),
    ]),
    ("SshKey", [
        ("privatekey", "private key", "T", "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----"),
        ("publickey", "public key", "T", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI fake@host"),
        ("fingerprint", "fingerprint", "T", "SHA256:abcdefg"),
    ]),
    ("CryptoWallet", [
        ("recoveryphrase", "recovery phrase", "T", "word1 word2 word3 word4 word5 word6"),
        ("password", "password", "P", "wallet-pw"),
        ("address", "wallet address", "T", "bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ]),
]

# 边界条目：专门测异常输入
EDGE_CASES = [
    ("边界-空字段值", "Login", [("username", "username", "T", ""),
                                ("password", "password", "P", "")]),
    ("边界-超长备注", "SecureNote", [("notesPlain", "notesPlain", "T", "长" * 2000)]),
    ("边界-组合字符与emoji", "SecureNote", [("notesPlain", "notesPlain", "T", "é\u0301 👨‍👩‍👧‍👦 🇨🇳 ①②③ ½ ㎡")]),
    ("边界-含引号与换行", "Login", [("username", "username", "T", 'He said "hi"\ttab'),
                                    ("password", "password", "P", "line1\nline2")]),
    ("边界-CSV公式注入", "Login", [("username", "username", "T", "=cmd|'/c calc'!A1"),
                                   ("password", "password", "P", "+1234")]),
    ("边界-超长字段名", "SecureNote", [("", "名" * 300, "T", "value")]),
]

VAULTS = [
    ("Private", "P", None),
    ("MyVault", "U", None),
    ("Shared", "E", "团队共享库"),
]


def build_item(idx, title, cu, fields, state="active", has_file=False):
    login_fields, sections = [], []
    for designation, name, ftype, value in fields:
        f = {"designation": designation, "name": name, "type": ftype, "value": value}
        # loginFields 只放 username / password，其余进 section（模拟 1Password 的行为）
        if designation in ("username", "password"):
            login_fields.append(f)
        else:
            sections.append(f)

    details = {}
    if login_fields:
        details["loginFields"] = login_fields
    if sections:
        details["sections"] = [{"title": "额外字段", "fields": sections}]
    if not login_fields and not sections:
        details["notesPlain"] = ""

    item = {
        "uuid": f"IT{idx:04d}",
        "categoryUuid": str(PLACEHOLDER_BASE + idx),
        "favIndex": 1 if idx % 7 == 0 else 0,
        "createdAt": 1700000000 + idx * 60,
        "updatedAt": 1700000000 + idx * 60,
        "state": state,
        "overview": {
            "title": title,
            "subtitle": f"占位副标题 {idx}",
            "url": f"https://example{idx}.com",
            "urls": [
                {"label": "", "url": f"https://example{idx}.com"},
                {"label": "管理后台", "url": f"https://admin.example{idx}.com"},
            ],
            "tags": ["测试", "synthetic"] if idx % 2 == 0 else [],
        },
        "details": details,
    }
    if has_file:
        item["file"] = {
            "attrs": {"fileName": f"doc{idx}.pdf", "size": 1024 + idx},
            "path": f"files/doc{idx}.pdf",
        }
    return item


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sample_coverage.1pux"
    out.parent.mkdir(parents=True, exist_ok=True)

    # 22 类各一条 + 边界条目不进 vault（放在第三个库里）
    main_items = [build_item(i + 1, f"SYNTH-{name}", i + 1, fields, has_file=(i % 5 == 0))
                  for i, (name, fields) in enumerate(TYPES)]
    edge_items = [build_item(100 + i, title, 10, fields)
                  for i, (title, _cat, fields) in enumerate(EDGE_CASES)]

    # 追加一条归档态、一条回收站态
    archived = build_item(200, "SYNTH-已归档", 1, TYPES[0][1], state="archived")
    trashed = build_item(201, "SYNTH-回收站", 1, TYPES[1][1], state="trashed")

    vault_objs = []
    for vi, (name, vtype, desc) in enumerate(VAULTS):
        if vi == 0:
            items = main_items[:11]
        elif vi == 1:
            items = main_items[11:]
        else:
            items = edge_items + [archived, trashed]
        vault_objs.append({
            "attrs": {"uuid": f"V{vi+1}", "name": name, "type": vtype,
                      "desc": desc or "", "avatar": ""},
            "items": items,
        })

    data = {"accounts": [{
        "attrs": {
            "accountName": "Synthetic Account",
            "name": "Synthetic Account",
            "avatar": "",
            "email": "synthetic@example.com",
            "uuid": "ACCSYNTHETIC",
            "domain": "https://my.1password.com/",
        },
        "vaults": vault_objs,
    }]}

    attrs = {
        "version": 3,
        "description": "LocalVault SYNTHETIC test sample - NOT real 1Password data",
        "createdAt": 1790000000,
    }

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("export.attributes", json.dumps(attrs, ensure_ascii=False, indent=2))
        z.writestr("export.data", json.dumps(data, ensure_ascii=False))
        for i in range(1, len(main_items) + 1):
            if i % 5 == 0:
                z.writestr(f"files/doc{i}.pdf", b"%PDF-1.4 synthetic placeholder")

    total = sum(len(v["items"]) for v in vault_objs)
    print(f"已生成合成样本：{out}")
    print(f"  条目类型覆盖：{len(TYPES)} 类")
    print(f"  边界条目：{len(EDGE_CASES)} 条")
    print(f"  保险库：{len(VAULTS)} 个；条目总数：{total}")
    print()
    print("⚠️  提醒：样本中的 categoryUuid 是占位值（9xx 段），")
    print("    不代表真实 1PUX 的数值，不可用于校准映射表。")


if __name__ == "__main__":
    main()
