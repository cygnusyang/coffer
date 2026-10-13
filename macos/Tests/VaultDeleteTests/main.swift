// VaultDeleteTests/main.swift —— 库删除向导/管理面纯函数策略单元测试
// （v2.10.0 D1，docs/16 §5 C7 + docs/04-测试与验收/17-v2.10.0 §2 CF-2 / §3 DL-5
// 自动段；对照 docs/03-功能设计/17-库删除实现接线.md §4）。
//
// 被测单元 DeleteVaultPolicy（Support/DeleteVaultPolicy.swift）为纯函数：
// 无 IO / 无 FFI / 无 Keychain 依赖（LicenseStatus 定义于 LicenseServicing.swift，
// 同为零 CoreBindings 纯状态模型），任何环境均可运行（参照 TouchIDStatus /
// AutoPromptBiometric 测试同纪律）。FfiVaultBrief 为绑定只读元数据，非密钥材料。
//
// 编译运行：tools/run_vault_delete_tests.sh

import Foundation

var passed = 0
var failed = 0

func check(_ condition: Bool, _ name: String) {
    if condition {
        passed += 1
        print("✓ \(name)")
    } else {
        failed += 1
        print("✗ \(name)")
    }
}

func brief(_ uuid: String, _ name: String, _ createdAt: Int64) -> FfiVaultBrief {
    FfiVaultBrief(
        vaultUuid: uuid,
        displayName: name,
        createdAt: createdAt,
        modifiedAt: createdAt,
        formatVersion: 1
    )
}

// ---- 1. 只读许可判定（UDR-7 / C6，AC-2.10.0-EN-7 自动段）----

check(DeleteVaultPolicy.canManage(licenseStatus: .unactivated) == true,
      "公开构建未激活（全功能免费版）→ 可管理")
check(DeleteVaultPolicy.canManage(licenseStatus: .trial(remainingDays: 5)) == true,
      "试用中 → 可管理")
check(DeleteVaultPolicy.canManage(licenseStatus: .active(serialMasked: "…")) == true,
      "已激活 → 可管理")
check(DeleteVaultPolicy.canManage(licenseStatus: .expired) == false,
      "试用已结束（只读模式）→ 不可管理")
check(DeleteVaultPolicy.canManage(licenseStatus: .unavailable) == true,
      "许可模块不可用 → 归可管理（Rust 门禁兜底）")

// ---- 2. 库名逐字符确认 trim 比对（UDR-1，AC-2.10.0-CF-2 自动段）----

check(DeleteVaultPolicy.confirmName(input: "我的密码库", vaultName: "我的密码库") == true,
      "精确匹配 → 通过")
check(DeleteVaultPolicy.confirmName(input: "  我的密码库  ", vaultName: " 我的密码库 ") == true,
      "双方含首尾空白 → trim 后精确匹配通过（UDR-1 不死路）")
check(DeleteVaultPolicy.confirmName(input: "   ", vaultName: "我的密码库") == false,
      "全空白输入 → 不匹配")
check(DeleteVaultPolicy.confirmName(input: "我的密码", vaultName: "我的密码库") == false,
      "前缀相似但不等 → 不匹配")
check(DeleteVaultPolicy.confirmName(input: "我的密码库", vaultName: "我的密码庫") == false,
      "字面不等（繁简/字符差异）→ 不匹配")
check(DeleteVaultPolicy.confirmName(input: "my vault", vaultName: "My Vault") == false,
      "大小写不等 → 不匹配")
check(DeleteVaultPolicy.confirmName(input: "", vaultName: "我的密码库") == false,
      "空输入 → 不匹配")

// ---- 3. masked UUID（D-5.1/5.3 长内容纪律，AC-2.10.0-CF-3 / EX-3）----

let longUUID = "12345678-9abc-def0-1234-56789abcdef0"
let masked = DeleteVaultPolicy.maskedUUID(longUUID)
check(masked == "12345678…", "超长 UUID → 前缀 8 + …")
check(DeleteVaultPolicy.maskedUUID("12345678") == "12345678", "恰好 8 字符 → 原样")
check(DeleteVaultPolicy.maskedUUID("abc") == "abc", "短 UUID → 原样")

// ---- 4. 删除后落位选择（docs/17 §3.2/§3.3，AC-2.10.0-DL-5 自动段）----

let vaultA = brief("uuid-A", "旧库A", 2020)
let vaultB = brief("uuid-B", "工作库B", 2021)
let vaultC = brief("uuid-C", "我的库C", 2022)

check(DeleteVaultPolicy.selectLandingVault(briefs: [vaultA, vaultB, vaultC], deletedUUID: "uuid-B")?.vaultUuid == "uuid-C",
      "三库删中间 → 剩余中 createdAt 最近者 C")
check(DeleteVaultPolicy.selectLandingVault(briefs: [vaultC, vaultA, vaultB], deletedUUID: "uuid-A")?.vaultUuid == "uuid-C",
      "无序数组删 A → 仍取 createdAt 最近者 C（与数组序无关）")
check(DeleteVaultPolicy.selectLandingVault(briefs: [vaultA, vaultB], deletedUUID: "uuid-B")?.vaultUuid == "uuid-A",
      "两库删较新者 → 剩余仅 A")
check(DeleteVaultPolicy.selectLandingVault(briefs: [vaultA], deletedUUID: "uuid-A") == nil,
      "单库删当前 → 无剩余（落 .noVault）")
check(DeleteVaultPolicy.selectLandingVault(briefs: [], deletedUUID: "uuid-X") == nil,
      "空列表 → nil（防御）")

print("")
print(failed == 0
      ? "VAULT DELETE TESTS OK —— \(passed) 项断言全部通过"
      : "VAULT DELETE TESTS FAILED —— \(failed)/\(passed + failed) 项断言失败")
if failed > 0 { exit(1) }
