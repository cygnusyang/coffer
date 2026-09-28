// PuxRealSampleTests/main.swift —— 685 条真实 1PUX 样本判据补验（v0.3.0 出口判据①）。
//
// 定位（docs/06 r2.1 M0-③ 口径：685 条，001=login×683、004×1、112×1，
// 004/112 两类歧义按 E-4 保守降级进 Notes）：
//   - 判据①预检：totalItems / importableItems / attachmentCount / notImported /
//     unknownCategories / categoryDistribution 全部冻结断言；
//   - 判据②导入：importedItems + 返回 report 与预检逐字段一致（FfiPuxPrecheckReport
//     为 Equatable，直接 == 即全字段比对）+ deletionAdvice 保守裁决；
//   - 判据③落库：listItems 全量 685 条。
//
// 安全纪律（硬性）：
//   - 建库工作目录由外部（脚本 mktemp）传入，本进程先断言目标路径
//     不命中真实库前缀 ~/Library/Containers/app.coffer.Coffer/ 再执行；
//   - 样本缺失 / 为空 → 明确报错退出（exit 2）；
//   - 临时工作目录进程内删除（defer），脚本侧 trap 二次保险。
//
// 探针模式（--probe）：只跑预检并打印全部实际值、不断言——用于冻结
// 断言口径前的实测核对（004/112 的实际 categoryUuid 由此取得）。
//
// 用法：PuxRealSampleTests <样本路径> <临时工作目录> [--probe]

import Foundation

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0

func check(_ tc: String, _ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else {
        failures.append("\(tc) \(name) \(detail)")
        print("FAIL  \(tc)  \(name)  \(detail)")
    }
}

/// 环境性失败（样本缺失、安全拦截等）：非断言问题，直接带码退出。
func fatal(_ msg: String) -> Never {
    print("ERROR  \(msg)")
    exit(2)
}

// MARK: - 入参与安全门禁

var probe = false
var positional: [String] = []
for arg in CommandLine.arguments.dropFirst() {
    if arg == "--probe" {
        probe = true
    } else {
        positional.append(arg)
    }
}
guard positional.count >= 2 else {
    fatal("用法：PuxRealSampleTests <样本路径> <临时工作目录> [--probe]")
}
let samplePath = positional[0]
let workDir = positional[1]

// 样本在位校验（缺失 / 为空 → 明确报错，退出码 2）
var isDir: ObjCBool = false
guard FileManager.default.fileExists(atPath: samplePath, isDirectory: &isDir),
      !isDir.boolValue else {
    fatal("样本不存在或不是文件：\(samplePath)（默认来源 .local-samples/real-export-20260602.1pux，git 忽略；可用环境变量 COFFER_1PUX_SAMPLE 覆盖）")
}
let sampleSize = (try? FileManager.default.attributesOfItem(atPath: samplePath))?[.size] as? Int ?? 0
guard sampleSize > 0 else {
    fatal("样本文件为空：\(samplePath)")
}

// 安全纪律：工作目录绝不允许命中真实库路径前缀
let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
let realVaultPrefix = home + "/Library/Containers/app.coffer.Coffer"
let normalizedWorkDir = URL(fileURLWithPath: workDir).standardizedFileURL.path
guard !normalizedWorkDir.hasPrefix(realVaultPrefix) else {
    fatal("安全拦截：工作目录 \(workDir) 命中真实库前缀 \(realVaultPrefix)，拒绝执行")
}

// MARK: - 建库 + 解锁（真实 KDF，约 1s；全程只在临时工作目录）

let testPassword = "T-G-1PUX-Acceptance-2026!"
let app = CofferApp()
let session: VaultSession
do {
    let brief = try app.createVault(baseDir: workDir, name: "1PUX 真实样本验收", password: testPassword)
    session = try app.openVault(baseDir: workDir, vaultUuid: brief.vaultUuid)
    _ = try session.unlock(password: testPassword)
} catch {
    fatal("建库/解锁失败：\(error)")
}
defer {
    session.lock()
    try? FileManager.default.removeItem(atPath: normalizedWorkDir)
}

// MARK: - 探针模式（只预检 + 打印实际值，不断言）

if probe {
    let report: FfiPuxPrecheckReport
    do {
        report = try session.precheck1pux(path: samplePath)
    } catch {
        fatal("预检失败：\(error)")
    }
    print("=== 探针：FfiPuxPrecheckReport 实际值 ===")
    print("totalItems            = \(report.totalItems)")
    print("importableItems       = \(report.importableItems)")
    print("attachmentCount       = \(report.attachmentCount)")
    print("trashedCount          = \(report.trashedCount)")
    print("passwordHistoryDropped= \(report.passwordHistoryDropped)")
    print("categoryDistribution  =")
    for c in report.categoryDistribution {
        print("    \(c.category): \(c.count)")
    }
    print("unknownCategories     =")
    for u in report.unknownCategories {
        print("    itemUuid=\(u.itemUuid) categoryUuid=\(u.categoryUuid)")
    }
    print("unmappedValueTypes    = \(report.unmappedValueTypes)")
    print("duplicateDocumentIds  = \(report.duplicateDocumentIds)")
    print("notImported           =")
    for n in report.notImported {
        print("    uuid=\(n.uuid) title=\(n.title) reason=\(n.reason)")
    }
    print("warnings              =")
    for w in report.warnings {
        print("    \(w)")
    }
    print("=== 探针结束（未做任何断言） ===")
    exit(0)
}

// MARK: - 冻结断言口径
//
// 来源：2026-09-28 探针实测冻结（**修正了 docs/06 r2.1 的口径偏差**——该
// 记录称「004/112 各 1 条类别歧义」，实测 004 是 1Password 官方类别
// identity（uuid 6vfjtuhfu5iiyyepemvr4bjcju/004），内核 mapping 已映射；
// 仅 112 未识别 → 降级 secure_note（数据并入备注）。分布：identity=1 +
// login=683 + secure_note=1。docs/06 记载随 T-H 回填修正）。改动此处必须先重跑 --probe 核对。

let expectTotalItems = 685
let expectImportableItems = 685
let expectLoginCount = 683
// 112 的实际 categoryUuid（1Password 官方类别 uuid 尾段，探针实测冻结；
// 004 已被内核映射为 identity，不在 unknown 之列）
let expectUnknownCategoryUuidSuffix = "112"
// 类别分布冻结清单（category: count，按类别名字典序比对）
let expectDistribution: [(category: String, count: UInt32)] = [
    ("identity", 1),
    ("login", 683),
    ("secure_note", 1),
]
let expectDegradedCount = 1

// MARK: - 判据①预检

let precheck: FfiPuxPrecheckReport
do {
    precheck = try session.precheck1pux(path: samplePath)
} catch {
    fatal("预检失败：\(error)")
}

check("PUX-01", "预检 totalItems == 685", precheck.totalItems == expectTotalItems,
      "实际 \(precheck.totalItems)")
check("PUX-02", "预检 importableItems == 685（含降级，E-4）", precheck.importableItems == expectImportableItems,
      "实际 \(precheck.importableItems)")
check("PUX-03", "预检 attachmentCount == 0（无附件）", precheck.attachmentCount == 0,
      "实际 \(precheck.attachmentCount)")
check("PUX-04", "预检 notImported 为空（FR-7.6 不静默丢弃）", precheck.notImported.isEmpty,
      "实际 \(precheck.notImported.map { $0.uuid + ": " + $0.reason })")

let unknownUuids = precheck.unknownCategories.map { $0.categoryUuid }
check("PUX-05", "unknownCategories 恰 1 条且为 112（004 已映射为 identity）",
      precheck.unknownCategories.count == 1
          && unknownUuids.allSatisfy { $0.hasSuffix(expectUnknownCategoryUuidSuffix) },
      "实际 \(precheck.unknownCategories.map { $0.itemUuid + "/" + $0.categoryUuid })")

let distSorted = precheck.categoryDistribution
    .map { (category: $0.category, count: $0.count) }
    .sorted { $0.category < $1.category }
let expectDistSorted = expectDistribution.sorted { $0.category < $1.category }
check("PUX-06", "categoryDistribution == 冻结分布（login=683 + 另两类各 1）",
      distSorted.count == expectDistSorted.count
          && zip(distSorted, expectDistSorted).allSatisfy { $0.category == $1.category && $0.count == $1.count },
      "实际 \(distSorted.map { $0.category + "=" + String($0.count) })")

// MARK: - 判据②导入（返回 report 与预检逐字段一致 + 保守删源建议）

let importResult: FfiPuxImportResult
do {
    importResult = try session.import1pux(path: samplePath)
} catch {
    fatal("导入失败：\(error)")
}

check("PUX-07", "importedItems == 685", importResult.importedItems == 685,
      "实际 \(importResult.importedItems)")
check("PUX-08", "导入返回 report 与预检逐字段一致（FfiPuxPrecheckReport ==）",
      importResult.report == precheck,
      "两报告不等——逐字段差异需人工核对")

check("PUX-09", "deletionAdvice.canDelete == false（004/112 降级，保守裁决）",
      importResult.deletionAdvice.canDelete == false,
      "实际 canDelete=\(importResult.deletionAdvice.canDelete)")
check("PUX-10", "degradedItems 恰 1 条（112 降级明细）",
      importResult.deletionAdvice.degradedItems.count == expectDegradedCount,
      "实际 \(importResult.deletionAdvice.degradedItems.map { $0.key + ": " + $0.reason })")
check("PUX-11", "deletionAdvice.blockers 非空（canDelete=false 必有原因）",
      !importResult.deletionAdvice.blockers.isEmpty,
      "实际 \(importResult.deletionAdvice.blockers)")

// MARK: - 判据③落库

let items: [FfiItemSummary]
do {
    items = try session.listItems(filter: nil)
} catch {
    fatal("listItems 失败：\(error)")
}
check("PUX-12", "listItems 全量 == 685 条（判据③落库）", items.count == 685,
      "实际 \(items.count)")

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
