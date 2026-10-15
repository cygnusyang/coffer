// DropzoneRealSampleRegressionTests/main.swift —— L2 真样全链路回归 harness
// （docs/19 §4.4，L2 断言面对齐 PuxRealSampleTests 判据①②③）。
//
// 定位：对**合成 fixture**（真实 Safari/Passwords.app 列头 + 合成脱敏假密码，
// tests/fixtures/csv/dropzone_passwords_headers.csv）跑全链路——列映射 → 空库
// 全 new → 全量导入落库（标题逐字）→ 重导去重 → 文件漂移 fail-closed 零落库。
// 走真实 core 逻辑（FFI precheckDropzone/importDropzone/listItems），临时建库。
//
// J-5 联动（docs/19 §4.3）：
//   - 本 harness = **永久自动回归**，消费**合成**样本（假密码，R2 安全）。
//   - 真样采样**只做一次**（人工）：tools/run_dropzone_j5_sample.sh 在
//     .local-samples/（git 忽略，真密码不落库）记录非敏感四核对项（列头/菜单名/
//     默认文件名 Passwords.csv/重复导出命名）→ 人工核对四项即核销 P-2 provisional
//     / J-5 发版门禁；若列头与合成 fixture 不符 → 更新 fixture + 复核 P-2 Safari
//     别名映射 + 重跑本 harness（docs/19 §4.3 不可逆标注：fixture 列头=数据契约，
//     J-5 核销前保持 provisional）。
//
// R2 安全纪律（硬性）：
//   - 建库工作目录由外部（脚本 mktemp）传入，本进程先断言不命中真实库前缀
//     ~/Library/Containers/top.cygnusyang.coffer/ 再执行；
//   - 合成 fixture 密码为占位假值；FfiDropzonePrecheck/FfiDropzoneRow **类型层无
//     密码字段**（R2 已实证 cf_ffi.swift:4088-4171），本 harness 无法也不应打印
//     任何密码值；
//   - 临时工作目录进程内删除（defer），脚本侧 trap 二次保险。
//
// 先红后绿：不适用——W1c scratch 探针（11/11）已验证可行性，本轮为正式化落地
// （docs/19 §4.4 断言面 + PuxRealSampleTests 骨架）。
//
// 用法：DropzoneRealSampleRegressionTests <fixture.csv> <临时工作目录>

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

let args = Array(CommandLine.arguments.dropFirst())
guard args.count >= 2 else {
    fatal("用法：DropzoneRealSampleRegressionTests <fixture.csv> <临时工作目录>")
}
let fixturePath = args[0]
let workDir = args[1]

// 样本在位校验（缺失 / 为空 → 明确报错，退出码 2）
var isDir: ObjCBool = false
guard FileManager.default.fileExists(atPath: fixturePath, isDirectory: &isDir),
      !isDir.boolValue else {
    fatal("合成 fixture 不存在或不是文件：\(fixturePath)（应为 tests/fixtures/csv/dropzone_passwords_headers.csv）")
}
let fixtureSize = (try? FileManager.default.attributesOfItem(atPath: fixturePath))?[.size] as? Int ?? 0
guard fixtureSize > 0 else {
    fatal("合成 fixture 为空：\(fixturePath)")
}

// 安全纪律：工作目录绝不允许命中真实库路径前缀
let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
let realVaultPrefix = home + "/Library/Containers/top.cygnusyang.coffer"
let normalizedWorkDir = URL(fileURLWithPath: workDir).standardizedFileURL.path
guard !normalizedWorkDir.hasPrefix(realVaultPrefix) else {
    fatal("安全拦截：工作目录 \(workDir) 命中真实库前缀 \(realVaultPrefix)，拒绝执行")
}

// MARK: - 建库 + 解锁（真实 KDF，约 1s；全程只在临时工作目录）

let testPassword = "T-G-L2-Dropzone-2026!"
let app = CofferApp()
let session: VaultSession
do {
    let brief = try app.createVault(baseDir: workDir, name: "L2 放置区回归", password: testPassword)
    session = try app.openVault(baseDir: workDir, vaultUuid: brief.vaultUuid)
    _ = try session.unlock(password: testPassword)
} catch {
    fatal("建库/解锁失败：\(error)")
}
defer {
    session.lock()
    try? FileManager.default.removeItem(atPath: normalizedWorkDir)
}

// MARK: - ① 预检：列映射 + 空库全 new（L2 判据①，PuxRealSampleTests 同构）

let pre1: FfiDropzonePrecheck
do {
    pre1 = try session.precheckDropzone(path: fixturePath)
} catch {
    fatal("预检失败：\(error)")
}
check("TC-L2-PRE-01", "列映射无未映射列（Title/URL/Username/Password/Notes/OTPAuth 全命中）",
      pre1.unmappedColumns.isEmpty, "unmapped=\(pre1.unmappedColumns)")
check("TC-L2-PRE-02", "空库全 new（validRows==3 + new==3 + dup==0 + conflict==0）",
      pre1.validRows == 3 && pre1.newCount == 3 && pre1.duplicateCount == 0 && pre1.conflictCount == 0,
      "validRows=\(pre1.validRows) new=\(pre1.newCount) dup=\(pre1.duplicateCount) cf=\(pre1.conflictCount)")
check("TC-L2-PRE-03", "行号自 2 起（表头=行 1，数据行 line_no 2,3,4）",
      pre1.rows.map(\.lineNo) == [2, 3, 4], "lineNos=\(pre1.rows.map(\.lineNo))")

// MARK: - ② 全量导入 + 落库标题逐字（L2 判据②③）

let allLineNos = pre1.rows.map(\.lineNo)
let imp: FfiCsvImportResult
do {
    imp = try session.importDropzone(path: fixturePath, includeLineNos: allLineNos)
} catch {
    fatal("导入失败：\(error)")
}
check("TC-L2-IMP-01", "导入 importedRows == 3（all-or-nothing 单事务）",
      imp.importedRows == 3, "imported=\(imp.importedRows)")

let items = (try? session.listItems(filter: nil)) ?? []
check("TC-L2-IMP-02", "listItems 落库 3 条", items.count == 3, "count=\(items.count)")
let titles = Set(items.map(\.title))
check("TC-L2-IMP-03", "落库标题逐字：GitHub / Example Bank / Media Streaming",
      titles == Set(["GitHub", "Example Bank", "Media Streaming"]),
      "titles=\(titles.sorted())")

// MARK: - ③ 重导同文件 → 全 duplicate（元数据级去重：Title/Username/URL 三元组命中）

let pre2: FfiDropzonePrecheck
do {
    pre2 = try session.precheckDropzone(path: fixturePath)
} catch {
    fatal("重导预检失败：\(error)")
}
check("TC-L2-DUP-01", "重导全 duplicate（dup==3 + new==0，密码永不作键）",
      pre2.duplicateCount == 3 && pre2.newCount == 0,
      "new=\(pre2.newCount) dup=\(pre2.duplicateCount) cf=\(pre2.conflictCount)")

// MARK: - ④ 文件漂移 fail-closed 零落库（docs/18 §3 已绿 18 例的 Swift 面复核）

// 预检后重写文件删除行（include 行号缺失）→ 须抛 Err 2002 + 零新增。
// 语义对齐 dropzone_import.rs:404：OVERWRITE 删行（追加不删则原行号仍存在，
// 不触发漂移）。
let driftPath = normalizedWorkDir + "/drift.csv"
try! FileManager.default.copyItem(atPath: fixturePath, toPath: driftPath)
let preDrift: FfiDropzonePrecheck
do {
    preDrift = try session.precheckDropzone(path: driftPath)
} catch {
    fatal("漂移预检失败：\(error)")
}
let beforeDrift = (try? session.listItems(filter: nil))?.count ?? -1
// 重写：仅 1 条数据行（line 2）；预检 include [2,3,4] 中 3/4 已缺失
let shrunken = "Title,URL,Username,Password,Notes,OTPAuth\n"
    + "Drift,https://drift.example,drift,PLACEHOLDER-PW-0004,,\n"
try! shrunken.write(toFile: driftPath, atomically: true, encoding: .utf8)
do {
    _ = try session.importDropzone(path: driftPath, includeLineNos: preDrift.rows.map(\.lineNo))
    let afterDrift = (try? session.listItems(filter: nil))?.count ?? -1
    check("TC-L2-DRIFT-01", "文件漂移 fail-closed 零落库（未报错路径：仍须零新增）",
          afterDrift == beforeDrift, "before=\(beforeDrift) after=\(afterDrift)")
} catch {
    let afterDrift = (try? session.listItems(filter: nil))?.count ?? -1
    check("TC-L2-DRIFT-01", "文件漂移 fail-closed 零落库（抛错路径：Err 2002 + 零新增）",
          afterDrift == beforeDrift,
          "before=\(beforeDrift) after=\(afterDrift) err=\(error)")
}

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
