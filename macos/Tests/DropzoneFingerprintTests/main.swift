// DropzoneFingerprintTests/main.swift —— 放置区「已导入过/已忽略」元数据指纹单测
// （docs/04-测试与验收/18-v2.11.0验收判据骨架.md §4：W-3/W-6 指纹键构造与往返、
// S-4 指纹不含明文、W-6 忽略取消恢复；上游 docs/21a §2.3 冻结键名）。
//
// 被测单元：DropzoneFingerprintStore（纯 Foundation，注入式 UserDefaults）。
// 隔离：每个用例使用独立 UserDefaults suite（UUID），测毕 removePersistentDomain
// 清空——不触碰 App 真实 defaults，不依赖执行顺序（隔离性纪律）。
//
// 驱动：tools/run_dropzone_fingerprint_tests.sh（swiftc 编译服务文件 + 本文件）。
//
// 契约（docs/21a §2.3 冻结，勿改）：
//   - 键格式 = <文件名>\u{1F}<size>|<mtimeMs>（\u{1F} 单位分隔符，与文件名内任意字符不冲突）
//   - 指纹只含名+大小+mtime 元数据，不含内容摘要、不含明文（S-4）
//   - dropzone.imported.fingerprints / dropzone.ignored.fingerprints（冻结键名）

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

// MARK: - 独立 defaults suite 工具（隔离）

var suitesToClean: [String] = []

func freshStore() -> (DropzoneFingerprintStore, String) {
    let suite = "test.dropzone.fingerprint.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    suitesToClean.append(suite)
    return (DropzoneFingerprintStore(defaults: defaults), suite)
}

/// 写一个真实临时文件，返回 (URL, size, mtimeMs)。
func writeTempFile(_ name: String, content: String) -> (URL, Int64, Int64) {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("dzfptest-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent(name)
    try! content.write(to: url, atomically: true, encoding: .utf8)
    let values = try! url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
    return (url, Int64(values.fileSize!), Int64(values.contentModificationDate!.timeIntervalSince1970 * 1000))
}

// MARK: - W-3/W-6 指纹键构造与往返

// 键格式 = <文件名>\u{1F}<size>|<mtimeMs>（冻结）
check("TC-DRZ-W-3", "makeFingerprint 键格式冻结",
      DropzoneFingerprintStore.makeFingerprint(fileName: "a.csv", size: 123, mtimeMs: 456)
        == "a.csv\u{1F}123|456",
      "实际 \(DropzoneFingerprintStore.makeFingerprint(fileName: "a.csv", size: 123, mtimeMs: 456))")

// 文件名含空格 / Unicode / 竖线（与分隔符无关）时键仍可解析语义（仅格式断言）
let unicodeName = "密码 导出 v2|副本.csv"
let unicodeKey = DropzoneFingerprintStore.makeFingerprint(fileName: unicodeName, size: 7, mtimeMs: 8)
check("TC-DRZ-W-3", "特殊文件名（空格/中文/竖线）不破坏键格式",
      unicodeKey.hasPrefix("\(unicodeName)\u{1F}7|8"),
      "实际 \(unicodeKey)")

// fingerprint(for:) 对真实文件 = makeFingerprint(fileName:size:mtimeMs) 一致
let (urlA, sizeA, mtimeA) = writeTempFile("safari.csv", content: "hello")
let fpA = DropzoneFingerprintStore(defaults: UserDefaults(suiteName: "test.dzfp." + UUID().uuidString)!)
    .fingerprint(for: urlA)
check("TC-DRZ-W-3", "fingerprint(for:) 与 makeFingerprint 同源",
      fpA == DropzoneFingerprintStore.makeFingerprint(fileName: "safari.csv", size: sizeA, mtimeMs: mtimeA),
      "fpA=\(fpA ?? "nil")")

// markImported → isImported 往返（同实例）
let (store1, _) = freshStore()
let fp1 = DropzoneFingerprintStore.makeFingerprint(fileName: "x.csv", size: 1, mtimeMs: 2)
check("TC-DRZ-W-3", "未标记 isImported=false",
      store1.isImported(fp1) == false)
store1.markImported(fp1)
check("TC-DRZ-W-3", "markImported 后 isImported=true",
      store1.isImported(fp1) == true)

// 跨实例持久：同 suite 的第二个实例读到同一集合（UserDefaults 落盘）
let suite2 = "test.dropzone.fingerprint.\(UUID().uuidString)"
let defaults2 = UserDefaults(suiteName: suite2)!
let store2a = DropzoneFingerprintStore(defaults: defaults2)
let store2b = DropzoneFingerprintStore(defaults: defaults2)
suitesToClean.append(suite2)
let fp2 = DropzoneFingerprintStore.makeFingerprint(fileName: "y.csv", size: 10, mtimeMs: 20)
store2a.markImported(fp2)
check("TC-DRZ-W-3", "跨实例持久：B 实例 isImported=true（同 suite）",
      store2b.isImported(fp2) == true)

// 已导入集合与已忽略集合互不串扰
let (store3, _) = freshStore()
let fp3 = DropzoneFingerprintStore.makeFingerprint(fileName: "z.csv", size: 3, mtimeMs: 4)
store3.markImported(fp3)
check("TC-DRZ-W-3", "已导入不入已忽略集（隔离）",
      store3.isIgnored(fp3) == false)

// MARK: - S-4 指纹不含明文

// 指纹 = 名+大小+mtime，不含文件内容摘要/明文
let (secretURL, _, _) = writeTempFile("notes.csv", content: "supersecretpassword-\(UUID().uuidString)")
let secretFp = DropzoneFingerprintStore(defaults: UserDefaults(suiteName: "test.dzfp." + UUID().uuidString)!)
    .fingerprint(for: secretURL)
check("TC-DRZ-S-4", "指纹不含文件内容（明文不落指纹）",
      secretFp.map { !$0.contains("supersecretpassword") } ?? false,
      "fp=\(secretFp ?? "nil")")

// 指纹仅由 名 + 大小 + mtimeMs 组成（无标题/内容摘要域）：对已知元数据做黑盒断言
let metaFp = DropzoneFingerprintStore.makeFingerprint(fileName: "plain.csv", size: 4242, mtimeMs: 999)
check("TC-DRZ-S-4", "指纹仅元数据（名+大小+mtimeMs，无附加域）",
      metaFp == "plain.csv\u{1F}4242|999",
      "实际 \(metaFp)")

// MARK: - W-6 忽略指纹取消恢复

let (store4, _) = freshStore()
let fp4 = DropzoneFingerprintStore.makeFingerprint(fileName: "bad.csv", size: 5, mtimeMs: 6)
check("TC-DRZ-W-6", "未忽略 isIgnored=false",
      store4.isIgnored(fp4) == false)
store4.markIgnored(fp4)
check("TC-DRZ-W-6", "markIgnored 后 isIgnored=true",
      store4.isIgnored(fp4) == true)
store4.removeIgnored(fp4)
check("TC-DRZ-W-6", "removeIgnored 后 isIgnored=false（回到可检测行列）",
      store4.isIgnored(fp4) == false)
check("TC-DRZ-W-6", "取消忽略不清已导入集（隔离）",
      store4.isImported(fp4) == false)

// 忽略集合跨实例持久（与已导入同语义）
let suite5 = "test.dropzone.fingerprint.\(UUID().uuidString)"
let defaults5 = UserDefaults(suiteName: suite5)!
let store5a = DropzoneFingerprintStore(defaults: defaults5)
let store5b = DropzoneFingerprintStore(defaults: defaults5)
suitesToClean.append(suite5)
let fp5 = DropzoneFingerprintStore.makeFingerprint(fileName: "w.csv", size: 11, mtimeMs: 22)
store5a.markIgnored(fp5)
check("TC-DRZ-W-6", "忽略集合跨实例持久",
      store5b.isIgnored(fp5) == true)

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
