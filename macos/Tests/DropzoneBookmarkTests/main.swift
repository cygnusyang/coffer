// DropzoneBookmarkTests/main.swift —— 放置区授权 bookmark 存取/失效/配对单测
// （docs/04-测试与验收/18-v2.11.0验收判据骨架.md §4：A-3 bookmark 失效检测
// standalone 部分、A-4 withAccess 生命周期配对、A-3/A-5 save/load/remove 往返、
// A-3/A-5/E-3 三态派生数据面；上游 docs/21a §3.2）。
//
// 被测单元：DropzoneBookmarkStore（Foundation + 注入式 UserDefaults）。
// 隔离：每个用例独立 UserDefaults suite（UUID）+ 真实临时目录，测毕清 suite +
// 删目录——不触碰 App 真实 defaults 与真实授权目录，不依赖执行顺序。
//
// 非沙盒 harness 经验事实（2026-10-16 本机实证）：
//   - withSecurityScope bookmark 创建/解析正常、startAccessing 返回 true；
//   - chmod 000 / rmdir 均被 validate() 检出（contentsOfDirectory 兜底）；
//   - `resolvingBookmarkData` 返回**规范真实路径**（/var → /private/var），
//     与 NSTemporaryDirectory 的 /var 前缀不同——路径断言须双方 realpath 后比较；
//   - 目录**删除后** resolvingBookmarkData 抛 Cocoa Code=4（file doesn't exist）
//     → load() 返回 nil（跨重启失效呈现 .notAuthorized 而非 .stale；.stale 由
//     内存 bookmark + validate 呈现——A-3/RT-06 ⑥ in-session 口径，观察已报 lead）。
//
// 三态派生说明：`AppModel.dropzoneAuthStatus`（AppModel.swift:137-142）为
// @MainActor + SwiftUI 重依赖，不可 standalone 实例化；本文件以其**契约镜像**
// `deriveStatus`（显式镜像同一派生规则）驱动**生产** `BookmarkStore.load`/`validate`
// 数据原语断言三态映射；AppModel 一行派生本身归 §5 grep/走查核。
//
// 驱动：tools/run_dropzone_bookmark_tests.sh（swiftc 编译服务文件 + 本文件）。

import Foundation
import Darwin

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

// MARK: - 工具（隔离）

var suitesToClean: [String] = []
var dirsToClean: [URL] = []

/// 独立 store：独立 UserDefaults suite + 独立临时目录。
func freshStore() -> (DropzoneBookmarkStore, URL) {
    let suite = "test.dropzone.bookmark.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    suitesToClean.append(suite)
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("dzbktest-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    dirsToClean.append(dir)
    return (DropzoneBookmarkStore(defaults: defaults), dir)
}

/// 规范真实路径（resolvingBookmarkData 返回 /private/var 前缀；双方须同一基准比较）。
func realpath(_ p: String) -> String {
    guard let rp = Darwin.realpath(p, nil) else { return p }
    defer { free(rp) }
    return String(cString: rp)
}

/// 三态派生契约镜像（AppModel.swift:137-142 同规则；数据原语 = 生产 load/validate）。
func deriveStatus(_ bookmark: DropzoneBookmark?) -> DropzoneAuthStatus {
    guard let bookmark = bookmark else { return .notAuthorized }
    return DropzoneBookmarkStore.shared.validate(bookmark)
        ? .authorized(bookmark)
        : .stale(bookmark)
}

// MARK: - A-3/A-5 bookmark save/load/remove 往返

let (store1, dir1) = freshStore()
check("TC-DRZ-A-5", "未授权 load() = nil", store1.load() == nil)

let bm1 = try! store1.save(dir1)
check("TC-DRZ-A-3", "save 后 load() 非空", store1.load() != nil)
check("TC-DRZ-A-3", "save/load URL 往返一致（realpath 基准）",
      store1.load().map { realpath($0.url.path) == realpath(dir1.path) } ?? false,
      "load=\(store1.load()?.url.path ?? "nil") vs dir=\(dir1.path)")

store1.remove()
check("TC-DRZ-A-5", "remove 后 load() = nil", store1.load() == nil,
      "实际 \(String(describing: store1.load()))")

// 跨实例持久：同 suite 第二个实例读到同一 bookmark（UserDefaults 落盘）
let (store2, dir2) = freshStore()
let bm2 = try! store2.save(dir2)
let store2b = DropzoneBookmarkStore(defaults: UserDefaults(suiteName: suiteOf(store2))!)
check("TC-DRZ-A-3", "bookmark 跨实例持久（同 suite）",
      store2b.load().map { realpath($0.url.path) == realpath(dir2.path) } ?? false,
      "load=\(store2b.load()?.url.path ?? "nil")")
check("TC-DRZ-A-3", "bookmarkData 往返完整",
      store2b.load()?.bookmarkData == bm2.bookmarkData)

func suiteOf(_ store: DropzoneBookmarkStore) -> String {
    suitesToClean.last!
}

// MARK: - A-3 bookmark 失效检测（standalone）

let (store3, dir3) = freshStore()
let bm3 = try! store3.save(dir3)
check("TC-DRZ-A-3", "基线 validate = true", store3.validate(bm3) == true)

// chmod 000 → false（contentsOfDirectory 兜底）；恢复 → true
try! FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: dir3.path)
check("TC-DRZ-A-3", "chmod 000 → validate = false（stale 判据）",
      store3.validate(bm3) == false)
try! FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir3.path)
check("TC-DRZ-A-3", "权限恢复 → validate = true", store3.validate(bm3) == true)

// rmdir → false（A-3 standalone：目录删除 → 失效判定）
try! FileManager.default.removeItem(at: dir3)
check("TC-DRZ-A-3", "rmdir → validate = false（stale 判据）", store3.validate(bm3) == false)

// 记录（非断言，观察已报 lead）：目录删除后 resolvingBookmarkData 抛 Cocoa Code=4
// → load() = nil；跨重启失效呈现 .notAuthorized（S0 重授权，非静默）而非 .stale。
// 契约 A-3/RT-06 ⑥ 的 .stale 由内存 bookmark + validate 呈现（in-session），
// 由「三态派生：失效 → .stale」用例覆盖。
let deletedLoad = store3.load()
print("INFO  TC-DRZ-A-3  目录删除后 load() = \(String(describing: deletedLoad))（跨重启→notAuthorized，观察已报 lead）")

// MARK: - A-4 withAccess 生命周期配对

let (store4, dir4) = freshStore()
let bm4 = try! store4.save(dir4)

// 正常路径：body 执行、返回值传播
let fourtyTwo: Int = try! store4.withAccess(bm4) { 42 }
check("TC-DRZ-A-4", "withAccess 正常路径：body 返回值传播", fourtyTwo == 42)

// 异常路径：body throw → 错误传播（defer stop 兜底停访，不驻留句柄）
do {
    _ = try store4.withAccess(bm4) { throw DropzoneBookmarkError.createBookmark(bm4.url) }
    check("TC-DRZ-A-4", "withAccess 异常路径：错误传播", false, "未抛错（异常未传播）")
} catch let e as DropzoneBookmarkError {
    check("TC-DRZ-A-4", "withAccess 异常路径：错误传播", true, "")
    _ = e
} catch {
    check("TC-DRZ-A-4", "withAccess 异常路径：错误类型", false, "\(error)")
}

// 配对后不驻留：连续多次 withAccess 均可用（无句柄累积副作用）
var runs = 0
for _ in 0..<3 {
    _ = try! store4.withAccess(bm4) { runs += 1 }
}
check("TC-DRZ-A-4", "withAccess 连续配对 3 次均执行（不驻留句柄）", runs == 3)

// 失效目录上 withAccess：body 是否执行依 startAccessing 行为（非沙盒可能仍 true）。
// 失效的确定性判定在 validate（A-3 已测），此处仅断言不 crash 且能收尾。
let (store5, dir5) = freshStore()
let bm5 = try! store5.save(dir5)
try! FileManager.default.removeItem(at: dir5)
_ = (try? store5.withAccess(bm5) { true }) ?? false
check("TC-DRZ-A-4", "失效目录 withAccess 不 crash（判据以 validate 为准）", true)

// MARK: - A-3/A-5/E-3 三态派生数据面（契约镜像 + 生产数据原语）

let (store6, dir6) = freshStore()
// nil → notAuthorized
check("TC-DRZ-E-3", "三态派生：nil → .notAuthorized",
      deriveStatus(store6.load()) == .notAuthorized)
// 有效 → authorized（load 返回规范路径，模式匹配 + realpath 比较）
let bm6 = try! store6.save(dir6)
if case .authorized(let loaded) = deriveStatus(store6.load()) {
    check("TC-DRZ-E-3", "三态派生：有效 → .authorized 且 URL 往返一致",
          realpath(loaded.url.path) == realpath(bm6.url.path),
          "loaded=\(loaded.url.path)")
} else {
    check("TC-DRZ-E-3", "三态派生：有效 → .authorized", false, "非 .authorized")
}
// 失效 → stale（in-session：内存 bookmark + validate 判定；rmdir 后）
try! FileManager.default.removeItem(at: dir6)
if case .stale = deriveStatus(bm6) {
    check("TC-DRZ-E-3", "三态派生：失效（rmdir）→ .stale", true)
} else {
    check("TC-DRZ-E-3", "三态派生：失效 → .stale", false, "非 .stale")
}

// MARK: - 汇总

for suite in suitesToClean { UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite) }
for dir in dirsToClean { try? FileManager.default.removeItem(at: dir) }

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
