// DropzoneImportModelTests/main.swift —— L1 DropzoneImportModel RED→GREEN harness
// （docs/04-测试与验收/19-UI测试自动化分层设计.md §3.3 FFI-linked 形态 + docs/18
// IT-12/14/15/16/18/19/20/21/22/28 模型面映射）。
//
// 被测单元：`DropzoneImportModel`（w1a 抽取，macos/Coffer/Dropzone/DropzoneImportModel.swift，
// 签名 = docs/19 §3.1/§3.2 冻结契约 + 视图抽取前逐字签名，见下方「契约头」）。
// 先红后绿：本 harness 为 RED 基线（w1a 落地前编译红 = 合法 RED；落地后复跑转绿）。
// 当前 RED 根因 = **AppPhase 契约依赖缺口**（AppModel.swift:18 定义 AppPhase，
// AppKit+SwiftUI 重依赖不可 standalone 编译；DropzoneImportContext 协议引用之，
// L1 harness 无法编译——已报 lead/w1a，须 AppPhase 迁至轻量文件）。
// 签名若有偏差 → 报 lead 裁定（签名=契约），不单方面改。
//
// 形态（docs/19 §3.3 方案 A）：FFI-linked——swiftc + cf_ffi.swift + libcf_ffi.a +
// 临时建库 + 合成 CSV + 内存 context stub + FakeWatcher + 注入式真实 store
// （bookmark/fingerprint 均经 UserDefaults(suiteName:) 隔离，绝不落 .standard 真键）。
// 安全纪律（PuxRealSampleTests 先例）：工作目录前缀拦截真实库
// ~/Library/Containers/top.cygnusyang.coffer/ + mktemp + trap 清理。
//
// 主 actor 驱动：model 为 @MainActor（Swift 6.3 编译器下从非隔离顶层调其 init 是
// #ActorIsolatedCall 硬错误），故全部测试体收进 `runTests()`（@MainActor），顶层
// 仅做入参/安全门禁/建库，再以 `MainActor.assumeIsolated` 驱动（main.swift 顶层
// 代码运行于主线程，编译器可见性外的事实由 assumeIsolated 声明）。
//
// 驱动：tools/run_dropzone_import_model_tests.sh

import Foundation

// ============================================================================
// 契约头（w1a 落地后的**实际冻结签名**，2026-10-16 逐字核对；改此 = 契约变更）
// ============================================================================
// @MainActor final class DropzoneImportModel: ObservableObject {
//     init(context: DropzoneImportContext? = nil,
//          watcher: DirectoryWatching,
//          bookmarkStore: DropzoneBookmarkStore,
//          fingerprintStore: DropzoneFingerprintStore)
//     func attach(context: DropzoneImportContext)
//     @Published var step: Step                     // 初始 .unauthorized
//     @Published var candidates: [DropzoneCandidate]
//     @Published var selectedCandidate: URL?
//     @Published var directoryCandidates: [DropzoneCandidate]
//     @Published var includedLineNos: Set<UInt32>
//     @Published var waitingHint: String?
//     var isImporting: Bool
//     var selectedIsImported: Bool
//     func onAppear()                               // S0 授权三态落地
//     func handlePhaseChange()                      // W-2（无参，读 context.phase）
//     func handleBookmarkChange()                   // IT-12 A-5（无参，读 context 状态）
//     func handleDidBecomeActive()                  // W-5 回前台补扫
//     func onDisappear()
//     func authorize(url: URL)                      // S0 授权唯一写点
//     func startWatching()
//     func handleWatchEvent()
//     func rescanAndEvaluate(foreground: Bool)
//     func defaultSelection(_ candidates: [DropzoneCandidate]) -> URL?
//     func dropzoneCandidates() -> [DropzoneCandidate]
//     func ignoreFile(_ url: URL)
//     func unignore(_ fingerprint: String)
//     func startPrecheck(_ url: URL)
//     func toggle(_ row: FfiDropzoneRow)
//     func duplicates(in: FfiDropzonePrecheck) -> [FfiDropzoneRow]
//     func conflicts(in: FfiDropzonePrecheck) -> [FfiDropzoneRow]
//     func allDuplicatesIncluded(in:) -> Bool
//     func includeAllDuplicates(in:)
//     func excludeAllDuplicates(in:)
//     func includedCount(in: FfiDropzonePrecheck, of: FfiDedupCategory) -> Int
//     func previewRowLabel(_:) -> String
//     func categoryName(_:) -> String
//     func doImport(report: FfiDropzonePrecheck, path: String)   // S4 异步单事务
//     func markImported(path: String)
//     func backToWaiting()
//     func errorText(_:) -> String
//     func sessionCall<R>(_: (VaultSession) throws -> R) throws -> R
// }
// enum Step { unauthorized, authFailed(String), waiting, pickFile,
//             prechecking(URL), precheckFailed(URL, String),
//             preview(FfiDropzonePrecheck, path: String),
//             importing(path: String, skippedDuplicates: UInt32),
//             done(FfiCsvImportResult, path: String, skippedDuplicates: UInt32),
//             importFailed(path: String, error: String) }
// struct DropzoneCandidate: Identifiable { url; fingerprint: String?;
//     isImported; isIgnored; id = url }
// @MainActor protocol DropzoneImportContext: AnyObject {
//     var phase: AppPhase { get }; var dropzoneAuthStatus: DropzoneAuthStatus { get }
//     var session: VaultSession? { get }
//     func setDropzoneBookmark(_:); func reloadItems()
// }
// protocol DirectoryWatching: AnyObject {  // 非 @MainActor
//     func start(watching: URL, onEvent: @escaping () -> Void) throws
//     func stop(); func rescan() -> [URL]
// }
// ============================================================================

// MARK: - 断言与汇总（@MainActor：failures/passCount 为可变全局，隐式主 actor 隔离）

@MainActor
var failures: [String] = []
@MainActor
var passCount = 0

@MainActor
func check(_ tc: String, _ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(tc)  \(name)")
    } else {
        failures.append("\(tc) \(name) \(detail)")
        print("FAIL  \(tc)  \(name)  \(detail)")
    }
}

/// 非隔离：只 print + exit，不触 actor 隔离状态（顶层与 runTests 共用）。
func fatal(_ msg: String) -> Never {
    print("ERROR  \(msg)")
    exit(2)
}

/// 泵主 runloop 直到条件成立（供 doImport 的 Task.detached→MainActor.run 异步
/// 完成点落地）；超时返回 false。谓词访问 model 状态 → 标 @MainActor。
@MainActor
func pumpUntil(timeout: TimeInterval = 10, _ cond: @MainActor () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while !cond() && Date() < deadline {
        RunLoop.main.run(until: Date().addingTimeInterval(0.02))
    }
    return cond()
}

// MARK: - 入参与安全门禁（PuxRealSampleTests 先例；顶层非隔离，仅纯操作）

let positional = Array(CommandLine.arguments.dropFirst())
guard positional.count >= 1 else { fatal("用法：DropzoneImportModelTests <临时工作目录>") }
let workDir = positional[0]

let home = FileManager.default.homeDirectoryForCurrentUser.standardizedFileURL.path
let realVaultPrefix = home + "/Library/Containers/top.cygnusyang.coffer"
let normalizedWorkDir = URL(fileURLWithPath: workDir).standardizedFileURL.path
guard !normalizedWorkDir.hasPrefix(realVaultPrefix) else {
    fatal("安全拦截：工作目录 \(workDir) 命中真实库前缀 \(realVaultPrefix)，拒绝执行")
}

// MARK: - 建库 + 解锁（真实 FFI，全程只在临时工作目录；FFI 类型非隔离）

let testPassword = "T-G-DzModel-Acceptance-2026!"
let app = CofferApp()
let session: VaultSession
do {
    let brief = try app.createVault(baseDir: workDir, name: "放置区模型验收", password: testPassword)
    session = try app.openVault(baseDir: workDir, vaultUuid: brief.vaultUuid)
    _ = try session.unlock(password: testPassword)
} catch {
    fatal("建库/解锁失败：\(error)")
}

// MARK: - 测试替身（协议 @MainActor → stub 同标）

/// 内存 context stub（docs/19 §3.2）：phase/dropzoneAuthStatus/session 受控，
/// setDropzoneBookmark/reloadItems 记录调用。
@MainActor
final class ContextStub: DropzoneImportContext {
    var phase: AppPhase
    var dropzoneAuthStatus: DropzoneAuthStatus
    var session: VaultSession?
    private(set) var bookmarkSets: [DropzoneBookmark] = []
    private(set) var reloadCount = 0

    init(phase: AppPhase = .unlocked,
         status: DropzoneAuthStatus = .notAuthorized,
         session: VaultSession? = nil) {
        self.phase = phase
        self.dropzoneAuthStatus = status
        self.session = session
    }
    func setDropzoneBookmark(_ bookmark: DropzoneBookmark) { bookmarkSets.append(bookmark) }
    func reloadItems() { reloadCount += 1 }
}

/// FakeWatcher（docs/19 §3.2，DirectoryWatching 非 @MainActor）：记录 start/stop
/// + 受控 rescan 返回值。
final class FakeWatcher: DirectoryWatching {
    private(set) var startURLs: [URL] = []
    private(set) var startCount = 0
    private(set) var stopCount = 0
    private(set) var rescanCount = 0
    var rescanResult: [URL] = []
    var startThrows = false

    func start(watching url: URL, onEvent: @escaping () -> Void) throws {
        if startThrows { throw DropzoneWatchError.cannotOpen(url, errno: EACCES) }
        startURLs.append(url)
        startCount += 1
    }
    func stop() { stopCount += 1 }
    func rescan() -> [URL] { rescanCount += 1; return rescanResult }
}

// MARK: - 工具

@MainActor
var suitesToClean: [String] = []

/// 全新模型 + 全新隔离 store；可注入 store（供测试侧断言真实 store 状态）。
@MainActor
func freshModel(context: ContextStub, watcher: FakeWatcher,
                bookmarkStore: DropzoneBookmarkStore? = nil,
                fingerprintStore: DropzoneFingerprintStore? = nil,
                rescanResult: [URL] = []) -> DropzoneImportModel {
    let suite = "test.dropzone.model.\(UUID().uuidString)"
    suitesToClean.append(suite)
    let bookmarks = bookmarkStore ?? DropzoneBookmarkStore(defaults: UserDefaults(suiteName: suite)!)
    let fingerprints = fingerprintStore ?? DropzoneFingerprintStore(defaults: UserDefaults(suiteName: suite)!)
    watcher.rescanResult = rescanResult
    return DropzoneImportModel(context: context, watcher: watcher,
                               bookmarkStore: bookmarks, fingerprintStore: fingerprints)
}

/// 放置区目录 + 合成 CSV（R2：假密码占位，与 L2 fixture 同源内容）。
func makeDropzoneDir(_ base: String, name: String, rows: String) -> URL {
    let dir = URL(fileURLWithPath: base).appendingPathComponent(name, isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let csv = "Title,URL,Username,Password,Notes,OTPAuth\n" + rows
    try! csv.write(to: dir.appendingPathComponent("Passwords.csv"), atomically: true, encoding: .utf8)
    return dir
}

/// 放置区单文件目录 + 可控 mtime（W-3 默认选最新用；指纹=名+大小+mtime）。
func makeCsvFile(_ base: String, name: String, mtimeOffset: TimeInterval) -> URL {
    let dir = URL(fileURLWithPath: base).appendingPathComponent(name, isDirectory: true)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent("Passwords.csv")
    try! "Title,URL,Username,Password,Notes,OTPAuth\nX,,,PLACEHOLDER-PW-0001,,\n"
        .write(to: url, atomically: true, encoding: .utf8)
    try! FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(mtimeOffset)],
                                           ofItemAtPath: url.path)
    return url
}

@MainActor
func newBookmark(_ url: URL) -> DropzoneBookmark {
    let suite = "test.dropzone.bookmark.\(UUID().uuidString)"
    suitesToClean.append(suite)
    return try! DropzoneBookmarkStore(defaults: UserDefaults(suiteName: suite)!).save(url)
}

// MARK: - 测试体（@MainActor，全部 S0-S5 判据）

@MainActor
func runTests() {
    defer {
        session.lock()
        try? FileManager.default.removeItem(atPath: normalizedWorkDir)
        for suite in suitesToClean {
            UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
        }
    }

    // ================================================================
    // IT-12（A-5 回落，走查→模型单测升级的关键面；docs/18 §9 终态口径 2026-10-16）
    // ================================================================

    let dropDir = makeDropzoneDir(workDir, name: "dropzone-it12", rows:
        "GitHub,https://github.com/octocat,octocat,PLACEHOLDER-PW-0001,Main account,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n")
    let bookmarkURL = dropDir
    let authBookmark = newBookmark(bookmarkURL)
    let csvPath = dropDir.appendingPathComponent("Passwords.csv").path

    // 基线：authorized → S1 + startWatching（空目录 → 停留 S1）
    let ctx12 = ContextStub(status: .authorized(authBookmark), session: session)
    let fake12 = FakeWatcher()
    let m12 = freshModel(context: ctx12, watcher: fake12)
    m12.onAppear()
    check("TC-DRZ-IT12", "IT-12 基线：authorized → S1 + startWatching",
          m12.step == .waiting && fake12.startCount == 1,
          "step=\(m12.step) start=\(fake12.startCount)")

    // 移除授权（status → .notAuthorized）→ 停表 + 回落 S0（handleBookmarkChange 读 context）
    ctx12.dropzoneAuthStatus = .notAuthorized
    m12.handleBookmarkChange()
    check("TC-DRZ-IT12", "IT-12 移除授权 → 停表 + 回落 S0",
          fake12.stopCount == 1 && m12.step == .unauthorized,
          "stop=\(fake12.stopCount) step=\(m12.step)")

    // 授权中 onChange（status 仍 .authorized）→ 不受扰（stop 不增、step 不变）
    let ctx12b = ContextStub(status: .authorized(authBookmark), session: session)
    let fake12b = FakeWatcher()
    let m12b = freshModel(context: ctx12b, watcher: fake12b)
    m12b.onAppear()
    let stepBefore12b = m12b.step
    m12b.handleBookmarkChange()
    check("TC-DRZ-IT12", "IT-12 授权保持 → no-op（停表不增、step 不变）",
          fake12b.stopCount == 0 && m12b.step == stepBefore12b,
          "stop=\(fake12b.stopCount) step=\(m12b.step)")

    // stale 派生（status .stale，bookmark 值未变）→ 同样回落（目录不可达，§9 终态口径）
    let ctx12c = ContextStub(status: .stale(authBookmark), session: session)
    let fake12c = FakeWatcher()
    let m12c = freshModel(context: ctx12c, watcher: fake12c)
    m12c.onAppear()
    m12c.handleBookmarkChange()
    check("TC-DRZ-IT12", "IT-12 stale 派生 → 回落 S0（停表 + step==.unauthorized）",
          fake12c.stopCount == 1 && m12c.step == .unauthorized,
          "stop=\(fake12c.stopCount) step=\(m12c.step)")

    // ================================================================
    // IT-15（W-2 锁定门禁：phase 离开 unlocked → 停表 fail-closed）
    // ================================================================

    let ctx15 = ContextStub(status: .authorized(authBookmark), session: session)
    let fake15 = FakeWatcher()
    let m15 = freshModel(context: ctx15, watcher: fake15)
    m15.onAppear()
    ctx15.phase = .locked
    m15.handlePhaseChange()
    check("TC-DRZ-IT15", "IT-15 锁定 → watcher.stop（fail-closed）", fake15.stopCount >= 1,
          "stop=\(fake15.stopCount)")
    ctx15.phase = .unlocked
    let stopAfterLock = fake15.stopCount
    m15.handlePhaseChange()
    check("TC-DRZ-IT15", "IT-15 解锁 → 不额外 stop", fake15.stopCount == stopAfterLock,
          "stop=\(fake15.stopCount)")

    // ================================================================
    // IT-28（S0-S5 状态机主路径 + 各出口）
    // ================================================================

    let ctx28 = ContextStub(session: session)
    let fake28 = FakeWatcher()
    let m28 = freshModel(context: ctx28, watcher: fake28)
    check("TC-DRZ-IT28", "IT-28 初始态 = .unauthorized（S0）", m28.step == .unauthorized,
          "step=\(m28.step)")

    // onAppear（未授权）→ 保持 S0，不启动监视
    m28.onAppear()
    check("TC-DRZ-IT28", "IT-28 未授权 onAppear → 保持 S0 + 不 startWatching",
          m28.step == .unauthorized && fake28.startCount == 0,
          "step=\(m28.step) start=\(fake28.startCount)")

    // authorize(url:)（S0→S1）+ startWatching + 广播
    ctx28.dropzoneAuthStatus = .authorized(authBookmark)
    m28.authorize(url: bookmarkURL)
    check("TC-DRZ-IT28", "IT-28 authorize → S1 + startWatching + 广播 setDropzoneBookmark",
          m28.step == .waiting && fake28.startCount == 1 && ctx28.bookmarkSets.count == 1,
          "step=\(m28.step) start=\(fake28.startCount) sets=\(ctx28.bookmarkSets.count)")

    // startPrecheck（真实合成 CSV）→ S3 preview + 默认 include = New∪Conflict
    m28.startPrecheck(URL(fileURLWithPath: csvPath))
    if case .preview(let report, path: _) = m28.step {
        check("TC-DRZ-IT28", "IT-28 startPrecheck → S3 preview（合成 CSV 解析）", report.validRows == 1,
              "validRows=\(report.validRows)")
        let expected = Set(report.rows.filter { $0.category != .duplicate }.map(\.lineNo))
        check("TC-DRZ-IT28", "IT-28 默认 include = New∪Conflict（重复排除）",
              m28.includedLineNos == expected,
              "included=\(m28.includedLineNos) expected=\(expected)")
    } else {
        check("TC-DRZ-IT28", "IT-28 startPrecheck → S3 preview", false, "step=\(m28.step)")
    }

    // backToWaiting（S3→S1 返回）→ 复位 + 补扫
    let rescanBefore28 = fake28.rescanCount
    m28.backToWaiting()
    check("TC-DRZ-IT28", "IT-28 backToWaiting → S1 + 补扫",
          m28.step == .waiting && fake28.rescanCount >= rescanBefore28 + 1,
          "step=\(m28.step) rescan \(rescanBefore28)→\(fake28.rescanCount)")

    // ================================================================
    // IT-21（P-4 派生计数：三连计数恒等 N）+ IT-22（P-5 批量切换即时统计）
    // ================================================================

    // 合成 3 行分类场景：库内已有 Alpha 三元组 → 同三元组=duplicate、
    // 全新=Beta=new、Title 命中但 Username 不同=conflict（FfiDedupCategory 语义）。
    let csv21a = makeDropzoneDir(workDir, name: "dropzone-it21", rows:
        "Alpha,https://a.example,a,PLACEHOLDER-PW-0001,,\n")
    // 表头=行 1、数据行自 line_no 2 起（dropzone_import.rs:352 同款）：用预检真实
    // 行号而非硬编码（先前探针同类缺陷已自纠）。
    let pre21a = try! session.precheckDropzone(path: csv21a.appendingPathComponent("Passwords.csv").path)
    _ = try! session.importDropzone(path: csv21a.appendingPathComponent("Passwords.csv").path,
                                    includeLineNos: pre21a.rows.map(\.lineNo))
    let csv21b = makeDropzoneDir(workDir, name: "dropzone-it21b", rows:
        "Alpha,https://a.example,a,PLACEHOLDER-PW-0001,,     \n"
        + "Beta,https://b.example,b,PLACEHOLDER-PW-0002,,    \n"
        + "Alpha,https://a.example,DIFFERENT,PLACEHOLDER-PW-0003,,\n")
    let m21 = freshModel(context: ContextStub(session: session), watcher: FakeWatcher())
    m21.startPrecheck(csv21b.appendingPathComponent("Passwords.csv"))
    if case .preview(let report, path: _) = m21.step {
        let n = m21.includedCount(in: report, of: .new)
            + m21.includedCount(in: report, of: .duplicate)
            + m21.includedCount(in: report, of: .conflict)
        check("TC-DRZ-IT21", "IT-21 三连计数恒等 N（includedLineNos.count）",
              n == m21.includedLineNos.count,
              "n=\(n) N=\(m21.includedLineNos.count) 分类=\(report.rows.map { "\($0.lineNo):\($0.category)" })")
        check("TC-DRZ-IT21", "IT-21 三分类均已产出（new/duplicate/conflict 各≥1）",
              report.rows.contains { $0.category == .new }
              && report.rows.contains { $0.category == .duplicate }
              && report.rows.contains { $0.category == .conflict },
              "分类=\(report.rows.map { "\($0.lineNo):\($0.category)" })")
        check("TC-DRZ-IT21", "IT-21 分类计数非负且各自独立",
              m21.includedCount(in: report, of: .new) >= 0
              && m21.includedCount(in: report, of: .duplicate) >= 0
              && m21.includedCount(in: report, of: .conflict) >= 0)

        // IT-22 批量切换：toggle 重复行 → 计数即时更新
        if let dup = report.rows.first(where: { $0.category == .duplicate }) {
            let before = m21.includedCount(in: report, of: .duplicate)
            m21.toggle(dup)
            let after = m21.includedCount(in: report, of: .duplicate)
            check("TC-DRZ-IT22", "IT-22 toggle 重复行 → duplicate 计数即时更新",
                  after == before + 1, "before=\(before) after=\(after)")
            m21.excludeAllDuplicates(in: report)
            check("TC-DRZ-IT22", "IT-22 excludeAllDuplicates → duplicate 全排除",
                  m21.allDuplicatesIncluded(in: report) == false)
            m21.includeAllDuplicates(in: report)
            let dupTotal = report.rows.filter { $0.category == .duplicate }.count
            check("TC-DRZ-IT22", "IT-22 includeAllDuplicates → duplicate 全含",
                  m21.allDuplicatesIncluded(in: report) == true
                  && m21.includedCount(in: report, of: .duplicate) == dupTotal,
                  "count=\(m21.includedCount(in: report, of: .duplicate)) dupTotal=\(dupTotal)")
        } else {
            check("TC-DRZ-IT22", "IT-22 合成样本含重复行", false, "未分类出 duplicate")
        }
    } else {
        check("TC-DRZ-IT21", "IT-21 startPrecheck → S3 preview", false, "step=\(m21.step)")
    }

    // ================================================================
    // IT-20（S2-E 预检失败 / import 失败回 S1）
    // ================================================================

    // 坏路径 → S2-E precheckFailed（就地错误态）
    let m20 = freshModel(context: ContextStub(session: session), watcher: FakeWatcher())
    m20.startPrecheck(URL(fileURLWithPath: "/nonexistent/\(UUID().uuidString).csv"))
    if case .precheckFailed = m20.step {
        check("TC-DRZ-IT20", "IT-20 坏路径 → S2-E precheckFailed", true)
    } else {
        check("TC-DRZ-IT20", "IT-20 坏路径 → S2-E precheckFailed", false, "step=\(m20.step)")
    }

    // session nil（锁定态）→ doImport all-or-nothing 零落库守卫：同步进 S4，
    // 异步完成点落 S5-E importFailed「会话不存在」（不崩溃、不写库）。
    let m20b = freshModel(context: ContextStub(session: nil), watcher: FakeWatcher())
    let emptyReport = FfiDropzonePrecheck(
        rows: [], totalRows: 0, validRows: 0, newCount: 0, duplicateCount: 0, conflictCount: 0,
        warnings: [], unmappedColumns: [], isEmptyVault: true)
    m20b.doImport(report: emptyReport, path: csvPath)
    check("TC-DRZ-IT20", "IT-20 session nil doImport → 同步进 S4 importing（不崩溃）",
          m20b.step == .importing(path: csvPath, skippedDuplicates: 0),
          "step=\(m20b.step)")
    let finished = pumpUntil { if case .importing = m20b.step { return false }; return true }
    check("TC-DRZ-IT20", "IT-20 session nil doImport → 完成点 S5-E importFailed（零落库）",
          finished && m20b.step == .importFailed(path: csvPath, error: "会话不存在。"),
          "finished=\(finished) step=\(m20b.step)")

    // ================================================================
    // IT-14（W-1 监视生命周期）/ IT-18（W-5 回前台补扫）
    // ================================================================

    // startWatching 失败（授权失效）→ S0-E authFailed（D-18.3 失效不静默）
    let ctx14 = ContextStub(status: .authorized(authBookmark), session: session)
    let fake14 = FakeWatcher()
    fake14.startThrows = true
    let m14 = freshModel(context: ctx14, watcher: fake14)
    m14.startWatching()
    if case .authFailed = m14.step {
        check("TC-DRZ-IT14", "IT-14 startWatching 失败 → S0-E authFailed", true)
    } else {
        check("TC-DRZ-IT14", "IT-14 startWatching 失败 → S0-E authFailed", false, "step=\(m14.step)")
    }

    // 回前台补扫：phase unlocked + S1 waiting → rescan（W-5）
    let ctx18 = ContextStub(status: .authorized(authBookmark), session: session)
    let fake18 = FakeWatcher()
    let m18 = freshModel(context: ctx18, watcher: fake18)
    m18.onAppear()
    let rescanBefore18 = fake18.rescanCount
    m18.handleDidBecomeActive()
    check("TC-DRZ-IT18", "IT-18 回前台（unlocked+S1）→ 补扫",
          fake18.rescanCount >= rescanBefore18 + 1,
          "rescan \(rescanBefore18)→\(fake18.rescanCount)")

    // 回前台但已锁定 → 不补扫（fail-closed）
    let ctx18b = ContextStub(status: .authorized(authBookmark), session: session)
    ctx18b.phase = .locked
    let fake18b = FakeWatcher()
    let m18b = freshModel(context: ctx18b, watcher: fake18b)
    m18b.onAppear()
    let rescanBefore18b = fake18b.rescanCount
    m18b.handleDidBecomeActive()
    check("TC-DRZ-IT18", "IT-18 回前台（locked）→ 不补扫",
          fake18b.rescanCount == rescanBefore18b,
          "rescan \(rescanBefore18b)→\(fake18b.rescanCount)")

    // ================================================================
    // IT-16（W-3 默认选最新 / 已导入过 → S1.5 pickFile 默认选中）
    // ================================================================

    let urlA = makeCsvFile(workDir, name: "dropzone-it16a", mtimeOffset: -7200)   // 较旧
    let urlB = makeCsvFile(workDir, name: "dropzone-it16b", mtimeOffset: -3600)   // 较新

    // T1：两候选均未导入过 → pickFile，默认选最新（B）
    let ctx16a = ContextStub(status: .authorized(authBookmark), session: session)
    let fake16a = FakeWatcher()
    let m16a = freshModel(context: ctx16a, watcher: fake16a, rescanResult: [urlA, urlB])
    m16a.onAppear()
    check("TC-DRZ-IT16", "IT-16 两候选均未导入 → S1.5 pickFile + 候选 2",
          m16a.step == .pickFile && m16a.candidates.count == 2,
          "step=\(m16a.step) count=\(m16a.candidates.count)")
    check("TC-DRZ-IT16", "IT-16 默认选中 = 最新修改时间（B）",
          m16a.selectedCandidate == urlB,
          "selected=\(String(describing: m16a.selectedCandidate))")

    // T2：A 已导入过（较旧）、B 未导入（较新）→ 默认选最新未导入（B）
    let fp16b = DropzoneFingerprintStore(defaults: UserDefaults(suiteName: "test.dropzone.model.16b")!)
    suitesToClean.append("test.dropzone.model.16b")
    if let fpA = fp16b.fingerprint(for: urlA) { fp16b.markImported(fpA) }
    let ctx16b = ContextStub(status: .authorized(authBookmark), session: session)
    let fake16b = FakeWatcher()
    let m16b = freshModel(context: ctx16b, watcher: fake16b, fingerprintStore: fp16b,
                          rescanResult: [urlA, urlB])
    m16b.onAppear()
    check("TC-DRZ-IT16", "IT-16 A 已导入过 → pickFile + 默认选最新未导入（B）",
          m16b.step == .pickFile && m16b.selectedCandidate == urlB,
          "step=\(m16b.step) selected=\(String(describing: m16b.selectedCandidate))")
    check("TC-DRZ-IT16", "IT-16 已导入过候选标 isImported 徽标态",
          m16b.candidates.first { $0.url == urlA }?.isImported == true,
          "candidates=\(m16b.candidates.map { "\($0.url.lastPathComponent):\($0.isImported)" })")

    // T3：两候选均已导入过 → pickFile，默认选最新（B），无 nil 默认（预检不禁用）
    let fp16c = DropzoneFingerprintStore(defaults: UserDefaults(suiteName: "test.dropzone.model.16c")!)
    suitesToClean.append("test.dropzone.model.16c")
    for u in [urlA, urlB] { if let fp = fp16c.fingerprint(for: u) { fp16c.markImported(fp) } }
    let ctx16c = ContextStub(status: .authorized(authBookmark), session: session)
    let fake16c = FakeWatcher()
    let m16c = freshModel(context: ctx16c, watcher: fake16c, fingerprintStore: fp16c,
                          rescanResult: [urlA, urlB])
    m16c.onAppear()
    check("TC-DRZ-IT16", "IT-16 全部已导入 → pickFile + 默认选最新（B，非 nil）",
          m16c.step == .pickFile && m16c.selectedCandidate == urlB,
          "step=\(m16c.step) selected=\(String(describing: m16c.selectedCandidate))")

    // ================================================================
    // IT-19（W-6 忽略 / 取消忽略——与 §4 指纹 harness 衔接）
    // ================================================================

    let fp19 = DropzoneFingerprintStore(defaults: UserDefaults(suiteName: "test.dropzone.model.19")!)
    suitesToClean.append("test.dropzone.model.19")
    let ignoreURL = URL(fileURLWithPath: "/tmp/ignored-\(UUID().uuidString).csv")
    try! "Title,URL,Username,Password\nX,,,PLACEHOLDER-PW-0001\n"
        .write(to: ignoreURL, atomically: true, encoding: .utf8)
    let ctx19 = ContextStub(status: .authorized(authBookmark), session: session)
    let m19 = freshModel(context: ctx19, watcher: FakeWatcher(), fingerprintStore: fp19)
    m19.ignoreFile(ignoreURL)
    let fpVal = fp19.fingerprint(for: ignoreURL)
    if let fp = fpVal {
        check("TC-DRZ-IT19", "IT-19 ignoreFile → 指纹落已忽略（W-6）", fp19.isIgnored(fp),
              "fingerprint=\(fp)")
    } else {
        check("TC-DRZ-IT19", "IT-19 ignoreFile → 指纹落已忽略（W-6）", false, "fingerprint(for:) 返回 nil")
    }
    check("TC-DRZ-IT19", "IT-19 ignoreFile → 回落 S1（忽略后回等待）",
          m19.step == .waiting, "step=\(m19.step)")
    // 取消忽略（S1.5）：从忽略集合移除
    fp19.removeIgnored(fpVal ?? "")
    check("TC-DRZ-IT19", "IT-19 removeIgnored → 不再被忽略",
          fpVal.map { !fp19.isIgnored($0) } ?? false)

    // 清理 /tmp 忽略探针
    try? FileManager.default.removeItem(at: ignoreURL)

    // ================================================================
    // 汇总
    // ================================================================

    print("--------------------------------------------------")
    print("结果：\(passCount) passed / \(failures.count) failed")
    if !failures.isEmpty {
        failures.forEach { print("  FAILED: \($0)") }
        exit(1)
    }
    print("ALL GREEN")
}

// MARK: - 顶层驱动（main.swift 顶层运行于主线程 → assumeIsolated 声明主 actor 事实）

MainActor.assumeIsolated {
    runTests()
}
