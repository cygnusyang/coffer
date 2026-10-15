// DropzoneBookmarkStore.swift —— 放置区安全作用域授权目录的持久化凭据
// （docs/21-密码导入放置区设计.md §2.3 / docs/21a-放置区导入实现方案.md §3.2）。
//
// 生命周期（D-18.4 单写单删 + 广播）：
//   - ★ 唯一写点 = 向导 S0 授权（save）
//   - ★ 唯一删点 = 设置页「移除授权」（remove）
//   - 失效检测 = validate（A-3 实证：目录删除/改名/权限变更后判定 false）
//   - 访问配对 = withAccess（startAccessing / stopAccessing 严格配对，A-4：
//     用完即停、不驻留句柄）
//
// R2 纪律：本类型只读写 UserDefaults（dropzone.bookmark.data 冻结键），不触碰
// 授权目录内容；授权目录的只读是代码纪律级承诺（docs/21 §4.6），由调用方保证
// 不写、不删。

import Foundation

/// 授权目录的安全作用域 bookmark（URL + 持久化凭据）。
struct DropzoneBookmark: Equatable {
    /// 授权目录 URL（安全作用域）。
    let url: URL
    /// 持久化凭据（URL.withSecurityScope 的 bookmarkData）。
    let bookmarkData: Data
}

/// 授权三态（docs/21a §3.2 冻结接口；G5 以 `AppModel.dropzoneAuthStatus`
/// 派生单一真相，向导与设置页同源同步）。
enum DropzoneAuthStatus: Equatable {
    case notAuthorized
    case authorized(DropzoneBookmark)
    case stale(DropzoneBookmark)
}

/// bookmark 生命周期错误（面向调用方可操作：stale → 重新授权；创建/解析失败 → 重试）。
enum DropzoneBookmarkError: Error, LocalizedError {
    /// 授权失效（startAccessingSecurityScopedResource 返回 false 或目录不可达）。
    case stale(DropzoneBookmark)
    /// 从目录 URL 生成 bookmarkData 失败。
    case createBookmark(URL)
    /// bookmarkData 无法解析回 URL（数据损坏）。
    case resolveBookmark

    var errorDescription: String? {
        switch self {
        case .stale:
            return "放置区授权已失效，请重新授权。"
        case .createBookmark:
            return "无法创建放置区授权凭据，请重试。"
        case .resolveBookmark:
            return "无法读取放置区授权凭据，请重新授权。"
        }
    }
}

/// security-scoped bookmark 存取（唯一写点 / 唯一删点 / 失效检测 / 访问配对）。
///
/// 线程安全：内部以 NSLock 串行化 UserDefaults 读写；文件系统判定本身线程安全，
/// 可被监视循环（后台队列）与 UI（主队列）并发调用。
final class DropzoneBookmarkStore {
    static let shared = DropzoneBookmarkStore()

    /// UserDefaults 键（docs/21a §2.3 冻结，勿改）。
    static let bookmarkDefaultsKey = "dropzone.bookmark.data"

    private let defaults: UserDefaults
    private let lock = NSLock()

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// 读授权（nil = 未授权）。bookmark 无法解析（数据损坏）按未授权处理；
    /// 失效的确定路径由 validate() 判定——目录删除/改名/权限变更通常仍可解析。
    func load() -> DropzoneBookmark? {
        lock.lock()
        defer { lock.unlock() }
        guard let data = defaults.data(forKey: Self.bookmarkDefaultsKey) else { return nil }
        var isStale = false
        do {
            let url = try URL(resolvingBookmarkData: data,
                              options: [.withSecurityScope],
                              relativeTo: nil,
                              bookmarkDataIsStale: &isStale)
            return DropzoneBookmark(url: url, bookmarkData: data)
        } catch {
            // 数据损坏/不可解析：无 URL 可呈现，返回 nil 走未授权（A-3 实证范围外路径）。
            return nil
        }
    }

    /// ★ 唯一写点（向导 S0 授权）：为目录 URL 生成 bookmark 并持久化。
    func save(_ url: URL) throws -> DropzoneBookmark {
        let data: Data
        do {
            data = try url.bookmarkData(options: [.withSecurityScope],
                                        includingResourceValuesForKeys: nil,
                                        relativeTo: nil)
        } catch {
            throw DropzoneBookmarkError.createBookmark(url)
        }
        lock.lock()
        defer { lock.unlock() }
        defaults.set(data, forKey: Self.bookmarkDefaultsKey)
        return DropzoneBookmark(url: url, bookmarkData: data)
    }

    /// ★ 唯一删点（设置页「移除授权」）。
    func remove() {
        lock.lock()
        defer { lock.unlock() }
        defaults.removeObject(forKey: Self.bookmarkDefaultsKey)
    }

    /// 失效检测（A-3）：目录须存在、可进入安全作用域、且可读。chmod 000 等权限
    /// 变更场景 startAccessing 可能仍返回 true，须以目录枚举兜底并入 stale 判定。
    func validate(_ b: DropzoneBookmark) -> Bool {
        let scoped = b.url.startAccessingSecurityScopedResource()
        defer { if scoped { b.url.stopAccessingSecurityScopedResource() } }
        guard scoped else { return false }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: b.url.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            return false
        }
        do {
            _ = try FileManager.default.contentsOfDirectory(atPath: b.url.path)
            return true
        } catch {
            return false
        }
    }

    /// 访问配对：body 执行期间持有安全作用域访问权，结束即停（A-4，不驻留句柄）。
    /// startAccessingSecurityScopedResource 失败（授权失效）→ 抛 stale，调用方转 .stale。
    func withAccess<T>(_ b: DropzoneBookmark, _ body: () throws -> T) throws -> T {
        let scoped = b.url.startAccessingSecurityScopedResource()
        guard scoped else { throw DropzoneBookmarkError.stale(b) }
        defer { b.url.stopAccessingSecurityScopedResource() }
        return try body()
    }
}
