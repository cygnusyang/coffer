// DropzoneFingerprintStore.swift —— 放置区「已导入过/已忽略」元数据指纹
// （docs/21a-v2.11.0-放置区导入-实现方案.md §2.3 / docs/21-v2.11.0-密码导入放置区-设计.md §4.6 R2）。
//
// 键格式 = <文件名>\u{1F}<size>|<mtimeMs>（冻结，勿改）。指纹只含名+大小+mtime
// 元数据，不含内容摘要、不含明文（S-4 判据 + R2「已忽略指纹」纪律）。同名同大小
// 同 mtime 的误判「已导入过」为良性（仅徽标 + 可覆盖提示，非拦截，docs/21a §5.4）。
//
// 已导入 / 已忽略分别独立落 UserDefaults（dropzone.imported.fingerprints /
// dropzone.ignored.fingerprints 冻结键）；removeIgnored 供 S1.5「取消忽略」使用。
// 本类不触碰授权目录内容，只读写 UserDefaults（目录只读纪律）。

import Foundation

/// 放置区文件元数据指纹存取（Set<String> 于 UserDefaults，NSLock 串行化）。
final class DropzoneFingerprintStore {
    static let shared = DropzoneFingerprintStore()

    /// UserDefaults 键（docs/21a §2.3 冻结，勿改）。
    static let importedDefaultsKey = "dropzone.imported.fingerprints"
    static let ignoredDefaultsKey = "dropzone.ignored.fingerprints"

    /// 文件名与大小/mtime 之间的分隔符（冻结：\u{1F} 单位分隔符，避免与文件名内
    /// 任意字符冲突）。
    private static let separator = "\u{1F}"

    private let defaults: UserDefaults
    private let lock = NSLock()

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// 由文件 URL 派生指纹；无法读取大小/mtime（非文件/无权限）返回 nil。
    func fingerprint(for url: URL) -> String? {
        guard let values = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
              let size = values.fileSize,
              let mtime = values.contentModificationDate else {
            return nil
        }
        return Self.makeFingerprint(fileName: url.lastPathComponent,
                                    size: Int64(size),
                                    mtimeMs: Int64(mtime.timeIntervalSince1970 * 1000))
    }

    /// 指纹字符串（名 + 大小 + mtime 毫秒；不含内容摘要）。
    static func makeFingerprint(fileName: String, size: Int64, mtimeMs: Int64) -> String {
        "\(fileName)\(separator)\(size)|\(mtimeMs)"
    }

    /// 标记已导入过（S5 导入成功）。
    func markImported(_ fingerprint: String) {
        mutate(key: Self.importedDefaultsKey) { $0.insert(fingerprint) }
    }

    /// 标记已忽略（S2-E / S1.5 忽略）。
    func markIgnored(_ fingerprint: String) {
        mutate(key: Self.ignoredDefaultsKey) { $0.insert(fingerprint) }
    }

    /// 是否已导入过（S1.5 徽标 + 放行提示）。
    func isImported(_ fingerprint: String) -> Bool {
        readSet(key: Self.importedDefaultsKey).contains(fingerprint)
    }

    /// 是否已忽略（S2-E 显示用）。
    func isIgnored(_ fingerprint: String) -> Bool {
        readSet(key: Self.ignoredDefaultsKey).contains(fingerprint)
    }

    /// 取消忽略（S1.5）：从忽略集合移除。
    func removeIgnored(_ fingerprint: String) {
        mutate(key: Self.ignoredDefaultsKey) { $0.remove(fingerprint) }
    }

    // MARK: 私有

    private func readSet(key: String) -> Set<String> {
        lock.lock()
        defer { lock.unlock() }
        return Set(defaults.stringArray(forKey: key) ?? [])
    }

    private func mutate(key: String, _ body: (inout Set<String>) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        var set = Set(defaults.stringArray(forKey: key) ?? [])
        body(&set)
        defaults.set(Array(set), forKey: key)
    }
}
