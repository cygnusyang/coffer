// VersionCompare.swift —— 版本号比较（docs/35 §6.1/§6.3 语义：semver 数字点分）。
//
// 用于 check() 的可升级判定与 minimumVersion 拒装判定。纯函数，可独立测试
// （Tests/UpdateTests）。语义：`CFBundleShortVersionString` 点分数字，如
// 2.7.0 / 2.10；缺组件按 0 补齐（2.7 == 2.7.0）；非数字组件无法比较 → nil。

import Foundation

/// 版本比较（纯函数，无状态）。
enum VersionCompare {
    /// 两版本相对序（lhs 相对 rhs）。
    enum Order: Equatable {
        /// lhs < rhs
        case ascending
        /// lhs == rhs
        case equal
        /// lhs > rhs
        case descending
    }

    /// 逐点分数字组件比较（缺失组件按 0 补齐）。任一点分含非数字 → nil
    /// （无法比较，fail-closed 由调用方处理）。
    static func compare(_ lhs: String, _ rhs: String) -> Order? {
        guard let l = components(lhs), let r = components(rhs) else {
            return nil
        }
        let count = max(l.count, r.count)
        for i in 0..<count {
            let a = i < l.count ? l[i] : 0
            let b = i < r.count ? r[i] : 0
            if a < b { return .ascending }
            if a > b { return .descending }
        }
        return .equal
    }

    /// 新版本是否比当前新（new > current）。
    static func isNewer(_ new: String, than current: String) -> Bool {
        compare(new, current) == .descending
    }

    /// 当前版本是否低于最低可安装版本（minimum > current → 拒装判据）。
    static func isBelow(_ current: String, minimum: String) -> Bool {
        compare(current, minimum) == .ascending
    }

    /// 点分版本拆成整数数组；含非数字点分 → nil。
    private static func components(_ v: String) -> [Int]? {
        let parts = v.split(separator: ".")
        var result: [Int] = []
        result.reserveCapacity(parts.count)
        for part in parts {
            guard let n = Int(part) else { return nil }
            result.append(n)
        }
        return result
    }
}
