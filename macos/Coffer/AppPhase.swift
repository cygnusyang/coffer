// AppPhase.swift —— 应用阶段状态机（纯 Foundation，独立文件）。
//
// v2.11.0 W1a 追加（lead 裁定）：自 AppModel.swift 纯移动至此——DropzoneImportContext
// 协议（docs/19 §3.2）引用 AppPhase，AppModel.swift 是 AppKit+SwiftUI 重依赖，L1
// harness（FFI-linked，docs/19 §3.3）无法 standalone 编译之。AppPhase 仅关联 String，
// 零 AppKit/SwiftUI 耦合，独立成文件后 harness 只需编译本文件（零行为变化，同 target
// 内引用不需 import）。

import Foundation

/// 应用阶段状态机。
enum AppPhase: Equatable {
    /// 启动中：枚举工作目录里的库。
    case booting
    /// 工作目录没有库：进入建库流程。
    case noVault
    /// 已有库但处于锁定态。
    case locked
    /// 已解锁，进入条目管理。
    case unlocked
    /// 不可恢复的启动失败（列出原因，引导用户检查环境）。
    case fatal(String)
}
