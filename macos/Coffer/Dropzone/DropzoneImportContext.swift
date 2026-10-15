// DropzoneImportContext.swift —— 放置区导入 model 需要的 AppModel 窄面
// （docs/19 §3.2 契约 stub 先例）。
//
// AppModel 是 @MainActor + SwiftUI 重依赖，不可 standalone 实例化（docs/18
// §4.x 已实证）；DropzoneImportModel 以本协议收窄依赖面（phase /
// dropzoneAuthStatus / session / 写回 / 刷新），AppModel 在下方 extension 里
// conform（AppModel.swift 零改动），测试用内存 stub 替换。
//
// 通用模式（docs/19 §3.4 ②）：AppModel 面收窄为协议（extension conform，
// 测试内存 stub）——DropzoneBookmarkTests/main.swift:68-74 契约镜像先例的
// 协议化演进。

import Foundation

/// model 需要的 AppModel 窄面（AppModel 在 extension 里 conform；测试用内存 stub）。
///
/// `@MainActor`：AppModel 全体成员均为主 actor 隔离，协议标 @MainActor 使
/// conform 无隔离交叉（否则 Swift 5 出 conformance-isolation 警告、Swift 6 为错误）；
/// model 同为 @MainActor，读取侧无摩擦。测试 stub 须标 @MainActor（docs/19 §3.3
/// harness 内存 context stub）。
@MainActor
protocol DropzoneImportContext: AnyObject {
    /// 应用阶段（锁定停摆 W-2 判据：非 .unlocked 即停表）。
    var phase: AppPhase { get }
    /// 放置区授权三态（AppModel.dropzoneAuthStatus 派生单一真相，D-18.4）。
    var dropzoneAuthStatus: DropzoneAuthStatus { get }
    /// 当前库会话（S2 预检 / S4 导入执行用；nil = 无会话）。
    var session: VaultSession? { get }
    /// 落盘放置区授权并广播（S0 授权唯一写点接线，D-18.4）。
    func setDropzoneBookmark(_ bookmark: DropzoneBookmark)
    /// 导入成功后刷新条目列表。
    func reloadItems()
}

// MARK: - 生产 conform（AppModel.swift 零改动）

extension AppModel: DropzoneImportContext {}
