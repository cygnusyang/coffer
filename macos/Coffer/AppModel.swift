// AppModel.swift —— 应用全局状态（@MainActor ObservableObject）。
//
// 职责（docs/07 §2.4）：
//   - 持有 FFI 工厂（CofferApp）与当前 VaultSession 引用
//   - appPhase 状态机：booting → noVault / locked → unlocked
//   - 建库 / 解锁 / 锁定的异步编排（Argon2id 慢调用用 Task.detached 包裹）
//
// 明文纪律（docs/07 §2.4 / §4.2）：
//   - 主密码只作为方法参数传入，不落任何 @State / @Published 属性
//   - 明文字段值只在取值那一刻经 FFI 取回，用完即弃，不进本模型

import AppKit
import Foundation
import SwiftUI

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

@MainActor
final class AppModel: ObservableObject {
    // MARK: - Published 状态

    @Published var phase: AppPhase = .booting
    @Published private(set) var vaultName: String = ""
    /// 最近一次可呈现的错误文案（code+message 直出，见 ErrorPresenter）。
    @Published var lastErrorMessage: String?
    /// 慢调用（建库 / 解锁 / 导入）进行中标记，用于禁用按钮。
    @Published private(set) var isBusy = false

    // MARK: 条目列表 / 详情状态（T05 阶段二）

    /// 当前过滤 + 搜索下的条目摘要列表。
    @Published var items: [FfiItemSummary] = []
    /// 侧栏过滤条件（变更即重载列表）。
    @Published var sidebarFilter: SidebarFilter = .all {
        didSet { guard oldValue != sidebarFilter else { return }; reloadItems() }
    }
    /// 标题搜索词（非空时走 search 接口）。
    @Published var searchText: String = ""
    /// 当前选中条目 ID。
    @Published var selectedItemID: String? {
        didSet { guard oldValue != selectedItemID else { return }; loadSelectedDetails() }
    }
    /// 选中条目的完整详情（Concealed 值已掩码）。
    @Published var currentDetails: FfiItemDetails?

    // MARK: - FFI 对象

    /// Rust 侧应用工厂（库的枚举 / 创建 / 打开注册表）。
    let factory: CofferApp
    /// 当前打开的库会话；noVault 阶段为 nil。
    private(set) var session: VaultSession?

    // MARK: - 路径

    /// 库工作目录（沙盒内 Documents/Coffer）。
    let baseDir: URL

    private var terminateObserver: NSObjectProtocol?

    // MARK: - 生命周期

    nonisolated init() {
        // 注意：AppModel 是 @MainActor，但 Swift 5 模式下 @StateObject
        // 初始化发生在主线程，这里的非隔离初始化只做确定性、无 IO 副作用的装配。
        self.factory = CofferApp()

        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Documents")
        self.baseDir = documents.appendingPathComponent("Coffer", isDirectory: true)
    }

    /// 启动入口（RootView.onAppear 调用）：建目录 + 枚举已有库。
    func bootstrap() {
        // 幂等：仅在 booting 阶段执行一次。
        guard phase == .booting else { return }
        try? FileManager.default.createDirectory(at: baseDir, withIntermediateDirectories: true)

        do {
            let briefs = try factory.listVaults(baseDir: baseDir.path)
                .sorted { $0.createdAt < $1.createdAt } // 最早创建者优先（Q-2：UI 只做单库）
            if let brief = briefs.last {
                openSession(brief)
            } else {
                phase = .noVault
            }
        } catch {
            phase = .fatal(ErrorPresenter.text(error))
        }
    }

    // MARK: - 会话管理

    /// 是否存在可用会话（密码强度估算等非门禁调用需要）。
    var hasSession: Bool { session != nil }

    private func openSession(_ brief: FfiVaultBrief) {
        do {
            let opened = try factory.openVault(baseDir: baseDir.path, vaultUuid: brief.vaultUuid)
            session = opened
            vaultName = brief.displayName
            phase = .locked
        } catch {
            phase = .fatal(ErrorPresenter.text(error))
        }
    }

    // MARK: - 建库

    /// 创建库（zxcvbn 门禁在 Rust 侧，score < 3 → 错误码 1010）。
    /// Argon2id 256 MiB 档位派生耗时约 0.5–1 s，用 Task.detached 包裹避免卡主线程。
    func createVault(name: String, password: String) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        let factory = self.factory
        let dir = self.baseDir.path
        do {
            let brief = try await Task.detached(priority: .userInitiated) {
                try factory.createVault(baseDir: dir, name: name, password: password)
            }.value
            openSession(brief)
        } catch {
            lastErrorMessage = ErrorPresenter.text(error)
        }
    }

    // MARK: - 解锁 / 锁定

    /// 解锁（Argon2id 慢调用，Task.detached 包裹）。
    /// 密码只作为参数传入：拷贝进 Task 闭包使用后即弃，不落任何属性。
    func unlock(password: String) async {
        guard let session, !isBusy else { return }
        isBusy = true
        defer { isBusy = false }

        do {
            let target = session
            let info = try await Task.detached(priority: .userInitiated) {
                try target.unlock(password: password)
            }.value
            vaultName = info.displayName
            phase = .unlocked
        } catch {
            lastErrorMessage = ErrorPresenter.text(error)
        }
    }

    /// 手动锁定：清零 Rust 侧密钥，回到锁定态。
    func lock() {
        session?.lock()
        phase = session != nil ? .locked : .noVault
    }

    /// 进程退出兜底（AppDelegate.applicationWillTerminate 调用）。
    nonisolated func lockAllForTermination() {
        MainActor.assumeIsolated {
            factory.lockAll()
        }
    }

    // MARK: - 密码强度（非门禁展示用）

    /// 强度估算：有会话时走 Rust 侧 zxcvbn（锁定态也可用，非门禁接口）；
    /// 无会话（首次建库）时返回 nil，由 UI 用本地粗估兜底。
    func estimateStrength(_ candidate: String) -> FfiStrengthEstimate? {
        guard let session else { return nil }
        return try? session.strengthEstimate(candidate: candidate)
    }
}
