// StatusItemController.swift —— 菜单栏常驻 NSStatusItem（PL-6，v0.5.0 回归修复）。
//
// 背景（PL-6；缺陷登记 docs/KNOWN-ISSUES.md 由 lead 核验后写）：macOS 26
// （Darwin 25.6.0）上 SwiftUI MenuBarExtra(.menu) 的状态栏图标渲染为空白——
// AX 层状态项存在但像素级扫描前景像素=0，菜单入口不可见。同屏其他 App 的
// AppKit NSStatusItem 图标全部正常渲染（本机菜单栏实证），故 v0.5.0 直接切
// AppKit 路线，不做「先试自定义 asset 再说」两段式。
//
// 职责（菜单项路由表 = 本文件头注职责块，docs/15 §3.3.1 为过期锚点已弃；语义
// 与 v0.4 MC-1 MenuBarExtra 完全一致）：
//   - 打开主窗口（title 并入库名+状态文案，随 phase/vaultName 刷新）→
//     AppDelegate.summonMainWindow（2026-10-16 用户裁定：取消永久 disabled 的
//     纯展示状态行——「可用不灰、永久不可用不占位」，状态并入打开项标题）
//   - 快速搜索…（⌥⌘P）→ AppDelegate.summonMainWindow
//   - 锁定全部 → model.factory.lockAll() + model.lock()（既有 API 双保险）
//   - 退出 Coffer → NSApp.terminate(nil)
//   - 图标：程序化绘制的 template 单色图案（品牌 = 经典挂锁轮廓；锁态 U 形
//     锁梁 + 实心锁体，解锁态锁梁向左上旋开、右腿抬离锁体顶边），随 phase
//     切换。禁用彩色——菜单栏图标必须 template，由系统按深浅色自适应渲染。
//
// 切片纪律：只读消费 AppModel（Combine 订阅 $phase / $vaultName）+ 调既有 API，
// 不新增不改 AppModel 状态机。
//
// 线程契约：start/stop 主线程调用（start 经 AppDelegate.attach，落点
// RootView.onAppear；stop 经 applicationWillTerminate）；@Published 在主线程
// 变更，订阅回调经 MainActor 隔离刷新（与 HotKeyMonitor 同纪律）。

import AppKit
import Combine

@MainActor
final class StatusItemController: NSObject {
    /// 状态栏项（start() 创建；stop()/deinit 移除）。
    private(set) var statusItem: NSStatusItem?

    /// 「打开主窗口」菜单项（title 并入状态文案，随 phase/vaultName 刷新）。
    private weak var openMenuItem: NSMenuItem?

    /// AppModel 弱引用（与 AppDelegate 同纪律：避免生命周期循环，由宿主持有）。
    private weak var model: AppModel?

    /// 主窗口呼出回调（AppDelegate 注入，转发 summonMainWindow(focusText:)）。
    private var summonMainWindow: ((Bool) -> Void)?

    /// Combine 订阅（phase/vaultName 变化驱动图标与状态行刷新）。
    private var cancellables = Set<AnyCancellable>()

    // MARK: - 生命周期

    /// 创建状态栏项并开始订阅。主线程调用（AppDelegate.attach，RootView.onAppear）。
    /// - Parameters:
    ///   - model: 应用状态（只读消费 $phase / $vaultName / factory）。
    ///   - summonMainWindow: 呼出/聚焦主窗口回调（focusText: Bool）。
    func start(model: AppModel, summonMainWindow: @escaping (Bool) -> Void) {
        self.model = model
        self.summonMainWindow = summonMainWindow

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = Self.icon(phase: model.phase)
        item.menu = buildMenu(model: model)
        statusItem = item
        openMenuItem = item.menu?.item(at: 0)

        subscribe(to: model)
    }

    /// 移除状态栏项并取消订阅（applicationWillTerminate 调用；幂等）。
    func stop() {
        cancellables.removeAll()
        if let statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
        }
        statusItem = nil
        openMenuItem = nil
        model = nil
        summonMainWindow = nil
    }

    deinit {
        // 兜底清理：stop() 已在 applicationWillTerminate 主线程调用，此处仅防
        // 漏删。宿主（AppDelegate）在主线程持有并释放，deinit 实为主线程；
        // 不做线程跳转（避免捕获非 Sendable NSStatusItem 的告警）。
        if let statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
        }
    }

    // MARK: - 菜单构建（docs/15 §3.3.1 路由表）

    /// 组装菜单：打开主窗口（并入状态文案）+ 快速搜索…（⌥⌘P）+ 锁定全部 + 退出。
    /// 状态信息并入可点击的打开项（用户裁定 2026-10-16：永久 disabled 的状态行
    /// 违反「可用不灰/永久不可用不占位」原则，故不设纯展示行）。
    private func buildMenu(model: AppModel) -> NSMenu {
        let menu = NSMenu()

        // 打开主窗口：呼出/聚焦，不改焦点（focusText: false）；title 并入
        // 库名+状态文案（openTitle 纯函数，随 phase/vaultName 订阅刷新）。
        let open = NSMenuItem(title: MenuStatusText.openTitle(phase: model.phase, vaultName: model.vaultName),
                              action: #selector(openMainWindow(_:)), keyEquivalent: "")
        open.target = self
        menu.addItem(open)

        // 快速搜索…：呼出/聚焦主窗口搜索框（research §6 判据①落主窗口聚焦，
        // 不建独立面板）；锁定态可用——窗口内先展示解锁页。keyEquivalent
        // 显示 ⌥⌘P（"p" + [.command, .option]，与 HK-1 全局键位一致）。
        let search = NSMenuItem(title: String(localized: "快速搜索…"), action: #selector(quickSearch(_:)), keyEquivalent: "p")
        search.keyEquivalentModifierMask = [.command, .option]
        search.target = self
        menu.addItem(search)

        menu.addItem(.separator())

        // 锁定全部（docs/15 §3.3.1）：factory 全局锁所有会话 + model.lock()
        // 清 UI 状态与剪贴板；均幂等，锁定态可用
        let lock = NSMenuItem(title: String(localized: "锁定全部"), action: #selector(lockAll(_:)), keyEquivalent: "")
        lock.target = self
        menu.addItem(lock)

        menu.addItem(.separator())

        let quit = NSMenuItem(title: String(localized: "退出 Coffer"), action: #selector(quit(_:)), keyEquivalent: "")
        quit.target = self
        menu.addItem(quit)

        return menu
    }

    // MARK: - 动作

    @objc private func openMainWindow(_ sender: Any?) {
        summonMainWindow?(false)
    }

    @objc private func quickSearch(_ sender: Any?) {
        summonMainWindow?(true)
    }

    @objc private func lockAll(_ sender: Any?) {
        // 既有 API 双保险（docs/15 §3.3.1）；锁定态可用（幂等）
        model?.factory.lockAll()
        model?.lock()
    }

    @objc private func quit(_ sender: Any?) {
        NSApp.terminate(nil)
    }

    // MARK: - phase/vaultName 订阅刷新（只读消费）

    /// 订阅 $phase 与 $vaultName，变化即刷新图标与打开项标题。
    private func subscribe(to model: AppModel) {
        model.$phase
            .combineLatest(model.$vaultName)
            .receive(on: RunLoop.main)
            .sink { [weak self] phase, vaultName in
                MainActor.assumeIsolated {
                    self?.refresh(phase: phase, vaultName: vaultName)
                }
            }
            .store(in: &cancellables)
    }

    /// phase/vaultName 变化 → 刷新图标与打开项标题（只读，不改 AppModel）。
    private func refresh(phase: AppPhase, vaultName: String) {
        statusItem?.button?.image = Self.icon(phase: phase)
        openMenuItem?.title = MenuStatusText.openTitle(phase: phase, vaultName: vaultName)
    }

    // MARK: - 纯函数面（可独立测试）

    /// 图标渲染尺寸（约 18pt 高，符合 NSStatusItem 惯例）。nonisolated：
    /// 纯常量，供测试直接读取。单一来源 = MenuIconGeometry.canvasSize。
    nonisolated static let imageSize = NSSize(
        width: MenuIconGeometry.canvasSize,
        height: MenuIconGeometry.canvasSize
    )

    /// 打开项标题与状态文案纯函数已抽至 MenuStatusText（Support/MenuStatusText.swift，
    /// 2026-10-16 抽取自本文件——可独立 swiftc 选编单测，AppKit 控制器不进 harness）。

    /// 程序化绘制菜单栏 template 图标（纯函数；black+alpha，isTemplate=true）。
    ///
    /// 品牌 = 经典挂锁轮廓（D2 重绘，docs/18 r0.2：锁梁由「圆形半圆」改「短竖直
    /// 腿 + 两段三次贝塞尔椭圆上半弧」扁穹——短扁敦实向 SF Symbols 挂锁比例靠，
    /// 参数单一来源 = MenuIconGeometry，几何断言见 Tests/MenuIconGeometryTests）。
    /// 两态共用同一锁体，仅锁梁姿态不同：
    ///   - 锁态：扁穹锁梁拱在锁体顶边，腿端沉入锁体（sink）被覆盖；锁体实心
    ///     （无钥匙孔，1x 下体宽 ~10×7pt，内部细节一律糊成点）
    ///   - 解锁态：锁梁绕左腿底端（锁体顶边左腿处）向左上旋转 40°；右腿随之
    ///     抬离锁体顶边 2×rx×sin40° = 0.257×glyph ≥ 0.18 硬阈值，一眼可辨。
    ///     大色块、无细特征，1x 清晰。
    nonisolated static func icon(phase: AppPhase) -> NSImage {
        // —— 锁体：实心圆角矩形（§4：0.72×0.54×glyph，圆角 0.12×体宽），底对齐
        //    glyph 底（flipped:false 即 y-up，glyph.minY = 底部）。
        let body = NSBezierPath(
            roundedRect: MenuIconGeometry.bodyRect,
            xRadius: MenuIconGeometry.bodyWidth * MenuIconGeometry.bodyCornerFactor,
            yRadius: MenuIconGeometry.bodyWidth * MenuIconGeometry.bodyCornerFactor
        )

        // —— 锁梁：U 形开放描边（圆头线帽、圆角线接；§5.1 竖直腿 + 两段三次
        //    贝塞尔椭圆上半弧，k=0.5523）。绘序先锁梁后锁体——锁态腿端沉入
        //    体顶（sink）被实心锁体覆盖，圆帽不外露。
        let lineWidth = MenuIconGeometry.lineWidth

        func makeShackle(legBottomY: CGFloat) -> NSBezierPath {
            let a = MenuIconGeometry.shackleAnchors(legBottomY: legBottomY)
            let p = NSBezierPath()
            p.lineWidth = lineWidth
            p.lineCapStyle = .round
            p.lineJoinStyle = .round
            p.move(to: a.leftLegBottom)
            p.line(to: a.leftLegTop)
            p.curve(to: a.domeTop,
                    controlPoint1: a.domeLeftCP1,
                    controlPoint2: a.domeLeftCP2)
            p.curve(to: a.rightLegTop,
                    controlPoint1: a.domeRightCP1,
                    controlPoint2: a.domeRightCP2)
            p.line(to: a.rightLegBottom)
            return p
        }

        let shackle: NSBezierPath
        if phase == .unlocked {
            // 解锁态：腿端平齐锁体顶边（脱扣搁在锁体上），整体绕左腿底端（=
            // 锁体顶边左腿处）向左上旋转 40°（y-up 正角 = 逆时针，右腿上抬）。
            // 右腿底端抬离 = 2×rx×sin40° = 0.257×glyph ≥ 0.18 硬阈值
            // （docs/18 §8.5 LOW-2 测试守护）。
            let anchor = NSPoint(
                x: MenuIconGeometry.glyph.midX - MenuIconGeometry.shackleRx,
                y: MenuIconGeometry.bodyTopY
            )
            var tf = AffineTransform()
            tf.translate(x: anchor.x, y: anchor.y)
            tf.rotate(byDegrees: MenuIconGeometry.unlockAngleDegrees)
            tf.translate(x: -anchor.x, y: -anchor.y)
            let rotated = NSBezierPath()
            rotated.append(makeShackle(legBottomY: MenuIconGeometry.bodyTopY))
            rotated.lineWidth = lineWidth
            rotated.lineCapStyle = .round
            rotated.lineJoinStyle = .round
            rotated.transform(using: tf)
            shackle = rotated
        } else {
            // 锁态：腿端沉入锁体顶边 sink（被实心锁体覆盖）
            shackle = makeShackle(legBottomY: MenuIconGeometry.bodyTopY - MenuIconGeometry.sink)
        }

        let image = NSImage(size: Self.imageSize, flipped: false) { _ in
            NSColor.black.setFill()
            // 先锁梁后锁体：锁体实心覆盖锁梁沉入的腿端
            shackle.stroke()
            body.fill()
            return true
        }
        image.isTemplate = true
        return image
    }
}
