// StatusItemController.swift —— 菜单栏常驻 NSStatusItem（PL-6，v0.5.0 回归修复）。
//
// 背景（PL-6；缺陷登记 docs/KNOWN-ISSUES.md 由 lead 核验后写）：macOS 26
// （Darwin 25.6.0）上 SwiftUI MenuBarExtra(.menu) 的状态栏图标渲染为空白——
// AX 层状态项存在但像素级扫描前景像素=0，菜单入口不可见。同屏其他 App 的
// AppKit NSStatusItem 图标全部正常渲染（本机菜单栏实证），故 v0.5.0 直接切
// AppKit 路线，不做「先试自定义 asset 再说」两段式。
//
// 职责（docs/15 §3.3.1 菜单项路由表，语义与 v0.4 MC-1 MenuBarExtra 完全一致）：
//   - 状态行（disabled 菜单项，仅展示）：库名 + 锁定/已解锁，五相文案
//   - 打开主窗口 / 快速搜索…（⌥⌘P）→ AppDelegate.summonMainWindow
//   - 锁定全部 → model.factory.lockAll() + model.lock()（既有 API 双保险）
//   - 退出 Coffer → NSApp.terminate(nil)
//   - 图标：程序化绘制的 template 单色图案（品牌 = 经典挂锁轮廓；锁态 U 形
//     锁梁 + 实心锁体，解锁态锁梁向左上旋开、右腿抬离锁体顶边），随 phase
//     切换。禁用彩色——菜单栏图标必须 template，由系统按深浅色自适应渲染。
//
// 切片纪律（docs/15 §6.1 S3）：只读消费 AppModel（Combine 订阅 $phase /
// $vaultName）+ 调既有 API，不新增不改 AppModel 状态机。
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

    /// 状态行菜单项（disabled，title 随 phase/vaultName 刷新）。
    private weak var statusMenuItem: NSMenuItem?

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
        statusMenuItem = item.menu?.item(at: 0)

        subscribe(to: model)
    }

    /// 移除状态栏项并取消订阅（applicationWillTerminate 调用；幂等）。
    func stop() {
        cancellables.removeAll()
        if let statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
        }
        statusItem = nil
        statusMenuItem = nil
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

    /// 组装菜单：状态行 + 打开主窗口 + 快速搜索…（⌥⌘P）+ 锁定全部 + 退出。
    private func buildMenu(model: AppModel) -> NSMenu {
        let menu = NSMenu()

        // 状态行（disabled，仅展示；title 由订阅刷新）
        let statusLine = NSMenuItem(
            title: Self.statusLine(phase: model.phase, vaultName: model.vaultName),
            action: nil, keyEquivalent: ""
        )
        statusLine.isEnabled = false
        statusMenuItem = statusLine
        menu.addItem(statusLine)

        menu.addItem(.separator())

        // 打开主窗口：呼出/聚焦，不改焦点（focusText: false）
        let open = NSMenuItem(title: "打开主窗口", action: #selector(openMainWindow(_:)), keyEquivalent: "")
        open.target = self
        menu.addItem(open)

        // 快速搜索…：呼出/聚焦主窗口搜索框（research §6 判据①落主窗口聚焦，
        // 不建独立面板）；锁定态可用——窗口内先展示解锁页。keyEquivalent
        // 显示 ⌥⌘P（"p" + [.command, .option]，与 HK-1 全局键位一致）。
        let search = NSMenuItem(title: "快速搜索…", action: #selector(quickSearch(_:)), keyEquivalent: "p")
        search.keyEquivalentModifierMask = [.command, .option]
        search.target = self
        menu.addItem(search)

        menu.addItem(.separator())

        // 锁定全部（docs/15 §3.3.1）：factory 全局锁所有会话 + model.lock()
        // 清 UI 状态与剪贴板；均幂等，锁定态可用
        let lock = NSMenuItem(title: "锁定全部", action: #selector(lockAll(_:)), keyEquivalent: "")
        lock.target = self
        menu.addItem(lock)

        menu.addItem(.separator())

        let quit = NSMenuItem(title: "退出 Coffer", action: #selector(quit(_:)), keyEquivalent: "")
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

    /// 订阅 $phase 与 $vaultName，变化即刷新图标与状态行。
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

    /// phase/vaultName 变化 → 刷新图标与状态行（只读，不改 AppModel）。
    private func refresh(phase: AppPhase, vaultName: String) {
        statusItem?.button?.image = Self.icon(phase: phase)
        statusMenuItem?.title = Self.statusLine(phase: phase, vaultName: vaultName)
    }

    // MARK: - 纯函数面（可独立测试）

    /// 图标渲染尺寸（约 18pt 高，符合 NSStatusItem 惯例）。nonisolated：
    /// 纯常量，供测试直接读取。
    nonisolated static let imageSize = NSSize(width: 18, height: 18)
    /// 图形区四周留边距（模板图标不宜顶满，深浅色下更好看）。
    private nonisolated static let glyphInset: CGFloat = 2

    /// 状态行文案（只读派生，语义与 v0.4 MC-1 menuStatusLine 一致；纯函数）。
    nonisolated static func statusLine(phase: AppPhase, vaultName: String) -> String {
        switch phase {
        case .booting:
            return "正在打开…"
        case .noVault:
            return "未创建密码库"
        case .locked:
            return vaultName.isEmpty ? "已锁定" : "\(vaultName)（已锁定）"
        case .unlocked:
            return vaultName.isEmpty ? "已解锁" : "\(vaultName)（已解锁）"
        case .fatal:
            return "启动失败"
        }
    }

    /// 程序化绘制菜单栏 template 图标（纯函数；black+alpha，isTemplate=true）。
    ///
    /// 品牌 = 经典挂锁轮廓（lead 返工规格，替代旧「圆角方形 + 钥匙孔」——
    /// 后者 1x 下钥匙孔仅 ~4.8pt，观感如霉斑）。两态共用同一锁体，仅锁梁姿态不同：
    ///   - 锁态：锁梁 U 形拱在锁体顶边，两腿沉入锁体被覆盖；锁体实心（无钥匙孔，
    ///     1x 下体宽 ~9×7pt，内部细节一律糊成点）
    ///   - 解锁态：锁梁绕左腿底端（锁体顶边）向左上旋转 ~40°；右腿随之抬离
    ///     锁体顶边 ≥0.18×glyph，一眼可辨。大色块、无细特征，1x 清晰。
    nonisolated static func icon(phase: AppPhase) -> NSImage {
        let glyph = NSRect(
            x: Self.glyphInset, y: Self.glyphInset,
            width: Self.imageSize.width - Self.glyphInset * 2,
            height: Self.imageSize.height - Self.glyphInset * 2
        )

        // —— 锁体：实心圆角矩形，底对齐 glyph 底（flipped:false 即 y-up，
        //     glyph.minY = 底部）。宽 ≈0.64×glyph、高 ≈0.52×glyph、圆角 ≈0.12×体宽。
        let bodyWidth = glyph.width * 0.64
        let bodyHeight = glyph.height * 0.52
        let bodyTopY = glyph.minY + bodyHeight
        let body = NSBezierPath(
            roundedRect: NSRect(
                x: glyph.midX - bodyWidth / 2, y: glyph.minY,
                width: bodyWidth, height: bodyHeight
            ),
            xRadius: bodyWidth * 0.12, yRadius: bodyWidth * 0.12
        )

        // —— 锁梁：U 形开放描边（圆头线帽），弧顶距 glyph 顶 ≈0.02×glyph，
        //    两腿下端沉入锁体顶边内（被锁体填充覆盖即可）。y-up 下弧线自左
        //    (180°) 经顶 (90°) 到右 (0°) 为顺时针（角度递减）。
        let lineWidth = glyph.height * 0.15
        let arcRadius = glyph.height * 0.22
        let legX = glyph.midX - arcRadius
        let arcCenterY = glyph.maxY - glyph.height * 0.02 - arcRadius

        func makeShackle(legBottomY: CGFloat) -> NSBezierPath {
            let p = NSBezierPath()
            p.lineWidth = lineWidth
            p.lineCapStyle = .round
            p.lineJoinStyle = .round
            p.move(to: NSPoint(x: legX, y: legBottomY))
            p.line(to: NSPoint(x: legX, y: arcCenterY))
            p.appendArc(
                withCenter: NSPoint(x: glyph.midX, y: arcCenterY), radius: arcRadius,
                startAngle: 180, endAngle: 360, clockwise: true
            )
            p.line(to: NSPoint(x: glyph.midX + arcRadius, y: legBottomY))
            return p
        }

        let shackle: NSBezierPath
        if phase == .unlocked {
            // 解锁态：锁梁两腿端平齐锁体顶边（不再沉入，呈「脱扣搁在锁体上」），
            // 整体绕左腿底端（= 锁体顶边左腿处）向左上旋转 ~40°。右腿底端随之
            // 抬离锁体顶边：路径端点 ≈0.28×glyph，含圆头仍 ≥0.2×glyph——
            // 高于 0.18×glyph 硬性阈值且留抗锯齿余量，悬空一目可辨。
            let anchor = NSPoint(x: legX, y: bodyTopY)
            var tf = AffineTransform()
            tf.translate(x: anchor.x, y: anchor.y)
            tf.rotate(byDegrees: 40)   // y-up 下正角 = 逆时针：右侧上抬
            tf.translate(x: -anchor.x, y: -anchor.y)
            let rotated = NSBezierPath()
            rotated.append(makeShackle(legBottomY: bodyTopY))
            rotated.lineWidth = lineWidth
            rotated.lineCapStyle = .round
            rotated.lineJoinStyle = .round
            rotated.transform(using: tf)
            shackle = rotated
        } else {
            // 锁态：两腿下端沉入锁体顶边内（≈0.11×glyph），被锁体填充覆盖
            shackle = makeShackle(legBottomY: bodyTopY - glyph.height * 0.11)
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
