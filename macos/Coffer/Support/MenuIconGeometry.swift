// MenuIconGeometry.swift —— 菜单栏图标纯几何参数（docs/18 §4/§5.1 实现契约）。
//
// 自 StatusItemController.icon(phase:) 抽出为无依赖顶层命名空间（v2.10.0 D2
// 图标重绘）：图标绘制唯一依据 = docs/18 §4 参数表（终值）+ §5.1 锁梁路径结构
// 契约。抽出动机同 RecoveryVerifySupport：View/Controller 文件依赖 AppKit 无法
// 单文件编译进测试目标，纯几何外置后可进 swiftc 选编单测（§8.5 LOW-2：抬离
// ≥0.18×glyph、路径梁/体 ≤0.7 几何断言落这里）。
//
// 坐标系：y-up（与 NSImage(flipped: false) 及 §5.1 图一致）；glyph = 14pt
// （画布 18 − 2×glyphInset）。因子 ×glyph，路径口径（含/不含圆帽双口径定义见
// docs/18 §3.3）。
//
// §4 参数守恒核验（对照 §4「参数间守恒检查」）：
//   纵向：体底 glyph.minY=2 → 体顶 9.56 → 竖直腿顶 10.96 → 穹顶路径 14.60
//         （帽顶 15.65 < 16，锁态落回字形区内）
//   横向：锁体 x 3.96–14.04；穹外宽 7.7pt（x 5.15–12.85）不超锁体宽

import Foundation
import CoreGraphics

/// 菜单栏图标几何（docs/18 r0.2 终值参数，纯函数命名空间）。
enum MenuIconGeometry {
    // MARK: 画布与图形区（§4：glyphInset 不变）

    /// 画布边长（NSStatusItem squareLength 惯例，18pt）。
    static let canvasSize: CGFloat = 18
    /// 图形区四周留边距（模板图标不顶满）。
    static let glyphInset: CGFloat = 2

    /// 图形区（14×14；y-up：minY=2 底、maxY=16 顶）。
    static var glyph: CGRect {
        CGRect(x: glyphInset, y: glyphInset,
               width: canvasSize - glyphInset * 2,
               height: canvasSize - glyphInset * 2)
    }

    // MARK: §4 终值参数（×glyph，路径口径）

    /// 锁体宽（0.64 → 0.72：整锁加宽，整体 w/h 0.61 → 0.74 向 SF 0.81 靠）。
    static let bodyWidthFactor: CGFloat = 0.72
    /// 锁体高（0.52 → 0.54：微增，锁梁压矮后锁体占比回 ~0.55）。
    static let bodyHeightFactor: CGFloat = 0.54
    /// 锁体圆角（比值维持 0.12×体宽）。
    static let bodyCornerFactor: CGFloat = 0.12
    /// 锁梁线宽（维持 0.15；1x 下 2px 级描边）。
    static let lineWidthFactor: CGFloat = 0.15
    /// 锁梁椭圆水平半轴 rx（原圆半径 0.22 → 0.20；穹底宽 = 2×rx+线宽 = 0.76×体宽）。
    static let shackleRxFactor: CGFloat = 0.20
    /// 锁梁椭圆垂直半轴 ry（穹高；0.26，穹顶扁、梁/体 1.00 → 0.67）。
    static let shackleRyFactor: CGFloat = 0.26
    /// 竖直腿（体顶上方可见；新增 0.10，U 形更明确）。
    static let legAboveFactor: CGFloat = 0.10
    /// 锁态腿沉入锁体（0.11 → 0.10：仅作圆帽覆盖余量，帽 1.05 < 1.40 全盖）。
    static let sinkFactor: CGFloat = 0.10
    /// 解锁态旋转角（维持 40°；机制不变，lift 重算见 §5.3）。
    static let unlockAngleDegrees: CGFloat = 40
    /// 椭圆 1/4 弧三次贝塞尔近似系数（§5.1 标准值）。
    static let bezierK: CGFloat = 0.5523

    // MARK: 派生绝对尺寸（×glyph）

    static var bodyWidth: CGFloat { glyph.width * bodyWidthFactor }
    static var bodyHeight: CGFloat { glyph.height * bodyHeightFactor }
    static var lineWidth: CGFloat { glyph.height * lineWidthFactor }
    static var shackleRx: CGFloat { glyph.width * shackleRxFactor }
    static var shackleRy: CGFloat { glyph.height * shackleRyFactor }
    static var legAbove: CGFloat { glyph.height * legAboveFactor }
    static var sink: CGFloat { glyph.height * sinkFactor }
    /// 锁体顶边 y（y-up；glyph.minY + 体高）。
    static var bodyTopY: CGFloat { glyph.minY + bodyHeight }

    /// 锁体圆角矩形（底对齐 glyph 底，实心填充）。
    static var bodyRect: CGRect {
        CGRect(x: glyph.midX - bodyWidth / 2, y: glyph.minY,
               width: bodyWidth, height: bodyHeight)
    }

    // MARK: §5.1 锁梁开放路径锚点（三次贝塞尔椭圆上半弧）

    /// 锁梁路径锚点（y-up；§5.1 伪码逐点对应）。
    /// - Parameter legBottomY: 竖直腿底端 y——锁态 = bodyTopY − sink（沉入体，
    ///   被锁体覆盖），解锁态 = bodyTopY。
    static func shackleAnchors(legBottomY: CGFloat) -> ShackleAnchors {
        let midX = glyph.midX
        let legTopY = bodyTopY + legAbove
        let domeTopY = legTopY + shackleRy
        return ShackleAnchors(
            leftLegBottom: CGPoint(x: midX - shackleRx, y: legBottomY),
            leftLegTop: CGPoint(x: midX - shackleRx, y: legTopY),
            domeTop: CGPoint(x: midX, y: domeTopY),
            rightLegTop: CGPoint(x: midX + shackleRx, y: legTopY),
            rightLegBottom: CGPoint(x: midX + shackleRx, y: legBottomY),
            domeLeftCP1: CGPoint(x: midX - shackleRx, y: legTopY + bezierK * shackleRy),
            domeLeftCP2: CGPoint(x: midX - bezierK * shackleRx, y: domeTopY),
            domeRightCP1: CGPoint(x: midX + bezierK * shackleRx, y: domeTopY),
            domeRightCP2: CGPoint(x: midX + shackleRx, y: legTopY + bezierK * shackleRy)
        )
    }

    // MARK: §8.5 几何断言派生量（LOW-2 测试；路径口径）

    /// 解锁态右腿底端抬离锁体顶边（绕左腿底端旋转 40° 后；2×rx×sinθ）。
    static var unlockedLiftOff: CGFloat {
        2 * shackleRx * sin(unlockAngleDegrees * .pi / 180)
    }

    /// 路径口径梁/体 =（竖直腿 + 穹高）÷ 锁体设计高（§4：0.667 ≤ 0.7）。
    static var shackleToBodyRatio: CGFloat {
        (legAbove + shackleRy) / bodyHeight
    }
}

/// §5.1 锁梁开放路径锚点集合（move/line/curve 逐点对应，NSBezierPath 消费）。
struct ShackleAnchors {
    let leftLegBottom: CGPoint
    let leftLegTop: CGPoint
    let domeTop: CGPoint
    let rightLegTop: CGPoint
    let rightLegBottom: CGPoint
    let domeLeftCP1: CGPoint
    let domeLeftCP2: CGPoint
    let domeRightCP1: CGPoint
    let domeRightCP2: CGPoint
}
