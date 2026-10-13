// MenuIconGeometryTests/main.swift —— 菜单栏图标几何断言单元测试（v2.10.0 D2，
// docs/18 §8.5 LOW-2 实现回归点）。
//
// 目标判据（docs/03-功能设计/18-菜单栏图标视觉规格.md r0.2）：
//   §4 参数表终值（路径口径）——本文件把每项绝对值断言为常量，参数回归即红。
//   §5.1 纵向守恒：体顶 9.56 → 竖直腿顶 10.96 → 穹顶路径 14.60（帽顶 15.65
//         < 16，锁态落回字形区内）；穹底宽 = 2×rx = 5.60pt。
//   §8.5 LOW-2 几何断言（本规格要求 dev-team 新增的回归点）：
//     ① 解锁态右腿抬离 ≥ 0.18×glyph 硬阈值（新值 2×rx×sin40° = 3.60pt =
//        0.257×glyph 通过；现状仅注释纪律、无测试）
//     ② 路径口径梁/体 ≤ 0.7（新值 (legAbove+ry)/体高 = 5.04/7.56 = 0.667 通过）
//
// 被测单元 macos/Coffer/Support/MenuIconGeometry.swift（enum MenuIconGeometry，
// Foundation + CoreGraphics，无 AppKit/SwiftUI/FFI 依赖）——与 RecoveryVerifySupport
// / UpdateCopy 同模式，可进 swiftc 选编单测。
//
// 先红后绿自检：对「退回旧几何参数（体 0.64×0.52、弧 rx=0.22、无竖直腿、sink
// 0.11）」每条 §4 绝对值断言都会红——本套件是 §4 终值 + §8.5 阈值的回归哨兵。

import Foundation
import CoreGraphics

// MARK: - 断言与汇总

var failures: [String] = []
var passCount = 0

func check(_ name: String, _ cond: Bool, _ detail: String = "") {
    if cond {
        passCount += 1
        print("PASS  \(name)")
    } else {
        failures.append("\(name) \(detail)")
        print("FAIL  \(name)  \(detail)")
    }
}

func approx(_ a: CGFloat, _ b: CGFloat, tolerance: CGFloat = 0.001) -> Bool {
    abs(a - b) <= tolerance
}

let glyph = MenuIconGeometry.glyph

// MARK: - §4 参数表终值（×glyph，glyph = 14pt）

do {
    check("glyph 尺寸 14×14", approx(glyph.width, 14) && approx(glyph.height, 14))
    check("锁体宽 0.72×glyph = 10.08pt", approx(MenuIconGeometry.bodyWidth, 10.08))
    check("锁体高 0.54×glyph = 7.56pt", approx(MenuIconGeometry.bodyHeight, 7.56))
    check("锁梁线宽 0.15×glyph = 2.1pt", approx(MenuIconGeometry.lineWidth, 2.1))
    check("椭圆水平半轴 rx 0.20×glyph = 2.80pt", approx(MenuIconGeometry.shackleRx, 2.80))
    check("椭圆垂直半轴 ry 0.26×glyph = 3.64pt", approx(MenuIconGeometry.shackleRy, 3.64))
    check("竖直腿 legAbove 0.10×glyph = 1.40pt", approx(MenuIconGeometry.legAbove, 1.40))
    check("锁态腿沉入 sink 0.10×glyph = 1.40pt", approx(MenuIconGeometry.sink, 1.40))
    check("锁体顶 bodyTopY = 9.56", approx(MenuIconGeometry.bodyTopY, 9.56))
}

// MARK: - §5.1 纵向结构守恒

do {
    let locked = MenuIconGeometry.shackleAnchors(
        legBottomY: MenuIconGeometry.bodyTopY - MenuIconGeometry.sink
    )
    check("竖直腿上端 legTopY = 10.96", approx(locked.leftLegTop.y, 10.96))
    check("穹顶路径 y = 14.60（帽顶 15.65 < 16 落回字形区）",
          approx(locked.domeTop.y, 14.60))
    check("锁态腿端沉入体顶下方 sink（8.16）",
          approx(locked.leftLegBottom.y, 9.56 - 1.40))
    check("穹底宽 = 2×rx = 5.60pt（腿中心距）",
          approx(locked.rightLegTop.x - locked.leftLegTop.x, 5.60))
    check("穹顶处 x 居中（midX=9）", approx(locked.domeTop.x, 9))
}

// MARK: - §8.5 LOW-2 几何断言（阈值 + 绝对值）

do {
    let threshold = 0.18 * glyph.height
    check("抬离 \(MenuIconGeometry.unlockedLiftOff) ≥ 0.18×glyph = \(threshold)",
          MenuIconGeometry.unlockedLiftOff >= threshold)
    check("抬离绝对值 = 2×rx×sin40° = 3.60pt（§5.3）",
          approx(MenuIconGeometry.unlockedLiftOff, 3.60, tolerance: 0.01))
    check("路径梁/体 \(MenuIconGeometry.shackleToBodyRatio) ≤ 0.7",
          MenuIconGeometry.shackleToBodyRatio <= 0.7)
    check("路径梁/体 = (legAbove+ry)/体高 = 0.667（§4）",
          approx(MenuIconGeometry.shackleToBodyRatio, 0.667, tolerance: 0.001))
}

// MARK: - 汇总

print("--------------------------------------------------")
print("结果：\(passCount) passed / \(failures.count) failed")
if !failures.isEmpty {
    failures.forEach { print("  FAILED: \($0)") }
    exit(1)
}
print("ALL GREEN")
