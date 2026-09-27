# Coffer App 图标 · 环形钥匙（Orbit Key）

选定方向：6 方向探索中的 **03 环形钥匙**，精修 v3。设计稿见 [icon-exploration-v3.html](./icon-exploration-v3.html)（含比例辅助线、朝向切换、v2/v3 对比、尺寸阶梯、dark 变体）。

## 设计依据

- Apple Human Interface Guidelines — App icons（2026-06-08 修订，Liquid Glass 章节）
- 分层结构：背景层 + 前景层，高光/折射/阴影全部由系统 Liquid Glass 渲染，图层内禁止烘焙圆角遮罩、投影、高光
- 前景图形为实心简化形，无细线无尖角；内容居中，画布占比约 81%

## 比例数据（100×100 视图）

| 部件 | 数值 | 关系 |
|------|------|------|
| 环外径 | Ø36 | 柄宽的 3.8 倍 |
| 环孔 | Ø24.5 | 占环外径 68% |
| 柄 | 9.5 × 46 | 略长于环直径 |
| 宽齿 | 12.5 × 9 | 贴柄末（L1，不透明） |
| 窄齿 | 9.5 × 8.5 | 贴柄末（L2，opacity 62%） |

## 图层文件（layers/）

拖入 Icon Composer（Xcode 26 附带），画布 1024×1024：

1. `background.svg` — 背景层：线性渐变 #57A0FF → #5F6CF8 → #A13EF2（150°）+ 左上光晕，满幅不透明
2. `foreground-l1.svg` — 前景 L1：环 + 柄 + 宽齿（不透明玻璃渐变）
3. `foreground-l2.svg` — 前景 L2：窄齿（62% 不透明度，放比 L1 低一档的深度组）

## 待办

- [ ] Icon Composer 组装三层，调深度组
- [ ] 核对四种外观：default / dark / clear / tinted（dark 变体背景可压深至 #3A3F9E → #2C2A86 → #45248C，见设计稿）
- [ ] 小尺寸验证（Settings / Spotlight / 通知，22–32px 下窄齿并预期合并）
- [ ] 导出 .icon 替换 `macos/Coffer/Resources/Coffer.icns`
