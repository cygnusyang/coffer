## 变更摘要

<!-- 一句话说明改了什么、为什么。 -->

## 关联

- 任务板：`docs/00-WORK-ITEMS.md` → ID：
- 缺陷登记：`docs/01-KNOWN-ISSUES.md` → ID：
- 设计交接单（如涉及 UI）：
- 判据 ID：

## 文档影响清单（必填，无影响写「无」）

- [ ] README
- [ ] CHANGELOG
- [ ] 需求 / 验收判据（docs/01、docs/04）
- [ ] 帮助中心
- [ ] API / CLI 文档
- [ ] 无

## 门禁证据

| 门禁 | 命令 | 日志路径 | 退出码 | 摘要 |
| --- | --- | --- | --- | --- |
| 代码 | `tools/run_gate.sh` | | | |
| UI（如涉及） | `tools/run_ui_gate.sh` | | | |
| 文档事实 | `tools/check_docs_facts.sh` | | | |

## 检查清单

- [ ] 测试覆盖变更与负路径；测试名引用判据 ID
- [ ] 未提交密码、令牌、私钥或实样数据
- [ ] 未使用 `git add -A` / `git add .`
- [ ] 文档影响清单已勾选
- [ ] 任务板行已回填关闭证据
