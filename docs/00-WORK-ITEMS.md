# WORK-ITEMS —— 工作项索引（唯一任务板）

> 本文件是 Coffer 三队（dev-team / ui-team / doc-team）的**唯一任务板**。
> 协议：`~/.claude/teams/PROTOCOL.md`；项目适配：[00-协作适配](00-协作适配.md)。
> 缺陷的完整证据仍登记在 [01-KNOWN-ISSUES](01-KNOWN-ISSUES.md)，本表只存索引，不复制内容。
>
> **claim 规则**：开工前把 Owner 改为自己、状态改 `in_progress`；未 claim 不得开工。
> **files 范围**：仓库相对路径或 glob；同一文件同一时间只允许一个 owner。
> **关闭证据**：命令、日志路径、commit、文档锚点四选一以上；缺证据视为未完成。
> 状态取值：`pending` / `in_progress` / `blocked` / `done` / `accepted`。

| ID | 类型 | 标题 | Owner | 状态 | files 范围 | 判据/锚点 | 关闭证据 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BUG-18 | BUG | cf-mcp uds 并行执行偶发 Connection refused（测试基建） | — | pending | core/cf-mcp/src/uds.rs | docs/01-KNOWN-ISSUES.md §BUG-18 | — |
| BUG-19 | BUG | set_password_usage_errors_exit_4 CI 间歇 BrokenPipe（测试基建） | — | pending | core/cf-mcp/src/cli.rs | docs/01-KNOWN-ISSUES.md §BUG-19 | — |
| BUG-21 | BUG | UpdateTests 三项依赖 Developer ID 签名产物（环境项） | — | accepted | macos/CofferTests/ | docs/01-KNOWN-ISSUES.md §BUG-21 | 目标版本：随 Developer ID 签名线恢复 |
| TASK-1 | TASK | run_gate.sh 增量门禁（--changed） | lead | done | tools/run_gate.sh | docs/00-协作适配.md §2 | docs-only 1s 通过 /tmp/gate-docsonly4.log；全量对照 1451/0/10 build=OK；假 cargo exit=2、非法 BASE exit=2（/tmp/gate-negative4.log）；--print-crates 反依赖闭包 cf-mcp→5 crate |
| TASK-2 | TASK | workitem.py conflicts 并行冲突判定 | lead | done | tools/workitem.py | - | conflicts 正负例 /tmp/wi-evidence2.log：词中通配 CONFLICT、同 owner 不冲突、accepted/blocked claim 拒绝 exit=1；/tmp/wi-evidence.log 串行组 6 对冲突 |
| TASK-3 | TASK | 判据覆盖核对脚本 | lead | done | tools/check_criteria_coverage.py,docs/00-协作适配.md,.github/workflows/rust.yml,.gitlab-ci.yml | - | 112 条 15 覆盖全部逐条可溯（/tmp/crit-evidence-audit3.log，修复同行别名串用假阳性）；零解析 exit=2；两 CI WARN-only 接入 |

## 维护

- 命令行维护：`python3 tools/workitem.py list | add | claim | status | done | check`
- 手工编辑必须保持上表列序与字段；`|` 在单元格内写成 `\|`。
- 新增工作项先从缺陷登记簿或需求文档取 ID，再在本表建索引行。
