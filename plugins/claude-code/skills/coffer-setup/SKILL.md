---
name: coffer-setup
description: Diagnose and repair the coffer MCP connection — run when mcp__coffer__* tools are missing, the coffer server fails to connect, or on a brand-new machine/first run
---

# Coffer Setup — 诊断与修复 coffer MCP 连接

当 `mcp__coffer__*` 工具缺失、coffer MCP 连接失败，或第一次在新机器上使用 coffer 时使用本 skill。按顺序排查，最快命中根因。

## 诊断顺序

### 1. 插件/连接状态

```
claude mcp list
```

- coffer 行 `- ✔ Connected` → 已就绪，回到 `coffer-credentials` skill 正常使用。
- 无 coffer 行或 `✘ Failed` → 继续。

### 2. 前置三要素（由 `coffer-launch.sh` 连接时探测）

**a. Coffer App 已安装（必须有内嵌 helper）**：

```
test -x /Applications/Coffer.app/Contents/Helpers/coffer.app/Contents/MacOS/coffer && echo OK || echo MISSING
```

缺失 → 提示用户安装 Coffer App（`brew`/官网/构建脚本），装好后再来。

**b. vault 已存在（容器目录里有 UUID 子目录）**：

```
ls "$HOME/Library/Containers/app.coffer.Coffer/Data/Documents/Coffer/"
```

为空 → 提示用户先打开 Coffer App 创建/解锁一次 vault。

**c. Keychain escrow 已建立（本机解锁过一次）**：

最直接的验证：跑一次 launch 脚本，看日志是否出现 `vault unlocked via MCP keychain escrow`：

```
env -u COFFER_VAULT_DIR "$HOME/.cache/..." true
```

（或以 2 秒超时起 `coffer-launch.sh`，读 stderr 首行。）若报「未启用 MCP 解锁托管」→ 提示用户：App 设置 → MCP / Agent 协作 → 启用「MCP 解锁托管」，并解锁一次。

### 3. 验证插件清单有效（可选）

```
claude plugin validate --strict <plugin-root>
```

### 4. 兜底：独立注册

插件 MCP 不可用但需要 coffer 时，可独立注册一份 user-scope 服务（等价于官方 README 的手动步骤）：

```
coffer-setup        # PATH 命令，自动探测二进制 + vault 并 `claude mcp add coffer --scope user`
```

> 注意：独立注册会与插件 MCP 同名（coffer）。一般二选一即可；插件 MCP 恢复后建议移除独立注册避免混淆（`claude mcp remove coffer`）。

## 完成标准

- `claude mcp list` 中 coffer `- ✔ Connected`。
- `mcp__coffer__list_secret_names` 能返回名字列表（值仍不会返回）。

若以上都通过仍连不上，把 `claude mcp list` 输出和 launch 日志交给用户/上报。
