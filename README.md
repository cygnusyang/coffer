# Coffer

**数据不出本机的密码管理器**：不连云端、没有联网能力（可审计验证，NFR-SEC-07），密码、密钥、凭据只存在本地。同时提供本机 MCP 服务，让 Claude Code、Codex 等 AI 工具按需取密——数据同样不出本机。

- 仓库：<https://github.com/cygnusyang/coffer> · 许可证：MIT

## 快速开始

### 构建 App（macOS）

```bash
./tools/build_macos_app.sh      # 产物 → macos/build/Coffer.app
open macos/build/Coffer.app     # 建议拖入 /Applications
```

要求 Rust >= 1.85（由 `core/rust-toolchain.toml` 固定）。本地构建为开发签名，首次启动若被 Gatekeeper 拦截：右键 App → 「打开」。

### 首次启动与建库

1. 创建保险库并设置**主密码**——唯一解锁凭据，无服务端、无恢复后门，**遗失 = 数据永久丢失**
2. 解锁后即可使用：**22 类条目模板** + 自定义字段、**TOTP 验证码**、随机字符 / 密码短语**双模式生成器**
3. 「设置」页：自动锁定、剪贴板自动清除、菜单栏常驻（全局快捷键 ⌥⌘P）

### 导入 / 导出 / 备份

| 方向 | 格式 | 说明 |
| --- | --- | --- |
| 导入 | 1PUX / CSV / opvault | 字段映射逐项可核对，未知字段不静默丢弃 |
| 导出 | 1PUX 兼容 / CSV | CSV 为明文，导出前双重确认 |
| 备份 | 加密备份 / 恢复 | 改主密码不重加密全库 |

### 浏览器自动填充（独立插件仓库）

配套浏览器插件已拆分为独立仓库：**[coffer-browser-extension](https://github.com/cygnusyang/coffer-browser-extension)**。
在浏览器登录表单上经本机 Coffer 保险库自动填充/保存密码，数据不出本机。

```bash
git clone https://github.com/cygnusyang/coffer-browser-extension.git
cd coffer-browser-extension && npm install && npm run build
# Chrome 扩展页「加载已解压的扩展程序」→ 选择 dist/，首次使用在 App 内批准配对
```

使用前提：本机已装 Coffer 且设置中启用「浏览器集成」。

### 与 AI 工具协同（MCP）

```bash
# 构建 CLI
cd core && cargo build --release -p cf-mcp
# 产物：core/target/release/coffer

# 注册到 Claude Code
claude mcp add coffer \
  -e COFFER_VAULT_DIR=/path/to/vault \
  -e COFFER_VAULT_PASSWORD=... \
  -- coffer mcp --provider coffer
```

注册后 Agent 可调用 4 个工具：`list_secret_names` / `list_secrets` / `run_with_secret` / `get_secret_metadata`。

### 测试

```bash
cd core && cargo test --workspace --no-fail-fast
```

## 文档

需求与设计 `docs/01`~`docs/04`；版本计划 `docs/09`；Agent 凭据域 `docs/10`；MCP 设计 `docs/20`；macOS 侧说明 `macos/README.md`。

## 许可证

[MIT](LICENSE)。Copyright (c) 2026 Coffer contributors。
