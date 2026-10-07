# Coffer 浏览器扩展（v2.3.0 G-C）

WebExtension MV3 薄客户端：通过 native messaging 连接本机 Coffer 的 `com.coffer.browser` host，
在 E2E 会话内完成登录信息的**填充**与**保存**。扩展自身不持有任何库密钥
（DEK/KEK/mcp_key）——会话密钥仅存于后台 service worker 内存，SW 终止即失效，
重连重握手（docs/31 §2.4 / §3.3）。

## 目录

```
manifest.json           MV3 清单（key/gecko.id 为 D-4 冻结占位）
build.mjs               esbuild 打包 → dist/
src/
  background.ts         SW：native port + E2E 会话 + 状态机 + 手势校验 + 路由
  protocol.ts           线上协议（握手帧/会话信封/错误码 8xxx/手势）——与 Rust 侧 G-A 对齐
  origin.ts             三种绑定匹配（exact/subdomain/domain，纯函数）
  crypto/e2e.ts         WebCrypto 原生：P-256 ECDH + HKDF-SHA256 + AES-256-GCM + HMAC-SHA256
  messages.ts           扩展内部 runtime 消息类型
  content/
    capture.ts          submit 捕获 + 提交成功验证（导航/AJAX 2xx）+ 保存提示
    fill.ts             focusin → 内联菜单 → 显式手势填充
    dom.ts              DOM 定位/读取/填充/尽力覆盖
    menu.ts             扩展源 iframe 内联菜单宿主
  ui/
    inline_menu.ts/html 内联菜单（扩展源 iframe，页面 JS 无法触达）
    popup.ts/html       工具栏弹窗（状态 + 当前站点条目 + 填充/锁定）
  tests/                origin + E2E 握手 mock broker 纯函数单测（Node）
```

## 构建

```bash
npm install        # devDeps：typescript / esbuild / @types/chrome / @types/node
npm run typecheck  # 浏览器源码 tsc 全量类型检查（不含 tests，见 tsconfig 分离）
npm test           # tsc(test) + node --test：origin 20 + E2E/gesture 6 = 26 用例
npm run build      # esbuild → dist/
```

产物 `dist/` 可直接 Chrome「加载已解压的扩展程序」加载（MV3，零运行时依赖）。

## 协议对齐（G-A）

握手/会话/错误码与 `docs/31 §3.3` 冻结契约一致；应用层消息为：
`get_entries → entries_result`、`get_secret(entry, fields[], origin, gesture, action?) → secret_result(values)`
（一次手势 = 一次授权填充，`fields` 数组一次取回）、`capture_save → capture_result`、`lock → lock_result`。
错误码 8xxx（8001–8008）。详见 `src/protocol.ts`。

## 安全边界

- 不自动填、不预填：填充必须经扩展 UI 内的真实用户点击（手势 b64(nonce‖issuedAtMs)，TTL 30 s，单次）。
- 填充后尽力覆盖 DOM（JS 无法真正 zeroize，诚实声明）。
- 捕获 = submit + 验证成功（导航到 action origin 或 2xx）才提示；仅显式接受；`data-coffer-ignore` 退出。
- 跨源表单动作需额外显式确认步骤。
- 内容脚本消息走 extension messaging，不走 DOM 事件；内联菜单为扩展源 iframe。

## D-4 占位

`manifest.json` 的 `key`（Chrome 签名公钥 base64）与 `browser_specific_settings.gecko.id` 为冻结占位，
正式分发前由 G-D/lead 替换为实际值；本地 unpacked 加载不受影响。
