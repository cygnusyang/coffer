/**
 * Inline menu UI — extension-origin iframe hosted inside the page by content scripts
 * (docs/31 §5.2, research Q4: same-origin isolation, page JS cannot read or click it).
 *
 * The page cannot synthesize clicks inside this cross-origin iframe (DEF CON 33), and a
 * real user click here is what authorizes a fill/save: the gesture is generated at the
 * click (TTL 30 s, single-use) and the action goes over runtime messaging to the
 * background worker. If the form action targets a different origin, an explicit confirm
 * step is required (docs/31 §5.2 — unless the user explicitly confirms an unbound origin).
 */
import { makeGesture } from "../protocol";
import type { EntryInfo } from "../protocol";
import type { MenuToBackgroundMessage } from "../messages";

const MODE = new URLSearchParams(location.search).get("mode") === "capture" ? "capture" : "fill";

interface MenuData {
  ok: boolean;
  mode?: "fill" | "capture";
  origin?: string;
  action?: string;
  title?: string;
  username?: string;
  entries?: EntryInfo[];
  error?: { code: number; message: string };
}

let data: MenuData = { ok: false };
/** Set once the user explicitly confirmed a cross-origin action target (docs/31 §5.2). */
let crossOriginApproved = false;

const app = (): HTMLElement => document.getElementById("app") as HTMLElement;

function esc(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function closeMenu(): void {
  window.parent.postMessage({ source: "coffer-menu-close" }, "*");
}

function send(msg: MenuToBackgroundMessage, onResult: (res: MenuData) => void): void {
  chrome.runtime.sendMessage(msg, (res: MenuData | undefined) => {
    if (chrome.runtime.lastError) onResult({ ok: false, error: { code: 8004, message: chrome.runtime.lastError.message ?? "worker unavailable" } });
    else onResult(res ?? { ok: false, error: { code: 8004, message: "no response" } });
  });
}

function renderHeader(): string {
  return `<div class="head"><span class="logo">Coffer</span><span class="origin" title="${esc(data.origin ?? "")}">${esc(data.origin ?? "")}</span></div>`;
}

function renderWarn(): string {
  const cross = isCrossOriginAction();
  if (!cross) return "";
  return `<div class="warn">此表单将提交到其他站点（${esc(actionOrigin() ?? "")}）。继续填充前请确认这是你信任的站点。</div>`;
}

function actionOrigin(): string | null {
  if (!data.action) return null;
  try {
    return new URL(data.action, data.origin).origin;
  } catch {
    return null;
  }
}

function isCrossOriginAction(): boolean {
  const ao = actionOrigin();
  return ao !== null && data.origin !== undefined && ao !== data.origin;
}

function renderStatus(text: string): void {
  app().innerHTML = `${renderHeader()}<div class="status">${esc(text)}</div>`;
}

function renderList(): void {
  const entries = data.entries ?? [];
  const rows = entries
    .map((e) => `<button class="entry" data-id="${esc(e.entry)}"><div>${esc(e.title)}</div></button>`)
    .join("");
  app().innerHTML = `${renderHeader()}${renderWarn()}<div class="list">${rows}</div>`;
}

function renderCrossOriginConfirm(id: string): void {
  app().innerHTML = `${renderHeader()}<div class="warn">此表单提交到 ${esc(actionOrigin() ?? "未知站点")}。确认填充吗？</div><div class="row"><button class="ghost" id="coffer-cancel">取消</button><button class="primary" id="coffer-confirm">确认填充</button></div>`;
  (app().querySelector("#coffer-confirm") as HTMLButtonElement).addEventListener("click", () => {
    // Explicit approval → broker records it (confirm_unbound_origin) bound to the clicked
    // entry, then fill proceeds (docs/31 §5.2 r0.4 — confirm carries entry, contract v1.1).
    const gesture = makeGesture();
    send({ type: "menu_cross_origin_confirm", entry: id, origin: data.origin ?? "", gesture }, (res) => {
      if (res.ok) {
        crossOriginApproved = true;
        doFill(id);
      } else {
        renderStatus(res.error?.message ?? "确认失败，请重试");
      }
    });
  });
  (app().querySelector("#coffer-cancel") as HTMLButtonElement).addEventListener("click", () => {
    renderList();
  });
}

function doFill(id: string): void {
  const gesture = makeGesture();
  send({ type: "menu_fill", entry: id, origin: data.origin ?? "", action: data.action, gesture }, (res) => {
    if (res.ok) closeMenu();
    else renderStatus(res.error?.message ?? "填充失败，请重试");
  });
}

function renderCapture(): void {
  app().innerHTML = `${renderHeader()}<div class="detail">保存该站点的登录信息？</div><div class="detail">用户名：${esc(data.username ?? "（空）")}</div><div class="detail">页面：${esc(data.title ?? "")}</div><div class="row"><button class="ghost" id="coffer-decline">取消</button><button class="primary" id="coffer-accept">保存到 Coffer</button></div>`;
  (app().querySelector("#coffer-accept") as HTMLButtonElement).addEventListener("click", () => {
    const gesture = makeGesture();
    send({ type: "menu_capture_accept", origin: data.origin ?? "", gesture }, (res) => {
      if (res.ok) closeMenu();
      else renderStatus(res.error?.message ?? "保存失败，请重试");
    });
  });
  (app().querySelector("#coffer-decline") as HTMLButtonElement).addEventListener("click", closeMenu);
}

function onLoad(): void {
  chrome.runtime.sendMessage({ type: "menu_ready" }, (res: MenuData | undefined) => {
    if (chrome.runtime.lastError || !res || !res.ok) {
      data = { ok: false };
      renderStatus("Coffer 会话不可用，请重新聚焦输入框");
      return;
    }
    data = res;
    if (data.mode === "capture") renderCapture();
    else renderList();
  });
}

app().addEventListener("click", (e) => {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>(".entry");
  if (!btn || !btn.dataset.id) return;
  const id = btn.dataset.id;
  // Cross-origin action target: no fill until the user explicitly approves (docs/31 §5.2).
  if (isCrossOriginAction() && !crossOriginApproved) {
    renderCrossOriginConfirm(id);
    return;
  }
  doFill(id);
});

document.addEventListener("DOMContentLoaded", onLoad);
