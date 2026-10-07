/**
 * Popup UI (action click). Surfaces session state, lists fillable entries for the active
 * tab's origin, and lets the user fill / lock / retry.
 *
 * A fill here also needs an explicit user gesture: the gesture is minted at the click on
 * an entry (single-use, TTL 30 s — docs/31 §6.1) and the popup is a trusted extension page,
 * so the click itself is the authorization (DEF CON 33: page JS cannot click popup UI).
 */
import { makeGesture } from "../protocol";
import type { SessionState, UiToBackgroundMessage } from "../messages";
import type { EntryInfo } from "../protocol";

let entries: EntryInfo[] = [];

function esc(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function queryActiveOrigin(): Promise<string | null> {
  return chrome.tabs.query({ active: true, lastFocusedWindow: true }).then((tabs) => {
    const url = tabs[0]?.url;
    if (!url) return null;
    try {
      return new URL(url).origin;
    } catch {
      return null;
    }
  });
}

function send(msg: UiToBackgroundMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (res: Record<string, unknown> | undefined) => {
      if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message ?? "no response" });
      else resolve(res ?? { ok: false, error: "no response" });
    });
  });
}

function renderState(st: SessionState): void {
  const dot = document.getElementById("dot") as HTMLElement;
  const status = document.getElementById("status") as HTMLElement;
  const lockBtn = document.getElementById("lock") as HTMLButtonElement;
  const hint = document.getElementById("unlock-hint") as HTMLElement;

  dot.className = "dot";
  switch (st.status) {
    case "paired":
      dot.classList.add("connected");
      status.textContent = "已连接";
      break;
    case "connecting":
      dot.classList.add("warn");
      status.textContent = "连接中…";
      break;
    case "awaiting_unlock":
      dot.classList.add("warn");
      status.textContent = "等待解锁";
      break;
    case "idle":
    case "error":
      dot.classList.add("err");
      status.textContent = st.status === "error" ? "出错" : "未连接";
      break;
  }
  lockBtn.hidden = st.status !== "paired";
  hint.hidden = st.status !== "awaiting_unlock";
}

function renderEntries(): void {
  const box = document.getElementById("entries") as HTMLElement;
  if (!entries.length) {
    box.innerHTML = `<div class="empty">当前站点没有可填充的条目</div>`;
    return;
  }
  box.innerHTML = entries
    .map((e) => `<button class="entry" data-id="${esc(e.id)}"><div>${esc(e.title)}</div></button>`)
    .join("");
  for (const btn of box.querySelectorAll<HTMLButtonElement>(".entry")) {
    btn.addEventListener("click", () => void doFill(btn.dataset.id as string));
  }
}

async function doFill(entry: string): Promise<void> {
  const origin = await queryActiveOrigin();
  if (!origin) return;
  const gesture = makeGesture();
  const res = await send({ type: "popup_fill", entry, origin, gesture });
  if (res.ok) {
    window.close();
  } else {
    const status = document.getElementById("status") as HTMLElement;
    status.textContent = "填充失败";
  }
}

async function load(): Promise<void> {
  const stRes = await send({ type: "get_state" });
  if (stRes.ok && stRes.state) renderState(stRes.state as SessionState);
  else renderState({ status: "idle", paired: false });

  const origin = await queryActiveOrigin();
  if (!origin) {
    renderEntries();
    return;
  }
  const res = await send({ type: "get_entries", origin });
  if (res.ok && Array.isArray(res.entries)) entries = res.entries as EntryInfo[];
  renderEntries();
}

(document.getElementById("retry") as HTMLButtonElement).addEventListener("click", () => void load());
(document.getElementById("lock") as HTMLButtonElement).addEventListener("click", () => {
  void send({ type: "lock" }).then(() => window.close());
});

document.addEventListener("DOMContentLoaded", () => void load());
