/**
 * Popup UI (action click). Surfaces session state, lists fillable entries for the active
 * tab's origin, and lets the user fill / lock / retry.
 *
 * A fill here also needs an explicit user gesture: the gesture is minted at the click on
 * an entry (single-use, TTL 30 s — docs/31 §6.1) and the popup is a trusted extension page,
 * so the click itself is the authorization (DEF CON 33: page JS cannot click popup UI).
 */
import { makeGesture, ErrCode } from "../protocol";
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
  const pairHint = document.getElementById("pair-hint") as HTMLElement;
  const pairBtn = document.getElementById("pair") as HTMLButtonElement;

  dot.className = "dot";
  pairHint.hidden = true;
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
    case "pairing":
      dot.classList.add("warn");
      status.textContent = "等待 Coffer 批准…";
      break;
    case "idle":
    case "error":
      dot.classList.add("err");
      if (st.errorCode === ErrCode.BrokerUnavailable) {
        // 决策⑥: App 未启动/不可达（design §5.3）——显式提示，不静默失败。
        status.textContent = st.paired ? "重连失败" : "App 不可达";
        pairHint.hidden = false;
        pairHint.textContent = st.paired
          ? "无法连接到 Coffer。请确认 Coffer 正在运行并已启用浏览器集成，然后点击「刷新」重试。"
          : "请打开 Coffer 并启用浏览器集成后，再点击「立即配对」重试。";
      } else if (st.errorCode === ErrCode.UserRejected) {
        // 配对被拒绝（8006 语义，design §5.1）——保持未配对态，可重试。
        status.textContent = "未连接";
        pairHint.hidden = false;
        pairHint.textContent = "配对已拒绝。可重新发起配对。";
      } else {
        status.textContent = st.status === "error" ? "出错" : "未连接";
      }
      break;
  }
  lockBtn.hidden = st.status !== "paired";
  hint.hidden = st.status !== "awaiting_unlock";
  // 「立即配对」: 未配对且未在配对中（未配对 / 决策⑥ / 拒绝 均可重试）。
  const showPair = !st.paired && (st.status === "idle" || st.status === "error");
  pairBtn.hidden = !showPair;
}

function renderEntries(unpaired = false): void {
  const box = document.getElementById("entries") as HTMLElement;
  if (unpaired) {
    // Not paired — no fillable entries to enumerate; keep the panel on the pairing UI.
    box.innerHTML = "";
    return;
  }
  if (!entries.length) {
    box.innerHTML = `<div class="empty">当前站点没有可填充的条目</div>`;
    return;
  }
  box.innerHTML = entries
    .map((e) => `<button class="entry" data-id="${esc(e.entry)}"><div>${esc(e.title)}</div></button>`)
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
  const st = stRes.ok && stRes.state ? (stRes.state as SessionState) : null;
  if (st) renderState(st);
  else renderState({ status: "idle", paired: false });

  if (!st || !st.paired) {
    renderEntries(true);
    return;
  }
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
(document.getElementById("pair") as HTMLButtonElement).addEventListener("click", () => {
  // 立即配对 → background sends pair_request; reload reflects the pairing/App-unavailable state.
  void send({ type: "pair" }).then((res) => {
    if (!res.ok) (document.getElementById("status") as HTMLElement).textContent = "配对失败";
    void load();
  });
});

document.addEventListener("DOMContentLoaded", () => void load());
