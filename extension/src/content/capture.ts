/**
 * Capture content script (docs/31 §5.1 / §6.3, D-7): watches form `submit`, verifies the
 * submission actually happened (navigation to the action origin, or a completed 2xx
 * fetch/XHR to it), then offers to save via the inline menu. Only an explicit user
 * acceptance saves; no autosave; `data-coffer-ignore` opts out; no username -> no prompt.
 *
 * Navigation path: the snapshot (including the password, which already belongs to the
 * page) is persisted in memory-only chrome.storage.session so the prompt can be shown on
 * the page we land on; it is removed once consumed or after a short TTL.
 */
import { findLoginFields, readCredentials, isIgnored, type CredentialSnapshot } from "./dom";
import { openInlineMenu, hideInlineMenu } from "./menu";
import type { BackgroundToContentMessage, PendingSnapshotData } from "../messages";

const PENDING_KEY = "coffer_pending_saves"; // map token -> PendingSnapshotData
const PENDING_TTL_MS = 120_000;
const AJAX_WINDOW_MS = 6_000;

let currentPending: PendingSnapshotData | null = null;

// --- submit capture (registered at document_start) ------------------------------------

document.addEventListener(
  "submit",
  (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (isIgnored(form)) return;
    const snap = readCredentials(findLoginFields(form));
    if (!snap || snap.username.length === 0) return; // 无用户名不 autosave (D-7)
    const token = crypto.randomUUID();
    currentPending = { token, origin: snap.origin, action: snap.action, username: snap.username, password: snap.password, title: snap.title, ts: Date.now() };
    void persistPending(currentPending);
    watchAjaxSubmit(snap);
  },
  true,
);

async function persistPending(snapshot: PendingSnapshotData): Promise<void> {
  try {
    const existing = ((await chrome.storage.session.get(PENDING_KEY))[PENDING_KEY] as Record<string, PendingSnapshotData> | undefined) ?? {};
    existing[snapshot.token] = snapshot;
    await chrome.storage.session.set({ [PENDING_KEY]: existing });
  } catch {
    // storage.session unavailable: the navigation path degrades, the in-page path still works.
  }
}

async function dropPending(): Promise<void> {
  currentPending = null;
  try {
    await chrome.storage.session.remove(PENDING_KEY);
  } catch {
    /* best-effort */
  }
}

function expectedOrigin(snapshot: { origin: string; action: string | null }): string | null {
  if (!snapshot.action) return snapshot.origin;
  try {
    return new URL(snapshot.action, snapshot.origin).origin;
  } catch {
    return null;
  }
}

// After a navigation, a fresh document checks for a pending save that matches this origin.
window.addEventListener(
  "pageshow",
  () => {
    void (async () => {
      let saves: Record<string, PendingSnapshotData> | undefined;
      try {
        saves = (await chrome.storage.session.get(PENDING_KEY))[PENDING_KEY] as Record<string, PendingSnapshotData> | undefined;
      } catch {
        return;
      }
      if (!saves) return;
      const now = Date.now();
      const stale: string[] = [];
      for (const [token, save] of Object.entries(saves)) {
        const expected = expectedOrigin(save);
        if (now - save.ts > PENDING_TTL_MS || expected === null) {
          stale.push(token);
          continue;
        }
        if (expected === window.location.origin) {
          // Navigation to the action origin = submission verified.
          currentPending = save;
          showCapturePrompt();
          return;
        }
        stale.push(token);
      }
      for (const t of stale) delete saves[t];
      void chrome.storage.session.set({ [PENDING_KEY]: saves });
    })();
  },
  false,
);

// AJAX path: a completed 2xx request to the action origin within a short window proves the
// submission landed (best-effort; navigation is the solid primary signal — docs/31 D-7).
function watchAjaxSubmit(snap: CredentialSnapshot): void {
  const targetOrigin = expectedOrigin(snap);
  if (!targetOrigin) return;
  const deadline = Date.now() + AJAX_WINDOW_MS;
  let confirmed = false;
  const xhrUrls = new WeakMap<XMLHttpRequest, string>();

  const originalFetch = window.fetch;
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  window.fetch = function (input, init) {
    const p = originalFetch.apply(this, arguments as unknown as Parameters<typeof fetch>);
    void p.then((res) => {
      if (!confirmed && Date.now() <= deadline && res.ok && resolveOrigin(input) === targetOrigin) confirmed = true;
    }).catch(() => {});
    return p;
  };

  // open() is overloaded; match the fullest overload so all call sites still work.
  XMLHttpRequest.prototype.open = function (this: XMLHttpRequest, method: string, url: string | URL, async?: boolean, username?: string | null, password?: string | null) {
    xhrUrls.set(this, String(url));
    return originalOpen.call(this, method, url, async ?? true, username ?? null, password ?? null);
  } as typeof XMLHttpRequest.prototype.open;

  XMLHttpRequest.prototype.send = function (body) {
    const xhr = this;
    xhr.addEventListener("load", () => {
      const url = xhrUrls.get(xhr);
      if (!confirmed && Date.now() <= deadline && xhr.status >= 200 && xhr.status < 300 && resolveOrigin(url) === targetOrigin) {
        confirmed = true;
      }
    });
    return originalSend.call(this, body);
  };

  window.setTimeout(
    () => {
      window.fetch = originalFetch;
      XMLHttpRequest.prototype.open = originalOpen;
      XMLHttpRequest.prototype.send = originalSend;
      if (confirmed) showCapturePrompt();
      else void dropPending();
    },
    AJAX_WINDOW_MS + 50,
  );
}

function resolveOrigin(url: string | URL | Request | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(String(url), window.location.href).origin;
  } catch {
    return null;
  }
}

// --- prompt + delivery -----------------------------------------------------------------

function showCapturePrompt(): void {
  if (!currentPending) return;
  hideInlineMenu();
  // Register the menu context so the background can route the capture accept back to this
  // frame; capture mode needs no entry list.
  void chrome.runtime.sendMessage({
    type: "menu_open",
    mode: "capture",
    origin: currentPending.origin,
    action: currentPending.action ?? undefined,
    title: currentPending.title,
    username: currentPending.username,
  });
  openInlineMenu({ mode: "capture", x: window.innerWidth - 348, y: 12 });
}

// Background requests the snapshot only when the user accepted the save (gesture-validated).
chrome.runtime.onMessage.addListener((msg: BackgroundToContentMessage, _sender, sendResponse) => {
  if (!msg) return false;
  if (msg.type === "fill_values") return false; // handled by fill.ts
  if (msg.type === "get_pending_snapshot") {
    sendResponse({ type: "pending_snapshot", snapshot: currentPending });
    return false;
  }
  if (msg.type === "capture_saved") {
    void dropPending();
    hideInlineMenu();
    return false;
  }
  return false;
});
