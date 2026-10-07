/**
 * Fill content script (docs/31 §5.2, D-6): shows the inline menu when a login field is
 * focused and applies fill values delivered by the background worker.
 *
 * - Fill is triggered ONLY by an explicit user click in the extension-origin menu
 *   (no autofill, no prefill — DEF CON 33 mitigation; gesture generated at click).
 * - The plaintext fill values arrive via tabs.sendMessage (extension messaging, not DOM
 *   events) and are dropped from our references immediately after writing to the DOM
 *   (best-effort zeroization; page JS visibility is a structural limit, docs/31 §0).
 */
import { findLoginFields, fillField, formActionUrl, wipeSecrets } from "./dom";
import { openInlineMenu, hideInlineMenu, isMenuOpen } from "./menu";
import type { EntryInfo } from "../protocol";
import type { BackgroundToContentMessage } from "../messages";

async function fetchEntries(origin: string, action: string | null): Promise<EntryInfo[] | null> {
  try {
    const res = (await chrome.runtime.sendMessage({
      type: "menu_open",
      mode: "fill",
      origin,
      action: action ?? undefined,
    })) as { entries?: EntryInfo[] } | { error?: unknown };
    if ("entries" in res && Array.isArray(res.entries)) return res.entries;
    return null;
  } catch {
    return null;
  }
}

// Open the menu when a login field gains focus.
document.addEventListener(
  "focusin",
  (e) => {
    const target = e.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (isMenuOpen()) return;
    const fields = findLoginFields();
    if (!fields.password || (fields.password !== target && fields.username !== target)) {
      hideInlineMenu();
      return;
    }
    if (fields.password.disabled) return;
    const origin = window.location.origin;
    const action = formActionUrl(fields.form);
    void (async () => {
      const entries = await fetchEntries(origin, action);
      if (entries === null || entries.length === 0) {
        hideInlineMenu();
        return;
      }
      const rect = target.getBoundingClientRect();
      openInlineMenu({ mode: "fill", x: rect.left, y: rect.bottom + 4 });
    })();
  },
  true,
);

// Apply fill values delivered by the background worker (from popup or inline menu).
chrome.runtime.onMessage.addListener((msg: BackgroundToContentMessage) => {
  if (!msg || msg.type !== "fill_values") return;
  const fields = findLoginFields();
  if (!fields.password) return;
  if (fields.username) fillField(fields.username, msg.username);
  fillField(fields.password, msg.password);
  // Best-effort wipe of the extension's own references (JS cannot truly zeroize).
  wipeSecrets({ username: msg.username, password: msg.password });
  hideInlineMenu();
});
