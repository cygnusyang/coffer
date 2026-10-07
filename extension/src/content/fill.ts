/**
 * Fill content script (docs/31 §5.2, D-6): shows the inline menu when a login field is
 * focused and applies fill values delivered by the background worker.
 *
 * - Fill is triggered ONLY by an explicit user click in the extension-origin menu
 *   (no autofill, no prefill — DEF CON 33 mitigation; gesture generated at click).
 * - The plaintext fill values arrive via tabs.sendMessage (extension messaging, not DOM
 *   events) and are dropped from our references immediately after writing to the DOM
 *   (best-effort zeroization; page JS visibility is a structural limit, docs/31 §0).
 * - HIGH-1 (G-R): the write targets are the exact field elements captured at the
 *   focusin that opened the menu — never fields re-found at write time. A page could
 *   have prepended a decoy `<input type=password>` (a re-find would take passwords[0] =
 *   decoy), or navigated the frame so the fill lands in a foreign document. The fill is
 *   re-authorized against the approved origin/action right before writing (fill_auth).
 */
import { findLoginFields, fillField, formActionUrl, isSameOriginAction, wipeSecrets } from "./dom";
import { openInlineMenu, hideInlineMenu, isMenuOpen } from "./menu";
import { authorizeFill, type CapturedFillTarget } from "./fill_auth";
import type { EntryInfo } from "../protocol";
import type { BackgroundToContentMessage } from "../messages";

/** Field refs captured at the last login-field focusin (per document; reset on nav). */
let capturedTarget: { usernameEl: HTMLInputElement | null; passwordEl: HTMLInputElement | null } | null = null;

/** Re-evaluate the captured target with FRESH connectivity + form-action checks. */
function currentTargetForAuth(): CapturedFillTarget | null {
  if (!capturedTarget) return null;
  const form = capturedTarget.passwordEl?.form ?? capturedTarget.passwordEl?.closest("form") ?? null;
  return {
    usernameEl: capturedTarget.usernameEl,
    passwordEl: capturedTarget.passwordEl,
    usernameConnected: capturedTarget.usernameEl?.isConnected ?? false,
    passwordConnected: capturedTarget.passwordEl?.isConnected ?? false,
    sameOriginAction: isSameOriginAction(form),
  };
}

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

// Open the menu when a login field gains focus. The fields found here are the ONLY
// elements the subsequent fill may write to.
document.addEventListener(
  "focusin",
  (e) => {
    const target = e.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (isMenuOpen()) return;
    const fields = findLoginFields();
    if (!fields.password || (fields.password !== target && fields.username !== target)) {
      capturedTarget = null;
      hideInlineMenu();
      return;
    }
    if (fields.password.disabled) {
      capturedTarget = null;
      return;
    }
    capturedTarget = { usernameEl: fields.username, passwordEl: fields.password };
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
// Write ONLY to the captured refs, and only after re-authorizing origin/action/connectivity.
chrome.runtime.onMessage.addListener((msg: BackgroundToContentMessage) => {
  if (!msg || msg.type !== "fill_values") return;
  const auth = authorizeFill({
    approvedOrigin: msg.origin,
    currentOrigin: window.location.origin,
    target: currentTargetForAuth(),
  });
  if (!auth.ok) {
    // Fail-closed: never write on doubt (decoy swap / navigation / stale target).
    wipeSecrets({ username: msg.username, password: msg.password });
    return;
  }
  if (auth.targets?.usernameEl) fillField(auth.targets.usernameEl as HTMLInputElement, msg.username);
  if (auth.targets?.passwordEl) fillField(auth.targets.passwordEl as HTMLInputElement, msg.password);
  // Best-effort wipe of the extension's own references (JS cannot truly zeroize).
  wipeSecrets({ username: msg.username, password: msg.password });
  hideInlineMenu();
});
