/**
 * Extension-internal runtime messages (chrome.runtime / tabs.sendMessage) — distinct
 * from the wire protocol in src/protocol.ts. These never leave the browser.
 */
import type { EntryInfo } from "./protocol";

/** Background state surfaced to popup / inline menu. */
export interface SessionState {
  status: "idle" | "connecting" | "paired" | "awaiting_unlock" | "error";
  errorCode?: number;
  paired: boolean; // pairing material present in chrome.storage.local
}

// --- UI -> background -----------------------------------------------------------------

export type UiToBackgroundMessage =
  | { type: "get_state" }
  | { type: "get_entries"; origin: string; action?: string }
  | { type: "popup_fill"; entry: string; origin: string; gesture: string }
  | { type: "lock" }
  | { type: "clear_pairing" };

// --- background -> content script -----------------------------------------------------

export type BackgroundToContentMessage =
  | {
      type: "fill_values";
      entry: string;
      username: string;
      password: string;
      /** Approved origin from the menu/popup context — re-verified before writing (HIGH-1). */
      origin: string;
      /** Approved form action at menu-open (null if none); same-origin re-checked before writing. */
      action: string | null;
    }
  | { type: "get_pending_snapshot" }
  | { type: "capture_saved" };

// --- content script -> background -----------------------------------------------------

/** menu_open is a request: background registers the menu context (host frame comes from
 * sender.frameId) and replies with `{ entries, origin }` (or `{ error }`) for fill mode,
 * and with `{ origin, title?, username?, action? }` for capture mode. */
export type ContentToBackgroundMessage =
  | { type: "menu_open"; mode: "fill" | "capture"; origin: string; action?: string; title?: string; username?: string }
  | { type: "menu_close" }
  | { type: "pending_snapshot"; snapshot: PendingSnapshotData | null };

// --- inline menu -> background (via runtime) ------------------------------------------

/** origin is included so the background can rebuild its menu context if the SW restarted
 * (MV3 service worker can be killed while the menu iframe stays open). */
export type MenuToBackgroundMessage =
  | { type: "menu_ready" }
  | { type: "menu_fill"; entry: string; origin: string; action?: string; gesture: string }
  | { type: "menu_cross_origin_confirm"; entry: string; origin: string; gesture: string }
  | { type: "menu_capture_accept"; origin: string; gesture: string };

// --- background -> inline menu / popup ------------------------------------------------

export type BackgroundToMenuMessage =
  | { type: "menu_entries"; entries: EntryInfo[]; origin: string; error?: { code: number; message: string } }
  | { type: "menu_confirm"; text: string; gestureRequired: true }
  | { type: "menu_save_started" }
  | { type: "menu_save_done"; ok: boolean }
  | { type: "state"; state: SessionState };

/** Snapshot data that crosses content script -> background for capture save. */
export interface PendingSnapshotData {
  token: string;
  origin: string;
  action: string | null;
  username: string;
  password: string;
  title: string;
  /** issuedAtMs for the in-memory capture prompt TTL (capture.ts). */
  ts: number;
}
