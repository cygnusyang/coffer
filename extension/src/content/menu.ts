/**
 * Inline menu host — shared by the fill and capture content scripts.
 *
 * The menu is an extension-origin iframe (docs/31 §5.2, research Q4): same-origin
 * isolation keeps page JS from reading menu contents or clicking menu rows (cross-origin
 * iframe clicks cannot be synthesized by the page). The mode is passed in the iframe URL;
 * the menu pulls its (non-sensitive) context from the background worker over runtime
 * messaging on load. Any action that touches a secret or the broker (menu_fill /
 * menu_capture_accept) goes over runtime messaging with a gesture generated at the real
 * user click — page JS cannot reach inside the iframe.
 */
import type { MenuToBackgroundMessage } from "../messages";

const MENU_URL = chrome.runtime.getURL("ui/inline_menu.html");
const MENU_WIDTH = 320;
const MENU_MAX_HEIGHT = 360;
const VIEWPORT_MARGIN = 8;

export type MenuMode = "fill" | "capture";

export interface MenuOpenOptions {
  mode: MenuMode;
  /** Viewport coordinates (CSS px) for the menu top-left corner. */
  x: number;
  y: number;
}

let currentMenu: HTMLIFrameElement | null = null;
let lastMode: MenuMode = "fill";

/** Open (or refresh) the inline menu at a viewport position. */
export function openInlineMenu(opts: MenuOpenOptions): void {
  if (currentMenu) hideInlineMenu();
  lastMode = opts.mode;

  const menu = document.createElement("iframe");
  menu.src = `${MENU_URL}?mode=${opts.mode}`;
  menu.setAttribute("aria-label", "Coffer");
  menu.setAttribute("title", "Coffer");
  menu.style.cssText = [
    "position:fixed",
    "z-index:2147483647",
    "border:0",
    "box-shadow:0 4px 16px rgba(0,0,0,0.25)",
    "border-radius:8px",
    `width:${MENU_WIDTH}px`,
    `max-height:${MENU_MAX_HEIGHT}px`,
    "background:transparent",
  ].join(";");

  positionMenu(menu, opts.x, opts.y);
  document.documentElement.appendChild(menu);
  currentMenu = menu;

  // Dismiss on outside interaction / scroll / blur.
  window.addEventListener("blur", dismiss, { capture: true, once: true });
  window.addEventListener("scroll", dismiss, { capture: true, once: true });
  window.addEventListener("resize", dismiss, { capture: true, once: true });
  document.addEventListener(
    "pointerdown",
    (e) => {
      if (e.target !== menu) dismiss();
    },
    { capture: true, once: true },
  );
}

function dismiss(): void {
  hideInlineMenu();
}

function positionMenu(menu: HTMLIFrameElement, x: number, y: number): void {
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const left = Math.min(Math.max(VIEWPORT_MARGIN, x), vw - MENU_WIDTH - VIEWPORT_MARGIN);
  const top = Math.min(Math.max(VIEWPORT_MARGIN, y), vh - 48);
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
}

export function hideInlineMenu(): void {
  if (!currentMenu) return;
  currentMenu.remove();
  currentMenu = null;
  void chrome.runtime.sendMessage({ type: "menu_close" });
}

export function isMenuOpen(): boolean {
  return currentMenu !== null;
}

/** Current menu mode (used by capture/fill to distinguish dismissal handling). */
export function menuMode(): MenuMode {
  return lastMode;
}

// The menu iframe signals completion/close via postMessage (non-sensitive close signal).
window.addEventListener("message", (e) => {
  if (
    currentMenu &&
    e.source === currentMenu.contentWindow &&
    typeof e.data === "object" &&
    e.data !== null &&
    (e.data as { source?: string }).source === "coffer-menu-close"
  ) {
    hideInlineMenu();
  }
});

/** Forward an action message from the inline menu to the background worker. */
export function sendMenuAction(msg: MenuToBackgroundMessage): void {
  void chrome.runtime.sendMessage(msg);
}
