"use strict";
(() => {
  // src/content/dom.ts
  var IGNORE_ATTR = "data-coffer-ignore";
  function isIgnored(el) {
    let cur = el;
    while (cur) {
      if (cur instanceof HTMLElement && cur.hasAttribute(IGNORE_ATTR)) return true;
      cur = cur.parentElement;
    }
    return false;
  }
  function isUsernameCandidate(input) {
    const type = (input.getAttribute("type") ?? "text").toLowerCase();
    if (!["", "text", "email", "tel"].includes(type)) return false;
    if (input.disabled || input.readOnly) return false;
    const auto = (input.getAttribute("autocomplete") ?? "").toLowerCase();
    if (["username", "email", "login"].includes(auto)) return true;
    const hints = [input.name, input.id, input.getAttribute("aria-label")].filter(Boolean).join(" ").toLowerCase();
    return /\b(user(?:name)?|email|login|account|e-mail)\b/.test(hints);
  }
  function findUsernameForPassword(scope, password) {
    const inputs = Array.from(scope.querySelectorAll("input"));
    const idx = inputs.indexOf(password);
    for (let i = idx - 1; i >= 0; i--) {
      if (isUsernameCandidate(inputs[i])) return inputs[i];
    }
    return inputs.find((el) => isUsernameCandidate(el)) ?? null;
  }
  function findLoginFields(scope = document) {
    const passwords = Array.from(scope.querySelectorAll('input[type="password"]')).filter(
      (p) => !isIgnored(p)
    );
    if (passwords.length === 0) return { form: null, username: null, password: null };
    const password = passwords[0];
    const form = password.form ?? password.closest("form");
    const username = findUsernameForPassword(form ?? scope, password) ?? findUsernameForPassword(scope, password) ?? null;
    return { form, username, password };
  }
  function formActionUrl(form) {
    if (!form) return null;
    const action = form.getAttribute("action");
    if (!action) return window.location.href;
    try {
      return new URL(action, form.baseURI).href;
    } catch {
      return null;
    }
  }
  function readCredentials(fields) {
    if (!fields.password) return null;
    const password = fields.password.value ?? "";
    if (password.length === 0) return null;
    return {
      origin: window.location.origin,
      username: fields.username?.value ?? "",
      password,
      title: document.title || window.location.hostname,
      action: formActionUrl(fields.form),
      form: fields.form,
      usernameField: fields.username,
      passwordField: fields.password
    };
  }

  // src/content/menu.ts
  var MENU_URL = chrome.runtime.getURL("ui/inline_menu.html");
  var MENU_WIDTH = 320;
  var MENU_MAX_HEIGHT = 360;
  var VIEWPORT_MARGIN = 8;
  var currentMenu = null;
  var lastMode = "fill";
  function openInlineMenu(opts) {
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
      "background:transparent"
    ].join(";");
    positionMenu(menu, opts.x, opts.y);
    document.documentElement.appendChild(menu);
    currentMenu = menu;
    window.addEventListener("blur", dismiss, { capture: true, once: true });
    window.addEventListener("scroll", dismiss, { capture: true, once: true });
    window.addEventListener("resize", dismiss, { capture: true, once: true });
    document.addEventListener(
      "pointerdown",
      (e) => {
        if (e.target !== menu) dismiss();
      },
      { capture: true, once: true }
    );
  }
  function dismiss() {
    hideInlineMenu();
  }
  function positionMenu(menu, x, y) {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const left = Math.min(Math.max(VIEWPORT_MARGIN, x), vw - MENU_WIDTH - VIEWPORT_MARGIN);
    const top = Math.min(Math.max(VIEWPORT_MARGIN, y), vh - 48);
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
  }
  function hideInlineMenu() {
    if (!currentMenu) return;
    currentMenu.remove();
    currentMenu = null;
    void chrome.runtime.sendMessage({ type: "menu_close" });
  }
  window.addEventListener("message", (e) => {
    if (currentMenu && e.source === currentMenu.contentWindow && typeof e.data === "object" && e.data !== null && e.data.source === "coffer-menu-close") {
      hideInlineMenu();
    }
  });

  // src/content/capture.ts
  var PENDING_KEY = "coffer_pending_saves";
  var PENDING_TTL_MS = 12e4;
  var AJAX_WINDOW_MS = 6e3;
  var currentPending = null;
  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (isIgnored(form)) return;
      const snap = readCredentials(findLoginFields(form));
      if (!snap || snap.username.length === 0) return;
      const token = crypto.randomUUID();
      currentPending = { token, origin: snap.origin, action: snap.action, username: snap.username, password: snap.password, title: snap.title, ts: Date.now() };
      void persistPending(currentPending);
      watchAjaxSubmit(snap);
    },
    true
  );
  async function persistPending(snapshot) {
    try {
      const existing = (await chrome.storage.session.get(PENDING_KEY))[PENDING_KEY] ?? {};
      existing[snapshot.token] = snapshot;
      await chrome.storage.session.set({ [PENDING_KEY]: existing });
    } catch {
    }
  }
  async function dropPending() {
    currentPending = null;
    try {
      await chrome.storage.session.remove(PENDING_KEY);
    } catch {
    }
  }
  function expectedOrigin(snapshot) {
    if (!snapshot.action) return snapshot.origin;
    try {
      return new URL(snapshot.action, snapshot.origin).origin;
    } catch {
      return null;
    }
  }
  window.addEventListener(
    "pageshow",
    () => {
      void (async () => {
        let saves;
        try {
          saves = (await chrome.storage.session.get(PENDING_KEY))[PENDING_KEY];
        } catch {
          return;
        }
        if (!saves) return;
        const now = Date.now();
        const stale = [];
        for (const [token, save] of Object.entries(saves)) {
          const expected = expectedOrigin(save);
          if (now - save.ts > PENDING_TTL_MS || expected === null) {
            stale.push(token);
            continue;
          }
          if (expected === window.location.origin) {
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
    false
  );
  function watchAjaxSubmit(snap) {
    const targetOrigin = expectedOrigin(snap);
    if (!targetOrigin) return;
    const deadline = Date.now() + AJAX_WINDOW_MS;
    let confirmed = false;
    const xhrUrls = /* @__PURE__ */ new WeakMap();
    const originalFetch = window.fetch;
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    window.fetch = function(input, init) {
      const p = originalFetch.apply(this, arguments);
      void p.then((res) => {
        if (!confirmed && Date.now() <= deadline && res.ok && resolveOrigin(input) === targetOrigin) confirmed = true;
      }).catch(() => {
      });
      return p;
    };
    XMLHttpRequest.prototype.open = function(method, url, async, username, password) {
      xhrUrls.set(this, String(url));
      return originalOpen.call(this, method, url, async ?? true, username ?? null, password ?? null);
    };
    XMLHttpRequest.prototype.send = function(body) {
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
      AJAX_WINDOW_MS + 50
    );
  }
  function resolveOrigin(url) {
    if (!url) return null;
    try {
      return new URL(String(url), window.location.href).origin;
    } catch {
      return null;
    }
  }
  function showCapturePrompt() {
    if (!currentPending) return;
    hideInlineMenu();
    void chrome.runtime.sendMessage({
      type: "menu_open",
      mode: "capture",
      origin: currentPending.origin,
      action: currentPending.action ?? void 0,
      title: currentPending.title,
      username: currentPending.username
    });
    openInlineMenu({ mode: "capture", x: window.innerWidth - 348, y: 12 });
  }
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg) return false;
    if (msg.type === "fill_values") return false;
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
})();
