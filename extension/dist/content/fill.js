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
  function sameOriginUrl(actionUrl, origin) {
    if (!actionUrl) return false;
    try {
      return new URL(actionUrl).origin === origin;
    } catch {
      return false;
    }
  }
  function isSameOriginAction(form) {
    return sameOriginUrl(formActionUrl(form), window.location.origin);
  }
  function setNativeValue(input, value) {
    const proto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    if (setter) setter.call(input, value);
    else input.value = value;
  }
  function fillField(input, value) {
    if (!input) return;
    setNativeValue(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }
  function wipeSecrets(s) {
    s.username = "";
    s.password = "";
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
  function isMenuOpen() {
    return currentMenu !== null;
  }
  window.addEventListener("message", (e) => {
    if (currentMenu && e.source === currentMenu.contentWindow && typeof e.data === "object" && e.data !== null && e.data.source === "coffer-menu-close") {
      hideInlineMenu();
    }
  });

  // src/content/fill_auth.ts
  function authorizeFill(opts) {
    if (!opts.target) return { ok: false, reason: "no_target" };
    if (opts.currentOrigin !== opts.approvedOrigin) return { ok: false, reason: "origin_mismatch" };
    if (!opts.target.passwordConnected) return { ok: false, reason: "target_disconnected" };
    if (!opts.target.sameOriginAction) return { ok: false, reason: "cross_origin_action" };
    return {
      ok: true,
      targets: {
        usernameEl: opts.target.usernameConnected ? opts.target.usernameEl : null,
        passwordEl: opts.target.passwordEl
      }
    };
  }

  // src/content/fill.ts
  var capturedTarget = null;
  function currentTargetForAuth() {
    if (!capturedTarget) return null;
    const form = capturedTarget.passwordEl?.form ?? capturedTarget.passwordEl?.closest("form") ?? null;
    return {
      usernameEl: capturedTarget.usernameEl,
      passwordEl: capturedTarget.passwordEl,
      usernameConnected: capturedTarget.usernameEl?.isConnected ?? false,
      passwordConnected: capturedTarget.passwordEl?.isConnected ?? false,
      sameOriginAction: isSameOriginAction(form)
    };
  }
  async function fetchEntries(origin, action) {
    try {
      const res = await chrome.runtime.sendMessage({
        type: "menu_open",
        mode: "fill",
        origin,
        action: action ?? void 0
      });
      if ("entries" in res && Array.isArray(res.entries)) return res.entries;
      return null;
    } catch {
      return null;
    }
  }
  document.addEventListener(
    "focusin",
    (e) => {
      const target = e.target;
      if (!(target instanceof HTMLInputElement)) return;
      if (isMenuOpen()) return;
      const fields = findLoginFields();
      if (!fields.password || fields.password !== target && fields.username !== target) {
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
    true
  );
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.type !== "fill_values") return;
    const auth = authorizeFill({
      approvedOrigin: msg.origin,
      currentOrigin: window.location.origin,
      target: currentTargetForAuth()
    });
    if (!auth.ok) {
      wipeSecrets({ username: msg.username, password: msg.password });
      return;
    }
    if (auth.targets?.usernameEl) fillField(auth.targets.usernameEl, msg.username);
    if (auth.targets?.passwordEl) fillField(auth.targets.passwordEl, msg.password);
    wipeSecrets({ username: msg.username, password: msg.password });
    hideInlineMenu();
  });
})();
