"use strict";
(() => {
  // src/protocol.ts
  var GESTURE_NONCE_LEN = 16;
  function b64encode(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  function makeGesture(nowMs = Date.now()) {
    const nonce = crypto.getRandomValues(new Uint8Array(GESTURE_NONCE_LEN));
    const out = new Uint8Array(GESTURE_NONCE_LEN + 8);
    out.set(nonce, 0);
    const dv = new DataView(out.buffer);
    dv.setBigUint64(GESTURE_NONCE_LEN, BigInt(nowMs), false);
    return b64encode(out);
  }

  // src/ui/inline_menu.ts
  var MODE = new URLSearchParams(location.search).get("mode") === "capture" ? "capture" : "fill";
  var data = { ok: false };
  var crossOriginApproved = false;
  var app = () => document.getElementById("app");
  function esc(s) {
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  }
  function closeMenu() {
    window.parent.postMessage({ source: "coffer-menu-close" }, "*");
  }
  function send(msg, onResult) {
    chrome.runtime.sendMessage(msg, (res) => {
      if (chrome.runtime.lastError) onResult({ ok: false, error: { code: 8004, message: chrome.runtime.lastError.message ?? "worker unavailable" } });
      else onResult(res ?? { ok: false, error: { code: 8004, message: "no response" } });
    });
  }
  function renderHeader() {
    return `<div class="head"><span class="logo">Coffer</span><span class="origin" title="${esc(data.origin ?? "")}">${esc(data.origin ?? "")}</span></div>`;
  }
  function renderWarn() {
    const cross = isCrossOriginAction();
    if (!cross) return "";
    return `<div class="warn">\u6B64\u8868\u5355\u5C06\u63D0\u4EA4\u5230\u5176\u4ED6\u7AD9\u70B9\uFF08${esc(actionOrigin() ?? "")}\uFF09\u3002\u7EE7\u7EED\u586B\u5145\u524D\u8BF7\u786E\u8BA4\u8FD9\u662F\u4F60\u4FE1\u4EFB\u7684\u7AD9\u70B9\u3002</div>`;
  }
  function actionOrigin() {
    if (!data.action) return null;
    try {
      return new URL(data.action, data.origin).origin;
    } catch {
      return null;
    }
  }
  function isCrossOriginAction() {
    const ao = actionOrigin();
    return ao !== null && data.origin !== void 0 && ao !== data.origin;
  }
  function renderStatus(text) {
    app().innerHTML = `${renderHeader()}<div class="status">${esc(text)}</div>`;
  }
  function renderList() {
    const entries = data.entries ?? [];
    const rows = entries.map((e) => `<button class="entry" data-id="${esc(e.id)}"><div>${esc(e.title)}</div></button>`).join("");
    app().innerHTML = `${renderHeader()}${renderWarn()}<div class="list">${rows}</div>`;
  }
  function renderCrossOriginConfirm(id) {
    app().innerHTML = `${renderHeader()}<div class="warn">\u6B64\u8868\u5355\u63D0\u4EA4\u5230 ${esc(actionOrigin() ?? "\u672A\u77E5\u7AD9\u70B9")}\u3002\u786E\u8BA4\u586B\u5145\u5417\uFF1F</div><div class="row"><button class="ghost" id="coffer-cancel">\u53D6\u6D88</button><button class="primary" id="coffer-confirm">\u786E\u8BA4\u586B\u5145</button></div>`;
    app().querySelector("#coffer-confirm").addEventListener("click", () => {
      const gesture = makeGesture();
      send({ type: "menu_cross_origin_confirm", origin: data.origin ?? "", gesture }, (res) => {
        if (res.ok) {
          crossOriginApproved = true;
          doFill(id);
        } else {
          renderStatus(res.error?.message ?? "\u786E\u8BA4\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5");
        }
      });
    });
    app().querySelector("#coffer-cancel").addEventListener("click", () => {
      renderList();
    });
  }
  function doFill(id) {
    const gesture = makeGesture();
    send({ type: "menu_fill", entry: id, origin: data.origin ?? "", action: data.action, gesture }, (res) => {
      if (res.ok) closeMenu();
      else renderStatus(res.error?.message ?? "\u586B\u5145\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5");
    });
  }
  function renderCapture() {
    app().innerHTML = `${renderHeader()}<div class="detail">\u4FDD\u5B58\u8BE5\u7AD9\u70B9\u7684\u767B\u5F55\u4FE1\u606F\uFF1F</div><div class="detail">\u7528\u6237\u540D\uFF1A${esc(data.username ?? "\uFF08\u7A7A\uFF09")}</div><div class="detail">\u9875\u9762\uFF1A${esc(data.title ?? "")}</div><div class="row"><button class="ghost" id="coffer-decline">\u53D6\u6D88</button><button class="primary" id="coffer-accept">\u4FDD\u5B58\u5230 Coffer</button></div>`;
    app().querySelector("#coffer-accept").addEventListener("click", () => {
      const gesture = makeGesture();
      send({ type: "menu_capture_accept", origin: data.origin ?? "", gesture }, (res) => {
        if (res.ok) closeMenu();
        else renderStatus(res.error?.message ?? "\u4FDD\u5B58\u5931\u8D25\uFF0C\u8BF7\u91CD\u8BD5");
      });
    });
    app().querySelector("#coffer-decline").addEventListener("click", closeMenu);
  }
  function onLoad() {
    chrome.runtime.sendMessage({ type: "menu_ready" }, (res) => {
      if (chrome.runtime.lastError || !res || !res.ok) {
        data = { ok: false };
        renderStatus("Coffer \u4F1A\u8BDD\u4E0D\u53EF\u7528\uFF0C\u8BF7\u91CD\u65B0\u805A\u7126\u8F93\u5165\u6846");
        return;
      }
      data = res;
      if (data.mode === "capture") renderCapture();
      else renderList();
    });
  }
  app().addEventListener("click", (e) => {
    const btn = e.target.closest(".entry");
    if (!btn || !btn.dataset.id) return;
    const id = btn.dataset.id;
    if (isCrossOriginAction() && !crossOriginApproved) {
      renderCrossOriginConfirm(id);
      return;
    }
    doFill(id);
  });
  document.addEventListener("DOMContentLoaded", onLoad);
})();
