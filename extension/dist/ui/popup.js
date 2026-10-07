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

  // src/ui/popup.ts
  var entries = [];
  function esc(s) {
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
  }
  function queryActiveOrigin() {
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
  function send(msg) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(msg, (res) => {
        if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message ?? "no response" });
        else resolve(res ?? { ok: false, error: "no response" });
      });
    });
  }
  function renderState(st) {
    const dot = document.getElementById("dot");
    const status = document.getElementById("status");
    const lockBtn = document.getElementById("lock");
    const hint = document.getElementById("unlock-hint");
    dot.className = "dot";
    switch (st.status) {
      case "paired":
        dot.classList.add("connected");
        status.textContent = "\u5DF2\u8FDE\u63A5";
        break;
      case "connecting":
        dot.classList.add("warn");
        status.textContent = "\u8FDE\u63A5\u4E2D\u2026";
        break;
      case "awaiting_unlock":
        dot.classList.add("warn");
        status.textContent = "\u7B49\u5F85\u89E3\u9501";
        break;
      case "idle":
      case "error":
        dot.classList.add("err");
        status.textContent = st.status === "error" ? "\u51FA\u9519" : "\u672A\u8FDE\u63A5";
        break;
    }
    lockBtn.hidden = st.status !== "paired";
    hint.hidden = st.status !== "awaiting_unlock";
  }
  function renderEntries() {
    const box = document.getElementById("entries");
    if (!entries.length) {
      box.innerHTML = `<div class="empty">\u5F53\u524D\u7AD9\u70B9\u6CA1\u6709\u53EF\u586B\u5145\u7684\u6761\u76EE</div>`;
      return;
    }
    box.innerHTML = entries.map((e) => `<button class="entry" data-id="${esc(e.entry)}"><div>${esc(e.title)}</div></button>`).join("");
    for (const btn of box.querySelectorAll(".entry")) {
      btn.addEventListener("click", () => void doFill(btn.dataset.id));
    }
  }
  async function doFill(entry) {
    const origin = await queryActiveOrigin();
    if (!origin) return;
    const gesture = makeGesture();
    const res = await send({ type: "popup_fill", entry, origin, gesture });
    if (res.ok) {
      window.close();
    } else {
      const status = document.getElementById("status");
      status.textContent = "\u586B\u5145\u5931\u8D25";
    }
  }
  async function load() {
    const stRes = await send({ type: "get_state" });
    if (stRes.ok && stRes.state) renderState(stRes.state);
    else renderState({ status: "idle", paired: false });
    const origin = await queryActiveOrigin();
    if (!origin) {
      renderEntries();
      return;
    }
    const res = await send({ type: "get_entries", origin });
    if (res.ok && Array.isArray(res.entries)) entries = res.entries;
    renderEntries();
  }
  document.getElementById("retry").addEventListener("click", () => void load());
  document.getElementById("lock").addEventListener("click", () => {
    void send({ type: "lock" }).then(() => window.close());
  });
  document.addEventListener("DOMContentLoaded", () => void load());
})();
