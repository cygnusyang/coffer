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
    const pairHint = document.getElementById("pair-hint");
    const pairBtn = document.getElementById("pair");
    dot.className = "dot";
    pairHint.hidden = true;
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
      case "pairing":
        dot.classList.add("warn");
        status.textContent = "\u7B49\u5F85 Coffer \u6279\u51C6\u2026";
        break;
      case "idle":
      case "error":
        dot.classList.add("err");
        if (st.errorCode === 8003 /* BrokerUnavailable */) {
          status.textContent = st.paired ? "\u91CD\u8FDE\u5931\u8D25" : "App \u4E0D\u53EF\u8FBE";
          pairHint.hidden = false;
          pairHint.textContent = st.paired ? "\u65E0\u6CD5\u8FDE\u63A5\u5230 Coffer\u3002\u8BF7\u786E\u8BA4 Coffer \u6B63\u5728\u8FD0\u884C\u5E76\u5DF2\u542F\u7528\u6D4F\u89C8\u5668\u96C6\u6210\uFF0C\u7136\u540E\u70B9\u51FB\u300C\u5237\u65B0\u300D\u91CD\u8BD5\u3002" : "\u8BF7\u6253\u5F00 Coffer \u5E76\u542F\u7528\u6D4F\u89C8\u5668\u96C6\u6210\u540E\uFF0C\u518D\u70B9\u51FB\u300C\u7ACB\u5373\u914D\u5BF9\u300D\u91CD\u8BD5\u3002";
        } else if (st.errorCode === 8006 /* UserRejected */) {
          status.textContent = "\u672A\u8FDE\u63A5";
          pairHint.hidden = false;
          pairHint.textContent = "\u914D\u5BF9\u5DF2\u62D2\u7EDD\u3002\u53EF\u91CD\u65B0\u53D1\u8D77\u914D\u5BF9\u3002";
        } else {
          status.textContent = st.status === "error" ? "\u51FA\u9519" : "\u672A\u8FDE\u63A5";
        }
        break;
    }
    lockBtn.hidden = st.status !== "paired";
    hint.hidden = st.status !== "awaiting_unlock";
    const showPair = !st.paired && (st.status === "idle" || st.status === "error");
    pairBtn.hidden = !showPair;
  }
  function renderEntries(unpaired = false) {
    const box = document.getElementById("entries");
    if (unpaired) {
      box.innerHTML = "";
      return;
    }
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
    const st = stRes.ok && stRes.state ? stRes.state : null;
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
    if (res.ok && Array.isArray(res.entries)) entries = res.entries;
    renderEntries();
  }
  document.getElementById("retry").addEventListener("click", () => void load());
  document.getElementById("lock").addEventListener("click", () => {
    void send({ type: "lock" }).then(() => window.close());
  });
  document.getElementById("pair").addEventListener("click", () => {
    void send({ type: "pair" }).then((res) => {
      if (!res.ok) document.getElementById("status").textContent = "\u914D\u5BF9\u5931\u8D25";
      void load();
    });
  });
  document.addEventListener("DOMContentLoaded", () => void load());
})();
