"use strict";
(() => {
  // src/protocol.ts
  var PROTOCOL_VERSION = 1;
  var SESSION_KDF_INFO = "cf/browser/session/v1";
  var SEC1_LEN = 65;
  var GCM_NONCE_LEN = 12;
  var GCM_TAG_LEN = 16;
  var FRAME_MAC_LEN = 32;
  var SESSION_KEY_LEN = 64;
  var ECDSA_SIG_LEN = 64;
  var GESTURE_TTL_MS = 3e4;
  var GESTURE_NONCE_LEN = 16;
  var ProtocolError = class extends Error {
    constructor(code, message) {
      super(message);
      this.code = code;
      this.name = "ProtocolError";
    }
  };
  function encodeUtf8(s) {
    return new TextEncoder().encode(s);
  }
  function decodeUtf8(b) {
    return new TextDecoder().decode(b);
  }
  function b64encode(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  function b64decode(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function hexEncode(bytes) {
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
  }
  function hexDecode(s) {
    if (s.length % 2 !== 0) throw new ProtocolError(8004 /* SessionNotEstablished */, "odd hex length");
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  function makeGesture(nowMs = Date.now()) {
    const nonce = crypto.getRandomValues(new Uint8Array(GESTURE_NONCE_LEN));
    const out = new Uint8Array(GESTURE_NONCE_LEN + 8);
    out.set(nonce, 0);
    const dv = new DataView(out.buffer);
    dv.setBigUint64(GESTURE_NONCE_LEN, BigInt(nowMs), false);
    return b64encode(out);
  }
  function parseGesture(gesture) {
    if (!gesture || typeof gesture !== "string") return null;
    let bytes;
    try {
      bytes = b64decode(gesture);
    } catch {
      return null;
    }
    if (bytes.length !== GESTURE_NONCE_LEN + 8) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const issuedAtMs = Number(dv.getBigUint64(GESTURE_NONCE_LEN, false));
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs <= 0) return null;
    return { nonce: bytes.slice(0, GESTURE_NONCE_LEN), issuedAtMs };
  }
  function gestureWithinTtl(gesture, nowMs = Date.now()) {
    const p = parseGesture(gesture);
    if (!p) return false;
    return p.issuedAtMs <= nowMs && nowMs - p.issuedAtMs <= GESTURE_TTL_MS;
  }

  // src/crypto/e2e.ts
  async function generateEphemeralKeyPair() {
    return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  }
  async function exportRawPublicKey(key) {
    const raw = await crypto.subtle.exportKey("raw", key);
    const bytes = new Uint8Array(raw);
    if (bytes.length !== SEC1_LEN || bytes[0] !== 4) {
      throw new ProtocolError(8004 /* SessionNotEstablished */, "unexpected P-256 public key encoding");
    }
    return bytes;
  }
  async function importRawPublicKey(raw) {
    if (raw.length !== SEC1_LEN || raw[0] !== 4) {
      throw new ProtocolError(8004 /* SessionNotEstablished */, "invalid P-256 public key");
    }
    return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, true, []);
  }
  async function ecdhShared(priv, peerPub) {
    const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerPub }, priv, 256);
    return new Uint8Array(bits);
  }
  async function hkdfBytes(ikm, salt, info, lengthBytes) {
    const base = await crypto.subtle.importKey(
      "raw",
      ikm,
      "HKDF",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      base,
      lengthBytes * 8
    );
    return new Uint8Array(bits);
  }
  async function deriveSessionKeys(ee, es, eInitPub, eRespPub) {
    const okm = await hkdfBytes(concat(ee, es), concat(eInitPub, eRespPub), encodeUtf8(SESSION_KDF_INFO), SESSION_KEY_LEN);
    return {
      ee,
      es,
      okm,
      encKey: okm.slice(0, 32),
      macKey: okm.slice(32)
    };
  }
  async function deriveClientSharedSecrets(ephSk, brokerEphPub, brokerStaticPub) {
    const ee = await ecdhShared(ephSk, brokerEphPub);
    const es = await ecdhShared(ephSk, brokerStaticPub);
    return { ee, es };
  }
  async function importHmacKey(keyBytes, usages) {
    return crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, usages);
  }
  async function computeConfirm(psk, okm) {
    const key = await importHmacKey(psk, ["sign"]);
    const mac = await crypto.subtle.sign("HMAC", key, okm);
    return new Uint8Array(mac);
  }
  async function frameMac(macKey, nonce, ctTag) {
    const key = await importHmacKey(macKey, ["sign"]);
    const mac = await crypto.subtle.sign("HMAC", key, concat(nonce, ctTag));
    return new Uint8Array(mac);
  }
  async function verifyFrameMac(macKey, nonce, ctTag, mac) {
    const key = await importHmacKey(macKey, ["verify"]);
    return crypto.subtle.verify("HMAC", key, mac, concat(nonce, ctTag));
  }
  async function importRawEcdsaPublicKey(raw) {
    if (raw.length !== SEC1_LEN || raw[0] !== 4) {
      throw new ProtocolError(8004 /* SessionNotEstablished */, "invalid broker public key");
    }
    return crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  }
  async function verifySignature(pk, message, sig) {
    if (sig.length !== ECDSA_SIG_LEN) return false;
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pk, sig, message);
  }
  function buildSigMessage(eInitPub, eRespPub) {
    return concat(eInitPub, eRespPub);
  }
  async function importAesKey(bytes) {
    return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }
  async function encryptPayload(encKey, nonce, plaintext) {
    const key = await importAesKey(encKey);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: new Uint8Array(0) },
      key,
      plaintext
    );
    return new Uint8Array(ct);
  }
  async function decryptPayload(encKey, nonce, ctTag) {
    const key = await importAesKey(encKey);
    try {
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: new Uint8Array(0) },
        key,
        ctTag
      );
      return new Uint8Array(pt);
    } catch {
      throw new ProtocolError(8004 /* SessionNotEstablished */, "AEAD verification failed");
    }
  }
  function buildFrameBytes(nonce, ctTag, mac) {
    return concat(nonce, ctTag, mac);
  }
  function parseFrameBytes(raw) {
    const minLen = GCM_NONCE_LEN + GCM_TAG_LEN + FRAME_MAC_LEN;
    if (raw.length < minLen) {
      throw new ProtocolError(8004 /* SessionNotEstablished */, "frame too short");
    }
    const macEnd = raw.length - FRAME_MAC_LEN;
    return { nonce: raw.slice(0, GCM_NONCE_LEN), ctTag: raw.slice(GCM_NONCE_LEN, macEnd), mac: raw.slice(macEnd) };
  }
  function serializeAppMessage(body) {
    return encodeUtf8(JSON.stringify(body));
  }
  function u64Le(value) {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
    return out;
  }
  var SessionCipher = class {
    encKeyBytes;
    macKeyBytes;
    outSeq = 0;
    recvSeq = 0;
    constructor(encKeyBytes, macKeyBytes) {
      this.encKeyBytes = encKeyBytes;
      this.macKeyBytes = macKeyBytes;
    }
    /** Encrypt one application message → SessionFrame {type:"e2e", v, frame: b64}. */
    async seal(body) {
      const seq = this.outSeq + 1;
      const plaintext = concat(u64Le(seq), serializeAppMessage(body));
      const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_LEN));
      const ctTag = await encryptPayload(this.encKeyBytes, nonce, plaintext);
      const mac = await frameMac(this.macKeyBytes, nonce, ctTag);
      this.outSeq = seq;
      return { type: "e2e", v: PROTOCOL_VERSION, frame: b64encode(buildFrameBytes(nonce, ctTag, mac)) };
    }
    /** Decrypt + authenticate a session frame → { seq, body } (Rust decrypt ordering). */
    async open(frame) {
      if (!frame || frame.type !== "e2e" || frame.v !== PROTOCOL_VERSION) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "malformed session frame");
      }
      let raw;
      try {
        raw = b64decode(frame.frame);
      } catch {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "malformed session frame encoding");
      }
      const { nonce, ctTag, mac } = parseFrameBytes(raw);
      const ok = await verifyFrameMac(this.macKeyBytes, nonce, ctTag, mac);
      if (!ok) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "frame MAC verification failed");
      }
      const plaintext = await decryptPayload(this.encKeyBytes, nonce, ctTag);
      if (plaintext.length < 8) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "malformed frame plaintext");
      }
      const seq = Number(new DataView(plaintext.buffer, plaintext.byteOffset, 8).getBigUint64(0, true));
      if (seq <= this.recvSeq) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "out-of-order or replayed session frame");
      }
      this.recvSeq = seq;
      let body;
      try {
        body = JSON.parse(decodeUtf8(plaintext.slice(8)));
      } catch {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "malformed frame payload JSON");
      }
      if (typeof body !== "object" || body === null || !("type" in body)) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "malformed frame payload");
      }
      return { seq, body };
    }
  };
  var E2EClient = class {
    constructor(pairing, opts) {
      this.pairing = pairing;
      if (pairing.brokerPublicKeyRaw.length !== SEC1_LEN || pairing.brokerPublicKeyRaw[0] !== 4) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "invalid pinned broker public key");
      }
      this.brokerEcdsa = importRawEcdsaPublicKey(pairing.brokerPublicKeyRaw);
      this.brokerEcdh = importRawPublicKey(pairing.brokerPublicKeyRaw);
      this.ephKeyPair = opts?.ephKeyPair ?? null;
    }
    ephKeyPair = null;
    eInitPub = null;
    cipher = null;
    brokerEcdsa;
    brokerEcdh;
    /** Step 1: emit initiator ephemeral → msg1 Init (SEC1 hex). */
    async start() {
      if (!this.ephKeyPair) this.ephKeyPair = await generateEphemeralKeyPair();
      this.eInitPub = await exportRawPublicKey(this.ephKeyPair.publicKey);
      return { type: "init", version: PROTOCOL_VERSION, e_init: hexEncode(this.eInitPub) };
    }
    /** Step 2: verify msg2 (pin + signature), derive session key, emit msg3 Confirm. */
    async processReply(resp) {
      if (!this.ephKeyPair || !this.eInitPub) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "start() not called");
      }
      if (!resp || resp.type !== "response" || resp.version !== PROTOCOL_VERSION) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "malformed response frame");
      }
      let eRespPub;
      let pkB;
      let sig;
      try {
        eRespPub = hexDecode(resp.e_resp);
        pkB = hexDecode(resp.pk_b);
        sig = hexDecode(resp.signature);
      } catch {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "malformed response encoding");
      }
      if (eRespPub.length !== SEC1_LEN || eRespPub[0] !== 4) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "bad broker ephemeral");
      }
      if (pkB.length !== SEC1_LEN || pkB[0] !== 4) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "bad broker public key");
      }
      if (sig.length !== ECDSA_SIG_LEN) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "bad signature length");
      }
      if (!bytesEqual(pkB, this.pairing.brokerPublicKeyRaw)) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "broker public key does not match pinned key");
      }
      const message = buildSigMessage(this.eInitPub, eRespPub);
      const ok = await verifySignature(await this.brokerEcdsa, message, sig);
      if (!ok) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "broker signature verification failed");
      }
      const brokerEphPub = await importRawPublicKey(eRespPub);
      const { ee, es } = await deriveClientSharedSecrets(this.ephKeyPair.privateKey, brokerEphPub, await this.brokerEcdh);
      const keys = await deriveSessionKeys(ee, es, this.eInitPub, eRespPub);
      const confirm = await computeConfirm(this.pairing.psk, keys.okm);
      this.cipher = new SessionCipher(keys.encKey, keys.macKey);
      return {
        confirm: { type: "confirm", version: PROTOCOL_VERSION, p: hexEncode(confirm) },
        session: this.cipher
      };
    }
    isReady() {
      return this.cipher !== null;
    }
    async seal(body) {
      if (!this.cipher) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "session not established");
      }
      return this.cipher.seal(body);
    }
    async open(frame) {
      if (!this.cipher) {
        throw new ProtocolError(8004 /* SessionNotEstablished */, "session not established");
      }
      return this.cipher.open(frame);
    }
  };
  function concat(...parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }
  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // src/fillable.ts
  var PASSWORD_KINDS = /* @__PURE__ */ new Set(["password"]);
  var USERNAME_KINDS = /* @__PURE__ */ new Set(["username", "email"]);
  function fillableFields(entry) {
    if (!entry || !Array.isArray(entry.fields)) return [];
    const out = [];
    for (const f of entry.fields) {
      const kind = f.designation?.kind ?? "";
      if (PASSWORD_KINDS.has(kind)) {
        if (!out.some((x) => x.role === "password")) out.push({ role: "password", name: f.name });
      } else if (USERNAME_KINDS.has(kind)) {
        if (!out.some((x) => x.role === "username")) out.push({ role: "username", name: f.name });
      }
    }
    return out.filter((f) => f.role === "username").concat(out.filter((f) => f.role === "password"));
  }

  // src/origin.ts
  function normalizeHost(host) {
    let h = host.trim().toLowerCase();
    if (h.endsWith(".")) h = h.slice(0, -1);
    return h;
  }
  function parseOrigin(input) {
    if (!input || typeof input !== "string") return null;
    let url;
    try {
      url = new URL(input);
    } catch {
      return null;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.origin === "null") return null;
    const host = normalizeHost(url.hostname);
    if (host.length === 0) return null;
    const port2 = url.port ? Number(url.port) : null;
    return {
      scheme: url.protocol === "https:" ? "https" : "http",
      host,
      port: port2,
      canonical: url.origin
    };
  }
  function canonicalOrigin(input) {
    return parseOrigin(input)?.canonical ?? null;
  }
  function originOfUrl(raw) {
    if (!raw || typeof raw !== "string") return null;
    return canonicalOrigin(raw);
  }

  // src/background.ts
  var NATIVE_HOST = "com.coffer.browser";
  var PAIRING_KEY = "coffer_pairing";
  var RETRY_DELAY_MS = 5e3;
  var MAX_RETRIES = 3;
  var MAX_ENTRY_LIST = 50;
  var port = null;
  var session = null;
  var sessionReady = null;
  var handshakeWait = null;
  var state = { status: "idle", paired: false };
  var retryTimer = null;
  var retries = 0;
  var gestureSeen = /* @__PURE__ */ new Map();
  var pendingQueue = [];
  var menuContexts = /* @__PURE__ */ new Map();
  var nextRequestId = 1;
  var lastSentRequestId = null;
  function setState(next) {
    state = { ...state, ...next };
    void chrome.runtime.sendMessage({ type: "state", state }).catch(() => {
    });
  }
  function errorOf(e) {
    if (e instanceof ProtocolError) return { code: e.code, message: e.message };
    if (e instanceof Error) return { code: 8004 /* SessionNotEstablished */, message: e.message };
    return { code: 8004 /* SessionNotEstablished */, message: String(e) };
  }
  async function loadPairing() {
    const raw = (await chrome.storage.local.get(PAIRING_KEY))[PAIRING_KEY];
    if (!raw || typeof raw.brokerPublicKeyRaw !== "string" || typeof raw.psk !== "string") return null;
    try {
      return { brokerPublicKeyRaw: b64decode(raw.brokerPublicKeyRaw), psk: b64decode(raw.psk) };
    } catch {
      return null;
    }
  }
  function connect() {
    if (port) return;
    try {
      port = chrome.runtime.connectNative(NATIVE_HOST);
    } catch {
      failHandshake(new ProtocolError(8003 /* BrokerUnavailable */, "native messaging host not found"));
      return;
    }
    port.onMessage.addListener(onPortMessage);
    port.onDisconnect.addListener(onPortDisconnect);
  }
  function onPortDisconnect() {
    const wasPaired = state.paired;
    port = null;
    session = null;
    sessionReady = null;
    lastSentRequestId = null;
    if (handshakeWait) {
      handshakeWait.reject(new ProtocolError(8003 /* BrokerUnavailable */, "native port closed"));
      handshakeWait = null;
    }
    const q = pendingQueue;
    pendingQueue.length = 0;
    for (const p of q) p.reject(new ProtocolError(8003 /* BrokerUnavailable */, "native port closed"));
    setState({ status: wasPaired ? "awaiting_unlock" : "idle", paired: wasPaired });
    if (wasPaired) scheduleRetry();
  }
  async function performHandshake() {
    const pairing = await loadPairing();
    if (!pairing) {
      throw new ProtocolError(8004 /* SessionNotEstablished */, "not paired \u2014 open Coffer and enable browser integration");
    }
    const client = new E2EClient(pairing);
    session = client;
    if (!port) connect();
    if (!port) throw new ProtocolError(8003 /* BrokerUnavailable */, "native port unavailable");
    const init = await client.start();
    port.postMessage(init);
    setState({ status: "connecting", paired: true });
    await waitForPaired();
    return client;
  }
  function waitForPaired() {
    return new Promise((resolve, reject) => {
      handshakeWait = { resolve, reject };
    });
  }
  async function ensureSession() {
    if (session && session.isReady() && port) return session;
    if (!sessionReady) sessionReady = performHandshake();
    try {
      return await sessionReady;
    } catch (e) {
      sessionReady = null;
      session = null;
      throw e;
    }
  }
  function failHandshake(e) {
    if (handshakeWait) {
      handshakeWait.reject(e);
      handshakeWait = null;
    }
    session = null;
    sessionReady = null;
  }
  async function onPortMessage(raw) {
    if (!raw || typeof raw !== "object") return;
    const frame = raw;
    switch (frame.type) {
      case "response": {
        if (!session) return;
        try {
          const { confirm } = await session.processReply(frame);
          port?.postMessage(confirm);
          if (handshakeWait) {
            handshakeWait.resolve();
            handshakeWait = null;
          }
          setState({ status: "paired", paired: state.paired });
        } catch (e) {
          failHandshake(e);
        }
        return;
      }
      case "broker_locked": {
        failHandshake(new ProtocolError(8003 /* BrokerUnavailable */, "broker locked"));
        setState({ status: "awaiting_unlock", paired: state.paired });
        return;
      }
      case "e2e": {
        if (!session) return;
        try {
          const opened = await session.open(frame);
          handleSessionBody(opened.body);
        } catch (e) {
          handleSessionBroken(e);
        }
        return;
      }
      default:
        return;
    }
  }
  function handleSessionBody(body) {
    if (!body || typeof body !== "object") return;
    if (body.type === "broker_locked") {
      const waiters = pendingQueue.splice(0);
      for (const w of waiters) w.reject(new ProtocolError(8003 /* BrokerUnavailable */, "broker locked"));
      lastSentRequestId = null;
      setState({ status: "awaiting_unlock", paired: state.paired });
      return;
    }
    if (body.type === "get_secret_result") {
      if (lastSentRequestId === null || body.request_id !== lastSentRequestId) {
        handleSessionBroken(new ProtocolError(8004 /* SessionNotEstablished */, "request_id echo mismatch"));
        return;
      }
      lastSentRequestId = null;
    }
    const waiter = pendingQueue.shift();
    if (!waiter) return;
    if (body.type === "error") {
      waiter.reject(new ProtocolError(body.code ?? 8004 /* SessionNotEstablished */, body.message ?? "broker error"));
    } else {
      waiter.resolve(body);
    }
  }
  function handleSessionBroken(e) {
    session = null;
    sessionReady = null;
    if (port) {
      try {
        port.disconnect();
      } catch {
      }
      port = null;
    }
    setState({ status: "idle", paired: state.paired });
    scheduleRetry();
  }
  function scheduleRetry() {
    if (retryTimer !== null || retries >= MAX_RETRIES) return;
    retries += 1;
    retryTimer = globalThis.setTimeout(() => {
      retryTimer = null;
      if (port) return;
      void ensureSession().catch(() => {
      });
    }, RETRY_DELAY_MS);
  }
  function resetSession() {
    session = null;
    sessionReady = null;
    if (port) {
      try {
        port.disconnect();
      } catch {
      }
    }
    port = null;
    retries = 0;
    setState({ status: "idle", paired: false });
  }
  async function brokerRequest(req) {
    const client = await ensureSession();
    if (!port) {
      throw new ProtocolError(8003 /* BrokerUnavailable */, "native port unavailable");
    }
    let wire;
    if (req.type === "get_secret") {
      wire = { ...req, request_id: nextRequestId++ };
      lastSentRequestId = wire.request_id;
    } else {
      wire = req;
      lastSentRequestId = null;
    }
    const envelope = await client.seal(wire);
    const waiter = new Promise((resolve, reject) => {
      pendingQueue.push({ resolve, reject });
    });
    port.postMessage(envelope);
    return waiter;
  }
  function consumeGesture(gesture) {
    if (!gestureWithinTtl(gesture)) {
      throw new ProtocolError(8007 /* GestureExpired */, "gesture expired or invalid");
    }
    const parsed = parseGesture(gesture);
    if (!parsed) throw new ProtocolError(8007 /* GestureExpired */, "gesture invalid");
    const nonce = b64encode(parsed.nonce);
    const now = Date.now();
    for (const [k, ts] of gestureSeen) {
      if (now - ts > GESTURE_TTL_MS) gestureSeen.delete(k);
    }
    if (gestureSeen.has(nonce)) {
      throw new ProtocolError(8007 /* GestureExpired */, "gesture already used (replay)");
    }
    gestureSeen.set(nonce, now);
  }
  function wireGesture() {
    return makeGesture();
  }
  function menuContextFor(sender, origin, action) {
    const tabId = sender.tab?.id;
    const existing = tabId !== void 0 ? menuContexts.get(tabId) : void 0;
    if (existing && existing.origin === origin) return existing;
    const fresh = { mode: "fill", hostFrameId: sender.frameId ?? 0, origin, action };
    if (tabId !== void 0) menuContexts.set(tabId, fresh);
    return fresh;
  }
  async function entryMetadata(ctx, entry) {
    if (ctx.entries) return ctx.entries.find((e) => e.entry === entry);
    try {
      const body = await brokerRequest({ type: "get_entries", origin: ctx.origin });
      if (body.type === "entries_result") {
        const list = body.entries.slice(0, MAX_ENTRY_LIST);
        ctx.entries = list;
        return list.find((e) => e.entry === entry);
      }
    } catch {
    }
    return void 0;
  }
  async function fillFromEntry(tabId, ctx, entry) {
    const meta = await entryMetadata(ctx, entry);
    const fields = fillableFields(meta);
    if (fields.length === 0) {
      throw new ProtocolError(8005 /* OriginNotBound */, "entry has no fillable fields");
    }
    const body = await brokerRequest({
      type: "get_secret",
      entry,
      fields: fields.map((f) => f.name),
      origin: ctx.origin,
      gesture: wireGesture()
    });
    if (body.type !== "get_secret_result") {
      throw new ProtocolError(8004 /* SessionNotEstablished */, "unexpected secret response");
    }
    const values = body.values;
    const usernameField = fields.find((f) => f.role === "username");
    const passwordField = fields.find((f) => f.role === "password");
    const tab = await chrome.tabs.get(tabId);
    if (originOfUrl(tab.url) !== ctx.origin) {
      throw new ProtocolError(8005 /* OriginNotBound */, "tab origin changed since menu opened");
    }
    const msg = {
      type: "fill_values",
      entry,
      username: (usernameField ? values[usernameField.name] : void 0) ?? "",
      password: (passwordField ? values[passwordField.name] : void 0) ?? "",
      origin: ctx.origin,
      action: ctx.action ?? null
    };
    await chrome.tabs.sendMessage(tabId, msg, { frameId: ctx.hostFrameId });
  }
  async function requestSnapshot(tabId, frameId) {
    try {
      const res = await chrome.tabs.sendMessage(tabId, { type: "get_pending_snapshot" }, { frameId });
      return res?.type === "pending_snapshot" ? res.snapshot : null;
    } catch {
      return null;
    }
  }
  async function handleMessage(msg, sender) {
    switch (msg.type) {
      case "get_state":
        return { state };
      case "get_entries": {
        const body = await brokerRequest({ type: "get_entries", origin: msg.origin });
        if (body.type === "entries_result") return { entries: body.entries.slice(0, MAX_ENTRY_LIST) };
        return { entries: [] };
      }
      case "menu_open": {
        const tabId = sender.tab?.id;
        if (tabId === void 0) return { entries: [] };
        const ctx = { mode: msg.mode, hostFrameId: sender.frameId ?? 0, origin: msg.origin };
        if (msg.action) ctx.action = msg.action;
        if (msg.title) ctx.title = msg.title;
        if (msg.username) ctx.username = msg.username;
        menuContexts.set(tabId, ctx);
        if (msg.mode === "capture") return { origin: msg.origin };
        try {
          const body = await brokerRequest({ type: "get_entries", origin: msg.origin });
          if (body.type === "entries_result") {
            ctx.entries = body.entries.slice(0, MAX_ENTRY_LIST);
            return { entries: ctx.entries };
          }
          return { entries: [] };
        } catch (e) {
          return { entries: [], error: errorOf(e) };
        }
      }
      case "menu_close":
        if (sender.tab?.id !== void 0) menuContexts.delete(sender.tab.id);
        return {};
      case "menu_ready": {
        const ctx = sender.tab?.id !== void 0 ? menuContexts.get(sender.tab.id) : void 0;
        if (!ctx) return { mode: "fill", origin: "", entries: [] };
        return {
          mode: ctx.mode,
          origin: ctx.origin,
          action: ctx.action,
          title: ctx.title,
          username: ctx.username,
          entries: ctx.entries ?? []
        };
      }
      case "menu_cross_origin_confirm": {
        consumeGesture(msg.gesture);
        const body = await brokerRequest({ type: "confirm_unbound_origin", origin: msg.origin, gesture: wireGesture() });
        if (body.type !== "origin_confirmed") {
          throw new ProtocolError(8004 /* SessionNotEstablished */, "origin not confirmed by broker");
        }
        return { confirmed: true };
      }
      case "menu_fill": {
        consumeGesture(msg.gesture);
        const ctx = menuContextFor(sender, msg.origin, msg.action);
        const tabId = sender.tab?.id;
        if (tabId === void 0) throw new ProtocolError(8005 /* OriginNotBound */, "no tab context");
        await fillFromEntry(tabId, ctx, msg.entry);
        return { filled: true };
      }
      case "popup_fill": {
        consumeGesture(msg.gesture);
        const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        const tab = tabs[0];
        if (!tab?.id) throw new ProtocolError(8005 /* OriginNotBound */, "no active tab");
        const ctx = { mode: "fill", hostFrameId: 0, origin: msg.origin };
        await fillFromEntry(tab.id, ctx, msg.entry);
        return { filled: true };
      }
      case "menu_capture_accept": {
        consumeGesture(msg.gesture);
        const ctx = menuContextFor(sender, msg.origin);
        const tabId = sender.tab?.id;
        if (tabId === void 0) throw new ProtocolError(8005 /* OriginNotBound */, "no tab context");
        const snapshot = await requestSnapshot(tabId, ctx.hostFrameId);
        if (!snapshot) throw new ProtocolError(8006 /* UserRejected */, "no pending capture snapshot");
        const body = await brokerRequest({
          type: "capture_save",
          origin: snapshot.origin,
          username: snapshot.username,
          password: snapshot.password,
          title: snapshot.title,
          category: "login",
          gesture: wireGesture()
        });
        if (body.type !== "capture_saved") {
          throw new ProtocolError(8004 /* SessionNotEstablished */, "unexpected capture response");
        }
        await chrome.tabs.sendMessage(tabId, { type: "capture_saved" }, { frameId: ctx.hostFrameId });
        return { saved: true, item_id: body.item_id };
      }
      case "pending_snapshot":
        return {};
      case "lock": {
        const body = await brokerRequest({ type: "lock" });
        if (body.type !== "locked") {
          throw new ProtocolError(8004 /* SessionNotEstablished */, "unexpected lock response");
        }
        return { locked: true };
      }
      case "clear_pairing":
        await chrome.storage.local.remove(PAIRING_KEY);
        resetSession();
        return { cleared: true };
      default:
        return {};
    }
  }
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    void handleMessage(msg, sender).then((data) => sendResponse({ ok: true, ...data })).catch((e) => sendResponse({ ok: false, error: errorOf(e) }));
    return true;
  });
  void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" }).catch(() => {
  });
  void chrome.storage.local.get(PAIRING_KEY).then((r) => setState({ paired: Boolean(r[PAIRING_KEY]) }));
  chrome.runtime.onStartup?.addListener(() => {
    void ensureSession().catch(() => {
    });
  });
})();
