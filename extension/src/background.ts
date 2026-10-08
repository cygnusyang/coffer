/**
 * Background service worker (MV3) — docs/31 §2.4 (state machine), §3.3 (E2E), §5 (flows),
 * §7 T-1/T-2/T-6/T-7.
 *
 * Responsibilities:
 *   - native messaging port to `coffer browser-agent` (host) — the host is a blind relay;
 *   - E2E client session (IKpsk2-style, see crypto/e2e.ts); the session key lives in module
 *     memory ONLY. MV3 SW termination kills it — the next request re-handshakes (docs/31 §2.4,
 *     a security positive, not a defect);
 *   - extension state machine: idle → connecting → paired / awaiting_unlock;
 *   - gesture validation (TTL 30 s, single-use replay cache) — docs/31 §6.1 / D-7;
 *   - message routing between popup / inline menu / content scripts and the broker.
 *
 * Non-sensitive reconnect state ("paired") may live in chrome.storage.session; pairing
 * material (PSK + pinned broker public key) lives in chrome.storage.local (docs/31 §3.3).
 *
 * Wire correlation: `get_secret` carries a `request_id` (u64, echoed by get_secret_result,
 * contract v1); the broker is the sole responder so the remaining request types are
 * correlated FIFO. Requests are serialized per flow (each awaits its response before the
 * next), so at most one is in flight.
 */
import { E2EClient, type PairingMaterial } from "./crypto/e2e";
import {
  ErrCode,
  ProtocolError,
  GESTURE_TTL_MS,
  makeGesture,
  b64encode,
  b64decode,
  parseGesture,
  gestureWithinTtl,
  type ResponseFrame,
  type SessionFrame,
  type AppRequest,
  type AppResponse,
  type EntryInfo,
} from "./protocol";
import { fillableFields } from "./fillable";
import { originOfUrl } from "./origin";
import type {
  SessionState,
  PendingSnapshotData,
  UiToBackgroundMessage,
  ContentToBackgroundMessage,
  MenuToBackgroundMessage,
  BackgroundToContentMessage,
} from "./messages";

const NATIVE_HOST = "com.coffer.browser";
const PAIRING_KEY = "coffer_pairing";
const RETRY_DELAY_MS = 5_000;
const MAX_RETRIES = 3;
const MAX_ENTRY_LIST = 50;

interface MenuContext {
  mode: "fill" | "capture";
  hostFrameId: number;
  origin: string;
  action?: string;
  title?: string;
  username?: string;
  entries?: EntryInfo[];
}

interface ResponseError {
  code: number;
  message: string;
}

/** One in-flight broker request (single-flight — FIFO correlation; get_secret echoed by
 * request_id). */
interface PendingWaiter {
  resolve: (b: AppResponse) => void;
  reject: (e: unknown) => void;
}

/**
 * Broker-bound request as built by callers: `get_secret`'s `request_id` is assigned by
 * the background just before sealing (on-wire only, u64 JS Number-safe < 2^53).
 */
type WireRequest =
  | Exclude<AppRequest, { type: "get_secret" }>
  | Omit<Extract<AppRequest, { type: "get_secret" }>, "request_id">;

let port: chrome.runtime.Port | null = null;
let session: E2EClient | null = null;
let sessionReady: Promise<E2EClient> | null = null;
let handshakeWait: { resolve: () => void; reject: (e: unknown) => void } | null = null;
let state: SessionState = { status: "idle", paired: false };
let retryTimer: number | null = null;
let retries = 0;

const gestureSeen = new Map<string, number>();
const pendingQueue: PendingWaiter[] = [];
const menuContexts = new Map<number, MenuContext>();

let nextRequestId = 1; // get_secret request_id (u64, JS Number-safe), echoed by the broker
let lastSentRequestId: number | null = null;

// --- state ---------------------------------------------------------------------------

function setState(next: Partial<SessionState>): void {
  state = { ...state, ...next };
  void chrome.runtime.sendMessage({ type: "state", state }).catch(() => {});
}

function errorOf(e: unknown): ResponseError {
  if (e instanceof ProtocolError) return { code: e.code, message: e.message };
  if (e instanceof Error) return { code: ErrCode.SessionNotEstablished, message: e.message };
  return { code: ErrCode.SessionNotEstablished, message: String(e) };
}

// --- pairing storage -----------------------------------------------------------------

async function loadPairing(): Promise<PairingMaterial | null> {
  const raw = (await chrome.storage.local.get(PAIRING_KEY))[PAIRING_KEY] as
    | { brokerPublicKeyRaw: string; psk: string }
    | undefined;
  if (!raw || typeof raw.brokerPublicKeyRaw !== "string" || typeof raw.psk !== "string") return null;
  try {
    return { brokerPublicKeyRaw: b64decode(raw.brokerPublicKeyRaw), psk: b64decode(raw.psk) };
  } catch {
    return null;
  }
}

// --- native port + E2E handshake ------------------------------------------------------

function connect(): void {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST);
  } catch {
    failHandshake(new ProtocolError(ErrCode.BrokerUnavailable, "native messaging host not found"));
    return;
  }
  port.onMessage.addListener(onPortMessage);
  port.onDisconnect.addListener(onPortDisconnect);
}

function onPortDisconnect(): void {
  const wasPaired = state.paired;
  port = null;
  session = null;
  sessionReady = null;
  lastSentRequestId = null;
  if (handshakeWait) {
    handshakeWait.reject(new ProtocolError(ErrCode.BrokerUnavailable, "native port closed"));
    handshakeWait = null;
  }
  const q = pendingQueue;
  pendingQueue.length = 0;
  for (const p of q) p.reject(new ProtocolError(ErrCode.BrokerUnavailable, "native port closed"));
  setState({ status: wasPaired ? "awaiting_unlock" : "idle", paired: wasPaired });
  if (wasPaired) scheduleRetry();
}

async function performHandshake(): Promise<E2EClient> {
  const pairing = await loadPairing();
  if (!pairing) {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "not paired — open Coffer and enable browser integration");
  }
  const client = new E2EClient(pairing);
  session = client;
  if (!port) connect();
  if (!port) throw new ProtocolError(ErrCode.BrokerUnavailable, "native port unavailable");
  const init = await client.start(); // msg1 Init (SEC1 hex)
  port.postMessage(init);
  setState({ status: "connecting", paired: true });
  await waitForPaired(); // resolves when msg2 Response → msg3 Confirm completes
  return client;
}

function waitForPaired(): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    handshakeWait = { resolve, reject };
  });
}

async function ensureSession(): Promise<E2EClient> {
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

function failHandshake(e: unknown): void {
  if (handshakeWait) {
    handshakeWait.reject(e);
    handshakeWait = null;
  }
  session = null;
  sessionReady = null;
}

async function onPortMessage(raw: unknown): Promise<void> {
  if (!raw || typeof raw !== "object") return;
  const frame = raw as Record<string, unknown>;

  switch (frame.type) {
    case "response": {
      // msg2 Response → verify pin/signature, derive keys, reply msg3 Confirm.
      if (!session) return;
      try {
        const { confirm } = await session.processReply(frame as unknown as ResponseFrame);
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
      // Broker vault locked (host relayed it before any E2E session) — prompt to unlock.
      failHandshake(new ProtocolError(ErrCode.BrokerUnavailable, "broker locked"));
      setState({ status: "awaiting_unlock", paired: state.paired });
      return;
    }
    case "e2e": {
      if (!session) return;
      try {
        const opened = await session.open(frame as unknown as SessionFrame);
        // Broker is the responder: extension-initiated request → broker reply (AppResponse).
        handleSessionBody(opened.body as AppResponse);
      } catch (e) {
        handleSessionBroken(e);
      }
      return;
    }
    default:
      return;
  }
}

function handleSessionBody(body: AppResponse): void {
  if (!body || typeof body !== "object") return;
  if (body.type === "broker_locked") {
    // Unsolicited notification: broker vault locked while the session was live. Any
    // in-flight request failed; surface "awaiting_unlock" (docs/31 §2.4).
    const waiters = pendingQueue.splice(0);
    for (const w of waiters) w.reject(new ProtocolError(ErrCode.BrokerUnavailable, "broker locked"));
    lastSentRequestId = null;
    setState({ status: "awaiting_unlock", paired: state.paired });
    return;
  }
  if (body.type === "get_secret_result") {
    // Echo must match the last sent get_secret request_id; a stray/mismatched echo means
    // the channel is corrupt — fail closed and reconnect.
    if (lastSentRequestId === null || body.request_id !== lastSentRequestId) {
      handleSessionBroken(new ProtocolError(ErrCode.SessionNotEstablished, "request_id echo mismatch"));
      return;
    }
    lastSentRequestId = null;
  }
  // Single-flight FIFO: the one outstanding request gets this response (error included —
  // error carries no request_id in the contract).
  const waiter = pendingQueue.shift();
  if (!waiter) return;
  if (body.type === "error") {
    waiter.reject(new ProtocolError(body.code ?? ErrCode.SessionNotEstablished, body.message ?? "broker error"));
  } else {
    waiter.resolve(body);
  }
}

function handleSessionBroken(e: unknown): void {
  // AEAD/session failure: the key is suspect — tear down and reconnect fresh.
  session = null;
  sessionReady = null;
  if (port) {
    try {
      port.disconnect();
    } catch {
      /* noop */
    }
    port = null;
  }
  setState({ status: "idle", paired: state.paired });
  scheduleRetry();
  void e;
}

function scheduleRetry(): void {
  if (retryTimer !== null || retries >= MAX_RETRIES) return;
  retries += 1;
  retryTimer = globalThis.setTimeout(() => {
    retryTimer = null;
    if (port) return;
    void ensureSession().catch(() => {});
  }, RETRY_DELAY_MS);
}

function resetSession(): void {
  session = null;
  sessionReady = null;
  if (port) {
    try {
      port.disconnect();
    } catch {
      /* noop */
    }
  }
  port = null;
  retries = 0;
  setState({ status: "idle", paired: false });
}

// --- broker request/response over E2E --------------------------------------------------

async function brokerRequest(req: WireRequest): Promise<AppResponse> {
  const client = await ensureSession();
  if (!port) {
    throw new ProtocolError(ErrCode.BrokerUnavailable, "native port unavailable");
  }
  let wire: AppRequest;
  if (req.type === "get_secret") {
    wire = { ...req, request_id: nextRequestId++ };
    lastSentRequestId = wire.request_id;
  } else {
    wire = req;
    lastSentRequestId = null; // no get_secret outstanding — clear the echo expectation
  }
  const envelope = await client.seal(wire);
  const waiter = new Promise<AppResponse>((resolve, reject) => {
    pendingQueue.push({ resolve, reject });
  });
  port.postMessage(envelope);
  return waiter;
}

// --- gesture (docs/31 §6.1 / D-7) ------------------------------------------------------

/** Validate a UI-minted gesture (single-use, TTL); rejects replay/expiry with 8007. */
function consumeGesture(gesture: string): void {
  if (!gestureWithinTtl(gesture)) {
    throw new ProtocolError(ErrCode.GestureExpired, "gesture expired or invalid");
  }
  const parsed = parseGesture(gesture);
  if (!parsed) throw new ProtocolError(ErrCode.GestureExpired, "gesture invalid");
  const nonce = b64encode(parsed.nonce);
  const now = Date.now();
  for (const [k, ts] of gestureSeen) {
    if (now - ts > GESTURE_TTL_MS) gestureSeen.delete(k);
  }
  if (gestureSeen.has(nonce)) {
    throw new ProtocolError(ErrCode.GestureExpired, "gesture already used (replay)");
  }
  gestureSeen.set(nonce, now);
}

/**
 * Mint a fresh single-use wire gesture for a broker-bound request. Called only while
 * processing a message that a real user click produced (popup / inline menu are trusted
 * extension pages page JS cannot trigger), so the click authorization carries over; the
 * UI gesture itself was already validated by consumeGesture().
 */
function wireGesture(): string {
  return makeGesture();
}

// --- menu contexts --------------------------------------------------------------------

function menuContextFor(sender: chrome.runtime.MessageSender, origin: string, action?: string): MenuContext {
  const tabId = sender.tab?.id;
  const existing = tabId !== undefined ? menuContexts.get(tabId) : undefined;
  if (existing && existing.origin === origin) return existing;
  const fresh: MenuContext = { mode: "fill", hostFrameId: sender.frameId ?? 0, origin, action };
  if (tabId !== undefined) menuContexts.set(tabId, fresh);
  return fresh;
}

// --- fill helpers ---------------------------------------------------------------------

async function entryMetadata(ctx: MenuContext, entry: string): Promise<EntryInfo | undefined> {
  if (ctx.entries) return ctx.entries.find((e) => e.entry === entry);
  // Context may have been lost to a SW restart while the menu stayed open — refetch.
  try {
    const body = await brokerRequest({ type: "get_entries", origin: ctx.origin });
    if (body.type === "entries_result") {
      const list = body.entries.slice(0, MAX_ENTRY_LIST);
      ctx.entries = list;
      return list.find((e) => e.entry === entry);
    }
  } catch {
    /* fall through to no-fields error */
  }
  return undefined;
}

/**
 * Fill a login: one multi-field get_secret (fields[] declared at once, one gesture = one
 * fill — D-7, adopted by G-A contract v1), then write the returned values to the DOM.
 */
async function fillFromEntry(tabId: number, ctx: MenuContext, entry: string): Promise<void> {
  const meta = await entryMetadata(ctx, entry);
  const fields = fillableFields(meta);
  if (fields.length === 0) {
    throw new ProtocolError(ErrCode.OriginNotBound, "entry has no fillable fields");
  }
  const body = await brokerRequest({
    type: "get_secret",
    entry,
    fields: fields.map((f) => f.name),
    origin: ctx.origin,
    gesture: wireGesture(),
  });
  if (body.type !== "get_secret_result") {
    throw new ProtocolError(ErrCode.SessionNotEstablished, "unexpected secret response");
  }
  const values = body.values; // keys = requested field names (contract v1)
  const usernameField = fields.find((f) => f.role === "username");
  const passwordField = fields.find((f) => f.role === "password");
  // HIGH-1 (G-R): re-verify the tab URL still matches the approved origin before the
  // plaintext is sent to the frame — the tab could have drifted (navigation / user
  // switch) since the menu opened. Fail-closed: unverifiable URL → reject.
  const tab = await chrome.tabs.get(tabId);
  if (originOfUrl(tab.url) !== ctx.origin) {
    throw new ProtocolError(ErrCode.OriginNotBound, "tab origin changed since menu opened");
  }
  const msg: BackgroundToContentMessage = {
    type: "fill_values",
    entry,
    username: (usernameField ? values[usernameField.name] : undefined) ?? "",
    password: (passwordField ? values[passwordField.name] : undefined) ?? "",
    origin: ctx.origin,
    action: ctx.action ?? null,
  };
  await chrome.tabs.sendMessage(tabId, msg, { frameId: ctx.hostFrameId });
}

async function requestSnapshot(tabId: number, frameId: number): Promise<PendingSnapshotData | null> {
  try {
    const res = (await chrome.tabs.sendMessage(tabId, { type: "get_pending_snapshot" }, { frameId })) as
      | { type: "pending_snapshot"; snapshot: PendingSnapshotData | null }
      | undefined;
    return res?.type === "pending_snapshot" ? res.snapshot : null;
  } catch {
    return null;
  }
}

// --- message dispatch -----------------------------------------------------------------

async function handleMessage(
  msg: UiToBackgroundMessage | ContentToBackgroundMessage | MenuToBackgroundMessage,
  sender: chrome.runtime.MessageSender,
): Promise<Record<string, unknown>> {
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
      if (tabId === undefined) return { entries: [] };
      const ctx: MenuContext = { mode: msg.mode, hostFrameId: sender.frameId ?? 0, origin: msg.origin };
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
      if (sender.tab?.id !== undefined) menuContexts.delete(sender.tab.id);
      return {};

    case "menu_ready": {
      const ctx = sender.tab?.id !== undefined ? menuContexts.get(sender.tab.id) : undefined;
      if (!ctx) return { mode: "fill", origin: "", entries: [] };
      return {
        mode: ctx.mode,
        origin: ctx.origin,
        action: ctx.action,
        title: ctx.title,
        username: ctx.username,
        entries: ctx.entries ?? [],
      };
    }

    case "menu_cross_origin_confirm": {
      // User explicitly approved filling a form whose action targets another origin
      // (docs/31 §5.2) — broker records the approval, then the menu retries the fill.
      consumeGesture(msg.gesture);
      const body = await brokerRequest({
        type: "confirm_unbound_origin",
        entry: msg.entry,
        origin: msg.origin,
        gesture: wireGesture(),
      });
      if (body.type !== "origin_confirmed") {
        throw new ProtocolError(ErrCode.SessionNotEstablished, "origin not confirmed by broker");
      }
      return { confirmed: true };
    }

    case "menu_fill": {
      consumeGesture(msg.gesture);
      const ctx = menuContextFor(sender, msg.origin, msg.action);
      const tabId = sender.tab?.id;
      if (tabId === undefined) throw new ProtocolError(ErrCode.OriginNotBound, "no tab context");
      await fillFromEntry(tabId, ctx, msg.entry);
      return { filled: true };
    }

    case "popup_fill": {
      consumeGesture(msg.gesture);
      const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      const tab = tabs[0];
      if (!tab?.id) throw new ProtocolError(ErrCode.OriginNotBound, "no active tab");
      // Popup fill targets the top frame (login forms are overwhelmingly top-level; the
      // inline menu covers per-frame fill).
      const ctx: MenuContext = { mode: "fill", hostFrameId: 0, origin: msg.origin };
      await fillFromEntry(tab.id, ctx, msg.entry);
      return { filled: true };
    }

    case "menu_capture_accept": {
      consumeGesture(msg.gesture);
      const ctx = menuContextFor(sender, msg.origin);
      const tabId = sender.tab?.id;
      if (tabId === undefined) throw new ProtocolError(ErrCode.OriginNotBound, "no tab context");
      const snapshot = await requestSnapshot(tabId, ctx.hostFrameId);
      if (!snapshot) throw new ProtocolError(ErrCode.UserRejected, "no pending capture snapshot");
      const body = await brokerRequest({
        type: "capture_save",
        origin: snapshot.origin,
        username: snapshot.username,
        password: snapshot.password,
        title: snapshot.title,
        category: "login",
        gesture: wireGesture(),
      });
      if (body.type !== "capture_saved") {
        throw new ProtocolError(ErrCode.SessionNotEstablished, "unexpected capture response");
      }
      await chrome.tabs.sendMessage(tabId, { type: "capture_saved" }, { frameId: ctx.hostFrameId });
      return { saved: true, item_id: body.item_id };
    }

    case "pending_snapshot":
      // Content script replies to tabs.sendMessage via sendResponse; this case is unreachable.
      return {};

    case "lock": {
      const body = await brokerRequest({ type: "lock" });
      if (body.type !== "locked") {
        throw new ProtocolError(ErrCode.SessionNotEstablished, "unexpected lock response");
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
  void handleMessage(msg as UiToBackgroundMessage | ContentToBackgroundMessage | MenuToBackgroundMessage, sender)
    .then((data) => sendResponse({ ok: true, ...data }))
    .catch((e) => sendResponse({ ok: false, error: errorOf(e) }));
  return true; // async response
});

// --- startup --------------------------------------------------------------------------

// Content scripts (untrusted contexts) need memory-only chrome.storage.session access.
void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" }).catch(() => {});
void chrome.storage.local.get(PAIRING_KEY).then((r) => setState({ paired: Boolean(r[PAIRING_KEY]) }));

chrome.runtime.onStartup?.addListener(() => {
  void ensureSession().catch(() => {});
});
