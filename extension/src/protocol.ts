/**
 * E2E protocol contract (docs/31 §3.3, D-6) — canonical = G-A/cf-browser Rust
 * (core/cf-browser/src/{e2e.rs,protocol.rs}, tests/e2e_kat.rs frozen vectors;
 * lead ruling 2026-10-07). This module mirrors the Rust serde shapes byte-for-byte
 * (type tags snake_case, hex wire format, no request_id).
 *
 * Handshake (IKpsk2 style; host is a blind transport):
 *   msg1 Init{type:"init", version, e_init: hex}           extension → broker
 *   msg2 Response{type:"response", version, e_resp: hex, pk_b: hex, signature: hex}
 *                                                          broker → extension
 *        signature = ECDSA-P256-SHA256 over e_init_pub‖e_resp_pub (P1363 r‖s, 64 B)
 *   msg3 Confirm{type:"confirm", version, p: hex}          extension → broker
 *        p = HMAC-SHA256(PSK, okm)
 *
 * Session key (es term is REQUIRED — lead ruling r0.2, docs/31 §3.3):
 *   ee = ECDH(e_ext_eph, e_broker_eph);  es = ECDH(e_ext_eph, pk_b)
 *   okm = HKDF-SHA256(ikm = ee‖es, salt = e_init_pub‖e_resp_pub,
 *                     info = "cf/browser/session/v1", L = 64)
 *   enc_key = okm[0:32], mac_key = okm[32:64]
 *   (the "双方 nonce" = the two ephemeral public keys, SEC1 65 B — no independent
 *   random nonce fields; docs/31 §3.3 r0.2 note.)
 *
 * Per-message frame (docs/31 §3.3):
 *   plaintext = seq(8, LE) ‖ payload_json
 *   ct_tag    = AES-256-GCM(enc_key, nonce12, plaintext, aad="")
 *   mac       = HMAC-SHA256(mac_key, nonce ‖ ct_tag)
 *   frame     = nonce(12) ‖ ct ‖ tag(16) ‖ mac(32)   (b64 for transport)
 *   seq monotonic, reject seq ≤ max seen (T-9).
 *
 * Application messages mirror AppRequest/AppResponse in protocol.rs (untagged over
 * tagged enums, snake_case type tags). `get_secret` carries `request_id` (u64, JS
 * Number-safe < 2^53) echoed by `get_secret_result`; the broker is the sole responder
 * and the extension the sole initiator, so the other request types are correlated FIFO.
 */

export const PROTOCOL_VERSION = 1;

// --- constants (mirror e2e.rs / protocol.rs) ----------------------------------------

/** Session-key KDF info literal (protocol.rs SESSION_KDF_INFO). */
export const SESSION_KDF_INFO = "cf/browser/session/v1";

/** SEC1 uncompressed public key length (0x04 ‖ X ‖ Y). */
export const SEC1_LEN = 65;

/** AES-256-GCM nonce length (96-bit). */
export const GCM_NONCE_LEN = 12;

/** AES-GCM auth tag length. */
export const GCM_TAG_LEN = 16;

/** Frame MAC length (HMAC-SHA256 output). */
export const FRAME_MAC_LEN = 32;

/** Session key total length (enc 32 + mac 32). */
export const SESSION_KEY_LEN = 64;

/** P1363 signature length (r ‖ s, 32 + 32). */
export const ECDSA_SIG_LEN = 64;

/** seq length inside the frame plaintext (u64 LE). */
export const SEQ_LEN = 8;

/** Gesture TTL (docs/31 §6.1 / D-7). */
export const GESTURE_TTL_MS = 30_000;
export const GESTURE_NONCE_LEN = 16;

/** Error codes, browser domain 8xxx (docs/31a 附). */
export enum ErrCode {
  HostRejected = 8001, // host refuses: parent process is not a signed browser (fail-closed)
  HostUnverified = 8002, // broker refuses: peer host not verified (PID/signature/challenge)
  BrokerUnavailable = 8003, // broker not running / App not enabled / locked
  SessionNotEstablished = 8004, // E2E handshake failed (auth or derivation)
  OriginNotBound = 8005, // no origin binding matches the request origin
  UserRejected = 8006, // user declined an explicit confirmation
  GestureExpired = 8007, // gesture replayed or past TTL
  CaptureUnverified = 8008, // submit not verified as successful (no save)
}

export class ProtocolError extends Error {
  constructor(
    public readonly code: ErrCode,
    message: string,
  ) {
    super(message);
    this.name = "ProtocolError";
  }
}

// --- codecs (browser + Node; atob/btoa are globals in Node >= 16) -------------------

export function encodeUtf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function decodeUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function b64encode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** base64url without padding (JWK x/y/d, RFC 7515). */
export function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Lowercase hex (Rust e2e::to_hex line format). */
export function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new ProtocolError(ErrCode.SessionNotEstablished, "odd hex length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// --- handshake messages (serde snake_case, hex) --------------------------------------

/** msg1: extension → broker. `e_init` = initiator ephemeral pub (SEC1 hex). */
export interface InitFrame {
  type: "init";
  version: number;
  e_init: string;
}

/** msg2: broker → extension. `signature` = ECDSA-P256 over e_init_pub‖e_resp_pub. */
export interface ResponseFrame {
  type: "response";
  version: number;
  e_resp: string;
  pk_b: string;
  signature: string;
}

/** msg3: extension → broker. `p` = HMAC-SHA256(PSK, okm). */
export interface ConfirmFrame {
  type: "confirm";
  version: number;
  p: string;
}

export type HandshakeMessage = InitFrame | ResponseFrame | ConfirmFrame;

// --- session frame (b64 of nonce‖ct‖tag‖mac) ------------------------------------------

export interface SessionFrame {
  type: "e2e";
  v: number;
  /** base64 of the raw frame bytes: nonce(12) ‖ ct ‖ tag(16) ‖ mac(32). */
  frame: string;
}

// --- application messages (mirror AppRequest/AppResponse serde) ----------------------

/**
 * cf-domain `Designation` wire form (cf-domain/src/field.rs): adjacently-tagged
 * `{"kind": ..., "value"?: ...}` (`#[serde(rename_all="snake_case", tag="kind",
 * content="value")]`). Known unit kinds: username / password / totp / notes_plain
 * (serde snake_case of `NotesPlain`; the 1P import/export spelling is "notesPlain") /
 * email; `Other(String)` → `{"kind":"other","value":...}`. The extension tolerates
 * unknown kinds — fill roles come from known kinds only, never guessed from names.
 */
export interface Designation {
  kind: string;
  value?: string;
}

/** One fillable field reference inside `EntryInfo` (protocol.rs `EntryFieldRef`). */
export interface EntryFieldRef {
  /** Field name, passed back verbatim as a `get_secret.fields` element. */
  name: string;
  /** Semantic designation — the fill-role source (not guessed from the name). */
  designation: Designation;
}

/** Menu entry metadata (protocol.rs `EntryInfo` — non-secret). */
export interface EntryInfo {
  /** Item identifier, echoed verbatim by `get_secret.entry`. */
  entry: string;
  /** Display title. */
  title: string;
  /** ItemCategory snake_case (e.g. "login"). */
  category: string;
  /** Requestable field references (a subset of `get_secret.fields`). */
  fields: EntryFieldRef[];
}

/**
 * extension → broker (AppRequest, protocol.rs — snake_case type tags).
 * `request_id` on get_secret: u64 echoed by get_secret_result (JS Number-safe < 2^53).
 */
export type AppRequest =
  | {
      type: "get_secret";
      /** u64 (JS Number-safe), echoed by get_secret_result. */
      request_id: number;
      entry: string;
      /** Item field names, one gesture covers the whole fill (D-7 adopted by G-A). */
      fields: string[];
      origin: string;
      gesture: string;
    }
  | {
      type: "capture_save";
      origin: string;
      username: string;
      password: string;
      title: string;
      /** ItemCategory snake_case (e.g. "login"). */
      category: string;
      gesture: string;
    }
  | { type: "confirm_unbound_origin"; origin: string; gesture: string }
  | { type: "lock" }
  | { type: "get_entries"; origin: string };

/** broker → extension (AppResponse, protocol.rs). */
export type AppResponse =
  | { type: "get_secret_result"; request_id: number; values: Record<string, string> }
  | { type: "capture_saved"; item_id: string }
  | { type: "origin_confirmed" }
  | { type: "locked" }
  | { type: "broker_locked" }
  | { type: "error"; code: number; message: string }
  | { type: "entries_result"; entries: EntryInfo[] };

/** Application message union (AppMessage, untagged over the two tagged enums). */
export type AppMessage = AppRequest | AppResponse;

// --- gesture (docs/31 §6.1, D-7) -----------------------------------------------------

/**
 * A gesture is generated by the extension UI at the moment of a real user click and is
 * bound to that UI event. Format: b64(16-byte random nonce ‖ 8-byte big-endian issuedAtMs).
 * Single-use, TTL 30 s; enforced by the background replay cache and (independently) by
 * the broker (8007 on expiry/replay).
 */
export interface ParsedGesture {
  nonce: Uint8Array;
  issuedAtMs: number;
}

export function makeGesture(nowMs: number = Date.now()): string {
  const nonce = crypto.getRandomValues(new Uint8Array(GESTURE_NONCE_LEN));
  const out = new Uint8Array(GESTURE_NONCE_LEN + 8);
  out.set(nonce, 0);
  const dv = new DataView(out.buffer);
  dv.setBigUint64(GESTURE_NONCE_LEN, BigInt(nowMs), false);
  return b64encode(out);
}

export function parseGesture(gesture: string): ParsedGesture | null {
  if (!gesture || typeof gesture !== "string") return null;
  let bytes: Uint8Array;
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

/** Age check: is this gesture within TTL of now? */
export function gestureWithinTtl(gesture: string, nowMs: number = Date.now()): boolean {
  const p = parseGesture(gesture);
  if (!p) return false;
  return p.issuedAtMs <= nowMs && nowMs - p.issuedAtMs <= GESTURE_TTL_MS;
}
