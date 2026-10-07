/**
 * Fill last-hop authorization tests (Wave-4 HIGH-1 hardening, G-R).
 *
 * The plaintext write must land ONLY on the field elements captured at the user's
 * focusin — never on fields re-found at write time (a page could have prepended a decoy
 * `<input type=password>` after the menu opened, or navigated the frame). Fail-closed:
 * any doubt → reject, no fill.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { authorizeFill, type CapturedFillTarget } from "../content/fill_auth";
import { sameOriginUrl } from "../content/dom";

// DOM-free element stand-ins: identity is what matters, not the concrete node type.
const realUsername = { tag: "input", name: "username" };
const realPassword = { tag: "input", type: "password" };
const decoy = { tag: "input", type: "password", injected: "after-menu-open" };

function goodTarget(overrides: Partial<CapturedFillTarget> = {}): CapturedFillTarget {
  return {
    usernameEl: realUsername,
    passwordEl: realPassword,
    usernameConnected: true,
    passwordConnected: true,
    sameOriginAction: true,
    ...overrides,
  };
}

test("decoy: an input injected after menu-open is never a write target (stored refs only)", () => {
  // Stored refs captured at focusin, BEFORE the page injects a decoy. A re-find would now
  // return the decoy as passwords[0] — the authorization must still target the stored ref.
  const auth = authorizeFill({
    approvedOrigin: "https://example.com",
    currentOrigin: "https://example.com",
    target: goodTarget(),
  });
  assert.equal(auth.ok, true);
  assert.equal(auth.targets?.passwordEl, realPassword);
  assert.notEqual(auth.targets?.passwordEl, decoy);
});

test("decoy-swap: page replaces the real password field → target_disconnected, no fill", () => {
  const auth = authorizeFill({
    approvedOrigin: "https://example.com",
    currentOrigin: "https://example.com",
    target: goodTarget({ passwordConnected: false }),
  });
  assert.deepEqual(auth, { ok: false, reason: "target_disconnected" });
});

test("navigation: document origin drifted from the approved origin → reject, no fill", () => {
  const auth = authorizeFill({
    approvedOrigin: "https://example.com",
    currentOrigin: "https://attacker.example.net",
    target: goodTarget(),
  });
  assert.deepEqual(auth, { ok: false, reason: "origin_mismatch" });
});

test("fresh document / no captured target (frame navigated, script re-injected) → no_target", () => {
  const auth = authorizeFill({
    approvedOrigin: "https://example.com",
    currentOrigin: "https://example.com",
    target: null,
  });
  assert.deepEqual(auth, { ok: false, reason: "no_target" });
});

test("cross-origin form action: captured form now submits elsewhere → cross_origin_action", () => {
  const auth = authorizeFill({
    approvedOrigin: "https://example.com",
    currentOrigin: "https://example.com",
    target: goodTarget({ sameOriginAction: false }),
  });
  assert.deepEqual(auth, { ok: false, reason: "cross_origin_action" });
});

test("username field disconnected but password intact → fill password only", () => {
  const auth = authorizeFill({
    approvedOrigin: "https://example.com",
    currentOrigin: "https://example.com",
    target: goodTarget({ usernameConnected: false }),
  });
  assert.equal(auth.ok, true);
  assert.equal(auth.targets?.usernameEl, null);
  assert.equal(auth.targets?.passwordEl, realPassword);
});

test("all checks pass → authorize with the captured refs", () => {
  const auth = authorizeFill({
    approvedOrigin: "https://example.com",
    currentOrigin: "https://example.com",
    target: goodTarget(),
  });
  assert.deepEqual(auth, {
    ok: true,
    targets: { usernameEl: realUsername, passwordEl: realPassword },
  });
});

// --- sameOriginUrl (the URL-level gate behind isSameOriginAction, dom.ts) ------------

test("sameOriginUrl: same-origin action accepted, cross-origin/opaque rejected", () => {
  const origin = "https://example.com";
  assert.equal(sameOriginUrl("https://example.com/login", origin), true);
  assert.equal(sameOriginUrl("https://example.com", origin), true);
  assert.equal(sameOriginUrl("https://evil.example.net/x", origin), false);
  assert.equal(sameOriginUrl("https://example.com:8443/x", origin), false);
  assert.equal(sameOriginUrl("http://example.com/x", origin), false);
  assert.equal(sameOriginUrl(null, origin), false);
  assert.equal(sameOriginUrl("not a url", origin), false);
});
