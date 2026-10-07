/**
 * Protocol message-set round-trip boundaries (docs/31 §3.3 / §5.2, docs/32 §1.3 G-T).
 *
 * The G-C core 40/40 already round-trips a subset (get_secret / lock / get_entries /
 * get_secret_result / entries_result). This file closes the gap for the FULL
 * `AppMessage` union over the session cipher: every request and response variant must
 * serde + AEAD-encrypt + decrypt byte-roundtrip with all fields intact, including the
 * error code passthrough (8005/8007/8008 semantics) and the designation variants of
 * `entries_result` (unknown kinds tolerated, `other` carries value).
 *
 * These are boundary/negative-path assertions (docs/32 §1.3-9 fill/§3-2 8xxx 语义) —
 * deliberately non-duplicative of the KAT (which pins byte-exact frozen vectors).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { SessionCipher } from "../crypto/e2e";
import {
  PROTOCOL_VERSION,
  b64encode,
  b64decode,
  type AppMessage,
  type EntryInfo,
} from "../protocol";

/** Random per-test session keys — round-trip must hold for any session, not a fixed one. */
function freshSession(): SessionCipher {
  const encKey = crypto.getRandomValues(new Uint8Array(32));
  const macKey = crypto.getRandomValues(new Uint8Array(32));
  return new SessionCipher(encKey, macKey);
}

/** Seal a message and open it back; returns the decrypted body. */
async function roundTrip(session: SessionCipher, msg: AppMessage): Promise<AppMessage> {
  const sealed = await session.seal(msg);
  assert.equal(sealed.type, "e2e");
  assert.equal(sealed.v, PROTOCOL_VERSION);
  // Frame must be base64 of nonce(12)‖ct‖tag(16)‖mac(32) = 12+ct+16+32 bytes.
  const raw = b64decode(sealed.frame);
  const ctLen = raw.length - 12 - 16 - 32;
  assert.ok(ctLen > 0, "frame 须含密文主体");
  const opened = await session.open(sealed);
  return opened.body;
}

test("all AppRequest variants round-trip through the session cipher", async () => {
  const session = freshSession();
  const requests: AppMessage[] = [
    {
      type: "get_secret",
      request_id: 42,
      entry: "demo",
      fields: ["username", "password", "totp"],
      origin: "https://example.com:8443",
      gesture: "b64nonce+timestamp",
    },
    {
      type: "capture_save",
      origin: "https://example.com",
      username: "demo-user",
      password: "s3cr3t",
      title: "GitHub",
      category: "login",
      gesture: "g1",
    },
    { type: "confirm_unbound_origin", origin: "https://example.com", gesture: "g2" },
    { type: "lock" },
    { type: "get_entries", origin: "https://example.com" },
  ];
  for (const req of requests) {
    assert.deepEqual(await roundTrip(session, req), req, `round-trip 失败: ${req.type}`);
  }
});

test("all AppResponse variants round-trip; error code passthrough intact (8005/8007/8008)", async () => {
  const session = freshSession();
  const responses: AppMessage[] = [
    { type: "get_secret_result", request_id: 42, values: { username: "u", password: "p" } },
    { type: "capture_saved", item_id: "item-9" },
    { type: "origin_confirmed" },
    { type: "locked" },
    { type: "broker_locked" },
    // 8xxx 语义穿透（docs/03 §12 / docs/32 §3-2）：code 原样往返，message 文案不裁剪。
    { type: "error", code: 8005, message: "该网站未授权访问此保险库" },
    { type: "error", code: 8007, message: "操作手势已过期或无效" },
    { type: "error", code: 8008, message: "未能确认表单提交成功" },
  ];
  for (const resp of responses) {
    assert.deepEqual(await roundTrip(session, resp), resp, `round-trip 失败: ${resp.type}`);
  }
});

test("entries_result round-trips designation variants, including unknown kinds and other{value}", async () => {
  const session = freshSession();
  // EntryInfo 全部 designation 形态（docs/31 §5.2 r0.4 契约）：单元 kind + other{value}
  // + 未知 kind（扩展容忍未知——fill 角色只从已知 kind 推，fillable.test.ts 覆盖）。
  const entries: EntryInfo[] = [
    {
      entry: "e1",
      title: "GitHub",
      category: "login",
      fields: [
        { name: "username", designation: { kind: "username" } },
        { name: "password", designation: { kind: "password" } },
      ],
    },
    {
      entry: "e2",
      title: "API Key",
      category: "api_credential",
      fields: [{ name: "key", designation: { kind: "other", value: "key" } }],
    },
    {
      entry: "e3",
      title: "TOTP",
      category: "login",
      fields: [{ name: "seed", designation: { kind: "totp" } }, { name: "misc", designation: { kind: "unknown_future_kind" } }],
    },
  ];
  const body = await roundTrip(session, { type: "entries_result", entries });
  assert.equal(body.type, "entries_result");
  assert.deepEqual(body.entries, entries);
});

test("empty / single-field get_secret_result and unicode values round-trip (边界)", async () => {
  const session = freshSession();
  const emptyValues = { type: "get_secret_result" as const, request_id: 1, values: {} };
  assert.deepEqual(await roundTrip(session, emptyValues), emptyValues);

  const unicode = {
    type: "get_secret_result" as const,
    request_id: 2,
    values: { username: "用户@例え", password: "パスワード🔑", note: "\u{1F4A9}" },
  };
  assert.deepEqual(await roundTrip(session, unicode), unicode);
});
