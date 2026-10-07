/**
 * Unit tests for fill-role derivation (`src/fillable.ts`).
 *
 * Fill roles come exclusively from the broker's `Designation.kind` (cf-domain
 * `Designation`, adjacently-tagged) — the extension must NOT guess from field names
 * ("pass"/"密码"/"code" would be wrong). Unknown kinds (totp/notes_plain/other/...)
 * are simply not fillable by the current username+password DOM fill.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fillableFields, type FillableField } from "../fillable";
import type { EntryInfo, EntryFieldRef } from "../protocol";

function entry(fields: EntryFieldRef[]): EntryInfo {
  return { entry: "e1", title: "GitHub", category: "login", fields };
}

function ref(name: string, kind: string, value?: string): EntryFieldRef {
  return value === undefined ? { name, designation: { kind } } : { name, designation: { kind, value } };
}

function roles(fields: FillableField[]): string[] {
  return fields.map((f) => `${f.role}:${f.name}`);
}

test("fillable: username+password from designation kinds, username first", () => {
  const e = entry([ref("pw", "password"), ref("login", "username")]);
  assert.deepEqual(roles(fillableFields(e)), ["username:login", "password:pw"]);
});

test("fillable: email designation fills the username role", () => {
  const e = entry([ref("email", "email"), ref("pw", "password")]);
  assert.deepEqual(roles(fillableFields(e)), ["username:email", "password:pw"]);
});

test("fillable: unknown kinds (totp/notes_plain/other/...) are not fillable", () => {
  const e = entry([
    ref("seed", "totp"),
    ref("note", "notes_plain"),
    ref("misc", "other", "custom"),
    ref("unrecognized", "something_new"),
  ]);
  assert.deepEqual(fillableFields(e), []);
});

test("fillable: role comes from designation.kind, not the field name", () => {
  // A field named "password" but designated username must be treated as username.
  const e = entry([ref("password", "username")]);
  assert.deepEqual(roles(fillableFields(e)), ["username:password"]);
  // A field named "login" but designated other must NOT be fillable.
  assert.deepEqual(fillableFields(entry([ref("login", "other", "x")])), []);
});

test("fillable: duplicate roles — first wins", () => {
  const e = entry([ref("a", "username"), ref("b", "username"), ref("x", "password"), ref("y", "password")]);
  assert.deepEqual(roles(fillableFields(e)), ["username:a", "password:x"]);
});

test("fillable: empty / undefined entry → empty", () => {
  assert.deepEqual(fillableFields(undefined), []);
  assert.deepEqual(fillableFields(entry([])), []);
});

test("fillable: missing or malformed designation → skipped (fail-safe, no crash)", () => {
  const e = entry([{ name: "broken", designation: undefined } as unknown as EntryFieldRef]);
  assert.deepEqual(fillableFields(e), []);
});
