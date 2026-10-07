/**
 * Pure fill-role derivation from entry metadata (no chrome APIs — unit-testable).
 *
 * Fill roles come exclusively from the broker's `Designation.kind` (cf-domain
 * `Designation`, adjacently-tagged `{"kind": ...}`; cf-domain/src/field.rs) — the
 * extension must NOT guess roles from field names ("pass"/"密码"/"code" would be
 * wrong). Known roles mapped today: `password` → password; `username`/`email` →
 * username (email fills the username box on login forms). Unknown kinds
 * (totp/notes_plain/other/...) are not fillable by the current username+password
 * DOM fill and are skipped.
 */
import type { EntryInfo } from "./protocol";

export interface FillableField {
  role: "username" | "password";
  /** Item field name as stored (passed back as a `get_secret.fields` element). */
  name: string;
}

const PASSWORD_KINDS = new Set(["password"]);
const USERNAME_KINDS = new Set(["username", "email"]);

export function fillableFields(entry: EntryInfo | undefined): FillableField[] {
  if (!entry || !Array.isArray(entry.fields)) return [];
  const out: FillableField[] = [];
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
