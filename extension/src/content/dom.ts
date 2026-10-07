/**
 * DOM helpers shared by the capture and fill content scripts (docs/31 §5).
 *
 * Field identification uses label for / ARIA / autocomplete heuristics (1Password
 * A.10-style). `data-coffer-ignore` is the opt-out attribute (D-7).
 *
 * Honest limit: the content script shares the page DOM, so values written into fields
 * are visible to page JS. We drop our own references immediately after writing
 * (best-effort; JS cannot truly zeroize strings — docs/31 §0).
 */

export const IGNORE_ATTR = "data-coffer-ignore";

/** Opt-out: any ancestor (or the element) carrying data-coffer-ignore. */
export function isIgnored(el: Element | null): boolean {
  let cur: Element | null = el;
  while (cur) {
    if (cur instanceof HTMLElement && cur.hasAttribute(IGNORE_ATTR)) return true;
    cur = cur.parentElement;
  }
  return false;
}

export interface LoginFields {
  form: HTMLFormElement | null;
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

function isUsernameCandidate(input: HTMLInputElement): boolean {
  const type = (input.getAttribute("type") ?? "text").toLowerCase();
  if (!["", "text", "email", "tel"].includes(type)) return false;
  if (input.disabled || input.readOnly) return false;
  const auto = (input.getAttribute("autocomplete") ?? "").toLowerCase();
  if (["username", "email", "login"].includes(auto)) return true;
  const hints = [input.name, input.id, input.getAttribute("aria-label")].filter(Boolean).join(" ").toLowerCase();
  return /\b(user(?:name)?|email|login|account|e-mail)\b/.test(hints);
}

function findUsernameForPassword(scope: ParentNode, password: HTMLInputElement): HTMLInputElement | null {
  const inputs = Array.from(scope.querySelectorAll<HTMLInputElement>("input"));
  const idx = inputs.indexOf(password);
  for (let i = idx - 1; i >= 0; i--) {
    if (isUsernameCandidate(inputs[i]!)) return inputs[i]!;
  }
  return inputs.find((el) => isUsernameCandidate(el)) ?? null;
}

/** Locate the login field pair (password required; username optional). */
export function findLoginFields(scope: ParentNode = document): LoginFields {
  const passwords = Array.from(scope.querySelectorAll<HTMLInputElement>('input[type="password"]')).filter(
    (p) => !isIgnored(p),
  );
  if (passwords.length === 0) return { form: null, username: null, password: null };
  const password = passwords[0]!;
  const form = password.form ?? password.closest("form");
  const username = findUsernameForPassword(form ?? scope, password) ?? findUsernameForPassword(scope, password) ?? null;
  return { form, username, password };
}

/** Resolve the form action against the document base URL; null if unparseable. */
export function formActionUrl(form: HTMLFormElement | null): string | null {
  if (!form) return null;
  const action = form.getAttribute("action");
  if (!action) return window.location.href; // omitted action submits to the current page
  try {
    return new URL(action, form.baseURI).href;
  } catch {
    return null;
  }
}

/** Pure: does an action URL belong to the given origin? Null/unparseable → false. */
export function sameOriginUrl(actionUrl: string | null, origin: string): boolean {
  if (!actionUrl) return false;
  try {
    return new URL(actionUrl).origin === origin;
  } catch {
    return false;
  }
}

/** Does the form submit to the same origin as the current page? (HIGH-1 fill gate.) */
export function isSameOriginAction(form: HTMLFormElement | null): boolean {
  return sameOriginUrl(formActionUrl(form), window.location.origin);
}

export interface CredentialSnapshot {
  origin: string;
  username: string;
  password: string;
  title: string;
  action: string | null;
  form: HTMLFormElement | null;
  usernameField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
}

/** Read current field values. Null when there is no non-empty password. */
export function readCredentials(fields: LoginFields): CredentialSnapshot | null {
  if (!fields.password) return null;
  const password = fields.password.value ?? "";
  if (password.length === 0) return null;
  return {
    origin: window.location.origin,
    username: fields.username?.value ?? "",
    password,
    title: document.title || window.location.hostname,
    action: formActionUrl(fields.form),
    form: fields.form,
    usernameField: fields.username,
    passwordField: fields.password,
  };
}

/** Set a field value through the native setter so framework bindings observe it. */
function setNativeValue(input: HTMLInputElement | HTMLTextAreaElement, value: string): void {
  const proto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
}

/** Fill a field and notify listeners. */
export function fillField(input: HTMLInputElement | HTMLTextAreaElement | null, value: string): void {
  if (!input) return;
  setNativeValue(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/** Best-effort wipe: clear the DOM field and drop our references (JS cannot zeroize). */
export function wipeValue(input: HTMLInputElement | null): void {
  if (!input) return;
  setNativeValue(input, "");
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

/** Drop plaintext references immediately after fill (best-effort; see module doc). */
export function wipeSecrets(s: { username: string; password: string }): void {
  s.username = "";
  s.password = "";
}
