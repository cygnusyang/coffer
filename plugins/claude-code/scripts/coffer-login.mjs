#!/usr/bin/env node
// coffer-login.mjs — browser-login driver for coffer's `run_with_secret`.
//
// The password reaches this process ONLY through an env var (--password-env);
// it never appears in argv, stdout, stderr, or logs, so it never enters
// Claude's context. This script fills a login form and (optionally) submits
// it in a persistent Chromium profile so the session survives future runs.
//
// Modes:
//   smoke:  --smoke            navigate, locate fields, report; no fill/submit
//   filled: --no-submit        fill fields but leave the submit to a human
//   login:  (default)          fill and submit, wait for a success signal
//
// Usage via mcp__coffer__run_with_secret:
//   run_with_secret {
//     secret: "<coffer secret name>",
//     cmd: "node",
//     args: ["coffer-login",
//            "--url", "https://community.obsidian.md/",
//            "--email", "you@example.com",
//            "--password-env", "PASSWORD",
//            "--open", ".login-button",
//            "--success-selector", ".current-user"],
//     env_name: "PASSWORD"
//   }
//
// Success signals (any one, polled): --success-selector (CSS), --success-text
// (substring of body), --success-url (RegExp on the final URL). Failure signals:
// --error-selector (CSS, checked each poll). If none fire within
// --success-wait-ms the run reports a timeout — the human should check the
// window (2FA/captcha may be pending), it does NOT mean the login failed.

import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

const require = createRequire(import.meta.url);

// --- playwright resolution -------------------------------------------------
// Portable loader. On any machine this resolves in order:
//   1. --playwright-path <dir> (explicit override)
//   2. local / NODE_PATH resolution (require('playwright'))
//   3. the global npm install (`npm root -g`)
// If none match, print the one-time install command instead of a bare error.
function loadPlaywright(a) {
  if (a['playwright-path']) {
    for (const p of [path.join(a['playwright-path'], 'index.js'), a['playwright-path']]) {
      try { return require(p); } catch {}
    }
  }
  try { return require('playwright'); } catch {}
  try {
    const r = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' });
    const root = (r.stdout || '').trim();
    if (root) { try { return require(path.join(root, 'playwright')); } catch {} }
  } catch {}
  throw new Error(
    'playwright not found. Install it once on this machine:\n' +
    '  npm i -g playwright && npx playwright install chromium\n' +
    '(or pass --playwright-path <dir> pointing at a playwright install)');
}

// --- arg parsing -----------------------------------------------------------
function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) continue;
    const name = k.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) { a[name] = true; continue; }
    a[name] = next; i++;
  }
  return a;
}

function usage() {
  return [
    'Usage: coffer-login.mjs --url <login-url> --password-env <ENV> [options]',
    '  --url <url>                (required) page to open',
    '  --password-env <ENV>       (required, unless --smoke) env var holding the password',
    '  --email <addr>             username/email to fill (optional)',
    '  --open <selector>          click this to open the login form before filling',
    '  --email-selector <css>     default #login-account-name',
    '  --password-selector <css>  default #login-account-password',
    '  --submit-selector <css>    default #login-button',
    '  --profile <dir>            persistent profile (default ~/.cache/coffer-login/<host>)',
    '  --headless                 run headless (default: headed, so a human can watch / do 2FA)',
    '  --no-submit                fill but do not click submit',
    '  --smoke                    locate fields only, never fill or submit (no password needed)',
    '  --success-selector <css>   success signal',
    '  --success-text <text>      success signal (substring of body text)',
    '  --success-url <regex>      success signal (matched against final URL)',
    '  --error-selector <css>     default ".alert-error, #login-error"',
    '  --success-wait-ms <ms>     default 15000',
  ].join('\n');
}

const DEFAULTS = {
  emailSelector: '#login-account-name',
  passwordSelector: '#login-account-password',
  submitSelector: '#login-button',
  errorSelector: '.alert-error, #login-error, .login-error',
  successWaitMs: 15000,
};

// --- run -------------------------------------------------------------------
async function run() {
  const a = parseArgs(process.argv.slice(2));
  if (!a.url || (!a['password-env'] && !a.smoke)) {
    console.error(usage());
    process.exit(2);
  }

  const playwright = loadPlaywright(a);
  const pwEnv = a['password-env'];
  const password = a.smoke ? '' : (process.env[pwEnv] ?? '');
  if (!a.smoke && password === '') {
    console.error(`[coffer-login] env var ${pwEnv} is empty/unset — refusing to log in with a blank password`);
    process.exit(3);
  }

  const host = new URL(a.url).hostname;
  const slug = host.replace(/\./g, '-');
  const profile = a.profile || path.join(homedir(), '.cache', 'coffer-login', slug);
  fs.mkdirSync(profile, { recursive: true });

  const ctx = await playwright.chromium.launchPersistentContext(profile, {
    headless: !!a.headless,
    viewport: { width: 1280, height: 900 },
  });
  const page = ctx.pages()[0] || (await ctx.newPage());

  const receipt = {
    ok: false,
    mode: a.smoke ? 'smoke' : (a['no-submit'] ? 'filled' : 'login'),
    url: a.url,
    host,
    profile,
    fields: { email: false, password: false },
    outcome: null,
    note: null,
  };

  try {
    page.setDefaultTimeout(Number(a['success-wait-ms']) || DEFAULTS.successWaitMs);
    const resp = await page.goto(a.url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    receipt.status = resp ? resp.status() : null;

    if (a.open) {
      try { await page.click(a.open, { timeout: 5000 }); }
      catch { /* form may already be visible — proceed */ }
    }

    // Locate fields.
    if (!a.smoke && a.email) {
      const el = await page.$(a['email-selector'] || DEFAULTS.emailSelector);
      if (el) { await el.fill(a.email); receipt.fields.email = true; }
    } else if (a.smoke) {
      receipt.fields.email = !!(await page.$((a['email-selector'] || DEFAULTS.emailSelector)));
    }
    if (!a.smoke) {
      const el = await page.$(a['password-selector'] || DEFAULTS.passwordSelector);
      if (el) { await el.fill(password); receipt.fields.password = true; }
    } else {
      receipt.fields.password = !!(await page.$((a['password-selector'] || DEFAULTS.passwordSelector)));
    }

    if (a.smoke) {
      receipt.ok = true;
      receipt.outcome = 'fields-located';
      receipt.note = 'smoke only — no credentials used';
      return receipt;
    }

    if (a['no-submit']) {
      receipt.ok = true;
      receipt.outcome = 'filled-awaiting-human';
      receipt.note = 'fields filled in the visible window; submit left to you';
      return receipt;
    }

    // Submit and poll for a success/failure signal.
    const submit = await page.$((a['submit-selector'] || DEFAULTS.submitSelector));
    if (!submit) {
      receipt.ok = false;
      receipt.note = 'submit button not found — nothing clicked';
      return receipt;
    }
    await submit.click();

    const successSel = a['success-selector'];
    const successText = a['success-text'];
    const successUrl = a['success-url'] ? new RegExp(a['success-url']) : null;
    const errorSel = a['error-selector'] || DEFAULTS.errorSelector;
    const waitMs = Number(a['success-wait-ms']) || DEFAULTS.successWaitMs;

    const deadline = Date.now() + waitMs;
    while (Date.now() < deadline) {
      const url = page.url();
      if (successUrl && successUrl.test(url)) {
        receipt.ok = true; receipt.outcome = 'success-url'; receipt.url = url; break;
      }
      if (successSel && (await page.$(successSel))) {
        receipt.ok = true; receipt.outcome = 'success-selector'; break;
      }
      if (successText) {
        const body = (await page.textContent('body')) || '';
        if (body.includes(successText)) {
          receipt.ok = true; receipt.outcome = 'success-text'; break;
        }
      }
      const errEl = await page.$(errorSel);
      if (errEl) {
        const msg = ((await errEl.textContent()) || '').trim().slice(0, 200);
        receipt.ok = false;
        receipt.outcome = 'error-signal';
        receipt.note = `login form reports an error: ${msg} (likely wrong credentials or 2FA)`;
        break;
      }
      await sleep(400);
    }
    if (receipt.outcome === null) {
      receipt.ok = false;
      receipt.outcome = 'timeout';
      receipt.note = 'no success/error signal within the wait — check the window (2FA/captcha may be pending)';
    }
    receipt.title = await page.title();
    return receipt;
  } finally {
    // Smoke runs close immediately. Real-login runs keep the browser open:
    // a headed login may need human 2FA, and the persistent context must be
    // left alive to save the session cookies.
    if (a.smoke) await ctx.close();
  }
}

// --- entry -----------------------------------------------------------------
run()
  .then((r) => { console.log(JSON.stringify(r)); process.exit(r.ok ? 0 : 1); })
  .catch((e) => { console.error('[coffer-login] failed:', e.message); process.exit(1); });
