/**
 * Bundle the extension into dist/ with esbuild (zero runtime deps — everything is
 * bundled; WebCrypto comes from the browser/Node runtime).
 *
 * Output layout (Chrome unpacked / Firefox temporary-addon loadable):
 *   dist/manifest.json
 *   dist/background.js          (service worker)
 *   dist/content/capture.js     (content script)
 *   dist/content/fill.js        (content script)
 *   dist/ui/popup.html + popup.js
 *   dist/ui/inline_menu.html + inline_menu.js
 */
import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)));
const dist = resolve(root, "dist");

await build({
  entryPoints: [
    resolve(root, "src/background.ts"),
    resolve(root, "src/content/capture.ts"),
    resolve(root, "src/content/fill.ts"),
    resolve(root, "src/ui/inline_menu.ts"),
    resolve(root, "src/ui/popup.ts"),
  ],
  outdir: dist,
  bundle: true,
  format: "iife",
  target: ["chrome110", "firefox115"],
  sourcemap: false,
  minify: false,
  logLevel: "info",
});

const copies = [
  ["manifest.json", "manifest.json"],
  ["src/ui/popup.html", "ui/popup.html"],
  ["src/ui/inline_menu.html", "ui/inline_menu.html"],
];
for (const [from, to] of copies) {
  const target = resolve(dist, to);
  mkdirSync(dirname(target), { recursive: true });
  copyFileSync(resolve(root, from), target);
}

console.log("build ok → dist/");
