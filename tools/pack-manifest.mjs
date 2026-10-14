#!/usr/bin/env node
// The published package.json (npm and pnpm run this as prepack and postpack, so it applies to
// `pnpm pack`, `npm pack`, `npm publish` and `npm stage publish`).
//
// The repository's "#crypto" import map carries one development condition, bap-source, whose targets
// are the TypeScript backends in src/crypto/ that this repository's tests and runners load. src/ is
// not shipped, so a published manifest with that branch would send any consumer build or tool that
// sets bap-source to missing files. `prepack` saves package.json and writes it without the
// development conditions; `postpack` restores the saved file byte for byte. test/tarball.ts checks the
// packed manifest: every exports and imports target must be a packed file.
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MANIFEST = join(ROOT, "package.json");
const SAVED = join(ROOT, "package.json.prepack");
const DEVELOPMENT_CONDITIONS = ["bap-source"];

function strip(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  const out = {};
  for (const [key, inner] of Object.entries(value)) {
    if (!DEVELOPMENT_CONDITIONS.includes(key)) out[key] = strip(inner);
  }
  return out;
}

const mode = process.argv[2];
if (mode === "prepack") {
  // A save left by an interrupted pack is the true manifest: restore it before stripping again.
  if (existsSync(SAVED)) renameSync(SAVED, MANIFEST);
  const text = readFileSync(MANIFEST, "utf8");
  writeFileSync(SAVED, text);
  const manifest = JSON.parse(text);
  manifest.imports = strip(manifest.imports);
  manifest.exports = strip(manifest.exports);
  writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
} else if (mode === "postpack") {
  if (existsSync(SAVED)) renameSync(SAVED, MANIFEST);
} else {
  console.error("usage: node tools/pack-manifest.mjs prepack|postpack");
  process.exit(2);
}
