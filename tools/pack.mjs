#!/usr/bin/env node
// Builds the package tarball that is checked and published (pnpm pack:release; test:tarball and the
// release workflow both use it). Run `pnpm build` first.
//
// It never writes the working tree. It copies the files npm would pack (the "files" list, read with
// `npm pack --dry-run --ignore-scripts`) into a staging directory outside the repository, writes the
// staged package.json without this repository's development conditions, and packs the staging
// directory with scripts ignored. The development condition bap-source points "#crypto" at
// src/crypto/*.ts, which the package does not ship, so the published manifest must not carry it.
// npm packs with fixed file times and order, so the same tree gives the same bytes: the release job
// compares the SHA-256 of its tarball with the one the verify job checked, and then publishes that
// file (`npm stage publish <file>`, which runs no scripts and reads the manifest from the tarball).
//
// Usage: node tools/pack.mjs [--out <dir>]   Prints {"file": <absolute path>, "sha256": <hex>}.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const DEVELOPMENT_CONDITIONS = ["bap-source"];

export function stripDevelopmentConditions(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  const out = {};
  for (const [key, inner] of Object.entries(value)) {
    if (!DEVELOPMENT_CONDITIONS.includes(key)) out[key] = stripDevelopmentConditions(inner);
  }
  return out;
}

export function pack(outDir) {
  const npm = (args, cwd) => execFileSync("npm", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const [listing] = JSON.parse(npm(["pack", "--dry-run", "--json", "--ignore-scripts"], ROOT));
  const manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  const staging = mkdtempSync(join(tmpdir(), "bap-pack-"));
  try {
    for (const { path } of listing.files) {
      if (path === "package.json") continue;
      mkdirSync(dirname(join(staging, path)), { recursive: true });
      copyFileSync(join(ROOT, path), join(staging, path));
    }
    manifest.imports = stripDevelopmentConditions(manifest.imports);
    manifest.exports = stripDevelopmentConditions(manifest.exports);
    writeFileSync(join(staging, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
    mkdirSync(outDir, { recursive: true });
    const [packed] = JSON.parse(npm(["pack", staging, "--pack-destination", outDir, "--json", "--ignore-scripts"], outDir));
    const file = join(outDir, packed.filename);
    const sha256 = createHash("sha256").update(readFileSync(file)).digest("hex");
    return { file, sha256 };
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const at = process.argv.indexOf("--out");
  const outDir = resolve(at > 0 && process.argv[at + 1] ? process.argv[at + 1] : join(ROOT, "build-pack"));
  console.log(JSON.stringify(pack(outDir)));
}
