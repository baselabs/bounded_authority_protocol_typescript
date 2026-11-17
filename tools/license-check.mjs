#!/usr/bin/env node
// Check the shipped dependency tree against the Apache-2.0/BSD/MIT/ISC license allowlist.
// Runtime dependencies are exactly pinned: @noble/ed25519, @noble/curves and @noble/hashes.
// The portable backend loads these MIT-licensed packages; the Node backend uses node:crypto.
// Dev dependencies are build tools and do not enter the published runtime dependency tree.
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

// Node's package lookup (walk up node_modules directories from the dependent's real directory), done
// on the filesystem: a package whose "exports" map hides ./package.json (the @noble packages do)
// cannot be read through require().
function packageDir(name, fromDir) {
  for (let dir = fromDir; ; dir = dirname(dir)) {
    const candidate = join(dir, "node_modules", ...name.split("/"));
    if (existsSync(join(candidate, "package.json"))) return realpathSync(candidate);
    if (dirname(dir) === dir) return null;
  }
}

// Permit only the explicitly listed permissive licenses in the shipped runtime dependency tree.
const ALLOW = new Set([
  "Apache-2.0", "Apache 2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD",
  "MIT", "ISC", "0BSD", "Unlicense", "CC0-1.0",
  // SPDX compound forms seen in the wild for permissive deps.
  "Apache-2.0 OR BSD-3-Clause", "Apache-2.0 OR MIT", "BSD-3-Clause OR Apache-2.0",
  "(MIT OR CC0-1.0)",
]);

function normalize(license) {
  if (!license) return null;
  if (typeof license === "string") return license.trim();
  if (typeof license === "object") return license.type ? String(license.type).trim() : null;
  return null;
}

// Collect runtime dependencies transitively (@noble/curves depends on @noble/hashes).
const runtimeDeps = pkg.dependencies ? Object.keys(pkg.dependencies) : [];
const seen = new Set();
const offenders = [];

function visit(name, fromDir) {
  if (seen.has(name)) return;
  seen.add(name);
  const dir = packageDir(name, fromDir);
  if (dir === null) {
    offenders.push(`${name}: cannot resolve package (is it installed?)`);
    return;
  }
  const depPkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const license = normalize(depPkg.license) ?? normalize(depPkg.licenses);
  if (!ALLOW.has(license)) {
    offenders.push(`${name}: license "${license ?? "(missing)"}" not in the allowlist`);
  }
  // Recurse into transitive runtime deps.
  const transitive = depPkg.dependencies ? Object.keys(depPkg.dependencies) : [];
  for (const t of transitive) visit(t, dir);
}

for (const dep of runtimeDeps) visit(dep, ROOT);

if (offenders.length > 0) {
  console.error("license-check: FAIL — disallowed runtime dependency licenses:");
  for (const o of offenders) console.error(`  ${o}`);
  process.exit(1);
}

if (runtimeDeps.length === 0) {
  console.log("license-check: PASS — zero runtime dependencies (stdlib-only by design)");
} else {
  console.log(`license-check: PASS — ${runtimeDeps.length} runtime dependency(ies), ${seen.size} package(s) with transitive ones, all allowlisted: ${[...seen].sort().join(", ")}`);
}
