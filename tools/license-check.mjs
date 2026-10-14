#!/usr/bin/env node
// Dependency-license check for @bounded-authority-protocol/verifier (ADR 0014 Decision 8). Since 0.7.0 the SDK
// has three runtime dependencies, all exactly pinned and MIT-licensed: @noble/ed25519, @noble/curves
// and @noble/hashes, loaded only by the portable crypto backend (browsers, Deno, Bun, and Node under
// --conditions=bap-portable); the node backend uses node:crypto. This gate fails if any runtime
// dependency, direct or transitive, carries a license outside the Apache-2.0/BSD/MIT/ISC allowlist
// (AGENTS rule 10). This is the TS analog of the Elixir scripts/check_dependency_licenses.exs.
//
// It enumerates the package's own dependency tree (dependencies, NOT devDependencies — dev tooling
// like eslint/tsx/typescript is build-time, not shipped in the published package's runtime surface).
// The published package ships only `dist` + LICENSE + NOTICE (see package.json `files`), so runtime
// license posture is what this gate certifies.
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

// The allowlist (AGENTS rule 10; ADR 0001 license decision): permissive, GPL-incompatible.
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
