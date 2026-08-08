#!/usr/bin/env node
// Dependency-license check for @bounded-authority/verifier (ADR 0014 Decision 8). The SDK is stdlib-
// only by design (node:crypto for Ed25519; zero runtime dependencies), so this gate verifies that
// claim and fails if any runtime dependency carries a license outside the Apache-2.0/BSD/MIT/ISC
// allowlist (AGENTS rule 10). This is the TS analog of the Elixir scripts/check_dependency_licenses.exs.
//
// It enumerates the package's own dependency tree (dependencies, NOT devDependencies — dev tooling
// like eslint/tsx/typescript is build-time, not shipped in the published package's runtime surface).
// The published package ships only `dist` + LICENSE + NOTICE (see package.json `files`), so runtime
// license posture is what this gate certifies.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

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

// Collect runtime dependencies transitively. The SDK has none by design; this gate exists to catch
// the day one is added.
const runtimeDeps = pkg.dependencies ? Object.keys(pkg.dependencies) : [];
const seen = new Set();
const offenders = [];

function visit(name) {
  if (seen.has(name)) return;
  seen.add(name);
  let depPkg;
  try {
    depPkg = require(`${name}/package.json`);
  } catch {
    offenders.push(`${name}: cannot resolve package (is it installed?)`);
    return;
  }
  const license = normalize(depPkg.license) ?? normalize(depPkg.licenses);
  if (!ALLOW.has(license)) {
    offenders.push(`${name}: license "${license ?? "(missing)"}" not in the allowlist`);
  }
  // Recurse into transitive runtime deps.
  const transitive = depPkg.dependencies ? Object.keys(depPkg.dependencies) : [];
  for (const t of transitive) visit(t);
}

for (const dep of runtimeDeps) visit(dep);

if (offenders.length > 0) {
  console.error("license-check: FAIL — disallowed runtime dependency licenses:");
  for (const o of offenders) console.error(`  ${o}`);
  process.exit(1);
}

if (runtimeDeps.length === 0) {
  console.log("license-check: PASS — zero runtime dependencies (stdlib-only by design)");
} else {
  console.log(`license-check: PASS — ${runtimeDeps.length} runtime dependency(ies), all allowlisted`);
}
