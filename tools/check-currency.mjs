#!/usr/bin/env node
// Dependency-currency gate (latest-first) — the pnpm analogue of the Elixir family's
// dependency-currency gate (BAP ADR 0032), written in the repo's managed language
// because the tri-platform build bar (BAP ADR 0031) rejects POSIX shell inside a
// declared gate. Classification is on `pnpm outdated --format json` DATA, never the
// tool's exit code: pnpm exits nonzero both on drift and on lookup failure, so the
// code cannot carry the verdict.
//
// Latest-first policy: every dependency resolvable to a newer registry version is
// updated in the change that discovers it; anything deliberately not at latest
// carries its reason in DELIBERATE_PINS below (package.json cannot hold comments).
//
// Documented departure from the Elixir shape: pnpm renders DIRECT dependencies only
// (no --all table), so transitive currency is not classified here — transitive moves
// ride deliberate `pnpm update` commits behind the CI-frozen lockfile.
//
// Classification:
//   isDeprecated                    -> exit 1, named
//   current !== latest, unpinned    -> exit 1, named (resolvable drift)
//   current !== latest, pinned      -> reported with the pin's reason
//   pinned but not listed by pnpm   -> reported (at latest or absent — drop a stale pin)
//   no table while deps are declared,
//   unparseable output, spawn error -> exit 1 (an unverified currency state never passes)
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const DELIBERATE_PINS = new Map([
  [
    "typescript",
    "7.x is the native-compiler major line; adopting it is a review-gated move (strict-build emit plus both conformance corpora), not a currency patch",
  ],
]);

// pnpm is a .CMD shim on Windows, which spawn cannot execute directly — route through
// the shell there only (the ADR 0031 `cmd /c` wrapper analogue; args are constants, so
// the shell surface is closed).
const child = spawn("pnpm", ["outdated", "--format", "json"], {
  shell: process.platform === "win32",
});

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const declared = Object.keys({
  ...manifest.dependencies,
  ...manifest.devDependencies,
});

let stdout = "";
let stderr = "";
child.stdout.on("data", (chunk) => (stdout += chunk));
child.stderr.on("data", (chunk) => (stderr += chunk));

child.on("error", (err) => {
  console.error(`check-currency: cannot run pnpm outdated: ${err.message}`);
  process.exit(1);
});

child.on("close", (code) => {
  let table;
  try {
    table = JSON.parse(stdout);
  } catch {
    console.error(
      `check-currency: no parseable dependency data (pnpm exited ${code}) — ` +
        `currency state unverified, and an unverified currency state never passes.` +
        (stderr ? `\n  pnpm stderr: ${stderr.trim()}` : ""),
    );
    process.exit(1);
  }

  const entries = Object.entries(table);
  if (entries.length === 0 && declared.length > 0) {
    console.error(
      "check-currency: pnpm outdated rendered no entries while package.json declares " +
        "dependencies — currency state unverified, and an unverified currency state never passes.",
    );
    process.exit(1);
  }

  const failures = [];
  const reports = [];
  for (const [name, info] of entries) {
    if (info.isDeprecated) {
      failures.push(`${name}: deprecated on the registry (current ${info.current}) — move off it`);
    } else if (info.current !== info.latest) {
      const pin = DELIBERATE_PINS.get(name);
      if (pin) {
        reports.push(`${name}: pinned at ${info.current} (latest ${info.latest}) — ${pin}`);
      } else {
        failures.push(
          `${name}: resolvable drift — current ${info.current}, latest ${info.latest} ` +
            `(update in this change or record a DELIBERATE_PINS reason)`,
        );
      }
    }
  }
  const listed = new Set(entries.map(([name]) => name));
  for (const name of DELIBERATE_PINS.keys()) {
    if (!listed.has(name)) {
      reports.push(`${name}: pin recorded but not listed by pnpm outdated — at latest or absent; drop the pin if stale`);
    }
  }

  for (const report of reports) console.log(report);
  if (failures.length > 0) {
    for (const failure of failures) console.error(failure);
    console.error(`check-currency: ${failures.length} dependency-currency failure(s).`);
    process.exit(1);
  }
  console.log(
    `check-currency: all ${declared.length} declared dependencies at latest ` +
      `or deliberately pinned (reasons above, if any).`,
  );
});
