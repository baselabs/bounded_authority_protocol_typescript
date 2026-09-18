#!/usr/bin/env node
// Dependency-currency gate (latest-first) — the pnpm analogue of the Elixir family's
// dependency-currency gate (BAP ADR 0032), written in the repo's managed language
// because the tri-platform build bar (BAP ADR 0031) rejects POSIX shell inside a
// declared gate. Classification is on data from real resolvers, never on a tool's
// exit status alone: `pnpm outdated --format json` for the drift table (it exits
// nonzero both on drift and on lookup failure, and exits 0 with `{}` when everything
// is current — that empty exit-0 table is a VERIFIED all-current state), plus
// `npm view <name> versions --json` resolved through the canonical `semver` package
// for the in-range maximum. npm returns versions in publish order, not semver
// order, so the max must be computed (semver.maxSatisfying), not picked off the end;
// pnpm's `wanted` field is lockfile-anchored and cannot carry this either.
//
// Latest-first policy: every dependency resolvable to a newer registry version is
// updated in the change that discovers it; anything deliberately not at latest
// carries its reason in DELIBERATE_PINS below (package.json cannot hold comments).
// A pin is major-jump-shaped only: it exempts a package from updates OUTSIDE its
// declared range (the range itself — package.json — is where "stay on this major"
// lives, mirroring the Elixir gate's `~>` requirement cap); it NEVER exempts drift
// the declared range already allows.
//
// Documented departures from the Elixir shape:
// - pnpm renders DIRECT dependencies only (no --all table), so transitive currency
//   is not classified here — transitive moves ride deliberate `pnpm update` commits
//   behind the CI-frozen lockfile.
// - The npm-side max can diverge from pnpm's resolver when a dist-tag rollback
//   leaves a stable in-range version above the `latest` tag: the gate then demands
//   a version `pnpm update` will not pick. That failure is loud (a named red), never
//   silent, and clears only via an explicit version bump.
// - The gate runs in CI on one lane (currency is a property of the manifest +
//   lockfile, OS-independent); the win32 shell path is exercised by local
//   `pnpm check:currency` runs on a Windows checkout, not by the CI matrix.
//
// Classification, per outdated package:
//   isDeprecated                   -> exit 1, named
//   current !== in-range max       -> exit 1, named — in-range resolvable drift; never pinnable
//   in-range max below latest      -> exit 1, named — newer release outside the declared range
//   in-range max below latest, pinned -> reported with the pin's reason
//   pinned but not listed by pnpm  -> reported (at latest or absent — drop a stale pin)
//   non-registry spec (file:, git, link, shorthand) -> exit 1: unverified, never passes
//   pnpm exit 0 + empty table      -> PASS (verified all-current), stale pins still reported
//   unparseable output, empty-but-nonzero table, npm-view failure/timeout, spawn error
//                                  -> exit 1 (an unverified currency state never passes)
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import semver from "semver";

const DELIBERATE_PINS = new Map([
  [
    "typescript",
    "7.x is the native-compiler major line; adopting it is a review-gated move (strict-build emit plus both conformance corpora), not a currency patch",
  ],
]);

const SUBPROCESS_TIMEOUT_MS = 120_000;

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const ranges = { ...manifest.dependencies, ...manifest.devDependencies };
const declared = Object.keys(ranges);

// Registry ranges start with a version or a range operator; anything else (file:,
// git+…, link:, workspace:, URL, user/repo shorthand, local paths) is a spec this
// gate cannot verify — it fails closed rather than silently passing.
const REGISTRY_RANGE = /^[0-9^~><=*\s-]/;

// pnpm/npm are .CMD shims on Windows, which spawn cannot execute directly — route
// through the shell there only (the ADR 0031 `cmd /c` wrapper analogue). All args
// are package names and flags with no shell metacharacters, so the shell surface
// is closed. Each resolver call is bounded: a stalled registry kills the child and
// the gate fails closed.
function run(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: root, shell: process.platform === "win32" });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      resolve({ error: `timed out after ${SUBPROCESS_TIMEOUT_MS} ms`, stdout, stderr, code: null });
    }, SUBPROCESS_TIMEOUT_MS);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ error: err.message, stdout, stderr, code: null });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ error: null, stdout, stderr, code });
    });
  });
}

async function inRangeMax(name) {
  const { error, stdout, code } = await run("npm", ["view", name, "versions", "--json"]);
  if (error || code !== 0) {
    return { error: `npm view ${name} versions failed (exit ${code ?? "n/a"}, ${error ?? "see stderr"})` };
  }
  let versions;
  try {
    versions = JSON.parse(stdout);
  } catch {
    return { error: `npm view ${name} versions: unparseable output` };
  }
  if (!Array.isArray(versions) || versions.length === 0 || !versions.every((v) => typeof v === "string")) {
    return { error: `npm view ${name} versions: unexpected shape` };
  }
  const max = semver.maxSatisfying(versions, ranges[name]);
  if (max === null) {
    return { error: `no version of ${name} satisfies the declared ${ranges[name]} — unverified` };
  }
  return { max };
}

const failures = [];
const reports = [];
const unverified = [];

function sweepStalePins(listed) {
  for (const name of DELIBERATE_PINS.keys()) {
    if (!listed.has(name)) {
      reports.push(`${name}: pin recorded but not listed by pnpm outdated — at latest or absent; drop the pin if stale`);
    }
  }
}

const pnpm = await run("pnpm", ["outdated", "--format", "json"]);
let table;
try {
  table = JSON.parse(pnpm.stdout);
} catch {
  console.error(
    `check-currency: no parseable dependency data (pnpm exited ${pnpm.code}) — ` +
      `currency state unverified, and an unverified currency state never passes.` +
      (pnpm.stderr ? `\n  pnpm stderr: ${pnpm.stderr.trim()}` : ""),
  );
  process.exit(1);
}

for (const [name, spec] of Object.entries(ranges)) {
  if (!REGISTRY_RANGE.test(spec)) {
    unverified.push(`${name}: spec ${JSON.stringify(spec)} is not a registry range this gate can verify`);
  }
}

const entries = Object.entries(table);
if (entries.length === 0) {
  sweepStalePins(new Set());
  for (const report of reports) console.log(report);
  if (pnpm.code === 0 && unverified.length === 0) {
    console.log(
      `check-currency: all ${declared.length} declared dependencies at latest ` +
        "(pnpm outdated rendered an empty, exit-0 table).",
    );
    process.exit(0);
  }
  if (pnpm.code !== 0) {
    console.error(
      "check-currency: pnpm outdated exited nonzero with no entries while " +
        "package.json declares dependencies — currency state unverified, and an " +
        "unverified currency state never passes." +
        (pnpm.stderr ? `\n  pnpm stderr: ${pnpm.stderr.trim()}` : ""),
    );
  }
  for (const item of unverified) console.error(item);
  console.error(`check-currency: ${unverified.length} unverified state(s) — an unverified currency state never passes.`);
  process.exit(1);
}

for (const [name, info] of entries) {
  if (!(name in ranges)) {
    unverified.push(`${name}: not declared in package.json (stray lockfile entry?)`);
    continue;
  }
  const resolution = await inRangeMax(name);
  if (resolution.error) {
    unverified.push(resolution.error);
    continue;
  }
  const { max } = resolution;
  if (info.isDeprecated) {
    failures.push(`${name}: deprecated on the registry (current ${info.current}) — move off it`);
  } else if (semver.gt(max, info.current)) {
    failures.push(
      `${name}: in-range resolvable drift — current ${info.current}, max within the declared ` +
        `${ranges[name]} is ${max} (the range already allows it; pnpm update in this change — never pinnable)`,
    );
  } else if (info.latest && semver.gt(info.latest, max)) {
    const pin = DELIBERATE_PINS.get(name);
    if (pin) {
      reports.push(`${name}: pinned (latest ${info.latest} sits outside the declared range) — ${pin}`);
    } else {
      failures.push(
        `${name}: newer release outside the declared range — range max ${max}, latest ` +
          `${info.latest} (move the range in this change or record a DELIBERATE_PINS reason)`,
      );
    }
  }
}
sweepStalePins(new Set(entries.map(([name]) => name)));

for (const report of reports) console.log(report);
for (const item of unverified) console.error(item);
for (const failure of failures) console.error(failure);
if (failures.length > 0 || unverified.length > 0) {
  console.error(
    `check-currency: ${failures.length} dependency-currency failure(s), ` +
      `${unverified.length} unverified state(s) — an unverified currency state never passes.`,
  );
  process.exit(1);
}
console.log(
  `check-currency: all ${declared.length} declared dependencies at latest ` +
    `or deliberately pinned (reasons above, if any).`,
);
