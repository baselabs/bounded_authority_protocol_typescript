#!/usr/bin/env node
// Verify direct dependency currency using real pnpm and npm registry results. Classify data,
// rather than exit status alone: pnpm outdated exits nonzero for both drift and lookup failure.
// Its empty exit-zero table confirms that everything is current. Use semver.maxSatisfying over
// npm's version list because publication order and pnpm's lockfile-anchored wanted field do not
// identify the highest permitted version.
//
// Update resolvable in-range drift; no pin excuses it. DELIBERATE_PINS records reasons only for
// retaining a declared major line when a newer major exists. Transitive dependencies move through
// deliberate lockfile updates. An unverifiable registry state always fails. Currency is independent
// of the operating system, so one CI lane runs this gate. Keep subprocess handling portable.
//
// Report deprecated packages, in-range drift and unpinned newer majors as failures. Report stale
// pins even when pnpm lists no drift. Reject non-registry specifications, unparsable results,
// resolver errors and timeouts. A dist-tag rollback can require an explicit version bump when
// pnpm update would not select the highest published in-range version.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import semver from "semver";

const DELIBERATE_PINS = new Map([
  [
    "typescript",
    "7.x is the native-compiler major line. Probed 2026-09-27 with 7.0.2: its package drops the JS compiler API the in-memory mutation tests use (ts.ScriptTarget/ts.ModuleKind, TS2339), and typescript-eslint 8.70.1 (latest) peers typescript <6.1.0 and fails to load (lint exit 2). Stay on 6.x until both move",
  ],
]);

const SUBPROCESS_TIMEOUT_MS = 120_000;

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const ranges = { ...manifest.dependencies, ...manifest.devDependencies };
const declared = Object.keys(ranges);

// Registry ranges start with a version or a range operator; anything else (file:,
// git+…, link:, workspace:, URL, user/repo shorthand, local paths) is a spec this
// gate cannot verify. Such specifications fail closed.
const REGISTRY_RANGE = /^[0-9^~><=*\s-]/;

// On Windows, execute pnpm/npm .CMD shims through the shell. Arguments contain only package
// names and flags without shell metacharacters. Bound every resolver call with a timeout.
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
    return { error: `no version of ${name} satisfies the declared ${ranges[name]}. Currency state is unverified.` };
  }
  return { max };
}

const failures = [];
const reports = [];
const unverified = [];

function sweepStalePins(listed) {
  for (const name of DELIBERATE_PINS.keys()) {
    if (!listed.has(name)) {
      reports.push(`${name}: a pin is recorded, but pnpm outdated does not list it. It is at latest or absent; drop the pin if stale.`);
    }
  }
}

const pnpm = await run("pnpm", ["outdated", "--format", "json"]);
let table;
try {
  table = JSON.parse(pnpm.stdout);
} catch {
  console.error(
    `check-currency: dependency data could not be parsed (pnpm exited ${pnpm.code}). ` +
      `Currency state is unverified, and an unverified currency state never passes.` +
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
        "package.json declares dependencies. Currency state is unverified, and an " +
        "unverified currency state never passes." +
        (pnpm.stderr ? `\n  pnpm stderr: ${pnpm.stderr.trim()}` : ""),
    );
  }
  for (const item of unverified) console.error(item);
  console.error(`check-currency: there are ${unverified.length} unverified state(s). An unverified currency state never passes.`);
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
    failures.push(`${name}: the registry marks the current version (${info.current}) as deprecated. Move off it.`);
  } else if (semver.gt(max, info.current)) {
    failures.push(
      `${name}: in-range drift is resolvable. The current version is ${info.current}; the maximum within the declared range ` +
        `${ranges[name]} is ${max}. The range already allows it; run pnpm update in this change. This drift cannot be pinned.`,
    );
  } else if (info.latest && semver.gt(info.latest, max)) {
    const pin = DELIBERATE_PINS.get(name);
    if (pin) {
      reports.push(`${name}: the dependency is pinned (latest ${info.latest} sits outside the declared range). Reason: ${pin}`);
    } else {
      failures.push(
        `${name}: a newer release sits outside the declared range. The range maximum is ${max}; latest is ` +
          `${info.latest}. Move the range in this change or record a DELIBERATE_PINS reason.`,
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
    `check-currency: there are ${failures.length} dependency-currency failure(s) and ` +
      `${unverified.length} unverified state(s). An unverified currency state never passes.`,
  );
  process.exit(1);
}
console.log(
  `check-currency: all ${declared.length} declared dependencies at latest ` +
    `or deliberately pinned (reasons above, if any).`,
);
