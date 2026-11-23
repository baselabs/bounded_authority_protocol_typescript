// package.json "engines" keeps the deliberate consumer-facing floor ">=22" (CHANGELOG 0.2.2: "engines.node
// >= 22 stays the consumer-facing floor"); CI pins exact patch versions for its own lanes, and every
// CI pin satisfies the floor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { parse } from "yaml";

const REPO = fileURLToPath(new URL("..", import.meta.url));

test('engines.node is exactly ">=22", and every CI Node pin satisfies it', () => {
  const range = (JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { engines: { node: string } }).engines.node;
  assert.equal(range, ">=22");
  const output = execFileSync(join(REPO, "scripts/toolchain.sh"), [], { cwd: REPO, encoding: "utf8" });
  const versions = new Map(output.trim().split("\n").map((line) => {
    const [tool, version] = line.split("="); return [tool!, version!] as const;
  }));
  const primary = versions.get("nodejs");
  const lanes = JSON.parse(versions.get("nodejs_lanes")!) as string[];
  assert.ok(primary, "CI requires a primary Node version");
  const pins = [primary, ...lanes];
  assert.ok(pins.length >= 2, `CI pins: ${pins.join(", ")}`);
  for (const pin of pins) assert.ok(semver.satisfies(pin, range), `${pin} satisfies ${range}`);
});

test("the lock cannot resolve this repository's own package from a registry", () => {
  const manifest = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { name: string };
  const lock = readFileSync(join(REPO, "pnpm-lock.yaml"), "utf8");
  const escaped = manifest.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // pnpm records every registry package (including aliases) under name@version.
  assert.doesNotMatch(lock, new RegExp(`${escaped}@[^\\s'\"]+`));
});

// pnpm resolves the link; npm's own field states the same link, so `npm audit signatures`
// treats the candidate as this directory and never looks up an unpublished version.
test("the companion signer resolves only this checkout's verifier", () => {
  const selector = "@bounded-authority-protocol/signer>@bounded-authority-protocol/verifier";
  const manifest = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as {
    overrides: Record<string, Record<string, string>>;
    pnpm: { overrides: Record<string, string> };
  };
  const lock = parse(readFileSync(join(REPO, "pnpm-lock.yaml"), "utf8")) as {
    overrides: Record<string, string>;
    snapshots: Record<string, { dependencies?: Record<string, string> }>;
  };
  assert.equal(manifest.pnpm.overrides[selector], "link:.");
  assert.deepEqual(manifest.overrides, { "@bounded-authority-protocol/signer": { "@bounded-authority-protocol/verifier": "file:." } });
  assert.equal(lock.overrides[selector], "link:.");
  const signers = Object.entries(lock.snapshots).filter(([name]) => name.startsWith("@bounded-authority-protocol/signer@"));
  assert.ok(signers.length > 0, "the lock must include the companion signer");
  for (const [name, snapshot] of signers) {
    // pnpm 10 normalizes the root-relative link:. to link: in dependency snapshots.
    assert.equal(snapshot.dependencies?.["@bounded-authority-protocol/verifier"], "link:", name);
  }
});
