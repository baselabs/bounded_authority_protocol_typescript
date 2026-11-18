// package.json "engines" keeps the deliberate consumer-facing floor ">=22" (CHANGELOG 0.2.2: "engines.node
// >= 22 stays the consumer-facing floor"); CI pins exact patch versions for its own lanes, and every
// CI pin satisfies the floor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { parse } from "yaml";

const REPO = fileURLToPath(new URL("..", import.meta.url));

test('engines.node is exactly ">=22", and every CI Node pin satisfies it', () => {
  const range = (JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { engines: { node: string } }).engines.node;
  assert.equal(range, ">=22");
  const ci = parse(readFileSync(join(REPO, ".github/workflows/ci.yml"), "utf8")) as { jobs: { verify: { strategy: { matrix: { "node-line": string[] } } } } };
  const directory = mkdtempSync(join(tmpdir(), "engine-pins-"));
  const output = join(directory, "outputs");
  let versions: Map<string, string>;
  try {
    execFileSync("sh", [join(REPO, "scripts/tool-versions.sh"), "read", "nodejs"], {
      env: { ...process.env, GITHUB_OUTPUT: output },
    });
    versions = new Map(readFileSync(output, "utf8").trim().split("\n").map((line) => {
      const [tool, version] = line.split("="); return [tool!, version!] as const;
    }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const pins = ci.jobs.verify.strategy.matrix["node-line"].map((line) => {
    const pin = versions.get(line); assert.ok(pin, `${line}: CI runtime has no exact tool pin`); return pin;
  });
  assert.ok(pins.length >= 2, `CI pins: ${pins.join(", ")}`);
  for (const pin of pins) assert.ok(semver.satisfies(pin, range), `${pin} satisfies ${range}`);
});

test("the companion signer resolves only this checkout's verifier", () => {
  const selector = "@bounded-authority-protocol/signer>@bounded-authority-protocol/verifier";
  const manifest = JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as {
    pnpm: { overrides: Record<string, string> };
  };
  const lock = parse(readFileSync(join(REPO, "pnpm-lock.yaml"), "utf8")) as {
    overrides: Record<string, string>;
    snapshots: Record<string, { dependencies?: Record<string, string> }>;
  };
  assert.equal(manifest.pnpm.overrides[selector], "link:.");
  assert.equal(lock.overrides[selector], "link:.");
  const signers = Object.entries(lock.snapshots).filter(([name]) => name.startsWith("@bounded-authority-protocol/signer@"));
  assert.ok(signers.length > 0, "the lock must include the companion signer");
  for (const [name, snapshot] of signers) {
    // pnpm 10 normalizes the root-relative link:. to link: in dependency snapshots.
    assert.equal(snapshot.dependencies?.["@bounded-authority-protocol/verifier"], "link:", name);
  }
});
