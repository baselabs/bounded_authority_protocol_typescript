// package.json "engines" keeps the deliberate consumer-facing floor ">=22" (CHANGELOG 0.2.2: "engines.node
// >= 22 stays the consumer-facing floor"); CI pins exact patch versions for its own lanes, and every
// CI pin satisfies the floor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { parse } from "yaml";

const REPO = fileURLToPath(new URL("..", import.meta.url));

test('engines.node is exactly ">=22", and every CI Node pin satisfies it', () => {
  const range = (JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { engines: { node: string } }).engines.node;
  assert.equal(range, ">=22");
  const ci = parse(readFileSync(join(REPO, ".github/workflows/ci.yml"), "utf8")) as { jobs: { verify: { strategy: { matrix: { node: string[] } } } } };
  const pins = ci.jobs.verify.strategy.matrix.node.map(String);
  assert.ok(pins.length >= 2, `CI pins: ${pins.join(", ")}`);
  for (const pin of pins) assert.ok(semver.satisfies(pin, range), `${pin} satisfies ${range}`);
});
