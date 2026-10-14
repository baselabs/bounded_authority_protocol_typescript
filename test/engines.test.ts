// package.json "engines" states what is tested: its Node floor is the lowest Node version CI runs the
// verify lanes on, and every CI Node pin satisfies it. A floor below what CI tests is a claim no check
// backs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { parse } from "yaml";

const REPO = fileURLToPath(new URL("..", import.meta.url));

test("engines.node starts at the lowest Node version CI tests, and every CI pin satisfies it", () => {
  const range = (JSON.parse(readFileSync(join(REPO, "package.json"), "utf8")) as { engines: { node: string } }).engines.node;
  const ci = parse(readFileSync(join(REPO, ".github/workflows/ci.yml"), "utf8")) as { jobs: { verify: { strategy: { matrix: { node: string[] } } } } };
  const pins = ci.jobs.verify.strategy.matrix.node.map(String);
  assert.ok(pins.length >= 2 && pins.every((v) => semver.valid(v)), `CI pins: ${pins.join(", ")}`);
  const lowest = pins.sort(semver.compare)[0]!;
  assert.equal(semver.minVersion(range)?.version, lowest, `engines.node "${range}" must start at ${lowest}`);
  for (const pin of pins) assert.ok(semver.satisfies(pin, range), `${pin} satisfies ${range}`);
});
