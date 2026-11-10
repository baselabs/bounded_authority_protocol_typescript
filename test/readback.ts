// The post-publish read-back (tools/readback.mjs; pnpm test:readback, run by CI's package job, which
// has Deno, Bun and Chromium). It reads back the published 1.0.0 against what its release run
// recorded, with the real registry and the real runtimes, and proves each binding check refuses a
// wrong value. `latest` is whatever npm names now, so this keeps passing once a later version ships.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
// @ts-expect-error tools/readback.mjs is untyped JavaScript
import { parseArgs, readback } from "../tools/readback.mjs";

// From release run 40960113087 (tag v1.0.0): "publishing …verifier-1.0.0.tgz sha256 c955f9e5…".
const V1 = {
  version: "1.0.0",
  sha256: "c955f9e5aa62ca1c3df7361a5252c00fd19b5fb4767c9eef5a741faab703c0ad",
  commit: "dec15ecaa859c519fc0727c6997c76fc7db80bd7",
  latest: execFileSync("npm", ["view", "@bounded-authority-protocol/verifier", "dist-tags.latest"], { encoding: "utf8" }).trim(),
};

test("read-back: the published 1.0.0 passes every check", async () => {
  const lines: string[] = [];
  await readback(V1, (line: string) => lines.push(line));
  assert.deepEqual(lines.map((l) => l.split(":")[0]), [
    "ok registry", "ok bytes", "ok provenance", "ok signatures", "ok quickstart", "ok Node.js", "ok Deno", "ok Bun", "ok Chromium",
  ]);
});

for (const [label, change, message] of [
  ["a tarball hash the release did not verify", { sha256: "0".repeat(64) }, /sha256 is c955f9e5.*, the release run verified 0{64}/],
  ["another commit", { commit: "1".repeat(40) }, /expected commit 1{40}/],
  ["another latest version", { latest: "0.0.1" }, /latest is .*, expected 0\.0\.1/],
] as const) {
  test(`read-back: refuses ${label}`, async () => {
    await assert.rejects(readback({ ...V1, ...change }, () => {}), message);
  });
}

test("read-back: the tarball hash is required, and options are closed", () => {
  assert.throws(() => parseArgs(["1.0.0"]), /--sha256 <64 hex digits> is required/);
  assert.throws(() => parseArgs(["1.0.0", "--sha256", V1.sha256, "--skip", "x"]), /unknown or incomplete option --skip/);
  assert.deepEqual(parseArgs(["1.0.0", "--sha256", V1.sha256, "--commit", V1.commit]), { ...V1, latest: "1.0.0" });
});
