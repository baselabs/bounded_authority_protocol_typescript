import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

test("the documented SQLite replay store survives independent contenders and restart", () => {
  const file = fileURLToPath(new URL("../docs/examples/durable-replay.ts", import.meta.url));
  const result = spawnSync(process.execPath, [file], { encoding: "utf8", timeout: 120_000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "durable replay: one winner, restart refused, distinct tuples accepted");
});
