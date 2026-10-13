// The Deno and Bun lanes (pnpm test:runtimes, which builds first). Each runtime runs
// conformance/lanes/runtime.ts from the repository: its sources import "#crypto", which the runtime
// resolves through package.json under its own condition (deno, bun) to the built portable backend.
// The lane asserts BACKEND_ID before any corpus; this test then holds every corpus to its pin and to
// the Node verdicts case by case. BAP_RUNTIMES selects the runtimes (default "deno,bun").
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertLaneAgrees, summarize, type LaneCorpus } from "./support/lanes.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const RUNTIMES = (process.env.BAP_RUNTIMES ?? "deno,bun").split(",").filter(Boolean);
const COMMANDS: Record<string, (expect: string) => string[]> = {
  deno: (expect) => ["deno", "run", "--sloppy-imports", "--allow-read", "--allow-env", "conformance/lanes/runtime.ts", `--expect=${expect}`],
  bun: (expect) => ["bun", "conformance/lanes/runtime.ts", `--expect=${expect}`],
};

function lane(runtime: string, expect: string) {
  const [cmd, ...args] = COMMANDS[runtime]!(expect);
  const r = spawnSync(cmd!, args, { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw r.error;
  return r;
}

for (const runtime of RUNTIMES) {
  assert.ok(COMMANDS[runtime], `known runtime ${runtime}`);

  test(`${runtime}: BACKEND_ID is portable, and every corpus agrees with its pin and with Node case by case`, (t) => {
    const r = lane(runtime, "portable");
    assert.equal(r.status, 0, r.stderr);
    const report = JSON.parse(r.stdout) as { runtime: string; backend: string; ok: boolean; corpora: Record<string, LaneCorpus> };
    assert.equal(report.backend, "portable");
    assert.ok(report.runtime.startsWith(runtime), report.runtime);
    assertLaneAgrees(report.runtime, report.corpora);
    assert.equal(report.ok, true);
    t.diagnostic(`${report.runtime}: ${summarize(report.corpora)}`);
  });

  test(`${runtime}: red-proof: the lane fails, running no corpus, when it expects the wrong backend`, () => {
    const r = lane(runtime, "node");
    assert.equal(r.status, 1);
    assert.match(r.stderr, /BACKEND_ID is "portable", this lane expects "node"; no corpus was run/);
    assert.equal(r.stdout.trim(), "");
  });
}
