// The Deno and Bun conformance lane (also runnable on Node): asserts the resolved BACKEND_ID first, then
// runs every runtime-neutral core over the corpus read through node:fs (both runtimes provide it) and
// prints one JSON report on stdout: the runtime, the backend, and per corpus the case count, verdict
// digest, wall time, failures and the full verdict list (so the Node-side test can name the first
// differing cases). Exit status: 0 only if the backend matches --expect and every corpus agrees with
// its corpus and with conformance/verdict-digests.json.
//
// Run from the repository root after `pnpm build` (the "#crypto" import resolves to the built backend
// under the deno and bun conditions):
//   deno run --sloppy-imports --allow-read conformance/lanes/runtime.ts --expect=portable
//   bun conformance/lanes/runtime.ts --expect=portable
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { BACKEND_ID } from "../../src/index.js";
import { CORES } from "../core/index.js";
import { CoreAbort } from "../core/types.js";
import { fsSource } from "../node_source.js";
import { verdictDigest } from "../digest.js";

declare const Deno: { version: { deno: string } } | undefined;
declare const Bun: { version: string } | undefined;

const runtime = typeof Deno !== "undefined" ? `deno ${Deno.version.deno}` : typeof Bun !== "undefined" ? `bun ${Bun.version}` : `node ${process.version}`;
const args = typeof Deno !== "undefined" ? (globalThis as unknown as { Deno: { args: string[] } }).Deno.args : process.argv.slice(2);
const expect = args.find((a) => a.startsWith("--expect="))?.slice("--expect=".length);
const exit = (code: number): never => {
  if (typeof Deno !== "undefined") (globalThis as unknown as { Deno: { exit(c: number): never } }).Deno.exit(code);
  process.exit(code);
};

if (expect !== "node" && expect !== "portable") {
  console.error("runtime lane: pass --expect=node or --expect=portable");
  exit(2);
}
if (BACKEND_ID !== expect) {
  console.error(`runtime lane (${runtime}): BACKEND_ID is "${BACKEND_ID}", this lane expects "${expect}"; no corpus was run`);
  exit(1);
}

const pins = JSON.parse(readFileSync(new URL("../verdict-digests.json", import.meta.url), "utf8")) as {
  digests: Record<string, { cases: number; sha256: string }>;
};
const source = fsSource(fileURLToPath(new URL("..", import.meta.url)));
const corpora: Record<string, { cases: number; digest: string; ms: number; failures: string[]; pinned: boolean; verdicts: (readonly [string, string])[] }> = {};
let ok = true;
for (const core of CORES) {
  const start = performance.now();
  try {
    const report = core.run(source);
    const digest = verdictDigest(report.verdicts);
    const pin = pins.digests[core.corpus];
    const pinned = pin !== undefined && pin.sha256 === digest && pin.cases === report.verdicts.length;
    ok &&= pinned && report.failures.length === 0;
    corpora[core.corpus] = { cases: report.verdicts.length, digest, ms: Math.round(performance.now() - start), failures: [...report.failures], pinned, verdicts: [...report.verdicts] };
  } catch (e) {
    ok = false;
    const message = e instanceof CoreAbort ? `${e.prefix}: ${e.message}` : String(e);
    corpora[core.corpus] = { cases: 0, digest: "", ms: Math.round(performance.now() - start), failures: [`abort: ${message}`], pinned: false, verdicts: [] };
  }
}
console.log(JSON.stringify({ runtime, backend: BACKEND_ID, ok, corpora }));
exit(ok ? 0 : 1);
