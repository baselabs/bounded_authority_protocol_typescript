#!/usr/bin/env tsx
// Every corpus in one run, after asserting which backend this process resolved. `pnpm
// conformance:portable` runs it under --conditions=bap-portable, so the portable backend is held to the
// same pinned verdict digests as the node backend. Usage: run_all.ts --backend=<node|portable>.
import { BACKEND_ID } from "../src/index.js";
import { runCore } from "./node_main.js";
import { CORES } from "./core/index.js";

const want = process.argv.find((a) => a.startsWith("--backend="))?.slice("--backend=".length);
if (want !== "node" && want !== "portable") {
  console.error("run_all: pass --backend=node or --backend=portable");
  process.exit(2);
}
if (BACKEND_ID !== want) {
  console.error(`run_all: BACKEND_ID is "${BACKEND_ID}", this lane expects "${want}"`);
  process.exit(1);
}
console.log(`run_all: BACKEND_ID ${BACKEND_ID}`);
for (const core of CORES) runCore(core);
console.log(`run_all: PASS (${CORES.length} corpora, every verdict digest equals conformance/verdict-digests.json)`);
