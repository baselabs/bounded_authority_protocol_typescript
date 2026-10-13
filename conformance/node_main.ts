// The shared entry of the thin Node runners (conformance/run*.ts): load the corpus from disk, run the
// runtime-neutral core, print its summary, and hold its verdict digest to the pin in
// conformance/verdict-digests.json. Any disagreement, abort, or digest mismatch exits nonzero.
import { readFileSync } from "node:fs";
import { BACKEND_ID } from "../src/index.js";
import { fsSource } from "./node_source.js";
import { verdictDigest } from "./digest.js";
import { CoreAbort, type Core } from "./core/types.js";

export interface PinnedDigests {
  readonly digests: Record<string, { readonly cases: number; readonly sha256: string }>;
}

export function pinnedDigests(): PinnedDigests {
  return JSON.parse(readFileSync(new URL("./verdict-digests.json", import.meta.url), "utf8")) as PinnedDigests;
}

export function runCore(core: Core): void {
  let report;
  try {
    report = core.run(fsSource());
  } catch (e) {
    if (e instanceof CoreAbort) {
      console.error(`${e.prefix}: ${e.message}`);
      process.exit(1);
    }
    throw e;
  }
  if (report.failures.length > 0) {
    for (const f of report.failures.slice(0, 50)) console.error(`  DISAGREE ${f}`);
    if (report.failures.length > 50) console.error(`  ... and ${report.failures.length - 50} more`);
    console.error(`${core.corpus}: ${report.failures.length} FAILURE(S) of ${report.verdicts.length} cases`);
    process.exit(1);
  }
  for (const line of report.summary) console.log(line);
  const digest = verdictDigest(report.verdicts);
  const pin = pinnedDigests().digests[core.corpus];
  console.log(`${core.corpus}: verdict digest ${digest} over ${report.verdicts.length} cases (backend ${BACKEND_ID})`);
  if (!pin || pin.sha256 !== digest || pin.cases !== report.verdicts.length) {
    console.error(`${core.corpus}: verdict digest differs from conformance/verdict-digests.json (${pin ? `${pin.sha256} over ${pin.cases}` : "no pin"})`);
    process.exit(1);
  }
}
