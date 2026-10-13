// Shared by the runtime and browser lane tests: the Node reference verdicts (node backend, computed in
// this process from the same corpus bytes) and the comparison every lane report is held to.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { BACKEND_ID } from "../../src/index.js";
import { CORES } from "../../conformance/core/index.js";
import { fsSource } from "../../conformance/node_source.js";
import { firstDifferences, verdictDigest } from "../../conformance/digest.js";
import type { VerdictEntry } from "../../conformance/core/types.js";

export interface LaneCorpus { cases: number; digest: string; ms: number; failures: string[]; verdicts: VerdictEntry[] }

const PINS = JSON.parse(readFileSync(new URL("../../conformance/verdict-digests.json", import.meta.url), "utf8")) as {
  digests: Record<string, { cases: number; sha256: string }>;
};

let reference: Map<string, VerdictEntry[]> | null = null;
export function nodeReference(): Map<string, VerdictEntry[]> {
  if (reference === null) {
    assert.equal(BACKEND_ID, "node", "the reference verdicts come from the node backend");
    reference = new Map(CORES.map((core) => [core.corpus, [...core.run(fsSource()).verdicts]]));
  }
  return reference;
}

// Every corpus present, agreeing with its corpus, equal to the pin, and equal case by case to Node.
export function assertLaneAgrees(label: string, corpora: Record<string, LaneCorpus>): void {
  assert.deepEqual(Object.keys(corpora).sort(), CORES.map((c) => c.corpus).sort(), `${label}: every corpus ran`);
  for (const [corpus, got] of Object.entries(corpora)) {
    assert.deepEqual(got.failures, [], `${label} ${corpus}: disagreements with the corpus`);
    const ref = nodeReference().get(corpus)!;
    const diff = firstDifferences(ref, got.verdicts);
    assert.deepEqual(diff, [], `${label} ${corpus}: first verdicts that differ from Node (node backend | ${label})`);
    assert.equal(verdictDigest(got.verdicts), got.digest, `${label} ${corpus}: reported digest is the digest of the reported verdicts`);
    assert.equal(got.digest, PINS.digests[corpus]!.sha256, `${label} ${corpus}: digest equals conformance/verdict-digests.json`);
    assert.equal(got.cases, PINS.digests[corpus]!.cases, `${label} ${corpus}: case count`);
  }
}

export function summarize(corpora: Record<string, LaneCorpus>): string {
  return Object.entries(corpora).map(([k, v]) => `${k} ${v.cases} cases ${v.ms} ms`).join(", ");
}
