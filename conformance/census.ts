#!/usr/bin/env tsx
// Standalone two-boundary key census for @bounded-authority-protocol/verifier (BAP-09 T5). Runs ONLY the
// census (no verdict recompute): loads the corpus, dispatches every case so the verify surfaces
// import their keys at the Ed25519 boundary, then asserts discovery == verify-import ⊇ expected-
// verify-keys == index public_key_fingerprints (ADR 0005 § Census evolution; ADR 0014 Decision 9).
//
// This is the V4-hole guard as a standalone gate: a verify-surface case whose key is never actually
// fed to Ed25519 verify aborts here, catching a runner that certifies a verdict it did not compute.
// The census itself lives in the v1 core (conformance/core/v1.ts), which aborts on any census break.
import { core } from "./core/v1.js";
import { CoreAbort } from "./core/types.js";
import { fsSource } from "./node_source.js";

try {
  const report = core.run(fsSource());
  const total = report.verdicts.length;
  const fail = report.failures.length;
  console.log(`census: ran ${total} cases (${total - fail} agree, ${fail} disagree) to populate the verify-import boundary`);
  console.log(report.summary[1]!.replace("discovery == verify-import ==", "discovery == verify-import ⊇ expected-verify-keys =="));
  if (fail > 0) process.exit(1);
  console.log("census: PASS (two-boundary equal)");
} catch (e) {
  if (e instanceof CoreAbort) {
    console.error(`${e.prefix}: ${e.message}`);
    process.exit(1);
  }
  throw e;
}
