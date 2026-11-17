#!/usr/bin/env tsx
// The standalone census dispatches cases to collect actual verification imports.
// Discovery must equal index fingerprints, and every key from a valid verification
// case must appear at the Ed25519 boundary. The v1 core owns these checks. Merely
// discovering a key cannot certify that its signature was verified.
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
