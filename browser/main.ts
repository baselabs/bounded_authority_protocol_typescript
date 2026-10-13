// The browser conformance lane. Runs in a real engine under the strict CSP the test server sends, with
// the package resolved the way a browser bundler resolves it (the portable backend). The page asserts
// BACKEND_ID and isSecureContext BEFORE any corpus runs, records every securitypolicyviolation, runs
// every runtime-neutral core, and publishes one result object for the Playwright test to read.
// In-page verification here is a conformance measurement, never a trust decision.
import { BACKEND_ID } from "../src/index.js";
import { CORES } from "../conformance/core/index.js";
import { CoreAbort } from "../conformance/core/types.js";
import { verdictDigest } from "../conformance/digest.js";
import { loadCorpus } from "./loader.js";

interface CorpusResult { cases: number; digest: string; ms: number; failures: string[]; verdicts: (readonly [string, string])[] }
interface LaneResult {
  backend: string; secure: boolean; userAgent: string; violations: string[]; error: string | null;
  corpora: Record<string, CorpusResult>; totalMs: number;
}

const violations: string[] = [];
document.addEventListener("securitypolicyviolation", (e) => violations.push(`${e.violatedDirective} ${e.blockedURI}`));

function publish(result: LaneResult): void {
  (window as unknown as { __BAP_RESULT__: LaneResult }).__BAP_RESULT__ = result;
  document.getElementById("out")!.textContent = JSON.stringify({ ...result, corpora: Object.fromEntries(Object.entries(result.corpora).map(([k, v]) => [k, { cases: v.cases, digest: v.digest, ms: v.ms, failures: v.failures.length }])) }, null, 2);
  document.body.dataset.state = "done";
}

async function main(): Promise<void> {
  const expected = new URLSearchParams(location.search).get("expect") ?? "portable";
  const result: LaneResult = { backend: BACKEND_ID, secure: isSecureContext, userAgent: navigator.userAgent, violations, error: null, corpora: {}, totalMs: 0 };
  if (BACKEND_ID !== expected) {
    publish({ ...result, error: `BACKEND_ID is "${BACKEND_ID}", this lane expects "${expected}"; no corpus was run` });
    return;
  }
  if (!isSecureContext) {
    publish({ ...result, error: "not a secure context; no corpus was run" });
    return;
  }
  const start = performance.now();
  const source = await loadCorpus("/conformance/");
  for (const core of CORES) {
    const t = performance.now();
    try {
      const report = core.run(source);
      result.corpora[core.corpus] = { cases: report.verdicts.length, digest: verdictDigest(report.verdicts), ms: Math.round(performance.now() - t), failures: [...report.failures], verdicts: [...report.verdicts] };
    } catch (e) {
      const message = e instanceof CoreAbort ? `${e.prefix}: ${e.message}` : String(e);
      result.corpora[core.corpus] = { cases: 0, digest: "", ms: Math.round(performance.now() - t), failures: [`abort: ${message}`], verdicts: [] };
    }
  }
  result.totalMs = Math.round(performance.now() - start);
  publish(result);
}

main().catch((e: unknown) => publish({ backend: BACKEND_ID, secure: isSecureContext, userAgent: navigator.userAgent, violations, error: String(e), corpora: {}, totalMs: 0 }));
