// Load offline, run the core, and hold computed verdicts to the corpus-derived digest.
import { BACKEND_ID } from "../src/index.js";
import { fsSource } from "./node_source.js";
import { assertVerdictDigest } from "./certification.js";
import { CoreAbort, type Core } from "./core/types.js";
export function runCore(core: Core): void {
  try {
    const source = fsSource(), report = core.run(source);
    const digest = assertVerdictDigest(source, core.dir, report.verdicts);
    if (report.failures.length > 0) {
      for (const f of report.failures.slice(0, 50)) console.error(`  DISAGREE ${f}`);
      throw new CoreAbort(core.corpus, `${report.failures.length} FAILURE(S) of ${report.verdicts.length} cases`);
    }
    for (const line of report.summary) console.log(line);
    console.log(`${core.corpus}: verdict digest ${digest} over ${report.verdicts.length} cases (backend ${BACKEND_ID})`);
  } catch (error) {
    console.error(error instanceof CoreAbort ? `${error.prefix}: ${error.message}` : String(error));
    process.exit(1);
  }
}
