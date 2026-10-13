// The runtime-neutral conformance contract. A core receives the corpus through a CorpusSource and
// returns a CoreReport; it never touches a filesystem, a process, or a runtime global, so the same
// core runs on Node, Deno, Bun, and in a browser page. Loaders (conformance/node_source.ts for the
// runtimes with node:fs, browser/loader.ts for pages) are the only I/O.

// Every path is relative to the conformance/ directory and "/"-separated, e.g. "corpus-v2/index.json".
export interface CorpusSource {
  // The exact bytes of one corpus file. Throws when the file is absent.
  read(path: string): Uint8Array;
  // Every file under a directory (recursively), relative to that directory, "/"-separated.
  list(dir: string): string[];
}

// A fail-closed stop: corpus integrity (index pin, file set, counts) or a runner invariant broke.
// The loader prints `${prefix}: ${message}` and exits nonzero, as the single-file runners did.
export class CoreAbort extends Error {
  constructor(readonly prefix: string, message: string) {
    super(message);
    this.name = "CoreAbort";
  }
}

// One case's verdict projection: [case id, canonical text of the verdict the SDK computed].
export type VerdictEntry = readonly [string, string];

export interface CoreReport {
  // The corpus name, stable across lanes ("v1", "v2", "v3", "local-loopback-http", ...).
  readonly corpus: string;
  // Lines a successful run prints (the single-file runners' output, unchanged).
  readonly summary: readonly string[];
  // Disagreements with the corpus; nonempty means the run failed.
  readonly failures: readonly string[];
  // Every case's verdict projection, in corpus order. Its digest is the cross-lane identity.
  readonly verdicts: readonly VerdictEntry[];
}

export interface Core {
  readonly corpus: string;
  // The corpus directory under conformance/.
  readonly dir: string;
  run(source: CorpusSource): CoreReport;
}
