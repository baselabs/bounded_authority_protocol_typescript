// The runtime-neutral conformance cores (conformance/core/*). Each core must fail closed on a
// one-byte-tampered index.json (the certified pin is checked by the core itself, not by a loader),
// must agree with every case of its corpus, and must reproduce the pinned verdict digest, which is
// the identity every runtime lane (Node with either backend, Deno, Bun, browsers) is held to.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fsSource } from "../conformance/node_source.js";
import { CoreAbort, type CorpusSource } from "../conformance/core/types.js";
import { CORES } from "../conformance/core/index.js";
import { firstDifferences, verdictDigest } from "../conformance/digest.js";

const source = fsSource();
const PINNED = JSON.parse(readFileSync(new URL("../conformance/verdict-digests.json", import.meta.url), "utf8")) as {
  digests: Record<string, { cases: number; sha256: string }>;
};

// Flip the case of the first ASCII letter that opens a JSON string, so the file stays valid JSON
// (a key or value changes) and only the pin can catch it.
function tamperedIndex(inner: CorpusSource, indexPath: string): CorpusSource {
  return {
    read(path) {
      const bytes = inner.read(path);
      if (path !== indexPath) return bytes;
      const text = new TextDecoder().decode(bytes);
      const at = text.search(/"[a-z]/) + 1;
      assert.ok(at > 0, "index.json has a string to tamper");
      const out = new Uint8Array(bytes);
      out[at] = out[at]! ^ 0x20;
      return out;
    },
    list: (dir) => inner.list(dir),
  };
}

test("eight cores, one per certified corpus", () => {
  assert.deepEqual(CORES.map((c) => c.corpus).sort(), [
    "content-assertion", "local-loopback-http", "producer-canonicality", "role-attestation", "strict-ed25519", "v1", "v2", "v3",
  ]);
});

for (const core of CORES) {
  test(`${core.corpus}: a one-byte-tampered index.json aborts before any verdict`, () => {
    assert.throws(() => core.run(tamperedIndex(source, `${core.dir}/index.json`)), CoreAbort);
  });

  test(`${core.corpus}: every case agrees and the verdict digest matches the pin`, () => {
    const report = core.run(source);
    assert.deepEqual(report.failures, []);
    const pin = PINNED.digests[core.corpus];
    assert.ok(pin, `a pinned digest for ${core.corpus}`);
    assert.equal(report.verdicts.length, pin.cases);
    assert.equal(verdictDigest(report.verdicts), pin.sha256);
  });
}

test("the verdict digest is order-sensitive and projection-sensitive", () => {
  const a = [["case-a", "invalid"], ["case-b", '{"ok":true}']] as const;
  const reordered = [a[1], a[0]] as const;
  const changed = [a[0], ["case-b", "invalid"]] as const;
  assert.notEqual(verdictDigest(a), verdictDigest(reordered));
  assert.notEqual(verdictDigest(a), verdictDigest(changed));
  assert.equal(verdictDigest(a), verdictDigest([...a]));
  assert.deepEqual(firstDifferences(a, changed), ['#1: case-b => {"ok":true} | case-b => invalid']);
});
