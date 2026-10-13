// Non-vacuity of the portable backend's two load-bearing choices, proven by building the REAL cores and
// profile modules with esbuild and swapping one thing at a time (the variant backends live only in this
// file, as esbuild virtual modules):
//   1. Ed25519 must be the explicit cofactorless check: a portable variant that calls noble's own
//      verify (zip215 true, then false) changes the strict corpus's verdict digest.
//   2. P-256 must pass lowS: false: with the profile's low-S gate removed (the permissiveness mutation),
//      the real portable backend lets the v3 corpus's high-S case through, so the corpus run goes red;
//      a variant with noble's default lowS: true hides the mutation (the run stays green), which is the
//      hidden second gate the design rules out.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build, type Plugin } from "esbuild";
import { fsSource } from "../conformance/node_source.js";
import type { Core } from "../conformance/core/types.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const PORTABLE = `${REPO}src/crypto/portable.ts`;
const PINS = JSON.parse(readFileSync(new URL("../conformance/verdict-digests.json", import.meta.url), "utf8")) as {
  digests: Record<string, { sha256: string }>;
};

interface Built { v3: Core; strict: Core; verdictDigest(v: readonly (readonly [string, string])[]): string; BACKEND_ID: string }

const LOW_S_GATE = 'if (s > HALF_N) fail("es256: high-s form (low-s required)");';

async function buildWith(cryptoModule: string | null, removeLowSGate: boolean): Promise<Built> {
  const plugin: Plugin = {
    name: "variant",
    setup(b) {
      b.onResolve({ filter: /^#crypto$/ }, () => (cryptoModule === null ? { path: PORTABLE } : { path: "variant", namespace: "variant" }));
      b.onLoad({ filter: /.*/, namespace: "variant" }, () => ({ contents: cryptoModule ?? "", loader: "ts", resolveDir: REPO }));
      b.onLoad({ filter: /src[\\/]es256\.ts$/ }, (args) => {
        const source = readFileSync(args.path, "utf8");
        assert.ok(source.includes(LOW_S_GATE), "the low-S gate line exists to be removed");
        return { contents: removeLowSGate ? source.replace(LOW_S_GATE, "") : source, loader: "ts" };
      });
    },
  };
  const result = await build({
    stdin: {
      contents: [
        'export { core as v3 } from "./conformance/core/v3.ts";',
        'export { core as strict } from "./conformance/core/strict_ed25519.ts";',
        'export { verdictDigest } from "./conformance/digest.ts";',
        'export { BACKEND_ID } from "./src/index.ts";',
      ].join("\n"),
      resolveDir: REPO,
      sourcefile: "variant-entry.ts",
      loader: "ts",
    },
    bundle: true,
    write: false,
    format: "esm",
    platform: "neutral",
    mainFields: ["module", "main"],
    plugins: [plugin],
    logLevel: "silent",
  });
  const code = result.outputFiles[0]!.text;
  return (await import(`data:text/javascript;base64,${Buffer.from(code).toString("base64")}`)) as Built;
}

const nobleVerifyVariant = (zip215: boolean) => `
export { BACKEND_ID, sha256, sha256Concat, ed25519Key, p256Key, p256Verify } from ${JSON.stringify(PORTABLE)};
import { verify, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
hashes.sha512 = sha512;
export function ed25519Cofactorless(key: { raw: Uint8Array }, message: Uint8Array, sig: Uint8Array): boolean {
  return verify(sig, message, key.raw, { zip215: ${zip215} });
}
`;

const lowSTrueVariant = `
export { BACKEND_ID, sha256, sha256Concat, ed25519Key, ed25519Cofactorless, p256Key } from ${JSON.stringify(PORTABLE)};
import { p256 } from "@noble/curves/nist.js";
export function p256Verify(key: { raw: Uint8Array }, message: Uint8Array, sig: Uint8Array): boolean {
  return p256.verify(sig, message, key.raw, { lowS: true, prehash: true, format: "compact" });
}
`;

const source = fsSource();

test("control: the real portable backend, built the same way, matches every pinned digest it is run on", async () => {
  const real = await buildWith(null, false);
  assert.equal(real.BACKEND_ID, "portable");
  for (const core of [real.v3, real.strict]) {
    const report = core.run(source);
    assert.deepEqual(report.failures, []);
    assert.equal(real.verdictDigest(report.verdicts), PINS.digests[core.corpus]!.sha256);
  }
});

for (const zip215 of [true, false]) {
  test(`noble verify (zip215: ${zip215}) in place of the cofactorless check changes the strict corpus digest`, async () => {
    const variant = await buildWith(nobleVerifyVariant(zip215), false);
    const report = variant.strict.run(source);
    assert.notEqual(variant.verdictDigest(report.verdicts), PINS.digests["strict-ed25519"]!.sha256);
    assert.ok(report.failures.length > 0, "the strict corpus disagrees with a cofactored verify");
  });
}

test("with the profile low-S gate removed, the real portable backend (lowS: false) lets the v3 corpus go red", async () => {
  const mutated = await buildWith(null, true);
  const report = mutated.v3.run(source);
  assert.ok(report.failures.some((f) => f.startsWith("verify-grant-v3-invalid-signature-high-s ")), report.failures.join("\n"));
});

test("with the profile low-S gate removed, a lowS: true backend hides the mutation (why the backend passes lowS: false)", async () => {
  const hidden = await buildWith(lowSTrueVariant, true);
  const report = hidden.v3.run(source);
  assert.deepEqual(report.failures, [], "a hidden backend gate keeps the corpus green with the profile gate gone");
});
