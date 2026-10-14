// The portable backend (src/crypto/portable.ts) is what browsers, Deno, Bun and workers run. Its Ed25519
// verify must be the explicit COFACTORLESS check behind the same byte-level gate as the Node build, not
// noble's own verify (cofactored in both zip215 modes). This suite (retargeted in 0.7.0 from the 0.6.0
// playground shim, which the portable backend replaced) bundles src/ed25519.ts for the browser the way
// a consumer's bundler does under the bap-portable condition (no alias, no injected Buffer), loads the
// bundle, and holds it to the strict corpus's verify cases and to the mixed-order pin that makes noble's
// own verify unfit for the job. (The bench page's node:crypto adapter, which this suite also held to the
// backend, was removed when the bench moved to the browser-safe signer 0.5.0.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { verify as nobleVerify, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

import { ed25519Cofactorless, ed25519Key } from "../src/crypto/portable.js";
// @ts-expect-error tools/browser-guard.mjs is untyped JavaScript
import { scanUnresolvedGlobals } from "../tools/browser-guard.mjs";
import {
  BASE, L, P, add, bigToLe, challenge, classifyEncoding, concat, encodePoint, findCofactorlessSignature, forgeUnderSmallOrderKey, keyHolder,
  leToBig, multiply, publicKeyFromSeed, signHonest, torsionPoints, verifyStrictReference,
} from "./support/ed25519_reference.js";

hashes.sha512 = sha512;

const REPO = fileURLToPath(new URL("..", import.meta.url));
const CORPUS = fileURLToPath(new URL("../conformance/corpus-strict-ed25519/", import.meta.url));

interface Bundle {
  verifyStrict(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
  acceptablePublicKey(publicKey: Uint8Array): boolean;
  torsionFree(publicKey: Uint8Array): boolean;
  importPublicKey(raw: Uint8Array, fingerprint: string): unknown;
  ed25519Verify(message: Uint8Array, signature: Uint8Array, key: unknown): boolean;
}

async function loadPortableBundle(): Promise<Bundle> {
  const result = await build({
    stdin: {
      contents: 'export { verifyStrict, acceptablePublicKey, torsionFree, importPublicKey, ed25519Verify } from "./src/ed25519.ts";',
      resolveDir: REPO,
      sourcefile: "portable-entry.ts",
      loader: "ts",
    },
    bundle: true,
    write: false,
    format: "esm",
    target: "es2022",
    platform: "browser",
    // The source tree under the portable condition, as a browser bundler sees the package.
    conditions: ["bap-source", "bap-portable"],
    logLevel: "silent",
  });
  const code = result.outputFiles[0]!.text;
  assert.ok(!/node:crypto/.test(code), "the bundle must not reach node:crypto");
  assert.deepEqual(await scanUnresolvedGlobals(code), [], "no free Node global (Buffer, process) and no eval in the bundle");
  return (await import(`data:text/javascript;base64,${Buffer.from(code).toString("base64")}`)) as Bundle;
}

const b64d = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const enc = (s: string) => new TextEncoder().encode(s);

interface VerifyCase { id: string; expected: { verdict: string }; input: { message: string; signature: string; public_key: string } }
function corpusVerifyCases(): VerifyCase[] {
  const index = JSON.parse(readFileSync(`${CORPUS}index.json`, "utf8")) as { files: Array<{ path: string }> };
  const out: VerifyCase[] = [];
  for (const f of index.files) {
    if (!/^cases\/(primitive|differential|taming)\//.test(f.path)) continue;
    out.push(...(JSON.parse(readFileSync(`${CORPUS}${f.path}`, "utf8")) as { cases: VerifyCase[] }).cases);
  }
  return out;
}

test("the portable browser bundle agrees with every verify case of the strict corpus (primitive, differential, taming)", async () => {
  const bundle = await loadPortableBundle();
  const cases = corpusVerifyCases();
  assert.equal(cases.length, 185 + 1024 + 12);
  const wrong: string[] = [];
  let accepted = 0;
  for (const c of cases) {
    const got = bundle.verifyStrict(b64d(c.input.message), b64d(c.input.signature), b64d(c.input.public_key));
    if (got) accepted += 1;
    if (got !== (c.expected.verdict === "valid")) wrong.push(c.id);
  }
  assert.deepEqual(wrong, []);
  assert.ok(accepted > 50, `the corpus accepts some inputs through the portable bundle (${accepted})`);
});

test("the portable bundle's key import and verify path rejects weak keys and verifies honest signatures", async () => {
  const bundle = await loadPortableBundle();
  const seed = new Uint8Array(32).fill(3);
  const publicKey = publicKeyFromSeed(seed);
  const message = enc("portable-honest");
  const signature = signHonest(seed, message);
  const key = bundle.importPublicKey(publicKey, "fp");
  assert.equal(bundle.ed25519Verify(message, signature, key), true);
  assert.equal(bundle.ed25519Verify(enc("portable-honest!"), signature, key), false);
  assert.throws(() => bundle.importPublicKey(new Uint8Array(32), "fp"));
  const identity = new Uint8Array(32); identity[0] = 1;
  assert.throws(() => bundle.importPublicKey(identity, "fp"));
  // Forged R = identity, S = 0 under the identity key: refused (by the key gate, and by the verify gate).
  assert.equal(bundle.verifyStrict(message, concat(identity, new Uint8Array(32)), identity), false);
  assert.equal(bundle.acceptablePublicKey(publicKey), true);
  assert.equal(bundle.torsionFree(publicKey), true);
});

test("honestA-mixedR: noble verify (zip215 true AND false) accepts it, the portable cofactorless check refuses it", async () => {
  const bundle = await loadPortableBundle();
  const holder = keyHolder(new Uint8Array(32).fill(8));
  const publicKey = encodePoint(holder.prime);
  const message = enc("mixed-r");
  const r = 12345n;
  // R carries an order-8 torsion component (T1, derived by arithmetic); S comes from the key holder, so
  // only the COFACTORED equation holds.
  const rPoint = add(multiply(r, BASE), torsionPoints()[1]!);
  const rBytes = encodePoint(rPoint);
  const s = (r + challenge(rBytes, publicKey, message) * holder.scalar) % L;
  const signature = concat(rBytes, bigToLe(s, 32));
  assert.equal(nobleVerify(signature, message, publicKey), true, "noble default (zip215 true) accepts");
  assert.equal(nobleVerify(signature, message, publicKey, { zip215: false }), true, "noble zip215 false accepts");
  assert.equal(verifyStrictReference(publicKey, signature, message), false, "rule S1 refuses");
  assert.equal(bundle.verifyStrict(message, signature, publicKey), false, "the portable bundle refuses");
  assert.equal(ed25519Cofactorless(ed25519Key(publicKey), message, signature), false, "the backend alone refuses");
  // Control: the same key and message, signed honestly, verify through the portable bundle.
  const honest = signHonest(new Uint8Array(32).fill(8), message);
  assert.equal(bundle.verifyStrict(message, honest, publicKey), true);
  assert.equal(leToBig(honest.subarray(32)) < L, true);
});
// The portable backend on its own (the tests above reach it behind the byte-level gate). Two of its
// checks are not redundant with that gate when the backend is called directly, and each has a tripwire
// here.

const direct = (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean => {
  try {
    return ed25519Cofactorless(ed25519Key(publicKey), message, signature);
  } catch {
    return false;
  }
};

test("backend direct: an honest signature verifies; S + L (the malleable twin) is refused by the backend itself", () => {
  const seed = new Uint8Array(32).fill(14);
  const publicKey = publicKeyFromSeed(seed);
  const message = enc("portable-direct");
  const honest = signHonest(seed, message);
  assert.equal(direct(message, honest, publicKey), true);
  const twin = concat(honest.subarray(0, 32), bigToLe(leToBig(honest.subarray(32)) + L, 32));
  // [S + L]B = [S]B, so the cofactorless equation alone would accept the twin: the S < L check is load-bearing.
  assert.equal(direct(message, twin, publicKey), false);
});

test("backend direct: a non-canonical alias key is refused by the strict point decode of the backend itself", () => {
  // The alias of the identity point with y = p + 1: a lenient (ZIP-215) decode reads it as the identity
  // and a forged signature verifies; the strict decode (zip215 = false) refuses the encoding.
  const alias = bigToLe(P + 1n, 32);
  assert.equal(classifyEncoding(alias).kind, "noncanonical");
  const forged = forgeUnderSmallOrderKey(alias, (n) => enc(`portable-alias-${n}`));
  assert.throws(() => ed25519Key(alias));
  assert.equal(direct(forged.message, forged.signature, alias), false);
});

test("the portable bundle's choke point applies the byte gate to an imported key: R = identity, S + L, noncanonical R", async () => {
  const bundle = await loadPortableBundle();
  const holder = keyHolder(new Uint8Array(32).fill(15));
  const publicKey = encodePoint(holder.prime);
  const key = bundle.importPublicKey(publicKey, "fp-portable-choke");
  const message = enc("portable-choke");
  const honest = signHonest(new Uint8Array(32).fill(15), message);
  assert.equal(bundle.ed25519Verify(message, honest, key), true, "control: an honest signature verifies");
  // R = identity built by the key holder: the cofactorless equation alone ACCEPTS it, so only the gate refuses it.
  const found = findCofactorlessSignature(holder, torsionPoints()[0]!, torsionPoints()[0]!, 0n, "portable-idr");
  assert.equal(direct(found.message, found.signature, publicKey), true, "the backend equation alone accepts it");
  assert.equal(bundle.ed25519Verify(found.message, found.signature, key), false, "the gate refuses it");
  const twin = concat(honest.subarray(0, 32), bigToLe(leToBig(honest.subarray(32)) + L, 32));
  assert.equal(bundle.ed25519Verify(message, twin, key), false);
});
