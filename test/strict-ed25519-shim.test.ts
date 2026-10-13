// The browser playground shim (web/shim/node-crypto.ts) stands in for node:crypto in the esbuild bundle.
// Its Ed25519 verify must be the explicit COFACTORLESS check behind the same byte-level gate as the Node
// build, not noble's default (zip215, cofactored). This suite bundles src/ed25519.ts exactly as
// `pnpm build:site` does (the node:crypto alias onto the shim, the Buffer global injected), loads the
// bundle, and holds it to the strict corpus's verify cases and to the mixed-order pin that makes noble's
// own verify unfit for the job.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { verify as nobleVerify, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

import { createPublicKey as shimCreatePublicKey, verifyEd25519 as shimVerify } from "../web/shim/node-crypto.js";
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

async function loadShimBundle(): Promise<Bundle> {
  const result = await build({
    stdin: {
      contents: 'export { verifyStrict, acceptablePublicKey, torsionFree, importPublicKey, ed25519Verify } from "./src/ed25519.ts";',
      resolveDir: REPO,
      sourcefile: "shim-entry.ts",
      loader: "ts",
    },
    bundle: true,
    write: false,
    format: "esm",
    target: "es2022",
    platform: "browser",
    alias: { "node:crypto": `${REPO}web/shim/node-crypto.ts` },
    inject: [`${REPO}web/shim/buffer-global.ts`],
    logLevel: "silent",
  });
  const code = result.outputFiles[0]!.text;
  assert.ok(!/from\s*["']node:crypto["']/.test(code), "the bundle must not reach the real node:crypto");
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

test("the shimmed bundle agrees with every verify case of the strict corpus (primitive, differential, taming)", async () => {
  const shim = await loadShimBundle();
  const cases = corpusVerifyCases();
  assert.equal(cases.length, 185 + 1024 + 12);
  const wrong: string[] = [];
  let accepted = 0;
  for (const c of cases) {
    const got = shim.verifyStrict(b64d(c.input.message), b64d(c.input.signature), b64d(c.input.public_key));
    if (got) accepted += 1;
    if (got !== (c.expected.verdict === "valid")) wrong.push(c.id);
  }
  assert.deepEqual(wrong, []);
  assert.ok(accepted > 50, `the corpus accepts some inputs through the shim (${accepted})`);
});

test("the shimmed key import and verify path rejects weak keys and verifies honest signatures", async () => {
  const shim = await loadShimBundle();
  const seed = new Uint8Array(32).fill(3);
  const publicKey = publicKeyFromSeed(seed);
  const message = enc("shim-honest");
  const signature = signHonest(seed, message);
  const key = shim.importPublicKey(publicKey, "fp");
  assert.equal(shim.ed25519Verify(message, signature, key), true);
  assert.equal(shim.ed25519Verify(enc("shim-honest!"), signature, key), false);
  assert.throws(() => shim.importPublicKey(new Uint8Array(32), "fp"));
  const identity = new Uint8Array(32); identity[0] = 1;
  assert.throws(() => shim.importPublicKey(identity, "fp"));
  // Forged R = identity, S = 0 under the identity key: refused (by the key gate, and by the verify gate).
  assert.equal(shim.verifyStrict(message, concat(identity, new Uint8Array(32)), identity), false);
  assert.equal(shim.acceptablePublicKey(publicKey), true);
  assert.equal(shim.torsionFree(publicKey), true);
});

test("honestA-mixedR: noble verify (zip215 true AND false) accepts it, the explicit cofactorless shim refuses it", async () => {
  const shim = await loadShimBundle();
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
  assert.equal(shim.verifyStrict(message, signature, publicKey), false, "the shim refuses");
  // Control: the same key and message, signed honestly, verify through the shim.
  const honest = signHonest(new Uint8Array(32).fill(8), message);
  assert.equal(shim.verifyStrict(message, honest, publicKey), true);
  assert.equal(leToBig(honest.subarray(32)) < L, true);
});
// The shim function on its own (the Node tests above reach it behind the byte-level gate). Two of its
// checks are not redundant with that gate when the shim is called directly, and each has a tripwire here.

const shimKey = (raw: Uint8Array) =>
  shimCreatePublicKey({ key: Uint8Array.from([...Buffer.from("302a300506032b6570032100", "hex"), ...raw]) });

test("shim direct: an honest signature verifies; S + L (the malleable twin) is refused by the shim itself", () => {
  const seed = new Uint8Array(32).fill(14);
  const publicKey = publicKeyFromSeed(seed);
  const message = enc("shim-direct");
  const honest = signHonest(seed, message);
  assert.equal(shimVerify(null, message, shimKey(publicKey), honest), true);
  const twin = concat(honest.subarray(0, 32), bigToLe(leToBig(honest.subarray(32)) + L, 32));
  // [S + L]B = [S]B, so the cofactorless equation alone would accept the twin: the S < L check is load-bearing.
  assert.equal(shimVerify(null, message, shimKey(publicKey), twin), false);
});

test("shim direct: a non-canonical alias key is refused by the strict point decode of the shim itself", () => {
  // The alias of the identity point with y = p + 1: a lenient (ZIP-215) decode reads it as the identity
  // and a forged signature verifies; the strict decode (zip215 = false) refuses the encoding.
  const alias = bigToLe(P + 1n, 32);
  assert.equal(classifyEncoding(alias).kind, "noncanonical");
  const forged = forgeUnderSmallOrderKey(alias, (n) => enc(`shim-alias-${n}`));
  assert.equal(shimVerify(null, forged.message, shimKey(alias), forged.signature), false);
});

test("the shimmed choke point applies the byte gate to an imported key: R = identity, S + L, noncanonical R", async () => {
  const shim = await loadShimBundle();
  const holder = keyHolder(new Uint8Array(32).fill(15));
  const publicKey = encodePoint(holder.prime);
  const key = shim.importPublicKey(publicKey, "fp-shim-choke");
  const message = enc("shim-choke");
  const honest = signHonest(new Uint8Array(32).fill(15), message);
  assert.equal(shim.ed25519Verify(message, honest, key), true, "control: an honest signature verifies");
  // R = identity built by the key holder: the shim cofactorless equation alone ACCEPTS it, so only the gate refuses it.
  const found = findCofactorlessSignature(holder, torsionPoints()[0]!, torsionPoints()[0]!, 0n, "shim-idr");
  assert.equal(shimVerify(null, found.message, shimKey(publicKey), found.signature), true, "the shim equation alone accepts it");
  assert.equal(shim.ed25519Verify(found.message, found.signature, key), false, "the gate refuses it");
  const twin = concat(honest.subarray(0, 32), bigToLe(leToBig(honest.subarray(32)) + L, 32));
  assert.equal(shim.ed25519Verify(message, twin, key), false);
});
