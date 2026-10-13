// Key acceptance at every place a key enters the verifier (rule S1, REQ1-KEY-ed25519-acceptable):
// the JWK encode / decode / thumbprint set is FALLIBLE (a weak key is refused with the closed error), the
// producers refuse a weak key before they emit a byte, the raw hash-only thumbprint path stays usable
// for censuses and generators, and a test pins that path's callers. Every refusal has a positive
// control: the same call with a generated key succeeds.
import { test } from "node:test";
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { InvalidError } from "../src/error.js";
import { sha256 } from "../src/ed25519.js";
import { base64urlEncode } from "../src/base64url.js";
import { strUtf8, type Tagged } from "../src/json.js";
import { jcsEncode } from "../src/jcs.js";
import {
  jwkDecodePublic, jwkEncodePublic, jwkFromPublicKey, publicKeyThumbprintRaw, thumbprint, thumbprintDigestUnchecked,
  thumbprintPreimage, thumbprintRaw,
} from "../src/jwk.js";
import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import * as ra from "../src/role_attestation.js";
import { assembleSegments } from "../src/compact.js";
import { offCurveEncodings, smallOrderEncodings, weakEncodings } from "./support/ed25519_reference.js";

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fresh = () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  return { raw: new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32)), privateKey };
};
const WEAK = [...weakEncodings(), ...offCurveEncodings(4), new Uint8Array(32)];
const IDENTITY = smallOrderEncodings()[0]!;

test("control: a generated key passes every function of the fallible JWK set", () => {
  const { raw } = fresh();
  const jwk = jwkFromPublicKey(raw);
  assert.equal(jwk.x, text(base64urlEncode(raw)));
  assert.equal(jwkDecodePublic(jwkEncodePublic(raw)).ok, true);
  assert.equal(thumbprintPreimage(jwk).length > 0, true);
  assert.equal(text(base64urlEncode(thumbprintRaw(jwk))), thumbprint(jwk));
  assert.deepEqual(publicKeyThumbprintRaw(raw), thumbprintRaw(jwk));
});

test("every function of the fallible JWK set refuses every weak key with the closed error", () => {
  for (const weak of WEAK) {
    const x = text(base64urlEncode(weak));
    const jwk = { crv: "Ed25519", kty: "OKP", x } as const;
    assert.throws(() => jwkFromPublicKey(weak), InvalidError, `jwkFromPublicKey ${hex(weak)}`);
    assert.throws(() => jwkEncodePublic(weak), InvalidError, `jwkEncodePublic ${hex(weak)}`);
    assert.throws(() => thumbprintPreimage(jwk), InvalidError, `thumbprintPreimage ${hex(weak)}`);
    assert.throws(() => thumbprint(jwk), InvalidError, `thumbprint ${hex(weak)}`);
    assert.throws(() => thumbprintRaw(jwk), InvalidError, `thumbprintRaw ${hex(weak)}`);
    assert.throws(() => publicKeyThumbprintRaw(weak), InvalidError, `publicKeyThumbprintRaw ${hex(weak)}`);
    const decoded = jwkDecodePublic(strUtf8(JSON.stringify(jwk)));
    assert.equal(decoded.ok, false, `jwkDecodePublic ${hex(weak)}`);
  }
});

test("thumbprintDigestUnchecked names ANY 32 bytes with the RFC 7638 digest (the census and generator path)", () => {
  const { raw } = fresh();
  // For an acceptable key it equals the checked path.
  assert.deepEqual(thumbprintDigestUnchecked(raw), publicKeyThumbprintRaw(raw));
  for (const weak of WEAK) {
    const x = text(base64urlEncode(weak));
    const preimage = strUtf8(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`);
    assert.deepEqual(thumbprintDigestUnchecked(weak), sha256(preimage), hex(weak));
  }
  assert.throws(() => thumbprintDigestUnchecked(new Uint8Array(31)), InvalidError);
});

// ---- the unchecked path is pinned to the census and generator callers (an architecture test) ----

const ROOT = fileURLToPath(new URL("..", import.meta.url));
function sources(dir: string, ext: RegExp): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sources(path, ext));
    else if (ext.test(entry.name)) out.push(path);
  }
  return out;
}

test("thumbprintDigestUnchecked is referenced only by its definition, the census runners and tests; never by src or the package index", () => {
  const users = [...sources("src", /\.ts$/), ...sources("conformance", /\.ts$/), ...sources("web", /\.ts$/), ...sources("test", /\.ts$/)]
    .filter((p) => readFileSync(join(ROOT, p), "utf8").includes("thumbprintDigestUnchecked"))
    .map((p) => p.split("\\").join("/"))
    .sort();
  const allowed = new Set([
    "src/jwk.ts", // the definition
    "conformance/run.ts", "conformance/run_v2.ts", // the two-boundary census
    "test/strict-ed25519-jwk.test.ts", // this pin
  ]);
  for (const user of users) assert.ok(allowed.has(user), `unexpected caller ${user}`);
  assert.deepEqual(users.filter((u) => u.startsWith("src/")), ["src/jwk.ts"], "no verify-path module may use the unchecked digest");
  assert.equal(readFileSync(join(ROOT, "src/index.ts"), "utf8").includes("thumbprintDigestUnchecked"), false, "not exported from the package");
});

// ---- producers refuse a weak key before they emit a byte; each has a generated-key control ----

const PROXIES: Array<[string, typeof v1]> = [["v1", v1], ["v2", v2 as unknown as typeof v1]];

test("boundary-anchor and key-transition producers refuse weak keys (v1 and v2) and accept a generated key", () => {
  const { raw } = fresh();
  const other = fresh().raw;
  for (const [name, m] of PROXIES) {
    const anchor = (publicKey: Uint8Array) => m.boundaryAnchorSigningInput({
      keyId: "k", anchorId: "urn:example:anchor:1", chainId: "urn:example:chain:1", anchoredAt: 1000, sequence: 1,
      chainHash: new Uint8Array(32), publicKey,
    });
    const transition = (currentPublicKey: Uint8Array, nextPublicKey: Uint8Array) => m.keyTransitionSigningInput({
      transitionId: "urn:example:transition:1", chainId: "urn:example:chain:1", effectiveAt: 1500,
      currentKeyId: "a", currentPublicKey, nextKeyId: "b", nextPublicKey,
    });
    assert.equal(anchor(raw).ok, true, `${name} anchor control`);
    assert.equal(transition(raw, other).ok, true, `${name} transition control`);
    for (const weak of WEAK) {
      assert.equal(anchor(weak).ok, false, `${name} anchor ${hex(weak)}`);
      assert.equal(transition(weak, other).ok, false, `${name} transition current ${hex(weak)}`);
      assert.equal(transition(raw, weak).ok, false, `${name} transition next ${hex(weak)}`);
    }
  }
});

test("the proof producers refuse a weak holder key and accept a generated one (v1 and v2)", () => {
  const holder = fresh();
  const issuer = fresh();
  for (const [name, m] of PROXIES) {
    const grantSi = m.grantSigningInput({
      keyId: "issuer", issuer: "https://issuer.example.test", grantId: "urn:example:grant:1",
      audiences: ["https://resource.example.test"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
      holderThumbprint: text(base64urlEncode(publicKeyThumbprintRaw(holder.raw))), operations: [{ name: "read", selectors: ["all"] }],
    });
    assert.ok(grantSi.ok);
    const grant = assembleSegments(grantSi.value, new Uint8Array(nodeCrypto.sign(null,
      Buffer.from(`${text(grantSi.value.protectedSegment)}.${text(grantSi.value.payloadSegment)}`), issuer.privateKey)));
    assert.ok(grant.ok);
    const proof = (holderPublicKey: Uint8Array) => m.proofSigningInput({
      holderPublicKey, proofId: "urn:example:proof:1", method: "POST", targetUri: "https://resource.example.test/invoke",
      issuedAt: 1100, invocationId: "550e8400-e29b-41d4-a716-446655440000", operation: "read", grantCompact: grant.value,
      castArguments: { t: "object", v: new Map() },
    });
    assert.equal(proof(holder.raw).ok, true, `${name} proof control`);
    for (const weak of WEAK) assert.equal(proof(weak).ok, false, `${name} proof ${hex(weak)}`);
  }
});

test("a role-attestation subject key is refused at the producer and at decode, and accepted when generated", () => {
  const attestor = fresh();
  const subject = fresh().raw;
  const producer = (subjectPublicKey: Uint8Array): ra.AttestationProducer => ({
    keyId: "attestor-1", jti: "urn:example:attestation:1", subjectKeyId: "subject-1", subjectPublicKey, role: "issuer",
    notBefore: 1000, expiresAt: 2000,
  });
  const signed = ra.attestationSigningInput(producer(subject));
  assert.ok(signed.ok, "producer control");
  const compact = ra.assembleAttestationCompact(signed.value, new Uint8Array(nodeCrypto.sign(null,
    Buffer.from(`${text(signed.value.protectedSegment)}.${text(signed.value.payloadSegment)}`), attestor.privateKey)));
  assert.ok(compact.ok);
  assert.equal(ra.decodeAttestation(compact.value).ok, true, "decode control");
  for (const weak of WEAK) assert.equal(ra.attestationSigningInput(producer(weak)).ok, false, `producer ${hex(weak)}`);

  // Decode refuses a weak subject key that the PRODUCER can no longer emit: build the payload by hand
  // (the same canonical member set), keep the producer protected segment, and sign nothing.
  const handBuilt = (subjectPublicKey: Uint8Array) => {
    const str = (v: string): Tagged => ({ t: "string", v: strUtf8(v) });
    const members = new Map<string, Tagged>([
      ["v", { t: "int", v: 1 }], ["jti", str("urn:example:attestation:1")], ["key_id", str("subject-1")],
      ["public_key", { t: "string", v: base64urlEncode(subjectPublicKey) }], ["role", str("issuer")],
      ["nbf", { t: "int", v: 1000 }], ["exp", { t: "int", v: 2000 }],
    ]);
    const payload = base64urlEncode(jcsEncode({ t: "object", v: members }));
    return strUtf8(`${text(signed.value.protectedSegment)}.${text(payload)}.${text(base64urlEncode(new Uint8Array(64)))}`);
  };
  assert.equal(ra.decodeAttestation(handBuilt(subject)).ok, true, "hand-built control decodes");
  for (const weak of WEAK) assert.equal(ra.decodeAttestation(handBuilt(weak)).ok, false, `decode ${hex(weak)}`);
});
