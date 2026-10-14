// Facts follow the profile's redaction rule (spec/bap-v1.md: "Facts are value-bearing and redacted,
// with fixed redacted rendering and no generic encoder, string, or enumeration protocol"; the
// content-assertion profile: "Inspection MUST redact values"). Every facts type, of every major and
// sibling profile:
//   - value-bearing: each field reads by name, unchanged;
//   - fixed redacted rendering: util.inspect, String(), template literals and JSON.stringify all
//     yield #BoundedAuthorityProtocol.<Module><redacted> (the Elixir reference's Inspect text);
//   - no enumeration: Object.keys, for-in and spreading see nothing.
// The decoded content assertion is not a facts type: it keeps the redacted inspection the Elixir
// reference gives it, and its fields stay enumerable. Every value here comes from a real
// verification over freshly signed artifacts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { inspect } from "node:util";
import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import * as v3 from "../src/v3.js";
import * as roleAttestation from "../src/role_attestation.js";
import * as contentAssertion from "../src/content_assertion.js";
import { publicKeyThumbprintRaw as edFingerprint } from "../src/jwk.js";
import { publicKeyThumbprintRaw as ecFingerprint, thumbprint as ecThumbprint, jwkFromPublicKey as ecJwk } from "../src/ec_jwk.js";
import { thumbprint as edThumbprint, jwkFromPublicKey as edJwk } from "../src/jwk.js";
import { jsonDecode, strUtf8 } from "../src/json.js";
import { boundsNew } from "../src/bounds.js";
import type { SigningInput } from "../src/compact.js";
import type { Result } from "../src/error.js";

const INSPECT = Symbol.for("nodejs.util.inspect.custom");
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const message = (i: SigningInput): Buffer => Buffer.concat([i.protectedSegment, Buffer.from("."), i.payloadSegment]);
// The three majors' facts types differ by their version literal; one untyped unwrap serves all.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const take = (r: { readonly ok: boolean }): any => { assert.ok(r.ok); return (r as unknown as { value: unknown }).value; };

interface Key { raw: Uint8Array; sign: (m: Uint8Array) => Uint8Array; fingerprint: Uint8Array; thumbprint: string }
function edKey(): Key {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url"));
  return { raw, sign: (m) => sign(null, m, privateKey), fingerprint: edFingerprint(raw), thumbprint: edThumbprint(edJwk(raw)) };
}
function ecKey(): Key {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" });
  const raw = new Uint8Array(Buffer.concat([Buffer.from([4]), Buffer.from(x!, "base64url"), Buffer.from(y!, "base64url")]));
  const signLowS = (m: Uint8Array, key: KeyObject): Uint8Array => {
    const sig = sign("sha256", m, { key, dsaEncoding: "ieee-p1363" });
    const s = BigInt(`0x${sig.subarray(32).toString("hex")}`);
    if (s > (N - 1n) / 2n) sig.set(Buffer.from((N - s).toString(16).padStart(64, "0"), "hex"), 32);
    return new Uint8Array(sig);
  };
  return { raw, sign: (m) => signLowS(m, privateKey), fingerprint: ecFingerprint(raw), thumbprint: ecThumbprint(ecJwk(raw)) };
}

// The six facts types of one contract-major, from real artifacts.
function majorFacts(ns: typeof v1 | typeof v2 | typeof v3, newKey: () => Key): Record<string, object> {
  const issuer = newKey(), holder = newKey(), a = newKey(), b = newKey();
  const signed = (input: Result<SigningInput>, key: Key): Uint8Array => {
    const i = take(input);
    return take(ns.assembleCompact(i, key.sign(message(i))));
  };
  const grant = signed(ns.grantSigningInput({
    keyId: "iss", issuer: "https://issuer.example", grantId: "g-1", audiences: ["https://api.example"],
    issuedAt: 1_000, notBefore: 1_000, expiresAt: 9_000, holderThumbprint: holder.thumbprint,
    operations: [{ name: "tickets.read", selectors: ["all"] }],
  }), issuer);
  const castArguments = jsonDecode(strUtf8('{"ticket":7}'));
  const invocationId = randomUUID();
  const proof = signed(ns.proofSigningInput({
    holderPublicKey: holder.raw, proofId: "p-1", method: "GET", targetUri: "https://api.example/tickets/7",
    issuedAt: 1_100, invocationId, operation: "tickets.read", grantCompact: grant, castArguments,
  }), holder);
  const trusted = { keyId: "iss", publicKey: issuer.raw };
  const grantFacts = take(ns.verifyGrant(grant, trusted, { issuer: "https://issuer.example", audience: "https://api.example", evaluationTime: 1_200, clockSkew: 60 }));
  const envelopeFacts = take(ns.checkEnvelope(grant, proof, {
    trustedIssuer: trusted, issuer: "https://issuer.example", audience: "https://api.example", method: "GET",
    targetUri: "https://api.example/tickets/7", invocationId, operation: "tickets.read", castArguments,
    evaluationTime: 1_200, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
  }));

  const chainId = "audit:tickets", zero = new Uint8Array(32);
  const rows: Uint8Array[] = [];
  let head: Uint8Array = zero;
  for (let sequence = 1; sequence <= 2; sequence++) {
    const e = take(ns.encodeConsumptionEntry({ chainId, sequence, previousHash: head, commitment: createHash("sha256").update(`c${sequence}`).digest() }));
    rows.push(e.bytes); head = e.hash;
  }
  const chain = { chainId, firstSequence: 1, lastSequence: 2, rowCount: 2, previousHash: zero, lastHash: head };
  const chainFacts = take(ns.checkChain({ rows, ...chain }, chain));

  const keyA = { keyId: "arch-a", publicKey: a.raw, validFrom: 1_000, validBefore: 3_000 };
  const keyB = { keyId: "arch-b", publicKey: b.raw, validFrom: 2_000, validBefore: null };
  const start = signed(ns.boundaryAnchorSigningInput({ anchorId: "an-0", anchoredAt: 1_500, chainId, sequence: 0, chainHash: zero, keyId: "arch-a", publicKey: a.raw }), a);
  const transition = signed(ns.keyTransitionSigningInput({ transitionId: "rot-1", chainId, effectiveAt: 2_500, currentKeyId: "arch-a", currentPublicKey: a.raw, nextKeyId: "arch-b", nextPublicKey: b.raw }), a);
  const end = signed(ns.boundaryAnchorSigningInput({ anchorId: "an-2", anchoredAt: 2_600, chainId, sequence: 2, chainHash: head, keyId: "arch-b", publicKey: b.raw }), b);
  const expStart = { anchorId: "an-0", anchoredAt: 1_500, chainId, sequence: 0, chainHash: zero, keyId: "arch-a", keyFingerprint: a.fingerprint };
  const expEnd = { anchorId: "an-2", anchoredAt: 2_600, chainId, sequence: 2, chainHash: head, keyId: "arch-b", keyFingerprint: b.fingerprint };
  const expT = { transitionId: "rot-1", chainId, effectiveAt: 2_500, currentKeyId: "arch-a", currentKeyFingerprint: a.fingerprint, nextKeyId: "arch-b", nextKeyFingerprint: b.fingerprint };
  const anchorFacts = take(ns.verifyHistoricalAnchor(start, keyA, expStart));
  const transitionFacts = take(ns.verifyKeyTransition(transition, keyA, keyB, expT));
  const context = { chain, startAnchor: expStart, endAnchor: expEnd, transitions: [expT], digest: zero, objectVersion: "o-1" };
  const encoded = take(ns.encodeAnchoredExport({ rows, startAnchor: start, endAnchor: end, transitions: [transition], ...chain }, context));
  const exportFacts = take(ns.verifyAnchoredExport({ chunks: [encoded.archive], version: "o-1" }, { keys: [keyA, keyB] }, { ...context, digest: encoded.digest }));
  return {
    GrantFacts: grantFacts, EnvelopeFacts: envelopeFacts, ChainFacts: chainFacts, AnchorFacts: anchorFacts,
    KeyTransitionFacts: transitionFacts, AnchoredExportFacts: exportFacts,
  };
}

function siblingFacts(): Record<string, object> {
  const attestor = edKey(), subject = edKey();
  const ai = take(roleAttestation.attestationSigningInput({ keyId: "root", jti: "att-1", subjectKeyId: "sub", subjectPublicKey: subject.raw, role: "holder", notBefore: 100, expiresAt: 200 }));
  const attestation = take(roleAttestation.assembleAttestationCompact(ai, attestor.sign(message(ai))));
  const attestationFacts = take(roleAttestation.verifyAttestation(attestation, {
    attestor: { keyId: "root", publicKey: attestor.raw, validFrom: 0, validBefore: null }, subjectKeyId: "sub", subjectPublicKey: subject.raw, now: 150,
  }));
  const contentDigest = take(contentAssertion.contentDigest(strUtf8("policy text")));
  const profileDigest = new Uint8Array(32).fill(3);
  const ci = take(contentAssertion.assertionSigningInput({
    attestorKeyId: "pub", jti: "ca-1", iss: "https://pub.example", aud: "https://rt.example", sub: "policy:x", profile: "urn:example:p",
    profileDigest, contentDigest, gen: 1, prev: new Uint8Array(32), iat: 10, nbf: 10, exp: 20,
  }));
  const assertion = take(contentAssertion.assembleCompact(ci, attestor.sign(message(ci))));
  const assertionFacts = take(contentAssertion.verifyAssertion(assertion, {
    attestor: { keyId: "pub", publicKey: attestor.raw, validFrom: 0, validBefore: null }, issuer: "https://pub.example", audience: "https://rt.example",
    subject: "policy:x", profile: "urn:example:p", profileDigest, contentDigest, now: 15, bounds: boundsNew(),
  }));
  return {
    "RoleAttestation.V1.AttestationFacts": attestationFacts,
    "ContentAssertion.V1.ContentAssertionFacts": assertionFacts,
    "ContentAssertion.V1.DecodedContentAssertion": take(contentAssertion.decodeAssertion(assertion)),
  };
}

const CASES: Array<[string, object]> = [
  ...Object.entries(majorFacts(v1, edKey)).map(([n, f]): [string, object] => [`V1.${n}`, f]),
  ...Object.entries(majorFacts(v2, edKey)).map(([n, f]): [string, object] => [`V2.${n}`, f]),
  ...Object.entries(majorFacts(v3, ecKey)).map(([n, f]): [string, object] => [`V3.${n}`, f]),
  ...Object.entries(siblingFacts()),
];

test("every facts type is covered: six per major and the three sibling-profile values", () => {
  assert.equal(CASES.length, 21);
});

const FIELD: Record<string, string> = {
  GrantFacts: "grantId", EnvelopeFacts: "invocationId", ChainFacts: "chainId", AnchorFacts: "anchorId",
  KeyTransitionFacts: "transitionId", AnchoredExportFacts: "objectVersion", AttestationFacts: "jti",
  ContentAssertionFacts: "sub", DecodedContentAssertion: "sub",
};

for (const [name, facts] of CASES) {
  const rendering = `#BoundedAuthorityProtocol.${name}<redacted>`;
  const type = name.split(".").pop()!;
  const field = FIELD[type]!;
  const value = (facts as Record<string, unknown>)[field];

  test(`${name}: inspection renders ${rendering}`, () => {
    assert.equal(inspect(facts), rendering);
    assert.equal(inspect({ ok: true, value: facts }, { breakLength: Infinity }), `{ ok: true, value: ${rendering} }`);
    assert.equal(typeof value, "string", `${field} reads by name`);
    assert.ok((value as string).length > 0);
  });

  if (type === "DecodedContentAssertion") {
    test(`${name}: a decoded value keeps enumerable fields and plain JSON`, () => {
      assert.ok(Object.keys(facts).includes(field));
      assert.equal(JSON.parse(JSON.stringify(facts))[field], value);
    });
    continue;
  }

  test(`${name}: JSON, String() and template literals yield the rendering; nothing enumerates; fields read by name`, () => {
    assert.equal(JSON.stringify(facts), JSON.stringify(rendering));
    assert.equal(JSON.stringify({ facts }), JSON.stringify({ facts: rendering }));
    assert.equal(String(facts), rendering);
    assert.equal(`${facts}`, rendering);
    assert.deepEqual(Object.keys(facts), []);
    const forIn: string[] = [];
    for (const k in facts) forIn.push(k);
    assert.deepEqual(forIn, []);
    assert.deepEqual({ ...facts }, {});
    assert.ok(Object.isFrozen(facts));
    assert.equal((facts as Record<string, unknown>)[field], value);
    assert.equal(typeof (facts as Record<string, unknown>).version, "number");
  });
}
