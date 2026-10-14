import * as nodeCrypto from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";

import { strUtf8 } from "../src/json.js";
import { base64urlEncode } from "../src/base64url.js";
import { MAXIMA, boundsNew } from "../src/bounds.js";
import { publicKeyThumbprintRaw } from "../src/jwk.js";
import { jcsEncode } from "../src/jcs.js";
import {
  attestationSigningInput,
  assembleAttestationCompact,
  decodeAttestation,
  verifyAttestation,
  type AttestationProducer,
  type ExpectedAttestation,
} from "../src/role_attestation.js";
import { assembleCompact, decodeGrant, grantSigningInput, verifyGrant, type GrantProducer } from "../src/v1.js";
import * as v2 from "../src/v2.js";
import * as v3 from "../src/v3.js";

const utf8 = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

function freshKey(): { publicKey: Uint8Array; privateKey: nodeCrypto.KeyObject } {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  const raw = new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  return { publicKey: raw, privateKey };
}

function signInput(
  input: { readonly protectedSegment: Uint8Array; readonly payloadSegment: Uint8Array },
  privateKey: nodeCrypto.KeyObject,
): Uint8Array {
  const message = strUtf8(`${utf8(input.protectedSegment)}.${utf8(input.payloadSegment)}`);
  return new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), privateKey));
}

function fixture() {
  const attestor = freshKey();
  const subject = freshKey();
  const producer: AttestationProducer = {
    keyId: "attestor-1",
    jti: "urn:example:attestation:1",
    subjectKeyId: "subject-1",
    subjectPublicKey: subject.publicKey,
    role: "issuer",
    notBefore: 1000,
    expiresAt: 2000,
  };
  const input = attestationSigningInput(producer);
  assert.equal(input.ok, true);
  if (!input.ok) throw new Error("fixture signing input failed");
  const signature = signInput(input.value, attestor.privateKey);
  const compact = assembleAttestationCompact(input.value, signature);
  assert.equal(compact.ok, true);
  if (!compact.ok) throw new Error("fixture assembly failed");
  const expected: ExpectedAttestation = {
    attestor: {
      keyId: "attestor-1",
      publicKey: attestor.publicKey,
      validFrom: 500,
      validBefore: 2500,
    },
    subjectKeyId: "subject-1",
    subjectPublicKey: subject.publicKey,
    now: 1500,
  };
  return { attestor, subject, producer, input: input.value, signature, compact: compact.value, expected };
}

test("role attestation round-trips both roles and returns anchor-posture facts", () => {
  const f = fixture();
  for (const role of ["issuer", "holder"] as const) {
    const input = attestationSigningInput({ ...f.producer, role });
    assert.equal(input.ok, true, role);
    if (!input.ok) return;
    const compact = assembleAttestationCompact(input.value, signInput(input.value, f.attestor.privateKey));
    assert.equal(compact.ok, true, role);
    if (!compact.ok) return;
    const decoded = decodeAttestation(compact.value);
    assert.equal(decoded.ok, true, role);
    if (!decoded.ok) return;
    assert.equal(decoded.value.keyId, "attestor-1");
    assert.equal(decoded.value.jti, "urn:example:attestation:1");
    assert.equal(decoded.value.subjectKeyId, "subject-1");
    assert.deepEqual(decoded.value.subjectPublicKey, f.subject.publicKey);
    assert.equal(decoded.value.role, role);
    assert.equal(decoded.value.notBefore, 1000);
    assert.equal(decoded.value.expiresAt, 2000);
    assert.equal(decoded.value.verification, "not_evaluated");

    const verified = verifyAttestation(compact.value, f.expected);
    assert.equal(verified.ok, true, role);
    if (!verified.ok) return;
    const facts = verified.value;
    // The facts contract (ADR 0036 D5): the anchor posture — trust not_evaluated, NO
    // authorization marker (critical rule 1 reserves it to grant/envelope/export facts).
    assert.deepEqual(
      Object.keys(facts).sort(),
      [
        "attestorKeyFingerprint", "attestorKeyId", "expiresAt", "jti", "notBefore",
        "role", "subjectKeyFingerprint", "subjectKeyId", "trust", "verification", "version",
      ].sort(),
    );
    assert.equal(facts.version, 1);
    assert.equal(facts.attestorKeyId, "attestor-1");
    assert.deepEqual(facts.attestorKeyFingerprint, publicKeyThumbprintRaw(f.attestor.publicKey));
    assert.equal(facts.subjectKeyId, "subject-1");
    assert.deepEqual(facts.subjectKeyFingerprint, publicKeyThumbprintRaw(f.subject.publicKey));
    assert.equal(facts.role, role);
    assert.equal(facts.jti, "urn:example:attestation:1");
    assert.equal(facts.notBefore, 1000);
    assert.equal(facts.expiresAt, 2000);
    assert.equal(facts.verification, "signature_and_window");
    assert.equal(facts.trust, "not_evaluated");
  }
});

test("role attestation verify proves kid binding, signature, subject binding, and self-attestation", () => {
  const f = fixture();

  // Tampered signature: flip a meaningful middle byte of the signature segment.
  const segs = utf8(f.compact).split(".");
  const sigBytes = segs[2]!.split("");
  sigBytes[40] = sigBytes[40] === "A" ? "B" : "A";
  const tampered = strUtf8(`${segs[0]}.${segs[1]}.${sigBytes.join("")}`);
  assert.equal(decodeAttestation(tampered).ok, true, "a canonical-width signature still decodes");
  assert.equal(verifyAttestation(tampered, f.expected).ok, false);

  // Header kid must equal the attestor key id.
  assert.equal(verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, keyId: "attestor-2" } }).ok, false);
  // Signature must verify under the caller-supplied attestor key.
  const otherKey = freshKey();
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, publicKey: otherKey.publicKey } }).ok,
    false,
  );

  // Subject binding: key id equality AND raw public_key byte-equality.
  assert.equal(verifyAttestation(f.compact, { ...f.expected, subjectKeyId: "subject-2" }).ok, false);
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, subjectPublicKey: otherKey.publicKey }).ok,
    false,
  );

  // Self-attestation. This first leg overrides only the expected context (the wire still
  // carries the subject key), so it rejects at the subject-binding gate — a sanity leg; the
  // wire-carried legs below are the discriminating proofs (cross-vendor review n2).
  const selfMaterial = verifyAttestation(f.compact, {
    ...f.expected,
    subjectKeyId: "attestor-1",
    subjectPublicKey: f.attestor.publicKey,
  });
  assert.equal(selfMaterial.ok, false, "expected-context mismatch (binding gate)");

  const wireKeyAttestor = attestationSigningInput({ ...f.producer, subjectKeyId: "attestor-1" });
  assert.equal(wireKeyAttestor.ok, true);
  if (wireKeyAttestor.ok) {
    const compact = assembleAttestationCompact(wireKeyAttestor.value, signInput(wireKeyAttestor.value, f.attestor.privateKey));
    assert.equal(compact.ok, true);
    if (compact.ok) {
      // Wire subject key id == attestor key id, distinct key material.
      assert.equal(
        verifyAttestation(compact.value, { ...f.expected, subjectKeyId: "attestor-1" }).ok,
        false,
        "attestor key id == subject key id must reject on its own",
      );
    }
  }

  const wireMaterialAttestor = attestationSigningInput({ ...f.producer, subjectPublicKey: f.attestor.publicKey });
  assert.equal(wireMaterialAttestor.ok, true);
  if (wireMaterialAttestor.ok) {
    const compact = assembleAttestationCompact(wireMaterialAttestor.value, signInput(wireMaterialAttestor.value, f.attestor.privateKey));
    assert.equal(compact.ok, true);
    if (compact.ok) {
      // Wire subject key material == attestor key, distinct key ids.
      assert.equal(
        verifyAttestation(compact.value, {
          ...f.expected,
          subjectKeyId: "subject-1",
          subjectPublicKey: f.attestor.publicKey,
        }).ok,
        false,
        "attestor thumbprint == subject thumbprint must reject on its own",
      );
    }
  }
});

test("role attestation window containment and the half-open now window", () => {
  const f = fixture();

  // Containment: nbf >= valid_from, exp <= valid_before (bounded); boundary equality accepts.
  assert.equal(verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: 1000 } }).ok, true, "nbf == valid_from accepts");
  assert.equal(verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: 1001 } }).ok, false, "nbf < valid_from rejects");
  assert.equal(verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: 2000 } }).ok, true, "exp == valid_before accepts");
  assert.equal(verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: 1999 } }).ok, false, "exp > valid_before rejects");
  // Unbounded valid_before: any contained-lifetime ceiling disappears.
  assert.equal(verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: null } }).ok, true);

  // now in [nbf, exp): now == nbf accepts, now == exp rejects.
  assert.equal(verifyAttestation(f.compact, { ...f.expected, now: 1000 }).ok, true, "now == nbf accepts");
  assert.equal(verifyAttestation(f.compact, { ...f.expected, now: 1999 }).ok, true);
  assert.equal(verifyAttestation(f.compact, { ...f.expected, now: 2000 }).ok, false, "now == exp rejects");
  assert.equal(verifyAttestation(f.compact, { ...f.expected, now: 999 }).ok, false, "now < nbf rejects");
});

test("role attestation context is validated: integer now, magnitude-bounded window endpoints", () => {
  const f = fixture();
  const MAX = 9007199254740991; // MAXIMA.integer_magnitude (2^53 - 1)

  // Fractional now must fail closed (a half-open window check alone would admit it).
  assert.equal(verifyAttestation(f.compact, { ...f.expected, now: 1500.5 }).ok, false);
  // Window endpoints: non-integer or over-magnitude (both directions) fail closed.
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: 500.5 } }).ok,
    false,
  );
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: MAX + 1 } }).ok,
    false,
  );
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validFrom: -MAX - 1 } }).ok,
    false,
  );
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: 2500.5 } }).ok,
    false,
  );
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: MAX + 1 } }).ok,
    false,
  );
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, validBefore: -MAX - 1 } }).ok,
    false,
  );
  // A null/wrong-typed context struct fails closed, not with a TypeError.
  assert.equal(verifyAttestation(f.compact, null as unknown as ExpectedAttestation).ok, false);
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, subjectPublicKey: undefined as unknown as Uint8Array }).ok,
    false,
  );
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, attestor: { ...f.expected.attestor, publicKey: new Uint8Array(31) } }).ok,
    false,
    "attestor public key width",
  );
  assert.equal(
    verifyAttestation(f.compact, { ...f.expected, subjectPublicKey: new Uint8Array(31) }).ok,
    false,
    "subject public key width",
  );
});

test("role attestation producer validates its inputs fail-closed", () => {
  const f = fixture();
  assert.equal(attestationSigningInput({ ...f.producer, role: "auditor" as "issuer" }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, notBefore: 2000, expiresAt: 2000 }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, notBefore: 2001, expiresAt: 2000 }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, notBefore: 1000.5 }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, expiresAt: 2000.5 }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, subjectPublicKey: new Uint8Array(31) }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, jti: "" }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, keyId: "attestor 1" }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, subjectKeyId: "subject 1" }).ok, false);
  // Non-string field types reject with the closed error — never coerce ("null") or throw a
  // TypeError past the Result contract (cross-vendor review m2).
  assert.equal(attestationSigningInput({ ...f.producer, keyId: null as unknown as string }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, subjectKeyId: 999 as unknown as string }).ok, false);
  assert.equal(attestationSigningInput({ ...f.producer, jti: 12345 as unknown as string }).ok, false);
  // A malformed caller Bounds object rejects with the closed error on every surface — not a
  // TypeError out of coerceBounds' iteration (cross-vendor review m1 + the repair pass: the
  // missing/null/array-override shapes are the ones that reached the broken branch).
  for (const malformedBounds of [
    {} as never,
    { maximum: { compact_bytes: 1 } } as never,
    { maximum: {}, overrides: null } as never,
    { maximum: {}, overrides: [1, 2] } as never,
    { maximum: {}, overrides: "map" } as never,
  ]) {
    assert.equal(attestationSigningInput(f.producer, malformedBounds).ok, false);
    assert.equal(decodeAttestation(f.compact, malformedBounds).ok, false);
    assert.equal(assembleAttestationCompact(f.input, f.signature, malformedBounds).ok, false);
    assert.equal(verifyAttestation(f.compact, { ...f.expected, bounds: malformedBounds }).ok, false);
  }
  // The legal hand-crafted shape still works (tightening takes effect — parse bounds).
  const handCrafted = { maximum: MAXIMA, overrides: new Map([["compact_bytes", 4096]]) } as never;
  assert.equal(decodeAttestation(f.compact, handCrafted).ok, true);
  // The producer takes no expected role and no private key — external signature only.
  assert.equal(attestationSigningInput(f.producer).ok, true);
});

test("role attestation producer honors caller bounds on its EMITTED bytes (finding-4 transfer)", () => {
  const f = fixture();
  const longJti = { ...f.producer, jti: "urn:example:attestation:" + "a".repeat(400) };
  // The emitted payload segment under DEFAULT bounds is legal...
  const legal = attestationSigningInput(longJti);
  assert.equal(legal.ok, true);
  if (!legal.ok) return;
  assert.ok(legal.value.payloadSegment.length > 128, "fixture emits a >128-byte segment");
  // ...but every decoder-enforced limit the producer can violate must gate at production:
  assert.equal(attestationSigningInput(longJti, boundsNew({ encoded_segment_bytes: 128 })).ok, false);
  assert.equal(attestationSigningInput(longJti, boundsNew({ decoded_segment_bytes: 128 })).ok, false);
  assert.equal(attestationSigningInput(longJti, boundsNew({ json_bytes: 128 })).ok, false);
  assert.equal(attestationSigningInput(longJti, boundsNew({ jcs_bytes: 128 })).ok, false);
  assert.equal(attestationSigningInput(longJti, boundsNew({ compact_bytes: 200 })).ok, false);
  // The emitted-number-lexeme class is closed one layer down in this surface: any integer
  // whose Number-toString carries an exponent is >= 1e21 — far past the 2^53-1 magnitude
  // bound — and the shared JCS encoder rejects it at production time (jcsEncode throws
  // "jcs: integer bound"; injection-probed — a producer-side lexeme gate is structurally
  // unreachable and was removed rather than shipped as dead coverage). The producing call
  // still fails closed:
  assert.equal(
    attestationSigningInput({ ...f.producer, notBefore: 10 ** 30, expiresAt: 10 ** 31 }).ok,
    false,
  );
  assert.equal(
    attestationSigningInput({ ...f.producer, notBefore: 10 ** 15, expiresAt: 10 ** 15 + 1 }).ok,
    true,
    "15-digit integers emit plain lexemes and stay legal",
  );
});

// Build a compact from arbitrary header/payload tagged values (test-only; bypasses the producer
// so wire-level decode gates can be exercised directly).
function buildCompact(headerMembers: Map<string, unknown>, payloadMembers: Map<string, unknown>, signature: Uint8Array): Uint8Array {
  const taggedObject = (members: Map<string, unknown>) => ({ t: "object", v: members }) as never;
  const protect = strUtf8(utf8(base64urlEncode(jcsEncode(taggedObject(headerMembers)))));
  const payload = strUtf8(utf8(base64urlEncode(jcsEncode(taggedObject(payloadMembers)))));
  const assembled = strUtf8(`${utf8(protect)}.${utf8(payload)}.${utf8(base64urlEncode(signature))}`);
  return assembled;
}

function basePayloadMembers(): Map<string, unknown> {
  return new Map<string, unknown>([
    ["exp", { t: "int", v: 2000 }],
    ["jti", { t: "string", v: strUtf8("urn:example:attestation:1") }],
    ["key_id", { t: "string", v: strUtf8("subject-1") }],
    ["nbf", { t: "int", v: 1000 }],
    ["public_key", { t: "string", v: base64urlEncode(fixtureSubjectKey()) }],
    ["role", { t: "string", v: strUtf8("issuer") }],
    ["v", { t: "int", v: 1 }],
  ]);
}

function baseHeaderMembers(): Map<string, unknown> {
  return new Map<string, unknown>([
    ["alg", { t: "string", v: strUtf8("EdDSA") }],
    ["kid", { t: "string", v: strUtf8("attestor-1") }],
    ["typ", { t: "string", v: strUtf8("ba+role-attestation") }],
  ]);
}

let cachedSubjectKey: Uint8Array | undefined;
function fixtureSubjectKey(): Uint8Array {
  if (!cachedSubjectKey) cachedSubjectKey = freshKey().publicKey;
  return cachedSubjectKey;
}

test("role attestation decode enforces the closed header and payload sets and canonical bytes", () => {
  const f = fixture();
  const sig = f.signature;

  // Unknown header member.
  const cty = buildCompact(new Map([...baseHeaderMembers(), ["cty", { t: "string", v: strUtf8("json") }]]), basePayloadMembers(), sig);
  assert.equal(decodeAttestation(cty).ok, false);
  // Wrong typ / wrong alg.
  assert.equal(
    decodeAttestation(buildCompact(new Map([...baseHeaderMembers(), ["typ", { t: "string", v: strUtf8("ba+cap") }]]), basePayloadMembers(), sig)).ok,
    false,
  );
  assert.equal(
    decodeAttestation(buildCompact(new Map([...baseHeaderMembers(), ["alg", { t: "string", v: strUtf8("ES256") }]]), basePayloadMembers(), sig)).ok,
    false,
  );
  // kid rules.
  assert.equal(
    decodeAttestation(buildCompact(new Map([...baseHeaderMembers(), ["kid", { t: "string", v: strUtf8("attestor 1") }]]), basePayloadMembers(), sig)).ok,
    false,
  );

  // Missing-member matrix (one per payload member).
  for (const member of ["v", "jti", "key_id", "public_key", "role", "nbf", "exp"]) {
    const members = basePayloadMembers();
    members.delete(member);
    assert.equal(decodeAttestation(buildCompact(baseHeaderMembers(), members, sig)).ok, false, `missing ${member}`);
  }
  // Unknown payload member.
  const extra = basePayloadMembers();
  extra.set("scope", { t: "string", v: strUtf8("everything") });
  assert.equal(decodeAttestation(buildCompact(baseHeaderMembers(), extra, sig)).ok, false);
  // v deviations: value and integer/float tag distinction. The float leg must be built from
  // raw text — jcsEncode canonicalizes Number 1.0 to the integer lexeme "1", so the float tag
  // is only observable on the wire as a literal "1.0" lexeme (the corpus's v-float-lexeme
  // bytes; the tagged decoder must reject it).
  assert.equal(decodeAttestation(buildCompact(baseHeaderMembers(), new Map([...basePayloadMembers(), ["v", { t: "int", v: 2 }]]), sig)).ok, false);
  const floatPayload = utf8(jcsEncode({ t: "object", v: basePayloadMembers() } as never)).replace('"v":1}', '"v":1.0}');
  assert.notEqual(floatPayload.indexOf("1.0"), -1);
  // The header segment is the base64url of the JCS bytes — single-encoded (a stray double
  // encode made these legs reject on a malformed header, not on the gate each names).
  const canonicalHeaderSegment = utf8(base64urlEncode(jcsEncode({ t: "object", v: baseHeaderMembers() } as never)));
  const floatCompact = strUtf8(
    `${canonicalHeaderSegment}.${utf8(base64urlEncode(strUtf8(floatPayload)))}.${utf8(base64urlEncode(sig))}`,
  );
  assert.equal(decodeAttestation(floatCompact).ok, false, "float-tagged 1.0 must reject");
  // Role closed set.
  assert.equal(decodeAttestation(buildCompact(baseHeaderMembers(), new Map([...basePayloadMembers(), ["role", { t: "string", v: strUtf8("auditor") }]]), sig)).ok, false);
  // public_key width (base64url of 31 bytes).
  assert.equal(
    decodeAttestation(buildCompact(baseHeaderMembers(), new Map([...basePayloadMembers(), ["public_key", { t: "string", v: base64urlEncode(new Uint8Array(31)) }]]), sig)).ok,
    false,
  );
  // Window rules: inverted and empty.
  assert.equal(
    decodeAttestation(buildCompact(baseHeaderMembers(), new Map([...basePayloadMembers(), ["nbf", { t: "int", v: 2000 }]]), sig)).ok,
    false,
  );
  assert.equal(
    decodeAttestation(buildCompact(baseHeaderMembers(), new Map([...basePayloadMembers(), ["exp", { t: "int", v: 1000 }]]), sig)).ok,
    false,
  );

  // Non-canonical payload order: hand-encode the payload members OUT of JCS order.
  const ordered = [...basePayloadMembers().entries()].reverse();
  let raw = "{";
  for (let i = 0; i < ordered.length; i++) {
    const [name, value] = ordered[i]!;
    raw += `${JSON.stringify(name)}:${utf8(jcsEncode(value as never))}`;
    raw += i === ordered.length - 1 ? "}" : ",";
  }
  const headerText = canonicalHeaderSegment;
  const nonCanonical = strUtf8(`${headerText}.${utf8(base64urlEncode(strUtf8(raw)))}.${utf8(base64urlEncode(sig))}`);
  assert.equal(decodeAttestation(nonCanonical).ok, false, "non-canonical payload order must reject");

  // Duplicate member: raw JSON with a duplicated role member. The rejection is JOINT — the
  // tagged decoder's duplicate gate fires first, and the payload-canonical gate is the
  // backstop (a duplicate re-encodes to different bytes); the discriminating proof of the
  // duplicate closure itself is the shared battery's json-level entry (depth-3 duplicate).
  const canonicalPayload = utf8(jcsEncode({ t: "object", v: basePayloadMembers() } as never));
  const dupPayload = canonicalPayload.replace('"role":"issuer"', '"role":"issuer","role":"issuer"');
  assert.notEqual(dupPayload, canonicalPayload);
  const dup = strUtf8(`${headerText}.${utf8(base64urlEncode(strUtf8(dupPayload)))}.${utf8(base64urlEncode(sig))}`);
  assert.equal(decodeAttestation(dup).ok, false, "duplicate member must reject (decode gate + canonical backstop)");

  // Truncated compact (signature one char short).
  const text = utf8(f.compact);
  assert.equal(decodeAttestation(strUtf8(text.slice(0, text.length - 1))).ok, false);
  // Non-canonical base64url signature byte (padding-bearing alphabet byte).
  assert.equal(decodeAttestation(strUtf8(`${text.slice(0, text.length - 1)}=`)).ok, false);
});

test("role attestation assembly revalidates and the kind discipline is closed", () => {
  const f = fixture();

  // Assembly re-parse: a hand-mangled payload segment (unknown member) must reject at assembly.
  const mangledPayload = new Map(basePayloadMembers());
  mangledPayload.set("scope", { t: "string", v: strUtf8("everything") });
  const mangled = {
    kind: "role_attestation" as const,
    protectedSegment: f.input.protectedSegment,
    payloadSegment: strUtf8(utf8(base64urlEncode(jcsEncode({ t: "object", v: mangledPayload } as never)))),
  };
  assert.equal(assembleAttestationCompact(mangled, f.signature).ok, false);

  // Signature width at assembly.
  assert.equal(assembleAttestationCompact(f.input, f.signature.subarray(0, 63)).ok, false);

  // Kind discipline both directions: the v1 assembler rejects the attestation input; the
  // attestation assembler rejects a grant input.
  assert.equal(assembleCompact(f.input, f.signature).ok, false);
  const grant: GrantProducer = {
    keyId: "issuer-1",
    issuer: "https://issuer.example.test",
    grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"],
    issuedAt: 1000,
    notBefore: 1000,
    expiresAt: 2000,
    holderThumbprint: utf8(base64urlEncode(publicKeyThumbprintRaw(f.subject.publicKey))),
    operations: [{ name: "read", selectors: ["all"] }],
  };
  const grantInput = grantSigningInput(grant);
  assert.equal(grantInput.ok, true);
  if (!grantInput.ok) return;
  assert.equal(assembleAttestationCompact(grantInput.value, f.signature).ok, false);
});

test("role attestation bytes are rejected by every contract-major surface, and vice versa", () => {
  const f = fixture();
  const attestation = f.compact;

  // Structural decode rejects on the profile typ (context-free proof of the typ gate).
  assert.equal(decodeGrant(attestation).ok, false);
  assert.equal(v2.decodeGrant(attestation).ok, false);
  assert.equal(v3.decodeGrant(attestation).ok, false);

  // The verification surfaces reject attestation bytes with a well-formed context (the typ
  // gate fires before any context comparison).
  const wellFormedGrantContext = {
    keyId: "attestor-1",
    publicKey: f.attestor.publicKey,
  };
  const expectedGrant = {
    issuer: "https://issuer.example.test",
    audience: "https://resource.example.test",
    evaluationTime: 1500,
    clockSkew: 60,
  };
  assert.equal(verifyGrant(attestation, wellFormedGrantContext, expectedGrant).ok, false);
  assert.equal(v2.verifyGrant(attestation, wellFormedGrantContext, expectedGrant).ok, false);
  assert.equal(v3.verifyGrant(attestation, { keyId: "attestor-1", publicKey: new Uint8Array(65) }, expectedGrant).ok, false);

  // And a live v1 grant compact is rejected by attestation decode.
  const grant: GrantProducer = {
    keyId: "issuer-1",
    issuer: "https://issuer.example.test",
    grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"],
    issuedAt: 1000,
    notBefore: 1000,
    expiresAt: 2000,
    holderThumbprint: utf8(base64urlEncode(publicKeyThumbprintRaw(f.subject.publicKey))),
    operations: [{ name: "read", selectors: ["all"] }],
  };
  const grantInput = grantSigningInput(grant);
  assert.equal(grantInput.ok, true);
  if (!grantInput.ok) return;
  const issuer = freshKey();
  const grantCompact = assembleCompact(grantInput.value, signInput(grantInput.value, issuer.privateKey));
  assert.equal(grantCompact.ok, true);
  if (!grantCompact.ok) return;
  assert.equal(decodeAttestation(grantCompact.value).ok, false);
  assert.equal(verifyAttestation(grantCompact.value, f.expected).ok, false);
});
