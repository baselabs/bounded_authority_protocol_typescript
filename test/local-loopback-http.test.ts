import * as nodeCrypto from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { publicKeyThumbprintRaw } from "../src/jwk.js";
import { strUtf8 } from "../src/json.js";
import { localLoopbackHttpUriNormalize, uriNormalize } from "../src/uri.js";
import { MAXIMA, type Bounds } from "../src/bounds.js";
import {
  assembleCompact,
  assembleLocalLoopbackHttpCompact,
  checkEnvelope,
  checkLocalLoopbackHttpEnvelope,
  decodeLocalLoopbackHttpProof,
  decodeProof,
  grantSigningInput,
  localLoopbackHttpProofSigningInput,
  proofSigningInput,
  type ExpectedRequest,
  type GrantProducer,
  type ProofProducer,
} from "../src/v1.js";

const utf8 = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const CERTIFIED_INDEX_SHA256 = "10fc4cf05affcddc9e6340ff392c247e25ab038cd938f2557829a7ce63b1a5e4";

test("local loopback HTTP URI profile accepts only exact loopback literals", () => {
  const valid: Array<readonly [string, string]> = [
    ["HTTP://127.0.0.1:80/a/../invoke", "http://127.0.0.1/invoke"],
    ["http://127.0.0.1:4000/invoke", "http://127.0.0.1:4000/invoke"],
    ["HTTP://[::1]:80/invoke", "http://[::1]/invoke"],
    ["http://127.0.0.1:443/invoke", "http://127.0.0.1:443/invoke"],
  ];
  for (const [input, expected] of valid) {
    const result = localLoopbackHttpUriNormalize(strUtf8(input));
    assert.equal(result.ok, true, input);
    if (result.ok) assert.equal(utf8(result.value), expected);
  }

  for (const invalid of [
    "https://127.0.0.1/invoke",
    "http://localhost/invoke",
    "http://127.0.0.2/invoke",
    "http://127.1/invoke",
    "http://2130706433/invoke",
    "http://[::ffff:127.0.0.1]/invoke",
    "http://[::1%25lo0]/invoke",
    "http://user@127.0.0.1/invoke",
    "http://127.0.0.1/invoke?query=true",
    "http://127.0.0.1/invoke#fragment",
    "http://127.0.0.1/[]",
  ]) {
    assert.equal(localLoopbackHttpUriNormalize(strUtf8(invalid)).ok, false, invalid);
  }

  const forged = { maximum: MAXIMA, overrides: new Map([["uri_bytes", 9000]]) } as Bounds;
  assert.equal(localLoopbackHttpUriNormalize(strUtf8("http://127.0.0.1/"), forged).ok, false);

  for (const invalidStandardPath of [
    "https://resource.example.test/[]",
    "https://resource.example.test/a|b",
    'https://resource.example.test/a"b',
  ]) {
    assert.equal(
      uriNormalize(strUtf8(invalidStandardPath)).ok,
      false,
      `standard RFC 3986 path must reject ${invalidStandardPath}`,
    );
  }
});

test("certified local-loopback corpus drives TypeScript verdicts", () => {
  const root = new URL("../../../priv/conformance/application-profiles/local-loopback-http/v1/", import.meta.url);
  const readJson = (name: string): unknown => JSON.parse(readFileSync(new URL(name, root), "utf8"));
  const indexBytes = readFileSync(new URL("index.json", root));
  assert.equal(nodeCrypto.createHash("sha256").update(indexBytes).digest("hex"), CERTIFIED_INDEX_SHA256);
  const index = JSON.parse(indexBytes.toString("utf8")) as {
    files: Array<{ path: string; sha256: string }>;
    profile: string; revision: number; proof_cases: number; uri_cases: number;
  };
  assert.equal(index.profile, "bap-application-proof/local-loopback-http/1");
  assert.equal(index.revision, 1);
  assert.equal(index.proof_cases, 8);
  assert.equal(index.uri_cases, 36);
  assert.deepEqual(index.files.map((file) => file.path), ["profile.json", "proof-cases.json"]);
  for (const file of index.files) {
    const bytes = readFileSync(new URL(file.path, root));
    assert.equal(nodeCrypto.createHash("sha256").update(bytes).digest("hex"), file.sha256, file.path);
  }

  const profile = readJson("profile.json") as {
    grant_compact: string;
    holder_public_key: string;
    issuer: { key_id: string; public_key: string; issuer: string; audience: string };
    request: {
      method: string; invocation_id: string; operation: string; evaluation_time: number;
      clock_skew: number; proof_max_age: number;
    };
    proofs: Record<"ipv4" | "ipv6", { target_uri: string; nonce: string; compact: string; proof_id: string }>;
    uri_cases: Array<{ id: string; input: string; valid: boolean; normalized?: string }>;
  };
  assert.equal(profile.uri_cases.length, index.uri_cases);
  for (const uriCase of profile.uri_cases) {
    const result = localLoopbackHttpUriNormalize(strUtf8(uriCase.input));
    assert.equal(result.ok, uriCase.valid, uriCase.id);
    if (result.ok) assert.equal(utf8(result.value), uriCase.normalized, uriCase.id);
  }

  const [protectedSegment, payloadSegment, signatureSegment] = profile.proofs.ipv4.compact.split(".");
  assert.ok(protectedSegment && payloadSegment && signatureSegment);
  const certifiedProducer: ProofProducer = {
    holderPublicKey: base64urlDecode(strUtf8(profile.holder_public_key)),
    proofId: profile.proofs.ipv4.proof_id,
    method: profile.request.method,
    targetUri: profile.proofs.ipv4.target_uri,
    issuedAt: profile.request.evaluation_time,
    invocationId: profile.request.invocation_id,
    operation: profile.request.operation,
    grantCompact: strUtf8(profile.grant_compact),
    castArguments: {
      t: "object",
      v: new Map([["record_id", { t: "string", v: strUtf8("record-1") }]]),
    },
    nonce: profile.proofs.ipv4.nonce,
  };
  const certifiedInput = localLoopbackHttpProofSigningInput(certifiedProducer);
  assert.equal(certifiedInput.ok, true);
  if (!certifiedInput.ok) return;
  assert.equal(utf8(certifiedInput.value.protectedSegment), protectedSegment);
  assert.equal(utf8(certifiedInput.value.payloadSegment), payloadSegment);
  const certifiedSignature = base64urlDecode(strUtf8(signatureSegment));
  const certifiedAssembly = assembleLocalLoopbackHttpCompact(certifiedInput.value, certifiedSignature);
  assert.equal(certifiedAssembly.ok, true);
  if (certifiedAssembly.ok) assert.equal(utf8(certifiedAssembly.value), profile.proofs.ipv4.compact);
  assert.equal(assembleCompact(certifiedInput.value, certifiedSignature).ok, false);

  const expected: ExpectedRequest = {
    trustedIssuer: {
      keyId: profile.issuer.key_id,
      publicKey: base64urlDecode(strUtf8(profile.issuer.public_key)),
    },
    issuer: profile.issuer.issuer,
    audience: profile.issuer.audience,
    method: profile.request.method,
    targetUri: profile.proofs.ipv4.target_uri,
    invocationId: profile.request.invocation_id,
    operation: profile.request.operation,
    castArguments: {
      t: "object",
      v: new Map([["record_id", { t: "string", v: strUtf8("record-1") }]]),
    },
    evaluationTime: profile.request.evaluation_time,
    clockSkew: profile.request.clock_skew,
    proofMaxAge: profile.request.proof_max_age,
    nonce: { kind: "required", value: profile.proofs.ipv4.nonce },
  };
  const cases = readJson("proof-cases.json") as Array<{
    id: string; compact: string; decode_local: boolean; decode_standard: boolean; envelope_local: boolean;
    expected_overrides?: { trusted_issuer_public_key?: string; invocation_id?: string };
  }>;
  assert.equal(cases.length, index.proof_cases);

  const ipv6 = profile.proofs.ipv6;
  const ipv6Input = localLoopbackHttpProofSigningInput({
    ...certifiedProducer,
    proofId: ipv6.proof_id,
    targetUri: ipv6.target_uri,
    nonce: ipv6.nonce,
  });
  assert.equal(ipv6Input.ok, true);
  if (!ipv6Input.ok) return;
  const [ipv6Protected, ipv6Payload, ipv6Signature] = ipv6.compact.split(".");
  assert.equal(utf8(ipv6Input.value.protectedSegment), ipv6Protected);
  assert.equal(utf8(ipv6Input.value.payloadSegment), ipv6Payload);
  const ipv6Assembly = assembleLocalLoopbackHttpCompact(
    ipv6Input.value,
    base64urlDecode(strUtf8(ipv6Signature!)),
  );
  assert.equal(ipv6Assembly.ok, true);
  if (!ipv6Assembly.ok) return;
  assert.equal(utf8(ipv6Assembly.value), ipv6.compact);
  assert.equal(decodeLocalLoopbackHttpProof(ipv6Assembly.value).ok, true);
  assert.equal(checkLocalLoopbackHttpEnvelope(strUtf8(profile.grant_compact), ipv6Assembly.value, {
    ...expected,
    targetUri: ipv6.target_uri,
    nonce: { kind: "required", value: ipv6.nonce },
  }).ok, true);

  for (const proofCase of cases) {
    const compact = strUtf8(proofCase.compact);
    const overrides = proofCase.expected_overrides ?? {};
    assert.ok(Object.keys(overrides).every((key) =>
      key === "trusted_issuer_public_key" || key === "invocation_id"
    ), `${proofCase.id}: unsupported expected override`);
    assert.ok(Object.keys(overrides).length <= 1, `${proofCase.id}: ambiguous expected override`);
    const caseExpected: ExpectedRequest = {
      ...expected,
      ...(overrides.invocation_id === undefined ? {} : { invocationId: overrides.invocation_id }),
      ...(overrides.trusted_issuer_public_key === undefined ? {} : {
        trustedIssuer: {
          ...expected.trustedIssuer,
          publicKey: base64urlDecode(strUtf8(overrides.trusted_issuer_public_key)),
        },
      }),
    };
    assert.equal(decodeLocalLoopbackHttpProof(compact).ok, proofCase.decode_local, proofCase.id);
    assert.equal(decodeProof(compact).ok, proofCase.decode_standard, proofCase.id);
    assert.equal(
      checkLocalLoopbackHttpEnvelope(strUtf8(profile.grant_compact), compact, caseExpected).ok,
      proofCase.envelope_local,
      proofCase.id,
    );
  }
});

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

test("local loopback HTTP proof is byte-distinct and nonce-bound", () => {
  const issuer = freshKey();
  const holder = freshKey();
  const grant: GrantProducer = {
    keyId: "issuer-1",
    issuer: "https://issuer.example.test",
    grantId: "urn:example:grant:1",
    audiences: ["https://resource.example.test"],
    issuedAt: 1000,
    notBefore: 1000,
    expiresAt: 2000,
    holderThumbprint: utf8(base64urlEncode(publicKeyThumbprintRaw(holder.publicKey))),
    operations: [{ name: "read", selectors: ["all"] }],
  };
  const grantInput = grantSigningInput(grant);
  assert.equal(grantInput.ok, true);
  if (!grantInput.ok) return;
  const grantCompact = assembleCompact(grantInput.value, signInput(grantInput.value, issuer.privateKey));
  assert.equal(grantCompact.ok, true);
  if (!grantCompact.ok) return;

  const proof: ProofProducer = {
    holderPublicKey: holder.publicKey,
    proofId: "urn:example:proof:loopback:1",
    method: "POST",
    targetUri: "http://127.0.0.1:4000/invoke",
    issuedAt: 1400,
    invocationId: "550e8400-e29b-41d4-a716-446655440000",
    operation: "read",
    grantCompact: grantCompact.value,
    castArguments: { t: "null" },
    nonce: "nonce-1",
  };
  const proofInput = localLoopbackHttpProofSigningInput(proof);
  assert.equal(proofInput.ok, true);
  if (!proofInput.ok) return;
  const signature = signInput(proofInput.value, holder.privateKey);
  const proofCompact = assembleLocalLoopbackHttpCompact(proofInput.value, signature);
  assert.equal(proofCompact.ok, true);
  if (!proofCompact.ok) return;

  assert.equal(decodeLocalLoopbackHttpProof(proofCompact.value).ok, true);
  assert.equal(decodeProof(proofCompact.value).ok, false);
  assert.equal(assembleCompact(proofInput.value, signature).ok, false);
  assert.equal(assembleLocalLoopbackHttpCompact(grantInput.value, signInput(grantInput.value, issuer.privateKey)).ok, false);

  const expected: ExpectedRequest = {
    trustedIssuer: { keyId: "issuer-1", publicKey: issuer.publicKey },
    issuer: "https://issuer.example.test",
    audience: "https://resource.example.test",
    method: "POST",
    targetUri: "http://127.0.0.1:4000/invoke",
    invocationId: "550e8400-e29b-41d4-a716-446655440000",
    operation: "read",
    castArguments: { t: "null" },
    evaluationTime: 1400,
    clockSkew: 0,
    proofMaxAge: 300,
    nonce: { kind: "required", value: "nonce-1" },
  };
  assert.equal(checkLocalLoopbackHttpEnvelope(grantCompact.value, proofCompact.value, expected).ok, true);
  assert.equal(checkLocalLoopbackHttpEnvelope(grantCompact.value, proofCompact.value, {
    ...expected,
    nonce: { kind: "required", value: "wrong-nonce" },
  }).ok, false);
  assert.equal(checkLocalLoopbackHttpEnvelope(grantCompact.value, proofCompact.value, {
    ...expected,
    trustedIssuer: { keyId: "issuer-1", publicKey: holder.publicKey },
  }).ok, false);
  assert.equal(checkLocalLoopbackHttpEnvelope(grantCompact.value, proofCompact.value, {
    ...expected,
    invocationId: "550e8400-e29b-41d4-a716-446655440001",
  }).ok, false);
  assert.equal(checkLocalLoopbackHttpEnvelope(grantCompact.value, proofCompact.value, {
    ...expected,
    nonce: null,
  } as unknown as ExpectedRequest).ok, false);
  assert.equal(checkEnvelope(grantCompact.value, proofCompact.value, expected).ok, false);
  const { nonce: _nonce, ...proofWithoutNonce } = proof;
  assert.equal(localLoopbackHttpProofSigningInput(proofWithoutNonce).ok, false);
  assert.equal(
    localLoopbackHttpProofSigningInput({ ...proof, proofId: "x".repeat(513) }).ok,
    false,
    "the inherited identifier_bytes maximum must gate local proof production",
  );
  assert.equal(
    proofSigningInput({
      ...proof,
      proofId: "x".repeat(513),
      targetUri: "https://resource.example.test/invoke",
    }).ok,
    true,
    "the existing standard producer verdict must remain unchanged",
  );
  assert.equal(
    checkLocalLoopbackHttpEnvelope(grantCompact.value, proofCompact.value, {
      ...expected,
      nonce: { kind: "not_required" },
    }).ok,
    false,
  );
});
