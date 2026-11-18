import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, checkEnvelope, grantSigningInput, jwkFromPublicKey, localLoopbackHttpProofSigningInput, assembleLocalLoopbackHttpCompact, checkLocalLoopbackHttpEnvelope, localLoopbackHttpUriNormalize, strUtf8, utf8Str, thumbprint,
  type ExpectedRequest, type SigningInput, type Tagged,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const message = (i: SigningInput): Uint8Array => Buffer.concat([i.protectedSegment, Buffer.from("."), i.payloadSegment]);
const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");

const g = grantSigningInput({
  keyId: "k1", issuer: "https://issuer.example", grantId: "grant-n", audiences: ["https://telemetry.example"],
  issuedAt: 1_000, notBefore: 1_000, expiresAt: 9_000,
  holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
  operations: [{ name: "readings.upload", selectors: ["all"] }],
});
assert.ok(g.ok);
const grant = assembleCompact(g.value, sign(null, message(g.value), issuer.privateKey));
assert.ok(grant.ok);

const args: Tagged = { t: "object", v: new Map() };
const invocationId = randomUUID();
const p = localLoopbackHttpProofSigningInput({
  holderPublicKey: raw(holder.publicKey), proofId: "proof-n", method: "PUT",
  targetUri: "http://127.0.0.1:3210/readings", issuedAt: 1_100, invocationId,
  operation: "readings.upload", grantCompact: grant.value, castArguments: args,
  nonce: "srv-nonce-5c1e", // the value your server issued
});
assert.ok(p.ok);
const proof = assembleLocalLoopbackHttpCompact(p.value, sign(null, message(p.value), holder.privateKey));
assert.ok(proof.ok);

const expected: ExpectedRequest = {
  trustedIssuer: { keyId: "k1", publicKey: raw(issuer.publicKey) },
  issuer: "https://issuer.example", audience: "https://telemetry.example", method: "PUT",
  targetUri: "http://127.0.0.1:3210/readings", invocationId, operation: "readings.upload",
  castArguments: args, evaluationTime: 1_120, clockSkew: 30, proofMaxAge: 120,
  nonce: { kind: "required", value: "srv-nonce-5c1e" },
};
assert.ok(checkLocalLoopbackHttpEnvelope(grant.value, proof.value, expected).ok);
assert.deepEqual(checkEnvelope(grant.value, proof.value, expected), { ok: false });
assert.deepEqual(checkLocalLoopbackHttpEnvelope(grant.value, proof.value, { ...expected, nonce: { kind: "not_required" } }), { ok: false });
assert.deepEqual(checkLocalLoopbackHttpEnvelope(grant.value, proof.value, { ...expected, nonce: { kind: "required", value: "other" } }), { ok: false });

const normalized = localLoopbackHttpUriNormalize(strUtf8("http://[::1]:80/a/../readings"));
assert.ok(normalized.ok);
assert.equal(utf8Str(normalized.value), "http://[::1]/readings");
assert.deepEqual(localLoopbackHttpUriNormalize(strUtf8("http://localhost/readings")), { ok: false });
assert.deepEqual(localLoopbackHttpUriNormalize(strUtf8("http://192.0.2.1/readings")), { ok: false });
