import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { assembleCompact, grantSigningInput, jwkFromPublicKey, thumbprint, verifyGrant, v2, v3 } from "@bounded-authority-protocol/verifier";

// The public root replaces every historical dist/... deep import. Select wire majors explicitly.
assert.equal(typeof v2.checkEnvelope, "function");
assert.equal(typeof v3.checkEnvelope, "function");
const keys = generateKeyPairSync("ed25519");
const publicKey = Buffer.from(keys.publicKey.export({ format: "jwk" }).x!, "base64url");
const input = grantSigningInput({ keyId: "migrate", issuer: "urn:example:issuer", grantId: "grant-migrate",
  audiences: ["urn:example:resource"], issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
  holderThumbprint: thumbprint(jwkFromPublicKey(publicKey)), operations: [{ name: "records.read", selectors: ["all"] }] });
assert.ok(input.ok);
const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
const compact = assembleCompact(input.value, sign(null, message, keys.privateKey));
assert.ok(compact.ok);
// 0.8+ frames conforming signatures only. Placeholder 64-byte signatures are not a fixture.
assert.deepEqual(assembleCompact(input.value, new Uint8Array(64)), { ok: false });
const facts = verifyGrant(compact.value, { keyId: "migrate", publicKey },
  { issuer: "urn:example:issuer", audience: "urn:example:resource", evaluationTime: 1500, clockSkew: 0 });
assert.ok(facts.ok);
assert.throws(() => JSON.stringify(facts.value), { name: "InvalidError" });
assert.throws(() => String(facts.value), { name: "InvalidError" });
// Explicit approved projection, never spreading facts into a log/event/response.
const event = { stage: "verified", authorization: facts.value.authorization };
assert.equal(JSON.stringify(event), '{"stage":"verified","authorization":"not_evaluated"}');
const historicalDeepPath = "@bounded-authority-protocol/verifier/dist/src/v3.js";
await assert.rejects(() => import(historicalDeepPath));
