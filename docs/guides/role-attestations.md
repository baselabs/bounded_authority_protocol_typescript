# Role attestations

A role attestation (`bap-role-attestation/1`) is a small signed statement: an attestor key
says that a subject key, known by a key id, holds the `issuer` or the `holder` role for a
bounded window. A deployment can use one to publish which keys may issue grants, or to vouch for a
holder key, without changing any grant. The profile uses major 1's Ed25519 mechanics but its own
`typ`, `ba+role-attestation`, and no contract-major parses it. Its four functions are in the
`roleAttestation` namespace. Every sample runs as written on Node.js.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { roleAttestation, verifyGrant } from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const root = generateKeyPairSync("ed25519"); // the attestor, for example an organization's root key
const issuerKey = generateKeyPairSync("ed25519"); // the subject

// The root key attests that "issuer-2026-10" may act as an issuer from t=1000 until t=2000.
const input = roleAttestation.attestationSigningInput({
  keyId: "root-2026",
  jti: "attestation-0001",
  subjectKeyId: "issuer-2026-10",
  subjectPublicKey: raw(issuerKey.publicKey),
  role: "issuer",
  notBefore: 1_000,
  expiresAt: 2_000,
});
assert.ok(input.ok);
const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
const attestation = roleAttestation.assembleAttestationCompact(input.value, sign(null, message, root.privateKey));
assert.ok(attestation.ok);

// The verifier supplies the attestor key it trusts (with its validity window), the subject it
// expects, and the time.
const expected = {
  attestor: { keyId: "root-2026", publicKey: raw(root.publicKey), validFrom: 0, validBefore: null },
  subjectKeyId: "issuer-2026-10",
  subjectPublicKey: raw(issuerKey.publicKey),
  now: 1_500,
};
const facts = roleAttestation.verifyAttestation(attestation.value, expected);
assert.ok(facts.ok);
assert.equal(facts.value.role, "issuer");
assert.equal(facts.value.verification, "signature_and_window");
assert.equal(facts.value.trust, "not_evaluated");

// The window is half-open: [notBefore, expiresAt).
assert.deepEqual(roleAttestation.verifyAttestation(attestation.value, { ...expected, now: 2_000 }), { ok: false });
// A different subject key under the same key id rejects.
assert.deepEqual(
  roleAttestation.verifyAttestation(attestation.value, { ...expected, subjectPublicKey: raw(generateKeyPairSync("ed25519").publicKey) }),
  { ok: false },
);
// An attestation is not a grant, and a grant verifier refuses it.
assert.deepEqual(
  verifyGrant(attestation.value, { keyId: "root-2026", publicKey: raw(root.publicKey) },
    { issuer: "root-2026", audience: "x", evaluationTime: 1_500, clockSkew: 0 }),
  { ok: false },
);
```

## What `verifyAttestation` checks

- The header is exactly `{alg: "EdDSA", kid, typ: "ba+role-attestation"}` and the payload exactly
  `{v, jti, key_id, public_key, role, nbf, exp}`, both in canonical JSON (JCS) bytes.
- The header `kid` equals `expected.attestor.keyId` and the signature verifies under the attestor
  key (rule S1).
- The payload's `key_id` equals `expected.subjectKeyId` and its `public_key` equals
  `expected.subjectPublicKey` byte for byte.
- It is not a self-attestation: the subject's key and key id both differ from the attestor's.
- The attestation window sits inside the attestor key's window (`nbf >= validFrom`, and
  `exp <= validBefore` when the key's window is bounded), and `nbf <= now < exp`.
- `role` is `issuer` or `holder`; times and the attestor window are integers within 2^53 - 1.

`AttestationFacts` carries the attestor and subject key ids and RFC 7638 fingerprints, the role,
`jti` and window, with `trust: "not_evaluated"` and no authorization marker. Whether the attestor
key is one you trust for this purpose, and what the role permits in your system, are your
decisions. `decodeAttestation` parses an attestation without checking its signature or window
(`verification: "not_evaluated"`), for display only.

The full rules are in the
[role-attestation profile specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md).
