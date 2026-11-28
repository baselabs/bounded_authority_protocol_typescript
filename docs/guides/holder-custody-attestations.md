# Holder custody attestations

An attestor signs the custody class of a specific Ed25519 holder key for a bounded
window. The class `standard` means the holder holds its own key. The class `hosted`
means an operator holds the key under a non-exporting handle and signs on the holder's
behalf. The host selects `holderCustodyAttestation` and supplies its own trusted
attestor, expected holder binding, time, and optional tighter bounds.

The example generates keys to show all four calls. In a deployment, sign the canonical
segments using the attestor's external key handle. Install trusted attestor keys and enroll
holder keys only after checking that each public key is torsion-free.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { holderCustodyAttestation } from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject) => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const attestor = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const holderPublicKey = raw(holder.publicKey);
const input = holderCustodyAttestation.attestationSigningInput({
  keyId: "custody-attestor-1",
  jti: "custody-1",
  subjectKeyId: "holder-1",
  subjectPublicKey: holderPublicKey,
  custodyClass: "standard",
  notBefore: 100,
  expiresAt: 200,
});
assert.ok(input.ok);

const { protectedSegment, payloadSegment } = input.value;
const message = Buffer.concat([protectedSegment, Buffer.from("."), payloadSegment]);
const signature = sign(null, message, attestor.privateKey);
const compact = holderCustodyAttestation.assembleAttestationCompact(input.value, signature);
assert.ok(compact.ok);

const decoded = holderCustodyAttestation.decodeAttestation(compact.value);
assert.ok(decoded.ok);
assert.equal(decoded.value.verification, "not_evaluated");

const expected = {
  attestor: { keyId: "custody-attestor-1", publicKey: raw(attestor.publicKey), validFrom: 0, validBefore: 200 },
  subjectKeyId: "holder-1",
  subjectPublicKey: holderPublicKey,
  now: 150,
};
const verified = holderCustodyAttestation.verifyAttestation(compact.value, expected);
assert.ok(verified.ok);
assert.equal(verified.value.custodyClass, "standard");
assert.equal(verified.value.trust, "not_evaluated");
assert.deepEqual(holderCustodyAttestation.verifyAttestation(compact.value, { ...expected, now: 200 }), { ok: false });
```

Verification checks the exact JWS signature, both key IDs, the expected holder public
key, separation of attestor and holder, containment in the attestor window, and
`notBefore <= now < expiresAt`. The verified facts carry key IDs and RFC 7638
thumbprints. The host owns operational trust, revocation, replay checks, and any
authorization decision. Per-grant holder standing comes from the grant's `cnf.jkt`
binding.

[API reference](../reference.md#the-holdercustodyattestation-namespace) ·
[Normative specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-holder-custody-attestation-v1.md)
