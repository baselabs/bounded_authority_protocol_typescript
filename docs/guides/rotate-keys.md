# Rotate keys

The package never discovers or stores keys: every verification takes the trusted public keys as
arguments. Key management is therefore yours, and this guide covers the three parts the protocol
shapes: what to check when you enroll a key, how to keep verifying while an issuer rotates, and how
an archive signing key hands over to its successor with an authenticated key transition. Every
sample runs as written on Node.js.

## Enroll a key once, with the full check

Verification applies rule S1 to every Ed25519 key it is given (canonical encoding, not one of the
eight small-order points, on the curve), but it deliberately skips the subgroup check. The protocol
puts that check at the host: call `torsionFree` when you enroll a key, when you install it as
trusted, and before you compare it with a deny list or revocation list. A canonical, torsion-free
key has exactly one encoding per secret, so comparing keys (or their thumbprints) compares
identities.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { acceptablePublicKey, publicKeyThumbprintRaw, torsionFree } from "@bounded-authority-protocol/verifier";

// Ed25519 (majors 1 and 2): reject anything that is not acceptable and torsion free.
function enrollEd25519(publicKey: Uint8Array): Uint8Array {
  if (!acceptablePublicKey(publicKey) || !torsionFree(publicKey)) throw new Error("key refused at enrollment");
  return publicKeyThumbprintRaw(publicKey); // the 32-byte RFC 7638 thumbprint: a stable key identity
}

const ed = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
const edKey = Buffer.from(ed.x!, "base64url");
assert.equal(enrollEd25519(edKey).length, 32);
assert.throws(() => enrollEd25519(new Uint8Array(32))); // the all-zero small-order point
```

For P-256 keys (major 3), check the point: 65 bytes, the `0x04` prefix, both coordinates below the
field prime, on the curve. New in 0.8.0: `v3.publicKeyThumbprintRaw` does it and
returns the key's fingerprint.

```ts since=0.8.0
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { v3 } from "@bounded-authority-protocol/verifier";

// Refuses anything that is not an acceptable P-256 point with InvalidError.
function enrollP256(publicKey: Uint8Array): Uint8Array {
  return v3.publicKeyThumbprintRaw(publicKey); // the 32-byte RFC 7638 thumbprint of the P-256 key
}

const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
const ecKey = Buffer.concat([Buffer.from([0x04]), Buffer.from(ec.x!, "base64url"), Buffer.from(ec.y!, "base64url")]);
assert.equal(enrollP256(ecKey).length, 32);
const offCurve = Buffer.from(ecKey);
offCurve[64] = offCurve[64]! ^ 1; // flip one bit of y
assert.throws(() => enrollP256(offCurve), { name: "InvalidError" });
```

On 0.7.0, which lacks that helper, encode and decode the key's canonical JWK: the decoder applies
the same point check (`trying` turns a refusal by the encoder, as in 0.8.0, into the
closed result).

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { trying, v3 } from "@bounded-authority-protocol/verifier";

const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
const ecKey = Buffer.concat([Buffer.from([0x04]), Buffer.from(ec.x!, "base64url"), Buffer.from(ec.y!, "base64url")]);
const acceptableP256 = (key: Uint8Array): boolean => {
  const decoded = trying(() => v3.jwkDecodePublic(v3.jwkEncodePublic(key)));
  return key.length === 65 && decoded.ok && decoded.value.ok;
};
assert.equal(acceptableP256(ecKey), true);
const offCurve = Buffer.from(ecKey);
offCurve[64] = offCurve[64]! ^ 1;
assert.equal(acceptableP256(offCurve), false);
```

## Rotate an issuer key

A grant names its issuer key in the protected header `kid`. To rotate:

1. Enroll the new key under a new `kid` and add it to the trusted set.
2. Switch the issuer to sign new grants with the new key.
3. Keep the old key trusted until every grant it signed has expired (its longest grant lifetime
   plus your clock skew), then remove it.

At verification, select the key by `kid` with `untrustedKeyLocator`, which reads only the header
and returns `trust: "not_evaluated"`. The `kid` is a lookup hint; the signature check against the
key you selected is what binds the grant to it. A `kid` you do not know is a refusal.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, grantSigningInput, jwkFromPublicKey, thumbprint, untrustedKeyLocator, verifyGrant,
  type GrantFacts, type Result, type SigningInput, type TrustedIssuer,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const message = (i: SigningInput): Uint8Array => Buffer.concat([i.protectedSegment, Buffer.from("."), i.payloadSegment]);
const holder = raw(generateKeyPairSync("ed25519").publicKey);

function issue(keyId: string, privateKey: KeyObject, grantId: string): Uint8Array {
  const input = grantSigningInput({
    keyId, issuer: "https://issuer.example", grantId, audiences: ["https://storage.example"],
    issuedAt: 1_000, notBefore: 1_000, expiresAt: 100_000,
    holderThumbprint: thumbprint(jwkFromPublicKey(holder)),
    operations: [{ name: "objects.list", selectors: ["all"] }],
  });
  assert.ok(input.ok);
  const compact = assembleCompact(input.value, sign(null, message(input.value), privateKey));
  assert.ok(compact.ok);
  return compact.value;
}

const oldKey = generateKeyPairSync("ed25519");
const newKey = generateKeyPairSync("ed25519");
const trusted = new Map<string, TrustedIssuer>([
  ["issuer-2026-09", { keyId: "issuer-2026-09", publicKey: raw(oldKey.publicKey) }],
  ["issuer-2026-10", { keyId: "issuer-2026-10", publicKey: raw(newKey.publicKey) }],
]);

function verifyAny(grant: Uint8Array): Result<GrantFacts> {
  const locator = untrustedKeyLocator(grant);
  const key = locator.ok ? trusted.get(locator.value.keyId) : undefined;
  if (key === undefined) return { ok: false };
  return verifyGrant(grant, key, {
    issuer: "https://issuer.example", audience: "https://storage.example", evaluationTime: 2_000, clockSkew: 60,
  });
}

const before = issue("issuer-2026-09", oldKey.privateKey, "grant-a");
const after = issue("issuer-2026-10", newKey.privateKey, "grant-b");
assert.ok(verifyAny(before).ok); // both verify during the overlap
assert.ok(verifyAny(after).ok);

// A grant whose kid names the new key but which the old key signed: the signature binds it.
assert.deepEqual(verifyAny(issue("issuer-2026-10", oldKey.privateKey, "grant-c")), { ok: false });

// Once the old grants have expired, retire the old key.
trusted.delete("issuer-2026-09");
assert.deepEqual(verifyAny(before), { ok: false });
assert.ok(verifyAny(after).ok);
```

## Hand over an archive key with an authenticated transition

Boundary anchors and anchored exports (see [Consumption chains and archives](chains-and-archives.md))
are signed by long-lived archive keys, and an archive may outlive several of them. A key
transition is a statement, signed by the current key, that names the next key and the time the
handover takes effect. `verifyKeyTransition` checks it against both keys as `HistoricalPublicKey`
values, each with its own validity window `[validFrom, validBefore)` (`validBefore: null` means
open-ended):

- the header `kid` and `expected.currentKeyId` equal the old key's `keyId`, and
  `expected.nextKeyId` equals the new key's;
- the payload's transition id, chain id, `effective_at`, both key fingerprints and `to_key_id`
  equal the expected values, and both fingerprints match the keys you passed;
- `effectiveAt` lies inside both keys' windows;
- the two keys differ, and the old key's signature verifies.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, keyTransitionSigningInput, publicKeyThumbprintRaw, verifyKeyTransition,
  type HistoricalPublicKey,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const a = generateKeyPairSync("ed25519");
const b = generateKeyPairSync("ed25519");

// The windows overlap so the handover time can sit inside both.
const keyA: HistoricalPublicKey = { keyId: "archive-a", publicKey: raw(a.publicKey), validFrom: 1_000, validBefore: 3_000 };
const keyB: HistoricalPublicKey = { keyId: "archive-b", publicKey: raw(b.publicKey), validFrom: 2_000, validBefore: null };

const input = keyTransitionSigningInput({
  transitionId: "rotation-2026-10", chainId: "audit:records", effectiveAt: 2_500,
  currentKeyId: keyA.keyId, currentPublicKey: keyA.publicKey,
  nextKeyId: keyB.keyId, nextPublicKey: keyB.publicKey,
});
assert.ok(input.ok);
const signature = sign(null, Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), a.privateKey);
const transition = assembleCompact(input.value, signature);
assert.ok(transition.ok);

const expected = {
  transitionId: "rotation-2026-10", chainId: "audit:records", effectiveAt: 2_500,
  currentKeyId: "archive-a", currentKeyFingerprint: publicKeyThumbprintRaw(keyA.publicKey),
  nextKeyId: "archive-b", nextKeyFingerprint: publicKeyThumbprintRaw(keyB.publicKey),
};
const facts = verifyKeyTransition(transition.value, keyA, keyB, expected);
assert.ok(facts.ok);
assert.equal(facts.value.verification, "authenticated_transition");
assert.equal(facts.value.trust, "not_evaluated");

// The handover time must sit inside both windows.
assert.deepEqual(verifyKeyTransition(transition.value, { ...keyA, validBefore: 2_400 }, keyB, expected), { ok: false });
// The new key cannot sign its own introduction.
assert.deepEqual(verifyKeyTransition(transition.value, keyB, keyA, expected), { ok: false });
```

`KeyTransitionFacts` carry the transition id, chain id, `effectiveAt` and both fingerprints, with
`trust: "not_evaluated"`: the transition proves the old key signed the handover, and whether you
trusted the old key at that time is still your decision. An anchored export verifies a whole
sequence of transitions in order; see [Consumption chains and archives](chains-and-archives.md).
