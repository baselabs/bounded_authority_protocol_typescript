# Content assertions

A content assertion (`bap-content-assertion/1`) is a signed statement about exact content
bytes: an attestor key binds the content's digest to an issuer, one audience, a stable subject
(the lineage the content belongs to), a pinned semantic profile, a generation number with its
predecessor, and a validity window. Typical uses are a published configuration, a policy document
or a model card that a runtime must load only in a version its publisher signed, and only in
order. The verifier never parses the content; it checks that the digest you computed over the
exact bytes you hold is the one the attestor signed. The functions are in the `contentAssertion`
namespace and use major 1's Ed25519 mechanics with their own `typ`, `ba+content-assertion`. Every
sample runs as written on Node.js.

## Publish and verify one assertion

```ts
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { boundsNew, contentAssertion, strUtf8 } from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const publisher = generateKeyPairSync("ed25519");

// The semantic profile: an identifier, plus the digest of the schema document it names.
const profile = "urn:example:triage-config:1";
const profileDigest = createHash("sha256").update("triage-config schema, revision 1").digest();

// The exact bytes the runtime will load.
const content = strUtf8(JSON.stringify({ model: "triage-v4", threshold: 0.82 }));
const contentDigest = contentAssertion.contentDigest(content); // SHA-256("BAP1-CONTENT\0" || content)
assert.ok(contentDigest.ok);

const input = contentAssertion.assertionSigningInput({
  attestorKeyId: "publisher-1",
  jti: "config-triage-0001",
  iss: "https://publisher.example",
  aud: "https://runtime.example",
  sub: "config:triage",
  profile,
  profileDigest,
  contentDigest: contentDigest.value,
  gen: 1, // the first generation...
  prev: new Uint8Array(32), // ...has the all-zero predecessor
  iat: 1_000,
  nbf: 1_000,
  exp: 90_000,
});
assert.ok(input.ok);
const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
const assertion = contentAssertion.assembleCompact(input.value, sign(null, message, publisher.privateKey));
assert.ok(assertion.ok);

// The runtime: digest the bytes it actually holds, then verify against its own expectations.
const expected = {
  attestor: { keyId: "publisher-1", publicKey: raw(publisher.publicKey), validFrom: 0, validBefore: null },
  issuer: "https://publisher.example",
  audience: "https://runtime.example",
  subject: "config:triage",
  profile,
  profileDigest,
  contentDigest: contentDigest.value,
  now: 5_000,
  bounds: boundsNew(), // required here; boundsNew() means the profile maximum
};
const facts = contentAssertion.verifyAssertion(assertion.value, expected);
assert.ok(facts.ok);
assert.equal(facts.value.gen, 1);
assert.equal(facts.value.trust, "not_evaluated");

// One changed byte of content is a different digest, and the assertion no longer matches it.
const edited = contentAssertion.contentDigest(strUtf8(JSON.stringify({ model: "triage-v4", threshold: 0.5 })));
assert.ok(edited.ok);
assert.deepEqual(contentAssertion.verifyAssertion(assertion.value, { ...expected, contentDigest: edited.value }), { ok: false });
```

`verifyAssertion` accepts only if the header is exactly `{alg: "EdDSA", kid, typ:
"ba+content-assertion"}` and the payload exactly `{v, jti, iss, aud, sub, profile, profile_digest,
content_digest, gen, prev, iat, nbf, exp}`, both canonical; `kid` equals the attestor's key id;
`iss`, `aud`, `sub`, `profile` and both digests equal the expected values; `iat` and `nbf` are not
before the attestor key's `validFrom` and `exp` is not after its `validBefore` (when bounded);
`nbf <= now < exp`; and the signature verifies under the attestor key (rule S1). An assertion is at
most 8,192 bytes, and content at most 65,536 bytes (`content_bytes`, which you can tighten).

`ContentAssertionFacts` repeats the signed fields and adds the attestor key fingerprint and
`digest`, the SHA-256 of the exact assertion bytes. Read fields by name: inspection prints the
facts as `#BoundedAuthorityProtocol.ContentAssertion.V1.ContentAssertionFacts<redacted>` (0.7.0
prints `ContentAssertionFacts<redacted>`), and in
0.8.0 `JSON.stringify` and `String()` of the facts throw (see the
[reference](../reference.md#facts-and-decoded-types)). To keep facts for a later `verifySuccessor`,
store a copy of their fields (`{ ...facts }`); a reconstructed plain object with those fields is
accepted.

## Successors

A new version of the same subject is a new assertion with `gen` one higher and `prev` set to the
predecessor's `digest`. `verifySuccessor(predecessor, successor, bounds)` compares two facts values:
same issuer, audience, subject, profile and profile digest; consecutive generations; `prev` equal
to the predecessor's digest; an issuance time not earlier than the predecessor's; and a different
`jti`. It does not check signatures or the current time, so pass it facts that `verifyAssertion`
returned (an expired predecessor is fine: verify it with a `now` inside its window, or keep the
facts you verified when you first loaded it).

```ts
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { boundsNew, contentAssertion, strUtf8 } from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const publisher = generateKeyPairSync("ed25519");
const attestor = { keyId: "publisher-1", publicKey: raw(publisher.publicKey), validFrom: 0, validBefore: null };
const profileDigest = createHash("sha256").update("retention-policy schema 3").digest();
const bounds = boundsNew();

function publish(text: string, gen: number, prev: Uint8Array, iat: number) {
  const contentDigest = contentAssertion.contentDigest(strUtf8(text));
  assert.ok(contentDigest.ok);
  const input = contentAssertion.assertionSigningInput({
    attestorKeyId: "publisher-1", jti: `retention-policy-${gen}`, iss: "https://records.example",
    aud: "https://archive.example", sub: "policy:retention", profile: "urn:example:retention:3",
    profileDigest, contentDigest: contentDigest.value, gen, prev, iat, nbf: iat, exp: iat + 86_400,
  });
  assert.ok(input.ok);
  const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
  const compact = contentAssertion.assembleCompact(input.value, sign(null, message, publisher.privateKey));
  assert.ok(compact.ok);
  const facts = contentAssertion.verifyAssertion(compact.value, {
    attestor, issuer: "https://records.example", audience: "https://archive.example", subject: "policy:retention",
    profile: "urn:example:retention:3", profileDigest, contentDigest: contentDigest.value, now: iat + 10, bounds,
  });
  assert.ok(facts.ok);
  return facts.value;
}

const first = publish("keep invoices 7 years", 1, new Uint8Array(32), 1_000);
const second = publish("keep invoices 10 years", 2, first.digest, 2_000);
assert.ok(contentAssertion.verifySuccessor(first, second, bounds).ok);

// Skipping a generation, or naming the wrong predecessor, rejects.
const third = publish("keep invoices 5 years", 3, second.digest, 3_000);
assert.deepEqual(contentAssertion.verifySuccessor(first, third, bounds), { ok: false });
const fork = publish("keep invoices 1 year", 2, new Uint8Array(32).fill(9), 2_500);
assert.deepEqual(contentAssertion.verifySuccessor(first, fork, bounds), { ok: false });
```

## Other functions

- `decodeAssertion(compact, bounds?)` parses and validates the structure without the signature or
  any context and returns the fields with `verification: "not_evaluated"`, for display.
- `assertionDigest(compact, bounds?)` checks the structure and returns the SHA-256 of the exact
  compact bytes (the value a successor's `prev` must carry). It makes no signature claim.

## What stays with you

Validate the content against its schema before you act on it: a valid signature says who published
these bytes, not that they are well formed. Decide which attestor keys you trust and for which
subjects, keep the highest generation you have accepted per subject (so an old but still valid
assertion cannot roll you back), and handle forks, first-version bootstrap and revocation by your
own policy. The verifier does not derive key windows or walk key transitions. The full rules are
in the
[content-assertion profile specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md)
and [ADR 0037](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/adr/0037-content-assertion-profile.md).
