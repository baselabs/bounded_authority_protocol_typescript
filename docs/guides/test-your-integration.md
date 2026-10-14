# Test your integration

Everything in this package is pure: no clock, no network, no storage. That makes integration tests
straightforward to write against the real thing. Generate real keys, build real grants and proofs
with the producer functions, sign them with `node:crypto`, and run them through the same
verification call your service makes. There is nothing to mock, and a test that stubs the verifier
proves nothing about it.

## A fixture factory

Keep one function that mints a valid envelope from a few overridable fields. Each test then starts
from a request that verifies and changes one thing.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, checkEnvelope, grantSigningInput, jsonDecode, jwkFromPublicKey, proofSigningInput,
  strUtf8, thumbprint, type EnvelopeFacts, type ExpectedRequest, type SigningInput,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const message = (i: SigningInput): Uint8Array => Buffer.concat([i.protectedSegment, Buffer.from("."), i.payloadSegment]);
const T0 = 1_760_000_000; // a fixed test clock, in seconds

function mintEnvelope(options: { issuedAt?: number; expiresAt?: number; argumentsJson?: string } = {}) {
  const issuer = generateKeyPairSync("ed25519");
  const holder = generateKeyPairSync("ed25519");
  const g = grantSigningInput({
    keyId: "test-issuer", issuer: "https://issuer.test", grantId: `grant-${randomUUID()}`,
    audiences: ["https://service.test"], issuedAt: options.issuedAt ?? T0, notBefore: options.issuedAt ?? T0,
    expiresAt: options.expiresAt ?? T0 + 3_600,
    holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
    operations: [{ name: "tickets.close", selectors: [{ kind: "one_of", path: ["queue"], values: [
      { t: "string", v: strUtf8("support") }, { t: "string", v: strUtf8("billing") },
    ] }] }],
  });
  assert.ok(g.ok);
  const grant = assembleCompact(g.value, sign(null, message(g.value), issuer.privateKey));
  assert.ok(grant.ok);
  const castArguments = jsonDecode(strUtf8(options.argumentsJson ?? '{"queue":"support","ticket":981}'));
  const invocationId = randomUUID();
  const p = proofSigningInput({
    holderPublicKey: raw(holder.publicKey), proofId: `proof-${invocationId}`, method: "POST",
    targetUri: "https://service.test/tickets/981/close", issuedAt: T0 + 10, invocationId,
    operation: "tickets.close", grantCompact: grant.value, castArguments,
  });
  assert.ok(p.ok);
  const proof = assembleCompact(p.value, sign(null, message(p.value), holder.privateKey));
  assert.ok(proof.ok);
  const expected: ExpectedRequest = {
    trustedIssuer: { keyId: "test-issuer", publicKey: raw(issuer.publicKey) },
    issuer: "https://issuer.test", audience: "https://service.test", method: "POST",
    targetUri: "https://service.test/tickets/981/close", invocationId, operation: "tickets.close",
    castArguments, evaluationTime: T0 + 20, clockSkew: 30, proofMaxAge: 120, nonce: { kind: "not_required" },
  };
  return { grant: grant.value, proof: proof.value, expected };
}

// The positive control: an untouched envelope verifies.
const base = mintEnvelope();
assert.ok(checkEnvelope(base.grant, base.proof, base.expected).ok);

// Negative cases: change one input at a time; every one must be the closed rejection.
const otherKey = raw(generateKeyPairSync("ed25519").publicKey);
const otherArgs = jsonDecode(strUtf8('{"queue":"security","ticket":981}'));
const contextChanges: Array<[string, Partial<ExpectedRequest>]> = [
  ["untrusted issuer key", { trustedIssuer: { keyId: "test-issuer", publicKey: otherKey } }],
  ["other audience", { audience: "https://other.test" }],
  ["other method", { method: "DELETE" }],
  ["other target", { targetUri: "https://service.test/tickets/982/close" }],
  ["other invocation", { invocationId: randomUUID() }],
  ["arguments outside the grant", { castArguments: otherArgs }],
  ["after expiry", { evaluationTime: T0 + 3_600 + 31 }],
  ["proof too old", { evaluationTime: T0 + 10 + 120 + 31 }],
];
for (const [name, change] of contextChanges) {
  assert.deepEqual(checkEnvelope(base.grant, base.proof, { ...base.expected, ...change }), { ok: false }, name);
}

// Byte tampering: flip one bit in the last signature character of the proof.
const tampered = Uint8Array.from(base.proof);
tampered[tampered.length - 2] = tampered[tampered.length - 2]! ^ 0x01;
assert.deepEqual(checkEnvelope(base.grant, tampered, base.expected), { ok: false });

// A grant whose holder may only touch other queues.
const outside = mintEnvelope({ argumentsJson: '{"queue":"security","ticket":981}' });
assert.deepEqual(checkEnvelope(outside.grant, outside.proof, outside.expected), { ok: false });

// Your service's stateful steps, tested with real facts: replay and revocation are refused by
// your code, because checkEnvelope accepts the identical envelope every time.
function decide(facts: EnvelopeFacts, seen: Set<string>, revoked: Set<string>): "execute" | "refuse" {
  if (revoked.has(facts.grantId)) return "refuse";
  const key = `${facts.grantId}/${facts.invocationId}`;
  if (seen.has(key)) return "refuse";
  seen.add(key);
  return "execute";
}
const seen = new Set<string>();
const first = checkEnvelope(base.grant, base.proof, base.expected);
const again = checkEnvelope(base.grant, base.proof, base.expected);
assert.ok(first.ok && again.ok);
assert.equal(decide(first.value, seen, new Set()), "execute");
assert.equal(decide(again.value, seen, new Set()), "refuse"); // the replay
const fresh = mintEnvelope();
const freshFacts = checkEnvelope(fresh.grant, fresh.proof, fresh.expected);
assert.ok(freshFacts.ok);
assert.equal(decide(freshFacts.value, seen, new Set([freshFacts.value.grantId])), "refuse"); // revoked
```

Write the positive control first and keep it: if a refactor breaks the fixture, every negative case
would still "pass" by rejecting, and only the positive control notices.

## Test your own state, too

The package proves what the bytes say; replay protection and revocation are yours. The end of the
sample above tests them with the same real fixtures: it verifies an envelope, reserves its
invocation id, and checks that the second presentation of the identical envelope is refused by the
service's own code even though `checkEnvelope` accepts it again.

## Both backends

On Node.js the package uses `node:crypto`; everywhere else it uses the portable `@noble` backend.
Verdicts are the same, and this repository proves it on every corpus. To run your own suite on the
portable backend as well, add the condition:

```bash
node --conditions=bap-portable --test
```

`BACKEND_ID` tells you which one a run resolved.

## Conformance vectors

You do not need to vendor the protocol's conformance corpora to trust this package: its CI
recomputes every certified verdict on every change (see the
[README](../../README.md#certified-not-self-tested)). If you implement part of the protocol
yourself, for example a signer in another language, the corpora are published in the
[protocol repository](https://github.com/baselabs/bounded_authority_protocol/tree/main/priv/conformance/),
each with an `index.json` whose SHA-256 you can pin.
