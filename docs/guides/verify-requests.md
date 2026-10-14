# Verify requests

A protected request carries two compact JWS values: the **grant**, signed by an issuer, and the
**proof**, signed by the holder for this one call. `checkEnvelope` verifies both and every binding
between them and your request, and returns `EnvelopeFacts`. This guide builds a grant and a proof
with real keys and then verifies the pair the way a resource server does. Every sample runs as
written on Node.js 22 or later, and the repository's test suite runs each one.

The examples use contract-major 1 (the package root). The `v2` and `v3` namespaces take the same
inputs; see [Contract-majors 2 and 3](contract-majors.md) for what changes.

## The three roles

| Role | Holds | Produces | In this package |
|---|---|---|---|
| Issuer | the issuer private key | a grant naming the holder's key, the audiences, the time window and the allowed operations | `grantSigningInput`, `assembleCompact` |
| Holder | the holder private key | one proof per call, bound to the grant, method, URI, invocation id, operation and arguments | `proofSigningInput`, `assembleCompact` |
| Resource | the issuer public keys it trusts | a decision to execute or refuse | `untrustedKeyLocator`, `checkEnvelope` |

This package builds signing inputs and verifies; it never signs. The samples sign with
`node:crypto`. In production use your KMS or HSM, or the
[signer package](https://www.npmjs.com/package/@bounded-authority-protocol/signer).

## The full flow

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact,
  checkEnvelope,
  grantSigningInput,
  jsonDecode,
  jwkFromPublicKey,
  proofSigningInput,
  strUtf8,
  thumbprint,
  untrustedKeyLocator,
  type ExpectedRequest,
  type SigningInput,
  type TrustedIssuer,
} from "@bounded-authority-protocol/verifier";

const rawPublicKey = (key: KeyObject): Uint8Array =>
  Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
// The bytes to sign are exactly ASCII(protectedSegment "." payloadSegment).
const signingMessage = (input: SigningInput): Uint8Array =>
  Buffer.concat([input.protectedSegment, Buffer.from("."), input.payloadSegment]);

const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const holderPublicKey = rawPublicKey(holder.publicKey);

// --- Issuer: the holder may read documents in the "reports" folder for one hour.
const grantInput = grantSigningInput({
  keyId: "issuer-2026-10",
  issuer: "https://issuer.example",
  grantId: "grant-7f3a",
  audiences: ["https://docs.example"],
  issuedAt: 1_760_000_000,
  notBefore: 1_760_000_000,
  expiresAt: 1_760_003_600,
  holderThumbprint: thumbprint(jwkFromPublicKey(holderPublicKey)),
  operations: [
    {
      name: "documents.read",
      selectors: [{ kind: "equals", path: ["folder"], value: { t: "string", v: strUtf8("reports") } }],
    },
  ],
});
assert.ok(grantInput.ok);
const grant = assembleCompact(grantInput.value, sign(null, signingMessage(grantInput.value), issuer.privateKey));
assert.ok(grant.ok);

// --- Holder: one call. The arguments are the parsed request the resource will act on.
const castArguments = jsonDecode(strUtf8(JSON.stringify({ folder: "reports", document_id: 42 })));
const invocationId = randomUUID(); // lowercase RFC 4122 UUID, unique per call
const proofInput = proofSigningInput({
  holderPublicKey,
  proofId: "proof-0001",
  method: "GET",
  targetUri: "https://docs.example/documents/42", // must already be in normal form
  issuedAt: 1_760_000_090,
  invocationId,
  operation: "documents.read",
  grantCompact: grant.value,
  castArguments,
});
assert.ok(proofInput.ok);
const proof = assembleCompact(proofInput.value, sign(null, signingMessage(proofInput.value), holder.privateKey));
assert.ok(proof.ok);

// --- Resource: pick the issuer key by the grant's kid, then verify everything at once.
const trustedIssuers = new Map<string, TrustedIssuer>([
  ["issuer-2026-10", { keyId: "issuer-2026-10", publicKey: rawPublicKey(issuer.publicKey) }],
]);
const locator = untrustedKeyLocator(grant.value); // header only: a hint, never trust
assert.ok(locator.ok);
const trustedIssuer = trustedIssuers.get(locator.value.keyId);
assert.ok(trustedIssuer !== undefined);

const expected: ExpectedRequest = {
  trustedIssuer,
  issuer: "https://issuer.example",
  audience: "https://docs.example", // this server's own identifier
  method: "GET", // from the HTTP request line
  targetUri: "https://docs.example/documents/42", // the URI this server received, normalized
  invocationId, // from the request (for example a header); reserve it after verification
  operation: "documents.read", // the operation this endpoint performs
  castArguments, // the arguments this server parsed from the request
  evaluationTime: 1_760_000_100, // your clock, in seconds
  clockSkew: 60, // 0 to 60
  proofMaxAge: 300, // 1 to 300
  nonce: { kind: "not_required" },
};
const result = checkEnvelope(grant.value, proof.value, expected);
assert.ok(result.ok);
assert.equal(result.value.grantId, "grant-7f3a");
assert.equal(result.value.invocationId, invocationId);
assert.equal(result.value.authorization, "not_evaluated");

// Any binding that differs rejects with the same closed value.
const otherFolder = jsonDecode(strUtf8(JSON.stringify({ folder: "payroll", document_id: 42 })));
assert.deepEqual(checkEnvelope(grant.value, proof.value, { ...expected, castArguments: otherFolder }), { ok: false });
assert.deepEqual(checkEnvelope(grant.value, proof.value, { ...expected, method: "DELETE" }), { ok: false });
assert.deepEqual(checkEnvelope(grant.value, proof.value, { ...expected, evaluationTime: 1_760_000_500 }), { ok: false });
```

## What `checkEnvelope` checks

Given the grant, the proof and your `ExpectedRequest`, it accepts only if all of these hold:

- the grant's protected header is exactly `{alg: "EdDSA", kid, typ: "ba+cap"}`, its `kid` equals
  `trustedIssuer.keyId`, and its signature verifies under `trustedIssuer.publicKey` (rule S1);
- the grant's `iss` equals `issuer`, its `aud` list contains `audience`, `iat < exp` and
  `nbf < exp`, `iat` and `nbf` are at most `evaluationTime + clockSkew`, and `exp` is greater than
  `evaluationTime - clockSkew`;
- the proof header is exactly `{alg: "EdDSA", jwk, typ: "dpop+jwt"}` with a public OKP Ed25519
  JWK (a private `d` member rejects), and the proof signature verifies under that key;
- the proof's `ath` is the SHA-256 of the exact grant bytes, and the JWK's RFC 7638 thumbprint
  equals the grant's `cnf.jkt`;
- the proof's `htm`, `htu`, `ba_inv` and `ba_op` equal `method`, `targetUri`, `invocationId` and
  `operation`, and `ba_req` equals the request digest of `operation` and `castArguments`;
- the proof's `iat` is in `[evaluationTime - proofMaxAge - clockSkew, evaluationTime + clockSkew]`;
- the nonce matches: absent from the proof for `{ kind: "not_required" }`, equal to `value` for
  `{ kind: "required", value }`;
- exactly one grant operation is named `operation`, and every one of its selectors matches
  `castArguments`.

It also rejects any input over the profile limits (see `MAXIMA` in the
[reference](../reference.md#bounds)), and any malformed context: a missing or wrong-width key, a
non-integer time, `clockSkew` above 60, or `proofMaxAge` of 0 or above 300.

## What stays with your service

`checkEnvelope` is pure. These steps are yours, in this order:

1. **Choose the trusted issuer key.** Map the grant's `kid` (from `untrustedKeyLocator`, which reads
   only the header) to a key you enrolled. An unknown `kid` is a refusal; never take a key from the
   request. See [Rotate keys](rotate-keys.md).
2. **Build `ExpectedRequest` from your own request handling**, not from the proof: the method and
   URI this server received, the operation this endpoint performs, and the arguments it parsed.
3. **Verify** with `checkEnvelope`.
4. **Reserve the invocation id once.** The package keeps no state, so the same envelope verifies
   again until it expires. Record `invocationId` (with `grantId`) in your own store and refuse a
   second use.
5. **Check revocation and policy**, then execute. `EnvelopeFacts` tells you what was proven; whether
   to act on it is your decision.

## Arguments and selectors

`castArguments` is a value in the package's tagged JSON algebra (`Tagged`): every value carries its
JSON type, strings are UTF-8 bytes, and integers and floats are distinct. The easiest way to build
one is to decode JSON text with `jsonDecode`, which applies the same strict rules as the wire
(duplicate member names reject, numbers keep their lexical type):

```ts
import assert from "node:assert/strict";
import { jsonDecode, selectorMatches, parseSelector, strUtf8, utf8Str } from "@bounded-authority-protocol/verifier";

const args = jsonDecode(strUtf8('{"folder":"reports","pages":12,"ratio":0.5}'));
assert.equal(args.t, "object");
if (args.t === "object") {
  const folder = args.v.get("folder");
  assert.ok(folder?.t === "string" && utf8Str(folder.v) === "reports");
  assert.equal(args.v.get("pages")?.t, "int");
  assert.equal(args.v.get("ratio")?.t, "float");
}

// Duplicate member names are refused (the closed InvalidError is thrown by jsonDecode).
assert.throws(() => jsonDecode(strUtf8('{"a":1,"a":2}')), { name: "InvalidError" });

// Selectors compare by type as well as value: integer 12 never equals float 12.0.
const intSelector = parseSelector(jsonDecode(strUtf8('{"kind":"equals","path":["pages"],"value":12}')));
const floatSelector = parseSelector(jsonDecode(strUtf8('{"kind":"equals","path":["pages"],"value":12.0}')));
assert.equal(selectorMatches(intSelector, args), true);
assert.equal(selectorMatches(floatSelector, args), false);
```

Major 1 has three selector kinds:

| Kind | Shape | Matches when |
|---|---|---|
| `all` | `"all"` or `{ kind: "all" }` | always |
| `equals` | `{ kind: "equals", path, value }` | the value at `path` exists and is semantically identical to `value` |
| `one_of` | `{ kind: "one_of", path, values }` | the value at `path` exists and is identical to one of `values` |

A `path` is a list of object member names; it never indexes into arrays. A missing path never
matches. Semantic identity compares types and values recursively, ignoring object member order.
Every selector of the named operation must match. Major 2 and 3 add the inclusive range kinds
`lte` and `gte`.

Two practical notes. `JSON.stringify(2.0)` is `"2"`, which decodes as an integer: if a grant
selector uses a float, make sure your arguments carry a float lexeme. And the request digest
(`ba_req`) covers the whole `castArguments` value, so the holder and the resource must build
exactly the same arguments.

## Target URIs

Target URIs are HTTPS, ASCII, with a host and no user information, query or fragment. Put query
parameters in `castArguments` instead. Both the proof's `htu` and your `targetUri` must already be
in normal form; use `uriNormalize` to compute it:

```ts
import assert from "node:assert/strict";
import { strUtf8, uriNormalize, utf8Str } from "@bounded-authority-protocol/verifier";

const normal = uriNormalize(strUtf8("HTTPS://Docs.Example:443/a/./b/../documents/%7e42"));
assert.ok(normal.ok);
assert.equal(utf8Str(normal.value), "https://docs.example/a/documents/~42");

assert.deepEqual(uriNormalize(strUtf8("https://docs.example/search?q=x")), { ok: false }); // query
assert.deepEqual(uriNormalize(strUtf8("http://docs.example/")), { ok: false }); // not HTTPS
```

Normalization lowercases the scheme and host, uppercases percent-escape hex, decodes escaped
unreserved characters, removes dot segments, maps an empty path to `/` and drops port 443. It does
no DNS, IDNA or network work.

## Nonces

When your server issues a nonce (for example in a `401` challenge), the holder includes it in the
proof and you pass it as `{ kind: "required", value }`. With `{ kind: "not_required" }`, a proof
that carries any nonce rejects.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, checkEnvelope, grantSigningInput, jwkFromPublicKey, proofSigningInput, thumbprint,
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
const p = proofSigningInput({
  holderPublicKey: raw(holder.publicKey), proofId: "proof-n", method: "PUT",
  targetUri: "https://telemetry.example/readings", issuedAt: 1_100, invocationId,
  operation: "readings.upload", grantCompact: grant.value, castArguments: args,
  nonce: "srv-nonce-5c1e", // the value your server issued
});
assert.ok(p.ok);
const proof = assembleCompact(p.value, sign(null, message(p.value), holder.privateKey));
assert.ok(proof.ok);

const expected: ExpectedRequest = {
  trustedIssuer: { keyId: "k1", publicKey: raw(issuer.publicKey) },
  issuer: "https://issuer.example", audience: "https://telemetry.example", method: "PUT",
  targetUri: "https://telemetry.example/readings", invocationId, operation: "readings.upload",
  castArguments: args, evaluationTime: 1_120, clockSkew: 30, proofMaxAge: 120,
  nonce: { kind: "required", value: "srv-nonce-5c1e" },
};
assert.ok(checkEnvelope(grant.value, proof.value, expected).ok);
assert.deepEqual(checkEnvelope(grant.value, proof.value, { ...expected, nonce: { kind: "not_required" } }), { ok: false });
assert.deepEqual(checkEnvelope(grant.value, proof.value, { ...expected, nonce: { kind: "required", value: "other" } }), { ok: false });
```

## Verifying a grant alone, and decoding for display

`verifyGrant` checks only the grant (header, signature, issuer, audience, time window) and returns
`GrantFacts`. Use it where there is no per-call proof, for example when an agent presents a grant
at registration. `decodeGrant` and `decodeProof` parse the structure without checking any
signature or context and return `verification: "not_evaluated"`; use them for display and
debugging, never for a decision. See the [reference](../reference.md#contract-major-1-the-package-root)
for every field.

## The local-loopback proof profile

For local development servers, `localLoopbackHttpProofSigningInput`,
`assembleLocalLoopbackHttpCompact`, `decodeLocalLoopbackHttpProof` and
`checkLocalLoopbackHttpEnvelope` implement a byte-distinct proof profile (`typ:
"ba+loopback-proof"`) whose target URIs are `http://127.0.0.1` or `http://[::1]` (optional port,
`:80` dropped) and whose nonce is mandatory. A standard `checkEnvelope` rejects these proofs, and
`checkLocalLoopbackHttpEnvelope` rejects standard ones. The grant is an ordinary major-1 grant.
