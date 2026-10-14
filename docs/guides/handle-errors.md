# Handle errors

## One closed result

Every verification, decode and producer function returns a `Result<T>`:

```text
{ ok: true, value: T }  |  { ok: false }
```

The failure carries no reason, no partial data and no error code, and that is deliberate: a
verifier that explains which check failed gives an attacker a probing oracle, and a partial result
invites a caller to act on half-verified data. Treat `{ ok: false }` as "refuse the request" and
move on. Check `ok` before reading `value`; TypeScript narrows the type for you.

```ts
import assert from "node:assert/strict";
import { decodeGrant, verifyGrant, type GrantFacts, type Result } from "@bounded-authority-protocol/verifier";

function handle(result: Result<GrantFacts>): string {
  if (!result.ok) return "403"; // no reason to log or return: the result has none
  return `200 for ${result.value.grantId}`;
}

const garbage = new TextEncoder().encode("not.a.grant");
assert.equal(handle(verifyGrant(garbage, { keyId: "k", publicKey: new Uint8Array(32) },
  { issuer: "https://issuer.example", audience: "https://api.example", evaluationTime: 0, clockSkew: 0 })), "403");
assert.deepEqual(decodeGrant(garbage), { ok: false });
```

## Functions that return booleans or throw

A few exports are not `Result`-shaped. The boolean checks never throw:

| Function | Returns |
|---|---|
| `verifyStrict`, `es256VerifyStrict` | `true` only for a valid signature under the strict rules; `false` for anything else, including wrong types or widths |
| `acceptablePublicKey`, `torsionFree` | `false` for anything that is not an acceptable (and torsion-free) 32-byte Ed25519 key |

These primitives throw the package's single error class, `InvalidError` (its `name` is
`"InvalidError"`), on invalid input:

| Function | Throws `InvalidError` when |
|---|---|
| `jsonDecode` | the bytes are not one strict, bounded JSON value (duplicate names, bad UTF-8, trailing data, over a limit) |
| `jcsEncode`, `semanticIdentity`, `typedProject`, `selectorMatches` | a tagged value cannot be canonicalized within the limits |
| `base64urlDecode` | the input is not canonical unpadded base64url, or decodes past the optional maximum |
| `boundsNew` | a limit name is unknown, or a value is not an integer, is not positive, widens a maximum, or changes a fixed width |
| `parseSelector` (root, `v2`, `v3`) | the object is not a valid selector for that major |
| `jwkEncodePublic`, `jwkFromPublicKey`, `thumbprint`, `thumbprintRaw`, `thumbprintPreimage`, `publicKeyThumbprintRaw` | the Ed25519 key is not 32 bytes or not acceptable (their `v3` forms: the key or JWK is not an acceptable P-256 point) |
| `sha256` | any part is not a `Uint8Array` |
| `fail`, `assert` | always, or when the condition is false (helpers for code built on the same contract) |

`utf8Str` throws the platform's `TypeError` on invalid UTF-8 (it uses a fatal `TextDecoder`).
`trying(fn)` runs `fn` and converts a thrown `InvalidError` into `{ ok: false }`, so you can give
your own helpers the same shape:

```ts
import assert from "node:assert/strict";
import { InvalidError, base64urlDecode, strUtf8, trying } from "@bounded-authority-protocol/verifier";

assert.throws(() => base64urlDecode(strUtf8("abc=")), InvalidError); // padding is not canonical
const decoded = trying(() => base64urlDecode(strUtf8("aGk")));
assert.ok(decoded.ok);
assert.deepEqual([...decoded.value], [0x68, 0x69]);
assert.deepEqual(trying(() => base64urlDecode(strUtf8("a"))), { ok: false });
```

An `InvalidError`'s message names the failed check for debugging. It is not part of the API and
can change in any release; never branch on it.

## Anything else is a bug

A `Result`-returning function converts only `InvalidError` into `{ ok: false }`. Any other
exception (a `TypeError`, a `RangeError`) propagates, because it means a defect in the package or a
call outside the documented types, never a verdict. Let it reach your error reporting, and please
[open an issue](https://github.com/baselabs/bounded_authority_protocol_typescript/issues) if the
input was well typed.

## Finding why a request rejects

When an integration rejects valid-looking requests, compare what the artifacts say with what you
passed. `decodeGrant` and `decodeProof` read the structure without any trust decision; use them in
development, never on the decision path.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact, decodeGrant, grantSigningInput, jwkFromPublicKey, thumbprint, verifyGrant,
  type ExpectedGrant, type TrustedIssuer,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const issuer = generateKeyPairSync("ed25519");
const input = grantSigningInput({
  keyId: "k1", issuer: "https://issuer.example", grantId: "grant-9", audiences: ["https://api.example"],
  issuedAt: 1_760_000_000, notBefore: 1_760_000_000, expiresAt: 1_760_003_600,
  holderThumbprint: thumbprint(jwkFromPublicKey(raw(generateKeyPairSync("ed25519").publicKey))),
  operations: [{ name: "reports.export", selectors: ["all"] }],
});
assert.ok(input.ok);
const grant = assembleCompact(input.value, sign(null,
  Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), issuer.privateKey));
assert.ok(grant.ok);

// Development-only helper: list the visible mismatches between a grant and your context.
function explain(compact: Uint8Array, trusted: TrustedIssuer, expected: ExpectedGrant): string[] {
  const decoded = decodeGrant(compact);
  if (!decoded.ok) return ["not a structurally valid major-1 grant (wrong major, malformed, or over a limit)"];
  const g = decoded.value;
  const problems: string[] = [];
  if (g.keyId !== trusted.keyId) problems.push(`kid is ${g.keyId}, trusted key is ${trusted.keyId}`);
  if (g.issuer !== expected.issuer) problems.push(`iss is ${g.issuer}`);
  if (!g.audiences.includes(expected.audience)) problems.push(`aud is ${g.audiences.join(", ")}`);
  if (g.notBefore > expected.evaluationTime + expected.clockSkew) problems.push("not yet valid");
  if (g.expiresAt <= expected.evaluationTime - expected.clockSkew) problems.push("expired");
  return problems.length > 0 ? problems : ["no visible mismatch: check the key bytes and signature"];
}

const trusted = { keyId: "k1", publicKey: raw(issuer.publicKey) };
const expected = { issuer: "https://issuer.example/", audience: "https://api.example", evaluationTime: Date.now(), clockSkew: 60 };
assert.deepEqual(verifyGrant(grant.value, trusted, expected), { ok: false });
assert.deepEqual(explain(grant.value, trusted, expected), ["iss is https://issuer.example", "expired"]);
```

That example shows two of the most common causes. The full list to check:

| Symptom | Usual cause |
|---|---|
| Every grant rejects | the trusted key is the wrong one, the wrong width (32 bytes for majors 1 and 2, 65 for major 3), or the grant is from another major (call the matching namespace) |
| `iss` or `aud` "looks right" | identifiers compare as exact strings: a trailing slash, letter case or a port is a different value |
| Valid only at some times | `evaluationTime` must be in **seconds**, not `Date.now()` milliseconds; `clockSkew` is at most 60 |
| Every proof rejects | `targetUri` not in normal form or carrying a query string; `method` case differs; `proofMaxAge` is 0 or above 300 |
| Some calls reject | `castArguments` differ from what the holder signed: a missing or extra member, or an integer where the holder sent a float |
| Rejects with a nonce flow | `nonce: { kind: "not_required" }` while the proof carries one, or the other way round |
| `invocationId` rejects | it must be a lowercase RFC 4122 UUID (versions 1 to 5) |
| A key is refused everywhere | it fails rule S1 key acceptance (non-canonical, small order or off the curve); check `acceptablePublicKey` |
