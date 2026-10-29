# Contract-majors 2 and 3

The protocol versions its wire format as parallel contract-majors. Each major is complete on its
own: it has its own payload `v`, its own domain separators (`BAP<n>-REQUEST\0`, `BAP<n>-CHAIN\0`,
`BAP<n>-ARCHIVE\0EXPORT\0`) and its own suite name, and it rejects every other major's bytes with
the closed error. There is no negotiation and no fallback: you pick the major in code by the
namespace you call.

| | Major 1 (root) | Major 2 (`v2`) | Major 3 (`v3`) |
|---|---|---|---|
| Payload `v` | `1` | `2` | `3` |
| Suite | `BAP1-Ed25519-SHA256` | `BAP2-Ed25519-SHA256` | `BAP3-ES256-SHA256` |
| Header `alg` | `EdDSA` | `EdDSA` | `ES256` |
| Raw public key | 32 bytes (Ed25519) | 32 bytes (Ed25519) | 65 bytes, `0x04 \|\| x \|\| y` (P-256) |
| Proof JWK | `{crv: "Ed25519", kty: "OKP", x}` | same as 1 | `{crv: "P-256", kty: "EC", x, y}` |
| Signature | 64 bytes, rule S1 | 64 bytes, rule S1 | 64 bytes, raw `r \|\| s`, low-S |
| Selector kinds | `all`, `equals`, `one_of` | adds `lte`, `gte` | as major 2 |
| Local-loopback proofs | yes | no | no |
| Export context | one `ExpectedExport` | `ExpectedExport` + `ExpectedAnchoredExport` | as major 2 |

Function names and argument shapes are otherwise the same in all three, so moving between majors
is a change of namespace and key type. Every sample here runs as written on Node.js.

## Major 2: range selectors

`lte` and `gte` compare the argument at `path` with a numeric bound, inclusively. The bound and the
argument must carry the same numeric tag: an integer argument never satisfies a float bound and
the reverse, and a non-numeric argument never matches. Several selectors on one operation must all
match, so a `gte` and an `lte` on the same path form a closed interval.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import {
  jsonDecode, jwkFromPublicKey, strUtf8, thumbprint, v2, verifyGrant, type SigningInput,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const message = (i: SigningInput): Uint8Array => Buffer.concat([i.protectedSegment, Buffer.from("."), i.payloadSegment]);
const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");

// The holder may set a thermostat between 16 and 24 degrees, inclusive.
const grantInput = v2.grantSigningInput({
  keyId: "facilities-1",
  issuer: "https://facilities.example",
  grantId: "grant-hvac-12",
  audiences: ["https://building.example"],
  issuedAt: 1_000,
  notBefore: 1_000,
  expiresAt: 90_000,
  holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
  operations: [{
    name: "thermostat.set",
    selectors: [
      { kind: "gte", path: ["celsius"], value: { t: "int", v: 16 } },
      { kind: "lte", path: ["celsius"], value: { t: "int", v: 24 } },
    ],
  }],
});
assert.ok(grantInput.ok);
const grant = v2.assembleCompact(grantInput.value, sign(null, message(grantInput.value), issuer.privateKey));
assert.ok(grant.ok);
const grantCompact = grant.value;

function attempt(argumentsJson: string): boolean {
  const castArguments = jsonDecode(strUtf8(argumentsJson));
  const invocationId = randomUUID();
  const proofInput = v2.proofSigningInput({
    holderPublicKey: raw(holder.publicKey), proofId: `proof-${invocationId}`, method: "POST",
    targetUri: "https://building.example/zones/4/thermostat", issuedAt: 1_100, invocationId,
    operation: "thermostat.set", grantCompact, castArguments,
  });
  assert.ok(proofInput.ok);
  const proof = v2.assembleCompact(proofInput.value, sign(null, message(proofInput.value), holder.privateKey));
  assert.ok(proof.ok);
  return v2.checkEnvelope(grantCompact, proof.value, {
    trustedIssuer: { keyId: "facilities-1", publicKey: raw(issuer.publicKey) },
    issuer: "https://facilities.example", audience: "https://building.example", method: "POST",
    targetUri: "https://building.example/zones/4/thermostat", invocationId, operation: "thermostat.set",
    castArguments, evaluationTime: 1_120, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" },
  }).ok;
}

assert.equal(attempt('{"celsius":24}'), true); // the bound itself is inside
assert.equal(attempt('{"celsius":16}'), true);
assert.equal(attempt('{"celsius":25}'), false);
assert.equal(attempt('{"celsius":20.5}'), false); // a float never satisfies an integer bound
assert.equal(attempt('{"fahrenheit":70}'), false); // a missing path never matches

// Major 1 refuses the major-2 grant outright: its payload carries v: 2.
assert.deepEqual(
  verifyGrant(grantCompact, { keyId: "facilities-1", publicKey: raw(issuer.publicKey) },
    { issuer: "https://facilities.example", audience: "https://building.example", evaluationTime: 1_120, clockSkew: 60 }),
  { ok: false },
);
```

`v2.parseSelector` and `v2.selectorMatches` expose the major-2 selector algebra directly, and
`v2.requestDigest` uses the `BAP2-REQUEST\0` separator, so a major-1 request digest never equals a
major-2 one for the same input.

## Major 3: ES256

Major 3 replaces Ed25519 with ECDSA over NIST P-256 and SHA-256 (`BAP3-ES256-SHA256`):

- **Raw public keys are 65 bytes**, the uncompressed SEC1 point `0x04 || x || y`. Compressed and
  hybrid points are invalid. Each coordinate must be less than the field prime and the point must
  be on the curve; the package checks this in pure arithmetic before any backend call.
- **The proof JWK is exactly `{crv: "P-256", kty: "EC", x, y}`**, each coordinate the unpadded
  base64url of 32 bytes. The holder thumbprint is the RFC 7638 thumbprint over those four members:
  `v3.thumbprint({ crv: "P-256", kty: "EC", x, y })`.
- **Signatures are the raw 64-byte `r || s` form** (RFC 7518 section 3.4), never DER, with
  `0 < r < n` and `0 < s <= (n - 1) / 2`. The last rule is **low-S**: for every valid `(r, s)`,
  `(r, n - s)` also verifies, so the profile accepts only the low half. Most ECDSA libraries,
  including `node:crypto` and WebCrypto, return either half, so **the signer must normalize**
  (`s = n - s` when `s` is high) before the signature is assembled. This package's producers do
  not normalize; a high-S signature assembles but never verifies. The
  [signer package](https://www.npmjs.com/package/@bounded-authority-protocol/signer) (0.5.0)
  normalizes in its v3 signing functions and then checks the result with `es256VerifyStrict`.

The sample uses `v3.jwkFromPublicKey`, new in 0.8.0 (unreleased); with 0.7.0 spell the JWK object
`{ crv: "P-256", kty: "EC", x, y }` from the key's coordinates.

```ts since=0.8.0
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, verify, type KeyObject } from "node:crypto";
import { es256VerifyStrict, jsonDecode, strUtf8, v3, type SigningInput } from "@bounded-authority-protocol/verifier";

// The P-256 group order n.
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const toHex32 = (v: bigint): string => v.toString(16).padStart(64, "0");

// Sign with node:crypto in the raw r || s form, then normalize to low-S.
function es256Sign(message: Uint8Array, privateKey: KeyObject): Uint8Array {
  const signature = sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" });
  const s = BigInt(`0x${signature.subarray(32).toString("hex")}`);
  if (s > (N - 1n) / 2n) signature.set(Buffer.from(toHex32(N - s), "hex"), 32);
  return signature;
}
// The 65-byte uncompressed SEC1 point and the EC JWK of a P-256 public key.
function p256Public(key: KeyObject): { raw: Uint8Array; jwk: v3.EcPublic } {
  const { x, y } = key.export({ format: "jwk" });
  const raw = Buffer.concat([Buffer.from([0x04]), Buffer.from(x!, "base64url"), Buffer.from(y!, "base64url")]);
  return { raw, jwk: v3.jwkFromPublicKey(raw) }; // refuses a point that is not an acceptable P-256 key
}
const message = (i: SigningInput): Uint8Array => Buffer.concat([i.protectedSegment, Buffer.from("."), i.payloadSegment]);

const issuer = generateKeyPairSync("ec", { namedCurve: "P-256" });
const holder = generateKeyPairSync("ec", { namedCurve: "P-256" });
const issuerKey = p256Public(issuer.publicKey);
const holderKey = p256Public(holder.publicKey);

// A robot arm may move at up to 250 mm/s.
const grantInput = v3.grantSigningInput({
  keyId: "fleet-p256",
  issuer: "https://fleet.example",
  grantId: "grant-arm-3",
  audiences: ["https://cell-7.example"],
  issuedAt: 1_000,
  notBefore: 1_000,
  expiresAt: 5_000,
  holderThumbprint: v3.thumbprint(holderKey.jwk),
  operations: [{ name: "arm.move", selectors: [{ kind: "lte", path: ["speed_mm_s"], value: { t: "int", v: 250 } }] }],
});
assert.ok(grantInput.ok);
const grantSignature = es256Sign(message(grantInput.value), issuer.privateKey);
assert.equal(es256VerifyStrict(message(grantInput.value), grantSignature, issuerKey.raw), true);
const grant = v3.assembleCompact(grantInput.value, grantSignature);
assert.ok(grant.ok);

const castArguments = jsonDecode(strUtf8('{"speed_mm_s":200,"target":"bin-3"}'));
const invocationId = randomUUID();
const proofInput = v3.proofSigningInput({
  holderPublicKey: holderKey.raw, proofId: "proof-arm-1", method: "POST",
  targetUri: "https://cell-7.example/arm/move", issuedAt: 1_100, invocationId,
  operation: "arm.move", grantCompact: grant.value, castArguments,
});
assert.ok(proofInput.ok);
const proof = v3.assembleCompact(proofInput.value, es256Sign(message(proofInput.value), holder.privateKey));
assert.ok(proof.ok);

const expected = {
  trustedIssuer: { keyId: "fleet-p256", publicKey: issuerKey.raw },
  issuer: "https://fleet.example", audience: "https://cell-7.example", method: "POST",
  targetUri: "https://cell-7.example/arm/move", invocationId, operation: "arm.move", castArguments,
  evaluationTime: 1_150, clockSkew: 60, proofMaxAge: 300, nonce: { kind: "not_required" as const },
};
const result = v3.checkEnvelope(grant.value, proof.value, expected);
assert.ok(result.ok);
assert.equal(result.value.version, 3);

// The high-S twin of the grant signature: node:crypto accepts it, the v3 profile does not.
const s = BigInt(`0x${Buffer.from(grantSignature.subarray(32)).toString("hex")}`);
const highS = Buffer.concat([grantSignature.subarray(0, 32), Buffer.from(toHex32(N - s), "hex")]);
assert.equal(verify("sha256", message(grantInput.value), { key: issuer.publicKey, dsaEncoding: "ieee-p1363" }, highS), true);
assert.equal(es256VerifyStrict(message(grantInput.value), highS, issuerKey.raw), false);
// Compact assembly is a producer surface: it refuses the twin with the closed error rather
// than framing a signature no conforming signer emits (new in 0.8.0).
const twin = v3.assembleCompact(grantInput.value, highS);
assert.deepEqual(twin, { ok: false });
```

New in 0.8.0 (unreleased), the v3 namespace has the P-256 forms of the key helpers, with the same names and shapes as the
root's Ed25519 ones for majors 1 and 2: `v3.jwkFromPublicKey(raw65)` returns the `v3.EcPublic` JWK
object, `v3.thumbprint`, `v3.thumbprintRaw` and `v3.thumbprintPreimage` take that object,
`v3.publicKeyThumbprintRaw(raw65)` gives the raw fingerprint anchors and transitions carry,
`v3.jwkEncodePublic(raw65)` returns the canonical JWK JSON bytes and `v3.jwkDecodePublic(bytes)` the
65-byte key. Each refuses a point that is not an acceptable P-256 key.

## Choosing a major

All three majors are current and verify side by side; a deployment can accept more than one by
routing each credential to the namespace its issuer is enrolled under. Ed25519 (majors 1 and 2)
gives deterministic signatures; major 2 adds the range selectors; major 3 fits key custody that
signs with P-256 but not Ed25519.
Never try one major and then another on the same bytes: the namespace is part of the trust
decision, and each major already rejects the others' artifacts.
