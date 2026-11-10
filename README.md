# @bounded-authority-protocol/verifier

[![npm](https://img.shields.io/npm/v/@bounded-authority-protocol/verifier)](https://www.npmjs.com/package/@bounded-authority-protocol/verifier)
[![CI](https://github.com/baselabs/bounded_authority_protocol_typescript/actions/workflows/ci.yml/badge.svg)](https://github.com/baselabs/bounded_authority_protocol_typescript/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

The TypeScript verifier for the **Bounded Authority Protocol** (BAP). An issuer signs a grant that
lets one key holder call named operations, within limits, for a bounded time; the holder signs a
proof for each call; a resource server checks both. This package does that check, and the related
checks for consumption chains, archives and key rotation, deterministically and without network,
clock or private-key access. It is a reimplementation of the protocol's published specifications,
held to the protocol's certified conformance corpora, and it runs with identical verdicts on
Node.js, in browsers, and on Deno, Bun and workers.

To see it work before you install anything, open the
[verifier bench](https://baselabs.github.io/bounded_authority_protocol_typescript/): it builds a
demo grant and proof in your browser, verifies them the way a resource server does, and lets you
tamper with each part to watch the check refuse it.

## Why use it

- **One call per decision input.** `checkEnvelope` verifies the grant signature, the issuer,
  audience and time window, the holder's proof signature, the method, URI, operation, request
  digest, nonce and every argument selector, and returns plain facts.
- **Fail closed, one error.** Every verification returns `{ ok: true, value }` or `{ ok: false }`.
  Unknown versions, algorithms, members, duplicate JSON keys, non-canonical encodings and
  over-limit input all reject with the same value-free result.
- **Strict cryptography.** Ed25519 follows the protocol's strict rule S1 (canonical points, no
  small-order keys or `R`, `S < L`, the cofactorless equation); ES256 requires uncompressed
  on-curve P-256 keys and low-S signatures.
- **Three wire majors and three sibling profiles in one package**, each verifying only its own
  bytes: contract-majors 1, 2 and 3, the local-loopback proof profile, role attestations and
  content assertions.

## What it is not

It verifies; it never authorizes. A successful result proves that the bytes you passed satisfy
the trusted keys, time and context you passed, nothing more. Results carry
`authorization: "not_evaluated"` or `trust: "not_evaluated"`, and there is no `allowed`,
`authorized` or decision anywhere in the API. The package holds no private keys and never signs,
reads no clock, makes no network or filesystem calls, and performs no replay reservation,
revocation check or policy decision. Choosing which keys to trust, reserving each invocation id
once, and deciding whether to execute belong to your service.

## Install

```bash
npm install @bounded-authority-protocol/verifier@2.0.0
```

The package is ESM-only. It needs Node.js 22 or later (CI runs Node 22.23.1 and 24.19.0), or a
current browser, Deno (CI: 2.5.6) or Bun (CI: 1.3.14). Its three runtime dependencies are
exactly pinned and MIT-licensed: `@noble/ed25519` 3.2.0, `@noble/curves` 2.4.0 and
`@noble/hashes` 2.4.0, used only by the portable backend (browsers, Deno, Bun, workers).

## Quickstart: issue and verify a grant

This creates two Ed25519 key pairs with `node:crypto`, builds the grant's exact signing input with
this package, signs it, and verifies it as a resource server would. In production the issuer signs
in its own key custody (KMS, HSM, or the companion [signer](#pairing-with-the-signer)); the verifier
only ever sees public keys.

Set up a new project (the package is ESM-only, so the project is `"type": "module"`):

```bash
mkdir bap-quickstart && cd bap-quickstart
npm init -y
npm pkg set type=module
npm install @bounded-authority-protocol/verifier@2.0.0
```

Save the code below as `quickstart.ts` in that directory and run `node quickstart.ts`. Running a `.ts`
file directly needs Node.js 22.18 or later, which strips the types (checked as written on 22.23.1 and
24.19.0); on an older Node 22, or another runtime, run `npx tsx quickstart.ts`. It prints nothing
when every assertion holds.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import {
  assembleCompact,
  grantSigningInput,
  jwkFromPublicKey,
  thumbprint,
  verifyGrant,
} from "@bounded-authority-protocol/verifier";

// A raw Ed25519 public key is 32 bytes.
const rawPublicKey = (key: KeyObject): Uint8Array =>
  Buffer.from(key.export({ format: "jwk" }).x!, "base64url");

const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");

// 1. The issuer builds the grant's signing input, signs it, and assembles the compact JWS.
const input = grantSigningInput({
  keyId: "issuer-2026-10",
  issuer: "https://issuer.example",
  grantId: "grant-0001",
  audiences: ["https://api.example"],
  issuedAt: 1_760_000_000,
  notBefore: 1_760_000_000,
  expiresAt: 1_760_003_600,
  // The grant is bound to the holder's key by its RFC 7638 thumbprint.
  holderThumbprint: thumbprint(jwkFromPublicKey(rawPublicKey(holder.publicKey))),
  operations: [{ name: "documents.read", selectors: ["all"] }],
});
assert.ok(input.ok);
const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
const grant = assembleCompact(input.value, sign(null, message, issuer.privateKey));
assert.ok(grant.ok);

// 2. The resource server verifies it against the issuer key it trusts and its own context.
const result = verifyGrant(
  grant.value,
  { keyId: "issuer-2026-10", publicKey: rawPublicKey(issuer.publicKey) },
  {
    issuer: "https://issuer.example",
    audience: "https://api.example",
    evaluationTime: 1_760_000_100, // you supply the time: the package reads no clock
    clockSkew: 60,
  },
);
assert.ok(result.ok);
assert.equal(result.value.grantId, "grant-0001");
assert.equal(result.value.authorization, "not_evaluated");

// The same grant two hours later: expired, so the closed rejection.
const late = verifyGrant(
  grant.value,
  { keyId: "issuer-2026-10", publicKey: rawPublicKey(issuer.publicKey) },
  { issuer: "https://issuer.example", audience: "https://api.example", evaluationTime: 1_760_007_200, clockSkew: 60 },
);
assert.deepEqual(late, { ok: false });
```

A real request also carries the holder's proof; [Verify requests](docs/guides/verify-requests.md)
walks through the full issuer, holder and resource flow with `checkEnvelope`.

## Documentation

| Guide | What it covers |
|---|---|
| [Verify requests](docs/guides/verify-requests.md) | Grants, holder proofs, `checkEnvelope`, selectors, nonces, picking the issuer key |
| [Protect an HTTP endpoint](docs/guides/http-server.md) | A Node.js server recipe: middleware that verifies the envelope and reserves each invocation once |
| [Deno, Bun and browsers](docs/guides/runtimes.md) | One module that runs on every runtime, and how to bundle it for a page |
| [Contract-majors 2 and 3](docs/guides/contract-majors.md) | `lte`/`gte` range selectors (v2) and the ES256 suite with low-S signatures (v3) |
| [Rotate keys](docs/guides/rotate-keys.md) | Key enrollment checks, several trusted issuer keys, authenticated key transitions |
| [Consumption chains and archives](docs/guides/chains-and-archives.md) | Consumption rows, boundary anchors, anchored exports |
| [Role attestations](docs/guides/role-attestations.md) | `bap-role-attestation/1`: binding a key to the issuer or holder role |
| [Content assertions](docs/guides/content-assertions.md) | `bap-content-assertion/1`: signed digests of exact content, with successor checks |
| [Handle errors](docs/guides/handle-errors.md) | The closed result, the functions that throw, and finding why an input rejects |
| [Test your integration](docs/guides/test-your-integration.md) | Building real fixtures and negative cases without mocks |
| [Upgrading from 1.x](docs/guides/upgrading.md) | What 2.0.0 changes, who is affected, and the steps |
| [API reference](docs/reference.md) | Every export: parameters, return shape, errors, examples |

## Strict Ed25519 (rule S1)

Every Ed25519 verification in the package goes through one gate, then the backend's cofactorless
equation. A signature is accepted only if the key `A` and the signature point `R` are canonical
encodings (RFC 8032 section 5.1.3), neither is one of the eight small-order encodings, and
`S < L`. A key that is non-canonical, of small order, or off the curve is refused wherever it
enters (trusted issuer and archive keys, proof-header JWKs, producers, thumbprints) with the
closed error. Three helpers are exported for hosts:

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { acceptablePublicKey, torsionFree, verifyStrict } from "@bounded-authority-protocol/verifier";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKey32 = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
const message = new TextEncoder().encode("hello");
const signature64 = sign(null, message, privateKey);

assert.equal(verifyStrict(message, signature64, publicKey32), true); // boolean; never throws
assert.equal(acceptablePublicKey(publicKey32), true); // canonical, not small order, on the curve
assert.equal(torsionFree(publicKey32), true); // acceptable, and [L]A = O

// The all-zero encoding is one of the eight small-order points: refused everywhere.
assert.equal(acceptablePublicKey(new Uint8Array(32)), false);
```

"Never throws" holds for any input, including an exotic one whose typed-array getters throw (a
`Proxy` around a `Uint8Array`, an object made from `Uint8Array.prototype`).

Verification itself has no subgroup check. A host MUST call `torsionFree` at key enrollment, at
trust install, and before any deny-list or revocation comparison, so that one secret has one key
encoding. It runs one scalar multiplication in BigInt arithmetic (under a millisecond on a current
laptop), so it belongs at those points and never on the per-request path.

The ES256 counterpart is `es256VerifyStrict(message, signature64, publicKey65)`: synchronous and
total (it never throws), it returns `true` only for an uncompressed, on-curve P-256 key, a raw
`r || s` signature with `0 < r < n` and `0 < s <= (n - 1) / 2` (low-S), and a valid ECDSA P-256 /
SHA-256 signature over the message. It applies the `REQ3-SIGNING-*` rules of the v3 profile to raw
bytes.

Compact assembly and anchored-export encoding are producer surfaces —
they frame a signature and verify none — so each refuses, with the closed error, a signature no
conforming signer emits and emits every accepted signature's bytes unchanged (erratum 3): an
Ed25519 signature whose `S` is at least the group order or whose `R` is non-canonical or of small
order, and an ES256 `r || s` outside `0 < r < n`, `0 < s <= (n - 1) / 2` — including the high-S
twin of a valid signature, which verifies under raw ECDSA. A signer normalizes to low-S itself
before assembly; the package never rewrites a signature.

## Browsers, Deno, Bun and workers

The package is ESM-only, has no side effects on import (`"sideEffects": false`), and uses no Node
API outside one module. Its cryptography sits behind an internal backend that the package's
`"imports"` conditions select, so the API stays synchronous everywhere and no WebCrypto is used:

| Runtime | Condition that matches | Backend (`BACKEND_ID`) |
|---|---|---|
| Node.js (default) | `node` | `"node"`: `node:crypto` |
| Node.js with `--conditions=bap-portable` | `bap-portable` | `"portable"`: `@noble` |
| Deno | `deno` | `"portable"` |
| Bun | `bun` | `"portable"` |
| Cloudflare Workers and other builds with the `workerd` or `worker` condition | `workerd`, `worker` | `"portable"` |
| Browsers and bundlers targeting them | `default` | `"portable"` |

The conditions are matched in the order `bap-portable`, `deno`, `bun`, `workerd`, `worker`, `node`,
so a build that sets any of the first five gets the portable backend even when it also sets `node`.
A build that sets `node` and none of them gets the node backend. Common cases:

- webpack's Electron targets (`electron-main`, `electron-preload`, `electron-renderer`), which add
  the `node` condition;
- esbuild with `--platform=node` (with a `workerd` or `worker` condition added, the portable backend);
- Rollup with `@rollup/plugin-node-resolve` and `exportConditions: ["node"]`;
- Vite SSR builds, which resolve the `node` condition.

To force the portable backend in any of these, add the `bap-portable` condition. `BACKEND_ID` names
the implementation, not the platform library under it: `"node"` means `node:crypto` of the running
runtime, whether that is linked against OpenSSL (Node.js) or BoringSSL (Electron), and it cannot
tell the two apart. Verdicts do not depend on it, because every protocol gate runs before the
backend. The packed manifest carries none of this repository's development conditions, so no
consumer build can resolve a source file the package does not ship.

```ts
import assert from "node:assert/strict";
import { BACKEND_ID } from "@bounded-authority-protocol/verifier";

// Which implementation this build resolved. Verdicts are the same in both.
assert.ok(BACKEND_ID === "node" || BACKEND_ID === "portable");
```

Both backends sit behind the same profile gates (rule S1 for Ed25519; the point, range and low-S
checks for ES256), the portable Ed25519 check is an explicit cofactorless one
(`encode([S]B - [k]A) == R`, never a cofactored verify), and the portable P-256 verify leaves the
low-S rule to the profile gate. Every certified corpus produces byte-identical verdict digests on
Node 22 and 24 with either backend, on Deno and Bun, and in Chromium, checked case by case against
the Node verdicts. CI, and the release workflow before it stages a publish, runs the same
browser lane in Chromium, Firefox and WebKit on Linux.

**In-page verification is display-only, never a trust decision.** A result computed in a web page
is for showing to a person. It must not authorize anything, feed a trust decision, or be sent
anywhere as evidence of authority: the page's own scripts, browser extensions and injected code
share its origin and can change both the inputs and the answer. The trusted decision stays with
the host runtime that holds the trusted keys. As on Node, trusted keys, time and expected context
are explicit inputs; a page must never take them from the artifact it is inspecting.

The package works under a strict Content Security Policy (`default-src 'none'; script-src 'self';
connect-src 'self'`, no `'unsafe-eval'`): it uses no `eval`, no `Function` constructor and no
dynamic `import()`, and the browser lanes run under exactly that policy. Linux WebKit in CI is
evidence for this pure-JavaScript verifier only, not for Safari.

Bundle size (esbuild, minified, browser target, tree-shaken from the package entry, measured for
0.7.0): every export 263 KB (70 KB gzip); `{ v3 }` 121 KB (36 KB gzip); `{ checkEnvelope }` (v1)
52 KB (19 KB gzip). CI fails a change that grows any of these more than 10% past that measurement
(`tools/bundle-size-budget.json`).

## Wire contract-majors

The protocol versions its wire formats as complete, parallel **contract-majors**. All three live
in this package; each verifies only its own bytes, with no fallback or downgrade in any direction.

| Major | Import | Selector kinds | Suite | Keys and signatures |
|---|---|---|---|---|
| 1 | `import { verifyGrant, ... }` (package root) | `all`, `equals`, `one_of` | `BAP1-Ed25519-SHA256` | Ed25519: 32-byte keys, 64-byte signatures |
| 2 | `import { v2 } from "@bounded-authority-protocol/verifier"` | adds `lte`, `gte` | `BAP2-Ed25519-SHA256` | Ed25519, as major 1 |
| 3 | `import { v3 } from "@bounded-authority-protocol/verifier"` | the same five as major 2 | `BAP3-ES256-SHA256` | ECDSA P-256: 65-byte uncompressed SEC1 keys, raw low-S `r \|\| s` signatures |

The `v2` and `v3` namespaces mirror the root's grant, proof, chain, anchor, transition and export
functions under their own payload `v`, domain separators and suite. Two differences: neither has
the local-loopback functions (that profile is bound to major 1), and both split the export
context into `ExpectedExport` (encode) and `ExpectedAnchoredExport` (verify). Every v1 and v2
artifact rejects under `v3` with the closed error, and the same holds in every other direction.
[Contract-majors 2 and 3](docs/guides/contract-majors.md) has runnable examples of both.

## Sibling profiles

Three profiles share major 1's primitives but are byte-distinct: no contract-major parses them,
and they parse no major's bytes.

- **Local-loopback proofs** (`bap-application-proof/local-loopback-http/1`): a proof profile for
  local development servers, with literal `127.0.0.1` or `[::1]` HTTP targets and a mandatory
  nonce. Its functions sit at the root: `localLoopbackHttpProofSigningInput`,
  `assembleLocalLoopbackHttpCompact`, `decodeLocalLoopbackHttpProof`,
  `checkLocalLoopbackHttpEnvelope` and `localLoopbackHttpUriNormalize`. A standard `dpop+jwt`
  verifier rejects these proofs.
- **Role attestations** (`bap-role-attestation/1`, the `roleAttestation` namespace): an attestor
  key binds a subject key to the `issuer` or `holder` role for a window inside the attestor key's
  validity. See [Role attestations](docs/guides/role-attestations.md).
- **Content assertions** (`bap-content-assertion/1`, the `contentAssertion` namespace): an
  attestor binds the digest of exact content bytes to an issuer, one audience, a subject lineage,
  a pinned semantic profile, a generation and predecessor, and a validity window. See
  [Content assertions](docs/guides/content-assertions.md).

## Pairing with the signer

This package verifies; it never signs and never holds a private key. Its sibling
[`@bounded-authority-protocol/signer`](https://www.npmjs.com/package/@bounded-authority-protocol/signer)
produces the signed bytes by calling this package's producer functions and delegating each
signature to a key handle you own. The dependency is one-way: the signer depends on the verifier
through a caret range on one verifier package major (signer 1.0.0 takes `^1.0.0`), never the
reverse. What the two must agree on is the wire contract-major (signer 1.0.0 signs majors 1, 2
and 3), not a package version number; the signer's own changelog names the verifier range each
of its releases takes.
The [envelope playground](https://baselabs.github.io/bounded_authority_signer_typescript/) runs
the whole flow in a browser.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { signGrant, signReport, type KeyHandle } from "@bounded-authority-protocol/signer";
import { checkEnvelope, jwkFromPublicKey, thumbprint, type Tagged } from "@bounded-authority-protocol/verifier";

const rawPublicKey = (key: KeyObject): Uint8Array =>
  Buffer.from(key.export({ format: "jwk" }).x!, "base64url");

// A KeyHandle routes sign() to your own custody. These in-process keys stand in for a KMS or HSM.
function handleFor(pair: { publicKey: KeyObject; privateKey: KeyObject }, role?: "issuer"): KeyHandle {
  const publicKey = rawPublicKey(pair.publicKey);
  return {
    sign: (message) => sign(null, message, pair.privateKey),
    publicKey: () => publicKey,
    thumbprint: () => thumbprint(jwkFromPublicKey(publicKey)),
    // Grants need an atomic issuer-role identity; a holder handle cannot sign one.
    ...(role === "issuer" ? { signingIdentity: () => ({ role, keyId: "issuer-key", publicKey }) } : {}),
  };
}
const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const holderHandle = handleFor(holder);

// Issuer: mint a grant for the holder's key.
const grant = await signGrant(
  {
    issuer: "https://issuer.example",
    grantId: "grant-0002",
    audiences: ["https://calendar.example"],
    issuedAt: 1_760_000_000,
    notBefore: 1_760_000_000,
    expiresAt: 1_760_086_400,
    holderThumbprint: await holderHandle.thumbprint(),
    operations: [{ name: "events.create", selectors: [{ kind: "equals", path: ["calendar"], value: { t: "string", v: new TextEncoder().encode("team") } }] }],
  },
  handleFor(issuer, "issuer"),
);
if (!grant.ok) throw new Error(`signing failed: ${grant.error}`);

// Holder: bind one invocation of that grant with a proof.
const invocationId = randomUUID(); // a lowercase RFC 4122 UUID, as the wire requires
const castArguments: Tagged = {
  t: "object",
  v: new Map<string, Tagged>([["calendar", { t: "string", v: new TextEncoder().encode("team") }]]),
};
const envelope = await signReport(
  { grantCompact: grant.value.grant, operation: "events.create", method: "POST",
    targetUri: "https://calendar.example/events", invocationId, castArguments },
  holderHandle,
  { issuedAt: 1_760_000_030 },
);
if (!envelope.ok) throw new Error(`signing failed: ${envelope.error}`);

// Resource: this package, and nothing else. Facts, never a decision.
const result = checkEnvelope(envelope.value.grant, envelope.value.proof, {
  trustedIssuer: { keyId: "issuer-key", publicKey: rawPublicKey(issuer.publicKey) },
  issuer: "https://issuer.example",
  audience: "https://calendar.example",
  method: "POST",
  targetUri: "https://calendar.example/events",
  invocationId,
  operation: "events.create",
  castArguments,
  evaluationTime: 1_760_000_060,
  clockSkew: 60,
  proofMaxAge: 300,
  nonce: { kind: "not_required" },
});
assert.ok(result.ok);
assert.equal(result.value.operation, "events.create");
```

The signer verifies every signature against the resolved public key before assembly, so a handle
fault or a wrong-key rotation race fails as `signing_failed` instead of producing bytes this
package rejects. Its full key-handle contract is in the
[signer's README](https://github.com/baselabs/bounded_authority_signer_typescript#readme).

## Certified, not self-tested

Every release of this package is verified against the protocol's published, certified conformance
corpora, recomputing every verdict from scratch with each corpus `index.json` SHA-256 asserted at
load, so a drifted snapshot fails loudly:

| Corpus | Cases |
|---|---|
| Contract-major 1 | 283 |
| Contract-major 2 | 268 |
| Contract-major 3 | 292 |
| Local-loopback proof profile | 44 |
| Role-attestation profile | 40 |
| Content-assertion profile | 131 assertion, 9 digest, 14 successor |
| Strict Ed25519 (rule S1, additive to the corpora above) | 2410 |
| Producer canonicality (erratum 3, additive: assembly and export encoding refuse a non-canonical signature) | 75 |
| Selector float-zero (erratum 6, new in 2.0.0, additive: decode rejects a float-tagged zero in `equals`/`one_of`; the grant producer refuses float-tagged integral selector values) | 161 |

Permissiveness bugs (a parser accepting what the spec forbids) are invisible to corpus agreement
by construction, so the suite also carries a mutation gate that proves each closure can fail:
remove a check mechanically and its test turns red.

Linux CI runs strict typecheck, build, lint (including a purity rule, no I/O, clock or randomness
in `src/`, and the browser-safety rules: no Node module or global, no dynamic code), a browser
typecheck, a scan of the browser bundle for unresolved globals, a bundle-size budget, a license
check, the unit tests (which also typecheck and run every code sample in this README and in
`docs/`), the mutation gate, and every corpus above against the vendored snapshots, on Node 22.23.1
and Node 24.19.0 with the node and the portable backend; the same corpora on Deno and Bun; the
browser lane in Playwright Chromium, Firefox and WebKit under a strict CSP; a consumer typecheck of
the packed tarball; and `npm audit signatures`.

Releases from 0.2.1 on are published only from this repository's release workflow, through npm
trusted publishing (GitHub Actions OIDC, no long-lived tokens) with npm provenance on every
artifact.

## Versioning

Package versions follow SemVer. **Package majors are not contract-majors.** Wire contract-majors
are a separate axis: wire artifacts self-declare their major (payload `v`, the `BAP<n>-…` suite
name, major-bound domain separators), a new contract-major lands additively as a minor release
(this package carries majors 1, 2 and 3 side by side), and the package number never encodes one.

**2.0.0 is the selector float-zero soundness repair**, the protocol's erratum 6, and
nothing else: the exports, the types and every other verdict are 1.0.0's. It is a major because
1.0.0 promised a major for any verdict change, and erratum 6 changes verdicts: some grants that
1.0.0 decodes and verifies are rejected, and some selector values its grant producer accepts are
refused (see [Verify requests](docs/guides/verify-requests.md#arguments-and-selectors)). A minor
would have changed every `^1.0.0` install without notice. No wire contract-major changes.
[Upgrading from 1.x](docs/guides/upgrading.md) says who is affected and what to do.

From 2.x on, the package follows one rule for verdicts:

- **A soundness repair is a minor release.** A soundness repair is a correction made under the
  protocol's [governance](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/governance.md#soundness-repairs):
  it only turns an accept into a reject, only for inputs no conforming producer emits, changes no
  verdict of any certified corpus, and arrives with its own additive certified corpus. A caret
  range such as `^2.0.0` carries it, as it carries every other minor and patch.
- **Any other verdict change, and any removal or breaking change of the public API, is a major.**
- **Earlier releases stay installable** and return the pre-repair verdict, which the protocol's
  [errata registry](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md)
  records, unless the repair needs a security advisory because a party without the signing key
  could exploit the old verdict; those releases are deprecated on npm with a pointer to the
  advisory. Erratum 6 is signer-bound (every affected value sits inside issuer-signed bytes), so
  it has no advisory and 1.x stays installable.

Deep imports, any path under `dist/`, are closed: the exports map exposes the package root and
`./package.json` only, so import from the root. Before 1.0 the minor position was the breaking
boundary; the [changelog](CHANGELOG.md) lists each release's verdict and API changes.

## Protocol documentation

- [BAP v1 specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md) ·
  [v2](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v2.md) ·
  [v3](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md) ·
  [local-loopback proof profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-local-loopback-http-v1.md) ·
  [role-attestation profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md) ·
  [content-assertion profile](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md)
- [Certified conformance corpora](https://github.com/baselabs/bounded_authority_protocol/tree/main/priv/conformance/)
- [Governance](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/governance.md)
  (how profiles evolve, soundness repairs, deprecation) and the
  [errata registry](https://github.com/baselabs/bounded_authority_protocol/blob/main/docs/errata.md)
  (every correction to a published specification, with its corpus impact)
- This package is an independent reimplementation of those specifications, held to the same
  certified corpora as the protocol's reference implementation. It publishes from its own
  repository, so its releases, provenance and issue tracker are separate from the protocol's.
  Strict Ed25519 (rule S1) is specified in the
  [v1 specification](https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519)
  and recorded as erratum 2.

## Related packages

- [bounded_authority_protocol](https://github.com/baselabs/bounded_authority_protocol): the
  protocol source, with the specifications, ADRs, the certified conformance corpora this package
  vendors, and the reference Elixir implementation.
- [@bounded-authority-protocol/signer](https://www.npmjs.com/package/@bounded-authority-protocol/signer):
  the issuer and holder companion that signs grants, proofs, boundary anchors and key transitions
  through a caller-owned key handle (see [Pairing with the signer](#pairing-with-the-signer)).

## Development

```bash
pnpm install
pnpm typecheck && pnpm build && pnpm lint && pnpm license-check
pnpm test                    # builds, then unit, struct and facade tests and every docs sample
pnpm test:permissiveness     # the mutation gate
pnpm conformance             # 283/283 and the key census (vendored v1 snapshot)
pnpm conformance:v2          # 268/268 and the key census (vendored v2 snapshot)
pnpm conformance:v3          # 292/292 and the key census (vendored v3 snapshot)
pnpm conformance:role-attestation    # 40/40 and the cross-profile legs
pnpm conformance:content-assertion   # 131 + 9 + 14 and producer/assembly byte agreement
pnpm conformance:strict-ed25519      # 2410/2410 strict-Ed25519 verdicts
pnpm conformance:local-loopback-http # 44/44 local-loopback proof verdicts
pnpm conformance:producer-canonicality # 75/75 producer-surface canonicality verdicts
pnpm conformance:selector-float-zero  # 161/161 selector float-zero verdicts (decode, producer, envelope)
pnpm test:portable           # unit tests and the mutation gate under --conditions=bap-portable
pnpm conformance:portable    # every corpus under the portable backend (same verdict digests)
pnpm typecheck:browser       # src/ under DOM + ES2022, no ambient types
pnpm guard:browser           # browser bundle: portable backend only, no unresolved globals or eval
pnpm size                    # browser bundle-size budget
pnpm pack:release            # the release tarball, packed from a staging copy (build first)
pnpm test:tarball            # packed tarball: consumer typecheck and Node/Deno/Bun runs
pnpm test:runtimes           # Deno and Bun conformance lanes (BAP_RUNTIMES=deno,bun)
pnpm test:browser            # Playwright lanes (BAP_BROWSERS=chromium,firefox,webkit)
pnpm check:currency          # dependency-currency gate (latest-first)
pnpm test:readback           # the post-publish read-back, held to the published 1.0.0
pnpm readback <version> --sha256 <hex>  # read back a release: registry, bytes, provenance, signatures, fresh consumers
```

## Security

Report a vulnerability privately through this repository's Security tab ("Report a vulnerability");
see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
