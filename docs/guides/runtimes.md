# Deno, Bun and browsers

The package runs unchanged on Node.js, Deno, Bun, in browsers and in workers, with the same
synchronous API and the same verdicts. Each runtime picks the right cryptography backend through
the package's `"imports"` conditions, so there is nothing to configure; the README's
[backend table](../../README.md#browsers-deno-bun-and-workers) lists which runtime gets which.

The module below runs as written on all of them. It plays the issuer with WebCrypto Ed25519 keys
(Node.js, Deno, Bun and current browsers all provide them), then verifies the grant with this
package and prints one line. It uses no Node.js API, so the same file also goes into a browser
bundle. The repository's test suite runs it on Node.js, on Deno and Bun against the packed
tarball, and as a bundle in Chromium, Firefox and WebKit.

Save it as `verify-anywhere.ts`:

```ts
import { BACKEND_ID, assembleCompact, grantSigningInput, jwkFromPublicKey, thumbprint, verifyGrant } from "@bounded-authority-protocol/verifier";

function check(condition: boolean, what: string): asserts condition {
  if (!condition) throw new Error(`check failed: ${what}`);
}

// The issuer's side, for this demonstration only: Ed25519 keys from WebCrypto. A real issuer signs
// in its own key custody, and the verifier only ever sees public keys.
async function ed25519Pair(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  check("privateKey" in pair, "an Ed25519 key pair");
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}
const issuer = await ed25519Pair();
const holder = await ed25519Pair();

const input = grantSigningInput({
  keyId: "issuer-1", issuer: "https://issuer.example", grantId: "grant-gallery", audiences: ["https://photos.example"],
  issuedAt: 1_760_000_000, notBefore: 1_760_000_000, expiresAt: 1_760_003_600,
  holderThumbprint: thumbprint(jwkFromPublicKey(holder.publicKey)),
  operations: [{ name: "albums.read", selectors: ["all"] }],
});
check(input.ok, "the grant's signing input");
// The bytes to sign are exactly ASCII(protectedSegment "." payloadSegment).
const message = new Uint8Array([...input.value.protectedSegment, 0x2e, ...input.value.payloadSegment]);
const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", issuer.privateKey, message));
const grant = assembleCompact(input.value, signature);
check(grant.ok, "the compact grant");

// The verifier's side: the same call and the same verdict on every runtime.
const result = verifyGrant(grant.value, { keyId: "issuer-1", publicKey: issuer.publicKey },
  { issuer: "https://issuer.example", audience: "https://photos.example", evaluationTime: 1_760_000_100, clockSkew: 60 });
check(result.ok && result.value.grantId === "grant-gallery", "the grant verifies");
console.log(`verified ${result.value.grantId} with the ${BACKEND_ID} backend`);
```

## Deno

```bash
deno add npm:@bounded-authority-protocol/verifier
deno run verify-anywhere.ts
```

`deno add` maps the package name to its `npm:` specifier in `deno.json`, so the import above works
unchanged; the run needs no permission flags. In a project that has a `package.json` and a
`node_modules` directory, Deno resolves the package from there instead. Either way it prints
`verified grant-gallery with the portable backend`.

## Bun

```bash
bun add @bounded-authority-protocol/verifier
bun verify-anywhere.ts
```

Bun runs TypeScript directly and prints the same line.

## Browsers

A browser cannot resolve a bare package name by itself, so bundle the module first. With esbuild:

```bash
npx esbuild verify-anywhere.ts --bundle --format=esm --platform=browser --outfile=verify-anywhere.js
```

Then load the bundle as a module script from a page served over HTTPS (or from `localhost`, which
browsers also treat as a secure context, as WebCrypto requires):

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Verify a grant</title>
  <script type="module" src="verify-anywhere.js"></script>
</head>
<body></body>
</html>
```

The browser console shows `verified grant-gallery with the portable backend`. Other bundlers
resolve the package through the same `"imports"` conditions; a build that sets the `node`
condition gets the Node.js backend unless you add `bap-portable`, and the
[README](../../README.md#browsers-deno-bun-and-workers) lists the common builds that do.
The package needs no `eval`, so the page works under a strict Content Security Policy such as
`script-src 'self'`.

A verdict computed in a page is for display only, never a trust decision: the page's own scripts
and extensions can change both the inputs and the result. Keep the decision on a server that holds
the trusted keys, as in [Protect an HTTP endpoint](http-server.md).
