# Protect an HTTP endpoint

This recipe puts `checkEnvelope` in front of one endpoint of a Node.js HTTP server, as middleware:
it reads the grant, the proof and the invocation id from the request, builds the expected request
from the server's own view of it, verifies, reserves the invocation id once, and only then runs the
handler. It then plays the holder against that server and shows a fresh call succeed and a replay,
an altered body and an argument outside the grant refuse. The repository's test suite runs it
exactly as written.

Two choices here are this recipe's, not the protocol's:

- **The transport.** The protocol defines the grant and proof bytes, not how they travel. This
  recipe sends them in three request headers, `BAP-Grant`, `BAP-Proof` and `BAP-Invocation`; use
  whatever your API already uses for credentials, over TLS.
- **The replay store.** The package keeps no state, so an envelope verifies again until its proof
  is too old. The in-memory store below is a sketch for one process. Across instances, use a shared
  store with an atomic insert-if-absent and an expiry, such as a unique key with a time to live.

```ts
import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  assembleCompact, checkEnvelope, grantSigningInput, jsonDecode, jwkFromPublicKey, proofSigningInput, strUtf8,
  thumbprint, trying, untrustedKeyLocator, uriNormalize, utf8Str,
  type EnvelopeFacts, type SigningInput, type Tagged, type TrustedIssuer,
} from "@bounded-authority-protocol/verifier";

// ---- The resource server ----------------------------------------------------------------------

// This server's identifier, which its grants name as their audience, and the origin its clients
// address. TLS terminates in front of the server, so requests arrive here as plain HTTP.
const AUDIENCE = "https://notes.example";
const ISSUER = "https://issuer.example";
const CLOCK_SKEW = 60; // seconds, at most 60
const PROOF_MAX_AGE = 120; // seconds, 1 to 300

// The issuer keys this server enrolled, by kid. A key never comes from the request.
const trustedIssuers = new Map<string, TrustedIssuer>();

// Replay store sketch: reserve each invocation of a grant once, until its proof can no longer verify.
interface ReplayStore { reserve(key: string, until: number, now: number): boolean }
function memoryReplayStore(): ReplayStore {
  const reserved = new Map<string, number>();
  return {
    reserve(key, until, now) {
      for (const [k, expiry] of reserved) if (expiry < now) reserved.delete(k);
      if (reserved.has(key)) return false;
      reserved.set(key, until);
      return true;
    },
  };
}
const replay = memoryReplayStore();

const header = (req: IncomingMessage, name: string): string | undefined => {
  const value = req.headers[name];
  return typeof value === "string" && value !== "" ? value : undefined;
};

// Cap the body while reading: the envelope is not authenticated yet, so an unbounded read would
// let any caller who copies a grant hold this server's memory. Pick your application's limit; the
// protocol's own bounds stop at 64 KiB of JSON.
const MAX_BODY_BYTES = 16_384;

async function readBody(req: IncomingMessage): Promise<Uint8Array | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) return undefined;
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

type Handler = (facts: EnvelopeFacts, args: Tagged, res: ServerResponse) => void;

// Middleware for one operation. Every refusal is the same 401, with no detail for the caller.
function requireEnvelope(operation: string, handler: Handler) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const refuse = (): void => void res.writeHead(401).end();
    const grant = header(req, "bap-grant");
    const proof = header(req, "bap-proof");
    const invocationId = header(req, "bap-invocation");
    if (grant === undefined || proof === undefined || invocationId === undefined) return refuse();

    // The grant's kid is a lookup hint read from its header; the signature check binds the key.
    const locator = untrustedKeyLocator(strUtf8(grant));
    const trustedIssuer = locator.ok ? trustedIssuers.get(locator.value.keyId) : undefined;
    if (trustedIssuer === undefined) return refuse();

    // The expected request comes from this server's own request handling, never from the proof:
    // the method and path it received, and the arguments it parsed (strict JSON, types kept).
    const target = uriNormalize(strUtf8(AUDIENCE + (req.url ?? "/"))); // a query string refuses
    const body = await readBody(req);
    if (body === undefined) return refuse();
    const args = trying(() => jsonDecode(body));
    if (!target.ok || !args.ok) return refuse();

    const now = Math.floor(Date.now() / 1000); // seconds, never Date.now() milliseconds
    const result = checkEnvelope(strUtf8(grant), strUtf8(proof), {
      trustedIssuer, issuer: ISSUER, audience: AUDIENCE, method: req.method ?? "",
      targetUri: utf8Str(target.value), invocationId, operation, castArguments: args.value,
      evaluationTime: now, clockSkew: CLOCK_SKEW, proofMaxAge: PROOF_MAX_AGE, nonce: { kind: "not_required" },
    });
    if (!result.ok) return refuse();

    // The proof verifies until its iat + proofMaxAge + clockSkew, so the reservation lasts that long.
    const facts = result.value;
    const key = `${facts.issuer} ${facts.grantId} ${facts.invocationId}`;
    if (!replay.reserve(key, facts.proofIssuedAt + PROOF_MAX_AGE + CLOCK_SKEW, now)) return refuse();

    // Revocation and your own policy come next. The facts say what was proven, not what to allow.
    handler(facts, args.value, res);
  };
}

const createNote = requireEnvelope("notes.create", (facts, _args, res) => {
  res.writeHead(201, { "content-type": "application/json" }).end(JSON.stringify({ grant: facts.grantId }));
});
const server = createServer((req, res) => {
  if (req.method === "POST" && req.url === "/notebooks/team/notes") {
    createNote(req, res).catch(() => res.writeHead(500).end());
    return;
  }
  res.writeHead(404).end();
});

// ---- The issuer and the holder, for this demonstration -----------------------------------------

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const message = (input: SigningInput): Uint8Array =>
  Buffer.concat([input.protectedSegment, Buffer.from("."), input.payloadSegment]);
const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
trustedIssuers.set("issuer-2026-11", { keyId: "issuer-2026-11", publicKey: raw(issuer.publicKey) });

// The issuer lets the holder add notes to the "team" notebook for one hour.
const issuedAt = Math.floor(Date.now() / 1000);
const grantInput = grantSigningInput({
  keyId: "issuer-2026-11", issuer: ISSUER, grantId: "grant-notes-1", audiences: [AUDIENCE],
  issuedAt, notBefore: issuedAt, expiresAt: issuedAt + 3600,
  holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
  operations: [{
    name: "notes.create",
    selectors: [{ kind: "equals", path: ["notebook"], value: { t: "string", v: strUtf8("team") } }],
  }],
});
assert.ok(grantInput.ok);
const signedGrant = assembleCompact(grantInput.value, sign(null, message(grantInput.value), issuer.privateKey));
assert.ok(signedGrant.ok);
const grant = signedGrant.value;

// The holder signs one proof per call, over the exact arguments it sends.
interface Call { headers: Record<string, string>; body: string }
function prepare(body: string): Call {
  const invocationId = randomUUID(); // a lowercase RFC 4122 UUID, new for every call
  const proofInput = proofSigningInput({
    holderPublicKey: raw(holder.publicKey), proofId: randomUUID(), method: "POST",
    targetUri: `${AUDIENCE}/notebooks/team/notes`, issuedAt: Math.floor(Date.now() / 1000), invocationId,
    operation: "notes.create", grantCompact: grant, castArguments: jsonDecode(strUtf8(body)),
  });
  assert.ok(proofInput.ok);
  const proof = assembleCompact(proofInput.value, sign(null, message(proofInput.value), holder.privateKey));
  assert.ok(proof.ok);
  return {
    headers: {
      "content-type": "application/json", "bap-grant": utf8Str(grant),
      "bap-proof": utf8Str(proof.value), "bap-invocation": invocationId,
    },
    body,
  };
}

await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
const send = async (call: Call): Promise<number> =>
  (await fetch(`${origin}/notebooks/team/notes`, { method: "POST", headers: call.headers, body: call.body })).status;
try {
  const standup = prepare('{"notebook":"team","title":"Standup"}');
  assert.equal(await send(standup), 201);
  assert.equal(await send(standup), 401); // the same envelope again: a replay
  assert.equal(await send({ ...standup, body: '{"notebook":"team","title":"Edited"}' }), 401); // not the signed arguments
  assert.equal(await send(prepare('{"notebook":"drafts","title":"Ideas"}')), 401); // outside the grant's selector
  assert.equal(await send({ ...prepare('{"notebook":"team","title":"Retro"}'), headers: {} }), 401); // no credentials
  assert.equal(await send(prepare(`{"notebook":"team","title":"Big","lines":${JSON.stringify(Array(3).fill("x".repeat(8000)))}}`)), 401); // signed, but over the body cap
  assert.equal(await send(prepare('{"notebook":"team","title":"Retro"}')), 201);
} finally {
  server.close();
  server.closeAllConnections();
}
```

What the middleware leaves to you, in order: enrolling issuer keys (see [Rotate keys](rotate-keys.md)),
revocation, and the decision to act. A server that issues nonces passes
`{ kind: "required", value }` instead of `not_required` (see
[Verify requests](verify-requests.md#nonces)). To find out why a request refuses while you build
the integration, see [Handle errors](handle-errors.md#finding-why-a-request-rejects); never send that
detail to the caller.
