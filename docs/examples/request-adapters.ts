import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  assembleCompact, checkEnvelope, grantSigningInput, jsonDecode, jwkFromPublicKey,
  proofSigningInput, strUtf8, thumbprint, trying, utf8Str, uriNormalize,
  type ExpectedRequest, type SigningInput,
} from "@bounded-authority-protocol/verifier";

const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
const issuer = generateKeyPairSync("ed25519");
const holder = generateKeyPairSync("ed25519");
const now = Math.floor(Date.now() / 1000);
const origin = "https://documents.example"; // configured public origin, never a forwarded header
function compact(input: SigningInput, key: KeyObject): Uint8Array {
  const result = assembleCompact(input, sign(null,
    Buffer.concat([input.protectedSegment, Buffer.from("."), input.payloadSegment]), key));
  assert.ok(result.ok); return result.value;
}
const g = grantSigningInput({
  keyId: "issuer-1", issuer: "https://issuer.example", grantId: "grant-adapters", audiences: [origin],
  issuedAt: now, notBefore: now, expiresAt: now + 3600,
  holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
  operations: [{ name: "documents.create", selectors: ["all"] }],
});
assert.ok(g.ok);
const grant = compact(g.value, issuer.privateKey);
const reserved = new Set<string>(); // demonstration only; replace with the durable store contract
function verify(method: string, path: string, headers: Headers, body: Uint8Array): number {
  if (body.length > 16384 || path !== "/documents") return 401;
  const target = uriNormalize(strUtf8(origin + path));
  const args = trying(() => jsonDecode(body));
  if (!target.ok || !args.ok) return 401;
  const expected: ExpectedRequest = {
    trustedIssuer: { keyId: "issuer-1", publicKey: raw(issuer.publicKey) },
    issuer: "https://issuer.example", audience: origin, method, targetUri: utf8Str(target.value),
    invocationId: headers.get("bap-invocation") ?? "", operation: "documents.create",
    castArguments: args.value, evaluationTime: Math.floor(Date.now() / 1000),
    clockSkew: 60, proofMaxAge: 120, nonce: { kind: "not_required" },
  };
  const result = checkEnvelope(strUtf8(headers.get("bap-grant") ?? ""), strUtf8(headers.get("bap-proof") ?? ""), expected);
  if (!result.ok) return 401;
  const key = JSON.stringify([result.value.issuer, result.value.grantId, result.value.invocationId]);
  if (reserved.has(key)) return 401;
  reserved.add(key);
  // This demo's host policy permits its single operation; real hosts check live revocation too.
  return 201;
}
async function boundedBody(request: IncomingMessage): Promise<Uint8Array | undefined> {
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of request) {
    const part = Buffer.from(chunk as Uint8Array); bytes += part.length;
    if (bytes > 16384) return undefined;
    chunks.push(part);
  }
  return Buffer.concat(chunks);
}
function requestHeaders(request: IncomingMessage): Headers | undefined {
  // Reject duplicate credentials before any framework collapses them into one value.
  const names = request.rawHeaders.filter((_value, i) => i % 2 === 0).map((name) => name.toLowerCase());
  if (["bap-grant", "bap-proof", "bap-invocation"].some((name) => names.filter((n) => n === name).length !== 1)) return undefined;
  const headers = new Headers();
  for (const name of ["bap-grant", "bap-proof", "bap-invocation"]) headers.set(name, String(request.headers[name]));
  return headers;
}
async function fetchHandler(request: Request): Promise<Response> {
  const url = new URL(request.url);
  return new Response(null, { status: verify(request.method, url.pathname + url.search, request.headers,
    new Uint8Array(await request.arrayBuffer())) });
}
async function nativeHandler(request: IncomingMessage, response: ServerResponse, mode: "native" | "fetch") {
  const headers = requestHeaders(request); const body = await boundedBody(request);
  if (headers === undefined || body === undefined) { response.writeHead(401).end(); return; }
  const path = request.url ?? "/";
  // Validate the raw path before constructing a URL: URL construction can normalize dot segments.
  const canonical = uriNormalize(strUtf8(origin + path));
  if (!canonical.ok || utf8Str(canonical.value) !== origin + path) { response.writeHead(401).end(); return; }
  const status = mode === "native" ? verify(request.method ?? "", path, headers, body)
    : (await fetchHandler(new Request(origin + path, { method: request.method ?? "POST", headers, body: Buffer.from(body) }))).status;
  response.writeHead(status).end();
}
for (const mode of ["native", "fetch"] as const) {
  const server = createServer((request, response) => {
    void nativeHandler(request, response, mode).catch(() => response.writeHead(503).end());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const body = '{"title":"Field notes"}'; const invocationId = randomUUID();
    const p = proofSigningInput({ holderPublicKey: raw(holder.publicKey), proofId: randomUUID(),
      method: "POST", targetUri: origin + "/documents", issuedAt: now, invocationId,
      operation: "documents.create", grantCompact: grant, castArguments: jsonDecode(strUtf8(body)) });
    assert.ok(p.ok);
    const headers = { "bap-grant": utf8Str(grant), "bap-proof": utf8Str(compact(p.value, holder.privateKey)), "bap-invocation": invocationId };
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/documents`;
    assert.equal((await fetch(url, { method: "POST", headers, body: body.replace("Field", "Changed") })).status, 401);
    assert.equal((await fetch(url, { method: "POST", headers, body })).status, 201);
    assert.equal((await fetch(url, { method: "POST", headers, body })).status, 401);
    assert.equal((await fetch(url + "?q=1", { method: "POST", headers, body })).status, 401);
  } finally { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
}
