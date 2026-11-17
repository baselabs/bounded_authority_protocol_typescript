import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import ts from "typescript";
import {
  assembleCompact, checkEnvelope, grantSigningInput, jsonDecode, jwkFromPublicKey,
  proofSigningInput, strUtf8, thumbprint,
  type EnvelopeFacts, type ExpectedRequest, type SigningInput,
} from "../src/index.js";

// Execute the guide's actual store and middleware reservation expression. Extracting both keeps
// this regression tied to the reader's recipe rather than a second implementation in the test.
async function guideReservation(): Promise<(facts: EnvelopeFacts, now: number) => boolean> {
  const guide = readFileSync(new URL("../docs/guides/http-server.md", import.meta.url), "utf8");
  const constants = guide.match(/^const (?:CLOCK_SKEW|PROOF_MAX_AGE) = .*$/gm);
  const store = guide.match(/interface ReplayStore[\s\S]*?const replay = memoryReplayStore\(\);/);
  const reservation = guide.match(/const key = .*;\n\s*if \(!replay\.reserve\((.*)\)\) return refuse\(\);/);
  assert.equal(constants?.length, 2, "extract the guide's time bounds");
  assert.ok(store && reservation, "extract the actual store and reservation call");
  const code = `${constants.join("\n")}\n${store[0]}\nexport function reserve(facts, now) {
    ${reservation[0].split("\n")[0]}
    return replay.reserve(${reservation[1]});
  }`;
  const { outputText } = ts.transpileModule(code, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  });
  const module = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`) as {
    reserve: (facts: EnvelopeFacts, now: number) => boolean;
  };
  return module.reserve;
}

test("the HTTP guide rejects a fresh proof for a reserved invocation through grant expiry plus skew", async () => {
  const reserve = await guideReservation();
  const issuer = generateKeyPairSync("ed25519");
  const holder = generateKeyPairSync("ed25519");
  const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
  const signed = (input: SigningInput, key: KeyObject): Uint8Array => {
    const signature = sign(null, Buffer.concat([input.protectedSegment, Buffer.from("."), input.payloadSegment]), key);
    const result = assembleCompact(input, signature);
    assert.ok(result.ok);
    return result.value;
  };
  const castArguments = jsonDecode(strUtf8('{"queue":"support","ticket":981}'));
  const input = grantSigningInput({
    keyId: "issuer-1", issuer: "https://issuer.example", grantId: "grant-1",
    audiences: ["https://service.example"], issuedAt: 100, notBefore: 100, expiresAt: 3700,
    holderThumbprint: thumbprint(jwkFromPublicKey(raw(holder.publicKey))),
    operations: [{ name: "tickets.close", selectors: [{ kind: "equals", path: ["queue"], value: { t: "string", v: strUtf8("support") } }] }],
  });
  assert.ok(input.ok);
  const grant = signed(input.value, issuer.privateKey);
  const expected: ExpectedRequest = {
    trustedIssuer: { keyId: "issuer-1", publicKey: raw(issuer.publicKey) },
    issuer: "https://issuer.example", audience: "https://service.example", method: "POST",
    targetUri: "https://service.example/tickets/981/close", operation: "tickets.close",
    invocationId: "a5aa4879-834f-4b20-8c0c-d5cb9622c9cb", castArguments,
    evaluationTime: 100, clockSkew: 60, proofMaxAge: 120, nonce: { kind: "not_required" },
  };
  const proofAt = (issuedAt: number, invocationId = expected.invocationId): Uint8Array => {
    const proof = proofSigningInput({
      holderPublicKey: raw(holder.publicKey), proofId: `proof-${issuedAt}`, method: expected.method,
      targetUri: expected.targetUri, issuedAt, invocationId, operation: expected.operation,
      grantCompact: grant, castArguments,
    });
    assert.ok(proof.ok);
    return signed(proof.value, holder.privateKey);
  };
  const firstProof = proofAt(100);
  const first = checkEnvelope(grant, firstProof, expected);
  assert.ok(first.ok);
  assert.equal(reserve(first.value, 100), true);
  assert.equal(reserve(first.value, 100), false, "an immediate replay refuses");

  // At 400 the original proof is too old, but the holder can sign a fresh, valid proof.
  assert.deepEqual(checkEnvelope(grant, firstProof, { ...expected, evaluationTime: 400 }), { ok: false });
  const nextInvocation = "40a1ab85-361a-4354-95e5-7d38dde03afc";
  const next = checkEnvelope(grant, proofAt(400, nextInvocation), { ...expected, invocationId: nextInvocation, evaluationTime: 400 });
  assert.ok(next.ok);
  assert.equal(reserve(next.value, 400), true, "another invocation is independently reservable");
  for (const now of [400, 3700, 3759]) {
    const fresh = checkEnvelope(grant, proofAt(now), { ...expected, evaluationTime: now });
    assert.ok(fresh.ok, `a new proof still verifies at ${now}`);
    assert.equal(reserve(fresh.value, now), false, `same invocation must not execute again at ${now}`);
  }
  assert.deepEqual(checkEnvelope(grant, proofAt(3760), { ...expected, evaluationTime: 3760 }), { ok: false },
    "at grant expiry plus skew no new proof under this grant verifies");
});
