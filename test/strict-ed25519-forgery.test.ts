// End-to-end strict-Ed25519 tests through the PUBLIC verification surface (verifyGrant, v1 and v2).
// Each case forges a grant signature under a weak public key with no private key: the key is one of
// the 8 small-order points or one of the 6 non-canonical aliases of a small-order point, S = 0, and
// R is the small-order point with R + [k]A = O. The reference proves every forgery is real: an
// ungated lenient cofactorless backend accepts it. The verifier must reject all of them, and must
// still accept an honest grant signed by a generated key (the positive control that keeps the
// rejections from being vacuous).
import { test } from "node:test";
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";

import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import { assembleSegments } from "../src/compact.js";
import { strUtf8 } from "../src/json.js";
import { base64urlEncode } from "../src/base64url.js";
import {
  P, bigToLe, classifyEncoding, forgeUnderSmallOrderKey, smallOrderEncodings, verifyUngatedCofactorless,
} from "./support/ed25519_reference.js";

const text = (b: Uint8Array) => new TextDecoder().decode(b);

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "https://resource.example.test";
const EXPECTED = { issuer: ISSUER, audience: AUDIENCE, evaluationTime: 1200, clockSkew: 60 };

function grant(n: number): v1.GrantProducer {
  return {
    keyId: "issuer", issuer: ISSUER, grantId: `urn:example:grant:forged-${n}`, audiences: [AUDIENCE],
    issuedAt: 1000, notBefore: 1000, expiresAt: 2000,
    holderThumbprint: text(base64urlEncode(new Uint8Array(32).fill(1))),
    operations: [{ name: "read", selectors: ["all"] }],
  };
}

type Major = { name: string; signingInput: typeof v1.grantSigningInput; verify: typeof v1.verifyGrant };
const MAJORS: Major[] = [
  { name: "v1", signingInput: v1.grantSigningInput, verify: v1.verifyGrant },
  { name: "v2", signingInput: v2.grantSigningInput, verify: v2.verifyGrant },
];

function messageOf(major: Major, n: number): Uint8Array {
  const si = major.signingInput(grant(n));
  if (!si.ok) throw new Error("grant signing input failed");
  return strUtf8(`${text(si.value.protectedSegment)}.${text(si.value.payloadSegment)}`);
}

function forgedGrant(major: Major, publicKey: Uint8Array): Uint8Array {
  const forged = forgeUnderSmallOrderKey(publicKey, (n) => messageOf(major, n));
  const si = major.signingInput(grant(forged.n));
  if (!si.ok) throw new Error("grant signing input failed");
  // The reference confirms the forgery is real: an ungated lenient cofactorless backend accepts it.
  assert.ok(verifyUngatedCofactorless(publicKey, forged.signature, forged.message), "forgery is real");
  // Frame the forgery directly: its signature (S = 0, R the small-order point) is exactly what a
  // producer surface refuses to frame since erratum 3, so the verifier-rejection claim below is
  // proven on bytes assembled without the gated assembler.
  return strUtf8(`${text(si.value.protectedSegment)}.${text(si.value.payloadSegment)}.${text(base64urlEncode(forged.signature))}`);
}

// The 8 canonical small-order encodings (derived by arithmetic) plus the 6 non-canonical aliases of
// the identity, the order-2 point and ... that decode to a small-order point under a lenient reader.
function weakKeys(): Array<[string, Uint8Array]> {
  const out: Array<[string, Uint8Array]> = smallOrderEncodings().map((k, i) => [`small-order-${i}`, k]);
  const aliases: Array<[string, Uint8Array]> = [
    ["alias y=p", bigToLe(P, 32)],
    ["alias y=p sign", bigToLe(P | (1n << 255n), 32)],
    ["alias y=p+1", bigToLe(P + 1n, 32)],
    ["alias y=p+1 sign", bigToLe((P + 1n) | (1n << 255n), 32)],
    ["alias identity x=0 sign", bigToLe(1n | (1n << 255n), 32)],
    ["alias order-2 x=0 sign", bigToLe((P - 1n) | (1n << 255n), 32)],
  ];
  for (const [name, bytes] of aliases) {
    const c = classifyEncoding(bytes);
    assert.equal(c.kind, "noncanonical", name);
    assert.ok(c.kind === "noncanonical" && c.point !== null, `${name} decodes leniently to a point`);
    out.push([name, bytes]);
  }
  return out;
}

test("control: an honest grant under a generated key verifies on v1 and v2", () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  const raw = new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  for (const major of MAJORS) {
    const si = major.signingInput(grant(0));
    assert.ok(si.ok);
    const message = strUtf8(`${text(si.value.protectedSegment)}.${text(si.value.payloadSegment)}`);
    const signature = new Uint8Array(nodeCrypto.sign(null, Buffer.from(message), privateKey));
    const compact = assembleSegments(si.value, signature);
    assert.ok(compact.ok);
    const result = major.verify(compact.value, { keyId: "issuer", publicKey: raw }, EXPECTED);
    assert.equal(result.ok, true, `${major.name} honest grant`);
  }
});

for (const major of MAJORS) {
  for (const [name, key] of weakKeys()) {
    test(`${major.name}.verifyGrant rejects a forged grant under a weak issuer key (${name})`, () => {
      const compact = forgedGrant(major, key);
      const result = major.verify(compact, { keyId: "issuer", publicKey: key }, EXPECTED);
      assert.equal(result.ok, false);
    });
  }
}
