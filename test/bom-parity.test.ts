// A leading U+FEFF (byte order mark) inside a JSON string value or member name is data, not an
// encoding signal. The reference decodes it as the character U+FEFF, so a grant whose header value,
// payload value, or member name starts with U+FEFF differs from the expected string and is invalid.
// These grants are honestly signed by a generated key: only the string bytes differ.
import { test } from "node:test";
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";

import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import { base64urlDecode, base64urlEncode } from "../src/base64url.js";
import { strUtf8, utf8Str } from "../src/json.js";

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "https://resource.example.test";
const EXPECTED = { issuer: ISSUER, audience: AUDIENCE, evaluationTime: 1200, clockSkew: 60 };
const BOM = "﻿";
const text = (b: Uint8Array) => new TextDecoder("utf-8", { ignoreBOM: true }).decode(b);

const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
const rawPublic = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12));

function producer(): v1.GrantProducer {
  return {
    keyId: "issuer", issuer: ISSUER, grantId: "urn:example:grant:bom", audiences: [AUDIENCE],
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

// Rewrites the decoded header and payload text, then signs the exact new bytes.
function signed(major: Major, edit: (header: string, payload: string) => [string, string]): Uint8Array {
  const si = major.signingInput(producer());
  if (!si.ok) throw new Error("grant signing input failed");
  const header = utf8Str(base64urlDecode(si.value.protectedSegment));
  const payload = utf8Str(base64urlDecode(si.value.payloadSegment));
  const [h, p] = edit(header, payload);
  const signingInput = `${text(base64urlEncode(strUtf8(h)))}.${text(base64urlEncode(strUtf8(p)))}`;
  const signature = nodeCrypto.sign(null, Buffer.from(signingInput), privateKey);
  return strUtf8(`${signingInput}.${text(base64urlEncode(new Uint8Array(signature)))}`);
}

const trusted = { keyId: "issuer", publicKey: rawPublic };

const EDITS: Array<[string, (h: string, p: string) => [string, string]]> = [
  ["header alg value", (h, p) => [h.replace('"alg":"EdDSA"', `"alg":"${BOM}EdDSA"`), p]],
  ["header kid value", (h, p) => [h.replace('"kid":"issuer"', `"kid":"${BOM}issuer"`), p]],
  ["payload iss value", (h, p) => [h, p.replace(`"iss":"${ISSUER}"`, `"iss":"${BOM}${ISSUER}"`)]],
  ["payload jti value", (h, p) => [h, p.replace('"jti":"urn:example:grant:bom"', `"jti":"${BOM}urn:example:grant:bom"`)]],
  ["payload member name", (h, p) => [h, p.replace('"v":', `"${BOM}v":`)]],
];

for (const major of MAJORS) {
  test(`${major.name}: the unmodified honestly signed grant verifies (positive control)`, () => {
    const compact = signed(major, (h, p) => [h, p]);
    assert.equal(major.verify(compact, trusted, EXPECTED).ok, true);
  });

  for (const [label, edit] of EDITS) {
    test(`${major.name}: a leading U+FEFF in the ${label} is data, so the grant is invalid`, () => {
      const compact = signed(major, edit);
      assert.notDeepEqual(compact, signed(major, (h, p) => [h, p]), "the edit changed the bytes");
      assert.equal(major.verify(compact, trusted, EXPECTED).ok, false);
    });
  }
}

test("utf8Str keeps a leading U+FEFF as a character", () => {
  assert.equal(utf8Str(strUtf8(`${BOM}x`)), `${BOM}x`);
});
