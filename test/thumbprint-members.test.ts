// RFC 7638 thumbprints hash exactly the required members of the key type, and the protocol's JWKs are
// closed: the Elixir V1.Jwk and V3.EcJwk thumbprint functions decode the JWK and accept only the exact
// member set ({crv, kty, x} for OKP Ed25519, {crv, kty, x, y} for EC P-256). The TypeScript helpers
// that take a JWK object (thumbprintPreimage, thumbprint, thumbprintRaw, and their v3 forms) refuse any
// other member with InvalidError: a private `d`, an `alg`, or any extra member.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { InvalidError, jwkFromPublicKey, thumbprint, thumbprintPreimage, thumbprintRaw, v3 } from "../src/index.js";

const ed = generateKeyPairSync("ed25519");
const edJwk = jwkFromPublicKey(Buffer.from(ed.publicKey.export({ format: "jwk" }).x!, "base64url"));
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { x, y } = ec.publicKey.export({ format: "jwk" });
const ecJwk = v3.jwkFromPublicKey(Buffer.concat([Buffer.from([4]), Buffer.from(x!, "base64url"), Buffer.from(y!, "base64url")]));
const privateD = (k: typeof ed.privateKey): string => k.export({ format: "jwk" }).d!;

const EXTRA: Array<[string, Record<string, string>]> = [
  ["a private d", { d: "" }], ["alg", { alg: "EdDSA" }], ["an extra member", { use: "sig" }],
];

test("controls: the exact JWKs are accepted", () => {
  assert.equal(thumbprint(edJwk).length, 43);
  assert.equal(v3.thumbprint(ecJwk).length, 43);
});

for (const [name, extra] of EXTRA) {
  test(`Ed25519 thumbprint helpers refuse a JWK with ${name}`, () => {
    const jwk = { ...edJwk, ...extra, ...(name === "a private d" ? { d: privateD(ed.privateKey) } : {}) };
    for (const f of [thumbprint, thumbprintRaw, thumbprintPreimage]) assert.throws(() => f(jwk as typeof edJwk), InvalidError, f.name);
  });
  test(`v3 thumbprint helpers refuse a JWK with ${name}`, () => {
    const jwk = { ...ecJwk, ...extra, ...(name === "a private d" ? { d: privateD(ec.privateKey) } : {}) };
    for (const f of [v3.thumbprint, v3.thumbprintRaw, v3.thumbprintPreimage]) assert.throws(() => f(jwk as typeof ecJwk), InvalidError, f.name);
  });
}

test("thumbprint helpers refuse a JWK missing a member or with a wrong kty/crv", () => {
  const { x: _x, ...noX } = edJwk;
  for (const bad of [noX, { ...edJwk, kty: "EC" }, { ...edJwk, crv: "X25519" }]) {
    assert.throws(() => thumbprint(bad as typeof edJwk), InvalidError);
  }
  const { y: _y, ...noY } = ecJwk;
  for (const bad of [noY, { ...ecJwk, kty: "OKP" }, { ...ecJwk, crv: "P-384" }]) {
    assert.throws(() => v3.thumbprint(bad as typeof ecJwk), InvalidError);
  }
});
