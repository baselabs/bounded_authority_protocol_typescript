// The public v3 JWK helpers, mirroring the root's Ed25519 helpers (jwkFromPublicKey, thumbprintPreimage,
// thumbprint, thumbprintRaw, publicKeyThumbprintRaw) and the Elixir V3.EcJwk.encode_public: a raw
// 65-byte uncompressed SEC1 point becomes {crv: "P-256", kty: "EC", x, y}, and a point that is not an
// acceptable P-256 public key (wrong width, a non-0x04 prefix, a coordinate not below p, off the curve)
// is refused with the closed InvalidError. Keys come from node:crypto; the expected JWK and thumbprint
// are computed here independently of the package.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { v3, InvalidError } from "../src/index.js";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const { x, y } = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
const raw = new Uint8Array(Buffer.concat([Buffer.from([4]), Buffer.from(x!, "base64url"), Buffer.from(y!, "base64url")]));
const preimage = `{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`;
const expectedThumbprint = createHash("sha256").update(preimage).digest();

const offCurve = Uint8Array.from(raw); offCurve[64] = offCurve[64]! ^ 1;
const compressed = Uint8Array.from(raw); compressed[0] = 0x02;
const xNotBelowP = Uint8Array.from(raw); xNotBelowP.set(Buffer.from(P.toString(16), "hex"), 1);
const BAD: Array<[string, Uint8Array]> = [
  ["64 bytes", raw.subarray(1)], ["33 bytes", raw.subarray(0, 33)], ["0x02 prefix", compressed],
  ["off the curve", offCurve], ["x = p", xNotBelowP],
];

test("v3.jwkFromPublicKey returns the public EC JWK of a raw 65-byte point", () => {
  const jwk: v3.EcPublic = v3.jwkFromPublicKey(raw);
  assert.deepEqual(jwk, { crv: "P-256", kty: "EC", x, y });
});

test("v3 thumbprint helpers agree with an independent RFC 7638 computation", () => {
  const jwk = v3.jwkFromPublicKey(raw);
  assert.equal(new TextDecoder().decode(v3.thumbprintPreimage(jwk)), preimage);
  assert.deepEqual(Buffer.from(v3.thumbprintRaw(jwk)), expectedThumbprint);
  assert.deepEqual(Buffer.from(v3.publicKeyThumbprintRaw(raw)), expectedThumbprint);
  assert.equal(v3.thumbprint(jwk), expectedThumbprint.toString("base64url"));
  assert.equal(new TextDecoder().decode(v3.jwkEncodePublic(raw)), preimage);
});

for (const [name, key] of BAD) {
  test(`v3 JWK helpers refuse a key that is not an acceptable P-256 point: ${name}`, () => {
    assert.throws(() => v3.jwkFromPublicKey(key), InvalidError);
    assert.throws(() => v3.publicKeyThumbprintRaw(key), InvalidError);
    assert.throws(() => v3.jwkEncodePublic(key), InvalidError);
  });
}

test("v3 JWK-object helpers refuse a JWK whose point is not acceptable", () => {
  const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
  const bad = { crv: "P-256" as const, kty: "EC" as const, x: b64(offCurve.subarray(1, 33)), y: b64(offCurve.subarray(33)) };
  const shortX = { crv: "P-256" as const, kty: "EC" as const, x: b64(raw.subarray(1, 32)), y: y! };
  for (const jwk of [bad, shortX]) {
    assert.throws(() => v3.thumbprintPreimage(jwk), InvalidError);
    assert.throws(() => v3.thumbprintRaw(jwk), InvalidError);
    assert.throws(() => v3.thumbprint(jwk), InvalidError);
  }
});
