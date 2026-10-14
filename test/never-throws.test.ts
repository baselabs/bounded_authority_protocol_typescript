// verifyStrict, es256VerifyStrict, acceptablePublicKey and torsionFree are documented as total: they
// return false for any input that is not valid, and never throw. Exotic inputs that pass an
// `instanceof Uint8Array` check but whose typed-array getters throw (a Proxy around a Uint8Array, an
// object created from Uint8Array.prototype) must also give false.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { acceptablePublicKey, es256VerifyStrict, torsionFree, verifyStrict } from "../src/index.js";

const ed = generateKeyPairSync("ed25519");
const key = new Uint8Array(Buffer.from(ed.publicKey.export({ format: "jwk" }).x!, "base64url"));
const message = new TextEncoder().encode("m");
const signature = new Uint8Array(sign(null, message, ed.privateKey));

const exotic = (): unknown[] => [
  new Proxy(new Uint8Array(32), {}),
  new Proxy(new Uint8Array(64), { get: () => { throw new Error("trap"); } }),
  Object.create(Uint8Array.prototype),
  { length: 32 },
  null,
  undefined,
  "x".repeat(32),
];

test("controls: valid inputs are accepted", () => {
  assert.equal(verifyStrict(message, signature, key), true);
  assert.equal(acceptablePublicKey(key), true);
  assert.equal(torsionFree(key), true);
});

test("the strict checks return false, never throw, on exotic inputs in every position", () => {
  for (const x of exotic()) {
    const u = x as Uint8Array;
    assert.equal(verifyStrict(u, signature, key), false);
    assert.equal(verifyStrict(message, u, key), false);
    assert.equal(verifyStrict(message, signature, u), false);
    assert.equal(es256VerifyStrict(u, new Uint8Array(64), new Uint8Array(65)), false);
    assert.equal(es256VerifyStrict(message, u, new Uint8Array(65)), false);
    assert.equal(es256VerifyStrict(message, new Uint8Array(64), u), false);
    assert.equal(acceptablePublicKey(u), false);
    assert.equal(torsionFree(u), false);
  }
});
