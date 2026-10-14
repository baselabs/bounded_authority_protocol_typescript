// verifyStrict, es256VerifyStrict, acceptablePublicKey and torsionFree are documented as total: they
// return false for any input that is not valid, and never throw. The signature checks run with a real
// key and a valid signature, so each refusal below is the input guard's: a message given as the same
// text as a string or a plain array would verify without the guard, and exotic inputs that pass an
// `instanceof Uint8Array` check but whose typed-array getters throw (a Proxy around a Uint8Array, an
// object created from Uint8Array.prototype) must also give false.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { acceptablePublicKey, es256VerifyStrict, torsionFree, verifyStrict } from "../src/index.js";

const TEXT = "the signed message";
const message = new TextEncoder().encode(TEXT);

const ed = generateKeyPairSync("ed25519");
const edKey = new Uint8Array(Buffer.from(ed.publicKey.export({ format: "jwk" }).x!, "base64url"));
const edSig = new Uint8Array(sign(null, message, ed.privateKey));

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
const { x, y } = ec.publicKey.export({ format: "jwk" });
const ecKey = new Uint8Array(Buffer.concat([Buffer.from([4]), Buffer.from(x!, "base64url"), Buffer.from(y!, "base64url")]));
const ecSig = ((): Uint8Array => {
  const sig = sign("sha256", message, { key: ec.privateKey, dsaEncoding: "ieee-p1363" });
  const s = BigInt(`0x${sig.subarray(32).toString("hex")}`);
  if (s > (N - 1n) / 2n) sig.set(Buffer.from((N - s).toString(16).padStart(64, "0"), "hex"), 32);
  return new Uint8Array(sig);
})();

const exotic = (bytes: Uint8Array): unknown[] => [
  TEXT,
  Array.from(bytes),
  new Proxy(new Uint8Array(bytes), {}),
  new Proxy(new Uint8Array(bytes), { get: () => { throw new Error("trap"); } }),
  Object.create(Uint8Array.prototype),
  { length: bytes.length },
  null,
  undefined,
];

test("controls: the real keys and signatures verify", () => {
  assert.equal(verifyStrict(message, edSig, edKey), true);
  assert.equal(es256VerifyStrict(message, ecSig, ecKey), true);
  assert.equal(acceptablePublicKey(edKey), true);
  assert.equal(torsionFree(edKey), true);
});

test("verifyStrict returns false, never throws, for an exotic value in each position", () => {
  exotic(message).forEach((v, i) => assert.equal(verifyStrict(v as Uint8Array, edSig, edKey), false, `message form ${i}`));
  for (const v of exotic(edSig)) assert.equal(verifyStrict(message, v as Uint8Array, edKey), false);
  for (const v of exotic(edKey)) assert.equal(verifyStrict(message, edSig, v as Uint8Array), false);
});

test("es256VerifyStrict returns false, never throws, for an exotic value in each position", () => {
  exotic(message).forEach((v, i) => assert.equal(es256VerifyStrict(v as Uint8Array, ecSig, ecKey), false, `message form ${i}`));
  for (const v of exotic(ecSig)) assert.equal(es256VerifyStrict(message, v as Uint8Array, ecKey), false);
  for (const v of exotic(ecKey)) assert.equal(es256VerifyStrict(message, ecSig, v as Uint8Array), false);
});

test("acceptablePublicKey and torsionFree return false, never throw, for exotic keys", () => {
  for (const v of exotic(edKey)) {
    assert.equal(acceptablePublicKey(v as Uint8Array), false);
    assert.equal(torsionFree(v as Uint8Array), false);
  }
});
