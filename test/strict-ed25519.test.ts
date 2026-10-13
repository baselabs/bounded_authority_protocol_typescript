// Rule S1 (strict Ed25519) at the verifier's single verify choke point. Expected values come from the
// test-support reference (pure BigInt group arithmetic, shares no code with src/ed25519.ts): the
// small-order set is derived by arithmetic, never copied, and one table serves the key A and the
// signature's R, so a mutant that edits an entry fails for both positions.
//
// Per-rule tripwires. Each vector violates exactly one rule:
//   A canonical            noncanonical aliases of mixed-order points as the key        (gate)
//   A small order          the 8 table points and 6 small-order aliases                 (gate, end to end)
//   R canonical            noncanonical, not small-order, R                             (gate; backend-redundant)
//   R small order          honestA-identityR and mixedA-smallR-{0..7}                   (gate, end to end)
//   S < L                  S in {L - 1 (valid), L, L + 1, 2^256 - 1}                    (gate; backend-redundant)
//   cofactorless equation  honestA-mixedR (a cofactored backend would accept it)        (backend)
import { test } from "node:test";
import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";
import type { BackendPublicKey } from "../src/crypto/types.js";

import { InvalidError } from "../src/error.js";
import {
  acceptablePublicKey, ed25519Verify, importPublicKey, strictGate, torsionFree, verifyStrict,
} from "../src/ed25519.js";
import {
  BASE, L, P, add, bigToLe, challenge, classifyEncoding, concat, encodePoint, findCofactorlessSignature,
  forgeUnderSmallOrderKey, keyHolder, leToBig, multiply, offCurveEncodings, publicKeyFromSeed, signHonest,
  smallOrderEncodings, torsionFreeReference, torsionPoints, verifyStrictReference, verifyUngatedCofactorless,
  acceptableReference, weakEncodings, expandSeed, pointEquals, isSmallOrder,
} from "./support/ed25519_reference.js";

const enc = (s: string) => new TextEncoder().encode(s);
const seed = (n: number) => new Uint8Array(32).fill(n);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

const SMALL_ORDER = smallOrderEncodings();
const T = torsionPoints();

// The six non-canonical aliases of small-order points.
const SMALL_ORDER_ALIASES = [
  bigToLe(P, 32), bigToLe(P | (1n << 255n), 32), bigToLe(P + 1n, 32), bigToLe((P + 1n) | (1n << 255n), 32),
  bigToLe(1n | (1n << 255n), 32), bigToLe((P - 1n) | (1n << 255n), 32),
];

// Weak encodings that are neither canonical nor small order: the key/R "canonical" clause isolated.
const NONCANONICAL_NOT_SMALL = weakEncodings().filter((e) => {
  const c = classifyEncoding(e);
  return c.kind === "noncanonical" && !(c.point !== null && isSmallOrder(c.point));
});

test("reference sanity: 8 small-order points, 48 weak encodings, and the alias split", () => {
  assert.equal(SMALL_ORDER.length, 8);
  assert.equal(new Set(SMALL_ORDER.map(hex)).size, 8);
  assert.equal(weakEncodings().length, 48);
  assert.equal(new Set(weakEncodings().map(hex)).size, 48);
  // 6 small-order aliases + 20 mixed-order + 14 off-curve = the 40 non-canonical encodings.
  assert.equal(NONCANONICAL_NOT_SMALL.length, 34);
  const offcurve = NONCANONICAL_NOT_SMALL.filter((e) => classifyEncoding(e).kind === "noncanonical" && (classifyEncoding(e) as { point: unknown }).point === null);
  assert.equal(offcurve.length, 14);
});

test("honest signatures verify under verifyStrict and agree with the platform backend", () => {
  for (let i = 1; i <= 6; i += 1) {
    const publicKey = publicKeyFromSeed(seed(i));
    const message = enc(`honest-${i}`);
    const signature = signHonest(seed(i), message);
    assert.equal(verifyStrict(message, signature, publicKey), true, `seed ${i}`);
    assert.equal(verifyStrictReference(publicKey, signature, message), true);
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKey)]);
    const key = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    assert.equal(nodeCrypto.verify(null, Buffer.from(message), key, Buffer.from(signature)), true);
    // One flipped bit in the message, the signature, or the key is rejected.
    assert.equal(verifyStrict(enc(`honest-${i}!`), signature, publicKey), false);
    const bad = Uint8Array.from(signature); bad[40] = bad[40]! ^ 1;
    assert.equal(verifyStrict(message, bad, publicKey), false);
  }
});

test("verifyStrict is total: wrong widths and non-byte inputs return false and never throw", () => {
  const publicKey = publicKeyFromSeed(seed(1));
  const message = enc("m");
  const signature = signHonest(seed(1), message);
  assert.equal(verifyStrict(message, signature, publicKey), true);
  assert.equal(verifyStrict(message, signature.subarray(0, 63), publicKey), false);
  assert.equal(verifyStrict(message, concat(signature, new Uint8Array(1)), publicKey), false);
  assert.equal(verifyStrict(message, signature, publicKey.subarray(0, 31)), false);
  assert.equal(verifyStrict(message, signature, concat(publicKey, new Uint8Array(1))), false);
  assert.equal(verifyStrict(message, new Uint8Array(0), new Uint8Array(0)), false);
  for (const junk of [null, undefined, "str", 5, {}, []]) {
    assert.equal(verifyStrict(junk as never, signature, publicKey), false);
    assert.equal(verifyStrict(message, junk as never, publicKey), false);
    assert.equal(verifyStrict(message, signature, junk as never), false);
  }
});

// ---- rule: A small order (table derived by arithmetic) ----

test("the shared small-order table equals the 8 points of E[8] derived by arithmetic", () => {
  // Pins the table itself: each arithmetic point is rejected as a key AND as an R. A mutant that edits
  // any table entry leaves one arithmetic encoding unrejected in both positions.
  const honest = publicKeyFromSeed(seed(2));
  for (let i = 0; i < 8; i += 1) {
    const p = SMALL_ORDER[i]!;
    assert.equal(acceptablePublicKey(p), false, `acceptable ${hex(p)}`);
    assert.equal(torsionFree(p), false, `torsionFree ${hex(p)}`);
    assert.equal(strictGate(concat(encodePoint(multiply(5n, BASE)), bigToLe(5n, 32)), p), false, `gate as A ${hex(p)}`);
    // As R, with an honest key and S < L: only the small-order clause can reject it.
    assert.equal(strictGate(concat(p, bigToLe(5n, 32)), honest), false, `gate as R ${hex(p)}`);
  }
  // Positive control for the R position: a canonical, non-small-order R passes the same gate.
  assert.equal(strictGate(concat(encodePoint(multiply(5n, BASE)), bigToLe(5n, 32)), honest), true);
});

test("a forged signature under each small-order key and alias is real, and verifyStrict rejects it", () => {
  const keys = [...SMALL_ORDER, ...SMALL_ORDER_ALIASES];
  assert.equal(keys.length, 14);
  for (const key of keys) {
    const forged = forgeUnderSmallOrderKey(key, (n) => enc(`forged-${n}`));
    // Real: an ungated lenient cofactorless backend accepts it. Rejected: the gate refuses it.
    assert.equal(verifyUngatedCofactorless(key, forged.signature, forged.message), true, hex(key));
    assert.equal(verifyStrict(forged.message, forged.signature, key), false, hex(key));
  }
});

// ---- rule: A canonical ----

test("noncanonical A is refused by the gate and by key acceptance (mixed-order and off-curve aliases)", () => {
  const sig = concat(encodePoint(multiply(3n, BASE)), bigToLe(7n, 32));
  for (const e of NONCANONICAL_NOT_SMALL) {
    assert.equal(strictGate(sig, e), false, `gate A ${hex(e)}`);
    assert.equal(acceptablePublicKey(e), false, `acceptable ${hex(e)}`);
    assert.equal(torsionFree(e), false, `torsionFree ${hex(e)}`);
  }
  // Positive control: a canonical key passes the same gate with the same signature.
  assert.equal(strictGate(sig, publicKeyFromSeed(seed(3))), true);
});

// ---- rule: R canonical (backend-redundant: only a direct gate test proves the clause) ----

test("noncanonical R is refused by the gate even when R is not small order", () => {
  const honest = publicKeyFromSeed(seed(3));
  for (const e of NONCANONICAL_NOT_SMALL) {
    assert.equal(strictGate(concat(e, bigToLe(9n, 32)), honest), false, `gate R ${hex(e)}`);
  }
  assert.equal(strictGate(concat(encodePoint(multiply(9n, BASE)), bigToLe(9n, 32)), honest), true);
});

// ---- rule: S < L (backend-redundant) ----

test("S at or above L is refused by the gate; S = L - 1 passes it", () => {
  const honest = publicKeyFromSeed(seed(4));
  const r = encodePoint(multiply(11n, BASE));
  const sigWith = (s: bigint) => concat(r, bigToLe(s, 32));
  assert.equal(strictGate(sigWith(L - 1n), honest), true);
  assert.equal(strictGate(sigWith(0n), honest), true);
  assert.equal(strictGate(sigWith(L), honest), false);
  assert.equal(strictGate(sigWith(L + 1n), honest), false);
  assert.equal(strictGate(sigWith(L + 5n), honest), false);
  assert.equal(strictGate(sigWith(2n ** 252n + 2n ** 100n), honest), true);
  assert.equal(strictGate(sigWith(2n ** 256n - 1n), honest), false);
  assert.equal(strictGate(sigWith(2n ** 255n), honest), false);
});

test("an honest signature with S replaced by S + L is refused (malleability)", () => {
  const message = enc("malleable");
  const publicKey = publicKeyFromSeed(seed(5));
  const signature = signHonest(seed(5), message);
  assert.equal(verifyStrict(message, signature, publicKey), true);
  const s = leToBig(signature.subarray(32));
  assert.ok(s + L < 2n ** 256n);
  assert.equal(verifyStrict(message, concat(signature.subarray(0, 32), bigToLe(s + L, 32)), publicKey), false);
});

// ---- rule: R small order (end to end, key-holder built) ----

test("honestA-identityR: a key holder's signature with R = identity verifies ungated and is refused", () => {
  const holder = keyHolder(seed(6));
  const publicKey = encodePoint(holder.prime);
  for (let n = 0; n < 8; n += 1) {
    const found = findCofactorlessSignature(holder, T[0]!, T[0]!, 0n, `idr-${n}`);
    assert.deepEqual([...found.publicKey], [...publicKey]);
    assert.deepEqual([...found.signature.subarray(0, 32)], [...SMALL_ORDER[0]!]);
    assert.equal(verifyUngatedCofactorless(found.publicKey, found.signature, found.message), true);
    assert.equal(verifyStrict(found.message, found.signature, found.publicKey), false);
  }
});

test("mixedA-smallR-{0..7}: A = A0 + T1 with R = each small-order point is real and refused", () => {
  const holder = keyHolder(seed(7));
  for (let j = 0; j < 8; j += 1) {
    const found = findCofactorlessSignature(holder, T[1]!, T[j]!, 0n, `msr-${j}`);
    assert.deepEqual([...found.signature.subarray(0, 32)], [...SMALL_ORDER[j]!]);
    assert.equal(verifyUngatedCofactorless(found.publicKey, found.signature, found.message), true, `j=${j}`);
    assert.equal(verifyStrict(found.message, found.signature, found.publicKey), false, `j=${j}`);
    // The mixed-order key itself passes key acceptance (S1 has no subgroup check at verify).
    assert.equal(acceptablePublicKey(found.publicKey), true);
  }
});

// ---- cofactorless equation and mixed-order pins ----

test("honestA-mixedR: R carries a torsion component; a cofactored check accepts it, S1 refuses it", () => {
  const holder = keyHolder(seed(8));
  const publicKey = encodePoint(holder.prime);
  const message = enc("mixed-r");
  const r = 12345n;
  const rPoint = add(multiply(r, BASE), T[1]!);
  const rBytes = encodePoint(rPoint);
  const k = challenge(rBytes, publicKey, message);
  const s = (r + k * holder.scalar) % L;
  const signature = concat(rBytes, bigToLe(s, 32));
  // Non-vacuity: the COFACTORED equation [8][S]B = [8]R + [8][k]A holds.
  const lhs = multiply(8n * s, BASE);
  const rhs = add(multiply(8n, rPoint), multiply(8n * k, holder.prime));
  assert.equal(pointEquals(lhs, rhs), true, "the cofactored equation holds");
  assert.equal(verifyUngatedCofactorless(publicKey, signature, message), false, "the cofactorless equation fails");
  assert.equal(verifyStrict(message, signature, publicKey), false);
});

test("mixedA-mixedR-both: accepted at verify; the key is accepted but torsionFree is false", () => {
  const holder = keyHolder(seed(9));
  // aTorsion = T1 (order 8), rTorsion = T2 with T2 + k T1 = O solved by the message search.
  const found = findCofactorlessSignature(holder, T[1]!, T[2]!, 777n, "both");
  assert.equal(verifyUngatedCofactorless(found.publicKey, found.signature, found.message), true);
  assert.equal(verifyStrict(found.message, found.signature, found.publicKey), true, "accepted at verify");
  assert.equal(verifyStrictReference(found.publicKey, found.signature, found.message), true);
  assert.equal(acceptablePublicKey(found.publicKey), true);
  assert.equal(torsionFree(found.publicKey), false, "rejected by torsionFree");
});

test("torsion variants A0 + T_i: acceptable for every i, torsionFree only for i = 0", () => {
  for (let n = 1; n <= 3; n += 1) {
    const holder = keyHolder(seed(n + 20));
    for (let i = 0; i < 8; i += 1) {
      const variant = encodePoint(add(holder.prime, T[i]!));
      assert.equal(acceptablePublicKey(variant), true, `n=${n} i=${i}`);
      assert.equal(torsionFree(variant), i === 0, `n=${n} i=${i}`);
      assert.equal(torsionFreeReference(variant), i === 0);
    }
  }
});

test("the weak encodings are neither acceptable nor torsion free; off-curve y values are refused", () => {
  for (const e of weakEncodings()) {
    assert.equal(acceptablePublicKey(e), false, hex(e));
    assert.equal(torsionFree(e), false, hex(e));
    assert.equal(acceptableReference(e), false);
  }
  for (const e of offCurveEncodings(12)) {
    assert.equal(classifyEncoding(e).kind, "offcurve");
    assert.equal(acceptablePublicKey(e), false, `off-curve ${hex(e)}`);
    assert.equal(torsionFree(e), false);
    // An off-curve key is a rejection at verify too (the backend refuses it).
    assert.equal(verifyStrict(enc("m"), concat(encodePoint(multiply(3n, BASE)), bigToLe(5n, 32)), e), false);
  }
});

test("key acceptance and torsionFree accept honest keys and reject wrong widths and junk", () => {
  for (let i = 1; i <= 8; i += 1) {
    const k = publicKeyFromSeed(seed(i));
    assert.equal(acceptablePublicKey(k), true);
    assert.equal(torsionFree(k), true);
  }
  const k = publicKeyFromSeed(seed(1));
  for (const bad of [k.subarray(0, 31), concat(k, new Uint8Array(1)), new Uint8Array(0), new Uint8Array(33)]) {
    assert.equal(acceptablePublicKey(bad), false);
    assert.equal(torsionFree(bad), false);
  }
  for (const junk of [null, undefined, "a".repeat(32), 5, {}, []]) {
    assert.equal(acceptablePublicKey(junk as never), false);
    assert.equal(torsionFree(junk as never), false);
  }
});

test("the identity encoding and the all-zero order-4 key are refused as keys", () => {
  assert.equal(acceptablePublicKey(fromHex("01" + "00".repeat(31))), false);
  assert.equal(acceptablePublicKey(new Uint8Array(32)), false);
  assert.equal(torsionFree(new Uint8Array(32)), false);
  assert.throws(() => importPublicKey(new Uint8Array(32), "fp"), InvalidError);
  assert.throws(() => importPublicKey(fromHex("01" + "00".repeat(31)), "fp"), InvalidError);
});

// ---- the verify choke point ----

test("importPublicKey refuses weak keys with InvalidError and accepts honest keys (positive control)", () => {
  for (const weak of [...weakEncodings(), ...offCurveEncodings(3)]) {
    assert.throws(() => importPublicKey(weak, "fp"), InvalidError, hex(weak));
  }
  for (let i = 1; i <= 3; i += 1) assert.doesNotThrow(() => importPublicKey(publicKeyFromSeed(seed(i)), "fp"));
});

test("ed25519Verify (the package choke point) applies the gate to a key it imported: R small order, S + L", () => {
  const holder = keyHolder(seed(12));
  const publicKey = encodePoint(holder.prime);
  const key = importPublicKey(publicKey, "fp-choke");
  // Control: an honest signature verifies through the choke point.
  const message = enc("choke");
  const honest = signHonest(seed(12), message);
  assert.equal(ed25519Verify(message, honest, key), true);
  // R = identity (key holder built): the cofactorless equation holds, the gate refuses.
  const found = findCofactorlessSignature(holder, T[0]!, T[0]!, 0n, "choke-idr");
  assert.equal(verifyUngatedCofactorless(found.publicKey, found.signature, found.message), true);
  assert.equal(ed25519Verify(found.message, found.signature, key), false);
  // S + L: the malleable twin of an honest signature.
  const twin = concat(honest.subarray(0, 32), bigToLe(leToBig(honest.subarray(32)) + L, 32));
  assert.equal(ed25519Verify(message, twin, key), false);
  // R noncanonical (a not-small-order alias) with the honest S: the gate refuses.
  assert.equal(ed25519Verify(message, concat(NONCANONICAL_NOT_SMALL[0]!, honest.subarray(32)), key), false);
});

test("ed25519Verify refuses a key object that did not come through importPublicKey (fail closed)", () => {
  const holder = keyHolder(seed(13));
  const publicKey = encodePoint(holder.prime);
  const message = enc("foreign");
  const signature = signHonest(seed(13), message);
  const foreign = nodeCrypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKey)]), format: "der", type: "spki",
  });
  // The backend would accept this honest signature; the package refuses to verify against a key whose
  // raw bytes it never gated.
  assert.equal(nodeCrypto.verify(null, Buffer.from(message), foreign, Buffer.from(signature)), true);
  // The BackendPublicKey brand already refuses a foreign key at the type level; the cast reaches the
  // runtime check, which must refuse it too.
  assert.equal(ed25519Verify(message, signature, foreign as unknown as BackendPublicKey), false);
  const imported = importPublicKey(publicKey, "fp-foreign");
  assert.equal(ed25519Verify(message, signature, imported), true);
});

// ---- differential property: verifyStrict == the pure reference ----

test("differential: verifyStrict equals the pure BigInt reference on 400 generated inputs", () => {
  let state = 0x9e3779b97f4a7c15n;
  const next = (bound: number): number => {
    state = (state * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    return Number((state >> 33n) % BigInt(bound));
  };
  const holders = [1, 2, 3].map((n) => keyHolder(seed(40 + n)));
  const weak = weakEncodings();
  const off = offCurveEncodings(4);
  let accepted = 0;
  let gateRejected = 0;
  for (let n = 0; n < 400; n += 1) {
    const holder = holders[next(holders.length)]!;
    const message = enc(`diff-${n}`);
    // Key: honest, torsion variant, weak encoding, or off-curve.
    let publicKey: Uint8Array;
    switch (next(5)) {
      case 0: publicKey = encodePoint(holder.prime); break;
      case 1: publicKey = encodePoint(add(holder.prime, T[next(8)]!)); break;
      case 2: publicKey = weak[next(weak.length)]!; break;
      case 3: publicKey = off[next(off.length)]!; break;
      default: publicKey = encodePoint(holder.prime);
    }
    // Signature: honest, honest with R's torsion changed, identity R, weak R, S >= L.
    let signature: Uint8Array;
    const honest = signHonest(holder.seed, message);
    switch (next(6)) {
      case 0: signature = honest; break;
      case 1: signature = concat(SMALL_ORDER[next(8)]!, honest.subarray(32)); break;
      case 2: signature = concat(weak[next(weak.length)]!, honest.subarray(32)); break;
      case 3: signature = concat(honest.subarray(0, 32), bigToLe(leToBig(honest.subarray(32)) + L, 32)); break;
      case 4: signature = concat(encodePoint(add(multiply(BigInt(n + 1), BASE), T[next(8)]!)), honest.subarray(32)); break;
      default: signature = honest;
    }
    const got = verifyStrict(message, signature, publicKey);
    const want = verifyStrictReference(publicKey, signature, message);
    assert.equal(got, want, `n=${n} key=${hex(publicKey)} sig=${hex(signature)}`);
    if (got) accepted += 1;
    if (!strictGate(signature, publicKey)) gateRejected += 1;
  }
  // The input mix exercises both outcomes (the comparison is not vacuous).
  assert.ok(accepted > 20, `accepted ${accepted}`);
  assert.ok(gateRejected > 100, `gate rejected ${gateRejected}`);
});

test("expandSeed clamping puts every honest A at prime order", () => {
  // The proof that honest keys are never small-order or mixed-order: a = 8m with 2^254 <= a < 2^255.
  for (let i = 1; i <= 10; i += 1) {
    const { scalar } = expandSeed(seed(i));
    assert.ok(scalar >= 2n ** 254n && scalar < 2n ** 255n && scalar % 8n === 0n);
    assert.notEqual(scalar % L, 0n);
  }
});
