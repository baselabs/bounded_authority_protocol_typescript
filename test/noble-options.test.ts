// The portable backend's P-256 verify passes { lowS: false } to @noble/curves so that the profile's own
// low-S gate (src/es256.ts) stays the only one; with noble's default (lowS: true) the backend would be a
// second, hidden gate and the permissiveness mutation "remove the profile low-S gate" would stay green
// under the portable backend. This test proves noble honors exactly that option name: the default
// rejects the high-S twin of a valid signature and { lowS: false } accepts it. The vector is RFC 6979
// appendix A.2.5 (P-256, SHA-256, message "sample"), whose s is in the high half.
import { test } from "node:test";
import assert from "node:assert/strict";
import { p256 } from "@noble/curves/nist.js";

const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const big = (b: Uint8Array) => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n);
const be32 = (v: bigint) => hex(v.toString(16).padStart(64, "0"));

const PUBLIC = hex("04" + "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" + "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
const MESSAGE = new TextEncoder().encode("sample");
const R = hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
const S_HIGH = hex("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");

const high = new Uint8Array([...R, ...S_HIGH]);
const low = new Uint8Array([...R, ...be32(N - big(S_HIGH))]);

test("the RFC 6979 vector's s is in the high half, and its twin is low-S", () => {
  assert.ok(big(S_HIGH) > (N - 1n) / 2n);
  assert.ok(big(low.subarray(32)) <= (N - 1n) / 2n);
});

test("noble p256.verify: the low-S twin verifies under the default options", () => {
  assert.equal(p256.verify(low, MESSAGE, PUBLIC), true);
});

test("noble p256.verify: the default (lowS: true) rejects the high-S spelling", () => {
  assert.equal(p256.verify(high, MESSAGE, PUBLIC), false);
});

test("noble p256.verify: { lowS: false } accepts the high-S spelling (the option name is honored)", () => {
  assert.equal(p256.verify(high, MESSAGE, PUBLIC, { lowS: false, prehash: true, format: "compact" }), true);
});

test("noble p256.verify: { lowS: false } still rejects a wrong message", () => {
  assert.equal(p256.verify(high, new TextEncoder().encode("samplf"), PUBLIC, { lowS: false, prehash: true, format: "compact" }), false);
});
