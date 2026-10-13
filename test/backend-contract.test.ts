// The crypto backend contract (src/crypto/backend.ts), held against BOTH implementations from one file:
// src/crypto/node.ts (node:crypto) and src/crypto/portable.ts (@noble). Published vectors only: FIPS
// 180-4 SHA-256 examples, RFC 8032 section 7.1 Ed25519 tests 1 to 3, and RFC 6979 appendix A.2.5 P-256
// SHA-256 signatures; plus the pins that make the portable Ed25519 check an explicit cofactorless one
// (the mixed-order R signature both noble verify modes accept, the S + L twin, the non-canonical alias
// key). The profile gates (rule S1, the P-256 range and low-S checks) are NOT a backend's job, so a
// backend must ACCEPT a high-S P-256 signature: that is what keeps the profile's gate load-bearing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as node from "../src/crypto/node.js";
import * as portable from "../src/crypto/portable.js";
import type * as Contract from "../src/crypto/backend.js";
import type { BackendPublicKey } from "../src/crypto/types.js";
import {
  BASE, L, P, add, bigToLe, challenge, classifyEncoding, concat, encodePoint, forgeUnderSmallOrderKey, keyHolder,
  leToBig, multiply, publicKeyFromSeed, signHonest, torsionPoints,
} from "./support/ed25519_reference.js";

// Both modules satisfy the contract's types exactly (a compile-time check under pnpm typecheck).
const BACKENDS: ReadonlyArray<readonly [string, typeof Contract]> = [["node", node], ["portable", portable]];

const hex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const enc = (s: string) => new TextEncoder().encode(s);

// A rejection is a false verdict or a throw at import or verify; the profile maps both to invalid.
function refuses(fn: () => boolean): boolean {
  try {
    return fn() === false;
  } catch {
    return true;
  }
}

test("both backends export exactly the contract's names, with their own BACKEND_ID", () => {
  const names = ["BACKEND_ID", "ed25519Cofactorless", "ed25519Key", "p256Key", "p256Verify", "sha256", "sha256Concat"];
  assert.deepEqual(Object.keys(node).sort(), names);
  assert.deepEqual(Object.keys(portable).sort(), names);
  assert.equal(node.BACKEND_ID, "node");
  assert.equal(portable.BACKEND_ID, "portable");
});

// ---- SHA-256 (FIPS 180-4 examples) ----

const SHA_VECTORS: ReadonlyArray<readonly [string, string]> = [
  ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
  ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"],
];

for (const [name, b] of BACKENDS) {
  test(`${name}: SHA-256 FIPS 180-4 vectors, whole and split across parts`, () => {
    for (const [message, digest] of SHA_VECTORS) {
      assert.equal(toHex(b.sha256(enc(message))), digest);
      const bytes = enc(message);
      const mid = bytes.length >> 1;
      assert.equal(toHex(b.sha256(bytes.subarray(0, mid), bytes.subarray(mid))), digest);
      assert.equal(toHex(b.sha256Concat([bytes.subarray(0, mid), new Uint8Array(0), bytes.subarray(mid)])), digest);
    }
  });

  test(`${name}: sha256Concat over the archive_chunks maximum (65,796 chunks) equals a streaming reference`, () => {
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < 65_796; i++) chunks.push(Uint8Array.of(i & 0xff, (i >> 8) & 0xff, (i >> 16) & 0xff, 0x5a));
    const reference = createHash("sha256");
    for (const c of chunks) reference.update(c);
    assert.equal(toHex(b.sha256Concat(chunks)), reference.digest("hex"));
  });
}

// ---- Ed25519 (RFC 8032 section 7.1) ----

const RFC8032: ReadonlyArray<{ name: string; publicKey: string; message: string; signature: string }> = [
  {
    name: "TEST 1", publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", message: "",
    signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    name: "TEST 2", publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", message: "72",
    signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  {
    name: "TEST 3", publicKey: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", message: "af82",
    signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
];

for (const [name, b] of BACKENDS) {
  test(`${name}: RFC 8032 section 7.1 tests 1 to 3 verify, and a one-bit change refuses`, () => {
    for (const v of RFC8032) {
      const key = b.ed25519Key(hex(v.publicKey));
      assert.equal(b.ed25519Cofactorless(key, hex(v.message), hex(v.signature)), true, v.name);
      const flipped = hex(v.signature);
      flipped[5] = flipped[5]! ^ 0x01;
      assert.ok(refuses(() => b.ed25519Cofactorless(key, hex(v.message), flipped)), `${v.name} bit flip`);
      assert.ok(refuses(() => b.ed25519Cofactorless(key, enc("other"), hex(v.signature))), `${v.name} other message`);
    }
  });

  test(`${name}: mixed-order R (cofactored-only signature) is refused: the check is cofactorless`, () => {
    const holder = keyHolder(new Uint8Array(32).fill(8));
    const publicKey = encodePoint(holder.prime);
    const message = enc("mixed-r");
    const rBytes = encodePoint(add(multiply(12345n, BASE), torsionPoints()[1]!));
    const s = (12345n + challenge(rBytes, publicKey, message) * holder.scalar) % L;
    const key = b.ed25519Key(publicKey);
    assert.ok(refuses(() => b.ed25519Cofactorless(key, message, concat(rBytes, bigToLe(s, 32)))));
    assert.equal(b.ed25519Cofactorless(key, message, signHonest(new Uint8Array(32).fill(8), message)), true, "control");
  });

  test(`${name}: the S + L twin of an honest signature is refused`, () => {
    const seed = new Uint8Array(32).fill(14);
    const publicKey = publicKeyFromSeed(seed);
    const message = enc("twin");
    const honest = signHonest(seed, message);
    const twin = concat(honest.subarray(0, 32), bigToLe(leToBig(honest.subarray(32)) + L, 32));
    const key = b.ed25519Key(publicKey);
    assert.equal(b.ed25519Cofactorless(key, message, honest), true, "control");
    assert.ok(refuses(() => b.ed25519Cofactorless(key, message, twin)));
  });

}

// Not a contract clause: refusing a non-canonical key is rule S1's job in src/ed25519.ts, which runs
// before any backend call. OpenSSL's own answer differs by version (observed while writing this suite:
// Node 22.23.1 accepts this forgery, Node 24.19.0 refuses it), which is exactly why the gate precedes
// the backend. The portable backend's strict point decode refuses it on its own, which this pin keeps.
test("portable: a forgery under the non-canonical identity alias (y = p + 1) is refused by the strict decode", () => {
  const alias = bigToLe(P + 1n, 32);
  assert.equal(classifyEncoding(alias).kind, "noncanonical");
  const forged = forgeUnderSmallOrderKey(alias, (n) => enc(`alias-${n}`));
  assert.throws(() => portable.ed25519Key(alias));
});

// ---- P-256 (RFC 6979 appendix A.2.5, SHA-256) ----

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const big = (b: Uint8Array) => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n);
const be32 = (v: bigint) => hex(v.toString(16).padStart(64, "0"));
const P256_PUBLIC = hex("04" + "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" + "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
const RFC6979: ReadonlyArray<{ message: string; r: string; s: string }> = [
  { message: "sample", r: "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", s: "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8" },
  { message: "test", r: "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367", s: "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083" },
];

for (const [name, b] of BACKENDS) {
  test(`${name}: RFC 6979 P-256 signatures verify in both s spellings; a wrong message or r refuses`, () => {
    const key = b.p256Key(P256_PUBLIC);
    for (const v of RFC6979) {
      const s = big(hex(v.s));
      const sig = concat(hex(v.r), hex(v.s));
      const twin = concat(hex(v.r), be32(N - s));
      assert.equal(b.p256Verify(key, enc(v.message), sig), true, `${v.message}`);
      assert.equal(b.p256Verify(key, enc(v.message), twin), true, `${v.message} twin: the low-S rule is the profile's, not the backend's`);
      assert.ok(refuses(() => b.p256Verify(key, enc(`${v.message}!`), sig)), `${v.message} other message`);
      const badR = concat(be32(big(hex(v.r)) ^ 1n), hex(v.s));
      assert.ok(refuses(() => b.p256Verify(key, enc(v.message), badR)), `${v.message} r changed`);
    }
  });

  test(`${name}: p256Key throws on an off-curve point and on a compressed encoding`, () => {
    const offCurve = concat(Uint8Array.of(4), be32(1n), be32(1n));
    assert.throws(() => b.p256Key(offCurve));
    assert.throws(() => b.p256Key(concat(Uint8Array.of(2), P256_PUBLIC.subarray(1, 33))));
  });
}

// ---- type safety: raw bytes cannot stand in for an imported key (compile-time probes) ----

export function typeProbes(raw: Uint8Array, key: BackendPublicKey): void {
  // @ts-expect-error a raw Uint8Array is not a BackendPublicKey
  node.ed25519Cofactorless(raw, raw, raw);
  // @ts-expect-error a raw Uint8Array is not a BackendPublicKey
  portable.p256Verify(raw, raw, raw);
  node.p256Verify(key, raw, raw);
}
