import { ed25519Cofactorless, ed25519Key, sha256 as backendSha256, sha256Concat as backendSha256Concat } from "#crypto";
import type { BackendPublicKey } from "./crypto/types.js";
import { assert, fail } from "./error.js";

// Ed25519 verification through the crypto backend ("#crypto": node:crypto on Node, @noble elsewhere;
// src/crypto/backend.ts), the crypto import boundary the two-boundary census tracks.
// Per spec/bap-v1.md § Signing and digest inputs + RFC 8032. The verifier validates the fixed 32-byte
// public-key and 64-byte signature encodings, applies rule S1 (below), then delegates the cofactorless
// equation to the backend. A backend rejection or exception returns exactly Invalid
// (REQ1-SIGNING-backend-reject).
//
// Rule S1 (strict Ed25519), mirroring BoundedAuthorityProtocol.Ed25519.verify_strict/3. A signature
// R || S over a message under a public key A is accepted only if, checked in this order BEFORE any
// backend call:
//   1. the key is exactly 32 bytes and the signature exactly 64 bytes;
//   2. A and R are canonical encodings (the encoded y is below p = 2^255 - 19, and the sign bit is clear
//      whenever x = 0; RFC 8032 section 5.1.3);
//   3. neither A nor R is one of the eight small-order encodings (one shared table serves both);
//   4. S < L, the prime order of the base point (RFC 8032 section 5.1.7);
//   5. the cofactorless equation encode([S]B - [k]A) == R holds byte for byte (the backend computes it).
// Curve membership of A at verify is left to the backend, which refuses an off-curve key. There is no
// subgroup check at verify: a key with a small-torsion component passes S1 when its signature satisfies
// the cofactorless equation. Hosts close that gap once per key with torsionFree at enrollment, at trust
// install and before any deny-list or revocation comparison; it never runs on the verify path.
//
// This is the single choke point: every Ed25519 verification in the package reaches the backend only
// through ed25519Verify (or verifyStrict), and every key reaches the backend only through importPublicKey.

// ---- field and group constants (RFC 8032 section 5.1) ----

// The field prime p = 2^255 - 19; the base-point order L = 2^252 + 27742317777372353535851937790883648493;
// the curve constant d = -121665/121666 mod p; and sqrt(-1) = 2^((p - 1) / 4) mod p.
const P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;
const L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;
const D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n;
const SQRT_M1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
const SIGN_BIT = 1n << 255n;
const P_MINUS_ONE = P - 1n;

// The eight small-order encodings (the points of E[8]), canonical form. One table serves both the key A
// and the signature's R.
const SMALL_ORDER: readonly string[] = [
  "0100000000000000000000000000000000000000000000000000000000000000", // order 1 (identity)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
  "0000000000000000000000000000000000000000000000000000000000000000", // order 4
  "0000000000000000000000000000000000000000000000000000000000000080", // order 4
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
];
const SMALL_ORDER_BYTES: readonly Uint8Array[] = SMALL_ORDER.map(
  (h) => Uint8Array.from(h.match(/../g)!.map((byte) => parseInt(byte, 16))),
);

const isBytes = (v: unknown, length: number): v is Uint8Array => v instanceof Uint8Array && v.length === length;

function littleEndian(bytes: Uint8Array, from: number, to: number): bigint {
  let v = 0n;
  for (let i = to - 1; i >= from; i--) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

function isSmallOrder(encoding: Uint8Array): boolean {
  for (const entry of SMALL_ORDER_BYTES) {
    let same = true;
    for (let i = 0; i < 32; i++) {
      if (encoding[i] !== entry[i]) { same = false; break; }
    }
    if (same) return true;
  }
  return false;
}

// Canonical: y < p, and the sign bit is clear on the two x = 0 points (y = 1 and y = p - 1).
function isCanonical(encoding: Uint8Array): boolean {
  const v = littleEndian(encoding, 0, 32);
  const y = v & (SIGN_BIT - 1n);
  if (y >= P) return false;
  return v < SIGN_BIT || (y !== 1n && y !== P_MINUS_ONE);
}

// The byte-level part of rule S1 (clauses 2 to 4), separate from the backend so each clause stays
// testable on its own: a cofactorless backend already refuses a non-canonical R and S >= L, so only a
// direct test of the gate can show those two clauses are present. Internal; not part of the package API.
export function strictGate(signature: Uint8Array, publicKey: Uint8Array): boolean {
  if (!isBytes(signature, 64) || !isBytes(publicKey, 32)) return false;
  const r = signature.subarray(0, 32);
  return (
    isCanonical(publicKey) && isCanonical(r) &&
    !isSmallOrder(publicKey) && !isSmallOrder(r) &&
    littleEndian(signature, 32, 64) < L
  );
}

// ---- pure BigInt Edwards arithmetic (acceptablePublicKey, torsionFree) ----

type Point = readonly [bigint, bigint, bigint, bigint]; // extended twisted Edwards (X:Y:Z:T), a = -1

const field = (v: bigint): bigint => {
  const r = v % P;
  return r < 0n ? r + P : r;
};

function square(value: bigint, count: number): bigint {
  let v = value;
  for (let i = 0; i < count; i++) v = field(v * v);
  return v;
}

// z^((p - 5) / 8) = z^(2^252 - 3) by a fixed addition chain: 251 squarings and 11 multiplications.
function powP58(z: bigint): bigint {
  const z2 = field(z * z);
  const z9 = field(square(z2, 2) * z);
  const z11 = field(z9 * z2);
  const z5 = field(field(z11 * z11) * z9);
  const z10 = field(square(z5, 5) * z5);
  const z20 = field(square(z10, 10) * z10);
  const z40 = field(square(z20, 20) * z20);
  const z50 = field(square(z40, 10) * z10);
  const z100 = field(square(z50, 50) * z50);
  const z200 = field(square(z100, 100) * z100);
  const z250 = field(square(z200, 50) * z50);
  return field(square(z250, 2) * z);
}

// RFC 8032 section 5.1.3 decoding of a canonical encoding: x^2 = (y^2 - 1) / (d y^2 + 1), with the
// candidate root x = u v^3 (u v^7)^((p - 5) / 8).
function decodePoint(encoding: Uint8Array): Point | null {
  const v = littleEndian(encoding, 0, 32);
  const y = v & (SIGN_BIT - 1n);
  const u = field(y * y - 1n);
  const w = field(D * y * y + 1n);
  const w3 = field(field(w * w) * w);
  const w7 = field(field(w3 * w3) * w);
  const candidate = field(u * w3 * powP58(field(u * w7)));
  let x: bigint;
  if (field(w * candidate * candidate - u) === 0n) x = candidate;
  else if (field(w * candidate * candidate + u) === 0n) x = field(candidate * SQRT_M1);
  else return null;
  const signed = v >= SIGN_BIT;
  const odd = (x & 1n) === 1n;
  if (odd !== signed) x = field(-x);
  return [x, y, 1n, field(x * y)];
}

function addPoints(p1: Point, p2: Point): Point {
  const [x1, y1, z1, t1] = p1;
  const [x2, y2, z2, t2] = p2;
  const a = field((y1 - x1) * (y2 - x2));
  const b = field((y1 + x1) * (y2 + x2));
  const c = field(2n * D * t1 * t2);
  const d = field(2n * z1 * z2);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return [field(e * f), field(g * h), field(f * g), field(e * h)];
}

function doublePoint(p: Point): Point {
  const [x1, y1, z1] = p;
  const a = field(x1 * x1);
  const b = field(y1 * y1);
  const c = field(2n * z1 * z1);
  const h = a + b;
  const e = field(h - (x1 + y1) * (x1 + y1));
  const g = a - b;
  const f = c + g;
  return [field(e * f), field(g * h), field(f * g), field(e * h)];
}

function multiplyPoint(scalar: bigint, point: Point): Point {
  let acc: Point = [0n, 1n, 1n, 0n];
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if ((k & 1n) === 1n) acc = addPoints(acc, addend);
    addend = doublePoint(addend);
    k >>= 1n;
  }
  return acc;
}

const isIdentity = ([x, y, z]: Point): boolean => x === 0n && y === z;

// ---- public strict API (names and semantics mirror BoundedAuthorityProtocol.Ed25519) ----

// Returns whether a raw 32-byte Ed25519 public key may enter a verification input: canonical, not one
// of the eight small-order encodings, and on the curve (the RFC 8032 section 5.1.3 decode succeeds).
// Any other input, including a non-32-byte or non-byte input, returns false.
export function acceptablePublicKey(publicKey: Uint8Array): boolean {
  if (!isBytes(publicKey, 32)) return false;
  return isCanonical(publicKey) && !isSmallOrder(publicKey) && decodePoint(publicKey) !== null;
}

// Returns whether a raw 32-byte public key is acceptable and torsion free ([L]A = O). A host calls this
// at key enrollment, at trust install and before any deny-list or revocation comparison. It runs one
// full scalar multiplication in pure BigInt arithmetic, so it never belongs on the per-signature
// verification path. A canonical, torsion-free key has exactly one encoding per secret, so key equality
// is identity equality.
export function torsionFree(publicKey: Uint8Array): boolean {
  if (!isBytes(publicKey, 32)) return false;
  if (!isCanonical(publicKey) || isSmallOrder(publicKey)) return false;
  const point = decodePoint(publicKey);
  return point !== null && isIdentity(multiplyPoint(L, point));
}

// Verifies an Ed25519 signature under rule S1. Returns true only for a 64-byte signature and a 32-byte
// key that pass the canonical, small-order and scalar-range checks and then the backend's cofactorless
// equation. Any other input, including wrong-size or non-byte input, returns false; it never throws.
export function verifyStrict(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  if (!(message instanceof Uint8Array) || !isBytes(signature, 64) || !isBytes(publicKey, 32)) return false;
  if (!strictGate(signature, publicKey)) return false;
  try {
    return ed25519Cofactorless(ed25519Key(publicKey), message, signature);
  } catch {
    return false;
  }
}

// ---- the backend boundary ----

// Census tracking: every key imported via importPublicKey is recorded here, so the conformance runner
// can assert discovery == verify-import == index public_key_fingerprints (both directions).
const importedFingerprints = new Set<string>();
export function _importedFingerprints(): Set<string> {
  return new Set(importedFingerprints);
}
export function _resetCensus(): void {
  importedFingerprints.clear();
}

// The raw 32-byte key behind each imported key object. ed25519Verify reads the key's bytes here to
// apply the strict gate, so a key object that did not come through importPublicKey is never verified
// against (fail closed). A WeakMap keeps this independent of the backend's key-object shape (each
// backend returns its own object).
const RAW_KEYS = new WeakMap<object, Uint8Array>();

// Import a raw 32-byte Ed25519 public key into the backend, recording the fingerprint for the census
// only after the import succeeds. Returns the backend key. Throws InvalidError on a malformed key or a
// key that fails acceptablePublicKey (non-canonical, small-order, or off the curve).
export function importPublicKey(rawKey: Uint8Array, fingerprint: string): BackendPublicKey {
  assert(rawKey.length === 32, "ed25519: public key must be 32 bytes");
  assert(acceptablePublicKey(rawKey), "ed25519: public key not acceptable");
  try {
    const key = ed25519Key(rawKey);
    RAW_KEYS.set(key, new Uint8Array(rawKey));
    importedFingerprints.add(fingerprint);
    return key;
  } catch {
    fail("ed25519: invalid public key");
  }
}

// Verify an Ed25519 signature under rule S1. Returns true if the signature is valid, false otherwise.
// Maps backend exceptions to InvalidError (REQ1-SIGNING-backend-reject). The strict gate runs before
// the backend; a key object that was not produced by importPublicKey never verifies.
export function ed25519Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: BackendPublicKey,
): boolean {
  assert(signature.length === 64, "ed25519: signature must be 64 bytes");
  const raw = RAW_KEYS.get(publicKey);
  if (raw === undefined || !strictGate(signature, raw)) return false;
  try {
    return ed25519Cofactorless(publicKey, message, signature);
  } catch {
    fail("ed25519: backend rejected");
  }
}

// SHA-256 helper (FIPS 180-4), used by thumbprints + digests. The backend computes it.
export function sha256(...parts: Uint8Array[]): Uint8Array {
  return backendSha256(...parts);
}

// SHA-256 over an ARRAY of chunks (no spread). Used by archive-verify, which hashes a caller-supplied
// chunk list that may hold up to archive_chunks (65796) entries — beyond V8's ~65534 call-argument
// ceiling, so the chunk list MUST be fed as an array, not spread into sha256(...chunks).
export function sha256Concat(parts: Uint8Array[]): Uint8Array {
  return backendSha256Concat(parts);
}
