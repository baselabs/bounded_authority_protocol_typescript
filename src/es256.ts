import { p256Key, p256Verify } from "#crypto";
import type { BackendPublicKey } from "./crypto/types.js";
import { assert, fail } from "./error.js";

// ES256 verification uses the selected crypto backend under spec/bap-v3.md and RFC 7518 section
// 3.4. Before calling it, validate the 65-byte uncompressed SEC1 point, coordinate ranges and
// curve equation. Require a 64-byte raw big-endian r || s signature with 0 < r < n and 0 < s <=
// floor(n/2). Both backends can verify high-S counterparts, so the explicit low-S gate prevents
// malleability. Backend rejection and exceptions map to InvalidError.

// Census tracking: every key imported via importEcPublicKey is recorded here, so the conformance
// runner can assert the verify-import census leg (every key a valid verification case declares was
// actually imported at the ES256 verify boundary).
const importedFingerprints = new Set<string>();
export function _importedFingerprints(): Set<string> {
  return new Set(importedFingerprints);
}
export function _resetCensus(): void {
  importedFingerprints.clear();
}

// NIST P-256 (secp256r1) domain parameters (SEC 2 §2.4.2), as BigInt.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn; // field prime
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n; // group order
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn; // curve b
// The low-S ceiling: s ≤ (n−1)/2 exactly (n is odd, so this is an integer).
const HALF_N = (N - 1n) / 2n;

// Fixed-width big-endian unsigned integer decoding (RFC 7518 §6.2.1.2/.3 spelling).
function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const byte of bytes) v = (v << 8n) | BigInt(byte);
  return v;
}

// Every producer requires a 64-byte raw r || s with 0 < r < n and 0 < s <= floor(n/2).
// Producers refuse noncanonical signatures without normalizing them. es256VerifyStrict shares
// this rule; es256Verify keeps inline gates whose diagnostic messages are pinned by the
// nonvacuity tests. This helper is internal. See spec/bap-v3.md section 3.2.
export function canonicalSignature(signature: Uint8Array): boolean {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  const r = bytesToBigInt(signature.subarray(0, 32));
  const s = bytesToBigInt(signature.subarray(32, 64));
  return r > 0n && r < N && s > 0n && s <= HALF_N;
}

// The on-curve equation y² = x³ − 3x + b mod p (short Weierstrass, a = −3 for P-256).
export function pointOnCurve(x: bigint, y: bigint): boolean {
  return (y * y - (x * x * x - 3n * x + B)) % P === 0n;
}

// Validate every P-256 key with pure arithmetic before backend import: exactly 65 bytes, prefix
// 0x04, coordinates below p and the curve equation satisfied. Compressed and hybrid points
// reject. This applies to caller-supplied keys and decoded proof JWKs.
export function validateEcPublicKey(rawKey: Uint8Array): void {
  assert(rawKey.length === 65, "es256: public key width must be 65 bytes");
  if (rawKey[0] !== 0x04) fail("es256: uncompressed SEC1 form required");
  const x = bytesToBigInt(rawKey.subarray(1, 33));
  const y = bytesToBigInt(rawKey.subarray(33, 65));
  if (x >= P || y >= P) fail("es256: coordinate not less than the field prime");
  if (!pointOnCurve(x, y)) fail("es256: point not on the curve");
}

// Import a previously validated SEC1 key into the backend, recording its census fingerprint
// only after success. Return the backend key or throw InvalidError. The pure arithmetic gates
// precede this import; backend validation adds an independent check.
export function importEcPublicKey(rawKey: Uint8Array, fingerprint: string): BackendPublicKey {
  assert(rawKey.length === 65, "es256: public key must be 65 bytes");
  try {
    const key = p256Key(rawKey);
    importedFingerprints.add(fingerprint);
    return key;
  } catch {
    fail("es256: invalid public key");
  }
}

// Verify the exact RFC 7515 signing input. Check raw 64-byte r || s width, integer ranges and
// low-S before the backend. The backend consumes raw r || s; DER is invalid on the wire.
// Backend exceptions map to InvalidError.
export function es256Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: BackendPublicKey,
): boolean {
  assert(signature.length === 64, "es256: signature must be 64 bytes");
  const r = bytesToBigInt(signature.subarray(0, 32));
  const s = bytesToBigInt(signature.subarray(32, 64));
  if (r === 0n || r >= N) fail("es256: r out of range");
  if (s === 0n || s >= N) fail("es256: s out of range");
  if (s > HALF_N) fail("es256: high-s form (low-s required)");
  try {
    return p256Verify(publicKey, message, signature);
  } catch {
    fail("es256: backend rejected");
  }
}

/**
 * Verifies an ES256 signature: 65-byte uncompressed on-curve P-256 key, raw 64-byte `r || s` with
 * `0 < r < n` and `0 < s <= (n-1)/2`, then ECDSA P-256 / SHA-256. Returns `false` for any invalid input; never
 * throws.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns `true` when the strict key/scalar encodings and ECDSA P-256/SHA-256 equation verify the exact message; `false` otherwise. Never throws.
 * @category Canonical bytes
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * assert.equal(api.es256VerifyStrict(new Uint8Array(), new Uint8Array(64), new Uint8Array(65)), false);
 * ```
 */
export function es256VerifyStrict(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  // Total: an exotic input whose typed-array getters throw is refused, never thrown past the caller.
  try {
    void message.length;
    if (!(message instanceof Uint8Array) || !(signature instanceof Uint8Array) || !(publicKey instanceof Uint8Array)) return false;
    if (signature.length !== 64 || publicKey.length !== 65) return false;
    try {
      validateEcPublicKey(publicKey);
    } catch {
      return false;
    }
    if (!canonicalSignature(signature)) return false; // the rule's single spelling (see above)
    try {
      return p256Verify(p256Key(publicKey), message, signature);
    } catch {
      return false;
    }
  } catch {
    return false;
  }
}
