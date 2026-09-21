import { createPublicKey, verify as verifySig } from "node:crypto";
import { assert, fail } from "./error.js";
import { base64urlEncode } from "./base64url.js";
import { utf8Str } from "./json.js";

// ES256 verification via node:crypto — the ECDSA-over-P-256-with-SHA-256 suite of contract-major 3
// (spec/bap-v3.md §3, RFC 7518 §3.4). The suite's raw public-key form is the 65-byte uncompressed
// SEC1 point 0x04||x||y (REQ3-KEY-uncompressed-sec1); compressed points are invalid. The decoded
// coordinates MUST each be less than the field prime p and MUST form a point on the curve
// (REQ3-KEY-point-on-curve) — pure arithmetic HERE, before the crypto backend, whose off-curve
// behavior is backend-specific and never load-bearing. The wire signature is the RFC 7518 §3.4 raw
// form — exactly 64 bytes, r||s, two fixed-width 32-byte unsigned big-endian integers
// (REQ3-SIGNING-raw-rs) — and the verifier rejects r=0/s=0, r≥n, s≥n, and the HIGH-S half
// s > (n−1)/2 (REQ3-SIGNING-range, REQ3-SIGNING-low-s) as invalid encodings BEFORE any backend
// call. Node's OpenSSL backend ACCEPTS the malleable high-S counterpart (for a valid (r,s),
// (r, n−s) also satisfies the verification equation), so the low-S profile gate is load-bearing:
// remove it and a third party's re-spelling of an observed signature verifies. A backend rejection
// OR exception returns exactly InvalidError (REQ3-SIGNING-backend-reject).

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

// The on-curve equation y² = x³ − 3x + b mod p (short Weierstrass, a = −3 for P-256).
export function pointOnCurve(x: bigint, y: bigint): boolean {
  return (y * y - (x * x * x - 3n * x + B)) % P === 0n;
}

// Full pure-arithmetic validation of the suite's raw public-key form: exactly 65 bytes, the 0x04
// uncompressed SEC1 prefix, both coordinates < p, and the point on the curve. Compressed (0x02/0x03)
// and hybrid forms fail the prefix gate. Applied to every EC key entering the profile —
// caller-supplied issuer and historical keys and the decoded proof-JWK point — before any backend call.
export function validateEcPublicKey(rawKey: Uint8Array): void {
  assert(rawKey.length === 65, "es256: public key width must be 65 bytes");
  if (rawKey[0] !== 0x04) fail("es256: uncompressed SEC1 form required");
  const x = bytesToBigInt(rawKey.subarray(1, 33));
  const y = bytesToBigInt(rawKey.subarray(33, 65));
  if (x >= P || y >= P) fail("es256: coordinate not less than the field prime");
  if (!pointOnCurve(x, y)) fail("es256: point not on the curve");
}

// Import a validated 65-byte SEC1 public key as a node:crypto KeyObject via its EC JWK spelling,
// recording the fingerprint for the census. Returns the KeyObject. Throws InvalidError on a
// malformed key. Callers run validateEcPublicKey first (the profile's arithmetic gates precede the
// backend); this import validates again — defense in depth, never load-bearing.
export function importEcPublicKey(rawKey: Uint8Array, fingerprint: string): ReturnType<typeof createPublicKey> {
  assert(rawKey.length === 65, "es256: public key must be 65 bytes");
  const jwk = {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: utf8Str(base64urlEncode(rawKey.subarray(1, 33))),
    y: utf8Str(base64urlEncode(rawKey.subarray(33, 65))),
  };
  try {
    const key = createPublicKey({ key: jwk, format: "jwk" });
    importedFingerprints.add(fingerprint);
    return key;
  } catch {
    fail("es256: invalid public key");
  }
}

// Verify an ES256 signature over the exact signing input. The 64-byte r||s integer-range and
// low-S gates run BEFORE the backend (REQ3-BOUNDS-ordering: signature width and integer-range
// checks, then the backend verification over the exact RFC 7515 signing input). DER is never a
// wire spelling — the backend consumes the same raw P1363 form through dsaEncoding: "ieee-p1363".
// Backend exceptions map to InvalidError (REQ3-SIGNING-backend-reject).
export function es256Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: ReturnType<typeof createPublicKey>,
): boolean {
  assert(signature.length === 64, "es256: signature must be 64 bytes");
  const r = bytesToBigInt(signature.subarray(0, 32));
  const s = bytesToBigInt(signature.subarray(32, 64));
  if (r === 0n || r >= N) fail("es256: r out of range");
  if (s === 0n || s >= N) fail("es256: s out of range");
  if (s > HALF_N) fail("es256: high-s form (low-s required)");
  try {
    return verifySig("sha256", Buffer.from(message), { key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(signature));
  } catch {
    fail("es256: backend rejected");
  }
}
