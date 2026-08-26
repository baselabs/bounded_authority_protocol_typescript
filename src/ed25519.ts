import { createPublicKey, verify as verifySig } from "node:crypto";
import { assert, fail } from "./error.js";

// Ed25519 verification via node:crypto (the crypto import boundary the two-boundary census tracks).
// Per spec/bap-v1.md § Signing and digest inputs + RFC 8032. The verifier validates the fixed 32-byte
// public-key and 64-byte signature encodings, then delegates Ed25519 verification to the backend. A
// backend rejection or exception returns exactly Invalid (REQ1-SIGNING-backend-reject).

// Census tracking: every key imported via importPublicKey is recorded here, so the conformance runner
// can assert discovery == verify-import == index public_key_fingerprints (both directions).
const importedFingerprints = new Set<string>();
export function _importedFingerprints(): Set<string> {
  return new Set(importedFingerprints);
}
export function _resetCensus(): void {
  importedFingerprints.clear();
}

// Import a raw 32-byte Ed25519 public key as a node:crypto KeyObject, recording the fingerprint for the
// census. Returns the KeyObject. Throws InvalidError on a malformed key.
export function importPublicKey(rawKey: Uint8Array, fingerprint: string): ReturnType<typeof createPublicKey> {
  assert(rawKey.length === 32, "ed25519: public key must be 32 bytes");
  // Build the SPKI DER for an Ed25519 public key: SEQUENCE { AlgId, BIT STRING <32 raw bytes> }.
  // This matches the runner's SPKI_ED25519_PREFIX (corpus_independent.mjs:27).
  const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([SPKI_PREFIX, Buffer.from(rawKey)]);
  try {
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    importedFingerprints.add(fingerprint);
    return key;
  } catch {
    fail("ed25519: invalid public key");
  }
}

// Verify an Ed25519 signature. Returns true if the signature is valid, false otherwise. Maps backend
// exceptions to InvalidError (REQ1-SIGNING-backend-reject).
export function ed25519Verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: ReturnType<typeof createPublicKey>,
): boolean {
  assert(signature.length === 64, "ed25519: signature must be 64 bytes");
  try {
    return verifySig(undefined, Buffer.from(message), publicKey, Buffer.from(signature));
  } catch {
    fail("ed25519: backend rejected");
  }
}

// SHA-256 helper (FIPS 180-4), used by thumbprints + digests.
import { createHash } from "node:crypto";
export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest());
}

// SHA-256 over an ARRAY of chunks (no spread). Used by archive-verify, which hashes a caller-supplied
// chunk list that may hold up to archive_chunks (65796) entries — beyond V8's ~65534 call-argument
// ceiling, so the chunk list MUST be fed as an array, not spread into sha256(...chunks).
export function sha256Concat(parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest());
}
