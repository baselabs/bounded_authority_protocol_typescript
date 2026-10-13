// The node:crypto backend (contract: ./backend.ts). These are the bodies that lived in ../ed25519.ts and
// ../es256.ts through 0.6.0, moved without a behavior change. This is the only module in the package
// that imports node:crypto (test/decoupling.test.ts) or uses Buffer.
import { createHash, createPublicKey, verify as verifySig, type KeyObject } from "node:crypto";
import { base64urlEncode } from "../base64url.js";
import { utf8Str } from "../json.js";
import type { BackendId, BackendPublicKey } from "./types.js";

export const BACKEND_ID: BackendId = "node";

const asKeyObject = (key: BackendPublicKey): KeyObject => key as unknown as KeyObject;
const asBackendKey = (key: KeyObject): BackendPublicKey => key as unknown as BackendPublicKey;

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest());
}

export function sha256Concat(parts: readonly Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(Buffer.from(p));
  return new Uint8Array(h.digest());
}

// The SPKI DER for an Ed25519 public key: SEQUENCE { AlgId, BIT STRING <32 raw bytes> }. This matches
// the reference runner's SPKI_ED25519_PREFIX (corpus_independent.mjs:27).
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function ed25519Key(raw32: Uint8Array): BackendPublicKey {
  return asBackendKey(createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw32)]), format: "der", type: "spki" }));
}

// OpenSSL's Ed25519 verify computes the cofactorless equation (RFC 8032 section 5.1.7 without the
// cofactor), which is what rule S1 requires.
export function ed25519Cofactorless(key: BackendPublicKey, message: Uint8Array, sig64: Uint8Array): boolean {
  return verifySig(undefined, Buffer.from(message), asKeyObject(key), Buffer.from(sig64));
}

// Imported through the key's EC JWK spelling; OpenSSL validates the point again (defense in depth).
export function p256Key(rawSec1_65: Uint8Array): BackendPublicKey {
  const jwk = {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: utf8Str(base64urlEncode(rawSec1_65.subarray(1, 33))),
    y: utf8Str(base64urlEncode(rawSec1_65.subarray(33, 65))),
  };
  return asBackendKey(createPublicKey({ key: jwk, format: "jwk" }));
}

// The raw P1363 r || s form through dsaEncoding "ieee-p1363"; DER is never a wire spelling.
export function p256Verify(key: BackendPublicKey, message: Uint8Array, sig64: Uint8Array): boolean {
  return verifySig("sha256", Buffer.from(message), { key: asKeyObject(key), dsaEncoding: "ieee-p1363" }, Buffer.from(sig64));
}
