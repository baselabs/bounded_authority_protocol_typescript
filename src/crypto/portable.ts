// The portable backend (contract: ./backend.ts): pure JavaScript over three exactly pinned, audited
// @noble packages, verification and hashing only. Selected for browsers, Deno, Bun and workers, and on
// Node under --conditions=bap-portable. It never uses WebCrypto, so every call is synchronous and the
// package API does not change shape.
//
// Ed25519 is an explicit COFACTORLESS check, encode([S]B - [k]A) == R compared byte for byte, moved
// from the 0.6.0 playground shim (web/shim/node-crypto.ts). Rule S1 mandates the cofactorless equation,
// and noble's own verify is cofactored in BOTH of its modes (zip215 true and false accept signatures
// with a torsion component in R or A that the cofactor multiplication cancels), so neither can stand in
// for it: test/backend-contract.test.ts and test/portable-nonvacuity.test.ts pin that reason. The
// strict RFC 8032 section 5.1.3 decode (zip215 = false) refuses a non-canonical or off-curve A.
//
// P-256 passes { lowS: false } so that the profile's own low-S gate (src/es256.ts) is the only one; with
// noble's default the backend would be a second, hidden gate, and removing the profile gate would not
// turn its mutation test red (test/noble-options.test.ts proves the option name is honored).
import { Point } from "@noble/ed25519";
import { p256 } from "@noble/curves/nist.js";
import { sha256 as nobleSha256, sha512 } from "@noble/hashes/sha2.js";
import type { BackendId, BackendPublicKey } from "./types.js";

export const BACKEND_ID: BackendId = "portable";

interface Ed25519Key { readonly kind: "ed25519"; readonly raw: Uint8Array; readonly point: Point }
interface P256Key { readonly kind: "p256"; readonly raw: Uint8Array }

const asBackendKey = (key: Ed25519Key | P256Key): BackendPublicKey => Object.freeze(key) as unknown as BackendPublicKey;
function keyOf<K extends "ed25519" | "p256">(key: BackendPublicKey, kind: K): K extends "ed25519" ? Ed25519Key : P256Key {
  const k = key as unknown as Ed25519Key | P256Key;
  if (k === null || typeof k !== "object" || k.kind !== kind) throw new TypeError("portable backend: wrong key kind");
  return k as K extends "ed25519" ? Ed25519Key : P256Key;
}

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = nobleSha256.create();
  for (const p of parts) h.update(p);
  return h.digest();
}

export function sha256Concat(parts: readonly Uint8Array[]): Uint8Array {
  const h = nobleSha256.create();
  for (const p of parts) h.update(p);
  return h.digest();
}

// ---- Ed25519 ----

// The base-point order L = 2^252 + 27742317777372353535851937790883648493.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const littleEndian = (bytes: Uint8Array): bigint => {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
};

export function ed25519Key(raw32: Uint8Array): BackendPublicKey {
  if (!(raw32 instanceof Uint8Array) || raw32.length !== 32) throw new TypeError("portable backend: Ed25519 key width");
  const raw = new Uint8Array(raw32);
  return asBackendKey({ kind: "ed25519", raw, point: Point.fromBytes(raw, false) });
}

export function ed25519Cofactorless(key: BackendPublicKey, message: Uint8Array, sig64: Uint8Array): boolean {
  const { raw: publicKey, point: a } = keyOf(key, "ed25519");
  if (sig64.length !== 64) return false;
  const rBytes = sig64.subarray(0, 32);
  const s = littleEndian(sig64.subarray(32));
  // noble's multiply also range-asserts a scalar to 1..L-1 (and throws, a rejection), so this check is
  // redundant with it; it stays so that rule S1 does not depend on that incidental assertion. The S + L
  // twin is pinned in test/backend-contract.test.ts.
  if (s >= L) return false;
  const challenge = new Uint8Array(rBytes.length + publicKey.length + message.length);
  challenge.set(rBytes, 0);
  challenge.set(publicKey, rBytes.length);
  challenge.set(message, rBytes.length + publicKey.length);
  const k = littleEndian(sha512(challenge)) % L;
  const sb = s === 0n ? Point.ZERO : Point.BASE.multiply(s);
  const ka = k === 0n ? Point.ZERO : a.multiply(k, false);
  const lhs = sb.subtract(ka).toBytes();
  if (lhs.length !== rBytes.length) return false;
  for (let i = 0; i < lhs.length; i++) if (lhs[i] !== rBytes[i]) return false;
  return true;
}

// ---- P-256 ----

export function p256Key(rawSec1_65: Uint8Array): BackendPublicKey {
  if (!(rawSec1_65 instanceof Uint8Array) || rawSec1_65.length !== 65 || rawSec1_65[0] !== 0x04) {
    throw new TypeError("portable backend: uncompressed SEC1 P-256 key required");
  }
  const raw = new Uint8Array(rawSec1_65);
  p256.Point.fromBytes(raw).assertValidity();
  return asBackendKey({ kind: "p256", raw });
}

export function p256Verify(key: BackendPublicKey, message: Uint8Array, sig64: Uint8Array): boolean {
  const { raw } = keyOf(key, "p256");
  return p256.verify(sig64, message, raw, { lowS: false, prehash: true, format: "compact" });
}
