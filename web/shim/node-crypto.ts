// The browser shim for the node:crypto surface this bench bundle exercises
// (verified by grep over both dist trees): createPublicKey, verify (Ed25519),
// createHash ("sha256"). Implemented over @noble (synchronous — checkEnvelope is
// a fully synchronous pipeline, so the shim must be too). Nothing here implements
// cryptography of its own; it only adapts shapes.
//
// The v3 ES256 surface (createPublicKey with an EC JWK, verify with
// dsaEncoding "ieee-p1363") is NOT shimmed: the bench imports only the v1
// façade from the package root, and esbuild's tree-shaking drops the unused
// v3 namespace from the bundle (verified by grep over site-dist/app.js). A
// bench page that starts importing `v3` must extend this shim first.
import { Point, hashes } from "@noble/ed25519";
import { Buffer } from "buffer";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

// noble/ed25519 3.x ships its SHA-512 as an injectable (tree-shakeable)
// dependency, unset by default — sign/verify/keygen throw until it is wired.
// Both the sync and async paths share the registry.
hashes.sha512 = sha512;

export interface ShimKeyObject {
  readonly kind: "shim-ed25519-public";
  readonly raw: Uint8Array;
}

const isUint8 = (v: unknown): v is Uint8Array => v instanceof Uint8Array;

/** Accepts both construction shapes the packages use: JWK {kty,crv,x} and SPKI DER. */
export function createPublicKey(opts: {
  key: { kty?: string; crv?: string; x?: string } | Uint8Array;
  format?: string;
  type?: string;
}): ShimKeyObject {
  const k = opts.key;
  if (isUint8(k)) {
    // SPKI DER for Ed25519 is 44 bytes: 12-byte header + 32-byte raw key.
    if (k.length < 32) throw new Error("shim: SPKI too short for Ed25519");
    return { kind: "shim-ed25519-public", raw: new Uint8Array(k.subarray(k.length - 32)) };
  }
  if (k.kty !== "OKP" || k.crv !== "Ed25519" || typeof k.x !== "string") {
    throw new Error("shim: only Ed25519 OKP JWK supported");
  }
  const bin = atob(k.x.replace(/-/g, "+").replace(/_/g, "/"));
  const raw = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) raw[i] = bin.charCodeAt(i);
  return { kind: "shim-ed25519-public", raw };
}

// The base-point order L = 2^252 + 27742317777372353535851937790883648493.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const littleEndian = (bytes: Uint8Array): bigint => {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
};

/**
 * Explicit COFACTORLESS Ed25519 verification: encode([S]B - [k]A) == R, compared byte for byte.
 *
 * Rule S1 (strict Ed25519) mandates the cofactorless equation, and noble's own verify is cofactored in
 * BOTH of its modes: `zip215: true` (the default) and `zip215: false` both accept signatures the
 * cofactorless equation rejects (a torsion component in R or A that the cofactor multiplication
 * cancels), so neither can stand in for it. test/strict-ed25519-shim.test.ts pins that reason (a
 * mixed-order-R signature that noble accepts in both modes and this check refuses) and runs every
 * verify case of the strict corpus through this shim. A is decoded with the strict RFC 8032 section 5.1.3 rule
 * (`zip215 = false`: canonical y, no sign bit when x = 0) and an off-curve A throws, which is a
 * rejection. S >= L is refused here as well.
 *
 * This function sits behind the same byte-level gate as the Node build: src/ed25519.ts applies the
 * canonical, small-order and S < L checks (strictGate) BEFORE it calls verify, and this shim is only
 * reached through that call. The checks here are the equation and its two bounds, not a second gate.
 */
function verifyCofactorless(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  let a: Point;
  try {
    a = Point.fromBytes(publicKey, false);
  } catch {
    return false;
  }
  const rBytes = signature.subarray(0, 32);
  const s = littleEndian(signature.subarray(32));
  // noble's multiply also range-asserts a scalar to 1..L-1 (and throws, which verifyEd25519 maps to false),
  // so this check is redundant with it; it stays so that rule S1 does not depend on that incidental assertion.
  // test/strict-ed25519-shim.test.ts pins the behavior (the S + L twin is refused).
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

/** The packages always call verify(null, data, ed25519Key, sig). */
export function verifyEd25519(
  _alg: unknown,
  data: Uint8Array,
  key: ShimKeyObject,
  signature: Uint8Array,
): boolean {
  try {
    return verifyCofactorless(signature, data, key.raw);
  } catch {
    return false;
  }
}
export { verifyEd25519 as verify };

/** The packages always call createHash("sha256") with update/digest chaining. */
export function createHash(algo: string): { update(d: Uint8Array): unknown; digest(enc?: string): Uint8Array | string } {
  if (algo !== "sha256") throw new Error(`shim: hash ${algo} not supported`);
  let acc = new Uint8Array(0);
  return {
    update(d: Uint8Array) {
      const next = new Uint8Array(acc.length + d.length);
      next.set(acc);
      next.set(d, acc.length);
      acc = next;
      return this;
    },
    digest(enc?: string) {
      // Return a POLYFILL BUFFER with no encoding asked, or the ENCODED STRING
      // when one is: package code calls digest("base64url") and interpolates
      // the result — returning the Buffer there stringifies it lossy-utf8
      // (the mojibake digest bug), and ignoring enc entirely printed byte
      // lists (the comma-decimal bug). The polyfill carries base64url.
      const out = Buffer.from(sha256(acc));
      return enc ? out.toString(enc as unknown as BufferEncoding) : out;
    },
  };
}
