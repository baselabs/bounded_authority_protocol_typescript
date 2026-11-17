import { fail, assert, type Result, ok, err } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { sha256 } from "./ed25519.js";
import { jcsEncode } from "./jcs.js";
import { jsonDecode, strUtf8, utf8Str } from "./json.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";
import { validateEcPublicKey } from "./es256.js";
import { readMembers } from "./jwk.js";

// The public P-256 JWK has exactly crv="P-256", kty="EC", x and y. Each coordinate is canonical
// unpadded base64url of 32 bytes. Hash the UTF-8 JCS encoding in crv, kty, x, y order for its
// 32-byte RFC 7638 thumbprint. The raw public key is a 65-byte uncompressed SEC1 point. See
// spec/bap-v3.md section 3.1.

/**
 * The closed public P-256 JWK shape for major 3. Coordinates are canonical unpadded base64url of
 * exactly 32 bytes each. Key helpers require an on-curve point; no private d is accepted.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#31-keys-and-the-proof-jwk
 */
export interface EcPublic {
  /** Exact JWK curve name required by the suite. */
  readonly crv: "P-256";
  /** Exact public JWK key family required by the suite. */
  readonly kty: "EC";
  /** Canonical unpadded base64url of the 32-byte unsigned big-endian P-256 x coordinate (43 ASCII characters). */
  readonly x: string;
  /** Canonical unpadded base64url of the 32-byte P-256 y coordinate. */
  readonly y: string;
}

/**
 * The canonical JSON bytes of the public EC JWK `{crv: "P-256", kty: "EC", x, y}` for a raw
 * 65-byte SEC1 key. Throws `InvalidError` for a key that is not an acceptable P-256 point (65 bytes,
 * the 0x04 prefix, both coordinates below p, on the curve), as the Elixir `V3.EcJwk.encode_public`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns Canonical UTF-8 JSON for the closed public JWK.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function jwkEncodePublic(rawKey: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): Uint8Array {
  assert(rawKey instanceof Uint8Array && rawKey.length === 65, "jwk.encode_public: public key width must be 65");
  validateEcPublicKey(rawKey);
  const jwk = jwkFromPublicKey(rawKey);
  // The encoded form is the JCS of {crv, kty, x, y} in lexicographic order. Build the tagged object.
  const members = new Map<string, never>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) } as never],
    ["kty", { t: "string", v: strUtf8(jwk.kty) } as never],
    ["x", { t: "string", v: strUtf8(jwk.x) } as never],
    ["y", { t: "string", v: strUtf8(jwk.y) } as never],
  ]);
  void resolve(bounds, "jcs_bytes" as MaximaKey);
  return jcsEncode({ t: "object", v: members }, bounds);
}

/**
 * Parses exactly a public P-256 EC JWK and returns the raw 65-byte uncompressed key after full
 * point validation.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns The validated raw 65-byte uncompressed SEC1 P-256 public key in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function jwkDecodePublic(input: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): Result<Uint8Array> {
  // Decode the JSON, then validate the closed EC shape.
  try {
    const value = jsonDecode(input, bounds);
    if (value.t !== "object") fail("jwk.decode_public: not an object");
    const obj = value.v;
    if (obj.size !== 4) fail("jwk.decode_public: closed members");
    const crv = obj.get("crv");
    const kty = obj.get("kty");
    const x = obj.get("x");
    const y = obj.get("y");
    if (!crv || !kty || !x || !y) fail("jwk.decode_public: missing member");
    if (crv.t !== "string" || utf8Str(crv.v) !== "P-256") fail("jwk.decode_public: crv");
    if (kty.t !== "string" || utf8Str(kty.v) !== "EC") fail("jwk.decode_public: kty");
    if (x.t !== "string") fail("jwk.decode_public: x string");
    if (y.t !== "string") fail("jwk.decode_public: y string");
    const xRaw = base64urlDecode(x.v);
    const yRaw = base64urlDecode(y.v);
    if (xRaw.length !== 32) fail("jwk.decode_public: x width");
    if (yRaw.length !== 32) fail("jwk.decode_public: y width");
    const raw = new Uint8Array(65);
    raw[0] = 0x04;
    raw.set(xRaw, 1);
    raw.set(yRaw, 33);
    // Pure-arithmetic coordinate range + on-curve gates (REQ3-KEY-point-on-curve), before any backend.
    validateEcPublicKey(raw);
    return ok(raw);
  } catch (e) {
    if (e instanceof Error && e.name === "InvalidError") return err();
    throw e;
  }
}

// Spell the EC JWK for a raw 65-byte SEC1 point. This helper checks structure; the profile key
// gates perform full curve validation.
export function jwkFromPublicKey(rawKey: Uint8Array): EcPublic {
  assert(rawKey.length === 65, "jwk: public key width");
  return {
    crv: "P-256",
    kty: "EC",
    x: utf8Str(base64urlEncode(rawKey.subarray(1, 33))),
    y: utf8Str(base64urlEncode(rawKey.subarray(33, 65))),
  };
}

// Encode exactly the required {crv, kty, x, y} members as JCS in lexicographic order to form
// the RFC 7638 thumbprint preimage. See REQ3-HEADER-thumbprint.
export function thumbprintPreimage(jwk: EcPublic): Uint8Array {
  const members = new Map<string, never>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) } as never],
    ["kty", { t: "string", v: strUtf8(jwk.kty) } as never],
    ["x", { t: "string", v: strUtf8(jwk.x) } as never],
    ["y", { t: "string", v: strUtf8(jwk.y) } as never],
  ]);
  return jcsEncode({ t: "object", v: members });
}

/**
 * The RFC 7638 thumbprint of a public P-256 JWK `{crv, kty, x, y}`, as unpadded base64url.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns A canonical 43-character unpadded base64url SHA-256 thumbprint.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function thumbprint(jwk: EcPublic): string {
  return utf8Str(base64urlEncode(sha256(thumbprintPreimage(jwk))));
}

// Raw 32-byte thumbprint.
export function thumbprintRaw(jwk: EcPublic): Uint8Array {
  return sha256(thumbprintPreimage(jwk));
}

// Raw 32-byte thumbprint directly from a raw 65-byte SEC1 public key.
export function publicKeyThumbprintRaw(rawKey: Uint8Array): Uint8Array {
  return thumbprintRaw(jwkFromPublicKey(rawKey));
}

// ---- the public v3 helpers (exported through the v3 namespace) ----
// Each refuses, with the closed InvalidError, a key that is not an acceptable P-256 point: the internal
// structural helpers above serve the profile code, which validates keys at its own gates.

// The raw 65-byte point behind a public EC JWK, after full validation.
function acceptableJwkPoint(jwk: EcPublic): Uint8Array {
  // Each member is read exactly once (see jwk.ts readMembers); the callers hash the preimage
  // re-encoded from the validated raw point, never a second read of the object.
  const m = readMembers(jwk, ["crv", "kty", "x", "y"]);
  if (m.crv !== "P-256" || m.kty !== "EC" || typeof m.x !== "string" || typeof m.y !== "string") fail("jwk: P-256 EC members");
  const x = base64urlDecode(strUtf8(m.x));
  const y = base64urlDecode(strUtf8(m.y));
  if (x.length !== 32 || y.length !== 32) fail("jwk: coordinate width");
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 33);
  validateEcPublicKey(raw);
  return raw;
}

/**
 * The public EC JWK object `{crv: "P-256", kty: "EC", x, y}` of a raw 65-byte uncompressed SEC1 key.
 * Throws `InvalidError` for a key that is not an acceptable P-256 point.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns The validated public EC JWK object.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function publicJwk(rawKey: Uint8Array): EcPublic {
  assert(rawKey instanceof Uint8Array && rawKey.length === 65, "jwk: public key width");
  validateEcPublicKey(rawKey);
  return jwkFromPublicKey(rawKey);
}

/**
 * The RFC 7638 thumbprint preimage of a public P-256 JWK: the canonical JSON of `{crv, kty, x, y}`.
 * Throws `InvalidError` for a JWK whose point is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns Canonical UTF-8 JSON of exactly the four RFC 7638 required EC JWK members.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function checkedThumbprintPreimage(jwk: EcPublic): Uint8Array {
  return thumbprintPreimage(jwkFromPublicKey(acceptableJwkPoint(jwk)));
}

/**
 * The RFC 7638 thumbprint of a public P-256 JWK as unpadded base64url (the form a v3 grant's
 * `holderThumbprint` takes). Throws `InvalidError` for a JWK whose point is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns A canonical 43-character unpadded base64url SHA-256 thumbprint.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function checkedThumbprint(jwk: EcPublic): string {
  return utf8Str(base64urlEncode(sha256(checkedThumbprintPreimage(jwk))));
}

/**
 * The RFC 7638 thumbprint of a public P-256 JWK as 32 raw bytes. Throws `InvalidError` for a JWK
 * whose point is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns The raw 32-byte RFC 7638 SHA-256 thumbprint.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function checkedThumbprintRaw(jwk: EcPublic): Uint8Array {
  return sha256(checkedThumbprintPreimage(jwk));
}

/**
 * The raw 32-byte RFC 7638 thumbprint of a raw 65-byte P-256 key (a v3 key fingerprint, as anchors
 * and transitions carry). Throws `InvalidError` for a key that is not an acceptable P-256 point.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 * @returns The raw 32-byte RFC 7638 SHA-256 thumbprint of the validated P-256 public key.
 * @throws InvalidError when the documented representation or resource limits are violated.
 */
export function checkedPublicKeyThumbprintRaw(rawKey: Uint8Array): Uint8Array {
  return thumbprintRaw(publicJwk(rawKey));
}
