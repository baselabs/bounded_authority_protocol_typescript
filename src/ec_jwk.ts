import { fail, assert, type Result, ok, err } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { sha256 } from "./ed25519.js";
import { jcsEncode } from "./jcs.js";
import { jsonDecode, strUtf8, utf8Str } from "./json.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";
import { validateEcPublicKey } from "./es256.js";

// RFC 7638 JWK thumbprint for EC P-256 public keys (spec/bap-v3.md §3.1). The public EC JWK has
// exactly four members — crv="P-256", kty="EC", x=<canonical unpadded base64url of 32 bytes>,
// y=<same> — and the thumbprint preimage is the JCS of that object with the required members in
// RFC 7638 lexicographic order (crv, kty, x, y). The thumbprint is unpadded-base64url SHA-256 of
// those UTF-8 bytes; the raw thumbprint is the 32-byte digest. The raw-byte public-key form this
// module pairs with is the 65-byte uncompressed SEC1 point 0x04||x||y (REQ3-KEY-uncompressed-sec1).

export interface EcPublic {
  readonly crv: "P-256";
  readonly kty: "EC";
  readonly x: string; // base64url of the 32 raw coordinate bytes
  readonly y: string; // base64url of the 32 raw coordinate bytes
}

// Encode a raw 65-byte SEC1 P-256 public key as the canonical EC JCS JSON bytes.
export function jwkEncodePublic(rawKey: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): Uint8Array {
  assert(rawKey.length === 65, "jwk.encode_public: public key width must be 65");
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

// Decode an EC public JWK from bytes (the JSON text). Returns the raw 65-byte SEC1 key. The closed
// member set is exactly {crv, kty, x, y} (every additional member, including private d, is invalid —
// REQ3-HEADER-no-private-jwk); crv must be "P-256", kty "EC"; x and y are canonical unpadded
// base64url of exactly 32 bytes each (the RFC 7518 §6.2.1.2/.3 fixed-width spelling), each less
// than the field prime, and the point must be on the curve (REQ3-KEY-point-on-curve).
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

// The EC JWK of a raw 65-byte SEC1 public key (structural spelling only — the full point
// validation lives with the profile's key gates / es256.validateEcPublicKey).
export function jwkFromPublicKey(rawKey: Uint8Array): EcPublic {
  assert(rawKey.length === 65, "jwk: public key width");
  return {
    crv: "P-256",
    kty: "EC",
    x: utf8Str(base64urlEncode(rawKey.subarray(1, 33))),
    y: utf8Str(base64urlEncode(rawKey.subarray(33, 65))),
  };
}

// RFC 7638 thumbprint preimage: the JCS bytes of {crv, kty, x, y} (lexicographic order) — exactly
// the required EC members over the exact member set (REQ3-HEADER-thumbprint).
export function thumbprintPreimage(jwk: EcPublic): Uint8Array {
  const members = new Map<string, never>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) } as never],
    ["kty", { t: "string", v: strUtf8(jwk.kty) } as never],
    ["x", { t: "string", v: strUtf8(jwk.x) } as never],
    ["y", { t: "string", v: strUtf8(jwk.y) } as never],
  ]);
  return jcsEncode({ t: "object", v: members });
}

// Thumbprint as base64url SHA-256 of the preimage.
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
