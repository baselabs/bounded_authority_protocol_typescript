import { fail, assert, type Result, ok, err } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { sha256 } from "./ed25519.js";
import { jcsEncode } from "./jcs.js";
import { jsonDecode, strUtf8, utf8Str } from "./json.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// RFC 7638 JWK thumbprint for OKP Ed25519 public keys (protocol-v1.md § Public verification contract).
// The public OKP JWK has exactly three members — crv="Ed25519", kty="OKP", x=<base64url raw 32 bytes>
// — in RFC 7638 lexicographic order (crv, kty, x). The thumbprint preimage is the JCS of that object;
// the thumbprint is SHA-256 of the preimage (base64url); the raw thumbprint is the 32-byte digest.

export interface OkpPublic {
  readonly crv: "Ed25519";
  readonly kty: "OKP";
  readonly x: string; // base64url of the 32 raw bytes
}

// Encode a raw 32-byte Ed25519 public key as the canonical OKP JCS JSON bytes.
export function jwkEncodePublic(rawKey: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): Uint8Array {
  assert(rawKey.length === 32, "jwk.encode_public: public key width must be 32");
  const jwk = jwkFromPublicKey(rawKey);
  // The encoded form is the JCS of {crv, kty, x} in lexicographic order. Build the tagged object.
  const members = new Map<string, never>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) } as never],
    ["kty", { t: "string", v: strUtf8(jwk.kty) } as never],
    ["x", { t: "string", v: strUtf8(jwk.x) } as never],
  ]);
  void resolve(bounds, "jcs_bytes" as MaximaKey);
  return jcsEncode({ t: "object", v: members }, bounds);
}

// Decode an OKP public JWK from bytes (the JSON text). Returns the raw 32-byte key.
export function jwkDecodePublic(input: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): Result<Uint8Array> {
  // Decode the JSON, then validate the closed OKP shape.
  try {
    const value = jsonDecode(input, bounds);
    if (value.t !== "object") fail("jwk.decode_public: not an object");
    const obj = value.v;
    if (obj.size !== 3) fail("jwk.decode_public: closed members");
    const crv = obj.get("crv");
    const kty = obj.get("kty");
    const x = obj.get("x");
    if (!crv || !kty || !x) fail("jwk.decode_public: missing member");
    if (crv.t !== "string" || utf8Str(crv.v) !== "Ed25519") fail("jwk.decode_public: crv");
    if (kty.t !== "string" || utf8Str(kty.v) !== "OKP") fail("jwk.decode_public: kty");
    if (x.t !== "string") fail("jwk.decode_public: x");
    const raw = base64urlDecode(x.v);
    if (raw.length !== 32) fail("jwk.decode_public: x width");
    return ok(raw);
  } catch (e) {
    if (e instanceof Error && e.name === "InvalidError") return err();
    throw e;
  }
}

export function jwkFromPublicKey(rawKey: Uint8Array): OkpPublic {
  assert(rawKey.length === 32, "jwk: public key width");
  return { crv: "Ed25519", kty: "OKP", x: utf8Str(base64urlEncode(rawKey)) };
}

// RFC 7638 thumbprint preimage: the JCS bytes of {crv, kty, x} (lexicographic order).
export function thumbprintPreimage(jwk: OkpPublic): Uint8Array {
  const members = new Map<string, never>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) } as never],
    ["kty", { t: "string", v: strUtf8(jwk.kty) } as never],
    ["x", { t: "string", v: strUtf8(jwk.x) } as never],
  ]);
  return jcsEncode({ t: "object", v: members });
}

// Thumbprint as base64url SHA-256 of the preimage.
export function thumbprint(jwk: OkpPublic): string {
  return utf8Str(base64urlEncode(sha256(thumbprintPreimage(jwk))));
}

// Raw 32-byte thumbprint.
export function thumbprintRaw(jwk: OkpPublic): Uint8Array {
  return sha256(thumbprintPreimage(jwk));
}

// Raw 32-byte thumbprint directly from a raw 32-byte public key.
export function publicKeyThumbprintRaw(rawKey: Uint8Array): Uint8Array {
  return thumbprintRaw(jwkFromPublicKey(rawKey));
}
