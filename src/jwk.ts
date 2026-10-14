import { fail, assert, type Result, ok, err } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { acceptablePublicKey, sha256 } from "./ed25519.js";
import { jcsEncode } from "./jcs.js";
import { jsonDecode, strUtf8, utf8Str } from "./json.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// RFC 7638 JWK thumbprint for OKP Ed25519 public keys (spec/bap-v1.md § Public verification contract).
// The public OKP JWK has exactly three members — crv="Ed25519", kty="OKP", x=<base64url raw 32 bytes>
// — in RFC 7638 lexicographic order (crv, kty, x). The thumbprint preimage is the JCS of that object;
// the thumbprint is SHA-256 of the preimage (base64url); the raw thumbprint is the 32-byte digest.
//
// Key acceptance (rule S1, REQ1-KEY-ed25519-acceptable). Every public function that encodes, decodes or
// hashes a key is FALLIBLE: a key that fails acceptablePublicKey (non-canonical, small-order, or off the
// curve) is refused with the closed InvalidError (decode returns the closed error), so no weak key
// reaches a thumbprint, a holder binding or a verify input. The one exception is thumbprintDigestUnchecked,
// the raw hash-only path for censuses, generators and deny-list fingerprinting: it is never used on a
// verify path, and a test pins its callers.

export interface OkpPublic {
  readonly crv: "Ed25519";
  readonly kty: "OKP";
  readonly x: string; // base64url of the 32 raw bytes
}

// Encode a raw 32-byte Ed25519 public key as the canonical OKP JCS JSON bytes.
/**
 * The canonical JSON bytes of the public OKP JWK `{crv, kty, x}` for a raw 32-byte Ed25519 key.
 * Throws `InvalidError` for a key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
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
/**
 * Parses exactly a public OKP Ed25519 JWK (no other member, including a private `d`) and returns
 * the raw 32-byte key.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
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
    if (!acceptablePublicKey(raw)) fail("jwk.decode_public: key not acceptable");
    return ok(raw);
  } catch (e) {
    if (e instanceof Error && e.name === "InvalidError") return err();
    throw e;
  }
}

/**
 * The public OKP JWK object of a raw 32-byte Ed25519 key. Throws `InvalidError` for a key that is
 * not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function jwkFromPublicKey(rawKey: Uint8Array): OkpPublic {
  assert(rawKey.length === 32, "jwk: public key width");
  assert(acceptablePublicKey(rawKey), "jwk: key not acceptable");
  return uncheckedJwk(rawKey);
}

function uncheckedJwk(rawKey: Uint8Array): OkpPublic {
  return { crv: "Ed25519", kty: "OKP", x: utf8Str(base64urlEncode(rawKey)) };
}

// RFC 7638 thumbprint preimage: the JCS bytes of {crv, kty, x} (lexicographic order). Fallible: the key
// behind x must be acceptable.
/**
 * The RFC 7638 thumbprint preimage: the canonical JSON of `{crv, kty, x}`. Throws `InvalidError`
 * for a key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function thumbprintPreimage(jwk: OkpPublic): Uint8Array {
  exactMembers(jwk, ["crv", "kty", "x"]);
  if (jwk.crv !== "Ed25519" || jwk.kty !== "OKP" || typeof jwk.x !== "string") fail("jwk: OKP Ed25519 members");
  const raw = base64urlDecode(strUtf8(jwk.x));
  assert(raw.length === 32, "jwk: x width");
  assert(acceptablePublicKey(raw), "jwk: key not acceptable");
  return preimageOf(jwk);
}

function preimageOf(jwk: OkpPublic): Uint8Array {
  const members = new Map<string, never>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) } as never],
    ["kty", { t: "string", v: strUtf8(jwk.kty) } as never],
    ["x", { t: "string", v: strUtf8(jwk.x) } as never],
  ]);
  return jcsEncode({ t: "object", v: members });
}

// Thumbprint as base64url SHA-256 of the preimage.
/**
 * The RFC 7638 thumbprint of a public Ed25519 JWK, as unpadded base64url (the form a grant's
 * `holderThumbprint` takes). Throws `InvalidError` for a key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function thumbprint(jwk: OkpPublic): string {
  return utf8Str(base64urlEncode(sha256(thumbprintPreimage(jwk))));
}

// Raw 32-byte thumbprint.
/**
 * The RFC 7638 thumbprint of a public Ed25519 JWK as 32 raw bytes. Throws `InvalidError` for a key
 * that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function thumbprintRaw(jwk: OkpPublic): Uint8Array {
  return sha256(thumbprintPreimage(jwk));
}

// The closed member set of a public JWK object, as the Elixir V1.Jwk and V3.EcJwk decoders require:
// exactly the RFC 7638 required members of its key type, as own string keys, and nothing else (no
// private `d`, no `alg`, no other member). Shared with ec_jwk.ts.
export function exactMembers(jwk: object, members: readonly string[]): void {
  if (jwk === null || typeof jwk !== "object") fail("jwk: object required");
  const own = Reflect.ownKeys(jwk);
  if (own.length !== members.length || !own.every((k) => typeof k === "string" && members.includes(k))) {
    fail("jwk: closed member set");
  }
}

// Raw 32-byte thumbprint directly from a raw 32-byte public key. Fallible, like every function above.
/**
 * The raw 32-byte RFC 7638 thumbprint of a raw 32-byte Ed25519 key. Throws `InvalidError` for a
 * key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
 */
export function publicKeyThumbprintRaw(rawKey: Uint8Array): Uint8Array {
  return thumbprintRaw(jwkFromPublicKey(rawKey));
}

// The raw hash-only thumbprint path: SHA-256 of the RFC 7638 preimage of ANY 32 bytes, with no key
// acceptance. For censuses, corpus generators and deny-list fingerprinting only (a weak key must still
// be nameable there). It is internal (not exported from the package index) and is never used on a verify
// path; test/strict-ed25519-jwk.test.ts pins its callers.
export function thumbprintDigestUnchecked(rawKey: Uint8Array): Uint8Array {
  assert(rawKey.length === 32, "jwk: public key width");
  return sha256(preimageOf(uncheckedJwk(rawKey)));
}
