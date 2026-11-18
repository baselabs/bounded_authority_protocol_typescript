import { fail, assert, type Result, ok, err } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { acceptablePublicKey, sha256 } from "./ed25519.js";
import { jcsEncode } from "./jcs.js";
import { jsonDecode, strUtf8, utf8Str } from "./json.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// The public Ed25519 JWK has exactly crv="Ed25519", kty="OKP" and x encoding 32 raw bytes. Hash
// its JCS encoding in crv, kty, x order for the 32-byte RFC 7638 thumbprint. Public helpers
// reject noncanonical, small-order or off-curve keys under rule S1. The internal
// thumbprintDigestUnchecked helper is reserved for census and deny-list fingerprints and never
// participates in verification.

/**
 * The closed public Ed25519 JWK shape. No private d or extra members are accepted. Key helpers
 * validate canonical, non-small-order, on-curve 32-byte keys before encoding or hashing.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#10-protected-headers
 * @category Request verification
 */
export interface OkpPublic {
  /** Exact JWK curve name required by the suite. */
  readonly crv: "Ed25519";
  /** Exact public JWK key family required by the suite. */
  readonly kty: "OKP";
  /** Canonical unpadded base64url of the 32-byte Ed25519 encoding (43 ASCII characters). */
  readonly x: string;
}

/**
 * The canonical JSON bytes of the public OKP JWK `{crv, kty, x}` for a raw 32-byte Ed25519 key.
 * Throws `InvalidError` for a key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519
 * @returns Canonical UTF-8 JSON for the closed public JWK.
 * @throws InvalidError when the documented representation or resource limits are violated.
 * @category Keys and trust
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * import { generateKeyPairSync } from "node:crypto";
 * const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
 * assert.ok(api.jwkDecodePublic(api.jwkEncodePublic(raw)).ok);
 * ```
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

/**
 * Parses exactly a public OKP Ed25519 JWK (no other member, including a private `d`) and returns
 * the raw 32-byte key.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519
 * @returns The validated raw 32-byte Ed25519 public key in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Keys and trust
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * import { generateKeyPairSync } from "node:crypto";
 * const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
 * assert.ok(api.jwkDecodePublic(api.jwkEncodePublic(raw)).ok);
 * ```
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
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519
 * @returns The validated public OKP JWK object.
 * @throws InvalidError when the documented representation or resource limits are violated.
 * @category Keys and trust
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * import { generateKeyPairSync } from "node:crypto";
 * const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
 * assert.equal(api.jwkFromPublicKey(raw).kty, "OKP");
 * ```
 */
export function jwkFromPublicKey(rawKey: Uint8Array): OkpPublic {
  assert(rawKey.length === 32, "jwk: public key width");
  assert(acceptablePublicKey(rawKey), "jwk: key not acceptable");
  return uncheckedJwk(rawKey);
}

function uncheckedJwk(rawKey: Uint8Array): OkpPublic {
  return { crv: "Ed25519", kty: "OKP", x: utf8Str(base64urlEncode(rawKey)) };
}

/**
 * The RFC 7638 thumbprint preimage: the canonical JSON of `{crv, kty, x}`. Throws `InvalidError`
 * for a key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519
 * @returns Canonical UTF-8 JSON of exactly the RFC 7638 required public JWK members.
 * @throws InvalidError when the documented representation or resource limits are violated.
 * @category Keys and trust
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * import { generateKeyPairSync } from "node:crypto";
 * const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
 * assert.ok(api.thumbprintPreimage(api.jwkFromPublicKey(raw)).length > 0);
 * ```
 */
export function thumbprintPreimage(jwk: OkpPublic): Uint8Array {
  // Each member is read exactly once into a local, those values are checked, and the preimage is
  // re-encoded from the validated raw key (the Elixir encode_public(decode_public(jwk))), so a getter
  // or Proxy that answers differently on a later read cannot get another key hashed.
  const { crv, kty, x } = readMembers(jwk, ["crv", "kty", "x"]);
  if (crv !== "Ed25519" || kty !== "OKP" || typeof x !== "string") fail("jwk: OKP Ed25519 members");
  const raw = base64urlDecode(strUtf8(x));
  assert(raw.length === 32, "jwk: x width");
  assert(acceptablePublicKey(raw), "jwk: key not acceptable");
  return preimageOf(uncheckedJwk(raw));
}

function preimageOf(jwk: OkpPublic): Uint8Array {
  const members = new Map<string, never>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) } as never],
    ["kty", { t: "string", v: strUtf8(jwk.kty) } as never],
    ["x", { t: "string", v: strUtf8(jwk.x) } as never],
  ]);
  return jcsEncode({ t: "object", v: members });
}

/**
 * The RFC 7638 thumbprint of a public Ed25519 JWK, as unpadded base64url (the form a grant's
 * `holderThumbprint` takes). Throws `InvalidError` for a key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519
 * @returns A canonical 43-character unpadded base64url SHA-256 thumbprint.
 * @throws InvalidError when the documented representation or resource limits are violated.
 * @category Keys and trust
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * import { generateKeyPairSync } from "node:crypto";
 * const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
 * assert.equal(api.thumbprint(api.jwkFromPublicKey(raw)).length, 43);
 * ```
 */
export function thumbprint(jwk: OkpPublic): string {
  return utf8Str(base64urlEncode(sha256(thumbprintPreimage(jwk))));
}

/**
 * The RFC 7638 thumbprint of a public Ed25519 JWK as 32 raw bytes. Throws `InvalidError` for a key
 * that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519
 * @returns The raw 32-byte RFC 7638 SHA-256 thumbprint.
 * @throws InvalidError when the documented representation or resource limits are violated.
 * @category Keys and trust
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * import { generateKeyPairSync } from "node:crypto";
 * const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
 * assert.equal(api.thumbprintRaw(api.jwkFromPublicKey(raw)).length, 32);
 * ```
 */
export function thumbprintRaw(jwk: OkpPublic): Uint8Array {
  return sha256(thumbprintPreimage(jwk));
}

// The closed member set of a public JWK object, as the Elixir V1.Jwk and V3.EcJwk decoders require:
// exactly the RFC 7638 required members of its key type, as own string keys, and nothing else (no
// private `d`, no `alg`, no other member). Returns each member read exactly once. Shared with
// ec_jwk.ts.
export function readMembers(jwk: object, members: readonly string[]): Record<string, unknown> {
  if (jwk === null || typeof jwk !== "object") fail("jwk: object required");
  try {
    const own = Reflect.ownKeys(jwk);
    if (own.length !== members.length || !own.every((k) => typeof k === "string" && members.includes(k))) {
      fail("jwk: closed member set");
    }
    // One read per member; a throwing getter or Proxy trap is the closed error.
    const values: Record<string, unknown> = Object.create(null);
    for (const name of members) values[name] = (jwk as Record<string, unknown>)[name];
    return values;
  } catch (e) {
    if (e instanceof Error && e.name === "InvalidError") throw e;
    fail("jwk: unreadable member");
  }
}

/**
 * The raw 32-byte RFC 7638 thumbprint of a raw 32-byte Ed25519 key. Throws `InvalidError` for a
 * key that is not acceptable.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#strict-ed25519
 * @returns The raw 32-byte RFC 7638 SHA-256 thumbprint of the validated public key.
 * @throws InvalidError when the documented representation or resource limits are violated.
 * @category Keys and trust
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * import { generateKeyPairSync } from "node:crypto";
 * const raw = Buffer.from(generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x!, "base64url");
 * assert.equal(api.publicKeyThumbprintRaw(raw).length, 32);
 * ```
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
