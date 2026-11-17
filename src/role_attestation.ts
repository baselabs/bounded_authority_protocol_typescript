/**
 * The bap-role-attestation/1 sibling profile binds a distinct public subject key to issuer or holder
 * for a bounded window under an already-trusted Ed25519 attestor. Select explicitly: no grant profile
 * parses these bytes. Verification proves a signature and context only; trust and operational
 * enrollment remain host policy.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#3-verification-contract
 * @module roleAttestation
 */
import { isStringOrUri } from "./string_or_uri.js";
import { fail, assert, trying, type Result } from "./error.js";
import { parseCompact, assembleSegments, type SigningInput } from "./compact.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "./json.js";
import { jcsEncode } from "./jcs.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { jwkFromPublicKey, thumbprintRaw } from "./jwk.js";
import { importPublicKey, ed25519Verify, acceptablePublicKey } from "./ed25519.js";
import { resolve, coerceBounds, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";
import type { HistoricalPublicKey } from "./v1.js";
import { redacted } from "./redact.js";

// The separately selected bap-role-attestation/1 profile binds a subject key to a role for a
// bounded window. It reuses Ed25519, tagged JSON, JCS, base64url and JWK primitives. Contract-
// major grant profiles reject its typ, and it rejects theirs. Verification returns signature
// and window facts with trust not_evaluated and no authorization marker. See spec/bap-role-
// attestation-v1.md.

const ALG = "EdDSA";
const ATTESTATION_TYP = "ba+role-attestation";
const VERSION = 1;
const ROLES = ["issuer", "holder"] as const;

// --- public types (spec §3 expected context; spec/bap-role-attestation-v1.md §3) ---

/**
 * An already-trusted Ed25519 attestor key and its half-open historical validity window. Raw keys are
 * 32 bytes; endpoints are integer Unix seconds, with null for an unbounded upper endpoint.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#3-verification-contract
 */
export type AttestorKey = HistoricalPublicKey;

/**
 * Explicit attestor trust, subject identity and evaluation time for role verification. Success proves
 * a signature and window, but does not enroll the subject or operationally authorize its role.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#3-verification-contract
 */
export interface ExpectedAttestation {
  /** Already-trusted attestor public key and its half-open validity window. */
  readonly attestor: AttestorKey;
  /** Subject kid, 1 to 128 permitted ASCII bytes. Verification rejects equality with the attestor kid. */
  readonly subjectKeyId: string;
  /** Raw 32-byte acceptable Ed25519 subject key. Verification rejects self-attestation by key material. */
  readonly subjectPublicKey: Uint8Array;
  /** Host-supplied integer Unix seconds. The verifier reads no clock. */
  readonly now: number;
  /** Optional tightened resource limits; omission uses the profile maxima. */
  readonly bounds?: Bounds;
}

/**
 * Unsigned, grant-unbound role attestation for a distinct subject key. Verification requires
 * [notBefore, expiresAt) to fit within the attestor window. Signing remains external.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#3-verification-contract
 */
export interface AttestationProducer {
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Artifact StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly jti: string;
  /** Subject kid, 1 to 128 permitted ASCII bytes. Verification rejects equality with the attestor kid. */
  readonly subjectKeyId: string;
  /** Raw 32-byte acceptable Ed25519 subject key. Verification rejects self-attestation by key material. */
  readonly subjectPublicKey: Uint8Array;
  /** Attested role, exactly issuer or holder. Operational enrollment remains host policy. */
  readonly role: "issuer" | "holder";
  /** Inclusive validity lower endpoint in integer Unix seconds. */
  readonly notBefore: number;
  /** Exclusive attestation expiry in integer Unix seconds. No clock skew applies. */
  readonly expiresAt: number;
}

/**
 * Canonical role-attestation claims after bounded decoding only. Signature, key window and expected
 * subject remain unverified. These values cannot enroll a key or authorize a role.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#3-verification-contract
 */
export interface AttestationDecoded {
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Artifact StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly jti: string;
  /** Subject kid, 1 to 128 permitted ASCII bytes. Verification rejects equality with the attestor kid. */
  readonly subjectKeyId: string;
  /** Raw 32-byte acceptable Ed25519 subject key. Verification rejects self-attestation by key material. */
  readonly subjectPublicKey: Uint8Array;
  /** Attested role, exactly issuer or holder. Operational enrollment remains host policy. */
  readonly role: string;
  /** Inclusive validity lower endpoint in integer Unix seconds. */
  readonly notBefore: number;
  /** Exclusive attestation expiry in integer Unix seconds. No clock skew applies. */
  readonly expiresAt: number;
  /** No cryptographic verification has run. Parsing alone establishes no trust or execution authority. */
  readonly verification: "not_evaluated";
}

/**
 * Role facts after signature, subject and validity-window checks. Fingerprints are raw 32-byte RFC
 * 7638 thumbprints. Trust remains unevaluated; there is no authorization marker or execution meaning.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#3-verification-contract
 */
export interface AttestationFacts {
  /** Role-attestation profile version 1, not the npm package version. */
  readonly version: 1;
  /** Attestor protected-header kid, 1 to 128 permitted ASCII bytes. */
  readonly attestorKeyId: string;
  /** Raw 32-byte RFC 7638 thumbprint of the attestor public key. */
  readonly attestorKeyFingerprint: Uint8Array;
  /** Subject kid, 1 to 128 permitted ASCII bytes. Verification rejects equality with the attestor kid. */
  readonly subjectKeyId: string;
  /** Raw 32-byte RFC 7638 thumbprint of the subject public key. */
  readonly subjectKeyFingerprint: Uint8Array;
  /** Attested role, exactly issuer or holder. Operational enrollment remains host policy. */
  readonly role: string;
  /** Artifact StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly jti: string;
  /** Inclusive validity lower endpoint in integer Unix seconds. */
  readonly notBefore: number;
  /** Exclusive attestation expiry in integer Unix seconds. No clock skew applies. */
  readonly expiresAt: number;
  /** Completed verification stage only; conveys no key trust, replay reservation or execution authority. */
  readonly verification: "signature_and_window";
  /** Always not_evaluated. The caller owns trust selection and policy. */
  readonly trust: "not_evaluated";
}

// --- shared claim validators (spec §2 member rules; the v1 primitive discipline) ---

function requireObjectExact(v: Tagged, keys: string[], ctx: string): asserts v is Extract<Tagged, { t: "object" }> {
  if (v.t !== "object") fail(`${ctx}: object`);
  const got = [...v.v.keys()].sort().join(",");
  const want = [...keys].sort().join(",");
  if (got !== want) fail(`${ctx}: closed members`);
}

function requireStringLit(obj: Extract<Tagged, { t: "object" }>, key: string, lit: string, ctx: string): void {
  const v = obj.v.get(key);
  if (!v || v.t !== "string" || utf8Str(v.v) !== lit) fail(`${ctx}: ${key}=${lit}`);
}

// BAP1 kid rules: bounded ASCII [A-Za-z0-9.-_~], 1..kid_bytes.
function requireKidValue(v: Tagged | undefined, key: string, bounds: Bounds): string {
  if (!v || v.t !== "string") fail(`attestation: ${key} string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(bounds, "kid_bytes" as MaximaKey)) fail(`attestation: ${key} bytes`);
  const s = utf8Str(b);
  if (!/^[A-Za-z0-9._~-]+$/.test(s)) fail(`attestation: ${key} charset`);
  return s;
}

function requireStringOrUri(v: Tagged | undefined, key: string, bounds: Bounds): string {
  if (!v || v.t !== "string") fail(`attestation: ${key} string`);
  const s = utf8Str(v.v);
  const len = strUtf8(s).length;
  if (len < 1 || len > resolve(bounds, "identifier_bytes" as MaximaKey)) fail(`attestation: ${key} bytes`);
  if (!isStringOrUri(s)) fail(`attestation: ${key} string-or-uri`);
  return s;
}

function requireInt(v: Tagged | undefined, key: string): number {
  if (!v || v.t !== "int") fail(`attestation: ${key} integer`);
  return v.v;
}

function requireB64urlN(v: Tagged | undefined, key: string, n: number): Uint8Array {
  if (!v || v.t !== "string") fail(`attestation: ${key} b64url string`);
  const raw = base64urlDecode(v.v);
  if (raw.length !== n) fail(`attestation: ${key} width`);
  return raw;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// --- the profile codec (spec §2: closed sets, member rules, canonical bytes) ---

interface AttestationClaims {
  readonly jti: string;
  readonly subjectKeyId: string;
  readonly subjectPublicKey: Uint8Array;
  readonly role: string;
  readonly nbf: number;
  readonly exp: number;
}

// The protected header has exactly {alg, kid, typ}. Both protected and payload segments must
// equal their RFC 8785 canonical encoding under REQ-RA1-CLAIM-canonical.
function parseAttestationHeader(seg: ReturnType<typeof parseCompact>, bounds: Bounds): { kid: string } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "kid", "typ"], "attestation header");
  requireStringLit(h, "alg", ALG, "attestation header");
  requireStringLit(h, "typ", ATTESTATION_TYP, "attestation header");
  const kid = requireKidValue(h.v.get("kid"), "kid", bounds);
  if (!bytesEqual(jcsEncode(h, bounds), seg.protectedBytes)) fail("attestation header: canonical");
  return { kid };
}

// The payload has exactly {v, jti, key_id, public_key, role, nbf, exp}. Version v is integer-
// tagged 1. Apply the grant-jti and kid string rules, decode public_key to exactly 32 Ed25519
// bytes, require role issuer or holder, and enforce integral nbf < exp. See spec/bap-role-
// attestation-v1.md#2-protected-header-and-payload-claims.
function parseAttestationPayload(seg: ReturnType<typeof parseCompact>, bounds: Bounds): AttestationClaims {
  const p = jsonDecode(seg.payloadBytes, bounds);
  requireObjectExact(p, ["exp", "jti", "key_id", "nbf", "public_key", "role", "v"], "attestation payload");
  const vV = p.v.get("v");
  if (!vV || vV.t !== "int" || vV.v !== VERSION) fail("attestation payload: v=1");
  const jti = requireStringOrUri(p.v.get("jti"), "jti", bounds);
  const subjectKeyId = requireKidValue(p.v.get("key_id"), "key_id", bounds);
  const subjectPublicKey = requireB64urlN(p.v.get("public_key"), "public_key", 32);
  // Rule S1 key acceptance: a subject key that is non-canonical, small-order or off the curve is refused
  // at decode, not only at verify (REQ1-KEY-ed25519-acceptable).
  assert(acceptablePublicKey(subjectPublicKey), "attestation payload: subject key not acceptable");
  const roleV = p.v.get("role");
  if (!roleV || roleV.t !== "string") fail("attestation payload: role string");
  const role = utf8Str(roleV.v);
  if (!(ROLES as readonly string[]).includes(role)) fail("attestation payload: role closed set");
  const nbf = requireInt(p.v.get("nbf"), "nbf");
  const exp = requireInt(p.v.get("exp"), "exp");
  if (!(nbf < exp)) fail("attestation payload: window");
  if (!bytesEqual(jcsEncode(p, bounds), seg.payloadBytes)) fail("attestation payload: canonical");
  return { jti, subjectKeyId, subjectPublicKey, role, nbf, exp };
}

function parseAttestation(compact: Uint8Array, bounds: Bounds): { kid: string; claims: AttestationClaims; seg: ReturnType<typeof parseCompact> } {
  const seg = parseCompact(compact, bounds);
  const { kid } = parseAttestationHeader(seg, bounds);
  const claims = parseAttestationPayload(seg, bounds);
  return { kid, claims, seg };
}

// --- the caller-supplied expected context (fail-closed shallow + magnitude parity) ---

// Validate context before dereferencing fields. Wrong types return the closed error. Attestor-
// window endpoints and now must be integers within integer_magnitude. Half-open window
// comparisons alone would admit fractional times.
function validateExpected(expected: ExpectedAttestation): Bounds {
  if (expected === null || typeof expected !== "object") fail("verify_attestation: expected context required");
  const a = expected.attestor;
  if (a === null || typeof a !== "object") fail("verify_attestation: attestor required");
  if (typeof a.keyId !== "string") fail("verify_attestation: attestor key id");
  if (!(a.publicKey instanceof Uint8Array) || a.publicKey.length !== 32) fail("verify_attestation: attestor key width");
  if (typeof expected.subjectKeyId !== "string") fail("verify_attestation: subject key id");
  if (!(expected.subjectPublicKey instanceof Uint8Array) || expected.subjectPublicKey.length !== 32) {
    fail("verify_attestation: subject key width");
  }
  const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
  const mag = resolve(b, "integer_magnitude" as MaximaKey);
  if (!Number.isInteger(a.validFrom) || Math.abs(a.validFrom) > mag) fail("verify_attestation: valid_from magnitude");
  if (a.validBefore !== null && (!Number.isInteger(a.validBefore) || Math.abs(a.validBefore) > mag)) {
    fail("verify_attestation: valid_before magnitude");
  }
  // Verdict-equivalent with containment (valid_before <= valid_from admits no window), stated
  // explicitly for the anchor-parity ordering gate.
  if (a.validBefore !== null && a.validBefore <= a.validFrom) fail("verify_attestation: valid_before ordering");
  if (!Number.isInteger(expected.now) || Math.abs(expected.now) > mag) fail("verify_attestation: now magnitude");
  return b;
}

// --- the four public surfaces (spec §4; REQ-RA1-API-complete) ---

/**
 * Builds the signing input of a `bap-role-attestation/1` attestation: the attestor binds a subject
 * key to the `issuer` or `holder` role for `[notBefore, expiresAt)`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#4-public-verification-contract
 * @returns Canonical protected and payload base64url segments for the role attestation in a success Result. Sign their exact dot-separated ASCII bytes externally. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function attestationSigningInput(attestation: AttestationProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
    if (attestation === null || typeof attestation !== "object") fail("attestation_signing_input: producer required");
    // Field types gate first: a non-string id or jti must reject with the closed error, never
    // coerce through TextEncoder ("null") or throw a TypeError.
    if (typeof attestation.keyId !== "string") fail("attestation_signing_input: key_id string");
    if (typeof attestation.subjectKeyId !== "string") fail("attestation_signing_input: subject key id string");
    if (typeof attestation.jti !== "string") fail("attestation_signing_input: jti string");
    const b = coerceBounds(bounds ?? MAXIMUM_BOUNDS);
    const keyId = requireKidValue({ t: "string", v: strUtf8(attestation.keyId) }, "key_id", b);
    const jtiBytes = strUtf8(attestation.jti);
    if (jtiBytes.length < 1 || jtiBytes.length > resolve(b, "identifier_bytes" as MaximaKey) || !isStringOrUri(attestation.jti)) {
      fail("attestation_signing_input: jti");
    }
    const subjectKeyId = requireKidValue({ t: "string", v: strUtf8(attestation.subjectKeyId) }, "key_id", b);
    if (!(attestation.subjectPublicKey instanceof Uint8Array)) fail("attestation_signing_input: subject key");
    assert(attestation.subjectPublicKey.length === 32, "attestation_signing_input: subject key width");
    assert(acceptablePublicKey(attestation.subjectPublicKey), "attestation_signing_input: subject key not acceptable");
    if (attestation.role !== "issuer" && attestation.role !== "holder") fail("attestation_signing_input: role closed set");
    if (!Number.isInteger(attestation.notBefore) || !Number.isInteger(attestation.expiresAt)) {
      fail("attestation_signing_input: integer times");
    }
    if (!(attestation.notBefore < attestation.expiresAt)) fail("attestation_signing_input: window");
    const header = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["kid", { t: "string", v: strUtf8(keyId) }],
      ["typ", { t: "string", v: strUtf8(ATTESTATION_TYP) }],
    ]);
    const payload = new Map<string, Tagged>([
      ["exp", { t: "int", v: attestation.expiresAt }],
      ["jti", { t: "string", v: jtiBytes }],
      ["key_id", { t: "string", v: strUtf8(subjectKeyId) }],
      ["nbf", { t: "int", v: attestation.notBefore }],
      ["public_key", { t: "string", v: base64urlEncode(attestation.subjectPublicKey) }],
      ["role", { t: "string", v: strUtf8(attestation.role) }],
      ["v", { t: "int", v: VERSION }],
    ]);
    // Apply decoder bounds to emitted segments, the projected compact and emitted number
    // lexemes. A producer must refuse bytes its consumer would reject.
    const payloadJson = jcsEncode({ t: "object", v: payload }, b);
    if (payloadJson.length > resolve(b, "json_bytes" as MaximaKey)) {
      fail("attestation_signing_input: emitted json_bytes");
    }
    if (payloadJson.length > resolve(b, "jcs_bytes" as MaximaKey)) {
      fail("attestation_signing_input: emitted jcs_bytes");
    }
    const protectedSegment = strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: header }, b))));
    const emittedPayloadSegment = strUtf8(utf8Str(base64urlEncode(payloadJson)));
    if (protectedSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey) ||
        emittedPayloadSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) {
      fail("attestation_signing_input: emitted encoded_segment_bytes");
    }
    if (payloadJson.length > resolve(b, "decoded_segment_bytes" as MaximaKey)) {
      fail("attestation_signing_input: emitted decoded_segment_bytes");
    }
    // Projected compact: both segments + two dots + the 86-char base64url of a 64-byte signature.
    if (protectedSegment.length + emittedPayloadSegment.length + 2 + 86 > resolve(b, "compact_bytes" as MaximaKey)) {
      fail("attestation_signing_input: projected compact_bytes");
    }
    return {
      kind: "role_attestation" as const,
      protectedSegment,
      payloadSegment: emittedPayloadSegment,
    };
  });
}

/**
 * Joins a role-attestation signing input and a 64-byte signature into a compact JWS and re-parses
 * it. It does not verify the signature.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#4-public-verification-contract
 * @returns Exact ASCII role-attestation compact bytes in a success Result, without signature verification. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function assembleAttestationCompact(input: SigningInput, signature: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return trying(() => {
    if (input === null || typeof input !== "object") fail("assemble_compact: signing input required");
    if (!(input.protectedSegment instanceof Uint8Array) || !(input.payloadSegment instanceof Uint8Array)) {
      fail("assemble_compact: segments");
    }
    if (input.kind !== "role_attestation") fail("assemble_compact: kind");
    if (!(signature instanceof Uint8Array)) fail("assemble_compact: signature");
    const b = coerceBounds(bounds ?? MAXIMUM_BOUNDS);
    if (input.protectedSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey) || input.payloadSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) fail("assemble_compact: segment bound");
    const assembled = assembleSegments(input, signature);
    if (!assembled.ok) fail("assemble_compact: signing input");
    const compact = assembled.value;
    if (compact.length > resolve(b, "compact_bytes" as MaximaKey)) fail("assemble_compact: compact_bytes");
    parseAttestation(compact, b);
    return compact;
  });
}

/**
 * Parses and validates a role attestation's structure and coherent nbf/exp window, without
 * signature, historical-key-window or current-time verification (`verification: "not_evaluated"`).
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#4-public-verification-contract
 * @returns Canonical attestation claims in a success Result, with verification not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function decodeAttestation(compact: Uint8Array, bounds?: Bounds): Result<AttestationDecoded> {
  return trying(() => {
    if (!(compact instanceof Uint8Array)) fail("decode_attestation: compact required");
    const b = coerceBounds(bounds ?? MAXIMUM_BOUNDS);
    const { kid, claims } = parseAttestation(compact, b);
    return {
      keyId: kid,
      jti: claims.jti,
      subjectKeyId: claims.subjectKeyId,
      subjectPublicKey: claims.subjectPublicKey,
      role: claims.role,
      notBefore: claims.nbf,
      expiresAt: claims.exp,
      verification: "not_evaluated" as const,
    };
  });
}

/**
 * Verifies a role attestation under the attestor key: signature, subject key id and key, no
 * self-attestation, window containment in the attestor key's validity, and `nbf <= now < exp`.
 * Facts carry `trust: "not_evaluated"`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#4-public-verification-contract
 * @returns Redacted AttestationFacts in a success Result after signature, subject and window checks; trust remains not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function verifyAttestation(compact: Uint8Array, expected: ExpectedAttestation): Result<AttestationFacts> {
  return trying(() => {
    if (!(compact instanceof Uint8Array)) fail("verify_attestation: compact required");
    const b = validateExpected(expected);
    const { kid, claims, seg } = parseAttestation(compact, b);
    if (kid !== expected.attestor.keyId) fail("verify_attestation: kid binding");
    const attestorFingerprint = thumbprintRaw(jwkFromPublicKey(expected.attestor.publicKey));
    const key = importPublicKey(expected.attestor.publicKey, utf8Str(base64urlEncode(attestorFingerprint)));
    if (!ed25519Verify(seg.signingInput, seg.signature, key)) fail("verify_attestation: signature");
    if (claims.subjectKeyId !== expected.subjectKeyId) fail("verify_attestation: subject key id binding");
    if (!bytesEqual(claims.subjectPublicKey, expected.subjectPublicKey)) fail("verify_attestation: subject key binding");
    // Reject self-attestation when either the attestor thumbprint equals the subject thumbprint
    // or the attestor key identifier equals the subject key identifier. Each check is
    // independently required by REQ-RA1-VERIFY-no-self-attestation.
    const subjectFingerprint = thumbprintRaw(jwkFromPublicKey(claims.subjectPublicKey));
    if (bytesEqual(attestorFingerprint, subjectFingerprint)) fail("verify_attestation: self-attestation material");
    if (expected.attestor.keyId === claims.subjectKeyId) fail("verify_attestation: self-attestation key id");
    // Require nbf >= valid_from and, for a bounded attestor window, exp <= valid_before.
    // Equality at expiry is valid containment because verification still requires now < exp. A
    // retired key cannot attest beyond its validity window.
    if (claims.nbf < expected.attestor.validFrom) fail("verify_attestation: nbf containment");
    if (expected.attestor.validBefore !== null && claims.exp > expected.attestor.validBefore) {
      fail("verify_attestation: exp containment");
    }
    // now in [nbf, exp) (REQ-RA1-VERIFY-now-window).
    if (!(claims.nbf <= expected.now && expected.now < claims.exp)) fail("verify_attestation: now window");
    return redacted({
      version: VERSION,
      attestorKeyId: expected.attestor.keyId,
      attestorKeyFingerprint: attestorFingerprint,
      subjectKeyId: claims.subjectKeyId,
      subjectKeyFingerprint: subjectFingerprint,
      role: claims.role,
      jti: claims.jti,
      notBefore: claims.nbf,
      expiresAt: claims.exp,
      verification: "signature_and_window" as const,
      trust: "not_evaluated" as const,
    }, "RoleAttestation.V1.AttestationFacts");
  });
}
