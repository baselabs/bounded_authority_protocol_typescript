import { fail, assert, trying, type Result } from "./error.js";
import { parseCompact, assembleSegments, type SigningInput } from "./compact.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "./json.js";
import { jcsEncode } from "./jcs.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { jwkFromPublicKey, thumbprintRaw } from "./jwk.js";
import { importPublicKey, ed25519Verify } from "./ed25519.js";
import { resolve, coerceBounds, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";
import type { HistoricalPublicKey } from "./v1.js";

// The bap-role-attestation/1 sibling profile (ADR 0036; spec/bap-role-attestation-v1.md) — a
// standalone, grant-unbound compact JWS in which an attestor key binds a subject key to a role
// for a bounded window. It single-sources the contract-major-1 primitives (Ed25519/EdDSA under
// BAP1-Ed25519-SHA256, the tagged JSON/JCS/base64url/JWK machinery — this module imports the
// same primitive layers src/v1.ts builds on) and is parsed by no contract-major profile: every
// major rejects its `ba+role-attestation` typ, and it rejects every major typ, with the single
// closed error. Profile selection lives in this separately named namespace — never inferred
// from bytes, context, or a failed verification (REQ-RA1-CORE-no-inference-fallback).
//
// Derived from the normative sources alone (ADR 0014's no-derivation bar): the profile spec +
// the certified 40-case corpus at conformance/corpus-role-attestation.
//
// Verification is not authority (AGENTS rule 1): facts carry trust "not_evaluated" and NO
// authorization marker — the anchor-facts posture ADR 0036 D5 fixes for this profile.

const ALG = "EdDSA";
const ATTESTATION_TYP = "ba+role-attestation";
const VERSION = 1;
const ROLES = ["issuer", "holder"] as const;

// --- public types (spec §3 expected context; ADR 0036 D4/D5) ---

// The attestor context is the anchor's HistoricalPublicKey shape: key id, raw 32-byte public
// key, and its own [valid_from, valid_before) validity window (valid_before null = unbounded).
export type AttestorKey = HistoricalPublicKey;

export interface ExpectedAttestation {
  readonly attestor: AttestorKey;
  readonly subjectKeyId: string;
  readonly subjectPublicKey: Uint8Array; // raw 32
  readonly now: number; // integer; the SDK reads no clock
  readonly bounds?: Bounds;
}

// The producer input (external-signature-only: the package owns no signer and accepts no
// private key or signing callback — REQ-RA1-API-no-signer).
export interface AttestationProducer {
  readonly keyId: string; // the attestor key id (kid rules)
  readonly jti: string; // non-empty bounded StringOrUri (grant jti rules)
  readonly subjectKeyId: string; // kid rules
  readonly subjectPublicKey: Uint8Array; // raw 32
  readonly role: "issuer" | "holder";
  readonly notBefore: number; // integer
  readonly expiresAt: number; // integer; the acceptance window is [notBefore, expiresAt)
}

// Bounded decode result: value-bearing, no trust evaluation (the decode surface mirrors
// decodeGrant's posture — verification: "not_evaluated").
export interface AttestationDecoded {
  readonly keyId: string;
  readonly jti: string;
  readonly subjectKeyId: string;
  readonly subjectPublicKey: Uint8Array; // raw 32
  readonly role: string;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly verification: "not_evaluated";
}

// AttestationFacts (ADR 0036 D5): the enumerated field set is the facts contract — the
// anchor-facts posture (verification signature_and_window, trust not_evaluated, NO
// authorization marker; fingerprints are RFC 7638 Ed25519 thumbprints derived internally;
// facts carry no raw key material, no signature, and no decision).
export interface AttestationFacts {
  readonly version: 1;
  readonly attestorKeyId: string;
  readonly attestorKeyFingerprint: Uint8Array; // raw 32
  readonly subjectKeyId: string;
  readonly subjectKeyFingerprint: Uint8Array; // raw 32
  readonly role: string;
  readonly jti: string;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly verification: "signature_and_window";
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

// StringOrURI (RFC 7519 §2): well-formed, non-empty, ≤ identifier_bytes.
function isWellFormed(s: string): boolean {
  const anyStr = s as string & { isWellFormed?: () => boolean };
  return typeof anyStr.isWellFormed === "function"
    ? anyStr.isWellFormed()
    : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

function isStringOrUri(s: string): boolean {
  if (!isWellFormed(s)) return false;
  const colon = s.indexOf(":");
  if (colon === -1) return true;
  const scheme = s.slice(0, colon);
  if (!/^[A-Za-z][A-Za-z0-9+\-.]*$/.test(scheme)) return false;
  if (!/^(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=])*$/.test(s)) return false;
  const rest = s.slice(colon + 1);
  if (!rest.startsWith("//")) return true;
  return validUriAuthority(rest.slice(2).split(/[/?#]/, 1)[0]!);
}

function validUriAuthority(authority: string): boolean {
  const at = authority.indexOf("@");
  const hostport = at === -1 ? authority : authority.slice(at + 1);
  if (hostport.includes("@")) return false;
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    if (close === -1) return false;
    if (!/^[0-9A-Fa-f:.]+$/.test(hostport.slice(1, close))) return false;
    const suffix = hostport.slice(close + 1);
    return suffix === "" || /^:\d*$/.test(suffix);
  }
  if (hostport.includes("[") || hostport.includes("]")) return false;
  if ((hostport.match(/:/g) ?? []).length > 1) return false;
  const sep = hostport.lastIndexOf(":");
  return sep === -1 || /^\d*$/.test(hostport.slice(sep + 1));
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

// Protected header: exactly {alg, kid, typ}; JCS-canonical bytes (REQ-RA1-HEADER-closed-set,
// REQ-RA1-CLAIM-canonical — both segments must equal their RFC 8785 re-encoding).
function parseAttestationHeader(seg: ReturnType<typeof parseCompact>, bounds: Bounds): { kid: string } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "kid", "typ"], "attestation header");
  requireStringLit(h, "alg", ALG, "attestation header");
  requireStringLit(h, "typ", ATTESTATION_TYP, "attestation header");
  const kid = requireKidValue(h.v.get("kid"), "kid", bounds);
  if (!bytesEqual(jcsEncode(h, bounds), seg.protectedBytes)) fail("attestation header: canonical");
  return { kid };
}

// Payload: exactly {v, jti, key_id, public_key, role, nbf, exp} with the member rules of
// spec §2 — v an integer 1 (the tagged algebra's int tag rejects float lexemes like 1.0),
// jti under grant-jti StringOrUri rules, key_id under kid rules, public_key base64url of
// exactly 32 raw Ed25519 bytes, role in the closed {issuer, holder} set, integral nbf < exp
// (REQ-RA1-CLAIM-closed-required, -window, -canonical).
function parseAttestationPayload(seg: ReturnType<typeof parseCompact>, bounds: Bounds): AttestationClaims {
  const p = jsonDecode(seg.payloadBytes, bounds);
  requireObjectExact(p, ["exp", "jti", "key_id", "nbf", "public_key", "role", "v"], "attestation payload");
  const vV = p.v.get("v");
  if (!vV || vV.t !== "int" || vV.v !== VERSION) fail("attestation payload: v=1");
  const jti = requireStringOrUri(p.v.get("jti"), "jti", bounds);
  const subjectKeyId = requireKidValue(p.v.get("key_id"), "key_id", bounds);
  const subjectPublicKey = requireB64urlN(p.v.get("public_key"), "public_key", 32);
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

// Context validation before any deref: a null/wrong-typed struct fails closed as the single
// error, never a native TypeError (the cross-vendor #22 discipline). The attestor window
// endpoints and `now` are magnitude-bounded under integer_magnitude (2^53-1) and must be
// integers — the verifyHistoricalAnchor parity (v1.ts: the Rust round-4 fix); the sibling
// Python/Go legs shipped without it once and it was repaired the same day. A fractional
// `now` is verdict-load-bearing: the half-open window comparison alone would admit it.
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

// 1. attestation signing-input production (external signature only).
export function attestationSigningInput(attestation: AttestationProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
    if (attestation === null || typeof attestation !== "object") fail("attestation_signing_input: producer required");
    // Field types gate first (cross-vendor review m2): a non-string id or jti must reject with
    // the closed error, never coerce through TextEncoder ("null") or throw a TypeError.
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
    // Producer/consumer bounds agreement (the cross-vendor finding-4 class, transferred to
    // this surface): the EMITTED segments and projected compact must satisfy the same
    // caller-resolved limits the decoder enforces, and the emitted number lexemes must be
    // decodable — the producer must not mint bytes its own consumer rejects.
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

// 2. compact assembly from signing input and external signature — revalidates the protected
// header, payload member rules, segment bounds, and signature width under this profile before
// returning a compact artifact (REQ-RA1-API-assembly-revalidate; symmetry with decode/verify).
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

// 3. attestation decoding — bounded decode, no trust evaluation.
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

// 4. attestation verification — the citation surface
// (BoundedAuthorityProtocol.RoleAttestation.V1.verify_attestation/2). Pure function from
// caller-supplied bytes + caller-supplied trusted inputs and expected context; proves spec §3
// (1) closed sets + canonical bytes, (2) kid binding + Ed25519 signature under the attestor
// key, (3) subject binding byte-equality, (4) self-attestation rejection (thumbprint and key
// id legs), (5) window containment in the attestor key window (exp == valid_before is
// containment and accepts), (6) now in the half-open [nbf, exp). Single closed error.
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
    // Self-attestation (REQ-RA1-VERIFY-no-self-attestation): the attestor thumbprint MUST NOT
    // equal the subject thumbprint, and the attestor key id MUST NOT equal the subject key id —
    // each leg rejects on its own.
    const subjectFingerprint = thumbprintRaw(jwkFromPublicKey(claims.subjectPublicKey));
    if (bytesEqual(attestorFingerprint, subjectFingerprint)) fail("verify_attestation: self-attestation material");
    if (expected.attestor.keyId === claims.subjectKeyId) fail("verify_attestation: self-attestation key id");
    // Window containment (REQ-RA1-VERIFY-window-containment): nbf >= valid_from and, when the
    // attestor window is bounded, exp <= valid_before — a retired attestor key cannot backdate
    // an outliving attestation; exp == valid_before is containment and accepts (the half-open
    // now window already prevents acceptance at any instant the key no longer covers).
    if (claims.nbf < expected.attestor.validFrom) fail("verify_attestation: nbf containment");
    if (expected.attestor.validBefore !== null && claims.exp > expected.attestor.validBefore) {
      fail("verify_attestation: exp containment");
    }
    // now in [nbf, exp) (REQ-RA1-VERIFY-now-window).
    if (!(claims.nbf <= expected.now && expected.now < claims.exp)) fail("verify_attestation: now window");
    return {
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
    };
  });
}
