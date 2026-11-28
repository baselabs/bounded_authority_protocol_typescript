/**
 * The bap-holder-custody-attestation/1 profile describes custody of a distinct Ed25519 holder key
 * during a bounded window. The host supplies the trusted attestor, expected holder and time.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-holder-custody-attestation-v1.md
 * @module holderCustodyAttestation
 */
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { resolve, type Bounds } from "./bounds.js";
import { assembleSegments, type SigningInput } from "./compact.js";
import {
  bounded, bytes, checkAssemblyBounds, equal, exact, identifier, int, integer, kid, object,
  parseFraming, parseHeader, string,
} from "./content_assertion_stages.js";
import { acceptablePublicKey, sha256, verifyStrict } from "./ed25519.js";
import { assert, trying, type Result } from "./error.js";
import { jcsEncode } from "./jcs.js";
import { jsonDecode, strUtf8, type Tagged } from "./json.js";
import { jwkEncodePublic } from "./jwk.js";
import { redacted } from "./redact.js";
import type { HistoricalPublicKey } from "./v1.js";

const TYPE = "ba+holder-custody-attestation";
const KIND = "holder_custody_attestation";
const PAYLOAD = ["v", "jti", "key_id", "public_key", "custody_class", "nbf", "exp"];

/** The holder holds its own key (standard) or an operator holds it under a non-exporting handle (hosted). */
export type CustodyClass = "standard" | "hosted";

/** Claims for an externally signed holder custody attestation. */
export interface AttestationProducer {
  /** Protected attestor key ID. */
  readonly keyId: string;
  /** Attestation identifier, a bounded StringOrURI. */
  readonly jti: string;
  /** Holder key ID. */
  readonly subjectKeyId: string;
  /** Raw 32-byte Ed25519 holder public key. */
  readonly subjectPublicKey: Uint8Array;
  /** Signed custody class. */
  readonly custodyClass: CustodyClass;
  /** Inclusive window start in integer Unix seconds. */
  readonly notBefore: number;
  /** Exclusive window end in integer Unix seconds. */
  readonly expiresAt: number;
}

/** Caller-selected verification inputs, including an independently supplied holder binding. */
export interface ExpectedAttestation {
  /** Already-trusted Ed25519 key and its half-open validity window. Use null for an unbounded end. */
  readonly attestor: HistoricalPublicKey;
  /** Expected holder key ID. */
  readonly subjectKeyId: string;
  /** Expected raw 32-byte Ed25519 holder public key. */
  readonly subjectPublicKey: Uint8Array;
  /** Evaluation time in integer Unix seconds. */
  readonly now: number;
  /** Optional limits that only tighten the profile maxima. */
  readonly bounds?: Bounds;
}

/** Diagnostic claims from a bounded decode. Treat them as unverified. */
export interface AttestationDecoded extends AttestationProducer {
  /** Wire version. */
  readonly version: 1;
  /** Decode has evaluated the structure only. */
  readonly verification: "not_evaluated";
}

/** Redacted facts produced by signature, holder binding and window verification. */
export interface AttestationFacts {
  /** Wire version. */
  readonly version: 1;
  /** Attestor key ID. */
  readonly attestorKeyId: string;
  /** Raw RFC 7638 SHA-256 thumbprint of the attestor key. */
  readonly attestorKeyFingerprint: Uint8Array;
  /** Holder key ID. */
  readonly subjectKeyId: string;
  /** Raw RFC 7638 SHA-256 thumbprint of the holder key. */
  readonly subjectKeyFingerprint: Uint8Array;
  /** Signed custody class. */
  readonly custodyClass: CustodyClass;
  /** Signed attestation identifier. */
  readonly jti: string;
  /** Inclusive window start in integer Unix seconds. */
  readonly notBefore: number;
  /** Exclusive window end in integer Unix seconds. */
  readonly expiresAt: number;
  /** The signature, supplied binding and window checks succeeded. */
  readonly verification: "signature_and_window";
  /** The host decides trust and policy. */
  readonly trust: "not_evaluated";
}

function publicKey(value: unknown, bounds: Bounds): asserts value is Uint8Array {
  bytes(value, 32);
  assert(value.length <= resolve(bounds, "public_key_bytes") && acceptablePublicKey(value), "Ed25519 public key");
}

function validateClaims(claims: Omit<AttestationProducer, "custodyClass"> & {readonly custodyClass: unknown},
  bounds: Bounds): asserts claims is AttestationProducer {
  kid(claims.keyId, bounds);
  identifier(claims.jti, bounds);
  kid(claims.subjectKeyId, bounds);
  publicKey(claims.subjectPublicKey, bounds);
  assert(claims.custodyClass === "standard" || claims.custodyClass === "hosted", "custody class");
  integer(claims.notBefore, bounds);
  integer(claims.expiresAt, bounds);
  assert(claims.notBefore < claims.expiresAt, "attestation window");
}

function parseClaims(headerBytes: Uint8Array, payloadBytes: Uint8Array, bounds: Bounds): AttestationProducer {
  const {alg, typ, keyId} = parseHeader(headerBytes, bounds);
  assert(alg === "EdDSA" && typ === TYPE, "protected profile");
  const payload = exact(jsonDecode(payloadBytes, bounds), PAYLOAD);
  assert(int(payload.v.get("v")) === 1, "attestation version");
  assert(equal(jcsEncode(payload, bounds), payloadBytes), "canonical payload");
  const encodedKey = payload.v.get("public_key");
  assert(encodedKey?.t === "string" && encodedKey.v.length <= resolve(bounds, "encoded_segment_bytes"), "encoded holder key");
  const claims = {
    keyId,
    jti: string(payload.v.get("jti")),
    subjectKeyId: string(payload.v.get("key_id")),
    subjectPublicKey: base64urlDecode(encodedKey.v, resolve(bounds, "decoded_segment_bytes")),
    custodyClass: string(payload.v.get("custody_class")),
    notBefore: int(payload.v.get("nbf")),
    expiresAt: int(payload.v.get("exp")),
  };
  validateClaims(claims, bounds);
  return claims;
}

function parse(compact: Uint8Array, bounds: Bounds) {
  const segments = parseFraming(compact, bounds);
  return {segments, claims: parseClaims(segments.protectedBytes, segments.payloadBytes, bounds)};
}

const text = (value: string): Tagged => ({t: "string", v: strUtf8(value)});
const numeric = (value: number): Tagged => ({t: "int", v: value});

/**
 * Produces canonical protected and payload segments for external Ed25519 signing.
 * Sign the ASCII segments joined by a single period. Invalid inputs return `{ok: false}`.
 */
export function attestationSigningInput(attestation: AttestationProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
    object(attestation);
    const {keyId, jti, subjectKeyId, subjectPublicKey, custodyClass, notBefore, expiresAt} = attestation;
    const b = bounded(bounds);
    validateClaims({keyId, jti, subjectKeyId, subjectPublicKey, custodyClass, notBefore, expiresAt}, b);
    const header = new Map([["alg", text("EdDSA")], ["kid", text(keyId)], ["typ", text(TYPE)]]);
    const payload = new Map<string, Tagged>([
      ["v", numeric(1)], ["jti", text(jti)], ["key_id", text(subjectKeyId)],
      ["public_key", {t: "string", v: base64urlEncode(subjectPublicKey)}],
      ["custody_class", text(custodyClass)], ["nbf", numeric(notBefore)], ["exp", numeric(expiresAt)],
    ]);
    const headerBytes = jcsEncode({t: "object", v: header}, b);
    const payloadBytes = jcsEncode({t: "object", v: payload}, b);
    jsonDecode(headerBytes, b);
    jsonDecode(payloadBytes, b);
    const protectedSegment = base64urlEncode(headerBytes);
    const payloadSegment = base64urlEncode(payloadBytes);
    checkAssemblyBounds(protectedSegment.length, payloadSegment.length, b);
    return {kind: KIND, protectedSegment, payloadSegment};
  });
}

/**
 * Assembles a compact JWS from the signing input and a canonical Ed25519 signature.
 * Assembly checks encoding and structure. Invalid inputs return `{ok: false}`.
 */
export function assembleAttestationCompact(input: SigningInput, signature: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return trying(() => {
    object(input);
    const {kind, protectedSegment, payloadSegment} = input;
    assert(kind === KIND, "signing kind");
    assert(protectedSegment instanceof Uint8Array && payloadSegment instanceof Uint8Array, "signing segments");
    bytes(signature, 64);
    const b = bounded(bounds);
    checkAssemblyBounds(protectedSegment.length, payloadSegment.length, b);
    const result = assembleSegments({kind, protectedSegment, payloadSegment}, signature);
    assert(result.ok, "signature canonicality");
    parse(result.value, b);
    return result.value;
  });
}

/** Decodes bounded, structurally valid custody claims. Invalid inputs return `{ok: false}`. */
export function decodeAttestation(compact: Uint8Array, bounds?: Bounds): Result<AttestationDecoded> {
  return trying(() => ({
    ...parse(compact, bounded(bounds)).claims,
    version: 1,
    verification: "not_evaluated",
  }));
}

function fingerprint(key: Uint8Array, bounds: Bounds): Uint8Array {
  const preimage = jwkEncodePublic(key);
  assert(preimage.length <= resolve(bounds, "decoded_segment_bytes"), "JWK byte bound");
  jsonDecode(preimage, bounds);
  return sha256(preimage);
}

/**
 * Verifies the Ed25519 signature, the expected holder binding, separation of attestor and holder,
 * and both validity windows. Returns redacted facts or the closed failure `{ok: false}`.
 */
export function verifyAttestation(compact: Uint8Array, expected: ExpectedAttestation): Result<AttestationFacts> {
  return trying(() => {
    object(expected);
    const {attestor, subjectKeyId, subjectPublicKey, now, bounds} = expected;
    const b = bounded(bounds);
    object(attestor);
    const {keyId, publicKey: attestorPublicKey, validFrom, validBefore} = attestor;
    kid(keyId, b);
    publicKey(attestorPublicKey, b);
    integer(validFrom, b);
    if (validBefore !== null) {
      integer(validBefore, b);
      assert(validFrom < validBefore, "attestor window");
    }
    kid(subjectKeyId, b);
    publicKey(subjectPublicKey, b);
    integer(now, b);

    const {claims, segments} = parse(compact, b);
    assert(claims.keyId === keyId && claims.subjectKeyId === subjectKeyId, "key ID binding");
    assert(equal(claims.subjectPublicKey, subjectPublicKey), "holder key binding");
    assert(keyId !== subjectKeyId, "self-attestation key ID");
    const attestorKeyFingerprint = fingerprint(attestorPublicKey, b);
    const subjectKeyFingerprint = fingerprint(subjectPublicKey, b);
    assert(!equal(attestorKeyFingerprint, subjectKeyFingerprint), "self-attestation thumbprint");
    const {custodyClass, jti, notBefore, expiresAt} = claims;
    assert(notBefore >= validFrom && (validBefore === null || expiresAt <= validBefore), "attestor window containment");
    assert(notBefore <= now && now < expiresAt, "current attestation window");
    assert(verifyStrict(segments.signingInput, segments.signature, attestorPublicKey), "attestation signature");
    return redacted({
      version: 1 as const, attestorKeyId: keyId, attestorKeyFingerprint, subjectKeyId, subjectKeyFingerprint,
      custodyClass, jti, notBefore, expiresAt, verification: "signature_and_window" as const, trust: "not_evaluated" as const,
    }, "HolderCustodyAttestation.V1.AttestationFacts");
  });
}
