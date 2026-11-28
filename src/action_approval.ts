/**
 * Verify a signed approval of one exact host request revision.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-action-approval-v1.md
 * @module actionApproval
 */
import { digestEqual } from "#crypto";
import { assert, type Result } from "./error.js";
import { resolve, type Bounds } from "./bounds.js";
import { base64urlDecode } from "./base64url.js";
import { strUtf8 } from "./json.js";
import type { HistoricalPublicKey } from "./v1.js";
import type { ContentAssertionFacts, ContentAssertionProducer } from "./content_assertion.js";
import type { ContentAssertionFacts as Es256Facts } from "./content_assertion_es256.js";
import * as ca from "./content_assertion_stages.js";
import * as record from "./approval_record.js";
import { redactedRendering, staticRendering } from "./redact.js";

/** Published semantic profile identifier for the signed assertion. */
export const PROFILE = "bap-action-approval/1";

/** Independent record ceilings. Omit a field to use its profile maximum. */
export interface RecordBounds {
  /** Positive raw UTF-8 bytes per text field, at most 1,024. */
  readonly string_bytes?: number;
  /** Positive resource count, at most 4,096. */
  readonly resource_count?: number;
  /** Positive encoded record bytes, at most 65,536. */
  readonly record_bytes?: number;
}

/** Exact request details committed to canonical record bytes. */
export interface ApprovalRecord {
  /** Subject of the action. */
  readonly subject: string;
  /** Exact action to perform. */
  readonly action: string;
  /** Request identity, also the assertion's subject. */
  readonly requestId: string;
  /** Approver role claimed by the record. */
  readonly approverRole: string;
  /** Nonempty set in unsigned UTF-8 order. */
  readonly resources: readonly string[];
  /** Independently derived, raw 32-byte request revision digest. */
  readonly revisionDigest: Uint8Array;
}

/** Suite chosen from operation configuration. */
export type Suite = "eddsa" | "es256";

/** One enrolled issuer and its current eligible roles. */
export interface TrustedApprover {
  /** Enrolled issuer identifier. */
  readonly issuer: string;
  /** Historical raw public key and its validity window. */
  readonly key: HistoricalPublicKey;
  /** Unique current approver roles, possibly empty. */
  readonly roles: readonly string[];
}

/** Caller-admitted trust snapshot for one domain and suite. */
export interface TrustSnapshot {
  /** Configured trust domain. */
  readonly trustDomain: string;
  /** Configured content assertion suite. */
  readonly suite: Suite;
  /** Bounded provenance identifier established by the host. */
  readonly provenance: string;
  /** Trusted snapshot time in integer Unix seconds. */
  readonly asOf: number;
  /** Already enrolled entries with unique key IDs. */
  readonly entries: readonly TrustedApprover[];
}

/** Independent expected operation, trusted time, and verification bounds. */
export interface ApprovalContext {
  /** Independently configured trust domain. */
  readonly trustDomain: string;
  /** Executing host's audience identifier. */
  readonly audience: string;
  /** Host request identity. */
  readonly requestId: string;
  /** Current request revision digest, exactly 32 bytes. */
  readonly revisionDigest: Uint8Array;
  /** Expected subject. */
  readonly subject: string;
  /** Exact expected action. */
  readonly action: string;
  /** Exact expected resource set, in unsigned UTF-8 order. */
  readonly resources: readonly string[];
  /** Nonempty, unique approver roles eligible under host policy. */
  readonly roles: readonly string[];
  /** Explicit trusted integer Unix seconds. */
  readonly now: number;
  /** Maximum trusted-key snapshot age in seconds, inclusive. */
  readonly maxStaleness: number;
  /** Maximum signed lifetime from issuance in seconds, inclusive. */
  readonly maxLifetime: number;
  /** Optional maximum signed active window in seconds, inclusive. */
  readonly maxActive?: number;
  /** Content assertion limits. */
  readonly bounds: Bounds;
  /** Independent approval record limits. */
  readonly recordBounds: RecordBounds;
  /** Locally admitted snapshot. Its absence refuses verification. */
  readonly snapshot?: TrustSnapshot | null;
}

/** Verified claims bound to the exact request, with redacted default rendering. */
export interface VerifiedApprovalFacts<S extends Suite = Suite> {
  /** Configured suite that verified the assertion. */
  readonly suite: S;
  /** Caller-supplied domain matched to the enrolled snapshot. */
  readonly trustDomain: string;
  /** Decoded canonical record. */
  readonly record: ApprovalRecord;
  /** Verified content assertion facts for the selected suite. */
  readonly assertion: S extends "es256" ? Es256Facts : ContentAssertionFacts;
  /** Operational trust remains with the host. */
  readonly trust: "not_evaluated";
}

/** Value-free local failure codes, in verification precedence order. */
export type Diagnostic =
  | "invalid_context" | "trust_unavailable" | "stale_trust" | "malformed"
  | "unsupported_algorithm" | "unknown_key" | "bad_signature" | "key_window"
  | "record_mismatch" | "issuer_mismatch" | "audience_mismatch" | "request_mismatch"
  | "subject_mismatch" | "scope_mismatch" | "not_yet_valid" | "expired"
  | "lifetime_too_long" | "active_too_long" | "role_not_permitted";

/** Host-local verification result. */
export type VerificationResult<S extends Suite = Suite> =
  | {
      /** Successful verification. */
      readonly ok: true;
      /** Facts bound to the caller's expected request. */
      readonly value: VerifiedApprovalFacts<S>;
    }
  | {
      /** Failed verification. */
      readonly ok: false;
      /** Host-local diagnostic code. */
      readonly code: Diagnostic;
    };

/** Closed codes from synchronous host predicate checks. */
export type PredicateDiagnostic = "revoked_key" | "replayed" | "predicate_failed";

/** The host helper's verified facts or a value-free local failure code. */
export type ApprovalResult<S extends Suite = Suite> = VerificationResult<S> | {
  /** Failed host predicate check. */
  readonly ok: false;
  /** Host-local predicate outcome. */
  readonly code: PredicateDiagnostic;
};

/** A presenter-facing result containing only the closed outcome. */
export type PresenterResult = {
  /** Successful verification and predicate checks. */
  readonly ok: true;
} | {
  /** Closed refusal. */
  readonly ok: false;
  /** Uniform presenter-facing code. */
  readonly code: "invalid";
};

/** Read-only local replay query for the verified artifact identity. */
export type IsReplayed = (trustDomain: string, issuer: string, artifactId: string) => boolean;
/** Read-only local revocation query for the admitted entry and verified fingerprint. */
export type IsRevoked = (entry: TrustedApprover, fingerprint: Uint8Array) => boolean;

const PROFILE_DIGEST = "fkT3MhfNJQN4OezCWDfehKrTZzYmubElyUyX6ZZ_oes";

/**
 * The frozen descriptor's raw 32-byte digest. Each call returns an owned copy.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa } from "@bounded-authority-protocol/verifier";
 * assert.equal(aa.profileDigest().length, 32);
 * ```
 */
export function profileDigest(): Uint8Array {
  return base64urlDecode(strUtf8(PROFILE_DIGEST));
}

/**
 * Encode a bounded approval record. Pass true to sort and deduplicate authoring resources.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa } from "@bounded-authority-protocol/verifier";
 * const encoded = aa.encodeRecord({
 *   subject: "document-1", action: "read", requestId: "read-1", approverRole: "reviewer",
 *   resources: ["title", "summary", "summary"], revisionDigest: new Uint8Array(32),
 * }, undefined, {}, true);
 * assert.ok(encoded.ok);
 * ```
 */
export function encodeRecord(value: ApprovalRecord, bounds?: Bounds, recordBounds: RecordBounds = {}, canonicalize = false): Result<Uint8Array> {
  return closed(() => {
    const b = ca.bounded(bounds);
    return record.encode(value, b, record.limits(b, recordBounds), canonicalize);
  });
}

/**
 * Decode exact canonical record bytes and return raw revision digest bytes.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa } from "@bounded-authority-protocol/verifier";
 * assert.deepEqual(aa.decodeRecord(new Uint8Array()), {ok: false});
 * ```
 */
export function decodeRecord(value: Uint8Array, bounds?: Bounds, recordBounds: RecordBounds = {}): Result<ApprovalRecord> {
  return closed(() => {
    const b = ca.bounded(bounds);
    return record.decode(value, b, record.limits(b, recordBounds));
  });
}

function closed<T>(fn: () => T): Result<T> {
  try { return {ok: true, value: fn()}; } catch { return {ok: false}; }
}

function failure<C extends string>(code: C): {readonly ok: false; readonly code: C} {
  return staticRendering({ok: false as const, code}, () => `{:error, :${code}}`, ["ok", "code"]);
}

function success<S extends Suite>(value: VerifiedApprovalFacts<S>) {
  return staticRendering({ok: true as const, value}, () => `{:ok, ${String(value)}}`, ["ok"]);
}

function roles(value: readonly string[], b: record.Limits, required: boolean): Set<string> {
  assert(Array.isArray(value) && (!required || value.length > 0), "role set");
  const names = new Set<string>();
  for (const role of value) {
    record.scalar(role, b.stringBytes);
    assert(!names.has(role), "unique roles");
    names.add(role);
  }
  return names;
}

function cap(value: unknown, b: Bounds): asserts value is number {
  ca.integer(value, b);
  assert(value >= 0, "nonnegative time cap");
}

function preflight(context: ApprovalContext) {
  ca.object(context);
  const {
    bounds: suppliedBounds, recordBounds, trustDomain, audience, requestId, revisionDigest,
    subject, action, resources: suppliedResources, roles: suppliedRoles, now, maxStaleness, maxLifetime, maxActive,
  } = context;
  assert(suppliedBounds !== undefined, "explicit bounds");
  const bounds = ca.bounded(suppliedBounds), limits = record.limits(bounds, recordBounds);
  record.scalar(trustDomain, resolve(bounds, "identifier_bytes"));
  ca.identifier(audience, bounds);
  record.requestId(requestId, limits, bounds);
  ca.bytes(revisionDigest, 32);
  assert(revisionDigest.buffer instanceof ArrayBuffer, "borrowed revision bytes");
  record.scalar(subject, limits.stringBytes);
  record.scalar(action, limits.stringBytes);
  const resources = record.resources(suppliedResources, limits, false);
  const expectedRoles = roles(suppliedRoles, limits, true);
  ca.integer(now, bounds);
  cap(maxStaleness, bounds);
  cap(maxLifetime, bounds);
  if (maxActive !== undefined || Object.hasOwn(context, "maxActive")) cap(maxActive, bounds);
  return {
    bounds, limits, expectedRoles,
    context: {trustDomain, audience, requestId, revisionDigest, subject, action, resources, now, maxStaleness, maxLifetime, maxActive},
  };
}

function snapshot(value: ApprovalContext["snapshot"], trustDomain: string, suite: ca.Suite, name: Suite, bounds: Bounds, limits: record.Limits) {
  ca.object(value);
  const {trustDomain: domain, suite: selectedSuite, provenance, asOf, entries} = value;
  assert(domain === trustDomain && selectedSuite === name, "snapshot domain and suite");
  record.scalar(provenance, resolve(bounds, "identifier_bytes"));
  ca.integer(asOf, bounds);
  assert(Array.isArray(entries), "snapshot entries");
  const keys = new Map<string, {entry: TrustedApprover; roles: Set<string>; fingerprint: Uint8Array}>();
  for (const supplied of entries as readonly TrustedApprover[]) {
    ca.object(supplied);
    const {key: suppliedKey, issuer, roles: suppliedRoles} = supplied;
    ca.object(suppliedKey);
    assert(Object.keys(suppliedKey).length === 4 &&
      ["keyId", "publicKey", "validFrom", "validBefore"].every(k => Object.hasOwn(suppliedKey, k)), "historical key fields");
    const {keyId, publicKey, validFrom, validBefore} = suppliedKey;
    const key = {keyId, publicKey, validFrom, validBefore};
    ca.validateHistoricalKey(key, bounds, suite);
    assert(publicKey.buffer instanceof ArrayBuffer, "borrowed key bytes");
    ca.identifier(issuer, bounds);
    const names = roles(suppliedRoles, limits, false);
    const entry = {issuer, key, roles: [...names]};
    assert(!keys.has(entry.key.keyId), "unique key IDs");
    keys.set(keyId, {entry, roles: names, fingerprint: ca.admittedFingerprint(suite, publicKey)});
  }
  return {keys, asOf};
}

function age(end: number, start: number): bigint {
  return BigInt(end) - BigInt(start);
}

function authenticatedCode(p: ContentAssertionProducer, encoded: Uint8Array, r: ApprovalRecord, context: ReturnType<typeof preflight>["context"],
  trusted: TrustedApprover, enrolled: Set<string>, expectedRoles: Set<string>): Diagnostic | null {
  if (!ca.keyWindow(p, trusted.key)) return "key_window";
  if (!digestEqual(p.contentDigest, ca.hashContent(encoded)) ||
      p.profile !== PROFILE || !digestEqual(p.profileDigest, profileDigest())) return "record_mismatch";
  if (p.iss !== trusted.issuer) return "issuer_mismatch";
  if (p.aud !== context.audience) return "audience_mismatch";
  if (r.requestId !== context.requestId || r.requestId !== p.sub ||
      !digestEqual(r.revisionDigest, context.revisionDigest)) return "request_mismatch";
  if (r.subject !== context.subject) return "subject_mismatch";
  if (r.action !== context.action || r.resources.length !== context.resources.length ||
      !r.resources.every((name, i) => name === context.resources[i])) return "scope_mismatch";
  const window = ca.currentWindow(p, context.now);
  if (window !== null) return window;
  if (age(p.exp, p.iat) > BigInt(context.maxLifetime)) return "lifetime_too_long";
  if (context.maxActive !== undefined && age(p.exp, p.nbf) > BigInt(context.maxActive)) return "active_too_long";
  if (!expectedRoles.has(r.approverRole) || !enrolled.has(r.approverRole)) return "role_not_permitted";
  return null;
}

function verify<S extends Suite>(suite: ca.Suite, name: S, encoded: Uint8Array, compact: Uint8Array, supplied: ApprovalContext):
  {readonly ok: true; readonly value: VerifiedApprovalFacts<S>; readonly entry: TrustedApprover} | {readonly ok: false; readonly code: Diagnostic} {
  const expected = closed(() => preflight(supplied));
  if (!expected.ok) return failure("invalid_context");
  const {bounds, limits, expectedRoles, context} = expected.value;
  const trust = closed(() => snapshot(supplied.snapshot, context.trustDomain, suite, name, bounds, limits));
  if (!trust.ok) return failure("trust_unavailable");
  const staleness = age(context.now, trust.value.asOf);
  if (staleness < 0n || staleness > BigInt(context.maxStaleness)) return failure("stale_trust");

  const framed = closed(() => {
    assert(compact instanceof Uint8Array && compact.buffer instanceof ArrayBuffer, "borrowed compact bytes");
    const seg = ca.parseFraming(compact, bounds);
    return {seg, header: ca.parseHeader(seg.protectedBytes, bounds)};
  });
  if (!framed.ok) return failure("malformed");
  const {seg, header} = framed.value;
  if (!ca.admitsSuite(header, suite)) return failure("unsupported_algorithm");
  const payload = closed(() => {
    const claims = ca.parsePayload(seg.payloadBytes, header.keyId, bounds);
    record.requestId(claims.sub, limits, bounds);
    assert(encoded instanceof Uint8Array && encoded.buffer instanceof ArrayBuffer, "borrowed record bytes");
    return {claims, decoded: record.decode(encoded, bounds, limits)};
  });
  if (!payload.ok) return failure("malformed");
  const {claims, decoded} = payload.value;
  const trusted = trust.value.keys.get(header.keyId);
  if (trusted === undefined) return failure("unknown_key");
  if (!suite.verify(seg.signingInput, seg.signature, trusted.entry.key.publicKey)) return failure("bad_signature");

  const code = authenticatedCode(claims, encoded, decoded, context, trusted.entry, trusted.roles, expectedRoles);
  if (code !== null) return failure(code);
  const assertion = ca.assertionFacts(suite, claims, compact, trusted.fingerprint, redactedRendering);
  const value = redactedRendering({suite: name, trustDomain: context.trustDomain, record: decoded, assertion, trust: "not_evaluated"} as VerifiedApprovalFacts<S>, "ActionApproval.V1.VerifiedApprovalFacts");
  return {ok: true, value, entry: trusted.entry};
}

/**
 * Verify approval using the preselected Ed25519 suite. Borrow inputs unchanged for the synchronous call.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa, boundsMaximum } from "@bounded-authority-protocol/verifier";
 * const context: aa.ApprovalContext = {
 *   trustDomain: "access-review", audience: "document-host", requestId: "read-1",
 *   revisionDigest: new Uint8Array(32), subject: "document-1", action: "read",
 *   resources: ["summary"], roles: ["reviewer"], now: 10, maxStaleness: 0, maxLifetime: 20,
 *   bounds: boundsMaximum(), recordBounds: {},
 * };
 * assert.deepEqual(aa.verifyEddsa(new Uint8Array(), new Uint8Array(), context), {ok: false, code: "trust_unavailable"});
 * ```
 */
export function verifyEddsa(recordBytes: Uint8Array, compact: Uint8Array, context: ApprovalContext): VerificationResult<"eddsa"> {
  const result = verify(ca.EDDSA, "eddsa", recordBytes, compact, context);
  return result.ok ? success(result.value) : result;
}

/**
 * Verify approval using the preselected ES256 suite. Borrow inputs unchanged for the synchronous call.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa, boundsMaximum } from "@bounded-authority-protocol/verifier";
 * const context: aa.ApprovalContext = {
 *   trustDomain: "access-review", audience: "document-host", requestId: "read-1",
 *   revisionDigest: new Uint8Array(32), subject: "document-1", action: "read",
 *   resources: ["summary"], roles: ["reviewer"], now: 10, maxStaleness: 0, maxLifetime: 20,
 *   bounds: boundsMaximum(), recordBounds: {},
 * };
 * assert.deepEqual(aa.verifyEs256(new Uint8Array(), new Uint8Array(), context), {ok: false, code: "trust_unavailable"});
 * ```
 */
export function verifyEs256(recordBytes: Uint8Array, compact: Uint8Array, context: ApprovalContext): VerificationResult<"es256"> {
  const result = verify(ca.ES256, "es256", recordBytes, compact, context);
  return result.ok ? success(result.value) : result;
}

function withPredicates<S extends Suite>(suite: ca.Suite, name: S, encoded: Uint8Array, compact: Uint8Array,
  context: ApprovalContext, isReplayed: IsReplayed, isRevoked: IsRevoked): ApprovalResult<S> {
  const verified = verify(suite, name, encoded, compact, context);
  if (!verified.ok) return verified;
  const {assertion, trustDomain} = verified.value;
  const outcome = closed<PredicateDiagnostic | null>(() => {
    const revoked = isRevoked(verified.entry, assertion.attestorKeyFingerprint.slice());
    if (revoked === true) return "revoked_key";
    if (revoked !== false) return "predicate_failed";
    const replayed = isReplayed(trustDomain, assertion.iss, assertion.jti);
    if (replayed === true) return "replayed";
    if (replayed !== false) return "predicate_failed";
    return null;
  });
  if (!outcome.ok) return failure("predicate_failed");
  if (outcome.value !== null) return failure(outcome.value);
  return staticRendering({ok: true as const, value: verified.value}, () => "#BoundedAuthorityProtocol.ActionApproval.V1.Approved<redacted>", ["ok"]);
}

/**
 * Verify Ed25519 approval, then query local revocation and replay state in that order.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa, boundsMaximum } from "@bounded-authority-protocol/verifier";
 * const context: aa.ApprovalContext = {
 *   trustDomain: "access-review", audience: "document-host", requestId: "read-1",
 *   revisionDigest: new Uint8Array(32), subject: "document-1", action: "read",
 *   resources: ["summary"], roles: ["reviewer"], now: 10, maxStaleness: 0, maxLifetime: 20,
 *   bounds: boundsMaximum(), recordBounds: {},
 * };
 * const uncalled = () => { assert.fail("predicates run only after pure verification"); };
 * const result = aa.verifyEddsaWithPredicates(new Uint8Array(), new Uint8Array(), context, uncalled, uncalled);
 * assert.deepEqual(result, {ok: false, code: "trust_unavailable"});
 * ```
 */
export function verifyEddsaWithPredicates(recordBytes: Uint8Array, compact: Uint8Array, context: ApprovalContext,
  isReplayed: IsReplayed, isRevoked: IsRevoked): ApprovalResult<"eddsa"> {
  return withPredicates(ca.EDDSA, "eddsa", recordBytes, compact, context, isReplayed, isRevoked);
}

/**
 * Verify ES256 approval, then query local revocation and replay state in that order.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa, boundsMaximum } from "@bounded-authority-protocol/verifier";
 * const context: aa.ApprovalContext = {
 *   trustDomain: "access-review", audience: "document-host", requestId: "read-1",
 *   revisionDigest: new Uint8Array(32), subject: "document-1", action: "read",
 *   resources: ["summary"], roles: ["reviewer"], now: 10, maxStaleness: 0, maxLifetime: 20,
 *   bounds: boundsMaximum(), recordBounds: {},
 * };
 * const uncalled = () => { assert.fail("predicates run only after pure verification"); };
 * const result = aa.verifyEs256WithPredicates(new Uint8Array(), new Uint8Array(), context, uncalled, uncalled);
 * assert.deepEqual(result, {ok: false, code: "trust_unavailable"});
 * ```
 */
export function verifyEs256WithPredicates(recordBytes: Uint8Array, compact: Uint8Array, context: ApprovalContext,
  isReplayed: IsReplayed, isRevoked: IsRevoked): ApprovalResult<"es256"> {
  return withPredicates(ca.ES256, "es256", recordBytes, compact, context, isReplayed, isRevoked);
}

/**
 * Project the same closed failure for every presenter-facing path.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { actionApproval as aa } from "@bounded-authority-protocol/verifier";
 * assert.deepEqual(aa.presenterResult({ok: false, code: "unknown_key"}), {ok: false, code: "invalid"});
 * ```
 */
export function presenterResult(result: ApprovalResult): PresenterResult {
  return result.ok ? Object.freeze({ok: true}) : failure("invalid");
}
