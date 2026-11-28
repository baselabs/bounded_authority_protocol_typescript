/**
 * P-256 content assertions under the explicitly selected ES256 sibling profile.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-es256-v1.md
 * @module contentAssertionEs256
 */
import type { Result } from "./error.js";
import type { SigningInput } from "./compact.js";
import type { HistoricalPublicKey } from "./v1.js";
import type { Bounds } from "./bounds.js";
import type * as ca from "./content_assertion.js";
import * as stages from "./content_assertion_stages.js";

/** The unsigned claim shape shared by both content assertion profiles. */
export type ContentAssertionProducer = ca.ContentAssertionProducer;
/** The expected context with a raw 65-byte uncompressed SEC1 P-256 attestor key. */
export interface ExpectedContentAssertion extends ca.ExpectedContentAssertion {
  /** Enrolled key with a raw 65-byte uncompressed point and historical validity window. */
  readonly attestor: HistoricalPublicKey;
}
/** The parsed assertion claims, with verification unevaluated. */
export type DecodedContentAssertion = ca.DecodedContentAssertion;
/** Verified P-256 assertion facts with ES256 profile provenance. */
export interface ContentAssertionFacts extends ca.ContentAssertionFacts {
  /** ES256 profile provenance preserved by cloning or explicit field projection. */
  readonly suite: "es256";
}

/**
 * Produce canonical signing segments for an external ES256 signer.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { contentAssertionEs256 as ca } from "@bounded-authority-protocol/verifier";
 * const result = ca.assertionSigningInput({
 *   attestorKeyId: "operations", jti: "artifact-1", iss: "registry", aud: "gateway", sub: "routes",
 *   profile: "routing-schema", profileDigest: new Uint8Array(32), contentDigest: new Uint8Array(32),
 *   gen: 1, prev: new Uint8Array(32), iat: 10, nbf: 10, exp: 20,
 * });
 * assert.ok(result.ok);
 * assert.equal(result.value.kind, "content_assertion_es256");
 * ```
 */
export function assertionSigningInput(input: ContentAssertionProducer, bounds?: Bounds): Result<SigningInput> {
  return stages.assertionSigningInput(stages.ES256, input, bounds);
}

/**
 * Assemble canonical segments and a raw 64-byte low-S signature without checking its equation.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { contentAssertionEs256 as ca } from "@bounded-authority-protocol/verifier";
 * const rejected = ca.assembleCompact({
 *   kind: "content_assertion", protectedSegment: new Uint8Array(), payloadSegment: new Uint8Array(),
 * }, new Uint8Array(64));
 * assert.deepEqual(rejected, {ok: false});
 * ```
 */
export function assembleCompact(input: SigningInput, signature: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return stages.assembleCompact(stages.ES256, input, signature, bounds);
}

/**
 * Decode canonical ES256 assertion structure and signature framing.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { contentAssertionEs256 as ca } from "@bounded-authority-protocol/verifier";
 * assert.deepEqual(ca.decodeAssertion(new Uint8Array()), {ok: false});
 * ```
 */
export function decodeAssertion(compact: Uint8Array, bounds?: Bounds): Result<DecodedContentAssertion> {
  return stages.decodeAssertion(stages.ES256, compact, bounds);
}

/**
 * Hash exact external content bytes in the shared BAP1-CONTENT domain.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { contentAssertionEs256 as ca } from "@bounded-authority-protocol/verifier";
 * const digest = ca.contentDigest(new Uint8Array([1]));
 * assert.ok(digest.ok);
 * assert.equal(digest.value.length, 32);
 * ```
 */
export function contentDigest(content: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return stages.contentDigest(content, bounds);
}

/**
 * Hash the exact compact after ES256 structural validation.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { contentAssertionEs256 as ca } from "@bounded-authority-protocol/verifier";
 * assert.deepEqual(ca.assertionDigest(new Uint8Array([1])), {ok: false});
 * ```
 */
export function assertionDigest(compact: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return stages.assertionDigest(stages.ES256, compact, bounds);
}

/**
 * Verify the signature, expected identities and digests, and all validity windows.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { contentAssertionEs256 as ca, boundsMaximum } from "@bounded-authority-protocol/verifier";
 * const digest = new Uint8Array(32);
 * const rejected = ca.verifyAssertion(new Uint8Array(), {
 *   attestor: {keyId: "operations", publicKey: new Uint8Array(65), validFrom: 0, validBefore: null},
 *   issuer: "registry", audience: "gateway", subject: "routes", profile: "routing-schema",
 *   profileDigest: digest, contentDigest: digest, now: 10, bounds: boundsMaximum(),
 * });
 * assert.deepEqual(rejected, {ok: false});
 * ```
 */
export function verifyAssertion(compact: Uint8Array, expected: ExpectedContentAssertion): Result<ContentAssertionFacts> {
  return stages.verifyAssertion(stages.ES256, compact, expected) as Result<ContentAssertionFacts>;
}

/**
 * Verify one lineage step between two ES256 assertion facts values.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { contentAssertionEs256 as ca, boundsMaximum } from "@bounded-authority-protocol/verifier";
 * // Check a lineage step only after both compacts verify in this profile.
 * function follows(previous: ca.ContentAssertionFacts, next: ca.ContentAssertionFacts): boolean {
 *   return ca.verifySuccessor(previous, next, boundsMaximum()).ok;
 * }
 * assert.equal(typeof follows, "function");
 * ```
 */
export function verifySuccessor(previous: ContentAssertionFacts, next: ContentAssertionFacts, bounds: Bounds): Result<void> {
  return stages.verifySuccessor(stages.ES256, previous, next, bounds);
}
