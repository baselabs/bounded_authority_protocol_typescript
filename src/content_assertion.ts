/**
 * The bap-content-assertion/1 sibling profile binds exact content and application-profile digests to a
 * signed assertion under an already-trusted Ed25519 attestor. Generation and predecessor digests
 * support explicit successor verification. The verifier fetches no content, interprets no application
 * schema and grants no authority.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#4-verification
 * @module contentAssertion
 */
// bap-content-assertion/1, specified by spec/bap-content-assertion-v1.md and its normative profile.
// Independent implementation from the public specification and corpus, using existing SDK primitives.
import type { Result } from "./error.js";
import type { SigningInput } from "./compact.js";
import type { Bounds } from "./bounds.js";
import type { HistoricalPublicKey } from "./v1.js";
import * as stages from "./content_assertion_stages.js";

/**
 * Unsigned digest-bound content assertion. Identifiers are bounded StringOrURI values. Generation one
 * uses an all-zero prev; later generations name a predecessor compact digest. Signing, schema
 * interpretation and lineage policy remain external.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#4-verification
 * @category Content assertions
 */
export interface ContentAssertionProducer {
  /** Attestor protected-header kid, 1 to 128 permitted ASCII bytes. */
  readonly attestorKeyId: string;
  /** Artifact StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly jti: string;
  /** Issuer StringOrURI claim, 1 to 512 UTF-8 bytes. */
  readonly iss: string;
  /** Audience StringOrURI claim, 1 to 512 UTF-8 bytes. */
  readonly aud: string;
  /** Subject StringOrURI claim, 1 to 512 UTF-8 bytes. */
  readonly sub: string;
  /** Application-profile StringOrURI, 1 to 512 UTF-8 bytes. The verifier does not interpret its schema. */
  readonly profile: string;
  /** Opaque caller-pinned 32-byte application-profile identity. BAP compares it without prescribing its construction. */
  readonly profileDigest: Uint8Array;
  /** Raw 32-byte contentDigest output using the BAP1-CONTENT domain separator. */
  readonly contentDigest: Uint8Array;
  /** Positive safe-integer generation. One starts a lineage; successors must increment by exactly one. */
  readonly gen: number;
  /** Raw 32-byte digest of the predecessor compact; all zeros at generation one. */
  readonly prev: Uint8Array;
  /** Issue timestamp in integer Unix seconds. */
  readonly iat: number;
  /** Inclusive assertion-validity lower endpoint in integer Unix seconds. */
  readonly nbf: number;
  /** Exclusive assertion-validity upper endpoint in integer Unix seconds; no clock skew applies. */
  readonly exp: number;
}
/**
 * Trusted attestor and independently expected identifiers, digests, time and limits for content
 * verification. The application computes and trusts content/profile bindings separately. Verification
 * fetches no content and infers no schema.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#4-verification
 * @category Content assertions
 */
export interface ExpectedContentAssertion {
  /** Already-trusted attestor public key and its half-open validity window. */
  readonly attestor: HistoricalPublicKey;
  /** Expected or verified issuer StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly issuer: string;
  /** Expected audience StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly audience: string;
  /** Independently expected subject StringOrURI, matched exactly. */
  readonly subject: string;
  /** Application-profile StringOrURI, 1 to 512 UTF-8 bytes. The verifier does not interpret its schema. */
  readonly profile: string;
  /** Opaque caller-pinned 32-byte application-profile identity. BAP compares it without prescribing its construction. */
  readonly profileDigest: Uint8Array;
  /** Raw 32-byte contentDigest output using the BAP1-CONTENT domain separator. */
  readonly contentDigest: Uint8Array;
  /** Host-supplied integer Unix seconds. The verifier reads no clock. */
  readonly now: number;
  /** Explicit resource bounds; use boundsMaximum() for the profile maxima. */
  readonly bounds: Bounds;
}
/**
 * Canonical content-assertion claims after bounded decoding without signature, time or
 * expected-context verification. This is a diagnostic view, never a trusted assertion.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#4-verification
 * @category Content assertions
 */
export interface DecodedContentAssertion extends ContentAssertionProducer {
  /** Content-assertion profile version 1, not the npm package version. */
  readonly version: 1;
  /** No cryptographic verification has run. Parsing alone establishes no trust or execution authority. */
  readonly verification: "not_evaluated";
}
/**
 * Content claims and compact digest after signature, window and expected-context checks. Trust remains
 * unevaluated. Successor verification checks lineage separately without reevaluating the predecessor
 * at the current time.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#4-verification
 * @category Content assertions
 */
export interface ContentAssertionFacts extends ContentAssertionProducer {
  /** Content-assertion profile version 1, not the npm package version. */
  readonly version: 1;
  /** Raw 32-byte RFC 7638 thumbprint of the attestor public key. */
  readonly attestorKeyFingerprint: Uint8Array;
  /** Raw 32-byte SHA-256 of the exact ASCII assertion compact, used for successor prev bindings. */
  readonly digest: Uint8Array;
  /** Completed verification stage only; conveys no key trust, replay reservation or execution authority. */
  readonly verification: "signature_and_window";
  /** Always not_evaluated. The caller owns trust selection and policy. */
  readonly trust: "not_evaluated";
}


/**
 * Builds the signing input of a `bap-content-assertion/1` assertion binding a content digest to
 * issuer, audience, subject, profile, generation and window.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#6-public-api-and-assembly
 * @returns Canonical protected and payload base64url segments for the content assertion in a success Result. Sign their exact dot-separated ASCII bytes externally. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { generateKeyPairSync, sign } from "node:crypto";
 * import { contentAssertion, sha256, strUtf8 } from "@bounded-authority-protocol/verifier";
 *
 * const content = contentAssertion.contentDigest(strUtf8("route table v12"));
 * assert.ok(content.ok);
 * const input = contentAssertion.assertionSigningInput({
 *   attestorKeyId: "ops-1", jti: "routes-12", iss: "https://ops.example", aud: "https://edge.example",
 *   sub: "routes:eu", profile: "urn:example:routes:2", profileDigest: sha256(strUtf8("routes schema 2")),
 *   contentDigest: content.value, gen: 1, prev: new Uint8Array(32), iat: 10, nbf: 10, exp: 20,
 * });
 * assert.ok(input.ok);
 * const signer = generateKeyPairSync("ed25519");
 * const signature = sign(null, Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), signer.privateKey);
 * const compact = contentAssertion.assembleCompact(input.value, signature);
 * assert.ok(compact.ok);
 *
 * const decoded = contentAssertion.decodeAssertion(compact.value);
 * assert.ok(decoded.ok);
 * assert.equal(decoded.value.sub, "routes:eu");
 * const digest = contentAssertion.assertionDigest(compact.value);
 * assert.ok(digest.ok);
 * assert.deepEqual(digest.value, sha256(compact.value));
 * assert.deepEqual(contentAssertion.contentDigest(new Uint8Array(0)), { ok: false }); // empty content
 * ```
 */
export function assertionSigningInput(p:ContentAssertionProducer,bounds?:Bounds):Result<SigningInput> {
  return stages.assertionSigningInput(stages.EDDSA,p,bounds);
}

/**
 * Joins a content-assertion signing input and a 64-byte signature into a compact JWS and re-parses
 * it. It does not verify the signature.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#6-public-api-and-assembly
 * @returns Exact ASCII compact JWS bytes in a success Result; no signature verification is performed. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { generateKeyPairSync, sign } from "node:crypto";
 * import { contentAssertion, sha256, strUtf8 } from "@bounded-authority-protocol/verifier";
 *
 * const content = contentAssertion.contentDigest(strUtf8("route table v12"));
 * assert.ok(content.ok);
 * const input = contentAssertion.assertionSigningInput({
 *   attestorKeyId: "ops-1", jti: "routes-12", iss: "https://ops.example", aud: "https://edge.example",
 *   sub: "routes:eu", profile: "urn:example:routes:2", profileDigest: sha256(strUtf8("routes schema 2")),
 *   contentDigest: content.value, gen: 1, prev: new Uint8Array(32), iat: 10, nbf: 10, exp: 20,
 * });
 * assert.ok(input.ok);
 * const signer = generateKeyPairSync("ed25519");
 * const signature = sign(null, Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), signer.privateKey);
 * const compact = contentAssertion.assembleCompact(input.value, signature);
 * assert.ok(compact.ok);
 *
 * const decoded = contentAssertion.decodeAssertion(compact.value);
 * assert.ok(decoded.ok);
 * assert.equal(decoded.value.sub, "routes:eu");
 * const digest = contentAssertion.assertionDigest(compact.value);
 * assert.ok(digest.ok);
 * assert.deepEqual(digest.value, sha256(compact.value));
 * assert.deepEqual(contentAssertion.contentDigest(new Uint8Array(0)), { ok: false }); // empty content
 * ```
 */
export function assembleCompact(input:SigningInput,signature:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return stages.assembleCompact(stages.EDDSA,input,signature,bounds);
}

/**
 * Parses and validates a content assertion's structure without checking its signature or any
 * context (`verification: "not_evaluated"`).
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#6-public-api-and-assembly
 * @returns Canonical content-assertion claims in a success Result, with verification not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * assert.deepEqual(api.contentAssertion.decodeAssertion(api.strUtf8("invalid")), { ok: false });
 * ```
 */
export function decodeAssertion(compact:Uint8Array,bounds?:Bounds):Result<DecodedContentAssertion> {
  return stages.decodeAssertion(stages.EDDSA,compact,bounds);
}

/**
 * The content digest an assertion binds: SHA-256 over `BAP1-CONTENT\0` and 1 to 65,536 exact
 * content bytes (`content_bytes`).
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#6-public-api-and-assembly
 * @returns The raw 32-byte domain-separated content digest in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { generateKeyPairSync, sign } from "node:crypto";
 * import { contentAssertion, sha256, strUtf8 } from "@bounded-authority-protocol/verifier";
 *
 * const content = contentAssertion.contentDigest(strUtf8("route table v12"));
 * assert.ok(content.ok);
 * const input = contentAssertion.assertionSigningInput({
 *   attestorKeyId: "ops-1", jti: "routes-12", iss: "https://ops.example", aud: "https://edge.example",
 *   sub: "routes:eu", profile: "urn:example:routes:2", profileDigest: sha256(strUtf8("routes schema 2")),
 *   contentDigest: content.value, gen: 1, prev: new Uint8Array(32), iat: 10, nbf: 10, exp: 20,
 * });
 * assert.ok(input.ok);
 * const signer = generateKeyPairSync("ed25519");
 * const signature = sign(null, Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]), signer.privateKey);
 * const compact = contentAssertion.assembleCompact(input.value, signature);
 * assert.ok(compact.ok);
 *
 * const decoded = contentAssertion.decodeAssertion(compact.value);
 * assert.ok(decoded.ok);
 * assert.equal(decoded.value.sub, "routes:eu");
 * const digest = contentAssertion.assertionDigest(compact.value);
 * assert.ok(digest.ok);
 * assert.deepEqual(digest.value, sha256(compact.value));
 * assert.deepEqual(contentAssertion.contentDigest(new Uint8Array(0)), { ok: false }); // empty content
 * ```
 */
export function contentDigest(content:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return stages.contentDigest(content,bounds);
}

/**
 * SHA-256 of the exact compact bytes after a structure check (the value a successor's `prev`
 * carries). Makes no signature claim.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#6-public-api-and-assembly
 * @returns The raw 32-byte SHA-256 of the structurally validated compact in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import * as api from "@bounded-authority-protocol/verifier";
 * assert.deepEqual(api.contentAssertion.assertionDigest(api.strUtf8("invalid")), { ok: false });
 * ```
 */
export function assertionDigest(compact:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return stages.assertionDigest(stages.EDDSA,compact,bounds);
}

/**
 * Verifies a content assertion under the attestor key against the expected identities, digests and
 * time. `expected.bounds` is required. Facts carry `trust: "not_evaluated"`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#6-public-api-and-assembly
 * @returns Redacted ContentAssertionFacts in a success Result, with trust not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
 * import { boundsNew, contentAssertion, strUtf8 } from "@bounded-authority-protocol/verifier";
 *
 * const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
 * const publisher = generateKeyPairSync("ed25519");
 * const attestor = { keyId: "publisher-1", publicKey: raw(publisher.publicKey), validFrom: 0, validBefore: null };
 * const profileDigest = createHash("sha256").update("retention-policy schema 3").digest();
 * const bounds = boundsNew();
 *
 * function publish(text: string, gen: number, prev: Uint8Array, iat: number) {
 *   const contentDigest = contentAssertion.contentDigest(strUtf8(text));
 *   assert.ok(contentDigest.ok);
 *   const input = contentAssertion.assertionSigningInput({
 *     attestorKeyId: "publisher-1", jti: `retention-policy-${gen}`, iss: "https://records.example",
 *     aud: "https://archive.example", sub: "policy:retention", profile: "urn:example:retention:3",
 *     profileDigest, contentDigest: contentDigest.value, gen, prev, iat, nbf: iat, exp: iat + 86_400,
 *   });
 *   assert.ok(input.ok);
 *   const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
 *   const compact = contentAssertion.assembleCompact(input.value, sign(null, message, publisher.privateKey));
 *   assert.ok(compact.ok);
 *   const facts = contentAssertion.verifyAssertion(compact.value, {
 *     attestor, issuer: "https://records.example", audience: "https://archive.example", subject: "policy:retention",
 *     profile: "urn:example:retention:3", profileDigest, contentDigest: contentDigest.value, now: iat + 10, bounds,
 *   });
 *   assert.ok(facts.ok);
 *   return facts.value;
 * }
 *
 * const first = publish("keep invoices 7 years", 1, new Uint8Array(32), 1_000);
 * const second = publish("keep invoices 10 years", 2, first.digest, 2_000);
 * assert.ok(contentAssertion.verifySuccessor(first, second, bounds).ok);
 *
 * // Skipping a generation, or naming the wrong predecessor, rejects.
 * const third = publish("keep invoices 5 years", 3, second.digest, 3_000);
 * assert.deepEqual(contentAssertion.verifySuccessor(first, third, bounds), { ok: false });
 * const fork = publish("keep invoices 1 year", 2, new Uint8Array(32).fill(9), 2_500);
 * assert.deepEqual(contentAssertion.verifySuccessor(first, fork, bounds), { ok: false });
 * ```
 */
export function verifyAssertion(compact:Uint8Array,e:ExpectedContentAssertion):Result<ContentAssertionFacts> {
  return stages.verifyAssertion(stages.EDDSA,compact,e);
}

/**
 * Compares two verified facts values: same context, consecutive generations, `prev` equal to the
 * predecessor's digest, non-decreasing issuance time and a new `jti`. Checks no signature and no
 * current time.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#6-public-api-and-assembly
 * @returns A success Result with undefined value when every lineage binding matches. No signature or current-time check is performed. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 * @category Content assertions
 * @example
 * ```ts
 * import assert from "node:assert/strict";
 * import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
 * import { boundsNew, contentAssertion, strUtf8 } from "@bounded-authority-protocol/verifier";
 *
 * const raw = (key: KeyObject): Uint8Array => Buffer.from(key.export({ format: "jwk" }).x!, "base64url");
 * const publisher = generateKeyPairSync("ed25519");
 * const attestor = { keyId: "publisher-1", publicKey: raw(publisher.publicKey), validFrom: 0, validBefore: null };
 * const profileDigest = createHash("sha256").update("retention-policy schema 3").digest();
 * const bounds = boundsNew();
 *
 * function publish(text: string, gen: number, prev: Uint8Array, iat: number) {
 *   const contentDigest = contentAssertion.contentDigest(strUtf8(text));
 *   assert.ok(contentDigest.ok);
 *   const input = contentAssertion.assertionSigningInput({
 *     attestorKeyId: "publisher-1", jti: `retention-policy-${gen}`, iss: "https://records.example",
 *     aud: "https://archive.example", sub: "policy:retention", profile: "urn:example:retention:3",
 *     profileDigest, contentDigest: contentDigest.value, gen, prev, iat, nbf: iat, exp: iat + 86_400,
 *   });
 *   assert.ok(input.ok);
 *   const message = Buffer.concat([input.value.protectedSegment, Buffer.from("."), input.value.payloadSegment]);
 *   const compact = contentAssertion.assembleCompact(input.value, sign(null, message, publisher.privateKey));
 *   assert.ok(compact.ok);
 *   const facts = contentAssertion.verifyAssertion(compact.value, {
 *     attestor, issuer: "https://records.example", audience: "https://archive.example", subject: "policy:retention",
 *     profile: "urn:example:retention:3", profileDigest, contentDigest: contentDigest.value, now: iat + 10, bounds,
 *   });
 *   assert.ok(facts.ok);
 *   return facts.value;
 * }
 *
 * const first = publish("keep invoices 7 years", 1, new Uint8Array(32), 1_000);
 * const second = publish("keep invoices 10 years", 2, first.digest, 2_000);
 * assert.ok(contentAssertion.verifySuccessor(first, second, bounds).ok);
 *
 * // Skipping a generation, or naming the wrong predecessor, rejects.
 * const third = publish("keep invoices 5 years", 3, second.digest, 3_000);
 * assert.deepEqual(contentAssertion.verifySuccessor(first, third, bounds), { ok: false });
 * const fork = publish("keep invoices 1 year", 2, new Uint8Array(32).fill(9), 2_500);
 * assert.deepEqual(contentAssertion.verifySuccessor(first, fork, bounds), { ok: false });
 * ```
 */
export function verifySuccessor(predecessor:ContentAssertionFacts,successor:ContentAssertionFacts,bounds:Bounds):Result<void> {
  return stages.verifySuccessor(stages.EDDSA,predecessor,successor,bounds);
}
