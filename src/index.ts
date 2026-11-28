// The public surface of @bounded-authority-protocol/verifier (the v1 protocol verification façade +
// versioned primitives). Re-exports the 17 v1 façade functions, the 4 local-loopback proof profile
// functions, the dispatch structs and the primitives the public contract names (spec/bap-v1.md §
// Public verification contract). Every export is listed in docs/reference.md.
//
// Verification returns closed Result<T> values; low-level primitives document their own throws
// or boolean contracts. Facts are value-bearing, redacted and non-authorizing.

import { BACKEND_ID as RESOLVED_BACKEND } from "#crypto";
import type { BackendId } from "./crypto/types.js";

/**
 * The crypto backend this build resolved: `"node"` (node:crypto) or `"portable"` (@noble).
 * Verdicts are the same in both.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @category Request verification
 */
export const BACKEND_ID: BackendId = RESOLVED_BACKEND;
export type { BackendId } from "./crypto/types.js";

export {
  // The 17 v1 façade functions and the 4 local-loopback proof profile functions.
  untrustedKeyLocator,
  decodeGrant,
  decodeProof,
  decodeLocalLoopbackHttpProof,
  verifyGrant,
  checkEnvelope,
  checkLocalLoopbackHttpEnvelope,
  requestDigest,
  encodeConsumptionEntry,
  checkChain,
  grantSigningInput,
  proofSigningInput,
  localLoopbackHttpProofSigningInput,
  assembleCompact,
  assembleLocalLoopbackHttpCompact,
  boundaryAnchorSigningInput,
  keyTransitionSigningInput,
  encodeAnchoredExport,
  verifyHistoricalAnchor,
  verifyKeyTransition,
  verifyAnchoredExport,
  // Versioned primitives the public contract names (spec/bap-v1.md L299-309).
  jwkEncodePublic,
  jwkDecodePublic,
  thumbprint,
  uriNormalize,
  boundsNew,
  boundsMaximum,
  MAXIMUM_BOUNDS,
  MAXIMA,
  REQUEST_PREFIX,
  ROW_PREFIX,
  ARCHIVE_PREFIX,
} from "./v1.js";

export { localLoopbackHttpUriNormalize } from "./uri.js";

/**
 * Contract-major 2 uses Ed25519, v:2 payloads, BAP2 domain separators and inclusive same-tag numeric
 * range selectors. Select this namespace explicitly; it rejects all other majors. Verification returns
 * non-authorizing facts and closed failures. Shared chain and verification rules are incorporated from
 * major 1.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v2.md#substitutions
 */
export * as v2 from "./v2.js";

/**
 * Contract-major 3 uses ES256 over P-256, v:3 payloads and BAP3 domain separators. Raw public keys are
 * 65-byte uncompressed SEC1 points; signatures are low-S, 64-byte raw r || s. Select explicitly; every
 * other major refuses. Shared verification rules come from major 1 and selectors from major 2. Facts
 * never authorize execution.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v3.md#suite-rules
 */
export * as v3 from "./v3.js";

/**
 * The bap-role-attestation/1 sibling profile binds a distinct public subject key to issuer or holder
 * for a bounded window under an already-trusted Ed25519 attestor. Select explicitly: no grant profile
 * parses these bytes. Verification proves a signature and context only; trust and operational
 * enrollment remain host policy.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-role-attestation-v1.md#3-verification-contract
 */
export * as roleAttestation from "./role_attestation.js";

/** Standalone Ed25519 holder custody attestations selected by the caller. */
export * as holderCustodyAttestation from "./holder_custody_attestation.js";

/**
 * The bap-content-assertion/1 sibling profile binds exact content and application-profile digests to a
 * signed assertion under an already-trusted Ed25519 attestor. Generation and predecessor digests
 * support explicit successor verification. The verifier fetches no content, interprets no application
 * schema and grants no authority.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-content-assertion-v1.md#4-verification
 */
export * as contentAssertion from "./content_assertion.js";

export type {
  TrustedIssuer,
  ExpectedGrant,
  HistoricalPublicKey,
  ExpectedAnchor,
  ExpectedKeyTransition,
  ConsumptionEntry,
  ChainInput,
  ExpectedChain,
  ExpectedRequest,
  SelectorInput,
  OperationInput,
  GrantProducer,
  ProofProducer,
  BoundaryAnchorProducer,
  KeyTransitionProducer,
  AnchoredExportInput,
  ExpectedExport,
  ArchivedObject,
  HistoricalKeyChain,
  EncodedConsumptionEntry,
  EncodedAnchoredExport,
  Bounds,
  SigningInput,
  Selector,
  MaximaKey,
} from "./v1.js";

export type {
  GrantFacts,
  EnvelopeFacts,
  ChainFacts,
  AnchorFacts,
  KeyTransitionFacts,
  AnchoredExportFacts,
  GrantDecoded,
  ProofDecoded,
  KeyLocator,
} from "./facts.js";

// Error + Result primitives (the closed InvalidError + the Result<T> = Ok|Err shape).
export { InvalidError, ok, err, trying, fail, assert } from "./error.js";
export type { Result } from "./error.js";

// The tagged JSON algebra (the public data model requestDigest + selector matching consume).
export { jsonDecode, utf8Str, strUtf8 } from "./json.js";
export type { Tagged } from "./json.js";

// The bounds + JCS + thumbprint primitives (full set the public contract implies).
export { jcsEncode } from "./jcs.js";
export {
  thumbprintRaw,
  thumbprintPreimage,
  jwkFromPublicKey,
  publicKeyThumbprintRaw,
} from "./jwk.js";
export type { OkpPublic } from "./jwk.js";
export { sha256, verifyStrict, acceptablePublicKey, torsionFree } from "./ed25519.js";
export { es256VerifyStrict } from "./es256.js";
export { base64urlDecode, base64urlEncode } from "./base64url.js";
export { parseSelector, selectorMatches, semanticIdentity } from "./selector.js";
export { typedProject } from "./digest.js";

/** Explicit ES256 content assertion profile using raw P-256 public keys. */
export * as contentAssertionEs256 from "./content_assertion_es256.js";

/** Canonical action approval records and suite-specific verification. */
export * as actionApproval from "./action_approval.js";
