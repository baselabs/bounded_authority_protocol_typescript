// The public surface of @bounded-authority-protocol/verifier (the v1 protocol verification façade +
// versioned primitives). Re-exports the 17 v1 façade functions, the 4 local-loopback proof profile
// functions, the dispatch structs and the primitives the public contract names (spec/bap-v1.md §
// Public verification contract). Every export is listed in docs/reference.md.
//
// No `authorized`/`decision` surface (verification is not authority); every function returns Result<T> =
// Ok | Err, mirroring {:ok,value}|{:error,:invalid}. Facts are value-bearing, redacted, and
// non-authorizing.

import { BACKEND_ID as RESOLVED_BACKEND } from "#crypto";
import type { BackendId } from "./crypto/types.js";

// The crypto backend this build resolved: "node" (node:crypto, Node.js default conditions) or
// "portable" (@noble: browsers, Deno, Bun, workers, and Node under --conditions=bap-portable). It
// selects the implementation only; every protocol gate and every verdict is the same in both.
/**
 * The crypto backend this build resolved: `"node"` (node:crypto) or `"portable"` (@noble).
 * Verdicts are the same in both.
 * @see https://github.com/baselabs/bounded_authority_protocol_typescript/blob/main/docs/reference.md
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

// The v2 contract-major profile façade (v:2 payloads, BAP2-* domain separators, lte/gte range
// selectors per ADR 0028). Exported as a namespace: its surface intentionally mirrors the v1
// façade's names, so the module path (v2) carries the major — v2.checkEnvelope,
// v2.grantSigningInput, v2.Selector, and so on. It rejects v1 bytes exactly as v1 rejects v2
// bytes; the two majors share no wire form.
export * as v2 from "./v2.js";

// The v3 contract-major profile façade (the BAP3-ES256-SHA256 suite, ADR 0035): v:3 payloads,
// BAP3-* domain separators, the v2 selector algebra (lte/gte incorporated), ES256 signatures over
// NIST P-256 with raw 65-byte SEC1 public keys and the low-S raw r||s signature form. Same
// namespace convention: v3.checkEnvelope, v3.proofSigningInput, v3.Selector, and so on. It
// rejects every v1 and v2 artifact with the single closed error, and vice versa; no major shares
// a wire form with another.
export * as v3 from "./v3.js";

// The bap-role-attestation/1 sibling profile (ADR 0036): a standalone, grant-unbound compact
// JWS binding a subject key to a role for a bounded window under contract-major-1 mechanics
// (Ed25519/EdDSA, BAP1-Ed25519-SHA256). Parsed by no contract-major profile — its
// `ba+role-attestation` typ and every major typ reject each other — and selected only through
// this separately named namespace: roleAttestation.attestationSigningInput,
// roleAttestation.assembleAttestationCompact, roleAttestation.decodeAttestation,
// roleAttestation.verifyAttestation. Facts carry trust "not_evaluated" and no authorization
// marker (the anchor posture); verification is not authority.
export * as roleAttestation from "./role_attestation.js";

// Standalone digest-bound assertion profile; explicit selection, never authorization.
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
