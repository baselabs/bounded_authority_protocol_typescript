// The public surface of @bounded-authority-protocol/verifier (the v1 protocol verification façade +
// versioned primitives). Re-exports the 17 façade functions + the dispatch structs + the primitives
// the public contract names (spec/bap-v1.md § Public verification contract, L266-309).
//
// No `authorized`/`decision` surface (AGENTS rule 1); every function returns Result<T> =
// Ok | Err, mirroring {:ok,value}|{:error,:invalid}. Facts are value-bearing, redacted, and
// non-authorizing.

export {
  // The 17 façade functions.
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
export { sha256 } from "./ed25519.js";
export { base64urlDecode, base64urlEncode } from "./base64url.js";
export { parseSelector, selectorMatches, semanticIdentity } from "./selector.js";
export { typedProject } from "./digest.js";
