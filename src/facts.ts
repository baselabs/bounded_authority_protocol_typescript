/**
 * Verified grant bindings and time claims, matching caller-supplied trusted inputs. These redacted
 * values are facts, never execution credentials. Authorization is not evaluated.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface GrantFacts {
  /** Wire contract-major number, not the npm package version. */
  readonly version: number;
  /** Expected or verified issuer StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly issuer: string;
  /** Grant StringOrURI identifier, 1 to 512 UTF-8 bytes, unique per issuer. */
  readonly grantId: string;
  /** Raw 32-byte RFC 7638 thumbprint of the trusted issuer public key. */
  readonly issuerKeyFingerprint: Uint8Array;
  /** Raw 32-byte RFC 7638 SHA-256 thumbprint of the holder public JWK. */
  readonly holderThumbprint: Uint8Array;
  /** Exact caller-expected audience found in the grant. */
  readonly matchedAudience: string;
  /** Issue timestamp in integer Unix seconds, within the profile integer magnitude. */
  readonly issuedAt: number;
  /** Inclusive validity lower endpoint in integer Unix seconds. */
  readonly notBefore: number;
  /** Exclusive validity upper endpoint in integer Unix seconds. Grant checks separately apply allowed skew. */
  readonly expiresAt: number;
  /** Always not_evaluated. Pure verification makes no operational authorization decision. */
  readonly authorization: "not_evaluated";
}

/**
 * Verified grant and proof bindings for the exact expected request. These redacted values are facts,
 * never execution credentials. Reserve replay, check revocation and apply host policy before acting.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface EnvelopeFacts {
  /** Wire contract-major number, not the npm package version. */
  readonly version: number;
  /** Expected or verified issuer StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly issuer: string;
  /** Grant StringOrURI identifier, 1 to 512 UTF-8 bytes, unique per issuer. */
  readonly grantId: string;
  /** Raw 32-byte RFC 7638 thumbprint of the trusted issuer public key. */
  readonly issuerKeyFingerprint: Uint8Array;
  /** Raw 32-byte RFC 7638 SHA-256 thumbprint of the holder public JWK. */
  readonly holderThumbprint: Uint8Array;
  /** Exact caller-expected audience found in the grant. */
  readonly matchedAudience: string;
  /** Grant issue timestamp in integer Unix seconds. */
  readonly grantIssuedAt: number;
  /** Grant inclusive validity lower endpoint in integer Unix seconds. */
  readonly grantNotBefore: number;
  /** Grant exclusive expiry in integer Unix seconds. Retain invocation reservations through this plus the largest accepted skew. */
  readonly grantExpiresAt: number;
  /** Proof StringOrURI identifier, 1 to 512 UTF-8 bytes, unique per proof. */
  readonly proofId: string;
  /** Lowercase RFC 4122 UUID for one logical invocation. Reserve it with issuer and grant id before execution. */
  readonly invocationId: string;
  /** Operation name, 1 to 128 printable ASCII bytes, naming exactly one grant operation. */
  readonly operation: string;
  /** Verified already-normalized target URI, at most 8,192 ASCII bytes. */
  readonly uri: string;
  /** Raw 32-byte SHA-256 of the exact ASCII grant compact, the proof ath binding. */
  readonly grantHash: Uint8Array;
  /** Raw 32-byte SHA-256 request digest over the major-specific prefix and typed projection. */
  readonly requestHash: Uint8Array;
  /** Proof issue timestamp in integer Unix seconds. Its age window does not bound invocation replay retention. */
  readonly proofIssuedAt: number;
  /** Always not_evaluated. Pure verification makes no operational authorization decision. */
  readonly authorization: "not_evaluated";
}

/**
 * Diagnostic facts for a contiguous, boundary-consistent consumption-row range. Hash consistency
 * establishes neither trust, execution, global completeness nor absence of deletion.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface ChainFacts {
  /** Wire contract-major number, not the npm package version. */
  readonly version: 1;
  /** Consumption-chain StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly chainId: string;
  /** First row sequence, a positive safe integer. */
  readonly firstSequence: number;
  /** Last row sequence, equal to firstSequence + rowCount - 1. */
  readonly lastSequence: number;
  /** Contiguous row count, integer 1 to 65,536 before tightening. */
  readonly rowCount: number;
  /** Raw 32-byte digest before this row or range; all zeros at genesis. */
  readonly previousHash: Uint8Array;
  /** Raw 32-byte digest of the last row with the major-specific chain prefix. */
  readonly lastHash: Uint8Array;
  /** Completed verification stage only; conveys no key trust, replay reservation or execution authority. */
  readonly verification: "boundary_consistent";
  /** Always not_evaluated. The caller owns trust selection and policy. */
  readonly trust: "not_evaluated";
}

/**
 * Diagnostic facts after an anchor signature and historical key window match. The caller still owns
 * trust selection; fingerprints identify keys without carrying raw key material.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface AnchorFacts {
  /** Wire contract-major number, not the npm package version. */
  readonly version: 1;
  /** Boundary-anchor StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly anchorId: string;
  /** Anchor timestamp in integer Unix seconds, within the historical key window. */
  readonly anchoredAt: number;
  /** Consumption-chain StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly chainId: string;
  /** Safe-integer boundary sequence: consumption rows start at 1; genesis anchors use 0. */
  readonly sequence: number;
  /** Raw 32-byte boundary chain-link hash; all zeros at sequence zero. */
  readonly chainHash: Uint8Array;
  /** Raw 32-byte RFC 7638 thumbprint identifying the public key. */
  readonly keyFingerprint: Uint8Array;
  /** Completed verification stage only; conveys no key trust, replay reservation or execution authority. */
  readonly verification: "signature_and_window";
  /** Always not_evaluated. The caller owns trust selection and policy. */
  readonly trust: "not_evaluated";
}

/**
 * Diagnostic facts after a signed handover and both historical key windows match. Authenticated
 * succession does not establish operational trust or authorization.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface KeyTransitionFacts {
  /** Wire contract-major number, not the npm package version. */
  readonly version: 1;
  /** Transition StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly transitionId: string;
  /** Consumption-chain StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly chainId: string;
  /** Transition time in integer Unix seconds, within both key-validity windows. */
  readonly effectiveAt: number;
  /** Raw 32-byte RFC 7638 thumbprint of the transition-signing key. */
  readonly currentKeyFingerprint: Uint8Array;
  /** Raw 32-byte RFC 7638 thumbprint of the successor key. */
  readonly nextKeyFingerprint: Uint8Array;
  /** Completed verification stage only; conveys no key trust, replay reservation or execution authority. */
  readonly verification: "authenticated_transition";
  /** Always not_evaluated. The caller owns trust selection and policy. */
  readonly trust: "not_evaluated";
}

/**
 * Facts after archive framing, digest, storage version, anchors, transitions and every row match
 * explicit expectations. Neither trust nor authorization is evaluated.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface AnchoredExportFacts {
  /** Wire contract-major number, not the npm package version. */
  readonly version: 1;
  /** Consumption-chain StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly chainId: string;
  /** First row sequence, a positive safe integer. */
  readonly firstSequence: number;
  /** Last row sequence, equal to firstSequence + rowCount - 1. */
  readonly lastSequence: number;
  /** Contiguous row count, integer 1 to 65,536 before tightening. */
  readonly rowCount: number;
  /** Raw 32-byte digest before this row or range; all zeros at genesis. */
  readonly previousHash: Uint8Array;
  /** Raw 32-byte digest of the last row with the major-specific chain prefix. */
  readonly lastHash: Uint8Array;
  /** Raw 32-byte SHA-256 digest of the exact complete archive bytes. */
  readonly digest: Uint8Array;
  /** Verified start boundary-anchor identifier. */
  readonly startAnchorId: string;
  /** Start-anchor timestamp in integer Unix seconds. */
  readonly startAnchoredAt: number;
  /** Raw 32-byte RFC 7638 thumbprint of the start archive key. */
  readonly startKeyFingerprint: Uint8Array;
  /** Verified end boundary-anchor identifier. */
  readonly endAnchorId: string;
  /** End-anchor timestamp in integer Unix seconds. */
  readonly endAnchoredAt: number;
  /** Raw 32-byte RFC 7638 thumbprint of the end archive key. */
  readonly endKeyFingerprint: Uint8Array;
  /** Authenticated archive-key handover count, integer 0 to 256. */
  readonly transitionCount: number;
  /** Independently obtained storage version, 1 to 512 UTF-8 bytes. */
  readonly objectVersion: string;
  /** Completed verification stage only; conveys no key trust, replay reservation or execution authority. */
  readonly verification: "anchored_export";
  /** Always not_evaluated. The caller owns trust selection and policy. */
  readonly trust: "not_evaluated";
  /** Always not_evaluated. Pure verification makes no operational authorization decision. */
  readonly authorization: "not_evaluated";
}

/**
 * Bounded grant claims without signature or expected-context verification. Use only for display and
 * diagnostics. These values establish no trust.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface GrantDecoded {
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Expected or verified issuer StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly issuer: string;
  /** Grant StringOrURI identifier, 1 to 512 UTF-8 bytes, unique per issuer. */
  readonly grantId: string;
  /** Nonempty list of at most 64 distinct audience StringOrURI values, each at most 512 UTF-8 bytes. */
  readonly audiences: string[];
  /** Issue timestamp in integer Unix seconds, within the profile integer magnitude. */
  readonly issuedAt: number;
  /** Inclusive validity lower endpoint in integer Unix seconds. */
  readonly notBefore: number;
  /** Exclusive validity upper endpoint in integer Unix seconds. Grant checks separately apply allowed skew. */
  readonly expiresAt: number;
  /** Raw 32-byte RFC 7638 SHA-256 thumbprint of the holder public JWK. */
  readonly holderThumbprint: Uint8Array;
  /** No cryptographic verification has run. Parsing alone establishes no trust or execution authority. */
  readonly verification: "not_evaluated";
}

/**
 * Bounded holder-proof identifiers without signature or expected-context verification. The presented
 * key thumbprint conveys no trust.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface ProofDecoded {
  /** Proof StringOrURI identifier, 1 to 512 UTF-8 bytes, unique per proof. */
  readonly proofId: string;
  /** Raw 32-byte RFC 7638 SHA-256 thumbprint of the holder public JWK. */
  readonly holderThumbprint: Uint8Array;
  /** No cryptographic verification has run. Parsing alone establishes no trust or execution authority. */
  readonly verification: "not_evaluated";
}

/**
 * An untrusted kid lookup hint read only from a grant protected header. Resolve against independently
 * enrolled issuer keys, then verify the entire grant.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface KeyLocator {
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Always not_evaluated. The caller owns trust selection and policy. */
  readonly trust: "not_evaluated";
}
