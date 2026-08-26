// Value-bearing, redacted, non-authorizing facts (spec/bap-v1.md § Public verification contract,
// REQ1-VERIFY-facts-redacted, REQ1-VERIFY-facts-not-credentials). No generic encoder, no `toJSON`,
// no authorization/decision method (AGENTS rule 1). Grant/Envelope/Export carry
// `authorization: "not_evaluated"`; Chain/Anchor/Transition carry `trust: "not_evaluated"`.

// GrantFacts (spec/bap-v1.md): version, issuer, grant_id, issuer-key fingerprint (raw 32),
// holder thumbprint (raw 32), matched audience, grant times, authorization:not_evaluated.
export interface GrantFacts {
  readonly version: number;
  readonly issuer: string;
  readonly grantId: string;
  readonly issuerKeyFingerprint: Uint8Array; // raw 32
  readonly holderThumbprint: Uint8Array; // raw 32
  readonly matchedAudience: string;
  readonly issuedAt: number;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly authorization: "not_evaluated";
}

// EnvelopeFacts (spec/bap-v1.md): GrantFacts + proof_id, invocation_id, operation, uri,
// grant hash (ath raw 32), request hash (ba_req raw 32), proof issued_at.
export interface EnvelopeFacts {
  readonly version: number;
  readonly issuer: string;
  readonly grantId: string;
  readonly issuerKeyFingerprint: Uint8Array;
  readonly holderThumbprint: Uint8Array;
  readonly matchedAudience: string;
  readonly grantIssuedAt: number;
  readonly grantNotBefore: number;
  readonly grantExpiresAt: number;
  readonly proofId: string;
  readonly invocationId: string;
  readonly operation: string;
  readonly uri: string; // normalized
  readonly grantHash: Uint8Array; // raw 32 (ath)
  readonly requestHash: Uint8Array; // raw 32 (ba_req)
  readonly proofIssuedAt: number;
  readonly authorization: "not_evaluated";
}

// ChainFacts (ADR 0004:84-87; REQ1-CHAIN-facts-shape): value-bearing, trust:not_evaluated.
// Field set mirrors the Elixir reference ChainFacts (chain_facts.ex) exactly.
export interface ChainFacts {
  readonly version: 1;
  readonly chainId: string;
  readonly firstSequence: number;
  readonly lastSequence: number;
  readonly rowCount: number;
  readonly previousHash: Uint8Array; // raw 32
  readonly lastHash: Uint8Array; // raw 32
  readonly verification: "boundary_consistent";
  readonly trust: "not_evaluated";
}

// AnchorFacts (spec/bap-v1.md § Historical anchor verify): trust:not_evaluated.
// Field set mirrors the Elixir reference AnchorFacts (anchor_facts.ex) exactly. The reference
// carries NO key_id (only the key_fingerprint); the SDK matches — keyFingerprint is the only key
// identifier on this fact.
export interface AnchorFacts {
  readonly version: 1;
  readonly anchorId: string;
  readonly anchoredAt: number;
  readonly chainId: string;
  readonly sequence: number;
  readonly chainHash: Uint8Array; // raw 32
  readonly keyFingerprint: Uint8Array; // raw 32
  readonly verification: "signature_and_window";
  readonly trust: "not_evaluated";
}

// KeyTransitionFacts (ADR 0004:44-55): trust:not_evaluated.
// Field set mirrors the Elixir reference KeyTransitionFacts (key_transition_facts.ex) exactly. The
// reference carries fingerprints only (no key ids); the SDK matches — currentKeyFingerprint and
// nextKeyFingerprint are the only key identifiers on this fact.
export interface KeyTransitionFacts {
  readonly version: 1;
  readonly transitionId: string;
  readonly chainId: string;
  readonly effectiveAt: number;
  readonly currentKeyFingerprint: Uint8Array; // raw 32 (reference: current_key_fingerprint)
  readonly nextKeyFingerprint: Uint8Array; // raw 32 (reference: next_key_fingerprint)
  readonly verification: "authenticated_transition";
  readonly trust: "not_evaluated";
}

// AnchoredExportFacts (spec/bap-v1.md): the ONLY facts type with an authorization field.
// Field set mirrors the Elixir reference AnchoredExportFacts (anchored_export_facts.ex) exactly.
export interface AnchoredExportFacts {
  readonly version: 1;
  readonly chainId: string;
  readonly firstSequence: number;
  readonly lastSequence: number;
  readonly rowCount: number;
  readonly previousHash: Uint8Array; // raw 32
  readonly lastHash: Uint8Array; // raw 32
  readonly digest: Uint8Array; // raw 32 archive SHA-256
  readonly startAnchorId: string;
  readonly startAnchoredAt: number;
  readonly startKeyFingerprint: Uint8Array; // raw 32
  readonly endAnchorId: string;
  readonly endAnchoredAt: number;
  readonly endKeyFingerprint: Uint8Array; // raw 32
  readonly transitionCount: number;
  readonly objectVersion: string;
  readonly verification: "anchored_export";
  readonly trust: "not_evaluated";
  readonly authorization: "not_evaluated";
}

// GrantDecoded / ProofDecoded / KeyLocator (decode + locator surfaces).
export interface GrantDecoded {
  readonly keyId: string;
  readonly issuer: string;
  readonly grantId: string;
  readonly audiences: string[];
  readonly issuedAt: number;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly holderThumbprint: Uint8Array; // raw 32 (cnf.jkt)
  readonly verification: "not_evaluated";
}

export interface ProofDecoded {
  readonly proofId: string;
  readonly holderThumbprint: Uint8Array; // raw 32 (JWK thumbprint)
  readonly verification: "not_evaluated";
}

export interface KeyLocator {
  readonly keyId: string;
  readonly trust: "not_evaluated";
}
