// Value-bearing, redacted, non-authorizing facts (protocol-v1.md § Public verification contract,
// REQ1-VERIFY-facts-redacted, REQ1-VERIFY-facts-not-credentials). No generic encoder, no `toJSON`,
// no authorization/decision method (AGENTS rule 1). Grant/Envelope/Export carry
// `authorization: "not_evaluated"`; Chain/Anchor/Transition carry `trust: "not_evaluated"`.

// GrantFacts (protocol-v1.md:322-324): version, issuer, grant_id, issuer-key fingerprint (raw 32),
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

// EnvelopeFacts (protocol-v1.md:342-348): GrantFacts + proof_id, invocation_id, operation, uri,
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
export interface ChainFacts {
  readonly chainId: string;
  readonly firstSequence: number;
  readonly lastSequence: number;
  readonly rowCount: number;
  readonly trust: "not_evaluated";
}

// AnchorFacts (protocol-v1.md § Historical anchor verify): trust:not_evaluated.
export interface AnchorFacts {
  readonly anchorId: string;
  readonly anchoredAt: number;
  readonly chainId: string;
  readonly sequence: number;
  readonly chainHash: Uint8Array; // raw 32
  readonly keyId: string;
  readonly keyFingerprint: Uint8Array; // raw 32
  readonly trust: "not_evaluated";
}

// KeyTransitionFacts (ADR 0004:44-55): trust:not_evaluated.
export interface KeyTransitionFacts {
  readonly transitionId: string;
  readonly chainId: string;
  readonly effectiveAt: number;
  readonly fromKeyId: string;
  readonly fromKeyFingerprint: Uint8Array; // raw 32
  readonly toKeyId: string;
  readonly toKeyFingerprint: Uint8Array; // raw 32
  readonly trust: "not_evaluated";
}

// AnchoredExportFacts (protocol-v1.md:437-440): the ONLY facts type with an authorization field.
export interface AnchoredExportFacts {
  readonly objectVersion: string;
  readonly chainId: string;
  readonly firstSequence: number;
  readonly lastSequence: number;
  readonly rowCount: number;
  readonly transitionCount: number;
  readonly digest: Uint8Array; // raw 32 archive SHA-256
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
