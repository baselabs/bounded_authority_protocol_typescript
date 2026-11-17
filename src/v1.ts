import { isStringOrUri } from "./string_or_uri.js";
import { fail, assert, type Result, trying } from "./error.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "./json.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { parseCompact, assembleSegments, scanCompact, type SigningInput, type CompactSegments } from "./compact.js";
import { jwkFromPublicKey, thumbprintRaw, jwkEncodePublic, jwkDecodePublic, thumbprint } from "./jwk.js";
import { importPublicKey, ed25519Verify, sha256, sha256Concat, signatureGate, _resetCensus } from "./ed25519.js";
import { requestDigest as computeRequestDigest, REQUEST_PREFIX, typedProject } from "./digest.js";
import { parseSelector, selectorMatches, integralFloatFree, type Selector } from "./selector.js";
import { localLoopbackHttpUriNormalize, uriNormalize } from "./uri.js";
import { jcsEncode } from "./jcs.js";
import { resolve, coerceBounds, boundsNew, boundsMaximum, MAXIMUM_BOUNDS, MAXIMA, type Bounds, type MaximaKey } from "./bounds.js";
import { redacted } from "./redact.js";
import type {
  GrantFacts, EnvelopeFacts, ChainFacts, AnchorFacts, KeyTransitionFacts,
  AnchoredExportFacts, GrantDecoded, ProofDecoded, KeyLocator,
} from "./facts.js";

// The v1 verification façade (spec/bap-v1.md § Public verification contract, L270-290). 17 public
// functions, each returning Result<T> = Ok|Err (the {:ok,value}|{:error,:invalid} mirror). No
// authorized/decision surface (rule 1). All claims revalidated at every public entry
// (REQ1-VERIFY-revalidate). Wire formats derived from spec/bap-v1.md + spec/bap-v1.md#chain + the corpus;
// the corpus is the byte-level arbiter.

const ALG = "EdDSA";
const GRANT_TYP = "ba+cap";
const PROOF_TYP = "dpop+jwt";
const LOCAL_LOOPBACK_PROOF_TYP = "ba+loopback-proof";
const ANCHOR_TYP = "ba+chain-anchor";
const TRANSITION_TYP = "ba+key-transition";
const VERSION = 1;
const DOT = 0x2e;

/**
 * Exact 11-byte ASCII domain separator `BAP1-CHAIN\0` for consumption-row hashing. Treat these bytes
 * as immutable; mutation changes the wire contract.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export const ROW_PREFIX = new Uint8Array([
  0x42, 0x41, 0x50, 0x31, 0x2d, 0x43, 0x48, 0x41, 0x49, 0x4e, 0x00, // "BAP1-CHAIN\0"
]);

/**
 * Exact 20-byte ASCII archive magic `BAP1-ARCHIVE\0EXPORT\0`. Both NUL bytes are included; this prefix
 * is never length-framed. Treat these bytes as immutable; mutation changes the wire contract.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#archive
 */
export const ARCHIVE_PREFIX = strUtf8("BAP1-ARCHIVE\0EXPORT\0");

// The all-zero 32-byte hash: sequence-1 predecessor + sequence-0 anchor chain hash (spec/bap-v1.md#chain).
const DEFAULT_HASH = new Uint8Array(32);

// --- dispatch struct types (match corpus input field names; the contract for each façade) ---

/**
 * An issuer key already trusted by the caller for this contract major. The key id binds a lookup
 * result, but does not discover trust. No private key is accepted.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface TrustedIssuer {
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Already-trusted raw 32-byte Ed25519 public key, never a JWK or private key. */
  readonly publicKey: Uint8Array;
}

/**
 * Caller-owned issuer, audience and evaluation context for grant verification. Supply time from the
 * verifying service, never from a presented claim. Malformed context fails closed.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface ExpectedGrant {
  /** Expected or verified issuer StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly issuer: string;
  /** Expected audience StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly audience: string;
  /** Host-supplied integer Unix seconds. Never derive this value from presenter-controlled claims. */
  readonly evaluationTime: number;
  /** Permitted skew in seconds, integer 0 to 60, further constrained by bounds. */
  readonly clockSkew: number;
  /** Optional tightened resource limits; omission uses the profile maxima. */
  readonly bounds?: Bounds;
}

/**
 * An already-trusted archive or attestor public key with the half-open validity interval [validFrom,
 * validBefore). A null upper endpoint is unbounded. Verification never discovers or enrolls this key.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface HistoricalPublicKey {
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Already-trusted raw 32-byte Ed25519 public key, never a JWK or private key. */
  readonly publicKey: Uint8Array;
  /** Inclusive key-validity lower endpoint in integer Unix seconds. */
  readonly validFrom: number;
  /** Exclusive key-validity upper endpoint in integer Unix seconds; null means unbounded. */
  readonly validBefore: number | null;
}

/**
 * Independently retained expectations for one signed consumption-chain boundary. Matching an anchor
 * proves a signature and key window; it establishes no trust or absence of deleted history.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface ExpectedAnchor {
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
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Raw 32-byte RFC 7638 thumbprint identifying the public key. */
  readonly keyFingerprint: Uint8Array;
  /** Optional tightened resource limits; omission uses the profile maxima. */
  readonly bounds?: Bounds;
}

/**
 * Caller-retained identity, time and fingerprints for an archive-key handover. The old key signs the
 * next key; both validity windows must contain effectiveAt.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface ExpectedKeyTransition {
  /** Transition StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly transitionId: string;
  /** Consumption-chain StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly chainId: string;
  /** Transition time in integer Unix seconds, within both key-validity windows. */
  readonly effectiveAt: number;
  /** Current signing-key kid, 1 to 128 permitted ASCII bytes. */
  readonly currentKeyId: string;
  /** Raw 32-byte RFC 7638 thumbprint of the transition-signing key. */
  readonly currentKeyFingerprint: Uint8Array;
  /** Successor-key kid, 1 to 128 permitted ASCII bytes. */
  readonly nextKeyId: string;
  /** Raw 32-byte RFC 7638 thumbprint of the successor key. */
  readonly nextKeyFingerprint: Uint8Array;
  /** Optional tightened resource limits; omission uses the profile maxima. */
  readonly bounds?: Bounds;
}

/**
 * One consumption-chain row before canonical encoding. Its commitment is an opaque 32-byte
 * caller-supplied digest. The verifier neither records execution nor interprets that commitment.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface ConsumptionEntry {
  /** Consumption-chain StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly chainId: string;
  /** Positive safe-integer consumption-row sequence, starting at 1. */
  readonly sequence: number;
  /** Raw 32-byte digest before this row or range; all zeros at genesis. */
  readonly previousHash: Uint8Array;
  /** Opaque raw 32-byte consumption commitment supplied by the caller. */
  readonly commitment: Uint8Array;
}

/**
 * Canonical consumption rows and their claimed boundaries. checkChain revalidates every row and
 * compares this range with independently supplied ExpectedChain values.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface ChainInput {
  /** Ordered canonical UTF-8 JSON rows, at most 65,536 rows, each at most 4,096 bytes. */
  readonly rows: Uint8Array[];
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
}

/**
 * Independently retained boundaries of an exact contiguous chain range. Matching them does not prove
 * global completeness, execution or absence of deletion.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface ExpectedChain {
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
  /** Optional tightened resource limits; omission uses the profile maxima. */
  readonly bounds?: Bounds;
}

/**
 * Trusted inputs and server-derived request context for envelope verification. All bindings must
 * match. Success yields non-authorizing facts; replay reservation, revocation and execution policy
 * remain host responsibilities.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface ExpectedRequest {
  /** Already-enrolled issuer kid and raw public key; never trust a presenter-supplied key. */
  readonly trustedIssuer: TrustedIssuer;
  /** Expected or verified issuer StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly issuer: string;
  /** Expected audience StringOrURI, 1 to 512 UTF-8 bytes, compared exactly. */
  readonly audience: string;
  /** RFC 9110 method token, 1 to 32 ASCII bytes (tightenable via method_bytes), matched case-sensitively without folding. */
  readonly method: string;
  /** Already-normalized target of at most 8,192 ASCII bytes. Standard profiles require HTTPS; the explicit v1 loopback profile permits only literal loopback HTTP. */
  readonly targetUri: string;
  /** Lowercase RFC 4122 UUID for one logical invocation. Reserve it with issuer and grant id before execution. */
  readonly invocationId: string;
  /** Operation name, 1 to 128 printable ASCII bytes, naming exactly one grant operation. */
  readonly operation: string;
  /** Tagged arguments derived by the host from the request, bound through their exact typed digest projection. */
  readonly castArguments: Tagged;
  /** Host-supplied integer Unix seconds. Never derive this value from presenter-controlled claims. */
  readonly evaluationTime: number;
  /** Permitted skew in seconds, integer 0 to 60, further constrained by bounds. */
  readonly clockSkew: number;
  /** Maximum proof age in seconds, integer 1 to 300, further constrained by bounds. */
  readonly proofMaxAge: number;
  /** Explicit policy: not_required requires absence; required requires exact equality. The explicit v1 loopback profile requires required. */
  readonly nonce: {
    /** Require an absent proof nonce. */
    kind: "not_required";
  } | {
    /** Require exact nonce equality. */
    kind: "required";
    /** Expected nonce, 1 to 512 UTF-8 bytes. */
    value: string;
  };
  /** Optional tightened resource limits; omission uses the profile maxima. */
  readonly bounds?: Bounds;
}

/**
 * A grant-producer selector. The bare string all and the object with kind all impose no restriction.
 * Active paths traverse object members only. equals and one_of compare tagged semantic identity.
 * Producers reject float-tagged integral values inside equality candidates because JCS would change
 * their meaning.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#selectors
 */
export type SelectorInput = "all" | {
    /** Unrestricted selector; other recognized wire members are inert. */
    readonly kind: "all";
  }
  | {
    /** Require exact tagged semantic equality at path. */
    readonly kind: "equals";
    /** Object-member path: 1 to 32 names of 1 to 128 UTF-8 bytes each; array indices are unsupported. */
    readonly path: string[];
    /** Tagged equality candidate; object member order is irrelevant. */
    readonly value: Tagged;
  }
  | {
    /** Require membership in the tagged candidate set at path. */
    readonly kind: "one_of";
    /** Object-member path: 1 to 32 names of 1 to 128 UTF-8 bytes each; array indices are unsupported. */
    readonly path: string[];
    /** Nonempty list of at most 256 tagged candidates, compared without collapsing integer and float tags. */
    readonly values: Tagged[];
  };

/**
 * One named operation and its nonempty conjunction of selectors. Every selector must match the
 * server-cast request arguments. Duplicate operation names are invalid.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface OperationInput {
  /** Operation name, 1 to 128 printable ASCII bytes, unique within a grant. */
  readonly name: string;
  /** Nonempty conjunction of at most 64 selectors; every selector must match. */
  readonly selectors: SelectorInput[];
}

/**
 * Public fields for a canonical issuer-grant signing input. Construction validates the major-specific
 * wire form but performs no signing, key custody or issuance-policy decision.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface GrantProducer {
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
  /** Canonical unpadded base64url string of exactly 32 RFC 7638 thumbprint bytes (43 ASCII characters). */
  readonly holderThumbprint: string;
  /** Nonempty list of at most 64 distinct named operations and selectors. */
  readonly operations: OperationInput[];
}

/**
 * Public fields for a holder proof binding one invocation and exact typed request arguments. The
 * holder signs externally. Construction does not authenticate the supplied grant.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export interface ProofProducer {
  /** Raw 32-byte Ed25519 holder public key; the holder signs the proof externally. */
  readonly holderPublicKey: Uint8Array;
  /** Proof StringOrURI identifier, 1 to 512 UTF-8 bytes, unique per proof. */
  readonly proofId: string;
  /** RFC 9110 method token, 1 to 32 ASCII bytes (tightenable via method_bytes), matched case-sensitively without folding. */
  readonly method: string;
  /** Already-normalized target of at most 8,192 ASCII bytes. Standard profiles require HTTPS; the explicit v1 loopback profile permits only literal loopback HTTP. */
  readonly targetUri: string;
  /** Issue timestamp in integer Unix seconds, within the profile integer magnitude. */
  readonly issuedAt: number;
  /** Lowercase RFC 4122 UUID for one logical invocation. Reserve it with issuer and grant id before execution. */
  readonly invocationId: string;
  /** Operation name, 1 to 128 printable ASCII bytes, naming exactly one grant operation. */
  readonly operation: string;
  /** Exact ASCII grant compact hashed into ath. Construction checks framing, not its signature. */
  readonly grantCompact: Uint8Array;
  /** Typed arguments bound into the proof. The host independently derives and compares its expected arguments. */
  readonly castArguments: Tagged;
  /** Optional nonce, 1 to 512 UTF-8 bytes. Omit when none is required; the v1 loopback profile requires it. */
  readonly nonce?: string;
}

/**
 * Unsigned chain-boundary fields for external signing by an archive key. Sequence zero denotes the
 * genesis boundary and requires an all-zero chain hash.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface BoundaryAnchorProducer {
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
  /** Protected-header kid, 1 to 128 ASCII bytes in the protocol key-id character class. */
  readonly keyId: string;
  /** Already-trusted raw 32-byte Ed25519 public key, never a JWK or private key. */
  readonly publicKey: Uint8Array;
}

/**
 * Unsigned handover from the current archive public key to its successor. The current key signs
 * externally. Construction does not enroll either key or evaluate trust.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface KeyTransitionProducer {
  /** Transition StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly transitionId: string;
  /** Consumption-chain StringOrURI identifier, 1 to 512 UTF-8 bytes. */
  readonly chainId: string;
  /** Transition time in integer Unix seconds, within both key-validity windows. */
  readonly effectiveAt: number;
  /** Current signing-key kid, 1 to 128 permitted ASCII bytes. */
  readonly currentKeyId: string;
  /** Raw 32-byte Ed25519 current public key; this key signs the transition. */
  readonly currentPublicKey: Uint8Array;
  /** Successor-key kid, 1 to 128 permitted ASCII bytes. */
  readonly nextKeyId: string;
  /** Raw 32-byte Ed25519 successor public key. */
  readonly nextPublicKey: Uint8Array;
}

/**
 * Rows, signed boundary anchors and ordered signed key transitions to frame as an archive. Encoding
 * checks canonical structures and consistency without verifying embedded signatures.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#archive
 */
export interface AnchoredExportInput {
  /** Ordered canonical UTF-8 JSON rows, at most 65,536 rows, each at most 4,096 bytes. */
  readonly rows: Uint8Array[];
  /** Signed ASCII boundary-anchor compact immediately before the first row. */
  readonly startAnchor: Uint8Array;
  /** Signed ASCII boundary-anchor compact at the last row. */
  readonly endAnchor: Uint8Array;
  /** Ordered signed key-transition compacts, at most 256 entries. */
  readonly transitions: Uint8Array[];
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
}

/**
 * Major-1 archive construction and verification expectations. Verification compares the retained
 * digest and object version; encoding returns its computed digest. Retain the expected boundaries
 * independently of the presented archive.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#archive
 */
export interface ExpectedExport {
  /** Independently retained expected contiguous-row boundaries. */
  readonly chain: ExpectedChain;
  /** Raw 32-byte SHA-256 digest of the exact complete archive bytes. */
  readonly digest: Uint8Array;
  /** Independently retained expected anchor identity, timestamp, key and chain boundary. */
  readonly startAnchor: ExpectedAnchor;
  /** Independently retained expected anchor identity, timestamp, key and chain boundary. */
  readonly endAnchor: ExpectedAnchor;
  /** Ordered independently expected key-transition contexts, at most 256 entries. */
  readonly transitions: ExpectedKeyTransition[];
  /** Independently obtained storage version, 1 to 512 UTF-8 bytes. */
  readonly objectVersion: string;
  /** Optional tightened resource limits; omission uses the profile maxima. */
  readonly bounds?: Bounds;
}

/**
 * An archived object supplied as arbitrary raw chunks and its storage version. Concatenation must
 * equal the exact archive bytes. Verification reads no filesystem or object store.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface ArchivedObject {
  /** Raw chunks whose concatenation is the exact archive. Boundaries have no wire meaning. */
  readonly chunks: Uint8Array[];
  /** Independently obtained storage version, 1 to 512 UTF-8 bytes. */
  readonly version: string;
}

/**
 * Already-trusted archive keys in handover order. The first key verifies the start anchor, the last
 * verifies the end anchor, and each transition advances one position. This is explicit trust input,
 * not key discovery.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface HistoricalKeyChain {
  /** Ordered trusted historical public keys, one more than the number of transitions. */
  readonly keys: HistoricalPublicKey[];
}

// --- shared closed-header / claim validators (derived from spec/bap-v1.md + RFCs) ---

// Parse a protected header object; validate the closed member set + alg + typ + kid.
function parseGrantHeader(seg: CompactSegments, bounds: Bounds): { kid: string } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "typ", "kid"], "grant header");
  requireStringLit(h, "alg", ALG, "grant header alg");
  requireStringLit(h, "typ", GRANT_TYP, "grant header typ");
  const kid = requireKid(h, bounds);
  return { kid };
}

type ProofProfile = "standard" | "local_loopback_http";

function proofTyp(profile: ProofProfile): string {
  return profile === "standard" ? PROOF_TYP : LOCAL_LOOPBACK_PROOF_TYP;
}

function parseProofHeader(seg: CompactSegments, bounds: Bounds, profile: ProofProfile = "standard"): { holderThumbprint: Uint8Array; holderKey: Uint8Array } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "typ", "jwk"], "proof header");
  requireStringLit(h, "alg", ALG, "proof header alg");
  requireStringLit(h, "typ", proofTyp(profile), "proof header typ");
  const jwkV = h.v.get("jwk")!;
  if (jwkV.t !== "object") fail("proof header: jwk object");
  // The OKP JWK has exactly {crv, kty, x}. Reject additional members, including private d,
  // under REQ1-HEADER-no-private-jwk.
  requireObjectExact(jwkV, ["crv", "kty", "x"], "proof jwk");
  requireStringLit(jwkV, "crv", "Ed25519", "proof jwk crv");
  requireStringLit(jwkV, "kty", "OKP", "proof jwk kty");
  const xV = jwkV.v.get("x")!;
  if (xV.t !== "string") fail("proof jwk: x string");
  const rawKey = base64urlDecode(xV.v);
  if (rawKey.length !== 32) fail("proof jwk: x width");
  const tp = thumbprintRaw(jwkFromPublicKey(rawKey));
  return { holderThumbprint: tp, holderKey: rawKey };
}

function parseAnchorHeader(seg: CompactSegments, bounds: Bounds): { kid: string } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "typ", "kid"], "anchor header");
  requireStringLit(h, "alg", ALG, "anchor header alg");
  requireStringLit(h, "typ", ANCHOR_TYP, "anchor header typ");
  const kid = requireKid(h, bounds);
  // Canonical form: the protected segment must be the exact JCS encoding (boundary_anchor_codec.ex:95-96).
  if (!bytesEqual(jcsEncode(h, bounds), seg.protectedBytes)) fail("anchor header: canonical");
  return { kid };
}

function parseTransitionHeader(seg: CompactSegments, bounds: Bounds): { kid: string } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "typ", "kid"], "transition header");
  requireStringLit(h, "alg", ALG, "transition header alg");
  requireStringLit(h, "typ", TRANSITION_TYP, "transition header typ");
  const kid = requireKid(h, bounds);
  // Canonical form: the protected segment must be the exact JCS encoding (key_transition_codec.ex:127-128).
  if (!bytesEqual(jcsEncode(h, bounds), seg.protectedBytes)) fail("transition header: canonical");
  return { kid };
}

function requireKid(h: Extract<Tagged, { t: "object" }>, bounds: Bounds): string {
  const kidV = h.v.get("kid")!;
  if (kidV.t !== "string") fail("header: kid string");
  const b = kidV.v;
  if (b.length < 1 || b.length > resolve(bounds, "kid_bytes" as MaximaKey)) fail("header: kid bytes");
  const s = utf8Str(b);
  if (!/^[A-Za-z0-9._~-]+$/.test(s)) fail("header: kid charset");
  return s;
}

function requireObjectExact(v: Tagged, keys: string[], ctx: string): asserts v is Extract<Tagged, { t: "object" }> {
  if (v.t !== "object") fail(`${ctx}: object`);
  const got = [...v.v.keys()].sort().join(",");
  const want = [...keys].sort().join(",");
  if (got !== want) fail(`${ctx}: closed members`);
}

function requireStringLit(obj: Extract<Tagged, { t: "object" }>, key: string, lit: string, ctx: string): void {
  const v = obj.v.get(key);
  if (!v || v.t !== "string" || utf8Str(v.v) !== lit) fail(`${ctx}: ${key}=${lit}`);
}

// Well-formed UTF-8 string check (mirrors the Elixir reference's String.valid?). Lone surrogates from a
// \uXXXX escape survive JSON.parse and the JCS round-trip, so byte-length checks alone do not catch
// them; the Elixir reference rejects such strings.
function isWellFormed(s: string): boolean {
  const anyStr = s as string & { isWellFormed?: () => boolean };
  return typeof anyStr.isWellFormed === "function"
    ? anyStr.isWellFormed()
    : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

// StringOrURI claim: non-empty, ≤ identifier_bytes, well-formed, valid StringOrURI.
function requireStringOrUri(v: Tagged | undefined, key: string, bounds: Bounds): string {
  if (!v || v.t !== "string") fail(`claim: ${key} string`);
  const s = utf8Str(v.v);
  const len = strUtf8(s).length;
  if (len < 1 || len > resolve(bounds, "identifier_bytes" as MaximaKey)) fail(`claim: ${key} bytes`);
  if (!isStringOrUri(s)) fail(`claim: ${key} string-or-uri`);
  return s;
}

function requireInt(v: Tagged | undefined, key: string): number {
  if (!v || v.t !== "int") fail(`claim: ${key} integer`);
  return v.v;
}

// Lowercase RFC 4122 UUID.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function requireUuid(v: Tagged | undefined, key: string): string {
  if (!v || v.t !== "string") fail(`claim: ${key} uuid string`);
  const s = utf8Str(v.v);
  if (!UUID_RE.test(s)) fail(`claim: ${key} uuid`);
  return s;
}

// Canonical base64url string of exactly N bytes → returns the raw bytes.
function requireB64urlN(v: Tagged | undefined, key: string, n: number): Uint8Array {
  if (!v || v.t !== "string") fail(`claim: ${key} b64url string`);
  const raw = base64urlDecode(v.v);
  if (raw.length !== n) fail(`claim: ${key} width`);
  return raw;
}

// Printable-ASCII operation name 1..operation_bytes (REQ1-CLAIM-operation-shape, valid_operation?).
function requireOperation(v: Tagged | undefined, key: string, bounds: Bounds): string {
  if (!v || v.t !== "string") fail(`claim: ${key} operation string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(bounds, "operation_bytes" as MaximaKey)) fail(`claim: ${key} operation bytes`);
  const s = utf8Str(b);
  if (!/^[\x20-\x7e]+$/.test(s)) fail(`claim: ${key} operation printable ASCII`);
  return s;
}

// RFC 9110 method token 1..method_bytes, ASCII token chars, byte-for-byte (no case-fold).
function requireMethod(v: Tagged | undefined, key: string, bounds: Bounds): string {
  if (!v || v.t !== "string") fail(`claim: ${key} method string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(bounds, "method_bytes" as MaximaKey)) fail(`claim: ${key} method bytes`);
  const s = utf8Str(b);
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(s)) fail(`claim: ${key} method token`);
  return s;
}

// A URI claim must fit uri_bytes and already equal its normalized HTTPS form. Re-normalization
// checks that equality.
function requireNormalizedUri(v: Tagged | undefined, key: string, bounds: Bounds, profile: ProofProfile = "standard"): string {
  if (!v || v.t !== "string") fail(`claim: ${key} uri string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(bounds, "uri_bytes" as MaximaKey)) fail(`claim: ${key} uri bytes`);
  const s = utf8Str(b);
  const norm = profile === "standard"
    ? uriNormalize(b, bounds)
    : localLoopbackHttpUriNormalize(b, bounds);
  if (!norm.ok) fail(`claim: ${key} uri normalized`);
  if (utf8Str(norm.value) !== s) fail(`claim: ${key} uri pre-normalized`);
  return s;
}

// Validate the closed grant payload members + operation structure. operations[] (NOT ba_req).
function validateGrantPayload(p: Tagged, bounds: Bounds): asserts p is Extract<Tagged, { t: "object" }> {
  requireObjectExact(p, ["v", "iss", "jti", "aud", "iat", "nbf", "exp", "cnf", "operations"], "grant payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("grant: v=1");
  const opsV = p.v.get("operations")!;
  if (opsV.t !== "array") fail("grant: operations array");
  if (opsV.v.length < 1 || opsV.v.length > resolve(bounds, "operations" as MaximaKey)) fail("grant: operations count");
  const names = new Set<string>();
  for (const op of opsV.v) {
    if (op.t !== "object") fail("grant: operation object");
    const opObj: Extract<Tagged, { t: "object" }> = op;
    requireObjectExact(opObj, ["name", "selectors"], "grant operation");
    const name = requireOperation(opObj.v.get("name"), "operation name", bounds);
    if (names.has(name)) fail("grant: operation name unique");
    names.add(name);
    const sels = opObj.v.get("selectors")!;
    if (sels.t !== "array") fail("grant: selectors array");
    if (sels.v.length < 1 || sels.v.length > resolve(bounds, "selectors" as MaximaKey)) fail("grant: selectors count");
    for (const s of sels.v) parseSelector(s, bounds); // Validate selector shape and path, value-count and node bounds with caller limits.
  }
}

function extractAudience(v: Tagged | undefined, bounds: Bounds): string[] {
  if (!v) fail("claim: aud");
  if (v.t === "string") {
    const s = utf8Str(v.v);
    const len = strUtf8(s).length;
    if (len < 1 || len > resolve(bounds, "identifier_bytes" as MaximaKey)) fail("claim: aud bytes");
    if (!isStringOrUri(s)) fail("claim: aud string-or-uri");
    return [s];
  }
  if (v.t === "array") {
    if (v.v.length < 1 || v.v.length > resolve(bounds, "audiences" as MaximaKey)) fail("claim: aud count");
    const seen = new Set<string>();
    const out: string[] = [];
    for (const a of v.v) {
      if (a.t !== "string") fail("claim: aud string");
      const s = utf8Str(a.v);
      const len = strUtf8(s).length;
      if (len < 1 || len > resolve(bounds, "identifier_bytes" as MaximaKey)) fail("claim: aud member bytes");
      if (!isStringOrUri(s)) fail("claim: aud member string-or-uri");
      if (seen.has(s)) fail("claim: aud unique");
      seen.add(s);
      out.push(s);
    }
    return out;
  }
  fail("claim: aud shape");
}

function validateProofPayload(p: Tagged, bounds: Bounds, profile: ProofProfile = "standard"): asserts p is Extract<Tagged, { t: "object" }> {
  if (p.t !== "object") fail("proof payload: object");
  const hasNonce = p.v.has("nonce");
  if (profile === "local_loopback_http" && !hasNonce) fail("proof: nonce required");
  const keys = hasNonce
    ? ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req", "nonce"]
    : ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req"];
  requireObjectExact(p, keys, "proof payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("proof: v=1");
  requireStringOrUri(p.v.get("jti"), "jti", bounds);
  requireMethod(p.v.get("htm"), "htm", bounds);
  requireNormalizedUri(p.v.get("htu"), "htu", bounds, profile);
  requireInt(p.v.get("iat"), "iat");
  requireUuid(p.v.get("ba_inv"), "ba_inv");
  requireOperation(p.v.get("ba_op"), "ba_op", bounds);
  requireB64urlN(p.v.get("ath"), "ath", 32);
  requireB64urlN(p.v.get("ba_req"), "ba_req", 32);
  if (hasNonce) {
    const n = p.v.get("nonce")!;
    if (n.t !== "string") fail("proof: nonce string");
    const ns = utf8Str(n.v);
    if (!isWellFormed(ns)) fail("proof: nonce well-formed");
    const len = strUtf8(ns).length;
    if (len < 1 || len > resolve(bounds, "nonce_bytes" as MaximaKey)) fail("proof: nonce bytes");
  }
}

// Validate the closed anchor payload (spec/bap-v1.md#chain § Boundary anchors).
function validateAnchorPayload(p: Tagged, payloadBytes: Uint8Array, bounds: Bounds): asserts p is Extract<Tagged, { t: "object" }> {
  requireObjectExact(p, ["anchor_id", "anchored_at", "chain_hash", "chain_id", "key_fingerprint", "sequence", "v"], "anchor payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("anchor: v=1");
  requireStringOrUri(p.v.get("anchor_id"), "anchor_id", bounds);
  requireInt(p.v.get("anchored_at"), "anchored_at");
  requireStringOrUri(p.v.get("chain_id"), "chain_id", bounds);
  requireInt(p.v.get("sequence"), "sequence");
  requireB64urlN(p.v.get("chain_hash"), "chain_hash", 32);
  requireB64urlN(p.v.get("key_fingerprint"), "key_fingerprint", 32);
  // Canonical form: the payload segment must be the exact JCS encoding (boundary_anchor_codec.ex:118-119).
  if (!bytesEqual(jcsEncode(p, bounds), payloadBytes)) fail("anchor payload: canonical");
}

// Validate the closed key-transition payload (spec/bap-v1.md#chain § Authenticated key transitions).
function validateTransitionPayload(p: Tagged, payloadBytes: Uint8Array, bounds: Bounds): asserts p is Extract<Tagged, { t: "object" }> {
  requireObjectExact(p, ["chain_id", "effective_at", "from_key_fingerprint", "to_key_fingerprint", "to_key_id", "transition_id", "v"], "transition payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("transition: v=1");
  requireStringOrUri(p.v.get("transition_id"), "transition_id", bounds);
  requireStringOrUri(p.v.get("chain_id"), "chain_id", bounds);
  requireInt(p.v.get("effective_at"), "effective_at");
  requireB64urlN(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32);
  requireB64urlN(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32);
  // to_key_id: a key id (kid charset + bytes), not a generic StringOrURI.
  const toKeyId = p.v.get("to_key_id")!;
  if (toKeyId.t !== "string") fail("transition: to_key_id string");
  const s = utf8Str(toKeyId.v);
  if (s.length < 1 || s.length > resolve(bounds, "kid_bytes" as MaximaKey)) fail("transition: to_key_id bytes");
  if (!/^[A-Za-z0-9._~-]+$/.test(s)) fail("transition: to_key_id charset");
  // Canonical form: the payload segment must be the exact JCS encoding (key_transition_codec.ex:151-152).
  if (!bytesEqual(jcsEncode(p, bounds), payloadBytes)) fail("transition payload: canonical");
}

// inWindow: valid_from <= time && (valid_before null/unbounded OR time < valid_before).
function inWindow(time: number, key: HistoricalPublicKey): boolean {
  return key.validFrom <= time && (key.validBefore === null || time < key.validBefore);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// --- the 17 façade functions ---


// Validate argument shapes before entering the verification body. Wrong types return Err rather
// than escaping as native TypeError or undergoing implicit string coercion. Structured
// arguments must be non-null objects with every field the body dereferences. The body then
// enforces field semantics. See spec/bap-v1.md#verification.

type Shape = "bytes" | "str" | "int" | "object" | "tagged" | { seq: Shape } | { fields: Record<string, Shape> } | { opt: Shape };

const SHAPE_BOUNDS_OPT: Shape = { opt: "object" };

const SHAPE_HIST_KEY: Shape = { fields: { keyId: "str", publicKey: "bytes", validFrom: "int", validBefore: { opt: "int" } } };
const SHAPE_GRANT_PRODUCER: Shape = { fields: { keyId: "str", issuer: "str", grantId: "str", audiences: { seq: "str" }, issuedAt: "int", notBefore: "int", expiresAt: "int", holderThumbprint: "str", operations: { seq: { fields: { name: "str" } } } } };
const SHAPE_PROOF_PRODUCER: Shape = { fields: { holderPublicKey: "bytes", proofId: "str", method: "str", targetUri: "str", issuedAt: "int", invocationId: "str", operation: "str", grantCompact: "bytes", castArguments: "tagged", nonce: { opt: "str" } } };
const SHAPE_ANCHOR_PRODUCER: Shape = { fields: { anchorId: "str", anchoredAt: "int", chainId: "str", sequence: "int", chainHash: "bytes", keyId: "str", publicKey: "bytes" } };
const SHAPE_TRANSITION_PRODUCER: Shape = { fields: { transitionId: "str", chainId: "str", effectiveAt: "int", currentKeyId: "str", currentPublicKey: "bytes", nextKeyId: "str", nextPublicKey: "bytes" } };
const SHAPE_EXPORT_INPUT: Shape = { fields: { rows: { seq: "bytes" }, startAnchor: "bytes", endAnchor: "bytes", transitions: { seq: "bytes" }, chainId: "str", firstSequence: "int", lastSequence: "int", rowCount: "int", previousHash: "bytes", lastHash: "bytes" } };
const SHAPE_EXPECTED_CHAIN: Shape = { fields: { chainId: "str", firstSequence: "int", lastSequence: "int", rowCount: "int", previousHash: "bytes", lastHash: "bytes", bounds: SHAPE_BOUNDS_OPT } };
const SHAPE_EXPECTED_ANCHOR: Shape = { fields: { anchorId: "str", anchoredAt: "int", chainId: "str", sequence: "int", chainHash: "bytes", keyId: "str", keyFingerprint: "bytes", bounds: SHAPE_BOUNDS_OPT } };
const SHAPE_EXPECTED_TRANSITION: Shape = { fields: { transitionId: "str", chainId: "str", effectiveAt: "int", currentKeyId: "str", currentKeyFingerprint: "bytes", nextKeyId: "str", nextKeyFingerprint: "bytes", bounds: SHAPE_BOUNDS_OPT } };
// Describe every nested field in the shape gate. Missing or wrong-typed nested members must
// reject before any dereference in the body.
const SHAPE_EXPECTED_EXPORT: Shape = { fields: { chain: SHAPE_EXPECTED_CHAIN, digest: "bytes", startAnchor: SHAPE_EXPECTED_ANCHOR, endAnchor: SHAPE_EXPECTED_ANCHOR, transitions: { seq: SHAPE_EXPECTED_TRANSITION }, objectVersion: "str", bounds: SHAPE_BOUNDS_OPT } };

function shapeOk(value: unknown, shape: Shape): boolean {
  if (shape === "bytes") return value instanceof Uint8Array;
  if (shape === "str") return typeof value === "string";
  if (shape === "int") return Number.isInteger(value); // rejects null/undefined/bool/float
  if (shape === "object") return typeof value === "object" && value !== null;
  if (shape === "tagged") return typeof value === "object" && value !== null && typeof (value as { t?: unknown }).t === "string";
  if ("seq" in shape) return Array.isArray(value) && value.every((item) => shapeOk(item, shape.seq));
  if ("opt" in shape) return value === undefined || value === null || shapeOk(value, shape.opt);
  if (typeof value !== "object" || value === null) return false;
  for (const [name, sub] of Object.entries(shape.fields)) {
    if (!shapeOk((value as Record<string, unknown>)[name], sub)) return false;
  }
  return true;
}

// The shape gate walks caller sequences before the body enforces count ceilings. Each element
// requires only a type check, so this initial validation remains linear in the supplied
// sequence length.
function closedShape(args: unknown[], shapes: Shape[]): void {
  for (let i = 0; i < shapes.length; i++) {
    if (!shapeOk(args[i], shapes[i]!)) fail(`shape: argument ${i}`);
  }
}

/**
 * Reads only the `kid` of a major-1 grant's protected header, to select a trusted key. The result
 * is a lookup hint (`trust: "not_evaluated"`), never trust.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns An untrusted protected-header key identifier in a success Result; no signature or trust is evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function untrustedKeyLocator(compact: Uint8Array, bounds?: Bounds): Result<KeyLocator> {
  return trying(() => {
    closedShape([compact, bounds], ["bytes", SHAPE_BOUNDS_OPT]);
    // Key-location decoding inspects only the protected segment of exactly three compact
    // segments. Payload and signature bytes are neither decoded nor independently size-checked.
    // Full parseCompact validation would reject inputs whose untrusted header hint is still
    // readable. The result remains an untrusted key identifier.
    const b = coerceBounds(bounds ?? MAXIMUM_BOUNDS);
    if (compact.length > resolve(b, "compact_bytes" as MaximaKey)) fail("key_locator: compact bound");
    // Exactly 3 segments on '.' (a 2- or 4-segment input fails the closed shape).
    const dots: number[] = [];
    for (let i = 0; i < compact.length; i++) if (compact[i] === DOT) dots.push(i);
    if (dots.length !== 2) fail("key_locator: three segments");
    const d0 = dots[0]!;
    // Exactly three segments are required. Empty payload and signature segments are permitted
    // here because key location decodes only the protected header. The protected segment must
    // be nonempty and decode to a valid grant header.
    if (d0 === 0) fail("key_locator: empty protected segment");
    const protectedText = compact.subarray(0, d0);
    if (protectedText.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) fail("key_locator: protected bound");
    const protectedBytes = base64urlDecode(protectedText, resolve(b, "decoded_segment_bytes" as MaximaKey));
    // Pass resolved caller bounds to protected-header JSON decoding so depth and total_nodes
    // limits apply.
    const h = jsonDecode(protectedBytes, b);
    requireObjectExact(h, ["alg", "typ", "kid"], "grant header");
    requireStringLit(h, "alg", ALG, "grant header alg");
    requireStringLit(h, "typ", GRANT_TYP, "grant header typ");
    const kidV = h.v.get("kid")!;
    if (kidV.t !== "string") fail("header: kid string");
    if (kidV.v.length < 1 || kidV.v.length > resolve(b, "kid_bytes" as MaximaKey)) fail("header: kid bytes");
    const kid = utf8Str(kidV.v);
    if (!/^[A-Za-z0-9._~-]+$/.test(kid)) fail("header: kid charset");
    return { keyId: kid, trust: "not_evaluated" as const };
  });
}

/**
 * Parses and validates a major-1 grant's structure and claims without checking its signature or
 * any context (`verification: "not_evaluated"`). For display and debugging, never for a decision.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns Structurally validated grant claims with verification not_evaluated in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function decodeGrant(compact: Uint8Array, bounds?: Bounds): Result<GrantDecoded> {
  return trying(() => {
    closedShape([compact, bounds], ["bytes", SHAPE_BOUNDS_OPT]);
    const b = bounds ?? MAXIMUM_BOUNDS;
    const seg = parseCompact(compact, b);
    const { kid } = parseGrantHeader(seg, b);
    const p = jsonDecode(seg.payloadBytes, b);
    validateGrantPayload(p, b);
    if (p.t !== "object") fail("decode_grant: payload object");
    const pobj = p;
    const iss = requireStringOrUri(pobj.v.get("iss"), "iss", b);
    const jti = requireStringOrUri(pobj.v.get("jti"), "jti", b);
    const aud = extractAudience(pobj.v.get("aud"), b);
    const iat = requireInt(pobj.v.get("iat"), "iat");
    const nbf = requireInt(pobj.v.get("nbf"), "nbf");
    const exp = requireInt(pobj.v.get("exp"), "exp");
    if (!(iat < exp) || !(nbf < exp)) fail("grant: times coherent");
    const cnf = pobj.v.get("cnf")!;
    requireObjectExact(cnf, ["jkt"], "grant cnf");
    const jkt = requireB64urlN(cnf.v.get("jkt"), "jkt", 32);
    return {
      keyId: kid, issuer: iss, grantId: jti, audiences: aud,
      issuedAt: iat, notBefore: nbf, expiresAt: exp,
      holderThumbprint: jkt, verification: "not_evaluated" as const,
    };
  });
}

/**
 * Parses and validates a standard (`dpop+jwt`) major-1 holder proof without checking its signature
 * or any context (`verification: "not_evaluated"`).
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns Structurally validated proof claims with verification not_evaluated in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function decodeProof(compact: Uint8Array, bounds?: Bounds): Result<ProofDecoded> {
  return decodeProofFor(compact, bounds, "standard");
}

/**
 * Parses and validates a local-loopback (`ba+loopback-proof`) holder proof without checking its
 * signature or any context.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-local-loopback-http-v1.md#4-public-verification-contract
 * @returns Structurally validated loopback-proof claims with verification not_evaluated in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function decodeLocalLoopbackHttpProof(compact: Uint8Array, bounds?: Bounds): Result<ProofDecoded> {
  return decodeProofFor(compact, bounds, "local_loopback_http");
}

function decodeProofFor(compact: Uint8Array, bounds: Bounds | undefined, profile: ProofProfile): Result<ProofDecoded> {
  return trying(() => {
    closedShape([compact, bounds], ["bytes", SHAPE_BOUNDS_OPT]);
    const b = bounds ?? MAXIMUM_BOUNDS;
    const seg = parseCompact(compact, b);
    const { holderThumbprint } = parseProofHeader(seg, b, profile);
    const p = jsonDecode(seg.payloadBytes, b);
    validateProofPayload(p, b, profile);
    const jti = requireStringOrUri(p.v.get("jti"), "jti", b);
    return { proofId: jti, holderThumbprint, verification: "not_evaluated" as const };
  });
}

/**
 * Verifies a major-1 grant against the trusted issuer key and the expected issuer, audience and
 * time. Facts carry `authorization: "not_evaluated"`: verification is not authority.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns Redacted GrantFacts in a success Result, with authorization not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function verifyGrant(compact: Uint8Array, trusted: TrustedIssuer, expected: ExpectedGrant): Result<GrantFacts> {
  return trying(() => {
    closedShape([compact, trusted, expected], ["bytes", "object", "object"]);
    // Validate the trusted issuer structure before dereferencing publicKey or keyId. Null,
    // missing fields and wrong types must return the closed error without a native TypeError.
    if (trusted === null || trusted === undefined) fail("verify_grant: trusted issuer required");
    if (!(trusted.publicKey instanceof Uint8Array) || trusted.publicKey.length !== 32) fail("verify_grant: issuer key width");
    if (typeof trusted.keyId !== "string") fail("verify_grant: issuer key id");
    // Evaluation time and clock skew must be integers, and skew must be nonnegative. A range-
    // only check would admit fractional times.
    if (!Number.isInteger(expected.evaluationTime)) fail("verify_grant: integer evaluation time");
    // The reference resolves Bounds.coerce(expected.bounds) once (runtime.ex:186) and threads it
    // into validate_expected_grant (clock_skew <= bounds.clock_skew) + every bound-sensitive check
    // below. A caller tightening via expected.bounds now actually takes effect.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    if (!Number.isInteger(expected.clockSkew) || expected.clockSkew < 0 || expected.clockSkew > resolve(b, "clock_skew" as MaximaKey)) fail("verify_grant: skew");
    const seg = parseCompact(compact, b);
    const { kid } = parseGrantHeader(seg, b);
    if (kid !== trusted.keyId) fail("verify_grant: kid exact");
    const p = jsonDecode(seg.payloadBytes, b);
    validateGrantPayload(p, b);
    if (p.t !== "object") fail("verify_grant: payload object");
    const pobj = p;
    const iss = requireStringOrUri(pobj.v.get("iss"), "iss", b);
    if (iss !== expected.issuer) fail("verify_grant: issuer exact");
    const aud = extractAudience(pobj.v.get("aud"), b);
    if (!aud.includes(expected.audience)) fail("verify_grant: audience match");
    const iat = requireInt(pobj.v.get("iat"), "iat");
    const nbf = requireInt(pobj.v.get("nbf"), "nbf");
    const exp = requireInt(pobj.v.get("exp"), "exp");
    if (!(iat < exp) || !(nbf < exp)) fail("verify_grant: times coherent");
    if (!(iat <= expected.evaluationTime + expected.clockSkew)) fail("verify_grant: iat window");
    if (!(nbf <= expected.evaluationTime + expected.clockSkew)) fail("verify_grant: nbf window");
    if (!(exp > expected.evaluationTime - expected.clockSkew)) fail("verify_grant: exp window");
    const cnf = pobj.v.get("cnf")!;
    requireObjectExact(cnf, ["jkt"], "grant cnf");
    const jkt = requireB64urlN(cnf.v.get("jkt"), "jkt", 32);
    const fp = thumbprintRaw(jwkFromPublicKey(trusted.publicKey));
    const key = importPublicKey(trusted.publicKey, utf8Str(base64urlEncode(fp)));
    if (!ed25519Verify(seg.signingInput, seg.signature, key)) fail("verify_grant: signature");
    return redacted({
      version: VERSION, issuer: iss, grantId: requireStringOrUri(p.v.get("jti"), "jti", b),
      issuerKeyFingerprint: fp, holderThumbprint: jkt, matchedAudience: expected.audience,
      issuedAt: iat, notBefore: nbf, expiresAt: exp, authorization: "not_evaluated" as const,
    }, "V1.GrantFacts");
  });
}

/**
 * Verifies a major-1 grant and its holder proof against one request: both signatures, issuer,
 * audience, time windows, holder binding, method, URI, invocation id, operation, request digest,
 * nonce and every selector of the operation.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns Redacted EnvelopeFacts for the matched request in a success Result. Authorization remains not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function checkEnvelope(grantCompact: Uint8Array, proofCompact: Uint8Array, expected: ExpectedRequest): Result<EnvelopeFacts> {
  return checkEnvelopeFor(grantCompact, proofCompact, expected, "standard");
}

/**
 * Like `checkEnvelope`, for a local-loopback proof: the target is `http://127.0.0.1` or
 * `http://[::1]` and `nonce` must be `{ kind: "required", value }`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-local-loopback-http-v1.md#4-public-verification-contract
 * @returns Redacted EnvelopeFacts for the matched loopback request in a success Result. Authorization remains not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function checkLocalLoopbackHttpEnvelope(grantCompact: Uint8Array, proofCompact: Uint8Array, expected: ExpectedRequest): Result<EnvelopeFacts> {
  return checkEnvelopeFor(grantCompact, proofCompact, expected, "local_loopback_http");
}

function checkEnvelopeFor(grantCompact: Uint8Array, proofCompact: Uint8Array, expected: ExpectedRequest, profile: ProofProfile): Result<EnvelopeFacts> {
  return trying(() => {
    closedShape([grantCompact, proofCompact, expected], ["bytes", "bytes", "object"]);
    const t = expected.trustedIssuer;
    // A null/wrong-typed trustedIssuer (or any structured- input field) must fail closed as
    // InvalidError, not propagate a native TypeError from the deref below. Validate the context
    // shape before touching it. The reference returns {:error,:invalid} for all malformed input.
    if (t === null || t === undefined) fail("check_envelope: trusted issuer required");
    if (!(t.publicKey instanceof Uint8Array) || t.publicKey.length !== 32) fail("check_envelope: issuer key width");
    if (typeof t.keyId !== "string") fail("check_envelope: issuer key id");
    // Evaluation time and clock skew must be integers; skew must be nonnegative and proofMaxAge
    // strictly positive. A range-only check would admit fractional times or a zero proof age.
    if (!Number.isInteger(expected.evaluationTime)) fail("check_envelope: integer evaluation time");
    // The reference resolves Bounds.coerce(expected.bounds) once (runtime.ex:204) and threads it
    // into validate_expected_request (clock_skew, proof_max_age) + parse_grant + parse_proof +
    // every bound-sensitive claim check below. A caller tightening via expected.bounds now takes
    // effect across both the grant and the proof.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    if (!Number.isInteger(expected.clockSkew) || expected.clockSkew < 0 || expected.clockSkew > resolve(b, "clock_skew" as MaximaKey)) fail("check_envelope: skew");
    if (!Number.isInteger(expected.proofMaxAge) || expected.proofMaxAge <= 0 || expected.proofMaxAge > resolve(b, "proof_max_age" as MaximaKey)) fail("check_envelope: proof_max_age");
    const expectedNonce = expected.nonce as unknown;
    if (typeof expectedNonce !== "object" || expectedNonce === null) fail("check_envelope: nonce shape");
    const nonceKind = (expectedNonce as { kind?: unknown }).kind;
    if (nonceKind !== "not_required" && nonceKind !== "required") fail("check_envelope: nonce kind");
    if (nonceKind === "required" && typeof (expectedNonce as { value?: unknown }).value !== "string") {
      fail("check_envelope: nonce value");
    }
    if (profile === "local_loopback_http" && nonceKind !== "required") fail("check_envelope: nonce required");
    const expectedUri = profile === "standard"
      ? uriNormalize(strUtf8(expected.targetUri), b)
      : localLoopbackHttpUriNormalize(strUtf8(expected.targetUri), b);
    if (!expectedUri.ok || utf8Str(expectedUri.value) !== expected.targetUri) fail("check_envelope: expected target_uri");
    // --- verify grant (issuer signature + context) ---
    const gseg = parseCompact(grantCompact, b);
    const { kid: gkid } = parseGrantHeader(gseg, b);
    if (gkid !== t.keyId) fail("check_envelope: grant kid");
    const gp = jsonDecode(gseg.payloadBytes, b);
    validateGrantPayload(gp, b);
    if (gp.t !== "object") fail("check_envelope: grant payload");
    const gobj = gp;
    const giss = requireStringOrUri(gobj.v.get("iss"), "iss", b);
    if (giss !== expected.issuer) fail("check_envelope: issuer");
    const gaud = extractAudience(gobj.v.get("aud"), b);
    if (!gaud.includes(expected.audience)) fail("check_envelope: audience");
    const giat = requireInt(gobj.v.get("iat"), "iat");
    const gnbf = requireInt(gobj.v.get("nbf"), "nbf");
    const gexp = requireInt(gobj.v.get("exp"), "exp");
    // CheckEnvelope must enforce grant-time coherence (iat<exp, nbf<exp), mirroring the reference's
    // coherent_times? (runtime.ex:872-875) which fires at parse time. decodeGrant and verifyGrant
    // already check this; checkEnvelope had its own inline path that omitted it.
    if (!(giat < gexp) || !(gnbf < gexp)) fail("check_envelope: grant times coherent");
    if (!(giat <= expected.evaluationTime + expected.clockSkew)) fail("check_envelope: grant iat");
    if (!(gnbf <= expected.evaluationTime + expected.clockSkew)) fail("check_envelope: grant nbf");
    if (!(gexp > expected.evaluationTime - expected.clockSkew)) fail("check_envelope: grant exp");
    const gfp = thumbprintRaw(jwkFromPublicKey(t.publicKey));
    const gkey = importPublicKey(t.publicKey, utf8Str(base64urlEncode(gfp)));
    if (!ed25519Verify(gseg.signingInput, gseg.signature, gkey)) fail("check_envelope: grant signature");
    // --- verify proof (holder signature) ---
    const pseg = parseCompact(proofCompact, b);
    const { holderThumbprint, holderKey } = parseProofHeader(pseg, b, profile);
    const pp = jsonDecode(pseg.payloadBytes, b);
    validateProofPayload(pp, b, profile);
    const hkey = importPublicKey(holderKey, utf8Str(base64urlEncode(holderThumbprint)));
    if (!ed25519Verify(pseg.signingInput, pseg.signature, hkey)) fail("check_envelope: proof signature");
    if (pp.t !== "object") fail("check_envelope: proof payload");
    // Compute ath as SHA-256 of the ASCII grant compact after the structural size scan. The
    // scan checks framing and bounds without imposing base64url canonicality. Verification has
    // already parsed the grant, but uses the same hash gate as producers.
    scanCompact(grantCompact, b);
    const athRaw = sha256(grantCompact);
    const athB64 = utf8Str(base64urlEncode(athRaw));
    const ppAth = pp.v.get("ath")!;
    if (ppAth.t !== "string" || utf8Str(ppAth.v) !== athB64) fail("check_envelope: ath");
    // Method / URI / invocation / operation bindings.
    const htm = requireMethod(pp.v.get("htm"), "htm", b);
    if (htm !== expected.method) fail("check_envelope: method");
    const htu = requireNormalizedUri(pp.v.get("htu"), "htu", b, profile);
    if (htu !== expected.targetUri) fail("check_envelope: target_uri");
    const baInv = requireUuid(pp.v.get("ba_inv"), "ba_inv");
    if (baInv !== expected.invocationId) fail("check_envelope: invocation_id");
    const baOp = requireOperation(pp.v.get("ba_op"), "ba_op", b);
    if (baOp !== expected.operation) fail("check_envelope: operation");
    // ba_req = request_digest(operation, cast_arguments) (base64url).
    const baReqRaw = computeRequestDigest(baOp, expected.castArguments, b);
    const baReqB64 = utf8Str(base64urlEncode(baReqRaw));
    const ppBaReq = pp.v.get("ba_req")!;
    if (ppBaReq.t !== "string" || utf8Str(ppBaReq.v) !== baReqB64) fail("check_envelope: ba_req");
    // Proof time window (REQ1-VERIFY-envelope-binding).
    const piat = requireInt(pp.v.get("iat"), "iat");
    if (!(piat >= expected.evaluationTime - expected.proofMaxAge - expected.clockSkew)) fail("check_envelope: proof iat min");
    if (!(piat <= expected.evaluationTime + expected.clockSkew)) fail("check_envelope: proof iat max");
    // Nonce binding.
    const ppNonce = pp.v.get("nonce");
    if (expected.nonce.kind === "not_required") {
      if (ppNonce !== undefined) fail("check_envelope: nonce must be absent");
    } else {
      if (!ppNonce || ppNonce.t !== "string" || utf8Str(ppNonce.v) !== expected.nonce.value) fail("check_envelope: nonce mismatch");
    }
    // Holder thumbprint must match grant cnf.jkt.
    const cnf = gobj.v.get("cnf")!;
    requireObjectExact(cnf, ["jkt"], "grant cnf");
    const jkt = requireB64urlN(cnf.v.get("jkt"), "jkt", 32);
    if (!bytesEqual(jkt, holderThumbprint)) fail("check_envelope: holder thumbprint");
    // The requested operation must be unique + every selector conjunctively matches.
    const opsV = gobj.v.get("operations");
    if (!opsV || opsV.t !== "array") fail("check_envelope: operations");
    const matching = opsV.v.filter((op): op is Extract<Tagged, { t: "object" }> => {
      if (op.t !== "object") return false;
      const nameV = op.v.get("name");
      return nameV !== undefined && nameV.t === "string" && utf8Str(nameV.v) === expected.operation;
    });
    if (matching.length !== 1) fail("check_envelope: unique operation");
    const matchOp = matching[0]!;
    const selsV = matchOp.v.get("selectors");
    if (!selsV || selsV.t !== "array") fail("check_envelope: selectors");
    for (const s of selsV.v) {
      const sel = parseSelector(s, b);
      if (!selectorMatches(sel, expected.castArguments)) fail("check_envelope: selector");
    }
    return redacted({
      version: VERSION, issuer: giss,
      grantId: requireStringOrUri(gobj.v.get("jti"), "jti", b),
      issuerKeyFingerprint: gfp, holderThumbprint, matchedAudience: expected.audience,
      grantIssuedAt: giat, grantNotBefore: gnbf, grantExpiresAt: gexp,
      proofId: requireStringOrUri(pp.v.get("jti"), "jti", b),
      invocationId: baInv, operation: baOp, uri: htu,
      grantHash: athRaw, requestHash: baReqRaw, proofIssuedAt: piat,
      authorization: "not_evaluated" as const,
    }, "V1.EnvelopeFacts");
  });
}

/**
 * The 32-byte request digest a proof carries as `ba_req`: SHA-256 over `BAP1-REQUEST\0` and the
 * JCS of `[operation, typed(castArguments)]`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#datamodel
 * @returns The raw 32-byte SHA-256 request digest in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function requestDigest(operation: string, castArguments: Tagged, bounds?: Bounds): Result<Uint8Array> {
  return trying(() => {
    closedShape([operation, castArguments, bounds], ["str", "tagged", SHAPE_BOUNDS_OPT]);
    return computeRequestDigest(operation, castArguments, bounds ?? MAXIMUM_BOUNDS);
  });
}

/**
 * Successful row encoding: canonical UTF-8 JSON and its major-specific SHA-256 chain-link digest.
 * Encoding is not an execution receipt.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 */
export interface EncodedConsumptionEntry {
  /** Complete canonical consumption-row UTF-8 JSON bytes. */
  readonly bytes: Uint8Array;
  /** Raw 32-byte SHA-256 of the major-specific row prefix followed by bytes. */
  readonly hash: Uint8Array;
}
/**
 * Encodes one consumption row as canonical bytes and returns them with the row hash, SHA-256 over
 * `BAP1-CHAIN\0` and the bytes.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 * @returns Canonical row bytes and their raw 32-byte chain-link hash in a success Result. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function encodeConsumptionEntry(entry: ConsumptionEntry, bounds?: Bounds): Result<EncodedConsumptionEntry> {
  return trying(() => {
    closedShape([entry, bounds], [{ fields: { chainId: "str", sequence: "int", previousHash: "bytes", commitment: "bytes" } }, SHAPE_BOUNDS_OPT]);
    const b = bounds ?? MAXIMUM_BOUNDS;
    if (!Number.isInteger(entry.sequence) || entry.sequence < 1) fail("encode_consumption_entry: positive sequence");
    assert(entry.previousHash.length === 32, "encode_consumption_entry: previous_hash width");
    assert(entry.commitment.length === 32, "encode_consumption_entry: commitment width");
    const chainIdBytes = strUtf8(entry.chainId);
    if (chainIdBytes.length < 1 || chainIdBytes.length > resolve(b, "identifier_bytes" as MaximaKey)) fail("encode_consumption_entry: chain_id bytes");
    if (!isStringOrUri(entry.chainId)) fail("encode_consumption_entry: chain_id string-or-uri");
    // Genesis invariant (consumption_chain.ex:123 validate_entry): sequence 1 requires the
    // all-zero predecessor. The verifier re-checks this, but the producer must reject pre-signing.
    if (entry.sequence === 1 && !bytesEqual(entry.previousHash, DEFAULT_HASH)) fail("encode_consumption_entry: genesis predecessor");
    const rowBytes = canonicalRowBytesFromId(chainIdBytes, entry.sequence, entry.previousHash, entry.commitment, b);
    if (rowBytes.length > resolve(b, "chain_row_bytes" as MaximaKey)) fail("encode_consumption_entry: chain_row_bytes");
    const hash = sha256(ROW_PREFIX, rowBytes);
    return { bytes: rowBytes, hash };
  });
}

// The canonical row bytes shared by the producer and the verifier (so the verifier's re-encode
// produces EXACTLY the bytes the producer emits and the chain hash is computed over). Two entry
// points: the producer works from the chain_id UTF-8 bytes it already validated; the verifier works
// from the decoded chain_id string (re-encoding it to bytes). Both must agree byte-for-byte.
function canonicalRowBytesFromId(chainIdBytes: Uint8Array, sequence: number, previousHash: Uint8Array, commitment: Uint8Array, b: Bounds): Uint8Array {
  const members = new Map<string, Tagged>([
    ["chain_id", { t: "string", v: chainIdBytes }],
    ["commitment", { t: "string", v: strUtf8(utf8Str(base64urlEncode(commitment))) }],
    ["previous", { t: "string", v: strUtf8(utf8Str(base64urlEncode(previousHash))) }],
    ["sequence", { t: "int", v: sequence }],
    ["v", { t: "int", v: VERSION }],
  ]);
  return jcsEncode({ t: "object", v: members }, b);
}

function canonicalRowBytes(chainId: string, sequence: number, previousHash: Uint8Array, commitment: Uint8Array, b: Bounds = MAXIMUM_BOUNDS): Uint8Array {
  return canonicalRowBytesFromId(strUtf8(chainId), sequence, previousHash, commitment, b);
}

/**
 * Verifies a contiguous range of raw consumption rows against the expected chain id, sequences,
 * count, predecessor hash and head hash. Facts carry `trust: "not_evaluated"`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 * @returns Boundary-consistent ChainFacts in a success Result, with trust not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function checkChain(chain: ChainInput, expected: ExpectedChain): Result<ChainFacts> {
  return trying(() => {
    closedShape([chain, expected], [{ fields: { rows: { seq: "bytes" }, chainId: "str", firstSequence: "int", lastSequence: "int", rowCount: "int", previousHash: "bytes", lastHash: "bytes" } }, { fields: { chainId: "str", firstSequence: "int", lastSequence: "int", rowCount: "int", previousHash: "bytes", lastHash: "bytes", bounds: SHAPE_BOUNDS_OPT } }]);
    // The reference resolves Bounds.coerce(expected.bounds) once (consumption_chain.ex check_chain)
    // and threads it into the row-count bound + every parse_row (chain_row_bytes). A caller
    // tightening via expected.bounds now takes effect.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    if (typeof chain.chainId !== "string" || !isStringOrUri(chain.chainId) || expected.chainId !== chain.chainId) fail("check_chain: chain_id");
    if (expected.firstSequence !== chain.firstSequence) fail("check_chain: first_sequence");
    if (expected.lastSequence !== chain.lastSequence) fail("check_chain: last_sequence");
    if (expected.rowCount !== chain.rowCount) fail("check_chain: row_count");
    if (chain.rowCount !== chain.rows.length || chain.rowCount < 1) fail("check_chain: row count");
    if (chain.rowCount > resolve(b, "chain_rows" as MaximaKey)) fail("check_chain: chain_rows bound");
    if (chain.lastSequence !== chain.firstSequence + chain.rowCount - 1) fail("check_chain: range");
    // Genesis: firstSequence === 1 requires the all-zero predecessor.
    if (chain.firstSequence === 1) {
      if (!bytesEqual(expected.previousHash, DEFAULT_HASH)) fail("check_chain: genesis predecessor");
    }
    // The reference's check_chain takes ChainInput{rows} + ExpectedChain and uses
    // expected.previous_hash as BOTH the validation seed and the returned fact; the SDK's
    // ChainInput also carries a previousHash that must equal the expected value (the non-genesis
    // row walk would otherwise seed from expected while the input field flows unchecked into the
    // returned facts). Validate equality in BOTH cases so chain.previousHash is never an unverified
    // echo.
    if (!bytesEqual(expected.previousHash, chain.previousHash)) fail("check_chain: previous_hash");
    let previous = expected.previousHash;
    let sequence = chain.firstSequence;
    for (let i = 0; i < chain.rows.length; i++) {
      const rowBytes = chain.rows[i]!;
      if (rowBytes.length > resolve(b, "chain_row_bytes" as MaximaKey)) fail(`check_chain: row ${i} bytes`);
      const row = jsonDecode(rowBytes, b);
      requireObjectExact(row, ["v", "chain_id", "sequence", "previous", "commitment"], `check_chain row ${i}`);
      const vV = row.v.get("v")!;
      if (vV.t !== "int" || vV.v !== VERSION) fail(`check_chain row ${i}: v`);
      const cidV = row.v.get("chain_id")!;
      if (cidV.t !== "string" || utf8Str(cidV.v) !== chain.chainId) fail(`check_chain row ${i}: chain_id`);
      const seqV = row.v.get("sequence")!;
      if (seqV.t !== "int" || seqV.v !== sequence) fail(`check_chain row ${i}: sequence`);
      // valid_sequence?: sequence must be strictly positive (> 0). The encode_consumption_entry
      // producer already rejects sequence < 1, but the raw row stream is untrusted input here, so
      // reject sequence 0 at verify time too (mirrors consumption_chain.ex:163 valid_sequence?).
      if (seqV.v < 1) fail(`check_chain row ${i}: sequence positive`);
      const prevRaw = requireB64urlN(row.v.get("previous"), "previous", 32);
      if (!bytesEqual(prevRaw, previous)) fail(`check_chain row ${i}: previous link`);
      const commitmentRaw = requireB64urlN(row.v.get("commitment"), "commitment", 32);
      // Canonical re-encode: the input row bytes MUST byte-equal the canonical re-encoded form
      // (mirrors consumption_chain.ex:96 parse_row `encode(entry).bytes == ^bytes`). This rejects
      // whitespace drift and member-order drift that would otherwise hash to a different chain link.
      const reEncoded = canonicalRowBytes(chain.chainId, seqV.v, prevRaw, commitmentRaw, b);
      if (!bytesEqual(reEncoded, rowBytes)) fail(`check_chain row ${i}: canonical`);
      previous = sha256(ROW_PREFIX, rowBytes);
      sequence++;
    }
    if (!bytesEqual(previous, expected.lastHash)) fail("check_chain: head");
    return redacted({
      version: 1 as const, chainId: chain.chainId, firstSequence: chain.firstSequence,
      lastSequence: chain.lastSequence, rowCount: chain.rowCount,
      // Copy the VERIFIED expected.previousHash (not the caller's chain.previousHash input) into a
      // fresh Uint8Array so a later mutation of either input buffer does not change the returned
      // fact (the reference's Elixir binaries are immutable; TS arrays are not). The reference
      // returns expected.previous_hash; lastHash is freshly computed.
      previousHash: new Uint8Array(expected.previousHash), lastHash: previous,
      verification: "boundary_consistent" as const, trust: "not_evaluated" as const,
    }, "V1.ChainFacts");
  });
}

/**
 * Builds the exact major-1 grant signing input. Sign the bytes `protectedSegment`, `.`,
 * `payloadSegment` with the issuer key, then call `assembleCompact`; the package never signs.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns Canonical protected and payload base64url segments for the grant in a success Result. Sign their exact dot-separated ASCII bytes externally. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function grantSigningInput(grant: GrantProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
    closedShape([grant, bounds], [SHAPE_GRANT_PRODUCER, SHAPE_BOUNDS_OPT]);
    const b = bounds ?? MAXIMUM_BOUNDS;
    const keyIdBytes = strUtf8(grant.keyId);
    if (keyIdBytes.length < 1 || keyIdBytes.length > resolve(b, "kid_bytes" as MaximaKey)) fail("grant_signing_input: key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(grant.keyId)) fail("grant_signing_input: key_id charset");
    if (!isStringOrUri(grant.issuer)) fail("grant_signing_input: issuer");
    if (!isStringOrUri(grant.grantId)) fail("grant_signing_input: grant_id");
    if (grant.audiences.length < 1 || grant.audiences.length > resolve(b, "audiences" as MaximaKey)) fail("grant_signing_input: audiences count");
    for (const a of grant.audiences) {
      const ab = strUtf8(a);
      if (ab.length < 1 || ab.length > resolve(b, "identifier_bytes" as MaximaKey)) fail("grant_signing_input: audience bytes");
      if (!isStringOrUri(a)) fail("grant_signing_input: audience string-or-uri");
    }
    if (!Number.isInteger(grant.issuedAt) || !Number.isInteger(grant.notBefore) || !Number.isInteger(grant.expiresAt)) fail("grant_signing_input: integer times");
    const jktRaw = base64urlDecode(strUtf8(grant.holderThumbprint));
    if (jktRaw.length !== 32) fail("grant_signing_input: holder_thumbprint width");
    if (grant.operations.length < 1 || grant.operations.length > resolve(b, "operations" as MaximaKey)) fail("grant_signing_input: operations count");
    const header = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["kid", { t: "string", v: keyIdBytes }],
      ["typ", { t: "string", v: strUtf8(GRANT_TYP) }],
    ]);
    const payload = buildGrantPayload(grant, b);
    return {
      kind: "grant",
      protectedSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: header }, b)))),
      payloadSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode(payload, b)))),
    };
  });
}

function buildGrantPayload(grant: GrantProducer, b: Bounds): Tagged {
  const audMembers: Tagged[] = grant.audiences.map((a) => ({ t: "string", v: strUtf8(a) }));
  const opsMembers: Tagged[] = grant.operations.map((op): Tagged => {
    const nameBytes = strUtf8(op.name);
    if (nameBytes.length < 1 || nameBytes.length > resolve(b, "operation_bytes" as MaximaKey)) fail("grant_signing_input: operation name bytes");
    if (!/^[\x20-\x7e]+$/.test(op.name)) fail("grant_signing_input: operation name charset");
    // The scalar shape gate cannot express the selectors union of the bare "all" string and
    // selector objects. Check the array here; selectorToTagged validates each item. Malformed
    // selectors must return the closed Result error.
    if (!Array.isArray(op.selectors)) fail("grant_signing_input: selectors array");
    if (op.selectors.length < 1 || op.selectors.length > resolve(b, "selectors" as MaximaKey)) fail("grant_signing_input: selectors count");
    const sels: Tagged[] = op.selectors.map((s) => selectorToTagged(s, b));
    const opMembers = new Map<string, Tagged>([
      ["name", { t: "string", v: nameBytes }],
      ["selectors", { t: "array", v: sels }],
    ]);
    return { t: "object", v: opMembers };
  });
  const cnfMembers = new Map<string, Tagged>([["jkt", { t: "string", v: strUtf8(grant.holderThumbprint) }]]);
  const payload = new Map<string, Tagged>([
    ["aud", { t: "array", v: audMembers }],
    ["cnf", { t: "object", v: cnfMembers }],
    ["exp", { t: "int", v: grant.expiresAt }],
    ["iat", { t: "int", v: grant.issuedAt }],
    ["iss", { t: "string", v: strUtf8(grant.issuer) }],
    ["jti", { t: "string", v: strUtf8(grant.grantId) }],
    ["nbf", { t: "int", v: grant.notBefore }],
    ["operations", { t: "array", v: opsMembers }],
    ["v", { t: "int", v: VERSION }],
  ]);
  return { t: "object", v: payload };
}

// Normalize a selector input (bare "all" string or object) to the tagged form for JCS.
function selectorToTagged(s: SelectorInput, b: Bounds): Tagged {
  // Leaf gates for the caller-shaped selector input: a null item, a non-array path (a string path
  // iterated as CHARACTERS and was silently minted), a non-string path member, a non-array values,
  // or a non-tagged value previously threw a native TypeError past the Result contract or coerced
  // into the signed grant.
  if (s === null || s === undefined) fail("selector: shape");
  if (s !== "all" && typeof s !== "object") fail("selector: shape");
  if (s === "all" || (typeof s === "object" && s.kind === "all")) {
    return { t: "object", v: new Map<string, Tagged>([["kind", { t: "string", v: strUtf8("all") }]]) };
  }
  if (typeof s === "object" && s.kind === "equals") {
    const path = validatePath(s.path, b);
    validateSelectorValue(s.value, b);
    producerValueGate(s.value);
    const members = new Map<string, Tagged>([
      ["kind", { t: "string", v: strUtf8("equals") }],
      ["path", path],
      ["value", s.value],
    ]);
    return { t: "object", v: members };
  }
  if (typeof s === "object" && s.kind === "one_of") {
    const path = validatePath(s.path, b);
    if (!Array.isArray(s.values)) fail("selector: values array");
    if (s.values.length < 1 || s.values.length > resolve(b, "one_of_values" as MaximaKey)) fail("selector: values count");
    for (const v of s.values) {
      validateSelectorValue(v, b);
      producerValueGate(v);
    }
    const members = new Map<string, Tagged>([
      ["kind", { t: "string", v: strUtf8("one_of") }],
      ["path", path],
      ["values", { t: "array", v: s.values }],
    ]);
    return { t: "object", v: members };
  }
  fail("selector: shape");
}

// Erratum 6, producers (REQ1-SIGNING-integral-float-selector): RFC 8785 writes an integral float
// as integer text, which decodes integer-tagged, so the producer refuses a float-tagged integral
// selector value (equals, one_of) at any depth rather than sign a value whose tag the wire changes.
function producerValueGate(v: Tagged): void {
  if (!integralFloatFree(v)) fail("grant_signing_input: float-tagged integral selector value");
}

function validatePath(path: string[], b: Bounds): Tagged {
  if (!Array.isArray(path)) fail("selector: path array");
  for (const seg of path) if (typeof seg !== "string") fail("selector: path segment string");
  if (path.length < 1 || path.length > resolve(b, "path_segments" as MaximaKey)) fail("selector: path length");
  const segs: Tagged[] = [];
  for (const seg of path) {
    const sb = strUtf8(seg);
    if (sb.length < 1 || sb.length > resolve(b, "key_bytes" as MaximaKey)) fail("selector: path segment bytes");
    segs.push({ t: "string", v: sb });
  }
  return { t: "array", v: segs };
}

function validateSelectorValue(v: Tagged, b: Bounds): void {
  if (v === null || v === undefined || typeof v !== "object" || typeof v.t !== "string") {
    fail("selector: value shape");
  }
  checkNode(v, 1, b);
}

function checkNode(v: Tagged, depth: number, b: Bounds): void {
  if (depth > resolve(b, "depth" as MaximaKey)) fail("selector: value depth");
  switch (v.t) {
    case "string":
      if (v.v.length > resolve(b, "string_bytes" as MaximaKey)) fail("selector: string bytes");
      return;
    case "int":
      if (Math.abs(v.v) > resolve(b, "integer_magnitude" as MaximaKey)) fail("selector: int magnitude");
      return;
    case "float":
      if (Math.abs(v.v) > resolve(b, "float_magnitude" as MaximaKey)) fail("selector: float magnitude");
      return;
    case "array": {
      if (v.v.length > resolve(b, "array_items" as MaximaKey)) fail("selector: array items");
      for (const item of v.v) checkNode(item, depth + 1, b);
      return;
    }
    case "object": {
      if (v.v.size > resolve(b, "object_members" as MaximaKey)) fail("selector: object members");
      for (const [, val] of v.v) checkNode(val, depth + 1, b);
      return;
    }
    default: return;
  }
}

/**
 * Builds the exact major-1 holder-proof signing input for one invocation of a grant. Sign it with
 * the holder key, then call `assembleCompact`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns Canonical protected and payload base64url segments for the holder proof in a success Result. Sign their exact dot-separated ASCII bytes externally. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function proofSigningInput(proof: ProofProducer, bounds?: Bounds): Result<SigningInput> {
  return proofSigningInputFor(proof, bounds, "standard");
}

/**
 * Like `proofSigningInput`, for a local-loopback proof (loopback target, nonce required).
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-local-loopback-http-v1.md#4-public-verification-contract
 * @returns Canonical protected and payload base64url segments for the loopback proof in a success Result. Sign their exact dot-separated ASCII bytes externally. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function localLoopbackHttpProofSigningInput(proof: ProofProducer, bounds?: Bounds): Result<SigningInput> {
  return proofSigningInputFor(proof, bounds, "local_loopback_http");
}

function proofSigningInputFor(proof: ProofProducer, bounds: Bounds | undefined, profile: ProofProfile): Result<SigningInput> {
  return trying(() => {
    closedShape([proof, bounds], [SHAPE_PROOF_PRODUCER, SHAPE_BOUNDS_OPT]);
    const b = bounds ?? MAXIMUM_BOUNDS;
    assert(proof.holderPublicKey.length === 32, "proof_signing_input: holder key width");
    const proofIdBytes = strUtf8(proof.proofId);
    if (
      !isStringOrUri(proof.proofId) ||
      (profile === "local_loopback_http" &&
        (proofIdBytes.length < 1 ||
          proofIdBytes.length > resolve(b, "identifier_bytes" as MaximaKey)))
    ) fail("proof_signing_input: proof_id");
    const methodBytes = strUtf8(proof.method);
    if (methodBytes.length < 1 || methodBytes.length > resolve(b, "method_bytes" as MaximaKey)) fail("proof_signing_input: method bytes");
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(proof.method)) fail("proof_signing_input: method token");
    // htu normalized + pre-normalized.
    const htuNorm = profile === "standard"
      ? uriNormalize(strUtf8(proof.targetUri), b)
      : localLoopbackHttpUriNormalize(strUtf8(proof.targetUri), b);
    if (!htuNorm.ok) fail("proof_signing_input: htu");
    if (utf8Str(htuNorm.value) !== proof.targetUri) fail("proof_signing_input: htu pre-normalized");
    if (!Number.isInteger(proof.issuedAt)) fail("proof_signing_input: integer iat");
    if (!UUID_RE.test(proof.invocationId)) fail("proof_signing_input: invocation_id");
    const opBytes = strUtf8(proof.operation);
    if (opBytes.length < 1 || opBytes.length > resolve(b, "operation_bytes" as MaximaKey)) fail("proof_signing_input: operation bytes");
    if (!/^[\x20-\x7e]+$/.test(proof.operation)) fail("proof_signing_input: operation charset");
    if (proof.nonce !== undefined) {
      if (!isWellFormed(proof.nonce)) fail("proof_signing_input: nonce well-formed");
      const nb = strUtf8(proof.nonce);
      if (nb.length < 1 || nb.length > resolve(b, "nonce_bytes" as MaximaKey)) fail("proof_signing_input: nonce bytes");
    }
    if (profile === "local_loopback_http" && proof.nonce === undefined) fail("proof_signing_input: nonce required");
    const jwk = jwkFromPublicKey(proof.holderPublicKey);
    const headerMembers = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["jwk", jwkToTagged(jwk)],
      ["typ", { t: "string", v: strUtf8(proofTyp(profile)) }],
    ]);
    // Scan grant framing and size before hashing the compact into ath. This prevents a producer
    // from embedding a digest of an arbitrary malformed string. The scan does not impose
    // base64url canonicality.
    scanCompact(proof.grantCompact, b);
    const athRaw = sha256(proof.grantCompact);
    const baReqRaw = computeRequestDigest(proof.operation, proof.castArguments, b);
    const payloadMembers = new Map<string, Tagged>([
      ["ath", { t: "string", v: strUtf8(utf8Str(base64urlEncode(athRaw))) }],
      ["ba_inv", { t: "string", v: strUtf8(proof.invocationId) }],
      ["ba_op", { t: "string", v: opBytes }],
      ["ba_req", { t: "string", v: strUtf8(utf8Str(base64urlEncode(baReqRaw))) }],
      ["htm", { t: "string", v: methodBytes }],
      ["htu", { t: "string", v: strUtf8(proof.targetUri) }],
      ["iat", { t: "int", v: proof.issuedAt }],
      ["jti", { t: "string", v: proofIdBytes }],
      ["v", { t: "int", v: VERSION }],
    ]);
    if (proof.nonce !== undefined) payloadMembers.set("nonce", { t: "string", v: strUtf8(proof.nonce) });
    return {
      kind: profile === "standard" ? "proof" : "local_loopback_http_proof",
      protectedSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: headerMembers }, b)))),
      payloadSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: payloadMembers }, b)))),
    };
  });
}

function jwkToTagged(jwk: { crv: string; kty: string; x: string }): Tagged {
  const members = new Map<string, Tagged>([
    ["crv", { t: "string", v: strUtf8(jwk.crv) }],
    ["kty", { t: "string", v: strUtf8(jwk.kty) }],
    ["x", { t: "string", v: strUtf8(jwk.x) }],
  ]);
  return { t: "object", v: members };
}

/**
 * Joins a signing input and a 64-byte signature into a compact JWS and re-parses the result. It
 * does not verify the signature.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @returns Exact ASCII compact JWS bytes in a success Result; no signature verification is performed. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function assembleCompact(input: SigningInput, signature: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return trying(() => {
    closedShape([input, signature, bounds], [{ fields: { kind: "str", protectedSegment: "bytes", payloadSegment: "bytes" } }, "bytes", SHAPE_BOUNDS_OPT]);
    // Assembly applies caller-resolved encoded-segment, decoded-segment, signature-width and
    // total compact-byte limits. Omitted bounds resolve to the protocol maximum.
    const b = coerceBounds(bounds ?? MAXIMUM_BOUNDS);
    if (input.protectedSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey) || input.payloadSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) fail("assemble_compact: segment bound");
    // The fixed signature_bytes bound is always 64; boundsNew rejects any other value. The
    // signature coercion already enforces that width.
    const assembled = assembleSegments(input, signature);
    if (!assembled.ok) fail("assemble_compact: signing input");
    const compact = assembled.value;
    if (compact.length > resolve(b, "compact_bytes" as MaximaKey)) fail("assemble_compact: compact_bytes");
    // Re-parse the assembled compact for its selected kind. Parsing enforces segment bounds and
    // base64url canonicality; header and payload decoders enforce the full claim contract. The
    // grant arm uses decodeGrant because its structural payload validator alone does not
    // validate issuer, identifiers, audience, times or holder binding.
    const seg = parseCompact(compact, b);
    const payload = jsonDecode(seg.payloadBytes, b);
    switch (input.kind) {
      case "grant": {
        const r = decodeGrant(compact, b);
        if (!r.ok) fail("assemble_compact: grant re-parse");
        break;
      }
      case "proof": parseProofHeader(seg, b); validateProofPayload(payload, b); break;
      case "boundary_anchor": parseAnchorHeader(seg, b); validateAnchorPayload(payload, seg.payloadBytes, b); break;
      case "key_transition": parseTransitionHeader(seg, b); validateTransitionPayload(payload, seg.payloadBytes, b); break;
      default: fail("assemble_compact: kind");
    }
    return compact;
  });
}

/**
 * Like `assembleCompact`, for a local-loopback proof signing input only.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-local-loopback-http-v1.md#4-public-verification-contract
 * @returns Exact ASCII loopback-proof compact bytes in a success Result, without signature verification. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function assembleLocalLoopbackHttpCompact(input: SigningInput, signature: Uint8Array, bounds?: Bounds): Result<Uint8Array> {
  return trying(() => {
    closedShape([input, signature, bounds], [{ fields: { kind: "str", protectedSegment: "bytes", payloadSegment: "bytes" } }, "bytes", SHAPE_BOUNDS_OPT]);
    if (input.kind !== "local_loopback_http_proof") fail("assemble_compact: kind");
    const b = coerceBounds(bounds ?? MAXIMUM_BOUNDS);
    if (input.protectedSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey) || input.payloadSegment.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) fail("assemble_compact: segment bound");
    const assembled = assembleSegments(input, signature);
    if (!assembled.ok) fail("assemble_compact: signing input");
    const compact = assembled.value;
    if (compact.length > resolve(b, "compact_bytes" as MaximaKey)) fail("assemble_compact: compact_bytes");
    const seg = parseCompact(compact, b);
    parseProofHeader(seg, b, "local_loopback_http");
    validateProofPayload(jsonDecode(seg.payloadBytes, b), b, "local_loopback_http");
    return compact;
  });
}

/**
 * Builds the signing input of a boundary anchor, which signs one point (sequence and chain hash)
 * of a consumption chain under an archive key.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 * @returns Canonical protected and payload base64url segments for the boundary anchor in a success Result. Sign their exact dot-separated ASCII bytes externally. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function boundaryAnchorSigningInput(anchor: BoundaryAnchorProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
    closedShape([anchor, bounds], [SHAPE_ANCHOR_PRODUCER, SHAPE_BOUNDS_OPT]);
    const b = bounds ?? MAXIMUM_BOUNDS;
    const keyIdBytes = strUtf8(anchor.keyId);
    if (keyIdBytes.length < 1 || keyIdBytes.length > resolve(b, "kid_bytes" as MaximaKey)) fail("anchor_signing_input: key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(anchor.keyId)) fail("anchor_signing_input: key_id charset");
    if (!isStringOrUri(anchor.anchorId)) fail("anchor_signing_input: anchor_id");
    if (!isStringOrUri(anchor.chainId)) fail("anchor_signing_input: chain_id");
    if (!Number.isInteger(anchor.anchoredAt)) fail("anchor_signing_input: integer anchored_at");
    if (!Number.isInteger(anchor.sequence) || anchor.sequence < 0) fail("anchor_signing_input: non-negative sequence");
    assert(anchor.chainHash.length === 32, "anchor_signing_input: chain_hash width");
    assert(anchor.publicKey.length === 32, "anchor_signing_input: public_key width");
    // Genesis invariant (boundary_anchor_codec.ex:185-189 valid_anchor_binding?): sequence 0 is the
    // chain root and requires the all-zero chain_hash. The verifier re-checks this; the producer
    // rejects pre-signing so a mis-bound genesis anchor cannot be minted.
    if (anchor.sequence === 0 && !bytesEqual(anchor.chainHash, DEFAULT_HASH)) fail("anchor_signing_input: genesis chain_hash");
    const header = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["kid", { t: "string", v: keyIdBytes }],
      ["typ", { t: "string", v: strUtf8(ANCHOR_TYP) }],
    ]);
    const fp = thumbprintRaw(jwkFromPublicKey(anchor.publicKey));
    const payload = new Map<string, Tagged>([
      ["anchor_id", { t: "string", v: strUtf8(anchor.anchorId) }],
      ["anchored_at", { t: "int", v: anchor.anchoredAt }],
      ["chain_hash", { t: "string", v: strUtf8(utf8Str(base64urlEncode(anchor.chainHash))) }],
      ["chain_id", { t: "string", v: strUtf8(anchor.chainId) }],
      ["key_fingerprint", { t: "string", v: strUtf8(utf8Str(base64urlEncode(fp))) }],
      ["sequence", { t: "int", v: anchor.sequence }],
      ["v", { t: "int", v: VERSION }],
    ]);
    return {
      kind: "boundary_anchor",
      protectedSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: header }, b)))),
      payloadSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: payload }, b)))),
    };
  });
}

/**
 * Builds the signing input of an authenticated key transition from the current archive key to the
 * next one; the current key signs it.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 * @returns Canonical protected and payload base64url segments for the key transition in a success Result. Sign their exact dot-separated ASCII bytes externally. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function keyTransitionSigningInput(t: KeyTransitionProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
    closedShape([t, bounds], [SHAPE_TRANSITION_PRODUCER, SHAPE_BOUNDS_OPT]);
    const b = bounds ?? MAXIMUM_BOUNDS;
    assert(t.currentPublicKey.length === 32 && t.nextPublicKey.length === 32, "transition_signing_input: key width");
    if (bytesEqual(t.currentPublicKey, t.nextPublicKey)) fail("transition_signing_input: distinct keys");
    const currentKeyIdBytes = strUtf8(t.currentKeyId);
    if (currentKeyIdBytes.length < 1 || currentKeyIdBytes.length > resolve(b, "kid_bytes" as MaximaKey)) fail("transition_signing_input: current_key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(t.currentKeyId)) fail("transition_signing_input: current_key_id charset");
    const nextKeyIdBytes = strUtf8(t.nextKeyId);
    if (nextKeyIdBytes.length < 1 || nextKeyIdBytes.length > resolve(b, "kid_bytes" as MaximaKey)) fail("transition_signing_input: next_key_id bytes");
    if (!/^[A-Za-z0-9._~-]+$/.test(t.nextKeyId)) fail("transition_signing_input: next_key_id charset");
    if (!isStringOrUri(t.transitionId)) fail("transition_signing_input: transition_id");
    if (!isStringOrUri(t.chainId)) fail("transition_signing_input: chain_id");
    if (!Number.isInteger(t.effectiveAt)) fail("transition_signing_input: integer effective_at");
    const header = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["kid", { t: "string", v: currentKeyIdBytes }],
      ["typ", { t: "string", v: strUtf8(TRANSITION_TYP) }],
    ]);
    const fromFp = thumbprintRaw(jwkFromPublicKey(t.currentPublicKey));
    const toFp = thumbprintRaw(jwkFromPublicKey(t.nextPublicKey));
    const payload = new Map<string, Tagged>([
      ["chain_id", { t: "string", v: strUtf8(t.chainId) }],
      ["effective_at", { t: "int", v: t.effectiveAt }],
      ["from_key_fingerprint", { t: "string", v: strUtf8(utf8Str(base64urlEncode(fromFp))) }],
      ["to_key_fingerprint", { t: "string", v: strUtf8(utf8Str(base64urlEncode(toFp))) }],
      ["to_key_id", { t: "string", v: nextKeyIdBytes }],
      ["transition_id", { t: "string", v: strUtf8(t.transitionId) }],
      ["v", { t: "int", v: VERSION }],
    ]);
    return {
      kind: "key_transition",
      protectedSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: header }, b)))),
      payloadSegment: strUtf8(utf8Str(base64urlEncode(jcsEncode({ t: "object", v: payload }, b)))),
    };
  });
}

/**
 * Successful archive encoding: complete framed bytes and their SHA-256 digest. Encoding checks
 * structure and consistency but verifies no signatures and grants no authority.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#archive
 */
export interface EncodedAnchoredExport {
  /** Complete binary archive including the unframed 20-byte magic prefix. */
  readonly archive: Uint8Array;
  /** Raw 32-byte SHA-256 digest of the exact complete archive bytes. */
  readonly digest: Uint8Array;
}
/**
 * Checks rows, anchors and transitions, then frames them into an anchored-export archive. Returns
 * the archive bytes and their SHA-256 digest.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#archive
 * @returns Framed archive bytes and their raw 32-byte SHA-256 digest in a success Result, without signature verification. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function encodeAnchoredExport(input: AnchoredExportInput, expected: ExpectedExport): Result<EncodedAnchoredExport> {
  return trying(() => {
    closedShape([input, expected], [SHAPE_EXPORT_INPUT, SHAPE_EXPECTED_EXPORT]);
    // Validate inputs BEFORE framing (mirrors anchored_export_codec.ex:33-57 encode →
    // validate_expected_export + parse_expected_transitions + validate_expected_key_path). The
    // parser would reject the bytes a too-large input would produce; the producer rejects earlier.
    // resolve expected.bounds once and thread it through the encode-time bounds checks so a caller
    // tightening via expected.bounds takes effect (matches verify_anchored_export).
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    validateExportInputs(input, expected, b);
    // Check rows against the expected chain boundaries before framing, using the outer caller
    // bounds. Any nested chain bounds must resolve to those same limits. Accepting a wider
    // nested bound would bypass a tightened outer limit.
    requireBoundsEqual(expected.chain.bounds, b, "encode_anchored_export: chain bounds");
    requireBoundsEqual(expected.startAnchor.bounds, b, "encode_anchored_export: start anchor bounds");
    requireBoundsEqual(expected.endAnchor.bounds, b, "encode_anchored_export: end anchor bounds");
    for (let i = 0; i < expected.transitions.length; i++) {
      requireBoundsEqual(expected.transitions[i]!.bounds, b, `encode_anchored_export: transition ${i} bounds`);
    }
    const chainRes = checkChain(
      { rows: input.rows, chainId: expected.chain.chainId, firstSequence: expected.chain.firstSequence, lastSequence: expected.chain.lastSequence, rowCount: expected.chain.rowCount, previousHash: expected.chain.previousHash, lastHash: expected.chain.lastHash },
      { ...expected.chain, bounds: b },
    );
    if (!chainRes.ok) fail("encode_anchored_export: rows chain");
    // Gated parses + full signed-field matches (anchored_export_codec.ex:40-52): the
    // start anchor, the end anchor, and every transition go through the width+canonical
    // gated decode and match their expected values field-by-field.
    const framedSignatures = [
      parseAndMatchAnchor(input.startAnchor, expected.startAnchor, "start", b),
      parseAndMatchAnchor(input.endAnchor, expected.endAnchor, "end", b),
      ...input.transitions.map((t, i) => parseAndMatchTransition(t, expected.transitions[i]!, i, b)),
    ];
    // Export encoding enforces the keyless Ed25519 rule S1 on every framed signature. It checks
    // canonical R, excludes small-order R and requires S < L. It neither verifies signatures
    // nor rewrites accepted bytes. See erratum 3.
    for (const signature of framedSignatures) {
      if (!signatureGate(signature)) fail("encode_anchored_export: signature canonicality");
    }
    const headerBytes = buildArchiveHeader(input, expected.chain, b);
    // Validate the framed chunk count and total bytes before joining the archive. Build the
    // list with loops: the maximum 65,796 chunks can exceed V8 call-argument limits if spread
    // into a function call.
    const parts: Uint8Array[] = [ARCHIVE_PREFIX, frame(headerBytes), frame(input.startAnchor)];
    for (const t of input.transitions) parts.push(frame(t));
    for (const r of input.rows) parts.push(frame(r));
    parts.push(frame(input.endAnchor));
    if (parts.length > resolve(b, "archive_chunks" as MaximaKey)) fail("encode_anchored_export: archive_chunks");
    let total = 0;
    for (const p of parts) total += p.length;
    if (total > resolve(b, "archive_bytes" as MaximaKey)) fail("encode_anchored_export: archive_bytes");
    const archive = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { archive.set(p, off); off += p.length; }
    return { archive, digest: sha256(archive) };
  });
}

// Parse an anchor and match all seven signed fields against expected values. Encoding checks
// structure and canonical form without verifying signatures. Return the decoded signature for
// the export encoder to check producer canonicality after the field matches.
function parseAndMatchAnchor(compact: Uint8Array, expected: ExpectedAnchor, which: "start" | "end", b: Bounds): Uint8Array {
  // Enforce anchor_bytes before parsing an anchor compact. This bound is stricter than the
  // general compact_bytes ceiling and keeps producers within the archive decoder contract.
  if (compact.length > resolve(b, "anchor_bytes" as MaximaKey)) fail(`encode_anchored_export: ${which} anchor anchor_bytes`);
  const seg = parseCompact(compact, b);
  const { kid } = parseAnchorHeader(seg, b);
  if (kid !== expected.keyId) fail(`encode_anchored_export: ${which} anchor kid`);
  const p = jsonDecode(seg.payloadBytes, b);
  validateAnchorPayload(p, seg.payloadBytes, b);
  if (p.t !== "object") fail(`encode_anchored_export: ${which} anchor payload`);
  if (requireStringOrUri(p.v.get("anchor_id"), "anchor_id", b) !== expected.anchorId) fail(`encode_anchored_export: ${which} anchor_id`);
  if (requireInt(p.v.get("anchored_at"), "anchored_at") !== expected.anchoredAt) fail(`encode_anchored_export: ${which} anchored_at`);
  if (requireStringOrUri(p.v.get("chain_id"), "chain_id", b) !== expected.chainId) fail(`encode_anchored_export: ${which} chain_id`);
  if (requireInt(p.v.get("sequence"), "sequence") !== expected.sequence) fail(`encode_anchored_export: ${which} sequence`);
  if (!bytesEqual(requireB64urlN(p.v.get("chain_hash"), "chain_hash", 32), expected.chainHash)) fail(`encode_anchored_export: ${which} chain_hash`);
  if (!bytesEqual(requireB64urlN(p.v.get("key_fingerprint"), "key_fingerprint", 32), expected.keyFingerprint)) fail(`encode_anchored_export: ${which} key_fingerprint`);
  return seg.signature;
}

// Gated parse + full 7-field match of a transition compact (reference
// KeyTransitionCodec.parse + transition_matches?, anchored_export_codec.ex:443-504).
// Returns the decoded signature: encode_anchored_export gates every framed signature's
// canonicality after the matches (erratum 3).
function parseAndMatchTransition(compact: Uint8Array, expected: ExpectedKeyTransition, i: number, b: Bounds): Uint8Array {
  // Same anchor_bytes ceiling the reference enforces on transitions (key_transition_codec.ex:114).
  if (compact.length > resolve(b, "anchor_bytes" as MaximaKey)) fail(`encode_anchored_export: transition ${i} anchor_bytes`);
  const seg = parseCompact(compact, b);
  const { kid } = parseTransitionHeader(seg, b);
  if (kid !== expected.currentKeyId) fail(`encode_anchored_export: transition ${i} kid`);
  const p = jsonDecode(seg.payloadBytes, b);
  validateTransitionPayload(p, seg.payloadBytes, b);
  if (p.t !== "object") fail(`encode_anchored_export: transition ${i} payload`);
  if (requireStringOrUri(p.v.get("transition_id"), "transition_id", b) !== expected.transitionId) fail(`encode_anchored_export: transition ${i} transition_id`);
  if (requireStringOrUri(p.v.get("chain_id"), "chain_id", b) !== expected.chainId) fail(`encode_anchored_export: transition ${i} chain_id`);
  if (requireInt(p.v.get("effective_at"), "effective_at") !== expected.effectiveAt) fail(`encode_anchored_export: transition ${i} effective_at`);
  if (!bytesEqual(requireB64urlN(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32), expected.currentKeyFingerprint)) fail(`encode_anchored_export: transition ${i} from_key_fingerprint`);
  if (!bytesEqual(requireB64urlN(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32), expected.nextKeyFingerprint)) fail(`encode_anchored_export: transition ${i} to_key_fingerprint`);
  const toKeyIdTagged = p.v.get("to_key_id");
  if (toKeyIdTagged === undefined || toKeyIdTagged.t !== "string" || utf8Str(toKeyIdTagged.v) !== expected.nextKeyId) fail(`encode_anchored_export: transition ${i} to_key_id`);
  return seg.signature;
}

// Encode-time input validation (mirrors anchored_export_codec.ex validate_expected_export +
// validate_chunks): the transition count, chain range coherence, anchor bindings, and the chunk
// list shape must hold before framing. The parser enforces all of this at verify time; the producer
// must not mint bytes its own consumer would reject.
function validateExportInputs(input: AnchoredExportInput, expected: ExpectedExport, b: Bounds): void {
  const chain = expected.chain;
  // Transition count bound (anchored_export_codec.ex:360 transition_count <= bounds.key_transitions).
  if (!Number.isInteger(input.transitions.length) || input.transitions.length > resolve(b, "key_transitions" as MaximaKey)) {
    fail("encode_anchored_export: transition_count bound");
  }
  if (expected.transitions.length !== input.transitions.length) fail("encode_anchored_export: transition count");
  // Anchor bindings (anchored_export_codec.ex:364-371): start spans first_sequence-1 with the
  // chain's previous_hash; end spans last_sequence with the chain's last_hash.
  if (expected.startAnchor.sequence !== chain.firstSequence - 1) fail("encode_anchored_export: start sequence");
  if (!bytesEqual(expected.startAnchor.chainHash, chain.previousHash)) fail("encode_anchored_export: start chain_hash");
  if (expected.endAnchor.sequence !== chain.lastSequence) fail("encode_anchored_export: end sequence");
  if (!bytesEqual(expected.endAnchor.chainHash, chain.lastHash)) fail("encode_anchored_export: end chain_hash");
  // All transitions + both anchors carry the chain_id (anchored_export_codec.ex:361-363).
  for (let i = 0; i < expected.transitions.length; i++) {
    if (expected.transitions[i]!.chainId !== chain.chainId) fail(`encode_anchored_export: transition ${i} chain_id`);
  }
  if (expected.startAnchor.chainId !== chain.chainId) fail("encode_anchored_export: start chain_id");
  if (expected.endAnchor.chainId !== chain.chainId) fail("encode_anchored_export: end chain_id");
  // Key-path invariants (validate_expected_key_path): the no-transition path requires start==end key
  // identity with a chronologically-non-decreasing end anchor; the transition path requires strictly
  // increasing effective_at with no fingerprint cycle. Mirrored by validateKeyPath.
  validateKeyPath(expected.startAnchor, expected.transitions, expected.endAnchor);
}

function buildArchiveHeader(input: AnchoredExportInput, chain: ExpectedChain, b: Bounds): Uint8Array {
  if (chain.chainId !== input.chainId) fail("encode_anchored_export: chain_id");
  if (chain.firstSequence !== input.firstSequence) fail("encode_anchored_export: first_sequence");
  if (chain.lastSequence !== input.lastSequence) fail("encode_anchored_export: last_sequence");
  if (chain.rowCount !== input.rowCount) fail("encode_anchored_export: row_count");
  const members = new Map<string, Tagged>([
    ["chain_id", { t: "string", v: strUtf8(chain.chainId) }],
    ["first_sequence", { t: "int", v: chain.firstSequence }],
    ["last_hash", { t: "string", v: strUtf8(utf8Str(base64urlEncode(chain.lastHash))) }],
    ["last_sequence", { t: "int", v: chain.lastSequence }],
    ["previous_hash", { t: "string", v: strUtf8(utf8Str(base64urlEncode(chain.previousHash))) }],
    ["row_count", { t: "int", v: chain.rowCount }],
    ["transition_count", { t: "int", v: input.transitions.length }],
    ["v", { t: "int", v: VERSION }],
  ]);
  const headerBytes = jcsEncode({ t: "object", v: members }, b);
  if (headerBytes.length > resolve(b, "archive_header_bytes" as MaximaKey)) fail("encode_anchored_export: header bytes");
  return headerBytes;
}

// Frame each archive entry as a four-byte unsigned big-endian byte length followed by its
// bytes. See spec/bap-v1.md#chain.
function frame(bytes: Uint8Array): Uint8Array {
  if (bytes.length === 0) fail("archive: zero-length frame");
  const out = new Uint8Array(4 + bytes.length);
  const v = bytes.length;
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  out.set(bytes, 4);
  return out;
}

/**
 * Verifies a boundary anchor under one historical key, including `validFrom <= anchoredAt <
 * validBefore`. Facts carry `trust: "not_evaluated"`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 * @returns Redacted AnchorFacts in a success Result after signature and key-window checks; trust remains not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function verifyHistoricalAnchor(compact: Uint8Array, key: HistoricalPublicKey, expected: ExpectedAnchor): Result<AnchorFacts> {
  return trying(() => {
    closedShape([compact, key, expected], ["bytes", SHAPE_HIST_KEY, "object"]);
    assert(key.publicKey.length === 32, "verify_historical_anchor: key width");
    // Thread expected.bounds (resolved once) through every bound-sensitive check, as the reference
    // does (boundary_anchor_codec.ex parses the compact + payload under bounds).
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    // Check both key-window endpoints against integer_magnitude under the resolved bounds. An
    // in-window signed timestamp does not make an oversized key-window endpoint valid.
    const mag = resolve(b, "integer_magnitude" as MaximaKey);
    // Number.isInteger: fractional/NaN endpoints fail closed.
    if (!Number.isInteger(key.validFrom) || Math.abs(key.validFrom) > mag) fail("verify_historical_anchor: valid_from magnitude");
    if (key.validBefore !== null && (!Number.isInteger(key.validBefore) || Math.abs(key.validBefore) > mag)) fail("verify_historical_anchor: valid_before magnitude");
    if (key.validBefore !== null && key.validBefore <= key.validFrom) fail("verify_historical_anchor: valid_before ordering");
    if (compact.length > resolve(b, "anchor_bytes" as MaximaKey)) fail("verify_historical_anchor: anchor_bytes");
    const seg = parseCompact(compact, b);
    const { kid } = parseAnchorHeader(seg, b);
    if (kid !== key.keyId) fail("verify_historical_anchor: kid");
    if (expected.keyId !== key.keyId) fail("verify_historical_anchor: expected key id");
    const p = jsonDecode(seg.payloadBytes, b);
    validateAnchorPayload(p, seg.payloadBytes, b);
    if (p.t !== "object") fail("verify_historical_anchor: payload object");
    const anchorId = requireStringOrUri(p.v.get("anchor_id"), "anchor_id", b);
    if (anchorId !== expected.anchorId) fail("verify_historical_anchor: anchor_id");
    const anchoredAt = requireInt(p.v.get("anchored_at"), "anchored_at");
    if (anchoredAt !== expected.anchoredAt) fail("verify_historical_anchor: anchored_at");
    const chainId = requireStringOrUri(p.v.get("chain_id"), "chain_id", b);
    if (chainId !== expected.chainId) fail("verify_historical_anchor: chain_id");
    const sequence = requireInt(p.v.get("sequence"), "sequence");
    if (sequence !== expected.sequence) fail("verify_historical_anchor: sequence");
    const chainHash = requireB64urlN(p.v.get("chain_hash"), "chain_hash", 32);
    if (!bytesEqual(chainHash, expected.chainHash)) fail("verify_historical_anchor: chain_hash");
    const keyFpRaw = requireB64urlN(p.v.get("key_fingerprint"), "key_fingerprint", 32);
    if (!bytesEqual(keyFpRaw, expected.keyFingerprint)) fail("verify_historical_anchor: key_fingerprint");
    // Genesis: sequence 0 requires the all-zero chain hash.
    if (expected.sequence === 0 && !bytesEqual(expected.chainHash, DEFAULT_HASH)) fail("verify_historical_anchor: genesis hash");
    // Derived fingerprint must equal expected.
    const derivedFp = thumbprintRaw(jwkFromPublicKey(key.publicKey));
    if (!bytesEqual(derivedFp, expected.keyFingerprint)) fail("verify_historical_anchor: fingerprint");
    if (!inWindow(anchoredAt, key)) fail("verify_historical_anchor: window");
    const pk = importPublicKey(key.publicKey, utf8Str(base64urlEncode(derivedFp)));
    if (!ed25519Verify(seg.signingInput, seg.signature, pk)) fail("verify_historical_anchor: signature");
    return redacted({
      version: 1 as const, anchorId, anchoredAt, chainId, sequence, chainHash,
      keyFingerprint: keyFpRaw, verification: "signature_and_window" as const,
      trust: "not_evaluated" as const,
    }, "V1.AnchorFacts");
  });
}

/**
 * Verifies that `oldKey` signed a handover to `newKey`, with the effective time inside both keys'
 * validity windows. Facts carry `trust: "not_evaluated"`.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#chain
 * @returns Redacted KeyTransitionFacts in a success Result after both key-window checks and the old-key signature; trust remains not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function verifyKeyTransition(compact: Uint8Array, oldKey: HistoricalPublicKey, newKey: HistoricalPublicKey, expected: ExpectedKeyTransition): Result<KeyTransitionFacts> {
  return trying(() => {
    closedShape([compact, oldKey, newKey, expected], ["bytes", SHAPE_HIST_KEY, SHAPE_HIST_KEY, "object"]);
    assert(oldKey.publicKey.length === 32 && newKey.publicKey.length === 32, "verify_key_transition: key width");
    if (bytesEqual(oldKey.publicKey, newKey.publicKey)) fail("verify_key_transition: distinct keys");
    // Thread expected.bounds (resolved once) through every bound-sensitive check.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    // Check both key-window endpoints against integer_magnitude under the resolved bounds. An
    // in-window signed timestamp does not make an oversized key-window endpoint valid.
    const mag = resolve(b, "integer_magnitude" as MaximaKey);
    if (!Number.isInteger(oldKey.validFrom) || !Number.isInteger(newKey.validFrom) || Math.abs(oldKey.validFrom) > mag || Math.abs(newKey.validFrom) > mag) fail("verify_key_transition: valid_from magnitude");
    if ((oldKey.validBefore !== null && (!Number.isInteger(oldKey.validBefore) || Math.abs(oldKey.validBefore) > mag)) || (newKey.validBefore !== null && (!Number.isInteger(newKey.validBefore) || Math.abs(newKey.validBefore) > mag))) fail("verify_key_transition: valid_before magnitude");
    if ((oldKey.validBefore !== null && oldKey.validBefore <= oldKey.validFrom) || (newKey.validBefore !== null && newKey.validBefore <= newKey.validFrom)) fail("verify_key_transition: valid_before ordering");
    if (compact.length > resolve(b, "anchor_bytes" as MaximaKey)) fail("verify_key_transition: anchor_bytes");
    const seg = parseCompact(compact, b);
    const { kid } = parseTransitionHeader(seg, b);
    if (kid !== oldKey.keyId) fail("verify_key_transition: kid");
    if (expected.currentKeyId !== oldKey.keyId) fail("verify_key_transition: current key id");
    if (expected.nextKeyId !== newKey.keyId) fail("verify_key_transition: next key id");
    const p = jsonDecode(seg.payloadBytes, b);
    validateTransitionPayload(p, seg.payloadBytes, b);
    if (p.t !== "object") fail("verify_key_transition: payload object");
    const transitionId = requireStringOrUri(p.v.get("transition_id"), "transition_id", b);
    if (transitionId !== expected.transitionId) fail("verify_key_transition: transition_id");
    const chainId = requireStringOrUri(p.v.get("chain_id"), "chain_id", b);
    if (chainId !== expected.chainId) fail("verify_key_transition: chain_id");
    const effectiveAt = requireInt(p.v.get("effective_at"), "effective_at");
    if (effectiveAt !== expected.effectiveAt) fail("verify_key_transition: effective_at");
    const fromFpRaw = requireB64urlN(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32);
    if (!bytesEqual(fromFpRaw, expected.currentKeyFingerprint)) fail("verify_key_transition: from fp");
    const toFpRaw = requireB64urlN(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32);
    if (!bytesEqual(toFpRaw, expected.nextKeyFingerprint)) fail("verify_key_transition: to fp");
    const toKeyIdV = p.v.get("to_key_id")!;
    if (toKeyIdV.t !== "string" || utf8Str(toKeyIdV.v) !== expected.nextKeyId) fail("verify_key_transition: to_key_id");
    // Derived fingerprints must equal expected.
    const derivedFrom = thumbprintRaw(jwkFromPublicKey(oldKey.publicKey));
    if (!bytesEqual(derivedFrom, expected.currentKeyFingerprint)) fail("verify_key_transition: current fp");
    const derivedTo = thumbprintRaw(jwkFromPublicKey(newKey.publicKey));
    if (!bytesEqual(derivedTo, expected.nextKeyFingerprint)) fail("verify_key_transition: next fp");
    if (!inWindow(effectiveAt, oldKey)) fail("verify_key_transition: current window");
    if (!inWindow(effectiveAt, newKey)) fail("verify_key_transition: next window");
    const pk = importPublicKey(oldKey.publicKey, utf8Str(base64urlEncode(derivedFrom)));
    if (!ed25519Verify(seg.signingInput, seg.signature, pk)) fail("verify_key_transition: signature");
    return redacted({
      version: 1 as const, transitionId, chainId, effectiveAt,
      currentKeyFingerprint: fromFpRaw, nextKeyFingerprint: toFpRaw,
      verification: "authenticated_transition" as const, trust: "not_evaluated" as const,
    }, "V1.KeyTransitionFacts");
  });
}

/**
 * Verifies a stored anchored-export archive (in any chunking) under the ordered archive keys:
 * digest, object version, framing, both anchors, every transition and every row.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#archive
 * @returns Redacted AnchoredExportFacts in a success Result; authorization remains not_evaluated. Failure is value-free { ok: false } for invalid, over-limit or mismatched inputs.
 */
export function verifyAnchoredExport(archived: ArchivedObject, keyChain: HistoricalKeyChain, expected: ExpectedExport): Result<AnchoredExportFacts> {
  return trying(() => {
    closedShape([archived, keyChain, expected], [{ fields: { chunks: { seq: "bytes" }, version: "str" } }, { fields: { keys: { seq: SHAPE_HIST_KEY } } }, SHAPE_EXPECTED_EXPORT]);
    // The count ceiling FIRST (even the static-bindings walk ran unbounded caller input before it).
    const vb0 = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    if (expected.transitions.length > resolve(vb0, "key_transitions" as MaximaKey)) fail("verify_anchored_export: transition count bound");
    // Key-window validity BEFORE chunk processing/hashing (the reference validates
    // key shapes at :91 before validate_chunks).
    if (keyChain.keys.length !== expected.transitions.length + 1) fail("verify_anchored_export: key count bound");
    // Key ID/public-key shape before the digest.
    for (const k of keyChain.keys) {
      if (typeof k.keyId !== "string" || k.keyId.length === 0 || k.keyId.length > resolve(vb0, "kid_bytes" as MaximaKey) || new TextEncoder().encode(k.keyId).length > resolve(vb0, "kid_bytes" as MaximaKey)) fail("verify_anchored_export: key id shape");
      // The reference's ASCII-unreserved key_id class, pre-hash.
      if (!/^[A-Za-z0-9._~-]*$/.test(k.keyId)) fail("verify_anchored_export: key id charset"); // ASCII-unreserved class
      if (!(k.publicKey instanceof Uint8Array) || k.publicKey.length !== 32) fail("verify_anchored_export: key width");
    }
    {
      const mag0 = resolve(vb0, "integer_magnitude" as MaximaKey);
      for (const k of keyChain.keys) {
        if (!Number.isInteger(k.validFrom) || Math.abs(k.validFrom) > mag0) fail("verify_anchored_export: key valid_from magnitude");
        if (k.validBefore !== null && (!Number.isInteger(k.validBefore) || Math.abs(k.validBefore) > mag0)) fail("verify_anchored_export: key valid_before magnitude");
        if (k.validBefore !== null && k.validBefore <= k.validFrom) fail("verify_anchored_export: key valid_before ordering");
      }
    }
    // Key shapes and validity windows have been checked above. Validate the expected chain,
    // anchors and transitions next, before archive chunks and hashing. This ordering rejects
    // malformed context before digest work, as required by the verification contract.
    const bpre = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    const mpre = resolve(bpre, "integer_magnitude" as MaximaKey);
    const preIdentifier = (v: unknown, label: string): void => {
      if (typeof v !== "string" || v.length === 0 || new TextEncoder().encode(v).length > resolve(bpre, "identifier_bytes" as MaximaKey) || !isStringOrUri(v)) fail(label);
    };
    preIdentifier(expected.chain.chainId, "verify_anchored_export: chain chain_id");
    if (expected.chain.firstSequence < 1 || expected.chain.firstSequence > mpre || expected.chain.lastSequence < 1 || expected.chain.lastSequence > mpre || expected.chain.firstSequence > expected.chain.lastSequence) fail("verify_anchored_export: chain range");
    if (expected.chain.rowCount < 1 || expected.chain.rowCount > resolve(bpre, "chain_rows" as MaximaKey) || expected.chain.rowCount !== expected.chain.lastSequence - expected.chain.firstSequence + 1) fail("verify_anchored_export: chain count");
    if (expected.chain.previousHash.length !== 32 || expected.chain.lastHash.length !== 32) fail("verify_anchored_export: chain hash width");
    if (expected.chain.firstSequence === 1 && !bytesEqual(expected.chain.previousHash, DEFAULT_HASH)) fail("verify_anchored_export: chain genesis");
    for (const [anch, which] of [[expected.startAnchor, "start"], [expected.endAnchor, "end"]] as const) {
      preIdentifier(anch.anchorId, `verify_anchored_export: ${which} anchor_id`);
      preIdentifier(anch.chainId, `verify_anchored_export: ${which} chain_id`);
      if (!Number.isInteger(anch.anchoredAt) || Math.abs(anch.anchoredAt) > mpre) fail(`verify_anchored_export: ${which} anchored_at`);
      if (!Number.isInteger(anch.sequence) || anch.sequence < 0 || anch.sequence > mpre) fail(`verify_anchored_export: ${which} sequence`);
      if (typeof anch.keyId !== "string" || anch.keyId.length === 0 || new TextEncoder().encode(anch.keyId).length > resolve(bpre, "kid_bytes" as MaximaKey) || !/^[A-Za-z0-9._~-]+$/.test(anch.keyId)) fail(`verify_anchored_export: ${which} key_id`);
      if (anch.chainHash.length !== 32 || anch.keyFingerprint.length !== 32) fail(`verify_anchored_export: ${which} hash width`);
      if (anch.sequence === 0 && !bytesEqual(anch.chainHash, DEFAULT_HASH)) fail(`verify_anchored_export: ${which} genesis`);
    }
    if (expected.transitions.length > resolve(bpre, "key_transitions" as MaximaKey)) fail("verify_anchored_export: transition count bound");
    for (let i = 0; i < expected.transitions.length; i++) {
      const t = expected.transitions[i]!;
      preIdentifier(t.transitionId, `verify_anchored_export: transition ${i} id`);
      preIdentifier(t.chainId, `verify_anchored_export: transition ${i} chain_id`);
      if (!Number.isInteger(t.effectiveAt) || Math.abs(t.effectiveAt) > mpre) fail(`verify_anchored_export: transition ${i} effective_at`);
      for (const kid of [t.currentKeyId, t.nextKeyId]) {
        if (typeof kid !== "string" || kid.length === 0 || new TextEncoder().encode(kid).length > resolve(bpre, "kid_bytes" as MaximaKey) || !/^[A-Za-z0-9._~-]+$/.test(kid)) fail(`verify_anchored_export: transition ${i} key_id`);
      }
      if (t.currentKeyFingerprint.length !== 32 || t.nextKeyFingerprint.length !== 32 || bytesEqual(t.currentKeyFingerprint, t.nextKeyFingerprint)) fail(`verify_anchored_export: transition ${i} fingerprints`);
    }
    // Static expected-side bindings (reference validate_expected_anchored_export →
    // validate_expected_export, anchored_export_codec.ex:362-371, reached at verify:92/:387): the
    // caller's expected anchors + transitions belong to the expected chain (none of the six were
    // enforced at verify; the anchors bound only to their own expected structs and the rows/header
    // only to the chain).
    const vb = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    if (expected.startAnchor.chainId !== expected.chain.chainId) fail("verify_anchored_export: start chain_id");
    if (expected.endAnchor.chainId !== expected.chain.chainId) fail("verify_anchored_export: end chain_id");
    if (expected.startAnchor.sequence !== expected.chain.firstSequence - 1) fail("verify_anchored_export: start sequence");
    if (!bytesEqual(expected.startAnchor.chainHash, expected.chain.previousHash)) fail("verify_anchored_export: start chain_hash");
    if (expected.endAnchor.sequence !== expected.chain.lastSequence) fail("verify_anchored_export: end sequence");
    if (!bytesEqual(expected.endAnchor.chainHash, expected.chain.lastHash)) fail("verify_anchored_export: end chain_hash");
    for (let i = 0; i < expected.transitions.length; i++) {
      if (expected.transitions[i]!.chainId !== expected.chain.chainId) fail(`verify_anchored_export: transition ${i} chain_id`);
    }
    void vb;
    // The reference resolves Bounds.coerce(expected.bounds) once (anchored_export_codec.ex:84-185)
    // and threads it into validate_chunks (archive_chunks, archive_bytes), parse_archive (frame
    // reads), and every row check. The inner anchors/transitions carry their own bounds (used by
    // their own compact parsers). A caller tightening via expected.bounds now takes effect.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    // Every nested bounds value must resolve to the same limits as the top-level bounds. An
    // absent nested value resolves to maximum and therefore rejects when the top level is
    // tightened. Never discard a conflicting nested bounds value.
    requireBoundsEqual(expected.chain.bounds, b, "verify_anchored_export: chain bounds");
    requireBoundsEqual(expected.startAnchor.bounds, b, "verify_anchored_export: start anchor bounds");
    requireBoundsEqual(expected.endAnchor.bounds, b, "verify_anchored_export: end anchor bounds");
    for (let i = 0; i < expected.transitions.length; i++) {
      requireBoundsEqual(expected.transitions[i]!.bounds, b, `verify_anchored_export: transition ${i} bounds`);
    }
    // Validate the chunk list BEFORE concatenation (mirrors
    // anchored_export_codec.ex:101-102,333-342 validate_chunks): each chunk nonempty, count <
    // archive_chunks, total ≤ archive_bytes. Hashing happens after the shape is validated. Version
    // shape (UTF-8 BYTES via TextEncoder) + equality BEFORE the digest (malformed metadata should
    // not force hashing).
    if (typeof archived.version !== "string" || archived.version.length === 0 || archived.version.length > resolve(b, "object_version_bytes" as MaximaKey) || !isWellFormed(archived.version) || typeof expected.objectVersion !== "string" || expected.objectVersion.length === 0 || expected.objectVersion.length > resolve(b, "object_version_bytes" as MaximaKey) || !isWellFormed(expected.objectVersion) || new TextEncoder().encode(archived.version).length > resolve(b, "object_version_bytes" as MaximaKey) || new TextEncoder().encode(expected.objectVersion).length > resolve(b, "object_version_bytes" as MaximaKey)) fail("verify_anchored_export: version shape");
    if (archived.version !== expected.objectVersion) fail("verify_anchored_export: object version");
    validateChunks(archived.chunks, b);
    // Hash the chunks incrementally without joining or spreading them. sha256Concat accepts the
    // array directly, including the maximum 65,796 chunks. Reject a mismatched archive digest
    // before parsing materializes the archive bytes.
    const digest = sha256Concat(archived.chunks);
    if (!bytesEqual(digest, expected.digest)) fail("verify_anchored_export: digest");
    // Materialize for parsing ONLY after the digest matches (caller-legitimate, bounded archive).
    // Loop-build (no spread) for the same V8 arg-ceiling reason.
    let total = 0;
    for (const c of archived.chunks) total += c.length;
    const archive = new Uint8Array(total);
    let off = 0;
    for (const c of archived.chunks) { archive.set(c, off); off += c.length; }
    if (archive.length <= ARCHIVE_PREFIX.length) fail("verify_anchored_export: archive too short");
    // Parse the archive frames.
    const parsed = parseArchive(archive, b);
    // Header canonical equality.
    const headerMembers = new Map<string, Tagged>([
      ["chain_id", { t: "string", v: strUtf8(expected.chain.chainId) }],
      ["first_sequence", { t: "int", v: expected.chain.firstSequence }],
      ["last_hash", { t: "string", v: strUtf8(utf8Str(base64urlEncode(expected.chain.lastHash))) }],
      ["last_sequence", { t: "int", v: expected.chain.lastSequence }],
      ["previous_hash", { t: "string", v: strUtf8(utf8Str(base64urlEncode(expected.chain.previousHash))) }],
      ["row_count", { t: "int", v: expected.chain.rowCount }],
      ["transition_count", { t: "int", v: expected.transitions.length }],
      ["v", { t: "int", v: VERSION }],
    ]);
    const expectedHeaderBytes = jcsEncode({ t: "object", v: headerMembers }, b);
    if (!bytesEqual(parsed.headerBytes, expectedHeaderBytes)) fail("verify_anchored_export: header");
    // Verify start + end anchors + each transition against the ordered historical key chain. A key
    // chain of N keys spans N-1 transitions (keys[0]→[1],..., keys[N-2]→[N-1]); a 1-key,
    // 0-transition archive is the no-rollover case the reference accepts
    // (validate_historical_key_shapes requires keys == transitions+1, with no minimum). The
    // exact-count check below is the gate. validate the key-chain length BEFORE dereferencing
    // keys[0]/keys[N-1] so a zero-key chain fails closed (Err) instead of raising TypeError on
    // undefined.
    if (parsed.transitions.length !== expected.transitions.length) fail("verify_anchored_export: transition count");
    if (keyChain.keys.length !== parsed.transitions.length + 1) fail("verify_anchored_export: key chain length");
    verifyAnchorCompact(parsed.start, keyChain.keys[0]!, expected.startAnchor, "verify_anchored_export start", b);
    verifyAnchorCompact(parsed.end, keyChain.keys[keyChain.keys.length - 1]!, expected.endAnchor, "verify_anchored_export end", b);
    // Key-path invariants (anchored_export_codec.ex:506-572 validate_expected_key_path): the expected
    // transition list must form a strictly-increasing effective_at sequence with no fingerprint cycle,
    // and the end anchor must close the path with a chronologically-non-decreasing anchored_at.
    validateKeyPath(expected.startAnchor, expected.transitions, expected.endAnchor);
    for (let i = 0; i < parsed.transitions.length; i++) {
      verifyTransitionCompact(parsed.transitions[i]!, keyChain.keys[i]!, keyChain.keys[i + 1]!, expected.transitions[i]!, `verify_anchored_export transition ${i}`, b);
    }
    // Each transition effective_at must strictly follow the preceding anchor or transition
    // time. The end anchor anchored_at must be at least the last transition time, or the start
    // anchor time when there are no transitions.
    let transitionTime = expected.startAnchor.anchoredAt;
    for (let i = 0; i < expected.transitions.length; i++) {
      const t = expected.transitions[i]!;
      if (!(t.effectiveAt > transitionTime)) fail(`verify_anchored_export transition ${i}: chronology`);
      transitionTime = t.effectiveAt;
    }
    if (!(expected.endAnchor.anchoredAt >= transitionTime)) fail("verify_anchored_export: end chronology");
    // Re-check every row (REQ1-EXPORT-complete-scan; mirrors check_chain).
    let previous = expected.chain.previousHash;
    let sequence = expected.chain.firstSequence;
    if (expected.chain.firstSequence === 1) {
      if (!bytesEqual(previous, DEFAULT_HASH)) fail("verify_anchored_export: genesis predecessor");
    }
    if (parsed.rows.length !== expected.chain.rowCount) fail("verify_anchored_export: row count");
    for (let i = 0; i < parsed.rows.length; i++) {
      const rowBytes = parsed.rows[i]!;
      const row = jsonDecode(rowBytes, b);
      requireObjectExact(row, ["v", "chain_id", "sequence", "previous", "commitment"], `verify_anchored_export row ${i}`);
      const vV = row.v.get("v")!;
      if (vV.t !== "int" || vV.v !== VERSION) fail(`verify_anchored_export row ${i}: v`);
      const cidV = row.v.get("chain_id")!;
      if (cidV.t !== "string" || utf8Str(cidV.v) !== expected.chain.chainId) fail(`verify_anchored_export row ${i}: chain_id`);
      const seqV = row.v.get("sequence")!;
      if (seqV.t !== "int" || seqV.v !== sequence) fail(`verify_anchored_export row ${i}: sequence`);
      if (seqV.v < 1) fail(`verify_anchored_export row ${i}: sequence positive`);
      const prevRaw = requireB64urlN(row.v.get("previous"), "previous", 32);
      if (!bytesEqual(prevRaw, previous)) fail(`verify_anchored_export row ${i}: previous link`);
      const commitmentRaw = requireB64urlN(row.v.get("commitment"), "commitment", 32);
      const reEncoded = canonicalRowBytes(expected.chain.chainId, seqV.v, prevRaw, commitmentRaw, b);
      if (!bytesEqual(reEncoded, rowBytes)) fail(`verify_anchored_export row ${i}: canonical`);
      previous = sha256(ROW_PREFIX, rowBytes);
      sequence++;
    }
    if (!bytesEqual(previous, expected.chain.lastHash)) fail("verify_anchored_export: head");
    return redacted({
      version: 1 as const, objectVersion: archived.version, chainId: expected.chain.chainId,
      firstSequence: expected.chain.firstSequence, lastSequence: expected.chain.lastSequence,
      rowCount: expected.chain.rowCount,
      // Copy caller-owned Uint8Array fields into fresh buffers so a later mutation of the input
      // does not change the returned facts (the reference's Elixir binaries are immutable; TS
      // arrays are not). lastHash/digest are freshly computed, as in checkChain.
      previousHash: new Uint8Array(expected.chain.previousHash),
      lastHash: previous, digest,
      startAnchorId: expected.startAnchor.anchorId, startAnchoredAt: expected.startAnchor.anchoredAt,
      startKeyFingerprint: new Uint8Array(expected.startAnchor.keyFingerprint),
      endAnchorId: expected.endAnchor.anchorId, endAnchoredAt: expected.endAnchor.anchoredAt,
      endKeyFingerprint: new Uint8Array(expected.endAnchor.keyFingerprint),
      transitionCount: expected.transitions.length,
      verification: "anchored_export" as const, trust: "not_evaluated" as const,
      authorization: "not_evaluated" as const,
    }, "V1.AnchoredExportFacts");
  });
}

// Anchor-compact verification (shared by verify_historical_anchor + the anchored-export path).
function verifyAnchorCompact(compact: Uint8Array, key: HistoricalPublicKey, expected: ExpectedAnchor, ctx: string, bounds?: Bounds): void {
  assert(key.publicKey.length === 32, `${ctx}: key width`);
  // Thread expected.bounds (resolved once) through every bound-sensitive check. When an enclosing
  // export passes its own resolved bounds, prefer it over the nested anchor's bounds so the
  // top-level tightening takes effect.
  const b = bounds ?? coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
  // Key-window endpoints must be integral and magnitude-bounded on the archive path as well as
  // the standalone path.
  {
    const mag = resolve(b, "integer_magnitude" as MaximaKey);
    if (!Number.isInteger(key.validFrom) || Math.abs(key.validFrom) > mag) fail(`${ctx}: valid_from magnitude`);
    if (key.validBefore !== null && (!Number.isInteger(key.validBefore) || Math.abs(key.validBefore) > mag)) fail(`${ctx}: valid_before magnitude`);
    if (key.validBefore !== null && key.validBefore <= key.validFrom) fail(`${ctx}: valid_before ordering`);
  }
  const seg = parseCompact(compact, b);
  const { kid } = parseAnchorHeader(seg, b);
  if (kid !== key.keyId) fail(`${ctx}: kid`);
  if (expected.keyId !== key.keyId) fail(`${ctx}: expected key id`);
  const p = jsonDecode(seg.payloadBytes, b);
  validateAnchorPayload(p, seg.payloadBytes, b);
  if (p.t !== "object") fail(`${ctx}: payload object`);
  const anchorId = requireStringOrUri(p.v.get("anchor_id"), "anchor_id", b);
  if (anchorId !== expected.anchorId) fail(`${ctx}: anchor_id`);
  const anchoredAt = requireInt(p.v.get("anchored_at"), "anchored_at");
  if (anchoredAt !== expected.anchoredAt) fail(`${ctx}: anchored_at`);
  const chainId = requireStringOrUri(p.v.get("chain_id"), "chain_id", b);
  if (chainId !== expected.chainId) fail(`${ctx}: chain_id`);
  const sequence = requireInt(p.v.get("sequence"), "sequence");
  if (sequence !== expected.sequence) fail(`${ctx}: sequence`);
  const chainHash = requireB64urlN(p.v.get("chain_hash"), "chain_hash", 32);
  if (!bytesEqual(chainHash, expected.chainHash)) fail(`${ctx}: chain_hash`);
  const keyFpRaw = requireB64urlN(p.v.get("key_fingerprint"), "key_fingerprint", 32);
  if (!bytesEqual(keyFpRaw, expected.keyFingerprint)) fail(`${ctx}: key_fingerprint`);
  if (expected.sequence === 0 && !bytesEqual(expected.chainHash, DEFAULT_HASH)) fail(`${ctx}: genesis hash`);
  const derivedFp = thumbprintRaw(jwkFromPublicKey(key.publicKey));
  if (!bytesEqual(derivedFp, expected.keyFingerprint)) fail(`${ctx}: fingerprint`);
  if (!inWindow(anchoredAt, key)) fail(`${ctx}: window`);
  const pk = importPublicKey(key.publicKey, utf8Str(base64urlEncode(derivedFp)));
  if (!ed25519Verify(seg.signingInput, seg.signature, pk)) fail(`${ctx}: signature`);
}

function verifyTransitionCompact(compact: Uint8Array, currentKey: HistoricalPublicKey, nextKey: HistoricalPublicKey, expected: ExpectedKeyTransition, ctx: string, bounds?: Bounds): void {
  assert(currentKey.publicKey.length === 32 && nextKey.publicKey.length === 32, `${ctx}: key width`);
  if (bytesEqual(currentKey.publicKey, nextKey.publicKey)) fail(`${ctx}: distinct keys`);
  // Thread expected.bounds (resolved once) through every bound-sensitive check. When an enclosing
  // export passes its own resolved bounds, prefer it over the nested transition's bounds so the
  // top-level tightening takes effect.
  const b = bounds ?? coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
  // Key-window endpoints: integral + magnitude-bounded for BOTH keys.
  {
    const mag = resolve(b, "integer_magnitude" as MaximaKey);
    if (!Number.isInteger(currentKey.validFrom) || !Number.isInteger(nextKey.validFrom) || Math.abs(currentKey.validFrom) > mag || Math.abs(nextKey.validFrom) > mag) fail(`${ctx}: valid_from magnitude`);
    if ((currentKey.validBefore !== null && (!Number.isInteger(currentKey.validBefore) || Math.abs(currentKey.validBefore) > mag)) || (nextKey.validBefore !== null && (!Number.isInteger(nextKey.validBefore) || Math.abs(nextKey.validBefore) > mag))) fail(`${ctx}: valid_before magnitude`);
    if ((currentKey.validBefore !== null && currentKey.validBefore <= currentKey.validFrom) || (nextKey.validBefore !== null && nextKey.validBefore <= nextKey.validFrom)) fail(`${ctx}: valid_before ordering`);
  }
  const seg = parseCompact(compact, b);
  const { kid } = parseTransitionHeader(seg, b);
  if (kid !== currentKey.keyId) fail(`${ctx}: kid`);
  if (expected.currentKeyId !== currentKey.keyId) fail(`${ctx}: current key id`);
  if (expected.nextKeyId !== nextKey.keyId) fail(`${ctx}: next key id`);
  const p = jsonDecode(seg.payloadBytes, b);
  validateTransitionPayload(p, seg.payloadBytes, b);
  if (p.t !== "object") fail(`${ctx}: payload object`);
  const transitionId = requireStringOrUri(p.v.get("transition_id"), "transition_id", b);
  if (transitionId !== expected.transitionId) fail(`${ctx}: transition_id`);
  const chainId = requireStringOrUri(p.v.get("chain_id"), "chain_id", b);
  if (chainId !== expected.chainId) fail(`${ctx}: chain_id`);
  const effectiveAt = requireInt(p.v.get("effective_at"), "effective_at");
  if (effectiveAt !== expected.effectiveAt) fail(`${ctx}: effective_at`);
  const fromFpRaw = requireB64urlN(p.v.get("from_key_fingerprint"), "from_key_fingerprint", 32);
  if (!bytesEqual(fromFpRaw, expected.currentKeyFingerprint)) fail(`${ctx}: from fp`);
  const toFpRaw = requireB64urlN(p.v.get("to_key_fingerprint"), "to_key_fingerprint", 32);
  if (!bytesEqual(toFpRaw, expected.nextKeyFingerprint)) fail(`${ctx}: to fp`);
  const toKeyIdV = p.v.get("to_key_id")!;
  if (toKeyIdV.t !== "string" || utf8Str(toKeyIdV.v) !== expected.nextKeyId) fail(`${ctx}: to_key_id`);
  const derivedFrom = thumbprintRaw(jwkFromPublicKey(currentKey.publicKey));
  if (!bytesEqual(derivedFrom, expected.currentKeyFingerprint)) fail(`${ctx}: current fp`);
  const derivedTo = thumbprintRaw(jwkFromPublicKey(nextKey.publicKey));
  if (!bytesEqual(derivedTo, expected.nextKeyFingerprint)) fail(`${ctx}: next fp`);
  if (!inWindow(effectiveAt, currentKey)) fail(`${ctx}: current window`);
  if (!inWindow(effectiveAt, nextKey)) fail(`${ctx}: next window`);
  const pk = importPublicKey(currentKey.publicKey, utf8Str(base64urlEncode(derivedFrom)));
  if (!ed25519Verify(seg.signingInput, seg.signature, pk)) fail(`${ctx}: signature`);
}

// Parse the archive byte stream into its frames (spec/bap-v1.md#archive).
interface ParsedArchive {
  readonly headerBytes: Uint8Array;
  readonly start: Uint8Array;
  readonly transitions: Uint8Array[];
  readonly rows: Uint8Array[];
  readonly end: Uint8Array;
}

function parseArchive(bytes: Uint8Array, bounds: Bounds): ParsedArchive {
  if (!bytesEqual(bytes.subarray(0, ARCHIVE_PREFIX.length), ARCHIVE_PREFIX)) fail("archive: prefix");
  let cursor = ARCHIVE_PREFIX.length;
  const headerFrame = readFrame(bytes, cursor, resolve(bounds, "archive_header_bytes" as MaximaKey), "archive header");
  cursor = headerFrame.next;
  // The header itself is canonical JSON; transition_count + row_count drive the frame iteration.
  const header = jsonDecode(headerFrame.bytes, bounds);
  requireObjectExact(header, ["v", "chain_id", "first_sequence", "last_sequence", "row_count", "transition_count", "previous_hash", "last_hash"], "archive header");
  const vV = header.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("archive: header v");
  const tcV = header.v.get("transition_count")!;
  if (tcV.t !== "int" || tcV.v < 0 || tcV.v > resolve(bounds, "key_transitions" as MaximaKey)) fail("archive: transition_count");
  const rcV = header.v.get("row_count")!;
  if (rcV.t !== "int" || rcV.v < 1 || rcV.v > resolve(bounds, "chain_rows" as MaximaKey)) fail("archive: row_count");
  // Sequence-range coherence (mirrors the runner).
  const fsV = header.v.get("first_sequence")!;
  const lsV = header.v.get("last_sequence")!;
  if (fsV.t !== "int" || lsV.t !== "int") fail("archive: header sequences");
  if (!(fsV.v > 0 && lsV.v >= fsV.v && rcV.v === lsV.v - fsV.v + 1)) fail("archive: row range");
  requireB64urlN(header.v.get("previous_hash"), "previous_hash", 32);
  requireB64urlN(header.v.get("last_hash"), "last_hash", 32);
  const startFrame = readFrame(bytes, cursor, resolve(bounds, "anchor_bytes" as MaximaKey), "start anchor");
  cursor = startFrame.next;
  const transitions: Uint8Array[] = [];
  for (let i = 0; i < tcV.v; i++) {
    const f = readFrame(bytes, cursor, resolve(bounds, "anchor_bytes" as MaximaKey), `transition ${i}`);
    transitions.push(f.bytes);
    cursor = f.next;
  }
  const rows: Uint8Array[] = [];
  for (let i = 0; i < rcV.v; i++) {
    const f = readFrame(bytes, cursor, resolve(bounds, "chain_row_bytes" as MaximaKey), `row ${i}`);
    rows.push(f.bytes);
    cursor = f.next;
  }
  const endFrame = readFrame(bytes, cursor, resolve(bounds, "anchor_bytes" as MaximaKey), "end anchor");
  cursor = endFrame.next;
  if (cursor !== bytes.length) fail("archive: exact EOF");
  return { headerBytes: headerFrame.bytes, start: startFrame.bytes, transitions, rows, end: endFrame.bytes };
}

function readFrame(bytes: Uint8Array, cursor: number, maximum: number, ctx: string): { bytes: Uint8Array; next: number } {
  if (cursor + 4 > bytes.length) fail(`${ctx}: frame length`);
  const length = (bytes[cursor]! << 24 | bytes[cursor + 1]! << 16 | bytes[cursor + 2]! << 8 | bytes[cursor + 3]!) >>> 0;
  if (length === 0 || length > maximum) fail(`${ctx}: frame bound`);
  const start = cursor + 4;
  const end = start + length;
  if (end > bytes.length) fail(`${ctx}: complete frame`);
  return { bytes: bytes.subarray(start, end), next: end };
}

// Validate the expected key-transition path (anchored_export_codec.ex:506-572 validate_expected_key_path).
// The no-transition path requires the start and end anchors to share key id + fingerprint with a
// chronologically-non-decreasing end anchored_at. The transition path requires: each transition's
// current key matches the running key; effective_at is strictly increasing; no next fingerprint has
// appeared before (cycle rejection); the end anchor closes on the last transition's next key with a
// chronologically-non-decreasing anchored_at.
function validateKeyPath(start: ExpectedAnchor, transitions: ExpectedKeyTransition[], end: ExpectedAnchor): void {
  if (transitions.length === 0) {
    if (start.keyId !== end.keyId || !bytesEqual(start.keyFingerprint, end.keyFingerprint)) fail("key path: start==end key");
    if (!(end.anchoredAt >= start.anchoredAt)) fail("key path: end chronological");
    return;
  }
  let currentKeyId = start.keyId;
  let currentFp = start.keyFingerprint;
  let previousTime = start.anchoredAt;
  // seen is seeded with the start anchor's fingerprint (anchored_export_codec.ex:523).
  const seen: Uint8Array[] = [start.keyFingerprint];
  for (let i = 0; i < transitions.length; i++) {
    const t = transitions[i]!;
    if (t.currentKeyId !== currentKeyId || !bytesEqual(t.currentKeyFingerprint, currentFp)) fail(`key path: transition ${i} current key`);
    // Require each transition effective_at to strictly increase over the previous signed time.
    if (!(t.effectiveAt > previousTime)) fail(`key path: transition ${i} chronology`);
    // No cycle: next_key_fingerprint must not be in seen (anchored_export_codec.ex:560,716-720).
    for (const s of seen) {
      if (bytesEqual(t.nextKeyFingerprint, s)) fail(`key path: transition ${i} cycle`);
    }
    currentKeyId = t.nextKeyId;
    currentFp = t.nextKeyFingerprint;
    previousTime = t.effectiveAt;
    seen.push(t.nextKeyFingerprint);
  }
  // The end anchor must close on the last transition's next key (anchored_export_codec.ex:535-536).
  if (end.keyId !== currentKeyId || !bytesEqual(end.keyFingerprint, currentFp)) fail("key path: end key");
  // Require the end anchor time to be at least the last transition time.
  if (!(end.anchoredAt >= previousTime)) fail("key path: end chronological");
}

// Validate the chunk list BEFORE concatenation (anchored_export_codec.ex:333-342 validate_chunks):
// at least one chunk, each chunk nonempty, count < archive_chunks, running total ≤ archive_bytes.
function validateChunks(chunks: Uint8Array[], bounds: Bounds): void {
  // Chunk elements must be Uint8Array.
  for (const c of chunks) {
    if (!(c instanceof Uint8Array)) fail("verify_anchored_export: chunk type");
  }
  if (chunks.length === 0) fail("archive: no chunks");
  // The reference's validate_chunks guard is `count < archive_chunks` on the recursive clause
  // (start 0), accepting up to archive_chunks INCLUSIVE. Use `>` not `>=`.
  if (chunks.length > resolve(bounds, "archive_chunks" as MaximaKey)) fail("archive: chunk count");
  let total = 0;
  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i]!;
    if (c.length === 0) fail(`archive: empty chunk ${i}`);
    total += c.length;
    if (total > resolve(bounds, "archive_bytes" as MaximaKey)) fail("archive: chunk bytes");
  }
}

// Nested bounds must coerce successfully and resolve to the same effective limits as top. An
// omitted nested value resolves to maximum, so it is valid only when the top level also has
// maximum effective limits. This prevents nested context from bypassing tightened limits.
function requireBoundsEqual(nested: Bounds | undefined, top: Bounds, ctx: string): void {
  if (nested === undefined) {
    // Absent nested bounds are valid only when the effective top-level limits equal maximum.
    // Identity overrides equal to the maximum are no-ops; compare effective values rather than
    // override-map size.
    for (const [mk, v] of top.overrides) {
      if (v !== MAXIMA[mk]) fail(`${ctx}: nested bounds absent under tightened top`);
    }
    return;
  }
  const coerced = coerceBounds(nested);
  for (const key of Object.keys(MAXIMA) as MaximaKey[]) {
    if (resolve(coerced, key) !== resolve(top, key)) fail(`${ctx}: nested bounds mismatch`);
  }
}

// Re-export the primitives the public index exposes (spec/bap-v1.md L299-309).
export { jwkEncodePublic, jwkDecodePublic, thumbprint, sha256, base64urlDecode, base64urlEncode };
export { boundsNew, boundsMaximum, MAXIMUM_BOUNDS, MAXIMA };
export { uriNormalize, parseSelector, selectorMatches, typedProject, REQUEST_PREFIX };
export type { Bounds, SigningInput, Selector, MaximaKey };
void strUtf8; void _resetCensus; void resolve; void boundsNew;
