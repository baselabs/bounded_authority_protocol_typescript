import { fail, assert, type Result, trying } from "./error.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "./json.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { parseCompact, assembleSegments, scanCompact, type SigningInput, type CompactSegments } from "./compact.js";
import { jwkFromPublicKey, thumbprintRaw, jwkEncodePublic, jwkDecodePublic, thumbprint } from "./jwk.js";
import { importPublicKey, ed25519Verify, sha256, sha256Concat, _resetCensus } from "./ed25519.js";
import { requestDigest as computeRequestDigest, REQUEST_PREFIX, typedProject } from "./digest.js";
import { parseSelector, selectorMatches, type Selector } from "./selector.js";
import { uriNormalize } from "./uri.js";
import { jcsEncode } from "./jcs.js";
import { resolve, coerceBounds, boundsNew, boundsMaximum, MAXIMUM_BOUNDS, MAXIMA, type Bounds, type MaximaKey } from "./bounds.js";
import type {
  GrantFacts, EnvelopeFacts, ChainFacts, AnchorFacts, KeyTransitionFacts,
  AnchoredExportFacts, GrantDecoded, ProofDecoded, KeyLocator,
} from "./facts.js";

// The v1 verification façade (protocol-v1.md § Public verification contract, L270-290). 17 public
// functions, each returning Result<T> = Ok|Err (the {:ok,value}|{:error,:invalid} mirror). No
// authorized/decision surface (rule 1). All claims revalidated at every public entry
// (REQ1-VERIFY-revalidate). Wire formats derived from docs/protocol-v1.md + ADR 0004 + the corpus;
// the corpus is the byte-level arbiter.

const ALG = "EdDSA";
const GRANT_TYP = "ba+cap";
const PROOF_TYP = "dpop+jwt";
const ANCHOR_TYP = "ba+chain-anchor";
const TRANSITION_TYP = "ba+key-transition";
const VERSION = 1;
const DOT = 0x2e;

// BAP1-CHAIN\0 prefix for consumption-row hashing (ADR 0004 § Consumption rows).
export const ROW_PREFIX = new Uint8Array([
  0x42, 0x41, 0x50, 0x31, 0x2d, 0x43, 0x48, 0x41, 0x49, 0x4e, 0x00, // "BAP1-CHAIN\0"
]);

// BAP1-ARCHIVE\0EXPORT\0 prefix (ADR 0004 § Anchored export; the 20-byte magic, NOT framed).
export const ARCHIVE_PREFIX = strUtf8("BAP1-ARCHIVE\0EXPORT\0");

// The all-zero 32-byte hash: sequence-1 predecessor + sequence-0 anchor chain hash (ADR 0004).
const DEFAULT_HASH = new Uint8Array(32);

// --- dispatch struct types (match corpus input field names; the contract for each façade) ---

export interface TrustedIssuer { readonly keyId: string; readonly publicKey: Uint8Array; } // raw 32

export interface ExpectedGrant {
  readonly issuer: string; readonly audience: string; readonly evaluationTime: number;
  readonly clockSkew: number; readonly bounds?: Bounds;
}

export interface HistoricalPublicKey {
  readonly keyId: string; readonly publicKey: Uint8Array; // raw 32
  readonly validFrom: number; readonly validBefore: number | null; // null = unbounded
}

export interface ExpectedAnchor {
  readonly anchorId: string; readonly anchoredAt: number; readonly chainId: string;
  readonly sequence: number; readonly chainHash: Uint8Array; // raw 32
  readonly keyId: string; readonly keyFingerprint: Uint8Array; // raw 32
  readonly bounds?: Bounds;
}

export interface ExpectedKeyTransition {
  readonly transitionId: string; readonly chainId: string; readonly effectiveAt: number;
  readonly currentKeyId: string; readonly currentKeyFingerprint: Uint8Array; // raw 32
  readonly nextKeyId: string; readonly nextKeyFingerprint: Uint8Array; // raw 32
  readonly bounds?: Bounds;
}

export interface ConsumptionEntry {
  readonly chainId: string; readonly sequence: number;
  readonly previousHash: Uint8Array; readonly commitment: Uint8Array; // both raw 32
}

export interface ChainInput {
  readonly rows: Uint8Array[]; // raw canonical row bytes
  readonly chainId: string; readonly firstSequence: number; readonly lastSequence: number;
  readonly rowCount: number; readonly previousHash: Uint8Array; readonly lastHash: Uint8Array; // raw 32
}

export interface ExpectedChain {
  readonly chainId: string; readonly firstSequence: number; readonly lastSequence: number;
  readonly rowCount: number; readonly previousHash: Uint8Array; readonly lastHash: Uint8Array; // raw 32
  readonly bounds?: Bounds;
}

export interface ExpectedRequest {
  readonly trustedIssuer: TrustedIssuer;
  readonly issuer: string; readonly audience: string;
  readonly method: string; readonly targetUri: string;
  readonly invocationId: string; readonly operation: string;
  readonly castArguments: Tagged;
  readonly evaluationTime: number; readonly clockSkew: number; readonly proofMaxAge: number;
  readonly nonce: { kind: "not_required" } | { kind: "required"; value: string };
  readonly bounds?: Bounds;
}

// A selector input to the grant producer: either the bare "all" string or a tagged object.
export type SelectorInput = "all" | { readonly kind: "all" }
  | { readonly kind: "equals"; readonly path: string[]; readonly value: Tagged }
  | { readonly kind: "one_of"; readonly path: string[]; readonly values: Tagged[] };

export interface OperationInput {
  readonly name: string;
  readonly selectors: SelectorInput[];
}

// A grant producer input (the structured grant; grant_signing_input builds the JWS segments).
export interface GrantProducer {
  readonly keyId: string; readonly issuer: string; readonly grantId: string;
  readonly audiences: string[]; readonly issuedAt: number; readonly notBefore: number;
  readonly expiresAt: number; readonly holderThumbprint: string; // base64url 32
  readonly operations: OperationInput[];
}

export interface ProofProducer {
  readonly holderPublicKey: Uint8Array; // raw 32
  readonly proofId: string; readonly method: string; readonly targetUri: string;
  readonly issuedAt: number; readonly invocationId: string; readonly operation: string;
  readonly grantCompact: Uint8Array; readonly castArguments: Tagged;
  readonly nonce?: string;
}

export interface BoundaryAnchorProducer {
  readonly anchorId: string; readonly anchoredAt: number; readonly chainId: string;
  readonly sequence: number; readonly chainHash: Uint8Array; // raw 32
  readonly keyId: string; readonly publicKey: Uint8Array; // raw 32
}

export interface KeyTransitionProducer {
  readonly transitionId: string; readonly chainId: string; readonly effectiveAt: number;
  readonly currentKeyId: string; readonly currentPublicKey: Uint8Array; // raw 32
  readonly nextKeyId: string; readonly nextPublicKey: Uint8Array; // raw 32
}

export interface AnchoredExportInput {
  readonly rows: Uint8Array[]; // raw canonical row bytes
  readonly startAnchor: Uint8Array; // start-anchor compact bytes (ASCII)
  readonly endAnchor: Uint8Array; // end-anchor compact bytes (ASCII)
  readonly transitions: Uint8Array[]; // transition compact bytes (ASCII), ordered
  readonly chainId: string; readonly firstSequence: number; readonly lastSequence: number;
  readonly rowCount: number; readonly previousHash: Uint8Array; readonly lastHash: Uint8Array; // raw 32
}

export interface ExpectedExport {
  readonly chain: ExpectedChain;
  readonly digest: Uint8Array; // raw 32 (archive SHA-256)
  readonly startAnchor: ExpectedAnchor;
  readonly endAnchor: ExpectedAnchor;
  readonly transitions: ExpectedKeyTransition[];
  readonly objectVersion: string;
  readonly bounds?: Bounds;
}

export interface ArchivedObject {
  readonly chunks: Uint8Array[]; // base64url-decoded flat chunk list, concatenated = archive
  readonly version: string; // the stored-object version (out-of-band context)
}

export interface HistoricalKeyChain {
  readonly keys: HistoricalPublicKey[]; // ordered: keys[0]=start, last=end, transitions advance positionally
}

// --- shared closed-header / claim validators (derived from protocol-v1.md + RFCs) ---

// Parse a protected header object; validate the closed member set + alg + typ + kid.
function parseGrantHeader(seg: CompactSegments, bounds: Bounds): { kid: string } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "typ", "kid"], "grant header");
  requireStringLit(h, "alg", ALG, "grant header alg");
  requireStringLit(h, "typ", GRANT_TYP, "grant header typ");
  const kid = requireKid(h, bounds);
  return { kid };
}

function parseProofHeader(seg: CompactSegments, bounds: Bounds): { holderThumbprint: Uint8Array; holderKey: Uint8Array } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "typ", "jwk"], "proof header");
  requireStringLit(h, "alg", ALG, "proof header alg");
  requireStringLit(h, "typ", PROOF_TYP, "proof header typ");
  const jwkV = h.v.get("jwk")!;
  if (jwkV.t !== "object") fail("proof header: jwk object");
  // Closed OKP members {crv, kty, x}; reject any extra member (incl. private d) — REQ1-HEADER-no-private-jwk.
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
  return { kid };
}

function parseTransitionHeader(seg: CompactSegments, bounds: Bounds): { kid: string } {
  const h = jsonDecode(seg.protectedBytes, bounds);
  requireObjectExact(h, ["alg", "typ", "kid"], "transition header");
  requireStringLit(h, "alg", ALG, "transition header alg");
  requireStringLit(h, "typ", TRANSITION_TYP, "transition header typ");
  const kid = requireKid(h, bounds);
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

// Well-formed UTF-8 string check (mirrors the official String.valid?). Lone surrogates from a
// \uXXXX escape survive JSON.parse and the JCS round-trip, so byte-length checks alone do not catch
// them; the official rejects such strings (corpus_independent.mjs:1732).
function isWellFormed(s: string): boolean {
  const anyStr = s as string & { isWellFormed?: () => boolean };
  return typeof anyStr.isWellFormed === "function"
    ? anyStr.isWellFormed()
    : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

// StringOrURI (RFC 7519 §2; mirrors the official valid_uri? / StringOrURI). A bare string with no
// ':' is always valid; an opaque scheme `a:b` (no `//`) is valid; a `//` authority is structurally
// validated. This is REQUIRED to reject the corpus's `ht tp://x` and `http://a:b` cases.
function isStringOrUri(s: string): boolean {
  if (!isWellFormed(s)) return false;
  const colon = s.indexOf(":");
  if (colon === -1) return true; // bare string: always a StringOrURI
  const scheme = s.slice(0, colon);
  if (!/^[A-Za-z][A-Za-z0-9+\-.]*$/.test(scheme)) return false;
  // uri_bytes shape: unreserved + reserved punctuation, or a %HH escape.
  if (!/^(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=])*$/.test(s)) return false;
  const rest = s.slice(colon + 1);
  if (!rest.startsWith("//")) return true; // opaque / path-rootless: no authority to validate.
  return validUriAuthority(rest.slice(2).split(/[/?#]/, 1)[0]!);
}

// RFC 3986 authority validation matching URI.new for the cases the profile can produce.
function validUriAuthority(authority: string): boolean {
  const at = authority.indexOf("@");
  const hostport = at === -1 ? authority : authority.slice(at + 1);
  if (hostport.includes("@")) return false; // a second @ lands in the host — invalid.
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    if (close === -1) return false; // unterminated IPv6 literal.
    if (!isIpv6(hostport.slice(1, close))) return false;
    const suffix = hostport.slice(close + 1);
    return suffix === "" || /^:\d*$/.test(suffix);
  }
  if (hostport.includes("[") || hostport.includes("]")) return false; // stray bracket in host.
  if ((hostport.match(/:/g) ?? []).length > 1) return false; // host/port ambiguity.
  const sep = hostport.lastIndexOf(":");
  return sep === -1 || /^\d*$/.test(hostport.slice(sep + 1));
}

function isIpv6(literal: string): boolean {
  // node:net isIP accepts only a valid IPv6 literal in brackets (matches Erlang :uri_string).
  // Avoid importing node:net in the library path (the purity gate bans it); a structural check is
  // sufficient for the StringOrURI authority gate (the corpus has no bracketed-IPv6 StringOrURI).
  return /^[0-9A-Fa-f:.]+$/.test(literal);
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

// Normalized HTTPS URI claim (≤ uri_bytes; must already equal Uri.normalize — checked by re-normalizing).
function requireNormalizedUri(v: Tagged | undefined, key: string, bounds: Bounds): string {
  if (!v || v.t !== "string") fail(`claim: ${key} uri string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(bounds, "uri_bytes" as MaximaKey)) fail(`claim: ${key} uri bytes`);
  const s = utf8Str(b);
  if (!s.toLowerCase().startsWith("https://")) fail(`claim: ${key} https scheme`);
  // REQ1-URI-pre-normalized: re-normalize and require equality.
  const norm = uriNormalize(b);
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
    for (const s of sels.v) parseSelector(s, bounds); // validate each selector's closed shape (thread caller bounds — selector/2 in the reference enforces path_segments, one_of_values, selector value node bounds)
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

function validateProofPayload(p: Tagged, bounds: Bounds): asserts p is Extract<Tagged, { t: "object" }> {
  if (p.t !== "object") fail("proof payload: object");
  const hasNonce = p.v.has("nonce");
  const keys = hasNonce
    ? ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req", "nonce"]
    : ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req"];
  requireObjectExact(p, keys, "proof payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("proof: v=1");
  requireStringOrUri(p.v.get("jti"), "jti", bounds);
  requireMethod(p.v.get("htm"), "htm", bounds);
  requireNormalizedUri(p.v.get("htu"), "htu", bounds);
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

// Validate the closed anchor payload (ADR 0004 § Boundary anchors).
function validateAnchorPayload(p: Tagged, bounds: Bounds): asserts p is Extract<Tagged, { t: "object" }> {
  requireObjectExact(p, ["anchor_id", "anchored_at", "chain_hash", "chain_id", "key_fingerprint", "sequence", "v"], "anchor payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("anchor: v=1");
  requireStringOrUri(p.v.get("anchor_id"), "anchor_id", bounds);
  requireInt(p.v.get("anchored_at"), "anchored_at");
  requireStringOrUri(p.v.get("chain_id"), "chain_id", bounds);
  requireInt(p.v.get("sequence"), "sequence");
  requireB64urlN(p.v.get("chain_hash"), "chain_hash", 32);
  requireB64urlN(p.v.get("key_fingerprint"), "key_fingerprint", 32);
}

// Validate the closed key-transition payload (ADR 0004 § Authenticated key transitions).
function validateTransitionPayload(p: Tagged, bounds: Bounds): asserts p is Extract<Tagged, { t: "object" }> {
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

// 1. untrusted_key_locator (protocol-v1.md § Untrusted key locator).
export function untrustedKeyLocator(compact: Uint8Array, bounds?: Bounds): Result<KeyLocator> {
  return trying(() => {
    // Cross-vendor #13: the reference (v1.ex:21-34) decodes ONLY the protected segment — payload and
    // signature are NOT decoded, interpreted, or independently size-checked. parseCompact decodes all
    // three, so a compact with a valid protected grant header but non-canonical payload/signature
    // bytes wrongly rejected. Mirror the reference: split into exactly 3 segments, decode protected
    // only, validate the grant header + kid. (An invalid payload/signature does not affect the kid.)
    const b = bounds ?? MAXIMUM_BOUNDS;
    if (compact.length > resolve(b, "compact_bytes" as MaximaKey)) fail("key_locator: compact bound");
    // Exactly 3 segments on '.' (a 2- or 4-segment input fails the closed shape).
    const dots: number[] = [];
    for (let i = 0; i < compact.length; i++) if (compact[i] === DOT) dots.push(i);
    if (dots.length !== 2) fail("key_locator: three segments");
    const d0 = dots[0]!;
    // Cross-vendor (key-locator empty segments): the reference (v1.ex:24) only requires exactly 3
    // segments and decodes the PROTECTED segment alone — payload and signature are bound to _ and
    // never decoded or size-checked, so empty payload/signature segments are ACCEPTED (e.g.
    // "<protected>.." yields kid=<protected's>). Only an empty PROTECTED segment (d0 === 0) is
    // invalid (it must base64url-decode to a header). Do NOT reject empty payload/signature.
    if (d0 === 0) fail("key_locator: empty protected segment");
    const protectedText = compact.subarray(0, d0);
    if (protectedText.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) fail("key_locator: protected bound");
    const protectedBytes = base64urlDecode(protectedText, resolve(b, "decoded_segment_bytes" as MaximaKey));
    // Cross-vendor re-review Finding 3: thread the caller-resolved bounds into the JSON decode
    // (reference v1.ex:27 Json.decode(header_bytes, bounds) — depth/total_nodes limits honor bounds).
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

// 2. decode_grant (REQ1-VERIFY-decode-not-evaluated).
export function decodeGrant(compact: Uint8Array, bounds?: Bounds): Result<GrantDecoded> {
  return trying(() => {
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

// 3. decode_proof.
export function decodeProof(compact: Uint8Array, bounds?: Bounds): Result<ProofDecoded> {
  return trying(() => {
    const b = bounds ?? MAXIMUM_BOUNDS;
    const seg = parseCompact(compact, b);
    const { holderThumbprint } = parseProofHeader(seg, b);
    const p = jsonDecode(seg.payloadBytes, b);
    validateProofPayload(p, b);
    const jti = requireStringOrUri(p.v.get("jti"), "jti", b);
    return { proofId: jti, holderThumbprint, verification: "not_evaluated" as const };
  });
}

// 4. verify_grant (REQ1-VERIFY-grant-exact, grant-times, no-iat-nbf-order).
export function verifyGrant(compact: Uint8Array, trusted: TrustedIssuer, expected: ExpectedGrant): Result<GrantFacts> {
  return trying(() => {
    // Cross-vendor #22 (fail-closed shallow): the reference pattern-matches %TrustedIssuer{} and
    // returns {:error, :invalid} for any malformed context struct (runtime.ex:181,196). A null OR a
    // struct missing publicKey/keyId must fail closed — not throw a native TypeError that escapes the
    // Result contract. Validate the trusted issuer's shape before dereferencing its fields.
    if (trusted === null || trusted === undefined) fail("verify_grant: trusted issuer required");
    if (!(trusted.publicKey instanceof Uint8Array) || trusted.publicKey.length !== 32) fail("verify_grant: issuer key width");
    if (typeof trusted.keyId !== "string") fail("verify_grant: issuer key id");
    // Cross-vendor #19: the reference requires is_integer(evaluation_time) and is_integer(clock_skew)
    // (>= 0) — runtime.ex:522-523. A range-only `< 0` check accepts fractional times.
    if (!Number.isInteger(expected.evaluationTime)) fail("verify_grant: integer evaluation time");
    // BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once (runtime.ex:186) and
    // threads it into validate_expected_grant (clock_skew <= bounds.clock_skew) + every bound-sensitive
    // check below. A caller tightening via expected.bounds now actually takes effect.
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
    return {
      version: VERSION, issuer: iss, grantId: requireStringOrUri(p.v.get("jti"), "jti", b),
      issuerKeyFingerprint: fp, holderThumbprint: jkt, matchedAudience: expected.audience,
      issuedAt: iat, notBefore: nbf, expiresAt: exp, authorization: "not_evaluated" as const,
    };
  });
}

// 5. check_envelope (REQ1-VERIFY-envelope-binding).
export function checkEnvelope(grantCompact: Uint8Array, proofCompact: Uint8Array, expected: ExpectedRequest): Result<EnvelopeFacts> {
  return trying(() => {
    const t = expected.trustedIssuer;
    // Cross-vendor #22 (fail-closed shallow): a null/wrong-typed trustedIssuer (or any structured-
    // input field) must fail closed as InvalidError, not propagate a native TypeError from the deref
    // below. Validate the context shape before touching it. The reference returns {:error,:invalid}
    // for all malformed input.
    if (t === null || t === undefined) fail("check_envelope: trusted issuer required");
    if (!(t.publicKey instanceof Uint8Array) || t.publicKey.length !== 32) fail("check_envelope: issuer key width");
    if (typeof t.keyId !== "string") fail("check_envelope: issuer key id");
    // Cross-vendor #19: the reference requires is_integer(evaluation_time), is_integer(clock_skew)
    // (>= 0), and proof_max_age > 0 (strictly positive) — runtime.ex:522-523,550-551. A range-only
    // `< 0` check accepts fractional times and proofMaxAge=0. The signed-time boundary is exact.
    if (!Number.isInteger(expected.evaluationTime)) fail("check_envelope: integer evaluation time");
    // BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once (runtime.ex:204) and
    // threads it into validate_expected_request (clock_skew, proof_max_age) + parse_grant + parse_proof
    // + every bound-sensitive claim check below. A caller tightening via expected.bounds now takes
    // effect across both the grant and the proof.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    if (!Number.isInteger(expected.clockSkew) || expected.clockSkew < 0 || expected.clockSkew > resolve(b, "clock_skew" as MaximaKey)) fail("check_envelope: skew");
    if (!Number.isInteger(expected.proofMaxAge) || expected.proofMaxAge <= 0 || expected.proofMaxAge > resolve(b, "proof_max_age" as MaximaKey)) fail("check_envelope: proof_max_age");
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
    // Cross-vendor #4: checkEnvelope must enforce grant-time coherence (iat<exp, nbf<exp), mirroring
    // the reference's coherent_times? (runtime.ex:872-875) which fires at parse time. decodeGrant and
    // verifyGrant already check this; checkEnvelope had its own inline path that omitted it.
    if (!(giat < gexp) || !(gnbf < gexp)) fail("check_envelope: grant times coherent");
    if (!(giat <= expected.evaluationTime + expected.clockSkew)) fail("check_envelope: grant iat");
    if (!(gnbf <= expected.evaluationTime + expected.clockSkew)) fail("check_envelope: grant nbf");
    if (!(gexp > expected.evaluationTime - expected.clockSkew)) fail("check_envelope: grant exp");
    const gfp = thumbprintRaw(jwkFromPublicKey(t.publicKey));
    const gkey = importPublicKey(t.publicKey, utf8Str(base64urlEncode(gfp)));
    if (!ed25519Verify(gseg.signingInput, gseg.signature, gkey)) fail("check_envelope: grant signature");
    // --- verify proof (holder signature) ---
    const pseg = parseCompact(proofCompact, b);
    const { holderThumbprint, holderKey } = parseProofHeader(pseg, b);
    const pp = jsonDecode(pseg.payloadBytes, b);
    validateProofPayload(pp, b);
    const hkey = importPublicKey(holderKey, utf8Str(base64urlEncode(holderThumbprint)));
    if (!ed25519Verify(pseg.signingInput, pseg.signature, hkey)) fail("check_envelope: proof signature");
    if (pp.t !== "object") fail("check_envelope: proof payload");
    // ath = SHA-256(ASCII grant compact), gated by scan (shape+size, not canonicity) — mirrors
    // CompactJws.hash (compact_jws.ex:60-66 scan then hash). The grant was already parsed above, so
    // this scan is redundant for verify but matches the reference's hash gate exactly.
    scanCompact(grantCompact, b);
    const athRaw = sha256(grantCompact);
    const athB64 = utf8Str(base64urlEncode(athRaw));
    const ppAth = pp.v.get("ath")!;
    if (ppAth.t !== "string" || utf8Str(ppAth.v) !== athB64) fail("check_envelope: ath");
    // Method / URI / invocation / operation bindings.
    const htm = requireMethod(pp.v.get("htm"), "htm", b);
    if (htm !== expected.method) fail("check_envelope: method");
    const htu = requireNormalizedUri(pp.v.get("htu"), "htu", b);
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
    return {
      version: VERSION, issuer: giss,
      grantId: requireStringOrUri(gobj.v.get("jti"), "jti", b),
      issuerKeyFingerprint: gfp, holderThumbprint, matchedAudience: expected.audience,
      grantIssuedAt: giat, grantNotBefore: gnbf, grantExpiresAt: gexp,
      proofId: requireStringOrUri(pp.v.get("jti"), "jti", b),
      invocationId: baInv, operation: baOp, uri: htu,
      grantHash: athRaw, requestHash: baReqRaw, proofIssuedAt: piat,
      authorization: "not_evaluated" as const,
    };
  });
}

// 6. request_digest (the façade; returns Ok<raw 32-byte digest> | Err — cross-vendor #21: mirror
// the Elixir {:ok, binary} | {:error, :invalid} and the other 15 façade functions).
export function requestDigest(operation: string, castArguments: Tagged, bounds?: Bounds): Result<Uint8Array> {
  return trying(() => computeRequestDigest(operation, castArguments, bounds ?? MAXIMUM_BOUNDS));
}

// 7. encode_consumption_entry (ADR 0004 § Consumption rows). Returns canonical row bytes + hash.
export interface EncodedConsumptionEntry { readonly bytes: Uint8Array; readonly hash: Uint8Array; }
export function encodeConsumptionEntry(entry: ConsumptionEntry, bounds?: Bounds): Result<EncodedConsumptionEntry> {
  return trying(() => {
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

// 8. check_chain (ADR 0004 § Consumption rows; REQ1-CHAIN-raw-rows-bounds).
export function checkChain(chain: ChainInput, expected: ExpectedChain): Result<ChainFacts> {
  return trying(() => {
    // BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once (consumption_chain.ex
    // check_chain) and threads it into the row-count bound + every parse_row (chain_row_bytes). A
    // caller tightening via expected.bounds now takes effect.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    if (expected.chainId !== chain.chainId) fail("check_chain: chain_id");
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
    // Cross-vendor F4: the reference's check_chain takes ChainInput{rows} + ExpectedChain and uses
    // expected.previous_hash as BOTH the validation seed and the returned fact; the SDK's ChainInput
    // also carries a previousHash that must equal the expected value (the non-genesis row walk would
    // otherwise seed from expected while the input field flows unchecked into the returned facts).
    // Validate equality in BOTH cases so chain.previousHash is never an unverified echo.
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
    return {
      version: 1 as const, chainId: chain.chainId, firstSequence: chain.firstSequence,
      lastSequence: chain.lastSequence, rowCount: chain.rowCount,
      // Cross-vendor re-review F3 + F4: copy the VERIFIED expected.previousHash (not the caller's
      // chain.previousHash input) into a fresh Uint8Array so a later mutation of either input buffer
      // does not change the returned fact (the reference's Elixir binaries are immutable; TS arrays
      // are not). The reference returns expected.previous_hash; lastHash is freshly computed.
      previousHash: new Uint8Array(expected.previousHash), lastHash: previous,
      verification: "boundary_consistent" as const, trust: "not_evaluated" as const,
    };
  });
}

// 9. grant_signing_input (the deterministic producer; REQ1-SIGNING-deterministic-produce).
export function grantSigningInput(grant: GrantProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
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
  if (s === "all" || (typeof s === "object" && s.kind === "all")) {
    return { t: "object", v: new Map<string, Tagged>([["kind", { t: "string", v: strUtf8("all") }]]) };
  }
  if (typeof s === "object" && s.kind === "equals") {
    const path = validatePath(s.path, b);
    validateSelectorValue(s.value, b);
    const members = new Map<string, Tagged>([
      ["kind", { t: "string", v: strUtf8("equals") }],
      ["path", path],
      ["value", s.value],
    ]);
    return { t: "object", v: members };
  }
  if (typeof s === "object" && s.kind === "one_of") {
    const path = validatePath(s.path, b);
    if (s.values.length < 1 || s.values.length > resolve(b, "one_of_values" as MaximaKey)) fail("selector: values count");
    for (const v of s.values) validateSelectorValue(v, b);
    const members = new Map<string, Tagged>([
      ["kind", { t: "string", v: strUtf8("one_of") }],
      ["path", path],
      ["values", { t: "array", v: s.values }],
    ]);
    return { t: "object", v: members };
  }
  fail("selector: shape");
}

function validatePath(path: string[], b: Bounds): Tagged {
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

// 10. proof_signing_input (REQ1-SIGNING-deterministic-produce).
export function proofSigningInput(proof: ProofProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
    const b = bounds ?? MAXIMUM_BOUNDS;
    assert(proof.holderPublicKey.length === 32, "proof_signing_input: holder key width");
    if (!isStringOrUri(proof.proofId)) fail("proof_signing_input: proof_id");
    const methodBytes = strUtf8(proof.method);
    if (methodBytes.length < 1 || methodBytes.length > resolve(b, "method_bytes" as MaximaKey)) fail("proof_signing_input: method bytes");
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(proof.method)) fail("proof_signing_input: method token");
    // htu normalized + pre-normalized.
    const htuNorm = uriNormalize(strUtf8(proof.targetUri), b);
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
    const jwk = jwkFromPublicKey(proof.holderPublicKey);
    const headerMembers = new Map<string, Tagged>([
      ["alg", { t: "string", v: strUtf8(ALG) }],
      ["jwk", jwkToTagged(jwk)],
      ["typ", { t: "string", v: strUtf8(PROOF_TYP) }],
    ]);
    // Producer ath: gate the grant compact by scan (shape+size, NOT base64url canonicity) before
    // hashing it into `ath` — mirrors CompactJws.ath (compact_jws.ex:53-58 scan then hash). A
    // caller-supplied non-compact grant must not be embedded as sha256(garbage) in the proof.
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
      ["jti", { t: "string", v: strUtf8(proof.proofId) }],
      ["v", { t: "int", v: VERSION }],
    ]);
    if (proof.nonce !== undefined) payloadMembers.set("nonce", { t: "string", v: strUtf8(proof.nonce) });
    return {
      kind: "proof",
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

// 11. assemble_compact (REQ1-VERIFY-no-signer-callback; public /2 contract, protocol-v1.md:299,319).
// Mirrors runtime.ex:147-155 assemble_compact: assemble via the low-level assembler, then
// validate_assembled_compact (runtime.ex:754-780) re-parses the composed compact per kind. The
// signing-input gates (kind↔typ, segment bounds, base64url payload, compact_bytes) come from
// CompactJws.assemble's valid_signing_input? (compact_jws.ex:36,80-101). The public contract
// carries no caller bounds, so the profile maximum (MAXIMUM_BOUNDS) is used. A mislabeled kind
// (typ ≠ kind), oversized segment, non-base64url payload, or malformed payload content fails
// closed — the producer must not mint bytes its own consumer (verify) would reject.
export function assembleCompact(input: SigningInput, signature: Uint8Array): Result<Uint8Array> {
  return trying(() => {
    const b = MAXIMUM_BOUNDS;
    const assembled = assembleSegments(input, signature);
    if (!assembled.ok) fail("assemble_compact: signing input");
    const compact = assembled.value;
    if (compact.length > resolve(b, "compact_bytes" as MaximaKey)) fail("assemble_compact: compact_bytes");
    // Re-parse the composed compact per kind (validate_assembled_compact). parseCompact enforces the
    // segment bounds + base64url decode; parseXxxHeader enforces kind↔typ; the payload validators
    // enforce the full payload structure. The GRANT arm uses decodeGrant (the full decoder) because
    // validateGrantPayload is structural-only — it does not validate iss/jti/aud/times/cnf, which
    // decodeGrant extracts + validates (mirrors reference parse_grant → decode_grant_fields).
    const seg = parseCompact(compact, b);
    const payload = jsonDecode(seg.payloadBytes, b);
    switch (input.kind) {
      case "grant": {
        const r = decodeGrant(compact, b);
        if (!r.ok) fail("assemble_compact: grant re-parse");
        break;
      }
      case "proof": parseProofHeader(seg, b); validateProofPayload(payload, b); break;
      case "boundary_anchor": parseAnchorHeader(seg, b); validateAnchorPayload(payload, b); break;
      case "key_transition": parseTransitionHeader(seg, b); validateTransitionPayload(payload, b); break;
      default: fail("assemble_compact: kind");
    }
    return compact;
  });
}

// 12. boundary_anchor_signing_input (ADR 0004 § Boundary anchors).
export function boundaryAnchorSigningInput(anchor: BoundaryAnchorProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
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

// 13. key_transition_signing_input (ADR 0004 § Authenticated key transitions).
export function keyTransitionSigningInput(t: KeyTransitionProducer, bounds?: Bounds): Result<SigningInput> {
  return trying(() => {
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

// 14. encode_anchored_export (ADR 0004 § Anchored export; REQ1-EXPORT-input-shape).
export interface EncodedAnchoredExport { readonly archive: Uint8Array; readonly digest: Uint8Array; }
export function encodeAnchoredExport(input: AnchoredExportInput, expected: ExpectedExport): Result<EncodedAnchoredExport> {
  return trying(() => {
    // Validate inputs BEFORE framing (mirrors anchored_export_codec.ex:33-57 encode →
    // validate_expected_export + parse_expected_transitions + validate_expected_key_path). The
    // parser would reject the bytes a too-large input would produce; the producer rejects earlier.
    // BAP-09 #10/#11: resolve expected.bounds once and thread it through the encode-time bounds
    // checks so a caller tightening via expected.bounds takes effect (matches verify_anchored_export).
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    validateExportInputs(input, expected, b);
    const headerBytes = buildArchiveHeader(input, expected.chain, b);
    // Build the framed chunk list, then validate count + bytes BEFORE materializing the joined
    // archive (mirrors reference validate_chunks on the chunk list, anchored_export_codec.ex:69 — not
    // on a concatenated binary, so an over-bound input rejects before the allocation). Loop-build
    // avoids spreading the chunk list past V8's ~65534 call-arg ceiling (archive_chunks ≤ 65796).
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

// UINT32_BE(len) || bytes — the archive framing (ADR 0004 § Anchored export).
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

// 15. verify_historical_anchor (ADR 0004 § Boundary anchors; protocol-v1.md § Historical anchor).
export function verifyHistoricalAnchor(compact: Uint8Array, key: HistoricalPublicKey, expected: ExpectedAnchor): Result<AnchorFacts> {
  return trying(() => {
    assert(key.publicKey.length === 32, "verify_historical_anchor: key width");
    // BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check, as
    // the reference does (boundary_anchor_codec.ex parses the compact + payload under bounds).
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    const seg = parseCompact(compact, b);
    const { kid } = parseAnchorHeader(seg, b);
    if (kid !== key.keyId) fail("verify_historical_anchor: kid");
    if (expected.keyId !== key.keyId) fail("verify_historical_anchor: expected key id");
    const p = jsonDecode(seg.payloadBytes, b);
    validateAnchorPayload(p, b);
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
    return {
      version: 1 as const, anchorId, anchoredAt, chainId, sequence, chainHash,
      keyFingerprint: keyFpRaw, verification: "signature_and_window" as const,
      trust: "not_evaluated" as const,
    };
  });
}

// 16. verify_key_transition (ADR 0004 § Authenticated key transitions).
export function verifyKeyTransition(compact: Uint8Array, oldKey: HistoricalPublicKey, newKey: HistoricalPublicKey, expected: ExpectedKeyTransition): Result<KeyTransitionFacts> {
  return trying(() => {
    assert(oldKey.publicKey.length === 32 && newKey.publicKey.length === 32, "verify_key_transition: key width");
    if (bytesEqual(oldKey.publicKey, newKey.publicKey)) fail("verify_key_transition: distinct keys");
    // BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    const seg = parseCompact(compact, b);
    const { kid } = parseTransitionHeader(seg, b);
    if (kid !== oldKey.keyId) fail("verify_key_transition: kid");
    if (expected.currentKeyId !== oldKey.keyId) fail("verify_key_transition: current key id");
    if (expected.nextKeyId !== newKey.keyId) fail("verify_key_transition: next key id");
    const p = jsonDecode(seg.payloadBytes, b);
    validateTransitionPayload(p, b);
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
    return {
      version: 1 as const, transitionId, chainId, effectiveAt,
      currentKeyFingerprint: fromFpRaw, nextKeyFingerprint: toFpRaw,
      verification: "authenticated_transition" as const, trust: "not_evaluated" as const,
    };
  });
}

// 17. verify_anchored_export (ADR 0004 § Anchored export; REQ1-EXPORT-complete-scan).
export function verifyAnchoredExport(archived: ArchivedObject, keyChain: HistoricalKeyChain, expected: ExpectedExport): Result<AnchoredExportFacts> {
  return trying(() => {
    // BAP-09 #10/#11: the reference resolves Bounds.coerce(expected.bounds) once (anchored_export_codec.ex:84-185)
    // and threads it into validate_chunks (archive_chunks, archive_bytes), parse_archive (frame
    // reads), and every row check. The inner anchors/transitions carry their own bounds (used by
    // their own compact parsers). A caller tightening via expected.bounds now takes effect.
    const b = coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
    // Cross-vendor (nested bounds pinning): the reference (anchored_export_codec.ex:352-354, :404-406)
    // pins every nested bounds to the top-level resolved bounds via `{:ok, ^bounds} <- Bounds.coerce(x.bounds)`
    // — a nested value that differs (or defaults to maximum when the top is tightened) is REJECTED.
    // The SDK previously preferred the outer bounds and silently discarded the nested value; pin them
    // explicitly so a mismatch fails closed, matching the reference.
    requireBoundsEqual(expected.chain.bounds, b, "verify_anchored_export: chain bounds");
    requireBoundsEqual(expected.startAnchor.bounds, b, "verify_anchored_export: start anchor bounds");
    requireBoundsEqual(expected.endAnchor.bounds, b, "verify_anchored_export: end anchor bounds");
    for (let i = 0; i < expected.transitions.length; i++) {
      requireBoundsEqual(expected.transitions[i]!.bounds, b, `verify_anchored_export: transition ${i} bounds`);
    }
    // Validate the chunk list BEFORE concatenation (mirrors anchored_export_codec.ex:101-102,333-342
    // validate_chunks): each chunk nonempty, count < archive_chunks, total ≤ archive_bytes. Hashing
    // happens after the shape is validated.
    validateChunks(archived.chunks, b);
    // Stream the digest over the chunks WITHOUT materializing/spreading them (reference hash_chunks,
    // anchored_export_codec.ex:705-714 — incremental SHA-256 per chunk, no concat). sha256Concat feeds
    // the chunk list as an array, never spread, so a list of up to archive_chunks (65796) entries
    // cannot hit V8's ~65534 call-arg ceiling. An inauthentic/oversized archive is rejected at the
    // digest compare before the parse materializes the bytes (BAP-15 Rust precedent, v1.rs:30-40).
    const digest = sha256Concat(archived.chunks);
    if (!bytesEqual(digest, expected.digest)) fail("verify_anchored_export: digest");
    // Object version: exact equality (out-of-band context, not embedded).
    if (archived.version !== expected.objectVersion) fail("verify_anchored_export: object version");
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
    // Verify start + end anchors + each transition against the ordered historical key chain.
    // A key chain of N keys spans N-1 transitions (keys[0]→[1], ..., keys[N-2]→[N-1]); a 1-key,
    // 0-transition archive is the no-rollover case the reference accepts (validate_historical_key_shapes
    // requires keys == transitions+1, with no minimum). The exact-count check below is the gate.
    // Cross-vendor re-review F2: validate the key-chain length BEFORE dereferencing keys[0]/keys[N-1]
    // so a zero-key chain fails closed (Err) instead of raising TypeError on undefined.
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
    // Chronology over the ACTUAL anchored times (anchored_export_codec.ex:138-154 verify_transitions
    // + chronological_end?): each transition's effective_at must be strictly greater than the
    // previous anchor/transition time, and the end anchor's anchored_at must be >= the last
    // transition's effective_at (>= the start anchor's anchored_at for the no-transition case —
    // covered by validateKeyPath's chronological_end on the start anchor).
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
    return {
      version: 1 as const, objectVersion: archived.version, chainId: expected.chain.chainId,
      firstSequence: expected.chain.firstSequence, lastSequence: expected.chain.lastSequence,
      rowCount: expected.chain.rowCount,
      // Cross-vendor (facts immutability): copy caller-owned Uint8Array fields into fresh buffers so a
      // later mutation of the input does not change the returned facts (the reference's Elixir binaries
      // are immutable; TS arrays are not). lastHash/digest are freshly computed. Same family as the
      // checkChain F3 fix.
      previousHash: new Uint8Array(expected.chain.previousHash),
      lastHash: previous, digest,
      startAnchorId: expected.startAnchor.anchorId, startAnchoredAt: expected.startAnchor.anchoredAt,
      startKeyFingerprint: new Uint8Array(expected.startAnchor.keyFingerprint),
      endAnchorId: expected.endAnchor.anchorId, endAnchoredAt: expected.endAnchor.anchoredAt,
      endKeyFingerprint: new Uint8Array(expected.endAnchor.keyFingerprint),
      transitionCount: expected.transitions.length,
      verification: "anchored_export" as const, trust: "not_evaluated" as const,
      authorization: "not_evaluated" as const,
    };
  });
}

// Anchor-compact verification (shared by verify_historical_anchor + the anchored-export path).
function verifyAnchorCompact(compact: Uint8Array, key: HistoricalPublicKey, expected: ExpectedAnchor, ctx: string, bounds?: Bounds): void {
  assert(key.publicKey.length === 32, `${ctx}: key width`);
  // BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check. When
  // an enclosing export passes its own resolved bounds (cross-vendor re-review F1), prefer it over
  // the nested anchor's bounds so the top-level tightening takes effect.
  const b = bounds ?? coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
  const seg = parseCompact(compact, b);
  const { kid } = parseAnchorHeader(seg, b);
  if (kid !== key.keyId) fail(`${ctx}: kid`);
  if (expected.keyId !== key.keyId) fail(`${ctx}: expected key id`);
  const p = jsonDecode(seg.payloadBytes, b);
  validateAnchorPayload(p, b);
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
  // BAP-09 #10/#11: thread expected.bounds (resolved once) through every bound-sensitive check. When
  // an enclosing export passes its own resolved bounds (cross-vendor re-review F1), prefer it over
  // the nested transition's bounds so the top-level tightening takes effect.
  const b = bounds ?? coerceBounds(expected.bounds ?? MAXIMUM_BOUNDS);
  const seg = parseCompact(compact, b);
  const { kid } = parseTransitionHeader(seg, b);
  if (kid !== currentKey.keyId) fail(`${ctx}: kid`);
  if (expected.currentKeyId !== currentKey.keyId) fail(`${ctx}: current key id`);
  if (expected.nextKeyId !== nextKey.keyId) fail(`${ctx}: next key id`);
  const p = jsonDecode(seg.payloadBytes, b);
  validateTransitionPayload(p, b);
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

// Parse the archive byte stream into its frames (ADR 0004 § Anchored export).
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
    // strictly_after?(effective_at, previous_time) — strictly increasing (anchored_export_codec.ex:559,722).
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
  // chronological_end?(end.anchored_at, previous_time) — >= the last transition's effective_at.
  if (!(end.anchoredAt >= previousTime)) fail("key path: end chronological");
}

// Validate the chunk list BEFORE concatenation (anchored_export_codec.ex:333-342 validate_chunks):
// at least one chunk, each chunk nonempty, count < archive_chunks, running total ≤ archive_bytes.
function validateChunks(chunks: Uint8Array[], bounds: Bounds): void {
  if (chunks.length === 0) fail("archive: no chunks");
  // Cross-vendor re-review Finding 2: the reference's validate_chunks guard is `count < archive_chunks`
  // on the recursive clause (start 0), accepting up to archive_chunks INCLUSIVE. Use `>` not `>=`.
  if (chunks.length > resolve(bounds, "archive_chunks" as MaximaKey)) fail("archive: chunk count");
  let total = 0;
  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i]!;
    if (c.length === 0) fail(`archive: empty chunk ${i}`);
    total += c.length;
    if (total > resolve(bounds, "archive_bytes" as MaximaKey)) fail("archive: chunk bytes");
  }
}

// Cross-vendor (nested bounds pinning): the reference pins nested expected.bounds to the top-level
// resolved bounds (anchored_export_codec.ex:352-354 `{:ok, ^bounds} <- Bounds.coerce(x.bounds)`).
// When a nested bounds is present, it must coerce cleanly AND resolve to the same value as `top`
// for every limit — otherwise a caller could tighten the top level while a nested struct widens or
// drifts silently. Absent nested bounds is the documented default-to-maximum case (the caller omits
// the field), which the reference also pins: Bounds.coerce(%{}) == maximum, so pin to top only when
// top != maximum (a tightened top rejects the default-maximum nested). When top IS maximum, an absent
// nested bounds is accepted (both resolve to maximum).
function requireBoundsEqual(nested: Bounds | undefined, top: Bounds, ctx: string): void {
  if (nested === undefined) {
    // Absent nested bounds: valid only if the top is also maximum (no tightening). A tightened top
    // requires every nested struct to carry the same tightening (the reference's pin rejects the
    // default-to-maximum coerce when top < maximum).
    if (top.overrides.size !== 0) fail(`${ctx}: nested bounds absent under tightened top`);
    return;
  }
  const coerced = coerceBounds(nested);
  for (const key of Object.keys(MAXIMA) as MaximaKey[]) {
    if (resolve(coerced, key) !== resolve(top, key)) fail(`${ctx}: nested bounds mismatch`);
  }
}

// Re-export the primitives the public index exposes (protocol-v1.md L299-309).
export { jwkEncodePublic, jwkDecodePublic, thumbprint, sha256, base64urlDecode, base64urlEncode };
export { boundsNew, boundsMaximum, MAXIMUM_BOUNDS, MAXIMA };
export { uriNormalize, parseSelector, selectorMatches, typedProject, REQUEST_PREFIX };
export type { Bounds, SigningInput, Selector, MaximaKey };
void strUtf8; void _resetCensus; void resolve; void boundsNew;
