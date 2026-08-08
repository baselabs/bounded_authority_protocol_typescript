import { fail, assert, type Result, ok, err, trying } from "./error.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "./json.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { parseCompact, assembleCompact, type SigningInput, type CompactSegments } from "./compact.js";
import { jwkFromPublicKey, thumbprintRaw, jwkEncodePublic } from "./jwk.js";
import { importPublicKey, ed25519Verify, sha256, _resetCensus } from "./ed25519.js";
import { requestDigest } from "./digest.js";
import { parseSelector, selectorMatches } from "./selector.js";
import { uriNormalize } from "./uri.js";
import { resolve, boundsNew, MAXIMUM_BOUNDS, type Bounds, type MaximaKey } from "./bounds.js";
import type {
  GrantFacts, EnvelopeFacts, ChainFacts, AnchorFacts, KeyTransitionFacts,
  AnchoredExportFacts, GrantDecoded, ProofDecoded, KeyLocator,
} from "./facts.js";

// The v1 verification façade (protocol-v1.md § Public verification contract, L270-290). 17 public
// functions, each returning Result<T> = Ok|Err (the {:ok,value}|{:error,:invalid} mirror). No
// authorized/decision surface (rule 1). All claims revalidated at every public entry
// (REQ1-VERIFY-revalidate).

const ALG = "EdDSA";
const GRANT_TYP = "ba+cap";
const PROOF_TYP = "dpop+jwt";
const ANCHOR_TYP = "ba+chain-anchor";
const TRANSITION_TYP = "ba+key-transition";
const VERSION = 1;

// --- shared closed-header / claim validators (derived from protocol-v1.md + RFCs) ---

// Parse a protected header object; validate the closed member set + alg + typ + kid.
function parseGrantHeader(seg: CompactSegments): { kid: string } {
  const h = jsonDecode(seg.protectedBytes);
  requireObjectExact(h, ["alg", "typ", "kid"], "grant header");
  requireStringLit(h, "alg", ALG, "grant header alg");
  requireStringLit(h, "typ", GRANT_TYP, "grant header typ");
  const kid = requireKid(h);
  return { kid };
}

function parseProofHeader(seg: CompactSegments): { holderThumbprint: Uint8Array; holderKey: Uint8Array } {
  const h = jsonDecode(seg.protectedBytes);
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

function parseAnchorHeader(seg: CompactSegments): { kid: string } {
  const h = jsonDecode(seg.protectedBytes);
  requireObjectExact(h, ["alg", "typ", "kid"], "anchor header");
  requireStringLit(h, "alg", ALG, "anchor header alg");
  requireStringLit(h, "typ", ANCHOR_TYP, "anchor header typ");
  const kid = requireKid(h);
  return { kid };
}

function parseTransitionHeader(seg: CompactSegments): { kid: string } {
  const h = jsonDecode(seg.protectedBytes);
  requireObjectExact(h, ["alg", "typ", "kid"], "transition header");
  requireStringLit(h, "alg", ALG, "transition header alg");
  requireStringLit(h, "typ", TRANSITION_TYP, "transition header typ");
  const kid = requireKid(h);
  return { kid };
}

function requireKid(h: Extract<Tagged, { t: "object" }>): string {
  const kidV = h.v.get("kid")!;
  if (kidV.t !== "string") fail("header: kid string");
  const b = kidV.v;
  if (b.length < 1 || b.length > resolve(MAXIMUM_BOUNDS, "kid_bytes" as MaximaKey)) fail("header: kid bytes");
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

// StringOrURI claim (RFC 7519 §2): non-empty, ≤ identifier_bytes. Case-sensitive.
function requireStringOrUri(v: Tagged | undefined, key: string): string {
  if (!v || v.t !== "string") fail(`claim: ${key} string`);
  const s = utf8Str(v.v);
  if (s.length < 1 || s.length > resolve(MAXIMUM_BOUNDS, "identifier_bytes" as MaximaKey)) fail(`claim: ${key} bytes`);
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

// Canonical base64url of exactly 32 bytes → returns the raw 32 bytes.
function requireB64url32(v: Tagged | undefined, key: string): Uint8Array {
  if (!v || v.t !== "string") fail(`claim: ${key} b64url string`);
  const raw = base64urlDecode(v.v);
  if (raw.length !== 32) fail(`claim: ${key} width`);
  return raw;
}

// Printable-ASCII operation name 1..operation_bytes.
function requireOperation(v: Tagged | undefined, key: string): string {
  if (!v || v.t !== "string") fail(`claim: ${key} operation string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(MAXIMUM_BOUNDS, "operation_bytes" as MaximaKey)) fail(`claim: ${key} operation bytes`);
  const s = utf8Str(b);
  if (!/^[\x20-\x7e]+$/.test(s)) fail(`claim: ${key} operation printable ASCII`);
  return s;
}

// RFC 9110 method token 1..method_bytes, ASCII token chars, byte-for-byte (no case-fold).
function requireMethod(v: Tagged | undefined, key: string): string {
  if (!v || v.t !== "string") fail(`claim: ${key} method string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(MAXIMUM_BOUNDS, "method_bytes" as MaximaKey)) fail(`claim: ${key} method bytes`);
  const s = utf8Str(b);
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(s)) fail(`claim: ${key} method token`);
  return s;
}

// Normalized HTTPS URI claim (≤ uri_bytes; must already equal Uri.normalize — checked by re-normalizing).
const URI_RE = /^[\x21-\x7e]+$/;
function requireNormalizedUri(v: Tagged | undefined, key: string): string {
  if (!v || v.t !== "string") fail(`claim: ${key} uri string`);
  const b = v.v;
  if (b.length < 1 || b.length > resolve(MAXIMUM_BOUNDS, "uri_bytes" as MaximaKey)) fail(`claim: ${key} uri bytes`);
  const s = utf8Str(b);
  if (!URI_RE.test(s)) fail(`claim: ${key} uri ASCII`);
  if (!s.toLowerCase().startsWith("https://")) fail(`claim: ${key} https scheme`);
  // REQ1-URI-pre-normalized: re-normalize and require equality.
  const norm = uriNormalize(b);
  if (!norm.ok) fail(`claim: ${key} uri normalized`);
  if (utf8Str(norm.value) !== s) fail(`claim: ${key} uri pre-normalized`);
  return s;
}

// --- the 17 façade functions ---

export interface TrustedIssuer { readonly keyId: string; readonly publicKey: Uint8Array; } // raw 32
export interface ExpectedGrant {
  readonly issuer: string; readonly audience: string; readonly evaluationTime: number;
  readonly clockSkew: number; readonly bounds?: Bounds;
}
export interface Operation { readonly name: string; readonly selectors: Tagged[]; } // selectors raw tagged

// 1. untrusted_key_locator
export function untrustedKeyLocator(compact: Uint8Array, bounds?: Bounds): Result<KeyLocator> {
  return trying(() => {
    const seg = parseCompact(compact, bounds ?? MAXIMUM_BOUNDS);
    const { kid } = parseGrantHeader(seg);
    return { keyId: kid, trust: "not_evaluated" as const };
  });
}

// 2. decode_grant
export function decodeGrant(compact: Uint8Array, bounds?: Bounds): Result<GrantDecoded> {
  return trying(() => {
    const seg = parseCompact(compact, bounds ?? MAXIMUM_BOUNDS);
    const { kid } = parseGrantHeader(seg);
    const p = jsonDecode(seg.payloadBytes);
    validateGrantPayload(p);
    if (p.t !== "object") fail("decode_grant: payload object");
    const pobj = p;
    const iss = requireStringOrUri(pobj.v.get("iss"), "iss");
    const jti = requireStringOrUri(pobj.v.get("jti"), "jti");
    const aud = extractAudience(pobj.v.get("aud"));
    const iat = requireInt(pobj.v.get("iat"), "iat");
    const nbf = requireInt(pobj.v.get("nbf"), "nbf");
    const exp = requireInt(pobj.v.get("exp"), "exp");
    if (!(iat < exp) || !(nbf < exp)) fail("grant: times coherent");
    const cnf = pobj.v.get("cnf")!;
    requireObjectExact(cnf, ["jkt"], "grant cnf");
    const jkt = requireB64url32(cnf.v.get("jkt"), "jkt");
    return {
      keyId: kid, issuer: iss, grantId: jti, audiences: aud,
      issuedAt: iat, notBefore: nbf, expiresAt: exp,
      holderThumbprint: jkt, verification: "not_evaluated" as const,
    };
  });
}

// Validate the closed grant payload members + operation structure. operations[] (NOT ba_req).
function validateGrantPayload(p: Tagged): asserts p is Extract<Tagged, { t: "object" }> {
  requireObjectExact(p, ["v", "iss", "jti", "aud", "iat", "nbf", "exp", "cnf", "operations"], "grant payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("grant: v=1");
  const opsV = p.v.get("operations")!;
  if (opsV.t !== "array") fail("grant: operations array");
  if (opsV.v.length < 1 || opsV.v.length > resolve(MAXIMUM_BOUNDS, "operations" as MaximaKey)) fail("grant: operations count");
  const names = new Set<string>();
  for (const op of opsV.v) {
    if (op.t !== "object") fail("grant: operation object");
    const opObj: Extract<Tagged, { t: "object" }> = op;
    requireObjectExact(opObj, ["name", "selectors"], "grant operation");
    const name = requireOperation(opObj.v.get("name"), "operation name");
    if (names.has(name)) fail("grant: operation name unique");
    names.add(name);
    const sels = opObj.v.get("selectors")!;
    if (sels.t !== "array") fail("grant: selectors array");
    if (sels.v.length < 1 || sels.v.length > resolve(MAXIMUM_BOUNDS, "selectors" as MaximaKey)) fail("grant: selectors count");
    for (const s of sels.v) parseSelector(s); // validate each selector's closed shape
  }
}

function extractAudience(v: Tagged | undefined): string[] {
  if (!v) fail("claim: aud");
  if (v.t === "string") {
    const s = utf8Str(v.v);
    if (s.length < 1 || s.length > resolve(MAXIMUM_BOUNDS, "identifier_bytes" as MaximaKey)) fail("claim: aud bytes");
    return [s];
  }
  if (v.t === "array") {
    if (v.v.length < 1 || v.v.length > resolve(MAXIMUM_BOUNDS, "audiences" as MaximaKey)) fail("claim: aud count");
    const seen = new Set<string>();
    const out: string[] = [];
    for (const a of v.v) {
      if (a.t !== "string") fail("claim: aud string");
      const s = utf8Str(a.v);
      if (s.length < 1 || s.length > resolve(MAXIMUM_BOUNDS, "identifier_bytes" as MaximaKey)) fail("claim: aud member bytes");
      if (seen.has(s)) fail("claim: aud unique");
      seen.add(s);
      out.push(s);
    }
    return out;
  }
  fail("claim: aud shape");
}

// 3. decode_proof
export function decodeProof(compact: Uint8Array, bounds?: Bounds): Result<ProofDecoded> {
  return trying(() => {
    const seg = parseCompact(compact, bounds ?? MAXIMUM_BOUNDS);
    const { holderThumbprint } = parseProofHeader(seg);
    const p = jsonDecode(seg.payloadBytes);
    validateProofPayload(p);
    const jti = requireStringOrUri(p.v.get("jti"), "jti");
    return { proofId: jti, holderThumbprint, verification: "not_evaluated" as const };
  });
}

function validateProofPayload(p: Tagged): asserts p is Extract<Tagged, { t: "object" }> {
  // Exact members depend on nonce presence.
  if (p.t !== "object") fail("proof payload: object");
  const hasNonce = p.v.has("nonce");
  const keys = hasNonce
    ? ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req", "nonce"]
    : ["v", "jti", "htm", "htu", "iat", "ba_inv", "ba_op", "ath", "ba_req"];
  requireObjectExact(p, keys, "proof payload");
  const vV = p.v.get("v")!;
  if (vV.t !== "int" || vV.v !== VERSION) fail("proof: v=1");
  requireStringOrUri(p.v.get("jti"), "jti");
  requireMethod(p.v.get("htm"), "htm");
  requireNormalizedUri(p.v.get("htu"), "htu");
  requireInt(p.v.get("iat"), "iat");
  requireUuid(p.v.get("ba_inv"), "ba_inv");
  requireOperation(p.v.get("ba_op"), "ba_op");
  requireB64url32(p.v.get("ath"), "ath");
  requireB64url32(p.v.get("ba_req"), "ba_req");
  if (hasNonce) {
    const n = p.v.get("nonce")!;
    if (n.t !== "string") fail("proof: nonce string");
    if (n.v.length < 1 || n.v.length > resolve(MAXIMUM_BOUNDS, "nonce_bytes" as MaximaKey)) fail("proof: nonce bytes");
  }
}

// 4. verify_grant
export function verifyGrant(compact: Uint8Array, trusted: TrustedIssuer, expected: ExpectedGrant): Result<GrantFacts> {
  return trying(() => {
    assert(trusted.publicKey.length === 32, "verify_grant: issuer key width");
    if (expected.clockSkew < 0 || expected.clockSkew > resolve(MAXIMUM_BOUNDS, "clock_skew" as MaximaKey)) fail("verify_grant: skew");
    const seg = parseCompact(compact, expected.bounds ?? MAXIMUM_BOUNDS);
    const { kid } = parseGrantHeader(seg);
    if (kid !== trusted.keyId) fail("verify_grant: kid exact"); // REQ1-VERIFY-grant-exact
    const p = jsonDecode(seg.payloadBytes);
    validateGrantPayload(p);
    if (p.t !== "object") fail("verify_grant: payload object");
    const pobj = p;
    const iss = requireStringOrUri(pobj.v.get("iss"), "iss");
    if (iss !== expected.issuer) fail("verify_grant: issuer exact");
    const aud = extractAudience(pobj.v.get("aud"));
    if (!aud.includes(expected.audience)) fail("verify_grant: audience match");
    const iat = requireInt(pobj.v.get("iat"), "iat");
    const nbf = requireInt(pobj.v.get("nbf"), "nbf");
    const exp = requireInt(pobj.v.get("exp"), "exp");
    if (!(iat < exp) || !(nbf < exp)) fail("verify_grant: times coherent");
    if (!(iat <= expected.evaluationTime + expected.clockSkew)) fail("verify_grant: iat window");
    if (!(nbf <= expected.evaluationTime + expected.clockSkew)) fail("verify_grant: nbf window");
    if (!(exp > expected.evaluationTime - expected.clockSkew)) fail("verify_grant: exp window");
    const cnf = pobj.v.get("cnf")!;
    if (cnf.t !== "object") fail("verify_grant: cnf object");
    requireObjectExact(cnf, ["jkt"], "grant cnf");
    const jkt = requireB64url32(cnf.v.get("jkt"), "jkt");
    // Ed25519 verify over the signing input.
    const fp = thumbprintRaw(jwkFromPublicKey(trusted.publicKey));
    const key = importPublicKey(trusted.publicKey, utf8Str(base64urlEncode(fp)));
    if (!ed25519Verify(seg.signingInput, seg.signature, key)) fail("verify_grant: signature");
    return {
      version: VERSION, issuer: iss, grantId: requireStringOrUri(p.v.get("jti"), "jti"),
      issuerKeyFingerprint: fp, holderThumbprint: jkt, matchedAudience: expected.audience,
      issuedAt: iat, notBefore: nbf, expiresAt: exp, authorization: "not_evaluated" as const,
    };
  });
}

// Re-export the primitives the public index exposes.
export { jwkEncodePublic, assembleCompact, requestDigest, sha256, base64urlDecode, base64urlEncode };
export { boundsNew, MAXIMUM_BOUNDS };
export type { Bounds, SigningInput };
void ok; void err; void boundsNew; void strUtf8; void _resetCensus;
