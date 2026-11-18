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
import { isStringOrUri } from "./string_or_uri.js";
import { assert, fail, trying, type Result } from "./error.js";
import { parseCompact, assembleSegments, type SigningInput } from "./compact.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "./json.js";
import { jcsEncode } from "./jcs.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { publicKeyThumbprintRaw } from "./jwk.js";
import { importPublicKey, ed25519Verify, sha256 } from "./ed25519.js";
import { boundsNew, coerceBounds, resolve, MAXIMUM_BOUNDS, type Bounds } from "./bounds.js";
import type { HistoricalPublicKey } from "./v1.js";
import { redacted, redactedInspection } from "./redact.js";

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

const PAYLOAD = ["v", "jti", "iss", "aud", "sub", "profile", "profile_digest", "content_digest", "gen", "prev", "iat", "nbf", "exp"];
const IDENTIFIERS = ["jti", "iss", "aud", "sub", "profile"] as const;
const DIGESTS = ["profileDigest", "contentDigest", "prev"] as const;
const TIMES = ["iat", "nbf", "exp"] as const;
const TYP = "ba+content-assertion";
const KIND = "content_assertion";
const CONTENT_PREFIX = strUtf8("BAP1-CONTENT\0");

function object(x: unknown): asserts x is Record<string, unknown> {
  assert(x !== null && typeof x === "object" && !Array.isArray(x), "object required");
}
function bytes(x: unknown, n: number): asserts x is Uint8Array {
  assert(x instanceof Uint8Array && x.length === n, "byte width");
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
function bounded(bounds: Bounds | undefined): Bounds {
  const b = coerceBounds(bounds === undefined ? MAXIMUM_BOUNDS : bounds);
  // Normalize and reject unknown override names, including structural hand-built Bounds.
  return boundsNew(Object.fromEntries(b.overrides));
}
function integer(x: unknown, b: Bounds): asserts x is number {
  assert(typeof x === "number" && Number.isSafeInteger(x) && Math.abs(x) <= resolve(b,"integer_magnitude"), "integer magnitude");
}
function kid(x: unknown, b: Bounds): asserts x is string {
  assert(typeof x === "string" && x.length > 0 && x.length <= resolve(b,"kid_bytes") && /^[A-Za-z0-9._~-]+$/.test(x), "key identifier");
}
function identifier(x: unknown, b: Bounds): asserts x is string {
  assert(typeof x === "string", "identifier string");
  assert(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(x), "Unicode scalar string");
  const n = strUtf8(x).length;
  assert(n > 0 && n <= resolve(b,"identifier_bytes"), "identifier bound");
  assert(isStringOrUri(x), "StringOrURI grammar");
}
function validateProducer(p: ContentAssertionProducer, b: Bounds): void {
  object(p); kid(p.attestorKeyId,b);
  for(const name of IDENTIFIERS) identifier(p[name],b);
  for(const name of DIGESTS) bytes(p[name],32);
  integer(p.gen,b); assert(p.gen>=1,"generation positive");
  for(const name of TIMES) integer(p[name],b);
  assert(p.iat<=p.nbf && p.nbf<p.exp,"structural time");
  assert((p.gen===1) === p.prev.every(x=>x===0),"genesis pairing");
}
function exact(v: Tagged, members: string[]): Extract<Tagged,{t:"object"}> {
  assert(v.t==="object","JSON object");
  assert(v.v.size===members.length && members.every(k=>v.v.has(k)),"closed members");
  return v;
}
function string(v: Tagged | undefined): string {
  assert(v?.t==="string","JSON string"); return utf8Str(v.v);
}
function int(v: Tagged | undefined): number {
  assert(v?.t==="int","JSON integer tag"); return v.v;
}
function digest(v: Tagged | undefined): Uint8Array {
  assert(v?.t==="string","JSON digest string"); const raw=base64urlDecode(v.v); bytes(raw,32); return raw;
}
function parseSegments(protectedBytes: Uint8Array, payloadBytes: Uint8Array, b: Bounds): ContentAssertionProducer {
  const h=exact(jsonDecode(protectedBytes,b),["alg","kid","typ"]);
  assert(string(h.v.get("alg"))==="EdDSA" && string(h.v.get("typ"))===TYP,"protected profile");
  assert(equal(jcsEncode(h,b),protectedBytes),"canonical header");
  const p=exact(jsonDecode(payloadBytes,b),PAYLOAD);
  assert(int(p.v.get("v"))===1,"version");
  assert(equal(jcsEncode(p,b),payloadBytes),"canonical payload");
  const decoded:ContentAssertionProducer={attestorKeyId:string(h.v.get("kid")),
    jti:string(p.v.get("jti")),iss:string(p.v.get("iss")),aud:string(p.v.get("aud")),sub:string(p.v.get("sub")),profile:string(p.v.get("profile")),
    profileDigest:digest(p.v.get("profile_digest")),contentDigest:digest(p.v.get("content_digest")),prev:digest(p.v.get("prev")),
    gen:int(p.v.get("gen")),iat:int(p.v.get("iat")),nbf:int(p.v.get("nbf")),exp:int(p.v.get("exp"))};
  validateProducer(decoded,b); return decoded;
}
function parse(compact: Uint8Array,b:Bounds) {
  assert(compact instanceof Uint8Array,"compact bytes");
  assert(compact.length<=resolve(b,"anchor_bytes"),"assertion byte bound");
  const seg=parseCompact(compact,b);
  const claims=parseSegments(seg.protectedBytes,seg.payloadBytes,b);
  return {seg,claims};
}
const text=(s:string):Tagged=>({t:"string",v:strUtf8(s)});
const numeric=(n:number):Tagged=>({t:"int",v:n});

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
  return trying(()=>{
    const b=bounded(bounds); validateProducer(p,b);
    const header:Tagged={t:"object",v:new Map([["alg",text("EdDSA")],["kid",text(p.attestorKeyId)],["typ",text(TYP)]])};
    const payload:Tagged={t:"object",v:new Map<string,Tagged>([
      ["v",numeric(1)],["jti",text(p.jti)],["iss",text(p.iss)],["aud",text(p.aud)],["sub",text(p.sub)],["profile",text(p.profile)],
      ["profile_digest",{t:"string",v:base64urlEncode(p.profileDigest)}],["content_digest",{t:"string",v:base64urlEncode(p.contentDigest)}],
      ["prev",{t:"string",v:base64urlEncode(p.prev)}],["gen",numeric(p.gen)],["iat",numeric(p.iat)],["nbf",numeric(p.nbf)],["exp",numeric(p.exp)]])};
    const h=jcsEncode(header,b),body=jcsEncode(payload,b);
    parseSegments(h,body,b); // Validate emitted number lexemes and JSON limits independently of producer shapes.
    const protectedSegment=base64urlEncode(h),payloadSegment=base64urlEncode(body);
    for(const segment of [protectedSegment,payloadSegment]) assert(segment.length<=resolve(b,"encoded_segment_bytes"),"encoded segment bound");
    for(const segment of [h,body]) assert(segment.length<=resolve(b,"decoded_segment_bytes"),"decoded segment bound");
    const length=protectedSegment.length+payloadSegment.length+2+86;
    assert(length<=resolve(b,"compact_bytes") && length<=resolve(b,"anchor_bytes"),"projected compact bound");
    return {kind:KIND,protectedSegment,payloadSegment};
  });
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
  return trying(()=>{
    object(input); assert(input.kind===KIND,"signing kind");
    assert(input.protectedSegment instanceof Uint8Array && input.payloadSegment instanceof Uint8Array,"signing segments");
    bytes(signature,64); const b=bounded(bounds);
    const assembled=assembleSegments(input,signature); if(!assembled.ok) fail();
    parse(assembled.value,b); return assembled.value;
  });
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
  return trying(()=>redactedInspection({version:1 as const,...parse(compact,bounded(bounds)).claims,verification:"not_evaluated" as const},"ContentAssertion.V1.DecodedContentAssertion"));
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
  return trying(()=>{
    const b=bounded(bounds); assert(content instanceof Uint8Array,"content bytes");
    assert(content.length>=1 && content.length<=resolve(b,"content_bytes"),"content byte bound");
    return sha256(CONTENT_PREFIX,content);
  });
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
  return trying(()=>{parse(compact,bounded(bounds));return sha256(compact);});
}
function expectedContext(e:ExpectedContentAssertion):Bounds {
  object(e); assert(e.bounds!==undefined,"explicit bounds"); const b=bounded(e.bounds);
  object(e.attestor); kid(e.attestor.keyId,b); bytes(e.attestor.publicKey,32);
  integer(e.attestor.validFrom,b);
  if(e.attestor.validBefore!==null) {integer(e.attestor.validBefore,b);assert(e.attestor.validBefore>e.attestor.validFrom,"key window");}
  for(const name of ["issuer","audience","subject","profile"] as const) identifier(e[name],b);
  bytes(e.profileDigest,32); bytes(e.contentDigest,32); integer(e.now,b); return b;
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
  return trying(()=>{
    const b=expectedContext(e); const {seg,claims:p}=parse(compact,b);
    assert(p.attestorKeyId===e.attestor.keyId,"key identity");
    assert(p.iss===e.issuer && p.aud===e.audience && p.sub===e.subject && p.profile===e.profile,"expected identity");
    assert(equal(p.profileDigest,e.profileDigest) && equal(p.contentDigest,e.contentDigest),"expected digests");
    assert(p.iat>=e.attestor.validFrom && p.nbf>=e.attestor.validFrom,"key lower bound");
    assert(e.attestor.validBefore===null || p.exp<=e.attestor.validBefore,"key upper bound");
    assert(p.nbf<=e.now && e.now<p.exp,"current window");
    const fingerprint=publicKeyThumbprintRaw(e.attestor.publicKey);
    const key=importPublicKey(e.attestor.publicKey,utf8Str(base64urlEncode(fingerprint)));
    assert(ed25519Verify(seg.signingInput,seg.signature,key),"signature");
    const facts:ContentAssertionFacts={version:1,...p,attestorKeyFingerprint:fingerprint,digest:sha256(compact),verification:"signature_and_window",trust:"not_evaluated"};
    return redacted(facts,"ContentAssertion.V1.ContentAssertionFacts");
  });
}
function validateFacts(f:ContentAssertionFacts,b:Bounds):void {
  object(f); assert(f.version===1 && f.verification==="signature_and_window" && f.trust==="not_evaluated","facts markers");
  validateProducer(f,b); bytes(f.attestorKeyFingerprint,32); bytes(f.digest,32);
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
  return trying(()=>{
    assert(bounds!==undefined,"explicit bounds"); const b=bounded(bounds); validateFacts(predecessor,b); validateFacts(successor,b);
    assert(predecessor.iss===successor.iss && predecessor.aud===successor.aud && predecessor.sub===successor.sub && predecessor.profile===successor.profile && equal(predecessor.profileDigest,successor.profileDigest),"successor context");
    assert(predecessor.gen<resolve(b,"integer_magnitude") && successor.gen===predecessor.gen+1,"successor generation");
    assert(equal(successor.prev,predecessor.digest),"predecessor digest");
    assert(successor.iat>=predecessor.iat,"successor issuance time");
    assert(successor.jti!==predecessor.jti,"distinct artifact");
  });
}
