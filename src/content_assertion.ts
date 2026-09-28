// bap-content-assertion/1, specified by BAP ADR 0037 and its normative profile.
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

export interface ContentAssertionProducer {
  readonly attestorKeyId: string;
  readonly jti: string;
  readonly iss: string;
  readonly aud: string;
  readonly sub: string;
  readonly profile: string;
  readonly profileDigest: Uint8Array;
  readonly contentDigest: Uint8Array;
  readonly gen: number;
  readonly prev: Uint8Array;
  readonly iat: number;
  readonly nbf: number;
  readonly exp: number;
}
export interface ExpectedContentAssertion {
  readonly attestor: HistoricalPublicKey;
  readonly issuer: string;
  readonly audience: string;
  readonly subject: string;
  readonly profile: string;
  readonly profileDigest: Uint8Array;
  readonly contentDigest: Uint8Array;
  readonly now: number;
  readonly bounds: Bounds;
}
export interface DecodedContentAssertion extends ContentAssertionProducer {
  readonly version: 1;
  readonly verification: "not_evaluated";
}
export interface ContentAssertionFacts extends ContentAssertionProducer {
  readonly version: 1;
  readonly attestorKeyFingerprint: Uint8Array;
  readonly digest: Uint8Array;
  readonly verification: "signature_and_window";
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
export function assembleCompact(input:SigningInput,signature:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return trying(()=>{
    object(input); assert(input.kind===KIND,"signing kind");
    assert(input.protectedSegment instanceof Uint8Array && input.payloadSegment instanceof Uint8Array,"signing segments");
    bytes(signature,64); const b=bounded(bounds);
    const assembled=assembleSegments(input,signature); if(!assembled.ok) fail();
    parse(assembled.value,b); return assembled.value;
  });
}
export function decodeAssertion(compact:Uint8Array,bounds?:Bounds):Result<DecodedContentAssertion> {
  return trying(()=>({version:1,...parse(compact,bounded(bounds)).claims,verification:"not_evaluated"}));
}
export function contentDigest(content:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return trying(()=>{
    const b=bounded(bounds); assert(content instanceof Uint8Array,"content bytes");
    assert(content.length>=1 && content.length<=resolve(b,"content_bytes"),"content byte bound");
    return sha256(CONTENT_PREFIX,content);
  });
}
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
    Object.defineProperty(facts,Symbol.for("nodejs.util.inspect.custom"),{value:()=>"ContentAssertionFacts<redacted>",enumerable:false});
    return facts;
  });
}
function validateFacts(f:ContentAssertionFacts,b:Bounds):void {
  object(f); assert(f.version===1 && f.verification==="signature_and_window" && f.trust==="not_evaluated","facts markers");
  validateProducer(f,b); bytes(f.attestorKeyFingerprint,32); bytes(f.digest,32);
}
// Facts are caller-provenanced values. This comparison is not signature verification or present-time admission.
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
