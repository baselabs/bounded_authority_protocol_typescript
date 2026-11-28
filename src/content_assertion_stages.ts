import { digestEqual } from "#crypto";
import { isStringOrUri } from "./string_or_uri.js";
import { assert, fail, trying, type Result } from "./error.js";
import { parseCompact, assembleSegments, assembleSegmentsEs256, type CompactSegments, type SigningInput } from "./compact.js";
import { jsonDecode, strUtf8, utf8Str, type Tagged } from "./json.js";
import { jcsEncode } from "./jcs.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { publicKeyThumbprintRaw } from "./jwk.js";
import { acceptablePublicKey, torsionFree, verifyStrict, sha256 } from "./ed25519.js";
import { boundsNew, coerceBounds, resolve, MAXIMUM_BOUNDS, type Bounds } from "./bounds.js";
import type { HistoricalPublicKey } from "./v1.js";
import { redacted, redactedInspection } from "./redact.js";
import { canonicalSignature, es256VerifyStrict } from "./es256.js";
import { checkedPublicKeyThumbprintRaw } from "./ec_jwk.js";
import type { ContentAssertionProducer, ContentAssertionFacts, DecodedContentAssertion, ExpectedContentAssertion } from "./content_assertion.js";

export interface Suite {
  readonly alg: "EdDSA" | "ES256";
  readonly typ: string;
  readonly kind: "content_assertion" | "content_assertion_es256";
  readonly name: string;
  readonly keyBytes: number;
  readonly fingerprint: (raw: Uint8Array) => Uint8Array;
  readonly verify: (input: Uint8Array, sig: Uint8Array, key: Uint8Array) => boolean;
  readonly assemble: typeof assembleSegments;
}

export const EDDSA: Suite = Object.freeze({
  alg: "EdDSA", typ: "ba+content-assertion", kind: "content_assertion",
  name: "ContentAssertion.V1", keyBytes: 32, fingerprint: publicKeyThumbprintRaw,
  verify: verifyStrict, assemble: assembleSegments,
});
export const ES256: Suite = Object.freeze({
  alg: "ES256", typ: "ba+content-assertion-es256", kind: "content_assertion_es256",
  name: "ContentAssertion.ES256.V1", keyBytes: 65, fingerprint: checkedPublicKeyThumbprintRaw,
  verify: es256VerifyStrict, assemble: (input: SigningInput, signature: Uint8Array) => {
    assert(canonicalSignature(signature), "canonical ES256 signature");
    return assembleSegmentsEs256(input, signature);
  },
});
const PAYLOAD = ["v", "jti", "iss", "aud", "sub", "profile", "profile_digest", "content_digest", "gen", "prev", "iat", "nbf", "exp"];
const IDENTIFIERS = ["jti", "iss", "aud", "sub", "profile"] as const;
const DIGESTS = ["profileDigest", "contentDigest", "prev"] as const;
const TIMES = ["iat", "nbf", "exp"] as const;
const CONTENT_PREFIX = strUtf8("BAP1-CONTENT\0");

export function object(x: unknown): asserts x is Record<string, unknown> {
  assert(x !== null && typeof x === "object" && !Array.isArray(x), "object required");
}
export function bytes(x: unknown, n: number): asserts x is Uint8Array {
  assert(x instanceof Uint8Array && x.length === n, "byte width");
}
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
export function bounded(bounds: Bounds | undefined): Bounds {
  const b = coerceBounds(bounds === undefined ? MAXIMUM_BOUNDS : bounds);
  // Normalize and reject unknown override names, including structural hand-built Bounds.
  return boundsNew(Object.fromEntries(b.overrides));
}
export function integer(x: unknown, b: Bounds): asserts x is number {
  assert(typeof x === "number" && Number.isSafeInteger(x) && Math.abs(x) <= resolve(b,"integer_magnitude"), "integer magnitude");
}
export function kid(x: unknown, b: Bounds): asserts x is string {
  assert(typeof x === "string" && x.length > 0 && x.length <= resolve(b,"kid_bytes") && /^[A-Za-z0-9._~-]+$/.test(x), "key identifier");
}
export function identifier(x: unknown, b: Bounds): asserts x is string {
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
export function exact(v: Tagged, members: readonly string[]): Extract<Tagged,{t:"object"}> {
  assert(v.t==="object","JSON object");
  assert(v.v.size===members.length && members.every(k=>v.v.has(k)),"closed members");
  return v;
}
export function string(v: Tagged | undefined): string {
  assert(v?.t==="string","JSON string"); return utf8Str(v.v);
}
export function int(v: Tagged | undefined): number {
  assert(v?.t==="int","JSON integer tag"); return v.v;
}
export function digest(v: Tagged | undefined): Uint8Array {
  assert(v?.t==="string","JSON digest string"); const raw=base64urlDecode(v.v); bytes(raw,32); return raw;
}
export function parseHeader(protectedBytes: Uint8Array, b: Bounds) {
  const h=exact(jsonDecode(protectedBytes,b),["alg","kid","typ"]);
  assert(equal(jcsEncode(h,b),protectedBytes),"canonical header");
  const alg=string(h.v.get("alg")), typ=string(h.v.get("typ")), keyId=string(h.v.get("kid"));
  kid(keyId,b);
  return {alg,typ,keyId};
}

export function admitsSuite(header: ReturnType<typeof parseHeader>, suite: Suite): boolean {
  return header.alg === suite.alg && header.typ === suite.typ;
}

export function parsePayload(payloadBytes: Uint8Array, keyId: string, b: Bounds): ContentAssertionProducer {
  const p=exact(jsonDecode(payloadBytes,b),PAYLOAD);
  assert(int(p.v.get("v"))===1,"version");
  assert(equal(jcsEncode(p,b),payloadBytes),"canonical payload");
  const decoded:ContentAssertionProducer={attestorKeyId:keyId,
    jti:string(p.v.get("jti")),iss:string(p.v.get("iss")),aud:string(p.v.get("aud")),sub:string(p.v.get("sub")),profile:string(p.v.get("profile")),
    profileDigest:digest(p.v.get("profile_digest")),contentDigest:digest(p.v.get("content_digest")),prev:digest(p.v.get("prev")),
    gen:int(p.v.get("gen")),iat:int(p.v.get("iat")),nbf:int(p.v.get("nbf")),exp:int(p.v.get("exp"))};
  validateProducer(decoded,b); return decoded;
}
export function parseFraming(compact: Uint8Array, b: Bounds): CompactSegments {
  assert(compact instanceof Uint8Array,"compact bytes");
  assert(compact.length<=resolve(b,"anchor_bytes"),"assertion byte bound");
  checkSignatureBounds(b);
  return parseCompact(compact,b);
}

function checkSignatureBounds(b: Bounds): void {
  assert(resolve(b,"encoded_segment_bytes") >= 86 && resolve(b,"decoded_segment_bytes") >= 64, "signature segment bound");
}

export function checkAssemblyBounds(headerLength: number, payloadLength: number, b: Bounds): void {
  checkSignatureBounds(b);
  const encodedMaximum = resolve(b, "encoded_segment_bytes");
  const decodedMaximum = resolve(b, "decoded_segment_bytes");
  for (const length of [headerLength, payloadLength]) {
    assert(length <= encodedMaximum, "encoded segment bound");
    // Canonical unpadded base64url uses exactly floor(3 * n / 4) decoded bytes.
    assert(Math.floor(length * 3 / 4) <= decodedMaximum, "decoded segment bound");
  }
  const length = headerLength + payloadLength + 2 + 86;
  assert(length <= resolve(b, "compact_bytes") && length <= resolve(b, "anchor_bytes"), "projected compact bound");
}

function parseSegments(protectedBytes: Uint8Array, payloadBytes: Uint8Array, b: Bounds, suite: Suite): ContentAssertionProducer {
  const header = parseHeader(protectedBytes,b);
  assert(admitsSuite(header,suite),"protected profile");
  return parsePayload(payloadBytes,header.keyId,b);
}

function parse(compact: Uint8Array,b:Bounds,suite:Suite) {
  const seg=parseFraming(compact,b);
  const claims=parseSegments(seg.protectedBytes,seg.payloadBytes,b,suite);
  return {seg,claims};
}
const text=(s:string):Tagged=>({t:"string",v:strUtf8(s)});
const numeric=(n:number):Tagged=>({t:"int",v:n});

export function assertionSigningInput(suite:Suite,p:ContentAssertionProducer,bounds?:Bounds):Result<SigningInput> {
  return trying(()=>{
    const b=bounded(bounds); validateProducer(p,b);
    const header:Tagged={t:"object",v:new Map([["alg",text(suite.alg)],["kid",text(p.attestorKeyId)],["typ",text(suite.typ)]])};
    const payload:Tagged={t:"object",v:new Map<string,Tagged>([
      ["v",numeric(1)],["jti",text(p.jti)],["iss",text(p.iss)],["aud",text(p.aud)],["sub",text(p.sub)],["profile",text(p.profile)],
      ["profile_digest",{t:"string",v:base64urlEncode(p.profileDigest)}],["content_digest",{t:"string",v:base64urlEncode(p.contentDigest)}],
      ["prev",{t:"string",v:base64urlEncode(p.prev)}],["gen",numeric(p.gen)],["iat",numeric(p.iat)],["nbf",numeric(p.nbf)],["exp",numeric(p.exp)]])};
    const h=jcsEncode(header,b),body=jcsEncode(payload,b);
    parseSegments(h,body,b,suite); // Validate number lexemes and JSON limits independently of producer shapes.
    const protectedSegment=base64urlEncode(h),payloadSegment=base64urlEncode(body);
    checkAssemblyBounds(protectedSegment.length, payloadSegment.length, b);
    return {kind:suite.kind,protectedSegment,payloadSegment};
  });
}
export function assembleCompact(suite:Suite,input:SigningInput,signature:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return trying(()=>{
    object(input); assert(input.kind===suite.kind,"signing kind");
    const {kind, protectedSegment, payloadSegment} = input;
    assert(protectedSegment instanceof Uint8Array && payloadSegment instanceof Uint8Array,"signing segments");
    bytes(signature,64); const b=bounded(bounds);
    checkAssemblyBounds(protectedSegment.length, payloadSegment.length, b);
    const assembled=suite.assemble({kind, protectedSegment, payloadSegment},signature); if(!assembled.ok) fail();
    parse(assembled.value,b,suite); return assembled.value;
  });
}
export function decodeAssertion(suite:Suite,compact:Uint8Array,bounds?:Bounds):Result<DecodedContentAssertion> {
  return trying(()=>redactedInspection({version:1 as const,...parse(compact,bounded(bounds),suite).claims,verification:"not_evaluated" as const},suite.name+".DecodedContentAssertion"));
}
export const hashContent = (content: Uint8Array): Uint8Array => sha256(CONTENT_PREFIX, content);

export function contentDigest(content:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return trying(()=>{
    const b=bounded(bounds); assert(content instanceof Uint8Array,"content bytes");
    assert(content.length>=1 && content.length<=resolve(b,"content_bytes"),"content byte bound");
    return hashContent(content);
  });
}
export function assertionDigest(suite:Suite,compact:Uint8Array,bounds?:Bounds):Result<Uint8Array> {
  return trying(()=>{parse(compact,bounded(bounds),suite);return sha256(compact);});
}
export function validateHistoricalKey(key: HistoricalPublicKey, b: Bounds, suite: Suite): void {
  object(key); kid(key.keyId,b); bytes(key.publicKey,suite.keyBytes);
  integer(key.validFrom,b);
  if(key.validBefore!==null) {
    integer(key.validBefore,b); assert(key.validBefore>key.validFrom,"key window");
  }
}

export function admittedFingerprint(suite: Suite, publicKey: Uint8Array): Uint8Array {
  if (suite.alg === "EdDSA") assert(acceptablePublicKey(publicKey) && torsionFree(publicKey),"snapshot key");
  return suite.fingerprint(publicKey);
}

export function keyWindow(p: ContentAssertionProducer, key: HistoricalPublicKey): boolean {
  return p.iat >= key.validFrom && p.nbf >= key.validFrom && (key.validBefore === null || p.exp <= key.validBefore);
}

export function currentWindow(p: ContentAssertionProducer, now: number): "not_yet_valid" | "expired" | null {
  if (now < p.nbf) return "not_yet_valid";
  return now >= p.exp ? "expired" : null;
}

export function assertionFacts(suite: Suite,p: ContentAssertionProducer,compact: Uint8Array,fingerprint: Uint8Array, render = redacted): ContentAssertionFacts {
  const facts:ContentAssertionFacts={version:1,...p,attestorKeyFingerprint:fingerprint,digest:sha256(compact),verification:"signature_and_window",trust:"not_evaluated"};
  const withSuite = suite.alg === "ES256" ? {...facts, suite: "es256" as const} : facts;
  return render(withSuite,suite.name+".ContentAssertionFacts");
}

function expectedContext(e:ExpectedContentAssertion,suite:Suite):Bounds {
  object(e); assert(e.bounds!==undefined,"explicit bounds"); const b=bounded(e.bounds);
  validateHistoricalKey(e.attestor,b,suite);
  for(const name of ["issuer","audience","subject","profile"] as const) identifier(e[name],b);
  bytes(e.profileDigest,32); bytes(e.contentDigest,32); integer(e.now,b); return b;
}

export function verifyAssertion(suite:Suite,compact:Uint8Array,e:ExpectedContentAssertion):Result<ContentAssertionFacts> {
  return trying(()=>{
    const b=expectedContext(e,suite); const {seg,claims:p}=parse(compact,b,suite);
    assert(p.attestorKeyId===e.attestor.keyId,"key identity");
    assert(p.iss===e.issuer && p.aud===e.audience && p.sub===e.subject && p.profile===e.profile,"expected identity");
    assert(digestEqual(p.profileDigest,e.profileDigest) && digestEqual(p.contentDigest,e.contentDigest),"expected digests");
    assert(keyWindow(p,e.attestor),"key window");
    assert(currentWindow(p,e.now)===null,"current window");
    const fingerprint=suite.fingerprint(e.attestor.publicKey);
    assert(suite.verify(seg.signingInput,seg.signature,e.attestor.publicKey),"signature");
    return assertionFacts(suite,p,compact,fingerprint);
  });
}
function validateFacts(f:ContentAssertionFacts,b:Bounds,suite:Suite):void {
  object(f); assert(f.version===1 && f.verification==="signature_and_window" && f.trust==="not_evaluated","facts markers");
  assert(suite.alg === "ES256" ? Object.hasOwn(f, "suite") && f.suite === "es256" : !("suite" in f), "facts suite");
  validateProducer(f,b); bytes(f.attestorKeyFingerprint,32); bytes(f.digest,32);
}
export function verifySuccessor(suite:Suite,predecessor:ContentAssertionFacts,successor:ContentAssertionFacts,bounds:Bounds):Result<void> {
  return trying(()=>{
    assert(bounds!==undefined,"explicit bounds"); const b=bounded(bounds); validateFacts(predecessor,b,suite); validateFacts(successor,b,suite);
    assert(predecessor.iss===successor.iss && predecessor.aud===successor.aud && predecessor.sub===successor.sub && predecessor.profile===successor.profile && digestEqual(predecessor.profileDigest,successor.profileDigest),"successor context");
    assert(predecessor.gen<resolve(b,"integer_magnitude") && successor.gen===predecessor.gen+1,"successor generation");
    assert(digestEqual(successor.prev,predecessor.digest),"predecessor digest");
    assert(successor.iat>=predecessor.iat,"successor issuance time");
    assert(successor.jti!==predecessor.jti,"distinct artifact");
  });
}
