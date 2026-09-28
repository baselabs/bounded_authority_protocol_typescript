import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { inspect } from "node:util";
import * as sdk from "../src/index.js";
import { boundsNew, MAXIMUM_BOUNDS } from "../src/bounds.js";
import { strUtf8, utf8Str } from "../src/json.js";
import type { ContentAssertionProducer, ExpectedContentAssertion, ContentAssertionFacts } from "../src/content_assertion.js";
import type { Result } from "../src/error.js";

const api = () => {
  const ca = (sdk as unknown as { contentAssertion: typeof import("../src/content_assertion.js") }).contentAssertion;
  assert.ok(ca, "public contentAssertion namespace must exist");
  return ca;
};
function value<T>(r: Result<T>): T { assert.equal(r.ok, true); if (!r.ok) throw new Error("unexpected refusal"); return r.value; }
function key() {
  const k = crypto.generateKeyPairSync("ed25519");
  return { privateKey: k.privateKey, publicKey: new Uint8Array(k.publicKey.export({ format: "jwk" }).x ? Buffer.from(k.publicKey.export({ format: "jwk" }).x!, "base64url") : []) };
}
function fixture() {
  const ca = api();
  const k = key();
  const producer: ContentAssertionProducer = {
    attestorKeyId: "assertor-1", jti: "urn:example:assertion:1", iss: "urn:example:issuer",
    aud: "urn:example:audience", sub: "urn:example:lineage", profile: "urn:example:profile",
    profileDigest: new Uint8Array(32).fill(7), contentDigest: value(ca.contentDigest(strUtf8("content"))),
    gen: 1, prev: new Uint8Array(32), iat: 1000, nbf: 1100, exp: 2000,
  };
  const expected: ExpectedContentAssertion = { attestor: { keyId: producer.attestorKeyId, publicKey: k.publicKey, validFrom: 900, validBefore: 2200 },
    issuer: producer.iss, audience: producer.aud, subject: producer.sub, profile: producer.profile,
    profileDigest: producer.profileDigest, contentDigest: producer.contentDigest, now: 1200, bounds: MAXIMUM_BOUNDS };
  const sign = (p: ContentAssertionProducer = producer, priv = k.privateKey) => {
    const si = value(ca.assertionSigningInput(p));
    const sig = new Uint8Array(crypto.sign(null, Buffer.from(`${utf8Str(si.protectedSegment)}.${utf8Str(si.payloadSegment)}`), priv));
    return value(ca.assembleCompact(si, sig));
  };
  const compact = sign();
  return { ca, k, producer, expected, sign, compact };
}
function wire(f: ReturnType<typeof fixture>, change: (h: Record<string, unknown>, p: Record<string, unknown>) => void,
              raw?: (h: string, p: string) => [string, string]) {
  const seg = utf8Str(f.compact).split(".");
  const h = JSON.parse(Buffer.from(seg[0]!, "base64url").toString()) as Record<string, unknown>;
  const p = JSON.parse(Buffer.from(seg[1]!, "base64url").toString()) as Record<string, unknown>;
  change(h, p);
  const canonical = (x: Record<string, unknown>) => JSON.stringify(Object.fromEntries(Object.entries(x).sort(([a],[b]) => a.localeCompare(b))));
  let hs = canonical(h), ps = canonical(p);
  if (raw) [hs, ps] = raw(hs, ps);
  const msg = `${Buffer.from(hs).toString("base64url")}.${Buffer.from(ps).toString("base64url")}`;
  return strUtf8(`${msg}.${crypto.sign(null, Buffer.from(msg), f.k.privateKey).toString("base64url")}`);
}

test("content assertion public namespace, actual Ed25519 issuance, exact digest and redacted facts", () => {
  const f = fixture(); const facts = value(f.ca.verifyAssertion(f.compact, f.expected));
  assert.equal(facts.trust, "not_evaluated"); assert.equal(facts.verification, "signature_and_window");
  assert.equal("authorization" in facts, false); assert.equal("publicKey" in facts, false);
  assert.deepEqual(facts.digest, new Uint8Array(crypto.createHash("sha256").update(f.compact).digest()));
  assert.deepEqual(value(f.ca.assertionDigest(f.compact)), facts.digest);
  assert.equal(inspect(facts).includes(f.producer.iss), false);
  assert.equal(value(f.ca.decodeAssertion(f.compact)).verification, "not_evaluated");
});

test("content digest is exact bytes with its own domain and a tightenable 65536 ceiling", () => {
  const ca=api(); const bytes=new Uint8Array([0,255,1]);
  assert.deepEqual(value(ca.contentDigest(bytes)), new Uint8Array(crypto.createHash("sha256").update(Buffer.from("BAP1-CONTENT\0")).update(bytes).digest()));
  assert.equal(ca.contentDigest(new Uint8Array()).ok,false);
  assert.equal(ca.contentDigest(new Uint8Array(65536)).ok,true);
  assert.equal(ca.contentDigest(new Uint8Array(65537)).ok,false);
  assert.equal(ca.contentDigest(bytes,boundsNew({content_bytes:2})).ok,false);
  assert.equal(ca.contentDigest("bytes" as unknown as Uint8Array).ok,false);
});

test("each expected binding and signature must match, with explicit valid context", () => {
  const f=fixture();
  for (const member of ["issuer","audience","subject","profile"] as const)
    assert.equal(f.ca.verifyAssertion(f.compact,{...f.expected,[member]:"urn:example:wrong"}).ok,false,member);
  for (const member of ["profileDigest","contentDigest"] as const)
    assert.equal(f.ca.verifyAssertion(f.compact,{...f.expected,[member]:new Uint8Array(32).fill(9)}).ok,false,member);
  for (const attestor of [{...f.expected.attestor,keyId:"wrong"},{...f.expected.attestor,publicKey:key().publicKey}])
    assert.equal(f.ca.verifyAssertion(f.compact,{...f.expected,attestor}).ok,false);
  const tampered=f.compact.slice(); const parts=utf8Str(tampered).split(".");
  const signature=Buffer.from(parts[2]!,"base64url"); signature[17]=signature[17]!^1;
  const bad=strUtf8(`${parts[0]}.${parts[1]}.${signature.toString("base64url")}`);
  assert.equal(f.ca.verifyAssertion(bad,f.expected).ok,false);
  assert.equal(f.ca.assertionDigest(bad).ok,true,"digest is not signature verification");
  for (const invalid of [null,{}, {...f.expected, bounds:undefined}, {...f.expected,attestor:null}, {...f.expected,now:1200.5},
    {...f.expected,now:Number.MAX_SAFE_INTEGER+1}, {...f.expected,attestor:{...f.expected.attestor,validFrom:-Number.MAX_SAFE_INTEGER-1}},
    {...f.expected,attestor:{...f.expected.attestor,validBefore:2200.5}}, {...f.expected,contentDigest:new Uint8Array(31)}])
    assert.deepEqual(f.ca.verifyAssertion(f.compact,invalid as ExpectedContentAssertion),{ok:false});
});

test("issuance and validity fit the key window; caller time is half open", () => {
  const f=fixture();
  for (const [now,ok] of [[1100,true],[1999,true],[2000,false],[1099,false]] as const)
    assert.equal(f.ca.verifyAssertion(f.compact,{...f.expected,now}).ok,ok);
  for (const [validFrom,validBefore,ok] of [[1000,2000,true],[1001,2200,false],[900,1999,false],[900,null,true]] as const)
    assert.equal(f.ca.verifyAssertion(f.compact,{...f.expected,attestor:{...f.expected.attestor,validFrom,validBefore}}).ok,ok);
});

test("closed canonical payload/header, integer lexemes, genesis and structural time", () => {
  const f=fixture();
  for (const name of ["v","jti","iss","aud","sub","profile","profile_digest","content_digest","gen","prev","iat","nbf","exp"])
    assert.equal(f.ca.decodeAssertion(wire(f,(_h,p)=>{delete p[name];})).ok,false,name);
  for (const edit of [
    (h:Record<string,unknown>,p:Record<string,unknown>)=>{p.extra=true;},
    (h:Record<string,unknown>)=>{h.extra=true;},
    (h:Record<string,unknown>)=>{h.typ="ba+role-attestation";},
    (h:Record<string,unknown>)=>{h.alg="ES256";},
    (_h:Record<string,unknown>,p:Record<string,unknown>)=>{p.v=2;},
    (_h:Record<string,unknown>,p:Record<string,unknown>)=>{p.aud=[p.aud];},
    (_h:Record<string,unknown>,p:Record<string,unknown>)=>{p.gen=2;},
    (_h:Record<string,unknown>,p:Record<string,unknown>)=>{p.prev=Buffer.alloc(32,1).toString("base64url");},
    (_h:Record<string,unknown>,p:Record<string,unknown>)=>{p.iat=1101;},
    (_h:Record<string,unknown>,p:Record<string,unknown>)=>{p.nbf=2000;},
  ]) assert.equal(f.ca.decodeAssertion(wire(f,edit)).ok,false);
  for (const member of ["profile_digest","content_digest","prev"])
    for(const bad of [Buffer.alloc(31).toString("base64url"), Buffer.alloc(33).toString("base64url"),"=".repeat(43)])
      assert.equal(f.ca.decodeAssertion(wire(f,(_h,p)=>{p[member]=bad;})).ok,false);
  for (const raw of [
    (h:string,p:string):[string,string]=>[" "+h,p],
    (h:string,p:string):[string,string]=>[h," "+p],
    (h:string,p:string):[string,string]=>[h,p.replace('"v":1','"v":1.0')],
    (h:string,p:string):[string,string]=>[h,p.replace('"iat":1000','"iat":1000.5')],
    (h:string,p:string):[string,string]=>[h,p.replace('"gen":1','"gen":1,"gen":1')],
  ]) assert.equal(f.ca.decodeAssertion(wire(f,()=>{},raw)).ok,false);
});

test("producer and assembly are closed under caller bounds and malformed inputs", () => {
  const f=fixture(); const si=value(f.ca.assertionSigningInput(f.producer));
  for(const p of [null,{}, {...f.producer,gen:2}, {...f.producer,gen:0}, {...f.producer,iat:1101},
    {...f.producer,iat:NaN}, {...f.producer,iss:"\ud800"}, {...f.producer,profileDigest:new Uint8Array(31)}])
    assert.equal(f.ca.assertionSigningInput(p as ContentAssertionProducer).ok,false);
  for(const limits of [{anchor_bytes:100},{compact_bytes:100},{encoded_segment_bytes:20},{decoded_segment_bytes:20},
    {json_bytes:20},{jcs_bytes:20},{number_lexeme_bytes:2},{object_members:12},{identifier_bytes:2}])
    assert.equal(f.ca.assertionSigningInput(f.producer,boundsNew(limits)).ok,false,JSON.stringify(limits));
  assert.equal(f.ca.assembleCompact({...si,kind:"grant"},new Uint8Array(64)).ok,false);
  assert.equal(f.ca.assembleCompact(si,new Uint8Array(63)).ok,false);
  assert.equal(f.ca.assembleCompact(si,new Uint8Array(64),boundsNew({anchor_bytes:100})).ok,false);
  assert.equal(f.ca.decodeAssertion(null as unknown as Uint8Array).ok,false);
  assert.equal(f.ca.assertionDigest(strUtf8("invalid")).ok,false);
});

test("successors bind exact context/history; expired predecessors and changed signer remain usable", () => {
  const f=fixture(); const old=value(f.ca.verifyAssertion(f.compact,f.expected)); const k2=key();
  const p2={...f.producer,attestorKeyId:"assertor-2",jti:"urn:example:assertion:2",gen:2,prev:old.digest,iat:2100,nbf:2100,exp:3000,contentDigest:new Uint8Array(32).fill(11)};
  const next=value(f.ca.verifyAssertion(f.sign(p2,k2.privateKey),{...f.expected,contentDigest:p2.contentDigest,now:2200,attestor:{keyId:p2.attestorKeyId,publicKey:k2.publicKey,validFrom:2050,validBefore:3100}}));
  assert.deepEqual(f.ca.verifySuccessor(old,next,MAXIMUM_BOUNDS),{ok:true,value:undefined});
  for(const changes of [{iss:"urn:other"},{aud:"urn:other"},{sub:"urn:other"},{profile:"urn:other"},
    {profileDigest:new Uint8Array(32)},{gen:3},{prev:new Uint8Array(32).fill(9)},{iat:999,nbf:999},{jti:old.jti},
    {trust:"evaluated"},{verification:"not_evaluated"},{digest:new Uint8Array(31)},{attestorKeyFingerprint:new Uint8Array(31)},
    {version:2},{gen:1},{iat:NaN},{attestorKeyId:""}])
    assert.equal(f.ca.verifySuccessor(old,{...next,...changes} as ContentAssertionFacts,MAXIMUM_BOUNDS).ok,false,JSON.stringify(changes));
  assert.equal(f.ca.verifySuccessor(value(f.ca.decodeAssertion(f.compact)) as unknown as ContentAssertionFacts,next,MAXIMUM_BOUNDS).ok,false);
  assert.equal(f.ca.verifySuccessor(null as unknown as ContentAssertionFacts,next,MAXIMUM_BOUNDS).ok,false);
});

test("existing profile surfaces reject content assertion bytes and generic assembler refuses its kind",()=>{
  const f=fixture();
  assert.equal(sdk.decodeGrant(f.compact).ok,false);
  assert.equal(sdk.v2.decodeGrant(f.compact).ok,false);
  assert.equal(sdk.v3.decodeGrant(f.compact).ok,false);
  assert.equal(sdk.roleAttestation.decodeAttestation(f.compact).ok,false);
  const si=value(f.ca.assertionSigningInput(f.producer));
  assert.equal(sdk.assembleCompact(si,new Uint8Array(64)).ok,false);
});
