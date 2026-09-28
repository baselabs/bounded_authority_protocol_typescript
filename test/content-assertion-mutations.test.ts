// Real source mutation checks, compiled in memory: no live source edits or checkout copies.
import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { readFileSync } from "node:fs";
import ts from "typescript";
import * as original from "../src/content_assertion.js";
import { MAXIMUM_BOUNDS } from "../src/bounds.js";
import { strUtf8, utf8Str } from "../src/json.js";
import type { ContentAssertionFacts, ContentAssertionProducer } from "../src/content_assertion.js";
import type { Result } from "../src/error.js";

function take<T>(r:Result<T>):T { assert.equal(r.ok,true); if(!r.ok) throw new Error("fixture rejection"); return r.value; }
const k=crypto.generateKeyPairSync("ed25519");
const publicKey=new Uint8Array(Buffer.from(k.publicKey.export({format:"jwk"}).x!,"base64url"));
const p:ContentAssertionProducer={attestorKeyId:"assertor",jti:"urn:example:a",iss:"urn:example:i",aud:"urn:example:a",sub:"urn:example:s",profile:"urn:example:p",
  profileDigest:new Uint8Array(32).fill(1),contentDigest:new Uint8Array(32).fill(2),gen:1,prev:new Uint8Array(32),iat:1000,nbf:1100,exp:2000};
const expected={attestor:{keyId:p.attestorKeyId,publicKey,validFrom:900,validBefore:2200},issuer:p.iss,audience:p.aud,subject:p.sub,profile:p.profile,
  profileDigest:p.profileDigest,contentDigest:p.contentDigest,now:1200,bounds:MAXIMUM_BOUNDS};
function sign(producer=p):Uint8Array {
  const si=take(original.assertionSigningInput(producer));
  const message=Buffer.from(`${utf8Str(si.protectedSegment)}.${utf8Str(si.payloadSegment)}`);
  return take(original.assembleCompact(si,new Uint8Array(crypto.sign(null,message,k.privateKey))));
}
const compact=sign();
const old=take(original.verifyAssertion(compact,expected));
const next=take(original.verifyAssertion(sign({...p,jti:"urn:example:b",gen:2,prev:old.digest,iat:1200,nbf:1200}),expected));
function rewrite(edit:(header:Record<string,unknown>,payload:Record<string,unknown>)=>void, leading:"header"|"payload"|null=null):Uint8Array {
  const parts=utf8Str(compact).split(".");
  const h=JSON.parse(Buffer.from(parts[0]!,"base64url").toString()) as Record<string,unknown>;
  const payload=JSON.parse(Buffer.from(parts[1]!,"base64url").toString()) as Record<string,unknown>;
  edit(h,payload);
  const canon=(x:Record<string,unknown>)=>JSON.stringify(Object.fromEntries(Object.entries(x).sort()));
  const msg=`${Buffer.from((leading==="header"?" ":"")+canon(h)).toString("base64url")}.${Buffer.from((leading==="payload"?" ":"")+canon(payload)).toString("base64url")}`;
  return strUtf8(`${msg}.${crypto.sign(null,Buffer.from(msg),k.privateKey).toString("base64url")}`);
}
const sourceUrl=new URL("../src/content_assertion.ts",import.meta.url);
const source=readFileSync(sourceUrl,"utf8");
async function mutant(needle:string,replacement:string):Promise<typeof original> {
  assert.equal(source.split(needle).length-1,1,"mutation must match exactly once");
  const modified=source.replace(needle,replacement).replace(/from "(\.\/[^" ]+)\.js"/g,(_m,s:string)=>`from "${new URL(s+".ts",sourceUrl).href}"`);
  const emitted=ts.transpileModule(modified,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  return await import(`data:text/javascript;base64,${Buffer.from(emitted).toString("base64")}`) as typeof original;
}
interface Mutation { name:string; needle:string; replacement?:string; rejected:(api:typeof original)=>boolean; }
const cases:Mutation[]=[
 {name:"expected identities",needle:'assert(p.iss===e.issuer && p.aud===e.audience && p.sub===e.subject && p.profile===e.profile,"expected identity");',rejected:a=>!a.verifyAssertion(compact,{...expected,audience:"urn:example:wrong"}).ok},
 {name:"expected content digest",needle:'assert(equal(p.profileDigest,e.profileDigest) && equal(p.contentDigest,e.contentDigest),"expected digests");',rejected:a=>!a.verifyAssertion(compact,{...expected,contentDigest:new Uint8Array(32)}).ok},
 {name:"expected key ID",needle:'assert(p.attestorKeyId===e.attestor.keyId,"key identity");',rejected:a=>!a.verifyAssertion(compact,{...expected,attestor:{...expected.attestor,keyId:"wrong"}}).ok},
 {name:"signature",needle:'assert(ed25519Verify(seg.signingInput,seg.signature,key),"signature");',rejected:a=>{const parts=utf8Str(compact).split(".");const sig=Buffer.from(parts[2]!,"base64url");sig[20]=sig[20]!^1;return !a.verifyAssertion(strUtf8(`${parts[0]}.${parts[1]}.${sig.toString("base64url")}`),expected).ok;}},
 {name:"key lower containment",needle:'assert(p.iat>=e.attestor.validFrom && p.nbf>=e.attestor.validFrom,"key lower bound");',rejected:a=>!a.verifyAssertion(compact,{...expected,attestor:{...expected.attestor,validFrom:1001}}).ok},
 {name:"key upper containment",needle:'assert(e.attestor.validBefore===null || p.exp<=e.attestor.validBefore,"key upper bound");',rejected:a=>!a.verifyAssertion(compact,{...expected,attestor:{...expected.attestor,validBefore:1999}}).ok},
 {name:"current expiry",needle:'assert(p.nbf<=e.now && e.now<p.exp,"current window");',rejected:a=>!a.verifyAssertion(compact,{...expected,now:2000}).ok},
 {name:"time scalar integer",needle:'assert(typeof x === "number" && Number.isSafeInteger(x) && Math.abs(x) <= resolve(b,"integer_magnitude"), "integer magnitude");',replacement:'assert(typeof x === "number", "number only");',rejected:a=>!a.verifyAssertion(compact,{...expected,now:1200.5}).ok},
 {name:"genesis",needle:'assert((p.gen===1) === p.prev.every(x=>x===0),"genesis pairing");',rejected:a=>!a.decodeAssertion(rewrite((_h,payload)=>{payload.gen=2;})).ok},
 {name:"structural issuance time",needle:'assert(p.iat<=p.nbf && p.nbf<p.exp,"structural time");',rejected:a=>!a.decodeAssertion(rewrite((_h,payload)=>{payload.iat=1101;})).ok},
 {name:"closed members",needle:'assert(v.v.size===members.length && members.every(k=>v.v.has(k)),"closed members");',rejected:a=>!a.decodeAssertion(rewrite((_h,payload)=>{payload.extra=true;})).ok},
 {name:"canonical header",needle:'assert(equal(jcsEncode(h,b),protectedBytes),"canonical header");',rejected:a=>!a.decodeAssertion(rewrite(()=>{},"header")).ok},
 {name:"canonical payload",needle:'assert(equal(jcsEncode(p,b),payloadBytes),"canonical payload");',rejected:a=>!a.decodeAssertion(rewrite(()=>{},"payload")).ok},
 {name:"protected profile",needle:'assert(string(h.v.get("alg"))==="EdDSA" && string(h.v.get("typ"))===TYP,"protected profile");',rejected:a=>!a.decodeAssertion(rewrite(h=>{h.typ="ba+role-attestation";})).ok},
 {name:"content byte ceiling",needle:'assert(content.length>=1 && content.length<=resolve(b,"content_bytes"),"content byte bound");',rejected:a=>!a.contentDigest(new Uint8Array(65537)).ok},
 {name:"successor markers",needle:'assert(f.version===1 && f.verification==="signature_and_window" && f.trust==="not_evaluated","facts markers");',rejected:a=>!a.verifySuccessor(old,{...next,trust:"evaluated"} as unknown as ContentAssertionFacts,MAXIMUM_BOUNDS).ok},
 {name:"successor context",needle:'assert(predecessor.iss===successor.iss && predecessor.aud===successor.aud && predecessor.sub===successor.sub && predecessor.profile===successor.profile && equal(predecessor.profileDigest,successor.profileDigest),"successor context");',rejected:a=>!a.verifySuccessor(old,{...next,aud:"urn:other"},MAXIMUM_BOUNDS).ok},
 {name:"successor generation",needle:'assert(predecessor.gen<resolve(b,"integer_magnitude") && successor.gen===predecessor.gen+1,"successor generation");',rejected:a=>!a.verifySuccessor(old,{...next,gen:3},MAXIMUM_BOUNDS).ok},
 {name:"successor predecessor",needle:'assert(equal(successor.prev,predecessor.digest),"predecessor digest");',rejected:a=>!a.verifySuccessor(old,{...next,prev:new Uint8Array(32).fill(9)},MAXIMUM_BOUNDS).ok},
 {name:"successor issuance time",needle:'assert(successor.iat>=predecessor.iat,"successor issuance time");',rejected:a=>!a.verifySuccessor(old,{...next,iat:999},MAXIMUM_BOUNDS).ok},
 {name:"successor artifact identity",needle:'assert(successor.jti!==predecessor.jti,"distinct artifact");',rejected:a=>!a.verifySuccessor(old,{...next,jti:old.jti},MAXIMUM_BOUNDS).ok},
];
for(const c of cases) test(`content assertion mutation killed: ${c.name}`,async()=>{
  assert.equal(c.rejected(original),true,"unmodified source must refuse");
  const modified=await mutant(c.needle,c.replacement??"");
  // The same behavioral refusal assertion MUST turn red on the named mutation.
  assert.throws(()=>assert.equal(c.rejected(modified),true),assert.AssertionError);
});
