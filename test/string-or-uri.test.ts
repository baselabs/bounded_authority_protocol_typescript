import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as v1 from "../src/v1.js";
import * as v2 from "../src/v2.js";
import * as v3 from "../src/v3.js";
import * as role from "../src/role_attestation.js";
import * as content from "../src/content_assertion.js";
import { strUtf8, utf8Str } from "../src/json.js";
import { uriNormalize } from "../src/uri.js";
import { MAXIMUM_BOUNDS, type Bounds } from "../src/bounds.js";
import type { SigningInput } from "../src/compact.js";
import type { Result } from "../src/error.js";

function take<T>(r: Result<T>): T { assert.ok(r.ok); return r.value; }
const ed = crypto.generateKeyPairSync("ed25519");
const ec = crypto.generateKeyPairSync("ec", {namedCurve:"prime256v1"});
const pub = new Uint8Array(Buffer.from(ed.publicKey.export({format:"jwk"}).x!,"base64url"));
const p: content.ContentAssertionProducer = {attestorKeyId:"attestor",jti:"urn:x#a",iss:"issuer",aud:"audience",sub:"subject",profile:"profile",profileDigest:new Uint8Array(32).fill(1),contentDigest:new Uint8Array(32).fill(2),gen:1,prev:new Uint8Array(32),iat:100,nbf:110,exp:200};
const grant: v1.GrantProducer = {keyId:"issuer",issuer:"issuer",grantId:"urn:x#a",audiences:["audience"],issuedAt:100,notBefore:110,expiresAt:200,holderThumbprint:Buffer.alloc(32,1).toString("base64url"),operations:[{name:"read",selectors:["all"]}]};
const rp: role.AttestationProducer = {keyId:"attestor",jti:"urn:x#a",subjectKeyId:"subject",subjectPublicKey:pub,role:"issuer",notBefore:110,expiresAt:200};
const profiles = [
  {name:"v1",produce:(id:string)=>v1.grantSigningInput({...grant,grantId:id}),decode:v1.decodeGrant},
  {name:"v2",produce:(id:string)=>v2.grantSigningInput({...grant,grantId:id}),decode:v2.decodeGrant},
  {name:"v3",produce:(id:string)=>v3.grantSigningInput({...grant,grantId:id}),decode:v3.decodeGrant},
  {name:"role",produce:(id:string)=>role.attestationSigningInput({...rp,jti:id}),decode:role.decodeAttestation},
  {name:"content",produce:(id:string)=>content.assertionSigningInput({...p,jti:id}),decode:content.decodeAssertion},
];
function signed(input: SigningInput, id: string, es256: boolean): Uint8Array {
  const payload = JSON.parse(Buffer.from(utf8Str(input.payloadSegment),"base64url").toString()) as Record<string, unknown>;
  payload.jti=id;
  const body=JSON.stringify(Object.fromEntries(Object.entries(payload).sort(([a],[b])=>a<b?-1:a>b?1:0)));
  const message=`${utf8Str(input.protectedSegment)}.${Buffer.from(body).toString("base64url")}`;
  let signature=es256?crypto.sign("sha256",Buffer.from(message),{key:ec.privateKey,dsaEncoding:"ieee-p1363"}):crypto.sign(null,Buffer.from(message),ed.privateKey);
  if(es256){
    const n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const s=BigInt(`0x${signature.subarray(32).toString("hex")}`);
    if(s>n/2n) signature=Buffer.concat([signature.subarray(0,32),Buffer.from((n-s).toString(16).padStart(64,"0"),"hex")]);
  }
  return strUtf8(`${message}.${signature.toString("base64url")}`);
}
const validIpv6Uris=["http://[::]/x","http://[::1]/x","http://[2001:db8::1]/x","http://[1:2:3:4:5:6:7:8]/x","http://[::ffff:192.0.2.1]/x","http://[1:2:3:4:5:6:192.0.2.1]/x"];
const invalidIpv6Uris=["http://[abc]/x","http://[1:2:3:4:5:6:7]/x","http://[1:2:3:4:5:6:7:8:9]/x","http://[1::2::3]/x","http://[12345::1]/x","http://[1:2:3:4:5:6:7::8]/x","http://[::ffff:192.0.2.999]/x","http://[::ffff:192.00.2.1]/x","http://[192.0.2.1::]/x"];
for(const profile of profiles) {
  test(`${profile.name} producer requires structurally valid IPv6 literals`,()=>{
    for(const id of validIpv6Uris) assert.equal(profile.produce(id).ok,true,id);
    for(const id of invalidIpv6Uris) assert.equal(profile.produce(id).ok,false,id);
  });
  test(`${profile.name} decoder enforces IPv6 structure on real signatures`,()=>{
    const input=take(profile.produce("urn:x#a"));
    for(const id of validIpv6Uris) assert.equal(profile.decode(signed(input,id,profile.name==="v3")).ok,true,id);
    for(const id of invalidIpv6Uris) assert.equal(profile.decode(signed(input,id,profile.name==="v3")).ok,false,id);
  });
  test(`${profile.name} producer preserves valid URI components and rejects malformed ones`,()=>{
    for(const id of ["urn:x#a","urn:x%23a%23b","urn:x%5Bfoo%5D","http://[::1]/x?q#f","bare[brackets]#twice#","http://user@host","http://u%5Bs%5D@host","http://user@[::1]"])
      assert.equal(profile.produce(id).ok,true,id);
    for(const id of ["urn:x#a#b","urn:x[foo]","urn:x?q[foo]","urn:x#f[oo]","http://[::1]/x[foo]","http://u[s]@host","http://u[@host","http://u]@host"])
      assert.equal(profile.produce(id).ok,false,id);
  });
  test(`${profile.name} decoder rejects independently signed malformed URI claims`,()=>{
    const input=take(profile.produce("urn:x#a"));
    for(const [id,accepted] of [["urn:x#a",true],["http://user@host",true],["http://u%5Bs%5D@host",true],["http://user@[::1]",true],["urn:x#a#b",false],["urn:x[foo]",false],["http://u[s]@host",false],["http://u[@host",false],["http://u]@host",false]] as const)
      assert.equal(profile.decode(signed(input,id,profile.name==="v3")).ok,accepted,id);
  });
}

test("content bounds reject malformed structural objects without leaking native exceptions",()=>{
  const valid= signed(take(content.assertionSigningInput(p)),p.jti,false);
  for(const malformed of [null,{}, {maximum:{},overrides:[]}, {maximum:{},overrides:new Map([[Symbol("unknown"),0]])}, {maximum:{},overrides:new Map([["unknown",1]])}]) {
    const b=malformed as Bounds;
    assert.deepEqual(content.assertionSigningInput(p,b),{ok:false});
    assert.deepEqual(content.decodeAssertion(valid,b),{ok:false});
    assert.deepEqual(content.assertionDigest(valid,b),{ok:false});
    assert.deepEqual(content.contentDigest(strUtf8("bytes"),b),{ok:false});
  }
  assert.equal(content.decodeAssertion(valid,MAXIMUM_BOUNDS).ok,true);
});

test("target-URI normalization retains its existing reference group-shape behavior",()=>{
  for(const input of ["https://[::1]/x","https://[2001:db8::1]/x","https://[::ffff:192.0.2.1]/x","https://[1:2:3:4:5:6:192.0.2.1]/x"])
    assert.equal(utf8Str(take(uriNormalize(strUtf8(input)))),input);
  for(const input of ["https://[abc]/x","https://[1::2::3]/x","https://[12345::1]/x"])
    assert.deepEqual(uriNormalize(strUtf8(input)),{ok:false});
  // OBSERVED reference V1.Uri.normalize accepts this per-side group shape, while
  // V1.StringOrUri rejects it. Preserve the transport profile's existing behavior.
  const legacy="https://[192.0.2.1::]/x";
  assert.equal(utf8Str(take(uriNormalize(strUtf8(legacy)))),legacy);
});
