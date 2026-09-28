// Compile source mutations in memory; never alter the working checkout.
import test from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { readFileSync } from "node:fs";
import ts from "typescript";
import * as content from "../src/content_assertion.js";
import { strUtf8, utf8Str } from "../src/json.js";
import type { Result } from "../src/error.js";

function take<T>(r:Result<T>):T { assert.ok(r.ok); return r.value; }
const key=crypto.generateKeyPairSync("ed25519");
const p:content.ContentAssertionProducer={attestorKeyId:"attestor",jti:"urn:x#a",iss:"issuer",aud:"audience",sub:"subject",profile:"profile",profileDigest:new Uint8Array(32).fill(1),contentDigest:new Uint8Array(32).fill(2),gen:1,prev:new Uint8Array(32),iat:100,nbf:110,exp:200};
function signed(id:string):Uint8Array {
  const input=take(content.assertionSigningInput(p));
  const payload=JSON.parse(Buffer.from(utf8Str(input.payloadSegment),"base64url").toString()) as Record<string,unknown>;
  payload.jti=id;
  const body=JSON.stringify(Object.fromEntries(Object.entries(payload).sort(([a],[b])=>a<b?-1:a>b?1:0)));
  const message=`${utf8Str(input.protectedSegment)}.${Buffer.from(body).toString("base64url")}`;
  return strUtf8(`${message}.${crypto.sign(null,Buffer.from(message),key.privateKey).toString("base64url")}`);
}
function moduleUrl(source:string):string {
  const emitted=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
  return `data:text/javascript;base64,${Buffer.from(emitted).toString("base64")}`;
}
async function mutatedDependency(needle:string, name = "string_or_uri"):Promise<typeof content> {
  const dependencyUrl=new URL(`../src/${name}.ts`,import.meta.url);
  const helper=readFileSync(dependencyUrl,"utf8");
  assert.equal(helper.split(needle).length-1,1,"exact one guard mutation");
  const helperSource=helper.replace(needle,"").replace(/from "(\.\/[^" ]+)\.js"/g,(_m,s:string)=>`from "${new URL(s+".ts",dependencyUrl).href}"`);
  const helperUrl=moduleUrl(helperSource);
  const contentUrl=new URL("../src/content_assertion.ts",import.meta.url);
  const source=readFileSync(contentUrl,"utf8").replace(JSON.stringify(`./${name}.js`),JSON.stringify(helperUrl))
    .replace(/from "(\.\/[^" ]+)\.js"/g,(_m,s:string)=>`from "${new URL(s+".ts",contentUrl).href}"`);
  return await import(moduleUrl(source)) as typeof content;
}
for(const c of [
  {name:"IPv6 group shape",needle:'if (!isIpv6(hostport.slice(1, close))) return false;',id:"http://[abc]/x"},
  {name:"IPv4 group at overall IPv6 tail",needle:'if (literal.includes(".") && literal.indexOf(".") < literal.lastIndexOf(":")) return false;',id:"http://[192.0.2.1::]/x"},
  {name:"brackets in userinfo",needle:'if (at !== -1 && /[\\[\\]]/.test(authority.slice(0, at))) return false;',id:"http://u[s]@host"},
  {name:"single fragment delimiter",needle:'if (s.indexOf("#") !== s.lastIndexOf("#")) return false;',id:"urn:x#a#b"},
  {name:"brackets outside authority",needle:'if (/[\\[\\]]/.test(pathQueryFragment)) return false;',id:"urn:x[foo]"},
]) test(`shared StringOrURI mutation killed: ${c.name}`,async()=>{
  const compact=signed(c.id);
  const refuses=(api:typeof content)=>{
    assert.equal(api.assertionSigningInput({...p,jti:c.id}).ok,false);
    assert.equal(api.decodeAssertion(compact).ok,false);
  };
  refuses(content);
  const mutant=await mutatedDependency(c.needle);
  assert.throws(()=>refuses(mutant),assert.AssertionError);
  assert.equal(mutant.decodeAssertion(compact).ok,true,"decoder also observes the deleted guard");
});

test("bounds unknown-key guard mutation killed: Symbol cannot escape as TypeError",async()=>{
  const bounds={maximum:{},overrides:new Map([[Symbol("unknown"),0]])} as unknown as import("../src/bounds.js").Bounds;
  const refuses=(api:typeof content)=>assert.deepEqual(api.contentDigest(strUtf8("bytes"),bounds),{ok:false});
  refuses(content);
  const mutant=await mutatedDependency('if (typeof key !== "string" || !Object.hasOwn(MAXIMA, key)) fail("bounds.coerce: unknown limit");',"bounds");
  assert.throws(()=>refuses(mutant),TypeError);
});
