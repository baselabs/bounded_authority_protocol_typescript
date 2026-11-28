import assert from "node:assert/strict";
import { inspect } from "node:util";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { actionApproval as aa, boundsNew, contentAssertion, contentAssertionEs256, strUtf8, BACKEND_ID } from "../src/index.js";
import { certifyCorpus, corpusDir } from "../conformance/certification.js";
import { fixture, raw, take } from "../conformance/core/candidate.js";
import { input } from "../conformance/core/action_approval.js";
import { fsSource } from "../conformance/node_source.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const cases = certifyCorpus(fsSource(), corpusDir("action-approval")).cases;
const get = (id: string) => {
  const found = cases.find(c => c.id === id);
  assert.ok(found, id);
  return input(found.data);
};

type Api = typeof aa;
function run(api: Api, id: string) {
  const {suite, record, compact, context} = get(id);
  return (suite === "es256" ? api.verifyEs256 : api.verifyEddsa)(record, compact, context);
}

test("approval uses the lifetime cap read during preflight", () => {
  const {record, compact, context} = get("eddsa-verified");
  assert.ok(aa.verifyEddsa(record, compact, context).ok);
  let reads = 0;
  const changing = {...context, get maxLifetime() {
    return ++reads === 1 ? 0 : context.maxLifetime;
  }};
  assert.deepEqual(aa.verifyEddsa(record, compact, changing), {ok: false, code: "lifetime_too_long"});
  assert.equal(reads, 1);
});

test("approval verifies and checks revocation with the same admitted key", () => {
  const {record, compact, context} = get("es256-verified");
  const snapshot = context.snapshot!;
  const entry = snapshot.entries[0]!;
  const publicKey = entry.key.publicKey;
  let reads = 0;
  const key = {...entry.key, get publicKey() {
    return ++reads === 1 ? publicKey : new Uint8Array(0);
  }};
  const changing = {...context, snapshot: {...snapshot, entries: [{...entry, key}, ...snapshot.entries.slice(1)]}};
  let checked = 0;
  const result = aa.verifyEs256WithPredicates(record, compact, changing, () => false, admitted => {
    checked++;
    assert.deepEqual(admitted.key.publicKey, publicKey);
    return false;
  });
  assert.ok(result.ok);
  assert.equal(checked, 1);
  assert.equal(reads, 1);
});

interface Edit { readonly file: string; readonly from: string; readonly to: string }
async function compile(edits: readonly Edit[], probe = false) {
  const result = await build({
    stdin: {contents: 'export * from "./src/action_approval.ts"; export { assembleCompact, decodeAssertion, verifyAssertion, verifySuccessor } from "./src/content_assertion_es256.ts";', resolveDir: root, loader: "ts"},
    bundle: true, platform: "node", format: "esm", write: false,
    plugins: [{name: "approval-mutation", setup(b) {
      b.onResolve({filter: /^#crypto$/}, () => ({path: join(root, `src/crypto/${BACKEND_ID}.ts`)}));
      b.onLoad({filter: /src[/\\](action_approval|content_assertion_stages|approval_record|compact|es256|string_or_uri)\.ts$/}, args => {
        let contents = readFileSync(args.path, "utf8");
        for (const {file, from, to} of edits.filter(edit => args.path.endsWith(`/${edit.file}.ts`))) {
          assert.equal(contents.split(from).length - 1, 1, from);
          contents = contents.replace(from, to);
        }
        if (probe && args.path.endsWith("/action_approval.ts")) {
          contents = 'export const calls = {payload_parser: 0, key_lookup: 0, foreign_verifier: 0};\n' + contents
            .replace("const claims = ca.parsePayload", "calls.payload_parser++; const claims = ca.parsePayload")
            .replace("const trusted = trust.value.keys.get", "calls.key_lookup++; const trusted = trust.value.keys.get")
            .replace("if (!suite.verify", "calls.foreign_verifier++; if (!suite.verify");
        }
        return {contents, loader: "ts"};
      });
    }}],
  });
  return await import(`data:text/javascript;base64,${Buffer.from(result.outputFiles[0]!.text).toString("base64")}`) as Api & {
    calls: Record<string, number>;
    assembleCompact: typeof contentAssertionEs256.assembleCompact;
    decodeAssertion: typeof contentAssertionEs256.decodeAssertion;
    verifyAssertion: typeof contentAssertionEs256.verifyAssertion;
    verifySuccessor: typeof contentAssertionEs256.verifySuccessor;
  };
}

test("valid foreign suites stop before parser, lookup and signature verification", async () => {
  const probe = await compile([], true);
  for (const [id, valid] of [["foreign-eddsa", "eddsa-verified"], ["foreign-es256", "es256-verified"]] as const) {
    assert.ok(run(aa, valid).ok);
    const foreign = get(id), known = get(valid);
    assert.deepEqual(foreign.compact, known.compact);
    assert.deepEqual(run(probe, id), {ok: false, code: "unsupported_algorithm"});
    const vector = cases.find(c => c.id === id)!;
    assert.deepEqual(probe.calls, vector.data.expected_calls);
  }
  assert.ok(run(probe, "es256-verified").ok);
  assert.deepEqual(probe.calls, {payload_parser: 1, key_lookup: 1, foreign_verifier: 1});
});

test("IPvFuture would pass approval and ES256 decode if admitted as an identifier host", async () => {
  const compact = get("es256-ipvfuture-signed-id").compact;
  assert.deepEqual(run(aa, "es256-ipvfuture-signed-id"), {ok: false, code: "malformed"});
  assert.equal(contentAssertionEs256.decodeAssertion(compact).ok, false);
  const mutant = await compile([{
    file: "string_or_uri",
    from: 'if (!isIpv6(hostport.slice(1, close))) return false;',
    to: 'if (!isIpv6(hostport.slice(1, close)) && hostport.slice(1, close) !== "v1.a") return false;',
  }]);
  assert.equal(run(mutant, "es256-ipvfuture-signed-id").ok, true);
  assert.equal(mutant.decodeAssertion(compact).ok, true);
});

const approval = (from: string, to = ""): Edit => ({file: "action_approval", from, to});
const mutations: readonly [string, string, Edit][] = [
  ["snapshot role uniqueness", "duplicate-enrolled-role", approval('assert(!names.has(role), "unique roles");')],
  ["entry key uniqueness", "duplicate-key-entry", approval('assert(!keys.has(entry.key.keyId), "unique key IDs");')],
  ["snapshot freshness", "old-trust", approval('if (staleness < 0n || staleness > BigInt(context.maxStaleness)) return failure("stale_trust");')],
  ["suite precedence", "foreign-eddsa", approval('if (!ca.admitsSuite(header, suite)) return failure("unsupported_algorithm");')],
  ["signed subject ceiling", "signed-sub-over", approval('record.requestId(claims.sub, limits, bounds);')],
  ["signature precedence", "bad-signature", approval('if (!suite.verify(seg.signingInput, seg.signature, trusted.entry.key.publicKey)) return failure("bad_signature");')],
  ["historical window", "key-window-lower", approval('if (!ca.keyWindow(p, trusted.key)) return "key_window";')],
  ["content digest", "wrong-content_digest", approval('!digestEqual(p.contentDigest, ca.hashContent(encoded)) ||')],
  ["profile digest", "wrong-profile_digest", approval(' || !digestEqual(p.profileDigest, profileDigest())')],
  ["profile identity", "wrong-profile", approval('p.profile !== PROFILE || ')],
  ["enrolled issuer", "issuer-mismatch", approval('if (p.iss !== trusted.issuer) return "issuer_mismatch";')],
  ["expected audience", "audience-mismatch", approval('if (p.aud !== context.audience) return "audience_mismatch";')],
  ["expected request", "request-expected", approval('r.requestId !== context.requestId || ')],
  ["signed request", "request-signed", approval('r.requestId !== p.sub ||')],
  ["revision", "revision-mismatch", approval('!digestEqual(r.revisionDigest, context.revisionDigest)', 'false')],
  ["subject", "subject-mismatch", approval('if (r.subject !== context.subject) return "subject_mismatch";')],
  ["action", "action-mismatch", approval('r.action !== context.action || ')],
  ["exact resources", "resources-mismatch", approval('r.resources.length !== context.resources.length ||\n      !r.resources.every((name, i) => name === context.resources[i])', 'false')],
  ["current window", "expired", approval('if (window !== null) return window;')],
  ["lifetime", "lifetime-too-long", approval('if (age(p.exp, p.iat) > BigInt(context.maxLifetime)) return "lifetime_too_long";')],
  ["active time", "active-too-long", approval('if (context.maxActive !== undefined && age(p.exp, p.nbf) > BigInt(context.maxActive)) return "active_too_long";')],
  ["required role", "role-not-required", approval('!expectedRoles.has(r.approverRole) || ')],
  ["enrolled role", "empty-enrolled-roles", approval(' || !enrolled.has(r.approverRole)')],
];
for (const [label, id, edit] of mutations) {
  test(`action approval mutation killed: ${label}`, async () => {
    const actual = (api: Api) => {
      const result = run(api, id);
      return result.ok ? "verified" : result.code;
    };
    const expected = cases.find(c => c.id === id)!.value;
    assert.equal(actual(aa), expected);
    assert.notEqual(actual(await compile([edit])), expected);
  });
}

test("approval default inspection redacts nested facts and closes presenter failures", () => {
  const result = run(aa, "rendering-canaries-verified");
  assert.ok(result.ok);
  const {record, compact, context} = get("rendering-canaries-verified");
  const helper = aa.verifyEs256WithPredicates(record, compact, context, () => false, () => false);
  assert.ok(helper.ok);
  assert.deepEqual({...result}, {ok: true});
  assert.deepEqual({...helper}, {ok: true});
  assert.match(result.value.record.subject, /canary/);
  assert.ok(result.value.record.revisionDigest instanceof Uint8Array);
  for (const value of [result, helper, result.value, result.value.record, result.value.assertion]) {
    assert.equal(inspect(value), String(value));
    assert.equal(JSON.parse(JSON.stringify(value)), String(value));
    assert.match(inspect(value), /<redacted>/);
    assert.doesNotMatch(inspect(value), /canary/);
    assert.doesNotMatch(inspect(value, {customInspect: false, getters: false, showHidden: true}), /canary/);
  }
  const subject = Object.getOwnPropertyDescriptor(result.value.record, "subject");
  assert.equal(subject?.enumerable, false);
  assert.equal(typeof subject?.get, "function");
  assert.equal(Object.hasOwn(subject!, "value"), false);
  const error = run(aa, "unknown-key");
  assert.equal(inspect(error), "{:error, :unknown_key}");
  assert.equal(inspect(aa.presenterResult(error)), "{:error, :invalid}");
});


test("ES256 low-S verification gate rejects a valid high-S counterpart", async () => {
  const vectors = certifyCorpus(fsSource(), corpusDir("content-assertion-es256")).cases;
  const accept = (verify: typeof contentAssertionEs256.verifyAssertion, id: string) => {
    const item = vectors.find(c => c.id === id)!.data;
    const context = fixture({...item.context as object, bounds: {}}) as contentAssertionEs256.ExpectedContentAssertion;
    return verify(strUtf8(item.compact as string), context).ok;
  };
  assert.equal(accept(contentAssertionEs256.verifyAssertion, "verified"), true);
  assert.equal(accept(contentAssertionEs256.verifyAssertion, "high-s"), false);
  const mutant = await compile([{file: "es256", from: "s <= HALF_N", to: "s < N"}]);
  assert.equal(accept(mutant.verifyAssertion, "high-s"), true);
});

const suiteGate = '  if (!ca.admitsSuite(header, suite)) return failure("unsupported_algorithm");';
const snapshotGate = '  if (!trust.ok) return failure("trust_unavailable");';
const freshGate = '  if (staleness < 0n || staleness > BigInt(context.maxStaleness)) return failure("stale_trust");';
const shapeGate = '  if (!framed.ok) return failure("malformed");';
const payloadStart = '  const payload = closed(() => {';
const payloadGate = '  if (!payload.ok) return failure("malformed");';
const lookup = '  const trusted = trust.value.keys.get(header.keyId);';
const lookupGate = '  if (trusted === undefined) return failure("unknown_key");';
const signatureGate = '  if (!suite.verify(seg.signingInput, seg.signature, trusted.entry.key.publicKey)) return failure("bad_signature");';
const keyWindowGate = '  if (!ca.keyWindow(p, trusted.key)) return "key_window";';
const recordGate = '  if (!digestEqual(p.contentDigest, ca.hashContent(encoded)) ||\n' +
  '      p.profile !== PROFILE || !digestEqual(p.profileDigest, profileDigest())) return "record_mismatch";';
const issuerGate = '  if (p.iss !== trusted.issuer) return "issuer_mismatch";';
const audienceGate = '  if (p.aud !== context.audience) return "audience_mismatch";';
const requestGate = '  if (r.requestId !== context.requestId || r.requestId !== p.sub ||\n' +
  '      !digestEqual(r.revisionDigest, context.revisionDigest)) return "request_mismatch";';
const subjectGate = '  if (r.subject !== context.subject) return "subject_mismatch";';
const scopeGate = '  if (r.action !== context.action || r.resources.length !== context.resources.length ||\n' +
  '      !r.resources.every((name, i) => name === context.resources[i])) return "scope_mismatch";';
const windowGate = '  const window = ca.currentWindow(p, context.now);\n  if (window !== null) return window;';
const lifetimeGate = '  if (age(p.exp, p.iat) > BigInt(context.maxLifetime)) return "lifetime_too_long";';
const activeGate = '  if (context.maxActive !== undefined && age(p.exp, p.nbf) > BigInt(context.maxActive)) return "active_too_long";';
const roleGate = '  if (!expectedRoles.has(r.approverRole) || !enrolled.has(r.approverRole)) return "role_not_permitted";';

const moveAfter = (check: string, after: string): Edit[] => [approval(check), approval(after, `${after}\n${check}`)];
const precedence: readonly [string, aa.Diagnostic, readonly Edit[]][] = [
  ["context-before-snapshot", "trust_unavailable", [
    // For this control, the bounds are valid and the clock is invalid. Admit the snapshot first.
    approval('  if (!expected.ok) return failure("invalid_context");', `  if (!expected.ok) {
    const bounds = ca.bounded(supplied.bounds);
    const limits = record.limits(bounds, supplied.recordBounds);
    const trust = closed(() => snapshot(supplied.snapshot, supplied.trustDomain, suite, name, bounds, limits));
    return failure(trust.ok ? "invalid_context" : "trust_unavailable");
  }`),
  ]],
  ["unavailable-before-stale-and-malformed", "stale_trust", [
    approval('  const staleness = age(context.now, trust.value.asOf);', '  const staleness = age(context.now, supplied.snapshot!.asOf);'),
    ...moveAfter(snapshotGate, freshGate),
  ]],
  ["stale-before-shape", "malformed", moveAfter(freshGate, shapeGate)],
  ["shape-before-suite", "unsupported_algorithm", [
    {file: "content_assertion_stages", from: '  kid(keyId,b);', to: ""},
    approval(payloadStart, `${payloadStart}\n    ca.kid(header.keyId, bounds);`),
  ]],
  ["signature-width-before-suite", "unsupported_algorithm", [
    {file: "compact", from: '  if (signature.length !== resolve(b, "signature_bytes" as MaximaKey)) fail("compact: signature width");', to: ""},
    approval(suiteGate, `${suiteGate}\n  if (seg.signature.length !== resolve(bounds, "signature_bytes")) return failure("malformed");`),
  ]],
  ["suite-before-claims", "malformed", moveAfter(suiteGate, payloadGate)],
  ["suite-before-key", "unknown_key", moveAfter(suiteGate, lookupGate)],
  ["record-shape-before-key", "unknown_key", [
    approval(`${lookup}\n${lookupGate}`),
    approval(payloadStart, `${lookup}\n${lookupGate}\n${payloadStart}`),
  ]],
  ["key-before-signature", "bad_signature", [
    // Supply an admitted fallback key to run the equation before reporting an unknown key ID.
    approval(`${lookupGate}\n${signatureGate}`, `  const key = trusted?.entry.key ?? trust.value.keys.values().next().value?.entry.key;
  if (key === undefined || !suite.verify(seg.signingInput, seg.signature, key.publicKey)) return failure("bad_signature");
${lookupGate}`),
  ]],
  ["signature-before-times", "key_window", [
    approval(keyWindowGate),
    approval(signatureGate, `  if (!ca.keyWindow(claims, trusted.entry.key)) return failure("key_window");\n${signatureGate}`),
  ]],
  ["key-window-before-record-binding", "record_mismatch", moveAfter(keyWindowGate, recordGate)],
  ["record-binding-before-issuer", "issuer_mismatch", moveAfter(recordGate, issuerGate)],
  ["issuer-before-audience", "audience_mismatch", moveAfter(issuerGate, audienceGate)],
  ["audience-before-request", "request_mismatch", moveAfter(audienceGate, requestGate)],
  ["request-before-subject", "subject_mismatch", moveAfter(requestGate, subjectGate)],
  ["request-before-scope", "scope_mismatch", moveAfter(requestGate, scopeGate)],
  ["subject-before-scope", "scope_mismatch", moveAfter(subjectGate, scopeGate)],
  ["scope-before-time", "not_yet_valid", moveAfter(scopeGate, windowGate)],
  ["window-before-duration", "lifetime_too_long", moveAfter(windowGate, lifetimeGate)],
  ["lifetime-before-active", "active_too_long", moveAfter(lifetimeGate, activeGate)],
  ["active-before-role", "role_not_permitted", moveAfter(activeGate, roleGate)],
];

for (const [id, reorderedCode, edits] of precedence) {
  test(`approval precedence mutation changes the first diagnostic: ${id}`, async () => {
    const vector = cases.find(c => c.file === "multi-fault-cases.json" && c.id === id);
    assert.ok(vector, "pinned multi-fault vector");
    assert.notEqual(vector.value, reorderedCode, "two distinguishable failures");
    assert.deepEqual(run(aa, id), {ok: false, code: vector.value});
    const mutant = await compile(edits);
    assert.deepEqual(run(mutant, id), {ok: false, code: reorderedCode});
  });
}

test("ES256 lineage survives structuredClone and another SDK copy, and both suites reject mixed facts", async () => {
  const vectors = certifyCorpus(fsSource(), corpusDir("content-assertion-es256")).cases;
  const facts = (id: string) => {
    const item = vectors.find(c => c.id === id)!.data;
    const context = fixture({...item.context as object, bounds: {}}) as contentAssertionEs256.ExpectedContentAssertion;
    return take(contentAssertionEs256.verifyAssertion(strUtf8(item.compact as string), context));
  };
  const old = structuredClone(facts("verified")), next = structuredClone(facts("successor"));
  const bounds = boundsNew();
  assert.equal(old.suite, "es256");
  assert.equal(next.suite, "es256");
  assert.equal(contentAssertionEs256.verifySuccessor(old, next, bounds).ok, true);
  const second = await compile([]);
  assert.equal(second.verifySuccessor(old, next, bounds).ok, true);

  const {suite: _oldSuite, ...ed25519Old} = old;
  const {suite: _nextSuite, ...ed25519Next} = next;
  assert.equal(contentAssertion.verifySuccessor(ed25519Old, ed25519Next, bounds).ok, true, "legacy facts shape");
  assert.equal(contentAssertion.verifySuccessor(old, next, bounds).ok, false);
  assert.equal(contentAssertion.verifySuccessor(ed25519Old, next, bounds).ok, false);
  assert.equal(contentAssertion.verifySuccessor(old, ed25519Next, bounds).ok, false);
  assert.equal(contentAssertionEs256.verifySuccessor(ed25519Old as typeof old, next, bounds).ok, false);
  assert.equal(contentAssertionEs256.verifySuccessor(old, ed25519Next as typeof next, bounds).ok, false);
  assert.equal(contentAssertionEs256.verifySuccessor(ed25519Old as typeof old, ed25519Next as typeof next, bounds).ok, false);
});

test("ES256 assembly enforces caller bounds before allocating the compact", async () => {
  const {signing} = JSON.parse(Buffer.from(fsSource().read(`${corpusDir("content-assertion-es256")}/profile.json`)).toString("utf8")) as {
    signing: {payload: Record<string, unknown>; kid: string; signature: string; compact: string};
  };
  const producer = fixture({...signing.payload, attestor_key_id: signing.kid}) as contentAssertionEs256.ContentAssertionProducer;
  const input = take(contentAssertionEs256.assertionSigningInput(producer));
  const signature = raw(signing.signature);
  const probe: Edit = {
    file: "compact",
    from: 'function concat(...parts: Uint8Array[]): Uint8Array {',
    to: 'function concat(...parts: Uint8Array[]): Uint8Array {\n  if (parts.length === 5) throw new Error("compact allocation reached");',
  };
  const instrumented = await compile([probe]);
  assert.equal(contentAssertionEs256.assembleCompact(input, signature).ok, true);
  assert.throws(() => instrumented.assembleCompact(input, signature), /compact allocation reached/);

  const header = {...input, protectedSegment: new Uint8Array(1024).fill(65)};
  const payload = {...input, payloadSegment: new Uint8Array(1024).fill(65)};
  const cases = [
    [header, boundsNew({encoded_segment_bytes: 1023})],
    [payload, boundsNew({encoded_segment_bytes: 1023})],
    [payload, boundsNew({decoded_segment_bytes: 767})],
    [input, boundsNew({compact_bytes: signing.compact.length - 1})],
    [input, boundsNew({anchor_bytes: signing.compact.length - 1})],
  ] as const;
  for (const [segments, limits] of cases) {
    assert.deepEqual(instrumented.assembleCompact(segments, signature, limits), {ok: false});
  }
  const mutant = await compile([
    probe,
    {file: "content_assertion_stages", from: "    checkAssemblyBounds(protectedSegment.length, payloadSegment.length, b);\n    const assembled",
      to: "    const assembled"},
  ]);
  for (const [segments, limits] of cases) {
    assert.throws(() => mutant.assembleCompact(segments, signature, limits), /compact allocation reached/);
  }
});
