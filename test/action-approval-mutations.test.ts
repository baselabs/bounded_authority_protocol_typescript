import assert from "node:assert/strict";
import { inspect } from "node:util";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { actionApproval as aa, contentAssertionEs256, strUtf8, BACKEND_ID } from "../src/index.js";
import { certifyCorpus, corpusDir } from "../conformance/certification.js";
import { fixture } from "../conformance/core/candidate.js";
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

interface Edit { readonly file: string; readonly from: string; readonly to: string }
async function compile(edits: readonly Edit[], probe = false) {
  const result = await build({
    stdin: {contents: 'export * from "./src/action_approval.ts"; export { verifyAssertion } from "./src/content_assertion_es256.ts";', resolveDir: root, loader: "ts"},
    bundle: true, platform: "node", format: "esm", write: false,
    plugins: [{name: "approval-mutation", setup(b) {
      b.onResolve({filter: /^#crypto$/}, () => ({path: join(root, `src/crypto/${BACKEND_ID}.ts`)}));
      b.onLoad({filter: /src[/\\](action_approval|content_assertion_stages|approval_record|es256)\.ts$/}, args => {
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
    verifyAssertion: typeof contentAssertionEs256.verifyAssertion;
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
  for (const value of [result, result.value, result.value.record, result.value.assertion]) {
    assert.equal(inspect(value), String(value));
    assert.equal(JSON.parse(JSON.stringify(value)), String(value));
    assert.match(inspect(value), /<redacted>/);
    assert.doesNotMatch(inspect(value), /canary/);
  }
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
