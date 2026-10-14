// Independent public-spec consumer. No sibling SDK implementation is imported.
// The frozen index pin and census are checked before trusting any corpus metadata.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { CoreAbort, type Core, type CorpusSource, type VerdictEntry } from "./types.js";
import * as ca from "../../src/content_assertion.js";
import * as sdk from "../../src/index.js";
import { boundsNew, MAXIMUM_BOUNDS, type Bounds } from "../../src/bounds.js";
import { base64urlDecode, base64urlEncode } from "../../src/base64url.js";
import { strUtf8, utf8Str } from "../../src/json.js";
import { trying } from "../../src/error.js";

const DIR = "corpus-content-assertion";
// Stable candidate; certification remains pending protocol-owner cross-SDK agreement.
const INDEX_SHA256 = "14b7436ccf7cc91fece52a1578c3760df6720a93494d147ee5ab523e2ce21876";
const FILES = ["profile.json", "digest-cases.json", "assertion-structure-cases.json", "assertion-verification-cases.json", "successor-cases.json", "content-base.raw", "content-maximum.raw", "content-over-limit.raw"].sort();
// The corpus integrity hash is @noble/hashes, independent of the package backend under test.
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sha = (b: Uint8Array) => hex(nobleSha256(b));
// The node:assert subset this runner used, failing closed through CoreAbort.
const stop = (message: string | undefined, detail: string): never => {
  throw new CoreAbort("content-assertion conformance", message === undefined ? detail : `${message} (${detail})`);
};
interface Asserts {
  equal(actual: unknown, expected: unknown, message?: string): void;
  ok(value: unknown, message?: string): asserts value;
  deepEqual(actual: unknown, expected: unknown, message?: string): void;
}
const assert: Asserts = {
  equal(actual: unknown, expected: unknown, message?: string): void {
    if (!Object.is(actual, expected)) stop(message, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  },
  ok(value: unknown, message?: string): void {
    if (!value) stop(message, "expected a truthy value");
  },
  deepEqual(actual: unknown, expected: unknown, message?: string): void {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) stop(message, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  },
};
const raw = (s: string) => base64urlDecode(strUtf8(s));
const encoded = (b: Uint8Array) => utf8Str(base64urlEncode(b));
type Verdict = "valid" | "invalid";
interface Artifact {
  compact: string; attestor?: string; expected_overrides?: Record<string, unknown>; bounds?: Record<string, number>; facts_overrides?: Record<string, unknown>;
}
interface AssertionCase extends Artifact {
  id: string; expected: {decode: Verdict; verify: Verdict}; legacy_accepts?: string[];
}
interface DigestCase {
  id: string; input: {bounds: Record<string, number>; content_file?: string; content_base64url?: string};
  expected: {verdict: Verdict; digest?: string};
}
interface SuccessorCase {
  id: string; predecessor: Artifact; successor: Artifact;
  expected: {predecessor: Verdict; successor: Verdict; relation: Verdict | "not_run"};
}
interface Profile {
  profile: string; revision: number;
  attestors: Record<string, {key_id: string; public_key: string; valid_from: number; valid_before: number | null}>;
  expected: {issuer: string; audience: string; subject: string; profile: string; profile_digest: string; content_digest: string; now: number};
}
function main(source: CorpusSource): { summary: string[]; verdicts: VerdictEntry[] } {
  const load = (path: string) => source.read(`${DIR}/${path}`);
  const json = <T>(path: string): T => JSON.parse(utf8Str(load(path))) as T;
  const verdicts: VerdictEntry[] = [];
  const indexBytes = load("index.json");
  assert.equal(sha(indexBytes), INDEX_SHA256, "independently pinned corpus index");
  const index = JSON.parse(utf8Str(indexBytes)) as {profile: string; revision: number; assertion_cases: number; digest_cases: number; successor_cases: number; private_material_tracked: boolean; files: {path: string; sha256: string}[]};
  assert.equal(index.profile, "bap-content-assertion/1");
  assert.equal(index.revision, 1);
  assert.equal(index.assertion_cases, 131); assert.equal(index.digest_cases, 9); assert.equal(index.successor_cases, 14);
  assert.equal(index.private_material_tracked, false);
  assert.deepEqual(index.files.map(f => f.path).sort(), FILES, "exact corpus file allowlist");
  for (const f of index.files) assert.equal(sha(load(f.path)), f.sha256, `${f.path} identity`);
  const profile = json<Profile>("profile.json");
  assert.equal(profile.profile, index.profile); assert.equal(profile.revision, index.revision);
  const assertions = [...json<AssertionCase[]>("assertion-structure-cases.json"), ...json<AssertionCase[]>("assertion-verification-cases.json")];
  const digests = json<DigestCase[]>("digest-cases.json");
  const successors = json<SuccessorCase[]>("successor-cases.json");
  assert.equal(assertions.length, 131); assert.equal(digests.length, 9); assert.equal(successors.length, 14);
  const all = [...assertions, ...digests, ...successors];
  assert.equal(new Set(all.map(c => c.id)).size, all.length, "unique case identifiers");
  const allowedOverrides = ["issuer", "audience", "subject", "profile", "profile_digest", "content_digest", "now", "attestor_key_id", "attestor_public_key", "attestor_valid_from", "attestor_valid_before"];
  function expected(a: Artifact, b: Bounds): ca.ExpectedContentAssertion {
    const key = profile.attestors[a.attestor ?? "primary"];
    assert.ok(key, "known attestor selector");
    const o = a.expected_overrides ?? {};
    for (const k of Object.keys(o)) assert.ok(allowedOverrides.includes(k), `unknown override ${k}`);
    const e = {...profile.expected, ...o} as Profile["expected"];
    return {
      attestor: {keyId: (o.attestor_key_id ?? key.key_id) as string,
        publicKey: raw((o.attestor_public_key ?? key.public_key) as string),
        validFrom: (o.attestor_valid_from ?? key.valid_from) as number,
        validBefore: ("attestor_valid_before" in o ? o.attestor_valid_before : key.valid_before) as number | null},
      issuer: e.issuer, audience: e.audience, subject: e.subject, profile: e.profile,
      profileDigest: raw(e.profile_digest), contentDigest: raw(e.content_digest), now: e.now, bounds: b,
    };
  }
  const verdict = (ok: boolean): Verdict => ok ? "valid" : "invalid";
  const legacy: Record<string, (bytes: Uint8Array) => {ok: boolean}> = {
    v1_grant: sdk.decodeGrant, v2_grant: sdk.v2.decodeGrant, v3_grant: sdk.v3.decodeGrant,
    loopback: sdk.decodeLocalLoopbackHttpProof, role_attestation: sdk.roleAttestation.decodeAttestation,
  };
  let producerChecks = 0;
  for (const c of assertions) {
    const compact = strUtf8(c.compact);
    const b = trying(() => boundsNew(c.bounds ?? {}));
    const d = b.ok ? ca.decodeAssertion(compact, b.value) : b;
    const v = b.ok ? ca.verifyAssertion(compact, expected(c, b.value)) : b;
    assert.equal(verdict(d.ok), c.expected.decode, `${c.id}: decode`);
    verdicts.push([c.id, `decode=${verdict(d.ok)};verify=${verdict(v.ok)}`]);
    assert.equal(verdict(v.ok), c.expected.verify, `${c.id}: verify`);
    const digest = b.ok ? ca.assertionDigest(compact, b.value) : b;
    assert.equal(digest.ok, d.ok, `${c.id}: digest parse gate`);
    if (digest.ok) assert.equal(hex(digest.value), sha(compact), `${c.id}: exact compact digest`);
    if (d.ok && b.ok) {
      const p = ca.assertionSigningInput(d.value, b.value);
      assert.ok(p.ok, `${c.id}: producer`);
      const [h, body, sig] = c.compact.split(".");
      assert.equal(utf8Str(p.value.protectedSegment), h); assert.equal(utf8Str(p.value.payloadSegment), body);
      const assembled = ca.assembleCompact(p.value, raw(sig!), b.value);
      assert.ok(assembled.ok); assert.equal(utf8Str(assembled.value), c.compact, `${c.id}: assembly bytes`);
      assert.equal(sdk.assembleCompact(p.value, raw(sig!)).ok, false, `${c.id}: kind isolation`);
      for (const [name, decode] of Object.entries(legacy)) assert.equal(decode(compact).ok, false, `${c.id}: ${name} rejects content assertion`);
      assert.equal(sdk.decodeProof(compact).ok, false); assert.equal(sdk.v2.decodeProof(compact).ok, false); assert.equal(sdk.v3.decodeProof(compact).ok, false);
      producerChecks++;
    }
    for (const name of c.legacy_accepts ?? []) {
      assert.ok(legacy[name], `${c.id}: known legacy profile`);
      assert.equal(legacy[name]!(compact).ok, true, `${c.id}: real ${name} known-positive`);
      assert.equal(d.ok, false, `${c.id}: content profile rejection`);
    }
  }
  for (const c of digests) {
    const b = trying(() => boundsNew(c.input.bounds));
    let bytes: Uint8Array;
    if (c.input.content_file !== undefined) {
      assert.ok(FILES.includes(c.input.content_file) && c.input.content_file.endsWith(".raw"), "sidecar allowlist");
      bytes = load(c.input.content_file);
    } else { assert.equal(typeof c.input.content_base64url, "string"); bytes = raw(c.input.content_base64url!); }
    const r = b.ok ? ca.contentDigest(bytes, b.value) : b;
    verdicts.push([c.id, r.ok ? `valid;digest=${encoded(r.value)}` : "invalid"]);
    assert.equal(verdict(r.ok), c.expected.verdict, `${c.id}: content digest`);
    if (r.ok) assert.equal(encoded(r.value), c.expected.digest, `${c.id}: digest bytes`);
  }
  function verify(a: Artifact) {
    const b = boundsNew(a.bounds ?? {});
    return ca.verifyAssertion(strUtf8(a.compact), expected(a, b));
  }
  function facts(f: ca.ContentAssertionFacts, a: Artifact): ca.ContentAssertionFacts {
    const o = a.facts_overrides ?? {};
    for (const k of Object.keys(o)) assert.ok(["verification", "trust", "digest"].includes(k), `unknown facts override ${k}`);
    // Facts enumerate nothing (the profile's redaction rule), so a stored copy is made field by field,
    // as a host reconstructing facts from storage does.
    const stored = Object.fromEntries(Object.getOwnPropertyNames(f).map((k) => [k, (f as unknown as Record<string, unknown>)[k]]).filter(([, v]) => typeof v !== "function"));
    return {...stored, ...o, ...(o.digest === undefined ? {} : {digest: raw(o.digest as string)})} as ca.ContentAssertionFacts;
  }
  for (const c of successors) {
    const p = verify(c.predecessor), s = verify(c.successor);
    assert.equal(verdict(p.ok), c.expected.predecessor, `${c.id}: predecessor verification`);
    assert.equal(verdict(s.ok), c.expected.successor, `${c.id}: successor verification`);
    const relation = p.ok && s.ok ? verdict(ca.verifySuccessor(facts(p.value, c.predecessor), facts(s.value, c.successor), MAXIMUM_BOUNDS).ok) : "not_run";
    verdicts.push([c.id, `predecessor=${verdict(p.ok)};successor=${verdict(s.ok)};relation=${relation}`]);
    assert.equal(relation, c.expected.relation, `${c.id}: relation`);
  }
  return { verdicts, summary: [`content-assertion conformance: ${assertions.length} assertions, ${digests.length} digests, ${successors.length} successors agree; ${producerChecks} producer/assembly byte checks; pinned index ${INDEX_SHA256}`] };
}

export const core: Core = {
  corpus: "content-assertion",
  dir: DIR,
  run: (source: CorpusSource) => ({ corpus: "content-assertion", failures: [], ...main(source) }),
};
