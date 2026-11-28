import { actionApproval as aa, contentAssertion, sha256, strUtf8, utf8Str } from "../../src/index.js";
import type { CertifiedCase } from "../certification.js";
import { corpusDir } from "../certification.js";
import { base64url, hashHex } from "../digest.js";
import { CoreAbort } from "./types.js";
import { candidateCore, check, fixture, project, projectAssertion, raw, take } from "./candidate.js";

const dir = corpusDir("action-approval");

export function input(c: Record<string, unknown>) {
  return {
    suite: c.suite as aa.Suite,
    record: raw(c.record as string),
    compact: strUtf8(c.compact as string),
    context: fixture(c.context) as aa.ApprovalContext,
  };
}

function pure(c: Record<string, unknown>) {
  const {suite, record, compact, context} = input(c);
  return suite === "eddsa" ? aa.verifyEddsa(record, compact, context) : aa.verifyEs256(record, compact, context);
}

function helper(c: Record<string, unknown>, observations: Record<string, unknown>) {
  const {suite, record, compact, context} = input(c);
  const calls: {predicate: string; arguments: unknown[]}[] = [];
  function observation(name: string, args: unknown[]): boolean {
    calls.push({predicate: name, arguments: args});
    const outcome = observations[name];
    if (outcome === "exception") throw new Error("provider failure");
    if (outcome === "cancelled") throw new Error("cancelled");
    return outcome as boolean;
  }
  const replayed: aa.IsReplayed = (...args) => observation("is_replayed", args);
  const revoked: aa.IsRevoked = (entry, thumbprint) => observation("is_revoked", [project(entry), base64url(thumbprint)]);
  const run = suite === "eddsa" ? aa.verifyEddsaWithPredicates : aa.verifyEs256WithPredicates;
  const result = run(record, compact, context, replayed, revoked);
  const presenter = aa.presenterResult(result);
  return {calls, helper: result.ok ? "approved" : result.code, presenter: presenter.ok ? "approved" : presenter.code,
    rendering: String(result.ok ? result : presenter)};
}

function recordCase(c: Record<string, unknown>) {
  const setup = fixture({bounds: c.ca_bounds, record_bounds: c.bounds}) as Pick<aa.ApprovalContext, "bounds" | "recordBounds">;
  let author: aa.ApprovalRecord;
  if (c.wire !== undefined) {
    const parsed = aa.decodeRecord(raw(c.wire as string), setup.bounds, setup.recordBounds);
    if (!parsed.ok) return "invalid";
    author = parsed.value;
  } else {
    const {v, ...record} = c.author as Record<string, unknown>;
    if (v !== 1) return "invalid";
    author = fixture(record) as aa.ApprovalRecord;
  }
  const encoded = aa.encodeRecord(author, setup.bounds, setup.recordBounds, c.canonicalize as boolean);
  if (!encoded.ok) return "invalid";
  return {wire: base64url(encoded.value), content_digest: base64url(take(contentAssertion.contentDigest(encoded.value, setup.bounds)))};
}

function verifyCase(c: Record<string, unknown>) {
  const result = pure(c);
  if (!result.ok) return result.code;
  const {suite, trustDomain, trust, assertion, record} = result.value;
  const {action, approverRole, requestId, resources, revisionDigest, subject} = record;
  return {
    suite, trust_domain: trustDomain, trust, assertion: projectAssertion(assertion),
    record: project({action, approverRole, requestId, resources, revisionDigest, subject, v: 1}),
  };
}

function renderingCase(id: string, c: Record<string, unknown>, source: Record<string, unknown>) {
  const result = pure(source);
  let actual: unknown = result;
  if (id === "nested-record" && result.ok) actual = result.value.record;
  if (id === "nested-assertion" && result.ok) actual = result.value.assertion;
  if (id === "presenter-error") actual = aa.presenterResult(result);
  if (id === "helper-exception") {
    const {record, compact, context} = input(source);
    const canaries = c.inputs as Record<string, string>;
    const fail = () => {
      const cause = new Error(canaries.provider_cause);
      const error = new Error(canaries.chained_context, {cause});
      error.stack = canaries.traceback!;
      throw error;
    };
    const local = aa.verifyEs256WithPredicates(record, compact, context, fail, fail);
    const presenter = aa.presenterResult(local);
    rejectCanaries(c, [JSON.stringify(local), JSON.stringify(presenter), String(local), String(presenter)]);
    return {local: String(local), presenter: String(presenter)};
  }
  const rendered = String(actual), serialized = JSON.stringify(actual);
  // Browser previews and structured clones must expose only static markers.
  const clone = structuredClone(actual);
  const markers = id === "verified-facts" ? {ok: true}
    : id === "host-local-error" ? {ok: false, code: "unknown_key"}
    : id === "presenter-error" ? {ok: false, code: "invalid"} : {};
  check(clone, markers, `${id}: enumerable browser preview`);
  rejectCanaries(c, [rendered, serialized, JSON.stringify(clone)]);
  check(JSON.parse(serialized), rendered, `${id}: log rendering`);
  return rendered;
}

function rejectCanaries(c: Record<string, unknown>, renderings: readonly string[]): void {
  const forbidden = c.forbidden as Record<string, string[]> | undefined;
  for (const variants of Object.values(forbidden ?? {})) {
    for (const value of variants) {
      if (renderings.some(text => text.includes(value))) throw new CoreAbort("action approval", "sensitive value in default rendering");
    }
  }
}

export const core = candidateCore("action-approval", dir, (source, cases) => {
  const metadata = JSON.parse(utf8Str(source.read(`${dir}/profile.json`))) as {
    profile: string; profile_preimage_hex: string; profile_digest_hex: string;
  };
  const preimage = Uint8Array.from(metadata.profile_preimage_hex.match(/../g)!, value => parseInt(value, 16));
  check(metadata.profile, aa.PROFILE, "profile identity");
  check(utf8Str(preimage.subarray(0, aa.PROFILE.length + 1)), `${aa.PROFILE}\0`, "profile domain");
  check(hashHex(preimage), metadata.profile_digest_hex, "descriptor known answer");
  check(base64url(sha256(preimage)), base64url(aa.profileDigest()), "published profile digest");
  return new Map(cases.map(c => [c.id, c]));
}, ({id, file, data: c}, cases) => {
  const lookup = (id: string): CertifiedCase => {
    const found = cases.get(id);
    if (found === undefined) throw new CoreAbort("action approval", "missing pure case");
    return found;
  };
  switch (file) {
    case "record-cases.json": return recordCase(c);
    case "approval-cases.json":
    case "multi-fault-cases.json": return verifyCase(c);
    case "helper-cases.json": return helper(lookup(c.pure_case as string).data, c.observations as Record<string, unknown>);
    case "rendering-cases.json": return renderingCase(id, c, lookup(c.pure_case as string).data);
    default: throw new CoreAbort("action approval", `unknown case family ${file}`);
  }
});
