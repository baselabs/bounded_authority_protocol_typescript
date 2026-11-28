// Fixture representation only. Outputs are projected from SDK results.
import { base64urlDecode } from "../../src/base64url.js";
import { strUtf8 } from "../../src/json.js";
import { MAXIMA } from "../../src/bounds.js";
import type { ContentAssertionFacts } from "../../src/content_assertion.js";
import type { Result } from "../../src/error.js";
import { certifyCorpus, completeVerdicts, type CertifiedCase } from "../certification.js";
import { base64url, jcs } from "../digest.js";
import { CoreAbort, type Core, type CorpusSource } from "./types.js";

const binary = new Set(["attestor_key_fingerprint", "content_digest", "digest", "prev", "profile_digest", "public_key", "revision_digest"]);
const camel = (name: string) => name.replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase());
const snake = (name: string) => name.replace(/[A-Z]/g, letter => "_" + letter.toLowerCase());
const isMap = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null;
export const raw = (value: string) => base64urlDecode(strUtf8(value));

export function fixture(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(fixture);
  if (!isMap(value)) return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => {
    const field = key === "ca_bounds" ? "bounds" : camel(key);
    if (binary.has(key)) return [field, typeof item === "string" ? raw(item) : item];
    if (key === "bounds" || key === "ca_bounds") return [field, {maximum: MAXIMA, overrides: new Map(Object.entries(item as Record<string, number>))}];
    if (key === "record_bounds") return [field, item];
    return [field, key === "valid_before" && item === "unbounded" ? null : fixture(item)];
  }));
}

export function project(value: unknown): unknown {
  if (value instanceof Uint8Array) return base64url(value);
  if (Array.isArray(value)) return value.map(project);
  if (!isMap(value)) return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    snake(key), key === "validBefore" && item === null ? "unbounded" : project(item),
  ]));
}

// Keep the frozen verdict schema independent of the TS-only suite discriminant and private accessors.
export function projectAssertion(facts: ContentAssertionFacts): unknown {
  const {attestorKeyId, jti, iss, aud, sub, profile, profileDigest, contentDigest, gen, prev, iat,
    nbf, exp, version, attestorKeyFingerprint, digest, verification, trust} = facts;
  return project({attestorKeyId, jti, iss, aud, sub, profile, profileDigest, contentDigest, gen, prev, iat,
    nbf, exp, version, attestorKeyFingerprint, digest, verification, trust});
}

export function take<T>(result: Result<T>): T {
  if (!result.ok) throw new CoreAbort("candidate conformance", "positive control rejected");
  return result.value;
}

export function check(actual: unknown, expected: unknown, id: string): void {
  if (jcs(actual) !== jcs(expected)) throw new CoreAbort("candidate conformance", `${id}: expected ${jcs(expected)}, got ${jcs(actual)}`);
}

export function candidateCore<T>(corpus: string, dir: string, prepare: (source: CorpusSource, cases: readonly CertifiedCase[]) => T,
  execute: (input: CertifiedCase, state: T) => unknown): Core {
  return {corpus, dir, run(source) {
    const {cases, indexSha} = certifyCorpus(source, dir);
    const state = prepare(source, cases);
    const verdicts = completeVerdicts(source, dir, cases.map(c => {
      const actual = execute(c, state);
      check(actual, c.value, c.id);
      return [c.id, actual];
    }));
    return {corpus, verdicts, failures: [], summary: [`${corpus}: ${cases.length} cases agree; pinned index ${indexSha}`]};
  }};
}
