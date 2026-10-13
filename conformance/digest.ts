// The verdict digest: SHA-256 over the canonical JSON (RFC 8785 JCS for this value shape: an array of
// two-string arrays) of every case's [case id, verdict projection], in corpus order. Equal digests mean
// equal verdicts case by case. It is computed with @noble/hashes directly, never through the package's
// own backend, so a lane cannot certify its own hash.
import { sha256 } from "@noble/hashes/sha2.js";
import type { VerdictEntry } from "./core/types.js";

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// For an array of arrays of strings, JSON.stringify emits exactly the JCS form: no whitespace, and
// JCS string escaping is ECMAScript JSON.stringify escaping.
export function verdictJcs(verdicts: readonly VerdictEntry[]): string {
  return JSON.stringify(verdicts.map(([id, projection]) => [id, projection]));
}

export function verdictDigest(verdicts: readonly VerdictEntry[]): string {
  return hex(sha256(new TextEncoder().encode(verdictJcs(verdicts))));
}

// The first `limit` positions where two verdict lists differ, for a mismatch report.
export function firstDifferences(a: readonly VerdictEntry[], b: readonly VerdictEntry[], limit = 10): string[] {
  const out: string[] = [];
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n && out.length < limit; i++) {
    const x = a[i], y = b[i];
    if (x?.[0] !== y?.[0] || x?.[1] !== y?.[1]) {
      out.push(`#${i}: ${x ? `${x[0]} => ${x[1]}` : "<absent>"} | ${y ? `${y[0]} => ${y[1]}` : "<absent>"}`);
    }
  }
  return out;
}
