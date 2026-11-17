// Independent RFC 8785 encoding and SHA-256. The verifier's JCS and hashes are under test.
import { sha256 } from "@noble/hashes/sha2.js";
import type { VerdictEntry } from "./core/types.js";
export function base64url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "", bits = 0, value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 6) { bits -= 6; out += alphabet[(value >>> bits) & 63]; }
  }
  if (bits) out += alphabet[(value << (6 - bits)) & 63];
  return out;
}
export const hash64 = (bytes: Uint8Array): string => base64url(sha256(bytes));
export const hashHex = (bytes: Uint8Array): string => Array.from(sha256(bytes), b => b.toString(16).padStart(2, "0")).join("");
export function jcs(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (typeof value === "string") {
    // RFC 8785 refuses lone UTF-16 surrogates.
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) throw new Error("JCS: lone surrogate");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${Array.from(value, jcs).join(",")}]`;
  if (typeof value === "object" && value !== null && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    return `{${Object.keys(value).sort().map(k => `${jcs(k)}:${jcs((value as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  throw new Error("JCS: non-JSON verdict value");
}
export const verdictJcs = (entries: readonly VerdictEntry[]): string => jcs(entries);
export const verdictDigest = (entries: readonly VerdictEntry[]): string => hash64(new TextEncoder().encode(verdictJcs(entries)));
// Select the certified shape only. Values always come from computation; null means refusal.
export function computedOutcome(expected: Record<string, unknown>, actual: Record<string, unknown> | null): Record<string, unknown> {
  if (actual === null) return {verdict: "invalid"};
  return {...Object.fromEntries(Object.keys(expected).filter(k => k !== "verdict").map(k => [k, actual[k]])), verdict: "valid"};
}
export function firstDifferences(a: readonly VerdictEntry[], b: readonly VerdictEntry[], limit = 10): string[] {
  const out: string[] = [];
  for (let i = 0; i < Math.max(a.length, b.length) && out.length < limit; i++) {
    const x = a[i], y = b[i];
    if (!x || !y || x[0] !== y[0] || jcs(x[1]) !== jcs(y[1])) out.push(`#${i}: ${x ? `${x[0]} => ${jcs(x[1])}` : "<absent>"} | ${y ? `${y[0]} => ${jcs(y[1])}` : "<absent>"}`);
  }
  return out;
}
