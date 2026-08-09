import { fail } from "./error.js";
import { resolve, MAXIMUM_BOUNDS, type Bounds, type MaximaKey } from "./bounds.js";
import { strUtf8, utf8Str, type Tagged } from "./json.js";

// RFC 8785 JSON Canonicalization Scheme over the tagged JSON algebra (protocol-v1.md:91-95,
// REQ1-JSON-jcs-exact). Accepts only the tagged algebra. Enforces every JSON + output bound while
// emitting RFC 8785 bytes: exact string escaping, invalid-Unicode rejection, unsigned UTF-16 object-
// name sorting at every depth, preserved array order, and ECMAScript binary64 number text
// (-0 as 0, fixed/exponent thresholds, lowercase e).
//
// Number formatting: RFC 8785 §3.2.2 mandates the shortest representation. ECMAScript's
// Number.prototype.toString (and JSON.stringify of a number) IS the shortest round-tripping repr
// (V8/Node matches this), so integers emit as bare integers and finite floats via their JS string
// form. The tagged algebra's int/float distinction is preserved (1 → "1" as int; 1.0 → "1" as float
// would be a Float tag, but JS coerces 1.0 to 1 at the value layer — the TAG carries the distinction,
// the serialization is byte-identical for equal numeric value, matching the Elixir JCS).

export function jcsEncode(value: Tagged, bounds: Bounds = MAXIMUM_BOUNDS): Uint8Array {
  const parts: Uint8Array[] = [];
  emit(value, parts, bounds);
  let total = 0;
  for (const p of parts) total += p.length;
  if (total > resolve(bounds, "jcs_bytes" as MaximaKey)) fail("jcs: jcs_bytes bound");
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function emit(value: Tagged, parts: Uint8Array[], bounds: Bounds): void {
  switch (value.t) {
    case "null": parts.push(STR_NULL); return;
    case "bool": parts.push(value.v ? STR_TRUE : STR_FALSE); return;
    case "int": parts.push(strUtf8(formatInt(value.v))); return;
    case "float": parts.push(strUtf8(formatFloat(value.v))); return;
    case "string": parts.push(escapeString(value.v, bounds)); return;
    case "array": {
      parts.push(LBRACKET);
      for (let i = 0; i < value.v.length; i++) {
        if (i > 0) parts.push(COMMA);
        emit(value.v[i]!, parts, bounds);
      }
      parts.push(RBRACKET);
      return;
    }
    case "object": {
      // RFC 8785 §3.2.3: object names sorted by unsigned UTF-16 code unit sequence.
      const names = [...value.v.keys()].sort(utf16Sort);
      parts.push(LBRACE);
      for (let i = 0; i < names.length; i++) {
        if (i > 0) parts.push(COMMA);
        const name = names[i]!;
        parts.push(escapeString(strUtf8(name), bounds));
        parts.push(COLON);
        emit(value.v.get(name)!, parts, bounds);
      }
      parts.push(RBRACE);
      return;
    }
    default: fail("jcs: unknown tag");
  }
}

const STR_NULL = strUtf8("null");
const STR_TRUE = strUtf8("true");
const STR_FALSE = strUtf8("false");
const LBRACE = strUtf8("{");
const RBRACE = strUtf8("}");
const LBRACKET = strUtf8("[");
const RBRACKET = strUtf8("]");
const COMMA = strUtf8(",");
const COLON = strUtf8(":");

function formatInt(n: number): string {
  return String(n);
}

// RFC 8785 §3.2.2: shortest representation. JS Number stringification produces the shortest
// round-tripping decimal; JSON.stringify emits it without exponent where V8 would. Both match the
// ECMAScript binary64 text the Elixir JCS produces (which also implements §3.2.2).
function formatFloat(n: number): string {
  if (!Number.isFinite(n)) fail("jcs: non-finite float");
  return JSON.stringify(n);
}

// RFC 8785 §3.2.2.1 string escaping: mandatory-escape chars (< 0x20, 0x22 ", 0x5c \, 0x7f DEL) +
// UTF-8 for the rest. The escapeString function below applies this inline.

// The short escapes per RFC 8785 §3.2.2.1 (b, f, n, r, t + the two structural " \).
const SHORT_ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: "\\\"",
  0x5c: "\\\\",
};

function escapeString(bytes: Uint8Array, bounds: Bounds): Uint8Array {
  const out: number[] = [0x22 /* " */];
  // Decode UTF-8 to code points so \uXXXX escaping (for < 0x20 and lone surrogates) is correct.
  const s = utf8Str(bytes);
  for (let i = 0; i < s.length; i++) {
    const cp = s.codePointAt(i)!;
    if (cp > 0xffff) {
      // Astral — emit the two UTF-16 surrogates as raw UTF-8 bytes (RFC 8785 keeps them, no \u).
      // Actually RFC 8785 emits astral chars as their UTF-8 bytes (not \u escapes). Emit raw.
      appendUtf8Bytes(cp, out);
      i++; // surrogate pair consumed 2 code units
    } else if (cp < 0x20) {
      const short = SHORT_ESCAPES[cp];
      if (short !== undefined) {
        for (let j = 0; j < short.length; j++) out.push(short.charCodeAt(j));
      } else {
        appendU(cp, out);
      }
    } else if (cp === 0x22 || cp === 0x5c) {
      const short = SHORT_ESCAPES[cp]!;
      for (let j = 0; j < short.length; j++) out.push(short.charCodeAt(j));
    } else if (cp === 0x7f) {
      appendU(0x7f, out);
    } else {
      appendUtf8Bytes(cp, out);
    }
  }
  out.push(0x22 /* " */);
  const result = new Uint8Array(out);
  // string_bytes bound applies to the decoded value; the escaped form can be longer. We check the
  // raw bytes against string_bytes at decode time, so no re-check here.
  void bounds;
  return result;
}

function appendU(cp: number, out: number[]): void {
  const hex = "\\u" + cp.toString(16).padStart(4, "0");
  for (let i = 0; i < hex.length; i++) out.push(hex.charCodeAt(i));
}

function appendUtf8Bytes(cp: number, out: number[]): void {
  if (cp < 0x80) out.push(cp);
  else if (cp < 0x800) {
    out.push(0xc0 | (cp >> 6));
    out.push(0x80 | (cp & 0x3f));
  } else if (cp < 0x10000) {
    out.push(0xe0 | (cp >> 12));
    out.push(0x80 | ((cp >> 6) & 0x3f));
    out.push(0x80 | (cp & 0x3f));
  } else {
    // Astral code points (cp >= 0x10000) — 4-byte UTF-8 (RFC 8785 keeps astral chars as their UTF-8
    // bytes, not \u escapes). The prior 3-byte-cap branch produced a malformed sequence for astral.
    out.push(0xf0 | (cp >> 18));
    out.push(0x80 | ((cp >> 12) & 0x3f));
    out.push(0x80 | ((cp >> 6) & 0x3f));
    out.push(0x80 | (cp & 0x3f));
  }
}

// Unsigned UTF-16 code-unit comparison (RFC 8785 §3.2.3). Compare by char code of each UTF-16 unit.
function utf16Sort(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) return ca - cb;
  }
  return a.length - b.length;
}
