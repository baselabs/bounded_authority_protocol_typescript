import { fail } from "./error.js";
import { resolve, coerceBounds, MAXIMUM_BOUNDS, type Bounds, type MaximaKey } from "./bounds.js";
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
  // Cross-vendor F2: re-validate caller-supplied bounds (Bounds is structural; a hand-crafted override
  // can widen limits past MAXIMA). Mirrors the reference's Bounds.coerce.
  const b = coerceBounds(bounds);
  const parts: Uint8Array[] = [];
  emit(value, parts, b, 0, 0);
  let total = 0;
  for (const p of parts) total += p.length;
  if (total > resolve(b, "jcs_bytes" as MaximaKey)) fail("jcs: jcs_bytes bound");
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// Emit one tagged value as RFC 8785 bytes, enforcing every per-node resource bound DURING encode
// (mirrors jcs.ex:27-101 encode_value). Returns the updated node count. Per-node invariants:
//   scalars: level <= depth (NOT <); int/float magnitude; string byte_size <= string_bytes.
//   array/object: level < depth (children at level+1); length <= array_items/object_members;
//     object key byte_size <= key_bytes. total_nodes incremented + checked at every node.
function emit(value: Tagged, parts: Uint8Array[], bounds: Bounds, level: number, nodes: number): number {
  const depth = resolve(bounds, "depth" as MaximaKey);
  switch (value.t) {
    case "null":
      if (level > depth) fail("jcs: depth bound");
      parts.push(STR_NULL);
      return nextNode(nodes, bounds);
    case "bool":
      if (level > depth) fail("jcs: depth bound");
      parts.push(value.v ? STR_TRUE : STR_FALSE);
      return nextNode(nodes, bounds);
    case "int":
      // Cross-vendor F3: the reference guard is `when is_integer(value)` (jcs.ex:38); a non-integer
      // int-tag value (1.5, or bool) must fail closed, not canonicalize. Number.isInteger rejects
      // floats and booleans.
      if (!Number.isInteger(value.v) || level > depth || Math.abs(value.v) > resolve(bounds, "integer_magnitude" as MaximaKey)) fail("jcs: integer bound");
      parts.push(strUtf8(formatInt(value.v)));
      return nextNode(nodes, bounds);
    case "float":
      if (level > depth || Math.abs(value.v) > resolve(bounds, "float_magnitude" as MaximaKey)) fail("jcs: float bound");
      parts.push(strUtf8(formatFloat(value.v)));
      return nextNode(nodes, bounds);
    case "string":
      // The decoder already validated UTF-8 + string_bytes; re-check here so a programmatically-built
      // over-bound value (not from the decoder) is rejected at encode, matching jcs.ex:57-59.
      // Cross-vendor (JCS UTF-8): the reference guard is `String.valid?(value)` (jcs.ex:58) which
      // rejects invalid UTF-8. A programmatically-built JString with invalid bytes would otherwise
      // reach escapeString → utf8Str (fatal TextDecoder) and throw TypeError past the closed-Result
      // contract. Validate UTF-8 here and fail closed (Err) instead.
      if (level > depth || value.v.length > resolve(bounds, "string_bytes" as MaximaKey) || !isValidUtf8(value.v)) fail("jcs: string bound");
      parts.push(escapeString(value.v, bounds));
      return nextNode(nodes, bounds);
    case "array": {
      if (level >= depth || value.v.length > resolve(bounds, "array_items" as MaximaKey)) fail("jcs: array bound");
      let n = nextNode(nodes, bounds);
      parts.push(LBRACKET);
      for (let i = 0; i < value.v.length; i++) {
        if (i > 0) parts.push(COMMA);
        n = emit(value.v[i]!, parts, bounds, level + 1, n);
      }
      parts.push(RBRACKET);
      return n;
    }
    case "object": {
      if (level >= depth || value.v.size > resolve(bounds, "object_members" as MaximaKey)) fail("jcs: object bound");
      const keyBytes = resolve(bounds, "key_bytes" as MaximaKey);
      let n = nextNode(nodes, bounds);
      // RFC 8785 §3.2.3: object names sorted by unsigned UTF-16 code unit sequence.
      const names = [...value.v.keys()].sort(utf16Sort);
      for (const name of names) {
        if (strUtf8(name).length > keyBytes) fail("jcs: key_bytes bound");
      }
      parts.push(LBRACE);
      for (let i = 0; i < names.length; i++) {
        if (i > 0) parts.push(COMMA);
        const name = names[i]!;
        parts.push(escapeString(strUtf8(name), bounds));
        parts.push(COLON);
        n = emit(value.v.get(name)!, parts, bounds, level + 1, n);
      }
      parts.push(RBRACE);
      return n;
    }
    default: fail("jcs: unknown tag");
  }
}

function nextNode(nodes: number, bounds: Bounds): number {
  const next = nodes + 1;
  if (next > resolve(bounds, "total_nodes" as MaximaKey)) fail("jcs: total_nodes bound");
  return next;
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

// UTF-8 validity check that does NOT throw (cross-vendor JCS UTF-8): the reference's String.valid?
// (jcs.ex:58) rejects invalid UTF-8 at encode. The fatal TextDecoder in utf8Str throws TypeError on
// invalid bytes, escaping the closed-Result contract; this gate lets jcsEncode fail closed instead.
// Walks the byte stream validating leading/multi-byte sequences (RFC 3629).
function isValidUtf8(bytes: Uint8Array): boolean {
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i]!;
    if (b0 < 0x80) { i++; continue; }
    let need: number;
    let min: number;
    if ((b0 & 0xe0) === 0xc0) { need = 1; min = 0x80; }
    else if ((b0 & 0xf0) === 0xe0) { need = 2; min = 0x800; }
    else if ((b0 & 0xf8) === 0xf0) { need = 3; min = 0x10000; }
    else return false; // invalid leading byte (continuation, or 0xf8+)
    if (i + need >= bytes.length) return false; // truncated
    let cp = b0 & (0x1f >> need);
    for (let j = 1; j <= need; j++) {
      const bj = bytes[i + j]!;
      if ((bj & 0xc0) !== 0x80) return false; // not a continuation byte
      cp = (cp << 6) | (bj & 0x3f);
    }
    if (cp < min) return false; // over-long encoding
    if (cp >= 0xd800 && cp <= 0xdfff) return false; // lone surrogate
    if (cp > 0x10ffff) return false; // out of range
    i += 1 + need;
  }
  return true;
}

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
      // DEL (0x7f): RFC 8785 serializes strings per ECMAScript JSON.stringify, which escapes only
      // U+0000–U+001F plus quote (0x22) and backslash (0x5c) — so raw DEL is RFC-COMPLIANT, NOT an
      // RFC deviation. The Elixir reference (the contract per AGENTS rule 7) emits RAW 0x7f here
      // (jcs.ex:147 has no DEL case, so the general codepoint branch passes it through raw), and the
      // SDK matches those bytes for identical signed inputs and request digests. Verified:
      // Jcs.encode("x<DEL>y") -> [34,120,127,121,34].
      out.push(0x7f);
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
