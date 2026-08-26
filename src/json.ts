import { fail } from "./error.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// Tagged JSON algebra (spec/bap-v1.md § JSON algebra and decoding, L72-95).
// Each JSON value is tagged so the integer/float distinction survives — selector semantic identity
// (REQ1-SELECTOR-semantic-identity) and the typed request-digest projection both depend on it.
//
//   Null | Boolean(bool) | Integer(int) | Float(float) | String(utf8) | Array([Value]) | Object([(String, Value)])
//
// Objects retain source member order; duplicate names at any depth reject pre-map-conversion
// (REQ1-JSON-no-duplicate). Input is one complete RFC 8259 value + only whitespace (REQ1-JSON-single-
// value). UTF-8 mandatory; no Unicode normalization (REQ1-JSON-no-normalization). Number lexemes are
// scanned raw before conversion (64-byte ceiling, exact decimal magnitude) — REQ1-JSON-raw-lexeme.
//
// PERMISSIVENESS CLOSURES (the load-bearing host-runtime discipline):
//  - duplicate-reject: hand-rolled recursive scan with a per-object Set of seen names. NOT JSON.parse
//    (which silently last-wins duplicates). [REQ1-JSON-no-duplicate]
//  - null-prototype: decoded objects are Object.create(null), so a "__proto__" member is DATA, not a
//    prototype mutation. [REQ1-SELECTOR-semantic-identity — ADR 0005:184-192 documents the collapse]
//  - single-value: trailing bytes after the top-level value reject. [REQ1-JSON-single-value]
//  - raw-lexeme: numbers scanned before conversion; magnitude + byte ceiling enforced on the lexeme.
//    [REQ1-JSON-raw-lexeme]
//  - int/float tag: integer vs float distinction preserved (1 ≠ 1.0). [tagged algebra]

export type Tagged =
  | { readonly t: "null" }
  | { readonly t: "bool"; readonly v: boolean }
  | { readonly t: "int"; readonly v: number }
  | { readonly t: "float"; readonly v: number }
  | { readonly t: "string"; readonly v: Uint8Array }
  | { readonly t: "array"; readonly v: Tagged[] }
  | { readonly t: "object"; readonly v: ReadonlyMap<string, Tagged> };

// Null-prototype object tag — markers are Object.create(null) instances, keyed by raw UTF-8 string.
// We store members as a Map keyed by the decoded string (UTF-8 byte sequence); insertion order is
// preserved (Map iteration order = insertion order in JS).

const MAX_INT = 9007199254740991;
const MAX_FLOAT = 9007199254740991;

// Safe byte access: returns -1 for out-of-bounds (so comparisons like `=== 0x22` are always safe).
function byteAt(src: Uint8Array, pos: number): number {
  return pos < src.length ? src[pos]! : -1;
}

interface DecodeCtx {
  readonly src: Uint8Array;
  pos: number; // mutable cursor
  readonly bounds: Bounds;
  nodes: number; // mutable node counter
  depth: number; // mutable depth
}

export function jsonDecode(src: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): Tagged {
  const maxJsonBytes = resolve(bounds, "json_bytes" as MaximaKey);
  if (src.length > maxJsonBytes) fail("json: input exceeds json_bytes bound");
  const ctx: DecodeCtx = { src, pos: 0, bounds, nodes: 0, depth: 0 };
  skipWs(ctx);
  const value = parseValue(ctx, 0);
  // REQ1-JSON-single-value: after the value, only JSON whitespace may remain.
  skipWs(ctx);
  if (ctx.pos !== src.length) fail("json: trailing bytes");
  // total_nodes budget.
  if (ctx.nodes > resolve(bounds, "total_nodes" as MaximaKey)) {
    fail("json: total_nodes bound exceeded");
  }
  return value;
}

function node(ctx: DecodeCtx): void {
  ctx.nodes++;
}

// Per-node-type depth gate (mirrors the official Jcs.encode/Json.decode model, corpus_independent
// .mjs:1913): root value at level 0; a SCALAR is valid at level <= depth; a CONTAINER is valid at
// level < depth (its children sit at level+1). A uniform `level > depth` gate wrongly accepts a
// container at the deepest legal scalar level.
function parseValue(ctx: DecodeCtx, level: number): Tagged {
  const src = ctx.src;
  const c = src[ctx.pos];
  if (c === undefined) fail("json: unexpected end of input");
  let v: Tagged;
  if (c === 0x22 /* " */) {
    if (level > resolve(ctx.bounds, "depth" as MaximaKey)) fail("json: depth bound");
    v = parseString(ctx);
  } else if (c === 0x7b /* { */) {
    if (level >= resolve(ctx.bounds, "depth" as MaximaKey)) fail("json: depth bound");
    v = parseObject(ctx, level + 1);
  } else if (c === 0x5b /* [ */) {
    if (level >= resolve(ctx.bounds, "depth" as MaximaKey)) fail("json: depth bound");
    v = parseArray(ctx, level + 1);
  } else if (c === 0x74 /* t */ || c === 0x66 /* f */) {
    if (level > resolve(ctx.bounds, "depth" as MaximaKey)) fail("json: depth bound");
    v = parseBool(ctx);
  } else if (c === 0x6e /* n */) {
    if (level > resolve(ctx.bounds, "depth" as MaximaKey)) fail("json: depth bound");
    v = parseNull(ctx);
  } else if (c === 0x2d /* - */ || (c >= 0x30 && c <= 0x39)) {
    if (level > resolve(ctx.bounds, "depth" as MaximaKey)) fail("json: depth bound");
    v = parseNumber(ctx);
  } else fail("json: unexpected byte");
  return v;
}

function parseNull(ctx: DecodeCtx): Tagged {
  node(ctx);
  expectLit(ctx, "null");
  return { t: "null" };
}
function parseBool(ctx: DecodeCtx): Tagged {
  node(ctx);
  const c = ctx.src[ctx.pos]!;
  if (c === 0x74 /* t */) {
    expectLit(ctx, "true");
    return { t: "bool", v: true };
  }
  expectLit(ctx, "false");
  return { t: "bool", v: false };
}

function expectLit(ctx: DecodeCtx, lit: string): void {
  const src = ctx.src;
  const pos = ctx.pos;
  for (let i = 0; i < lit.length; i++) {
    if (src[pos + i] !== lit.charCodeAt(i)) fail(`json: expected ${lit}`);
  }
  ctx.pos += lit.length;
}

function parseString(ctx: DecodeCtx): Tagged {
  node(ctx);
  const start = ctx.pos;
  const bytes = scanString(ctx, start);
  // RFC 8259 §2.5 / REQ1-JSON-no-normalization: a JSON string's bytes MUST be valid UTF-8. The
  // scanner copies raw bytes (multi-byte sequences pass through); validate here so an invalid byte
  // (e.g. a lone 0xff) rejects as InvalidError rather than producing a wrong JCS digest or a
  // non-InvalidError TextDecoder throw at a later utf8Str conversion.
  try {
    DECODER.decode(bytes);
  } catch {
    fail("json: string not valid UTF-8");
  }
  if (bytes.length > resolve(ctx.bounds, "string_bytes" as MaximaKey)) fail("json: string_bytes bound");
  return { t: "string", v: bytes };
}

// Scan a JSON string starting at the opening quote; return the decoded UTF-8 bytes. Validates escapes
// and rejects unpaired surrogates / non-UTF-8 (REQ1-JSON-no-normalization: preserve without normalizing,
// but the bytes must be valid UTF-8).
function scanString(ctx: DecodeCtx, start: number): Uint8Array {
  const src = ctx.src;
  // Skip opening quote.
  ctx.pos = start + 1;
  const out: number[] = [];
  for (;;) {
    const c = src[ctx.pos];
    if (c === undefined) fail("json: unterminated string");
    if (c === 0x22 /* " */) {
      ctx.pos++;
      return new Uint8Array(out);
    }
    if (c === 0x5c /* \ */) {
      const e = src[ctx.pos + 1];
      if (e === undefined) fail("json: bad escape");
      ctx.pos += 2;
      switch (e) {
        case 0x22: out.push(0x22); break;
        case 0x5c: out.push(0x5c); break;
        case 0x2f: out.push(0x2f); break;
        case 0x62: out.push(0x08); break;
        case 0x66: out.push(0x0c); break;
        case 0x6e: out.push(0x0a); break;
        case 0x72: out.push(0x0d); break;
        case 0x74: out.push(0x09); break;
        case 0x75: { // \uXXXX — 4 hex digits; handle surrogate pairs.
          const hi = parseHex4(ctx);
          if (hi >= 0xd800 && hi <= 0xdbff) {
            // High surrogate; require \uXXXX low surrogate.
            if (src[ctx.pos] !== 0x5c || src[ctx.pos + 1] !== 0x75) {
              fail("json: unpaired high surrogate");
            }
            ctx.pos += 2;
            const lo = parseHex4(ctx);
            if (lo < 0xdc00 || lo > 0xdfff) fail("json: bad low surrogate");
            const cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
            encodeUtf8(cp, out);
          } else if (hi >= 0xdc00 && hi <= 0xdfff) {
            fail("json: unpaired low surrogate");
          } else {
            encodeUtf8(hi, out);
          }
          break;
        }
        default: fail("json: bad escape");
      }
    } else if (c < 0x20) {
      fail("json: unescaped control byte");
    } else {
      // Copy raw byte (UTF-8 multi-byte sequences pass through as-is; validity checked at decode).
      out.push(c);
      ctx.pos++;
    }
  }
}

function parseHex4(ctx: DecodeCtx): number {
  const src = ctx.src;
  let v = 0;
  for (let i = 0; i < 4; i++) {
    const c = src[ctx.pos];
    if (c === undefined) fail("json: bad \\u escape");
    let d: number;
    if (c >= 0x30 && c <= 0x39) d = c - 0x30;
    else if (c >= 0x41 && c <= 0x46) d = c - 0x41 + 10;
    else if (c >= 0x61 && c <= 0x66) d = c - 0x61 + 10;
    else fail("json: bad \\u hex");
    v = (v << 4) | d;
    ctx.pos++;
  }
  return v;
}

function encodeUtf8(cp: number, out: number[]): void {
  if (cp < 0x80) out.push(cp);
  else if (cp < 0x800) {
    out.push(0xc0 | (cp >> 6));
    out.push(0x80 | (cp & 0x3f));
  } else if (cp < 0x10000) {
    out.push(0xe0 | (cp >> 12));
    out.push(0x80 | ((cp >> 6) & 0x3f));
    out.push(0x80 | (cp & 0x3f));
  } else {
    out.push(0xf0 | (cp >> 18));
    out.push(0x80 | ((cp >> 12) & 0x3f));
    out.push(0x80 | ((cp >> 6) & 0x3f));
    out.push(0x80 | (cp & 0x3f));
  }
}

function parseNumber(ctx: DecodeCtx): Tagged {
  node(ctx);
  const src = ctx.src;
  const start = ctx.pos;
  // Scan the RFC 8259 number lexeme: optional -, int part, optional frac, optional exp.
  let pos = start;
  if (byteAt(src, pos) === 0x2d /* - */) pos++;
  // Integer part: 0 or [1-9][0-9]*
  if (byteAt(src, pos) === 0x30) pos++;
  else {
    const c = byteAt(src, pos);
    if (c >= 0x31 && c <= 0x39) {
      pos++;
      let d = byteAt(src, pos);
      while (d >= 0x30 && d <= 0x39) { pos++; d = byteAt(src, pos); }
    } else fail("json: bad number");
  }
  let isFloat = false;
  if (byteAt(src, pos) === 0x2e /* . */) {
    isFloat = true;
    pos++;
    const f = byteAt(src, pos);
    if (!(f >= 0x30 && f <= 0x39)) fail("json: bad fraction");
    let fd = byteAt(src, pos);
    while (fd >= 0x30 && fd <= 0x39) { pos++; fd = byteAt(src, pos); }
  }
  const ec = byteAt(src, pos);
  if (ec === 0x65 /* e */ || ec === 0x45 /* E */) {
    isFloat = true;
    pos++;
    const sign = byteAt(src, pos);
    if (sign === 0x2b || sign === 0x2d) pos++;
    const e = byteAt(src, pos);
    if (!(e >= 0x30 && e <= 0x39)) fail("json: bad exponent");
    let ed = byteAt(src, pos);
    while (ed >= 0x30 && ed <= 0x39) { pos++; ed = byteAt(src, pos); }
  }
  const lexemeEnd = pos;
  const lexeme = src.subarray(start, lexemeEnd);
  // REQ1-JSON-raw-lexeme: 64-byte ceiling on the lexeme.
  if (lexeme.length > resolve(ctx.bounds, "number_lexeme_bytes" as MaximaKey)) {
    fail("json: number lexeme exceeds bound");
  }
  ctx.pos = lexemeEnd;
  const text = asciiStr(lexeme);
  if (isFloat) {
    // REQ1-JSON-raw-lexeme: check the magnitude of the RAW lexeme by decimal arithmetic BEFORE
    // Number() conversion. A lexeme like "9007199254740991.0001" rounds to the max binary64 value
    // under Number(), so a post-conversion Math.abs(n) > MAX check accepts it — defeating the exact
    // bound. The reference (json.ex magnitude_within?) compares the lexeme's significant digits
    // against the maximum's digit string. Mirror that here.
    if (!lexemeMagnitudeWithin(text, MAX_FLOAT)) fail("json: float magnitude bound");
    const n = Number(text);
    if (!Number.isFinite(n)) fail("json: float not finite");
    return { t: "float", v: n };
  }
  if (!lexemeMagnitudeWithin(text, MAX_INT)) fail("json: integer magnitude bound");
  const n = Number(text);
  if (!Number.isSafeInteger(n)) fail("json: integer magnitude bound or unsafe");
  return { t: "int", v: n };
}

// Exact decimal magnitude check of a number lexeme against `maximum`, mirroring the reference
// (json.ex:298-349 magnitude_within? / compare_boundary). Returns true if |value| <= maximum.
// Compares the lexeme's significant digits by their effective integer position — NOT the float
// value (which loses precision). Handles sign, fraction, and exponent exactly.
function lexemeMagnitudeWithin(text: string, maximum: number): boolean {
  const unsigned = text[0] === "-" || text[0] === "+" ? text.slice(1) : text;
  // Split mantissa / exponent (sign already validated by the scanner).
  let mantissa = unsigned;
  let exponent = 0;
  const eIdx = unsigned.search(/[eE]/);
  if (eIdx !== -1) {
    mantissa = unsigned.slice(0, eIdx);
    exponent = parseInt(unsigned.slice(eIdx + 1), 10);
  }
  let integerDigits = mantissa;
  let fractionDigits = "";
  const dotIdx = mantissa.indexOf(".");
  if (dotIdx !== -1) {
    integerDigits = mantissa.slice(0, dotIdx);
    fractionDigits = mantissa.slice(dotIdx + 1);
  }
  const digits = (integerDigits + fractionDigits).replace(/^0+/, "");
  if (digits === "") return true; // value is zero
  const maximumDigits = String(maximum);
  // Effective integer-position of the last significant digit (reference's integer_length).
  const integerLength = digits.length + exponent - fractionDigits.length;
  if (integerLength < maximumDigits.length) return true;
  if (integerLength > maximumDigits.length) return false;
  // Same digit-count boundary: compare the leading integer_part (padded/truncated to maximum's
  // length) then require the leftover fractional_part to be all-zero if equal (compare_boundary).
  const maximumLength = maximumDigits.length;
  let integerPart: string;
  let fractionalPart: string;
  if (digits.length >= maximumLength) {
    integerPart = digits.slice(0, maximumLength);
    fractionalPart = digits.slice(maximumLength);
  } else {
    integerPart = digits + "0".repeat(maximumLength - digits.length);
    fractionalPart = "";
  }
  return integerPart < maximumDigits || (
    integerPart === maximumDigits && /^[0]*$/.test(fractionalPart)
  );
}

// Null-prototype object parse: Object.create(null) shape; duplicate keys reject at every depth.
function parseObject(ctx: DecodeCtx, childLevel: number): Tagged {
  node(ctx);
  const src = ctx.src;
  ctx.pos++; // skip {
  const members = new Map<string, Tagged>();
  let count = 0;
  skipWs(ctx);
  if (src[ctx.pos] === 0x7d /* } */) {
    ctx.pos++;
    return { t: "object", v: members };
  }
  for (;;) {
    skipWs(ctx);
    if (src[ctx.pos] !== 0x22 /* " */) fail("json: expected member name");
    const nameBytes = scanString(ctx, ctx.pos);
    if (nameBytes.length > resolve(ctx.bounds, "key_bytes" as MaximaKey)) fail("json: key_bytes bound");
    // A member name's bytes MUST be valid UTF-8 (RFC 8259 §2.5 / REQ1-JSON-no-normalization).
    // Validate before utf8Str so a lone 0xff in a name fails closed as InvalidError rather than
    // throwing a non-InvalidError TypeError via the fatal TextDecoder (matches parseString above).
    try {
      DECODER.decode(nameBytes);
    } catch {
      fail("json: member name not valid UTF-8");
    }
    const nameStr = utf8Str(nameBytes);
    // REQ1-JSON-no-duplicate: reject before map conversion.
    if (members.has(nameStr)) fail("json: duplicate member");
    skipWs(ctx);
    if (src[ctx.pos] !== 0x3a /* : */) fail("json: expected colon");
    ctx.pos++;
    skipWs(ctx);
    const value = parseValue(ctx, childLevel);
    members.set(nameStr, value);
    count++;
    if (count > resolve(ctx.bounds, "object_members" as MaximaKey)) fail("json: object_members bound");
    skipWs(ctx);
    const sep = src[ctx.pos];
    if (sep === 0x2c /* , */) {
      ctx.pos++;
      continue;
    }
    if (sep === 0x7d /* } */) {
      ctx.pos++;
      break;
    }
    fail("json: expected , or }");
  }
  return { t: "object", v: members };
}

function parseArray(ctx: DecodeCtx, childLevel: number): Tagged {
  node(ctx);
  const src = ctx.src;
  ctx.pos++; // skip [
  const items: Tagged[] = [];
  skipWs(ctx);
  if (src[ctx.pos] === 0x5d /* ] */) {
    ctx.pos++;
    return { t: "array", v: items };
  }
  for (;;) {
    skipWs(ctx);
    const value = parseValue(ctx, childLevel);
    items.push(value);
    if (items.length > resolve(ctx.bounds, "array_items" as MaximaKey)) fail("json: array_items bound");
    skipWs(ctx);
    const sep = src[ctx.pos];
    if (sep === 0x2c /* , */) {
      ctx.pos++;
      continue;
    }
    if (sep === 0x5d /* ] */) {
      ctx.pos++;
      break;
    }
    fail("json: expected , or ]");
  }
  return { t: "array", v: items };
}

const WS = new Set([0x20, 0x09, 0x0a, 0x0d]);
function skipWs(ctx: DecodeCtx): void {
  const src = ctx.src;
  while (WS.has(src[ctx.pos] ?? -1)) ctx.pos++;
}

function asciiStr(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return s;
}

// UTF-8 decode (TextDecoder is allowed in the library path — it is a pure transformation, not I/O).
const DECODER = new TextDecoder("utf-8", { fatal: true });
const ENCODER = new TextEncoder();
export function utf8Str(bytes: Uint8Array): string {
  return DECODER.decode(bytes);
}
export function strUtf8(s: string): Uint8Array {
  return ENCODER.encode(s);
}
