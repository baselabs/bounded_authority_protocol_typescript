import { fail } from "./error.js";

// Unpadded base64url decode + encode, canonical per REQ1-B64-* (protocol-v1.md:107-110):
//   - REQ1-B64-alphabet: only A-Za-z0-9-_ (no +/, no padding =, no whitespace)
//   - REQ1-B64-no-padding: padding/whitespace forbidden
//   - REQ1-B64-length: length mod 4 == 1 is invalid (cannot decode)
//   - REQ1-B64-canonical: decode succeeds only if unpadded re-encode reproduces the input exactly
//
// Derived from protocol-v1.md § base64url + RFC 4648 §5. NOT using Buffer.from(s, "base64url") for
// decode because Node's base64url accepts padding/whitespace and is permissive; the bounds-checked
// canonical decoder is hand-rolled.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const REV = new Int8Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) REV[ALPHABET.charCodeAt(i)] = i;

// Reject any byte that is not in the alphabet (covers +, /, = padding, whitespace, control chars).
function classifyByte(byte: number): number {
  return byte >= 0 && byte < 128 ? REV[byte]! : -1;
}

export function base64urlDecode(input: Uint8Array, maxDecodedBytes?: number): Uint8Array {
  const len = input.length;
  // REQ1-B64-length: length mod 4 == 1 is structurally invalid.
  if (len % 4 === 1) fail("base64url: invalid length mod 4 == 1");
  // The decoded length is deterministic from the input length + tail.
  let outLen = (len >> 2) * 3;
  if (len % 4 === 2) outLen += 1;
  else if (len % 4 === 3) outLen += 2;
  if (maxDecodedBytes !== undefined && outLen > maxDecodedBytes) {
    fail("base64url: decoded length exceeds bound");
  }
  const out = new Uint8Array(outLen);
  let op = 0;
  let i = 0;
  // Full 4-char groups → 3 bytes.
  const full = len - (len % 4 === 0 ? 0 : len % 4);
  while (i < full) {
    const a = classifyByte(input[i++]!);
    const b = classifyByte(input[i++]!);
    const c = classifyByte(input[i++]!);
    const d = classifyByte(input[i++]!);
    if (a < 0 || b < 0 || c < 0 || d < 0) fail("base64url: non-alphabet byte");
    out[op++] = (a << 2) | (b >> 4);
    out[op++] = (b << 4) | (c >> 2);
    out[op++] = (c << 6) | d;
  }
  // Tail group.
  const rem = len - i;
  if (rem === 2) {
    const a = classifyByte(input[i++]!);
    const b = classifyByte(input[i++]!);
    if (a < 0 || b < 0) fail("base64url: non-alphabet byte");
    out[op++] = (a << 2) | (b >> 4);
  } else if (rem === 3) {
    const a = classifyByte(input[i++]!);
    const b = classifyByte(input[i++]!);
    const c = classifyByte(input[i++]!);
    if (a < 0 || b < 0 || c < 0) fail("base64url: non-alphabet byte");
    out[op++] = (a << 2) | (b >> 4);
    out[op++] = (b << 4) | (c >> 2);
  }
  // REQ1-B64-canonical: re-encode the decoded bytes; the unpadded form must reproduce the input.
  const reEncoded = base64urlEncode(out.subarray(0, op));
  if (reEncoded.length !== len || !bytesEqual(reEncoded, input)) {
    fail("base64url: non-canonical input");
  }
  return out.subarray(0, op);
}

export function base64urlEncode(input: Uint8Array): Uint8Array {
  const len = input.length;
  const outLen = ((len + 2) / 3 | 0) * 4;
  // Trim the padding: unpadded output length.
  const rem = len % 3;
  const padded = rem === 0 ? outLen : outLen - (3 - rem);
  const out = new Uint8Array(padded);
  let op = 0;
  let i = 0;
  const full = len - rem;
  while (i < full) {
    const a = input[i++]!;
    const b = input[i++]!;
    const c = input[i++]!;
    out[op++] = ALPHABET.charCodeAt(a >> 2);
    out[op++] = ALPHABET.charCodeAt(((a & 0x03) << 4) | (b >> 4));
    out[op++] = ALPHABET.charCodeAt(((b & 0x0f) << 2) | (c >> 6));
    out[op++] = ALPHABET.charCodeAt(c & 0x3f);
  }
  if (rem === 1) {
    const a = input[i++]!;
    out[op++] = ALPHABET.charCodeAt(a >> 2);
    out[op++] = ALPHABET.charCodeAt((a & 0x03) << 4);
  } else if (rem === 2) {
    const a = input[i++]!;
    const b = input[i++]!;
    out[op++] = ALPHABET.charCodeAt(a >> 2);
    out[op++] = ALPHABET.charCodeAt(((a & 0x03) << 4) | (b >> 4));
    out[op++] = ALPHABET.charCodeAt((b & 0x0f) << 2);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
