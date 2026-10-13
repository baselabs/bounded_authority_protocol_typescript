// RFC 3629 UTF-8 admission in the JCS string encoder. The lead-byte payload mask in the validator was
// `0x1f >> need`, which cuts the high payload bits of every 2-, 3- and 4-byte lead above its
// threshold and falsely rejected whole ranges: U+0400..U+047F, U+8000..U+87FF and U+100000..U+10FFFF.
// The reference accepts every Unicode scalar value, so a false reject is an interoperability and
// availability defect. These tests sweep every scalar value (including all three ranges, exhaustively)
// against the platform UTF-8 encoder, and pin the invalid sequences the validator must keep rejecting.
import { test } from "node:test";
import assert from "node:assert/strict";

import { jcsEncode } from "../src/jcs.js";
import { InvalidError } from "../src/error.js";
import type { Tagged } from "../src/json.js";

const str = (bytes: Uint8Array): Tagged => ({ t: "string", v: bytes });
const encoder = new TextEncoder();

function encodeOrNull(bytes: Uint8Array): Uint8Array | null {
  try {
    return jcsEncode(str(bytes));
  } catch (e) {
    if (e instanceof InvalidError) return null;
    throw e;
  }
}

// A scalar value that RFC 8785 serializes raw: not a C0 control, not the quote or the backslash.
const isRaw = (cp: number) => cp >= 0x20 && cp !== 0x22 && cp !== 0x5c;

function expectedFor(cp: number): Uint8Array {
  const body = encoder.encode(String.fromCodePoint(cp));
  const out = new Uint8Array(body.length + 2);
  out[0] = 0x22;
  out.set(body, 1);
  out[out.length - 1] = 0x22;
  return out;
}

function sweep(from: number, to: number): { checked: number; wrong: number[] } {
  const wrong: number[] = [];
  let checked = 0;
  for (let cp = from; cp <= to; cp += 1) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue; // surrogates are not scalar values
    if (!isRaw(cp)) continue;
    checked += 1;
    const got = encodeOrNull(encoder.encode(String.fromCodePoint(cp)));
    const want = expectedFor(cp);
    if (got === null || got.length !== want.length || !got.every((b, i) => b === want[i])) wrong.push(cp);
  }
  return { checked, wrong };
}

const BOUNDARIES = [
  0x03ff, 0x0400, 0x043f, 0x0440, 0x047f, 0x0480, 0x07ff, 0x0800, 0x7fff, 0x8000, 0x803f, 0x8040,
  0x87ff, 0x8800, 0xd7ff, 0xe000, 0xfffd, 0xffff, 0x10000, 0xfffff, 0x100000, 0x10ffff,
];

for (const cp of BOUNDARIES) {
  test(`jcsEncode admits U+${cp.toString(16).toUpperCase().padStart(4, "0")} byte for byte`, () => {
    const got = encodeOrNull(encoder.encode(String.fromCodePoint(cp)));
    assert.notEqual(got, null);
    assert.deepEqual([...got!], [...expectedFor(cp)]);
  });
}

test("jcsEncode admits every code point in U+0400..U+047F (2-byte leads D0 and D1)", () => {
  const { checked, wrong } = sweep(0x0400, 0x047f);
  assert.equal(checked, 0x80);
  assert.deepEqual(wrong, []);
});

test("jcsEncode admits every code point in U+8000..U+87FF (3-byte lead E8 and its neighbors)", () => {
  const { checked, wrong } = sweep(0x8000, 0x87ff);
  assert.equal(checked, 0x800);
  assert.deepEqual(wrong, []);
});

test("jcsEncode admits every code point in U+100000..U+10FFFF (4-byte lead F4)", () => {
  const { checked, wrong } = sweep(0x100000, 0x10ffff);
  assert.equal(checked, 0x10000);
  assert.deepEqual(wrong, []);
});

test("jcsEncode admits every Unicode scalar value U+0020..U+10FFFF and encodes it byte for byte", () => {
  const { checked, wrong } = sweep(0x20, 0x10ffff);
  assert.equal(checked, 0x10ffff - 0x20 + 1 - 0x800 - 2); // minus the surrogates, the quote and the backslash
  assert.deepEqual(wrong, []);
});

const INVALID: Array<[string, number[]]> = [
  ["overlong C0 80", [0xc0, 0x80]],
  ["overlong C1 BF", [0xc1, 0xbf]],
  ["overlong E0 80 80", [0xe0, 0x80, 0x80]],
  ["overlong E0 9F BF", [0xe0, 0x9f, 0xbf]],
  ["overlong F0 80 80 80", [0xf0, 0x80, 0x80, 0x80]],
  ["overlong F0 8F BF BF", [0xf0, 0x8f, 0xbf, 0xbf]],
  ["surrogate ED A0 80", [0xed, 0xa0, 0x80]],
  ["surrogate ED BF BF", [0xed, 0xbf, 0xbf]],
  ["above U+10FFFF F4 90 80 80", [0xf4, 0x90, 0x80, 0x80]],
  ["above U+10FFFF F7 BF BF BF", [0xf7, 0xbf, 0xbf, 0xbf]],
  ["lead F5 80 80 80", [0xf5, 0x80, 0x80, 0x80]],
  ["lead F8", [0xf8, 0x88, 0x80, 0x80, 0x80]],
  ["lead FF", [0xff]],
  ["stray continuation 80", [0x80]],
  ["stray continuation BF", [0xbf]],
  ["truncated 2-byte", [0xd0]],
  ["truncated 3-byte", [0xe8, 0x80]],
  ["truncated 4-byte", [0xf4, 0x8f, 0xbf]],
  ["bad continuation in 2-byte", [0xd0, 0x41]],
  ["bad continuation in 3-byte", [0xe8, 0x80, 0x41]],
  ["bad continuation in 4-byte", [0xf4, 0x8f, 0xbf, 0x41]],
];

for (const [name, bytes] of INVALID) {
  test(`jcsEncode rejects invalid UTF-8: ${name}`, () => {
    assert.equal(encodeOrNull(Uint8Array.from(bytes)), null);
  });
}

test("jcsEncode accepts the highest valid sequences next to the rejected ones", () => {
  // F4 8F BF BF is U+10FFFF (valid); F4 90 80 80 is U+110000 (invalid). ED 9F BF is U+D7FF (valid);
  // ED A0 80 is U+D800 (invalid). The pair pins both edges of each exclusion.
  assert.notEqual(encodeOrNull(Uint8Array.from([0xf4, 0x8f, 0xbf, 0xbf])), null);
  assert.equal(encodeOrNull(Uint8Array.from([0xf4, 0x90, 0x80, 0x80])), null);
  assert.notEqual(encodeOrNull(Uint8Array.from([0xed, 0x9f, 0xbf])), null);
  assert.equal(encodeOrNull(Uint8Array.from([0xed, 0xa0, 0x80])), null);
});

test("jcsEncode keeps a leading U+FEFF in a value and in a member name (no byte-order-mark strip)", () => {
  const bom = "﻿";
  const value = jcsEncode(str(encoder.encode(`${bom}a`)));
  assert.deepEqual([...value], [0x22, 0xef, 0xbb, 0xbf, 0x61, 0x22]);
  const members = new Map<string, Tagged>([[`${bom}k`, str(encoder.encode("v"))]]);
  const object = jcsEncode({ t: "object", v: members });
  assert.deepEqual([...object], [...encoder.encode(`{"${bom}k":"v"}`)]);
});
