// Test-only pure-BigInt Ed25519 reference arithmetic. It shares no code with src/ed25519.ts: the
// unit tests derive the small-order table, the weak-encoding census, torsion variants and the
// key-holder forgeries from this module, so a defect in the library's tables or arithmetic cannot
// be mirrored here. Verdicts come from group arithmetic only (RFC 8032 section 5.1): no backend, no
// byte table. Not part of the published package (the package "files" list is dist only).
//
// Points use extended twisted Edwards coordinates (X:Y:Z:T), a = -1, with the complete
// add-2008-hwcd-3 law, so the identity and every torsion point share one formula.
import { createHash } from "node:crypto";

export const P = 2n ** 255n - 19n;
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const mod = (x: bigint): bigint => {
  const r = x % P;
  return r < 0n ? r + P : r;
};

export function powmod(base: bigint, exponent: bigint, modulus: bigint = P): bigint {
  let result = 1n;
  let b = base % modulus;
  if (b < 0n) b += modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

const inv = (x: bigint): bigint => powmod(x, P - 2n);
export const D = mod(-121665n * inv(121666n));
const SQRT_M1 = powmod(2n, (P - 1n) / 4n);
const D2 = mod(2n * D);

export type Point = readonly [bigint, bigint, bigint, bigint];
export const IDENTITY: Point = [0n, 1n, 1n, 0n];

export function add(p1: Point, p2: Point): Point {
  const [x1, y1, z1, t1] = p1;
  const [x2, y2, z2, t2] = p2;
  const a = mod((y1 - x1) * (y2 - x2));
  const b = mod((y1 + x1) * (y2 + x2));
  const c = mod(t1 * D2 * t2);
  const d = mod(2n * z1 * z2);
  const e = b - a;
  const f = d - c;
  const g = d + c;
  const h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}

export function negate([x, y, z, t]: Point): Point {
  return [mod(-x), y, z, mod(-t)];
}

export function multiply(scalar: bigint, point: Point): Point {
  if (scalar < 0n) throw new Error("negative scalar");
  let result: Point = IDENTITY;
  let addend = point;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) result = add(result, addend);
    addend = add(addend, addend);
    k >>= 1n;
  }
  return result;
}

export function pointEquals([x1, y1, z1]: Point, [x2, y2, z2]: Point): boolean {
  return mod(x1 * z2 - x2 * z1) === 0n && mod(y1 * z2 - y2 * z1) === 0n;
}

export const isIdentity = (point: Point): boolean => pointEquals(point, IDENTITY);

export function leToBig(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

export function bigToLe(value: bigint, width: number): Uint8Array {
  const out = new Uint8Array(width);
  let v = value;
  for (let i = 0; i < width; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error("value does not fit width");
  return out;
}

export function encodePoint([x, y, z]: Point): Uint8Array {
  const zi = inv(z);
  const ax = mod(x * zi);
  const ay = mod(y * zi);
  return bigToLe(ay | ((ax & 1n) << 255n), 32);
}

function recoverX(y: bigint, sign: bigint): { x: bigint; zeroWithSign: boolean } | null {
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  const x2 = mod(u * inv(v));
  if (x2 === 0n) return { x: 0n, zeroWithSign: sign === 1n };
  let x = powmod(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - x2) !== 0n) return null;
  if ((x & 1n) !== sign) x = P - x;
  return { x, zeroWithSign: false };
}

export type Encoding =
  | { kind: "point"; point: Point }
  | { kind: "noncanonical"; point: Point | null }
  | { kind: "offcurve" };

// Classifies a 32-byte encoding by the strict RFC 8032 section 5.1.3 decode: canonical (y < p, no
// sign bit when x = 0) and on the curve, or the lenient (reduce-y, drop-sign) reading when not
// canonical, or off the curve.
export function classifyEncoding(bytes: Uint8Array): Encoding {
  if (bytes.length !== 32) throw new Error("32-byte encoding required");
  const v = leToBig(bytes);
  const sign = v >> 255n;
  let y = v & ((1n << 255n) - 1n);
  let noncanonical = false;
  if (y >= P) {
    noncanonical = true;
    y -= P;
  }
  const recovered = recoverX(y, sign);
  if (recovered === null) return noncanonical ? { kind: "noncanonical", point: null } : { kind: "offcurve" };
  if (recovered.zeroWithSign) noncanonical = true;
  const point: Point = [recovered.x, y, 1n, mod(recovered.x * y)];
  return noncanonical ? { kind: "noncanonical", point } : { kind: "point", point };
}

export function strictDecode(bytes: Uint8Array): Point | null {
  const c = classifyEncoding(bytes);
  return c.kind === "point" ? c.point : null;
}

export const BASE: Point = (() => {
  const point = strictDecode(bigToLe(mod(4n * inv(5n)), 32));
  if (point === null) throw new Error("base point decode failed");
  return point;
})();

export const isSmallOrder = (point: Point): boolean => isIdentity(multiply(8n, point));
export const isTorsionFree = (point: Point): boolean => isIdentity(multiply(L, point));

export function sha512(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha512");
  for (const part of parts) h.update(part);
  return new Uint8Array(h.digest());
}

export function challenge(r: Uint8Array, a: Uint8Array, message: Uint8Array): bigint {
  return leToBig(sha512(r, a, message)) % L;
}

export const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

// S1 verify_strict by pure arithmetic: strict decode of A and R, [8]P = O small-order test, S < L,
// then the cofactorless equation encode([S]B - [k]A) == R, byte for byte.
export function verifyStrictReference(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const rBytes = signature.subarray(0, 32);
  const s = leToBig(signature.subarray(32));
  const a = classifyEncoding(publicKey);
  if (a.kind !== "point" || isSmallOrder(a.point)) return false;
  const r = classifyEncoding(rBytes);
  if (r.kind === "noncanonical") return false;
  if (r.kind === "point" && isSmallOrder(r.point)) return false;
  if (s >= L) return false;
  const k = challenge(rBytes, publicKey, message);
  const lhs = add(multiply(s, BASE), negate(multiply(k, a.point)));
  return eq(encodePoint(lhs), rBytes);
}

export const acceptableReference = (publicKey: Uint8Array): boolean => {
  if (publicKey.length !== 32) return false;
  const a = classifyEncoding(publicKey);
  return a.kind === "point" && !isSmallOrder(a.point);
};

export const torsionFreeReference = (publicKey: Uint8Array): boolean => {
  if (!acceptableReference(publicKey)) return false;
  return isTorsionFree(strictDecode(publicKey)!);
};

export function expandSeed(seed: Uint8Array): { scalar: bigint; prefix: Uint8Array } {
  const h = sha512(seed);
  let a = leToBig(h.subarray(0, 32));
  a &= (1n << 254n) - 8n;
  a |= 1n << 254n;
  return { scalar: a, prefix: h.subarray(32) };
}

export const publicKeyFromSeed = (seed: Uint8Array): Uint8Array =>
  encodePoint(multiply(expandSeed(seed).scalar, BASE));

// RFC 8032 section 5.1.6, deterministic.
export function signHonest(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const { scalar, prefix } = expandSeed(seed);
  const publicKey = publicKeyFromSeed(seed);
  const r = leToBig(sha512(prefix, message)) % L;
  const rBytes = encodePoint(multiply(r, BASE));
  const s = (r + challenge(rBytes, publicKey, message) * scalar) % L;
  return concat(rBytes, bigToLe(s, 32));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// The 8 points of E[8] as multiples of one order-8 point, derived by arithmetic: T[i] = [i]T1.
export function torsionPoints(): Point[] {
  for (let y = 2n; ; y += 1n) {
    const candidate = strictDecode(bigToLe(y, 32));
    if (candidate === null) continue;
    const t = multiply(L, candidate);
    if (!isIdentity(multiply(4n, t))) {
      const points: Point[] = [];
      let acc: Point = IDENTITY;
      for (let i = 0; i < 8; i += 1) {
        points.push(acc);
        acc = add(acc, t);
      }
      return points;
    }
  }
}

export const smallOrderEncodings = (): Uint8Array[] => torsionPoints().map(encodePoint);

// Every weak 32-byte encoding by enumeration: the 8 canonical small-order encodings, the 38
// encodings with y >= p (19 values of y, both sign bits), and the 2 x = 0 encodings that carry the
// sign bit (y = 1 and y = p - 1). 48 in all.
export function weakEncodings(): Uint8Array[] {
  const out = smallOrderEncodings();
  for (let y = P; y < 1n << 255n; y += 1n) {
    out.push(bigToLe(y, 32), bigToLe(y | (1n << 255n), 32));
  }
  out.push(bigToLe(1n | (1n << 255n), 32), bigToLe((P - 1n) | (1n << 255n), 32));
  return out;
}

// A canonical y with no square root: an off-curve encoding.
export function offCurveEncodings(count: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let y = 2n; out.length < count; y += 1n) {
    const bytes = bigToLe(y, 32);
    if (classifyEncoding(bytes).kind === "offcurve") out.push(bytes);
  }
  return out;
}

export interface KeyHolder {
  readonly seed: Uint8Array;
  readonly scalar: bigint;
  readonly prime: Point; // A0 = [a]B
}

export function keyHolder(seed: Uint8Array): KeyHolder {
  const { scalar } = expandSeed(seed);
  return { seed, scalar, prime: multiply(scalar, BASE) };
}

// A signature by the key holder over (R, A, M) for a caller-chosen R point and public key encoding:
// S = r + k a (mod L) where R = [r]B + rTorsion. Used to build vectors that violate exactly one
// rule. `r` is the prime part of R; the torsion part of R and of A are the caller's concern.
export function signWith(
  holder: KeyHolder, r: bigint, rPoint: Point, publicKeyBytes: Uint8Array, message: Uint8Array,
): Uint8Array {
  const rBytes = encodePoint(rPoint);
  const k = challenge(rBytes, publicKeyBytes, message);
  return concat(rBytes, bigToLe((r + k * holder.scalar) % L, 32));
}

// Searches message suffixes until the signature R || S built by the key holder over the torsion
// pair (rTorsion, aTorsion) satisfies the cofactorless equation: [S]B = R + [k]A needs
// rTorsion + k aTorsion = O. Returns the message and signature that verify on an ungated backend.
export function findCofactorlessSignature(
  holder: KeyHolder, aTorsion: Point, rTorsion: Point, r: bigint, prefix: string,
): { message: Uint8Array; signature: Uint8Array; publicKey: Uint8Array } {
  const publicKey = encodePoint(add(holder.prime, aTorsion));
  const rPoint = add(multiply(r, BASE), rTorsion);
  for (let n = 0; n < 4096; n += 1) {
    const message = new TextEncoder().encode(`${prefix}-${n}`);
    const signature = signWith(holder, r, rPoint, publicKey, message);
    const lhs = multiply(leToBig(signature.subarray(32)), BASE);
    const k = challenge(signature.subarray(0, 32), publicKey, message);
    const rhs = add(rPoint, multiply(k, add(holder.prime, aTorsion)));
    if (pointEquals(lhs, rhs)) return { message, signature, publicKey };
  }
  throw new Error("no cofactorless signature found");
}

// What an UNGATED lenient cofactorless backend computes (ref10 / OpenSSL shape: lenient decode of A,
// S < L, R compared byte for byte). A forged vector must satisfy this, which proves it is a real
// forgery (accepted without the strict rule) and not just malformed.
export function verifyUngatedCofactorless(
  publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array,
): boolean {
  const a = classifyEncoding(publicKey);
  if (a.kind === "offcurve" || a.point === null) return false;
  const rBytes = signature.subarray(0, 32);
  const s = leToBig(signature.subarray(32));
  if (s >= L) return false;
  const k = challenge(rBytes, publicKey, message);
  const lhs = add(multiply(s, BASE), negate(multiply(k, a.point)));
  return eq(encodePoint(lhs), rBytes);
}

// A forgery that needs no secret: public key A of small order (any of the 8 points or an alias that
// decodes to one), S = 0, and R the small-order point with R + [k]A = O. `next` yields candidate
// messages; the first message for which some R works is returned.
export function forgeUnderSmallOrderKey(
  publicKey: Uint8Array, next: (n: number) => Uint8Array,
): { n: number; message: Uint8Array; signature: Uint8Array } {
  const decoded = classifyEncoding(publicKey);
  if (decoded.kind === "offcurve" || decoded.point === null) throw new Error("not a point");
  const a = decoded.point;
  const rs = smallOrderEncodings();
  const rPoints = torsionPoints();
  for (let n = 0; n < 4096; n += 1) {
    const message = next(n);
    for (let i = 0; i < 8; i += 1) {
      const k = challenge(rs[i]!, publicKey, message);
      if (isIdentity(add(rPoints[i]!, multiply(k, a)))) {
        return { n, message, signature: concat(rs[i]!, new Uint8Array(32)) };
      }
    }
  }
  throw new Error("no forgery found");
}
