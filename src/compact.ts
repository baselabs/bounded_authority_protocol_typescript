import { fail, assert, trying, type Result } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { resolve, coerceBounds, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";
import { signatureGate } from "./ed25519.js";

// JWS compact serialization has three base64url segments separated by dots. The exact signing
// input is ASCII(base64url(protected) + "." + base64url(payload)); the signature segment is
// excluded. See RFC 7515 and REQ1-SIGNING-exact-input.

export interface CompactSegments {
  readonly protectedSegment: Uint8Array; // the raw base64url TEXT (not decoded)
  readonly payloadSegment: Uint8Array;
  readonly signature: Uint8Array; // decoded raw bytes (64 for Ed25519)
  readonly protectedBytes: Uint8Array; // decoded
  readonly payloadBytes: Uint8Array; // decoded
  readonly signingInput: Uint8Array; // ASCII(protected "." payload) text
}

const DOT = 0x2e;

// Parse + bound a compact input into 3 segments. Validates the segment count, bounds, canonical
// base64url of each segment, and decodes protected + payload (signature kept raw after decode).
export function parseCompact(input: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): CompactSegments {
  // Re-validate caller-supplied bounds (a hand-crafted Bounds can widen limits past MAXIMA,
  // bypassing boundsNew). Mirrors the reference's Bounds.coerce on every entry point.
  const b = coerceBounds(bounds);
  if (input.length > resolve(b, "compact_bytes" as MaximaKey)) fail("compact: byte bound");
  if (input.length === 0) fail("compact: empty");
  // Split into exactly 3 segments on '.'.
  const dots: number[] = [];
  for (let i = 0; i < input.length; i++) if (input[i] === DOT) dots.push(i);
  if (dots.length !== 2) fail("compact: three segments");
  const d0 = dots[0]!;
  const d1 = dots[1]!;
  if (d0 === 0 || d1 === d0 + 1 || d1 === input.length - 1) fail("compact: empty segment");
  const protectedText = input.subarray(0, d0);
  const payloadText = input.subarray(d0 + 1, d1);
  const signatureText = input.subarray(d1 + 1);
  if (protectedText.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) fail("compact: protected segment bound");
  if (payloadText.length > resolve(b, "encoded_segment_bytes" as MaximaKey)) fail("compact: payload segment bound");
  const protectedBytes = base64urlDecode(protectedText, resolve(b, "decoded_segment_bytes" as MaximaKey));
  const payloadBytes = base64urlDecode(payloadText, resolve(b, "decoded_segment_bytes" as MaximaKey));
  const signature = base64urlDecode(signatureText);
  // The decode path requires the decoded signature to match signature_bytes. The ath/hash
  // structural scan deliberately omits this check because it does not decode signature bytes.
  if (signature.length !== resolve(b, "signature_bytes" as MaximaKey)) fail("compact: signature width");
  return {
    protectedSegment: protectedText,
    payloadSegment: payloadText,
    signature,
    protectedBytes,
    payloadBytes,
    signingInput: concat(protectedText, DOTB, payloadText),
  };
}

const DOTB = new Uint8Array([DOT]);

// Scan compact structure and bounds before ath/hash computation. The full decode path
// separately checks base64url canonicality. This scan rejects malformed framing, wrong segment
// counts and oversized inputs before hashing.
export function scanCompact(input: Uint8Array, bounds: Bounds = MAXIMUM_BOUNDS): void {
  const b = coerceBounds(bounds);
  if (input.length > resolve(b, "compact_bytes" as MaximaKey)) fail("compact: byte bound");
  if (input.length === 0) fail("compact: empty");
  const dots: number[] = [];
  for (let i = 0; i < input.length; i++) if (input[i] === DOT) dots.push(i);
  if (dots.length !== 2) fail("compact: three segments");
  const d0 = dots[0]!, d1 = dots[1]!;
  if (d0 === 0 || d1 === d0 + 1 || d1 === input.length - 1) fail("compact: empty segment");
  const segBytes = resolve(b, "encoded_segment_bytes" as MaximaKey);
  if (d0 > segBytes) fail("compact: protected segment bound");
  if (d1 - d0 - 1 > segBytes) fail("compact: payload segment bound");
  if (input.length - d1 - 1 > segBytes) fail("compact: signature segment bound");
  // signature dot-free: dots.length === 2 guarantees no dot inside the signature segment.
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/**
 * Closed artifact discriminant carried by SigningInput. It selects the assembly profile and does
 * not permit profile inference from presented bytes. Sibling profiles use distinct labeled kinds.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 * @inline
 * @category Canonical bytes
 */
export type SigningInputKind = "grant" | "proof" | "local_loopback_http_proof" | "boundary_anchor" | "key_transition" | "role_attestation" | "content_assertion";

/**
 * Canonical unpadded-base64url JWS segments for external signing. Sign the exact ASCII
 * protectedSegment bytes, one period byte (0x2e), then payloadSegment bytes. Assembly accepts a
 * signature, never a private key or callback.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#datamodel
 * @category Canonical bytes
 */
export interface SigningInput {
  /** Closed discriminant selecting the documented artifact or selector variant. */
  readonly kind: SigningInputKind;
  /** Unpadded base64url ASCII of the canonical protected header, without any period. */
  readonly protectedSegment: Uint8Array;
  /** Unpadded base64url ASCII of the canonical payload, without any period. */
  readonly payloadSegment: Uint8Array;
}

// Low-level Ed25519 assembly checks the closed kind set, 64-byte signature width and the
// keyless part of rule S1: canonical R, R not small-order, and S < L. It emits accepted bytes
// unchanged without verifying signatures. The public facade then reparses the complete header
// and payload for the selected kind. All Ed25519 profiles share this assembler. See erratum 3.
export function assembleSegments(input: SigningInput, signature: Uint8Array): Result<Uint8Array> {
  return trying(() => {
    const KINDS: SigningInputKind[] = ["grant", "proof", "local_loopback_http_proof", "boundary_anchor", "key_transition", "role_attestation", "content_assertion"];
    if (!KINDS.includes(input.kind)) fail("assemble_segments: kind closed set");
    assert(signature.length === 64, "assemble_segments: signature width 64");
    if (!signatureGate(signature)) fail("assemble_segments: signature canonicality");
    // compact = protected "." payload "." base64url(signature).
    const sigB64 = base64urlEncode(signature);
    return concat(input.protectedSegment, DOTB, input.payloadSegment, DOTB, sigB64);
  });
}

// Low-level ES256 assembly enforces the 64-byte width. The public major-3 facade separately
// enforces canonical raw big-endian r || s and low-S. This signature representation differs
// from Ed25519 R || S.
export function assembleSegmentsEs256(input: SigningInput, signature: Uint8Array): Result<Uint8Array> {
  return trying(() => {
    const KINDS: SigningInputKind[] = ["grant", "proof", "boundary_anchor", "key_transition"];
    if (!KINDS.includes(input.kind)) fail("assemble_segments: kind closed set");
    assert(signature.length === 64, "assemble_segments: signature width 64");
    const sigB64 = base64urlEncode(signature);
    return concat(input.protectedSegment, DOTB, input.payloadSegment, DOTB, sigB64);
  });
}
