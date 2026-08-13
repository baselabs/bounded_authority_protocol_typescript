import { fail, assert, trying, type Result } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { resolve, coerceBounds, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

// JWS compact serialization (RFC 7515) — the 3-segment wire shape: base64url(protected) || "." ||
// base64url(payload) || "." || base64url(signature). The signing input (REQ1-SIGNING-exact-input)
// is ASCII(base64url(protected) || "." || base64url(payload)) — no signature, no extra bytes.

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
  // Cross-vendor F2: re-validate caller-supplied bounds (a hand-crafted Bounds can widen limits past
  // MAXIMA, bypassing boundsNew). Mirrors the reference's Bounds.coerce on every entry point.
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
  // Decoded signature-width gate (runtime.ex:237 parse_grant, :259 parse_proof,
  // boundary_anchor_codec.ex:88, key_transition_codec.ex:120 all enforce byte_size(signature) ==
  // signature_bytes). scanCompact (the ath/hash gate) intentionally does NOT — it mirrors
  // CompactJws.scan (shape+size only); the decoded-width check belongs to the decode path.
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

// scan_compact — faithful port of the reference CompactJws.scan (compact_jws.ex:16-27): the
// shape+size gate that `ath`/`hash` run BEFORE hashing a compact. It validates structure + bounds
// only — NOT base64url canonicity (canonicity is the full verify path's job via parseCompact). The
// producer ath (proof_signing_input) and the verify grant-hash both gate on this so a non-compact
// grant (wrong segment count, oversized, dotted signature) is rejected rather than hashed. Mirrors
// the Rust scan_compact gate added in the BAP-15 closeout.
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

// assemble_compact: SigningInput (protected + payload segments as text) + 64-byte signature → compact.
// REQ1-VERIFY-no-signer-callback: takes a signature, never a key. kind ∈ {grant, proof,
// boundary_anchor, key_transition} (the runner's accepted signing-input kinds).
export type SigningInputKind = "grant" | "proof" | "boundary_anchor" | "key_transition";

export interface SigningInput {
  readonly kind: SigningInputKind;
  readonly protectedSegment: Uint8Array; // base64url text
  readonly payloadSegment: Uint8Array; // base64url text
}

// assemble_segments: the LOW-LEVEL compact assembler (mirrors CompactJws.assemble's byte assembly,
// compact_jws.ex:41-43). Validates only the kind closed-set + 64-byte signature width, then
// concatenates protected.payload.base64url(signature). It does NOT validate the signing-input
// header/payload content — that is the v1.ts assemble_compact FAÇADE's job (re-parse per kind,
// runtime.ex:151 validate_assembled_compact). Test helpers and conformance use this to build
// compacts freely; the public contract is the façade (assembleCompact in v1.ts).
export function assembleSegments(input: SigningInput, signature: Uint8Array): Result<Uint8Array> {
  return trying(() => {
    const KINDS: SigningInputKind[] = ["grant", "proof", "boundary_anchor", "key_transition"];
    if (!KINDS.includes(input.kind)) fail("assemble_segments: kind closed set");
    assert(signature.length === 64, "assemble_segments: signature width 64");
    // compact = protected "." payload "." base64url(signature).
    const sigB64 = base64urlEncode(signature);
    return concat(input.protectedSegment, DOTB, input.payloadSegment, DOTB, sigB64);
  });
}
