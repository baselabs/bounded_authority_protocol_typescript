import { fail, assert, ok, err, trying, type Result } from "./error.js";
import { base64urlDecode, base64urlEncode } from "./base64url.js";
import { resolve, type Bounds, MAXIMUM_BOUNDS, type MaximaKey } from "./bounds.js";

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
  if (input.length > resolve(bounds, "compact_bytes" as MaximaKey)) fail("compact: byte bound");
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
  if (protectedText.length > resolve(bounds, "encoded_segment_bytes" as MaximaKey)) fail("compact: protected segment bound");
  if (payloadText.length > resolve(bounds, "encoded_segment_bytes" as MaximaKey)) fail("compact: payload segment bound");
  const protectedBytes = base64urlDecode(protectedText, resolve(bounds, "decoded_segment_bytes" as MaximaKey));
  const payloadBytes = base64urlDecode(payloadText, resolve(bounds, "decoded_segment_bytes" as MaximaKey));
  const signature = base64urlDecode(signatureText);
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

// Cross-vendor #21: assemble_compact returns Ok<Uint8Array> | Err, mirroring the Elixir
// {:ok, binary} | {:error, :invalid} and the other 15 façade functions (ADR 0014 D3). Failures
// (bad kind, signature width) return Err via the trying wrapper rather than throwing InvalidError.
export function assembleCompact(input: SigningInput, signature: Uint8Array): Result<Uint8Array> {
  return trying(() => {
    const KINDS: SigningInputKind[] = ["grant", "proof", "boundary_anchor", "key_transition"];
    if (!KINDS.includes(input.kind)) fail("assemble_compact: kind closed set");
    assert(signature.length === 64, "assemble_compact: signature width 64");
    // compact = protected "." payload "." base64url(signature).
    const sigB64 = base64urlEncode(signature);
    return concat(input.protectedSegment, DOTB, input.payloadSegment, DOTB, sigB64);
  });
}
