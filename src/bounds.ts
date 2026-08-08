import { fail } from "./error.js";

// The fixed v1 profile maxima — the 38-row Hard maxima table (protocol-v1.md:352-390).
// Pinned by the corpus bounds.new cases so any mistyped constant fails. Fixed-width keys
// (REQ1-BOUNDS-fixed-widths, L395): digest_bytes, public_key_bytes, signature_bytes are the immutable
// cryptographic constants of suite BAP1-Ed25519-SHA256 — they MUST equal the maximum exactly (widening
// is forbidden); all others may be tightened to a positive integer at most the maximum.
export const MAXIMA = {
  compact_bytes: 65536,
  encoded_segment_bytes: 32768,
  decoded_segment_bytes: 24576,
  json_bytes: 65536,
  depth: 32,
  object_members: 64,
  array_items: 256,
  total_nodes: 4096,
  string_bytes: 8192,
  key_bytes: 128,
  number_lexeme_bytes: 64,
  integer_magnitude: 9007199254740991,
  float_magnitude: 9007199254740991,
  kid_bytes: 128,
  jcs_bytes: 65536,
  uri_bytes: 8192,
  identifier_bytes: 512,
  nonce_bytes: 512,
  method_bytes: 32,
  operation_bytes: 128,
  audiences: 64,
  operations: 64,
  selectors: 64,
  path_segments: 32,
  one_of_values: 256,
  public_key_bytes: 32,
  signature_bytes: 64,
  digest_bytes: 32,
  clock_skew: 60,
  proof_max_age: 300,
  chain_row_bytes: 4096,
  chain_rows: 65536,
  anchor_bytes: 8192,
  archive_header_bytes: 8192,
  archive_chunks: 65796,
  archive_bytes: 270820384,
  object_version_bytes: 512,
  key_transitions: 256,
} as const;

export type MaximaKey = keyof typeof MAXIMA;

// The immutable maximum. Bounds.maximum() returns the profile maxima (REQ1-BOUNDS-tighten-only).
export interface Bounds {
  readonly maximum: typeof MAXIMA;
  readonly overrides: ReadonlyMap<MaximaKey, number>;
}

export const MAXIMUM_BOUNDS: Bounds = { maximum: MAXIMA, overrides: new Map() };

export function boundsMaximum(): Bounds {
  return MAXIMUM_BOUNDS;
}

// REQ1-BOUNDS-reject-list (L397): unknown, non-integer, zero, negative, widening, or fixed-width-
// changing limits are invalid. Fixed-width keys (L395) cannot be tightened or widened.
const FIXED_WIDTH_KEYS: ReadonlySet<MaximaKey> = new Set<MaximaKey>([
  "digest_bytes",
  "public_key_bytes",
  "signature_bytes",
]);

export function boundsNew(tightening?: Readonly<Record<string, number>>): Bounds {
  if (tightening === undefined) return MAXIMUM_BOUNDS;
  const overrides = new Map<MaximaKey, number>();
  for (const [key, value] of Object.entries(tightening)) {
    if (!(key in MAXIMA)) fail(`bounds.new: unknown limit ${key}`);
    if (!Number.isInteger(value)) fail(`bounds.new: non-integer limit ${key}`);
    const mk = key as MaximaKey;
    if (FIXED_WIDTH_KEYS.has(mk)) {
      // REQ1-BOUNDS-fixed-widths: fixed-width keys cannot be tightened or widened, but setting to
      // the exact maximum is an identity no-op (valid). Any other value rejects.
      if (value !== MAXIMA[mk]) fail(`bounds.new: fixed-width key ${key} must equal maximum`);
    } else {
      if (value <= 0) fail(`bounds.new: non-positive limit ${key}`);
      if (value > MAXIMA[mk]) fail(`bounds.new: widening limit ${key}`);
    }
    overrides.set(mk, value);
  }
  return { maximum: MAXIMA, overrides };
}

// Resolve a bound: the override if present, else the maximum.
export function resolve(b: Bounds, key: MaximaKey): number {
  return b.overrides.get(key) ?? MAXIMA[key];
}
