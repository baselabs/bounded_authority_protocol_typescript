// The crypto backend contract: six functions and one constant. Type-only: this module emits an empty
// .js, and its .d.ts is what the "#crypto" package import resolves to for every type checker. The two
// implementations are ./node.ts (node:crypto) and ./portable.ts (@noble), selected by the package.json
// "imports" conditions (bap-source, bap-portable, deno, bun, node, types, default).
//
// The profile modules (../ed25519.ts, ../es256.ts) own every protocol gate (widths, the strict Ed25519
// rule S1, the P-256 point, range and low-S checks) and call a backend only after those gates pass. A
// backend computes, it never decides policy: both implementations accept exactly the same inputs.
import type { BackendId, BackendPublicKey } from "./types.js";

export declare const BACKEND_ID: BackendId;

// SHA-256 (FIPS 180-4) over the concatenation of the parts. Throws InvalidError (the package's closed
// error) unless every part is a Uint8Array: nothing is coerced.
export declare function sha256(...parts: Uint8Array[]): Uint8Array;

// SHA-256 over an array of chunks (never spread: an archive can hold 65,796 chunks). Throws InvalidError
// unless `parts` is an array whose every element is a Uint8Array.
export declare function sha256Concat(parts: readonly Uint8Array[]): Uint8Array;

// Import a raw 32-byte Ed25519 public key. Throws on a key the backend cannot import; the profile has
// already refused non-canonical, small-order and off-curve keys before this call.
export declare function ed25519Key(raw32: Uint8Array): BackendPublicKey;

// The cofactorless Ed25519 equation encode([S]B - [k]A) == R, byte for byte. Returns false or throws
// on any failure.
export declare function ed25519Cofactorless(key: BackendPublicKey, message: Uint8Array, sig64: Uint8Array): boolean;

// Import a P-256 public key in the uncompressed SEC1 form: exactly 65 bytes, the 0x04 prefix, then x and
// y. Throws on any other width or prefix (compressed, hybrid or other) and on a point not on the curve.
export declare function p256Key(rawSec1_65: Uint8Array): BackendPublicKey;

// ECDSA P-256 over SHA-256 of the message, signature in the raw 64-byte r || s form. Accepts both the
// low-S and the high-S spelling: the low-S rule is the profile's gate, never the backend's.
export declare function p256Verify(key: BackendPublicKey, message: Uint8Array, sig64: Uint8Array): boolean;
