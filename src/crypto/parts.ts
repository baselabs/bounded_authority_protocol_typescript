// The input check both backends apply before hashing: every part must be a Uint8Array (a subclass such
// as Node's Buffer is one). Anything else, including a string, a number array, an ArrayBuffer, a
// DataView or another typed array, is refused with the package's closed error, never coerced, so the
// two backends hash exactly the same inputs and refuse exactly the same ones.
import { fail } from "../error.js";

export function checkedParts(parts: unknown): readonly Uint8Array[] {
  if (!Array.isArray(parts)) fail("sha256: parts must be an array of Uint8Array");
  for (const part of parts) {
    if (!(part instanceof Uint8Array)) fail("sha256: every part must be a Uint8Array");
  }
  return parts as readonly Uint8Array[];
}
