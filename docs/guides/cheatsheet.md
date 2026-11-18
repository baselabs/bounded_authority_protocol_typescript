# Cheatsheet

| Task | Entry point | Remember |
|---|---|---|
| Verify a request | `checkEnvelope` | trusted inputs and actual request; reserve replay before execution |
| Local development | `checkLocalLoopbackHttpEnvelope` | literal loopback HTTP, major 1, required server nonce |
| Verify a grant | `verifyGrant` | no per-call proof or policy decision |
| Display an artifact | `decodeGrant`, `decodeProof`, `untrustedKeyLocator` | parsing is not trust |
| Select wire major | root / `v2` / `v3` | major 3 uses 65-byte P-256 keys and low-S signatures |
| Parse arguments | `jsonDecode(strUtf8(text))` | duplicates refuse; integer and float tags differ |
| Tighten limits | `boundsNew` | positive ceilings; fixed widths remain fixed |
| Verify archive | `verifyAnchoredExport` | explicit keys, bounds, boundaries, digest and object version |
| Verify role | `roleAttestation.verifyAttestation` | host decides enrollment and role policy |
| Verify content | `contentAssertion.verifyAssertion` | exact bytes, schema and attestor policy are host-owned |
| Verify lineage | `contentAssertion.verifySuccessor` | verify both facts first; persist the accepted head |
| Handle refusal | `if (!result.ok)` | no reason or partial value; refuse admission |
| Log safely | explicit approved fields | no credentials or facts spreading |

Times are integer Unix seconds. Digests are 32 bytes. Ed25519 keys are 32 bytes. Both suites use
64-byte signatures. Skew is 0 to 60 seconds; proof age is 1 to 300 seconds. The
[reference](../reference.md#bounds) lists every limit and the generated reference documents every field.

---

Documentation navigation: [Previous: Glossary](glossary.md) · [Next: API reference](../reference.md)
