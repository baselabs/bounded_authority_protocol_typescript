# Glossary

| Term | Meaning |
|---|---|
| Grant | issuer-signed constraints naming a holder key, audience, operations and validity window |
| Proof | holder signature binding one grant to a method, target, invocation and argument digest |
| Envelope | the grant and its per-call proof supplied as raw bytes |
| Trusted issuer | a public key and identity enrolled independently by the host |
| Facts | redacted value-bearing verification results; never execution credentials |
| Invocation | a logical call identified by a lowercase RFC 4122 UUID and reserved with issuer and grant |
| Nonce | server-selected challenge value; lifecycle and freshness are host-owned |
| Contract major | explicitly selected complete wire profile, independent of npm SemVer |
| Tagged JSON | JSON values retaining integer/float tags and UTF-8 string bytes |
| Consumption chain | contiguous domain-separated row hashes with explicit expected boundaries |
| Anchor | signed chain boundary under a historical public key |
| Key transition | authenticated archive-key handover with overlapping validity windows |
| Anchored export | framed archive verified against pinned digest, object version and boundaries |
| Attestation | separate profile binding a subject key to a role under a trusted attestor |
| Content assertion | signed exact-content/profile digest and lineage claims |
| Successor | one consecutive lineage step between independently verified assertion facts |
| Replay store | host-owned durable, atomic reservation of issuer/grant/invocation through grant validity |

---

Documentation navigation: [Previous: FAQ](faq.md) · [Next: Cheatsheet](cheatsheet.md)
