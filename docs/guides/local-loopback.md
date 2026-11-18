# Local-loopback development

Use the local-loopback application-proof profile for development processes reached by literal
`127.0.0.1` or `[::1]` HTTP addresses. It is major 1 only and uses `ba+loopback-proof`, never
`dpop+jwt`. Hostnames, remote IP addresses, query strings and fragments refuse. The audience
remains an independently selected identifier; an HTTP loopback target does not turn it into trust.

A server-issued nonce is mandatory. Deliver the challenge over the actual local connection,
keep its lifecycle in the host, and reconstruct the method, canonical literal target and arguments
from that connection. Loopback is not authentication: other local processes can reach the server.
Still enroll trusted keys, reserve invocations, check revocation and apply policy. Never silently
fall back from HTTPS to this profile.

The [complete runnable recipe](../examples/local-loopback.ts) generates fresh keys, signs a nonce-bound
proof, verifies it, and asserts wrong-nonce, missing-nonce, standard-profile and remote-target
refusals. The [notebook](../notebooks/local-loopback.ipynb) runs the same journey in a fresh Deno kernel.

---

Documentation navigation: [Previous: Deno, Bun and browsers](runtimes.md) · [Next: Rotate keys](rotate-keys.md)
