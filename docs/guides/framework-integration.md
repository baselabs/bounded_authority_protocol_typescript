# Request adapters in every kind of host

An adapter translates the host's actual request into the verifier's explicit expected context.
Fetch-style handlers and Node-native middleware are examples of this class. The same rules apply
to framework controllers, RPC gateways, edge workers, queues with authenticated HTTP ingress,
and other transports; a framework name does not define the supported boundary.

The [executed adapter recipe](../examples/request-adapters.ts) starts real HTTP servers for a native
handler and a Fetch-style handler. Each gets freshly signed bytes over a real connection. Changed
arguments refuse before the first successful request, then replay and query-bearing targets refuse.
It closes every server. Both handlers use the same explicit operation and enrolled public key.

Map each adapter deliberately:

| Expected input | Host source |
|---|---|
| `trustedIssuer`, issuer, audience | enrolled configuration and this resource's identity |
| method and target | actual ingress method, configured public origin, validated original path |
| operation | the route or command the server selected |
| `castArguments` | strict, bounded decode and application casting of the bytes used by execution |
| invocation and nonce | bounded transport field, server-owned challenge state |
| time, skew and proof age | host clock policy; common authoritative clock with the replay store |

Reject duplicate credential headers before a framework joins them. Bound the body while reading,
retain numeric lexical tags, and authenticate exactly the arguments passed to the handler. Never
verify one parsed body and execute another. Middleware that rewrites paths, case, escaped segments,
body fields or query parameters belongs before an explicit canonical reconstruction step.

For TLS proxies, configure allowed ingress origins and trusted proxy hops. Do not concatenate
arbitrary `Host`, `Forwarded` or `X-Forwarded-*` values into the expected URI. Reject unexpected
absolute targets, queries and fragments. URL constructors can normalize dot segments, so validate
the original target before losing it. The example's HTTP transport represents a TLS-terminated
connection with a configured HTTPS origin; it is not the local-loopback proof profile.

After verification, reserve replay in the [durable store](durable-replay.md), check live revocation
and host policy, and only then execute. A Fetch runtime's request type does not provide any of
these properties by itself. Integration tests must cover the production proxy and casting path.

---

Documentation navigation: [Previous: Protect an HTTP endpoint](http-server.md) · [Next: Deno, Bun and browsers](runtimes.md)
