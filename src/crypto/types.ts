// Types shared by the crypto backend contract (./backend.ts) and the profile modules. Structural only:
// no DOM or Node global type appears here, so no public declaration depends on either environment.

declare const brand: unique symbol;

// An imported public key, opaque to everything but the backend that produced it. Raw bytes cannot
// stand in for it (the brand is a unique symbol no value outside the backends can carry).
export type BackendPublicKey = { readonly [brand]: "bap-backend-public-key" };

// "node": the node:crypto backend (Node.js under its default conditions).
// "portable": the pure-JavaScript backend (browsers, Deno, Bun, workers, and Node under bap-portable).
export type BackendId = "node" | "portable";
