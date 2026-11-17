// Types shared by the crypto backend contract (./backend.ts) and the profile modules. Structural only:
// no DOM or Node global type appears here, so no public declaration depends on either environment.

declare const brand: unique symbol;

// An imported public key, opaque to everything but the backend that produced it. Raw bytes cannot
// stand in for it (the brand is a unique symbol no value outside the backends can carry).
export type BackendPublicKey = { readonly [brand]: "bap-backend-public-key" };

/**
 * The resolved crypto implementation: node uses node:crypto; portable uses pure JavaScript noble
 * libraries. Selection must not change protocol verdicts.
 * @see https://github.com/baselabs/bounded_authority_protocol/blob/main/spec/bap-v1.md#verification
 */
export type BackendId = "node" | "portable";
