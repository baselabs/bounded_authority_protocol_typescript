// ESLint config for @bounded-authority-protocol/verifier — the library-path purity gate (ADR 0014 Decision 8)
// and, since 0.7.0, the browser-safety gate. test/guards.test.ts holds every rule below to a probe that
// must trip it, linted against THIS file.
//
// Purity (AGENTS rule 2): the verify path is pure and deterministic: no filesystem, network, clock,
// RNG, env, or process access in src/. The conformance runner (conformance/) and tests (test/) are the
// I/O carve-out (they load the corpus), mirroring the Elixir CLI carve-out (ADR 0005). A stray
// Date.now() / fetch / fs / crypto.random* in src/ fails this gate. This is the TS analog of the Elixir
// tools/architecture_gate.exs purity rules for lib/.
//
// Browser safety: src/ runs in browsers, Deno, Bun and workers, so no Node built-in module (prefixed or
// bare), no Node global (Buffer, process, require, ...) including through globalThis, no dynamic
// import(), and no eval, implied eval or Function constructor (a strict CSP forbids them). The single
// exception is src/crypto/node.ts, the node:crypto backend, which may import node:crypto and use
// Buffer and nothing else from Node.
//
// No secret material (AGENTS rule 6): @noble is reachable only from src/crypto/portable.ts, and only
// through an allowlist of verification and hash entry points; signing, key generation, the utils
// namespaces and noble's mutable hash registry are banned.
import { builtinModules } from "node:module";
import tseslint from "typescript-eslint";

const NODE_MESSAGE =
  "Node built-in modules are forbidden in src/ (purity, AGENTS rule 2; browser safety): only src/crypto/node.ts may import node:crypto";
const NODE_BUILTINS = [...new Set(builtinModules.flatMap((name) => (name.startsWith("node:") ? [name, name.slice(5)] : [name, `node:${name}`])))].sort();

const NOBLE_MESSAGE =
  "@noble is reachable only from src/crypto/portable.ts, and only through @noble/ed25519, @noble/curves/nist.js and @noble/hashes/sha2.js (verify-only, AGENTS rule 6)";
const NOBLE_SIGNING = ["sign", "signAsync", "keygen", "keygenAsync", "getPublicKey", "getPublicKeyAsync", "utils", "hashes", "etc"];

function restrictedImports({ allowNodeCrypto, allowNoble }) {
  const paths = NODE_BUILTINS.filter((name) => !(allowNodeCrypto && name === "node:crypto")).map((name) => ({
    name,
    message: NODE_MESSAGE,
  }));
  const patterns = [{ group: allowNodeCrypto ? ["node:*", "!node:crypto"] : ["node:*"], message: NODE_MESSAGE }];
  if (allowNoble) {
    paths.push({
      name: "@noble/ed25519",
      importNames: NOBLE_SIGNING,
      message: "verification only: signing, key generation, utils and the hash registry are banned (AGENTS rule 6)",
    });
    patterns.push({ regex: "^@noble/(?!(?:ed25519|curves/nist\\.js|hashes/sha2\\.js)$)", message: NOBLE_MESSAGE });
  } else {
    patterns.push({ group: ["@noble/**"], message: NOBLE_MESSAGE });
  }
  return ["error", { paths, patterns }];
}

const PURITY_GLOBALS = [
  { name: "fetch", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
  { name: "XMLHttpRequest", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
  { name: "WebSocket", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
  { name: "setTimeout", message: "timers forbidden in the verify path (AGENTS rule 2)" },
  { name: "setInterval", message: "timers forbidden in the verify path (AGENTS rule 2)" },
];
const NODE_GLOBALS = ["Buffer", "process", "global", "require", "module", "exports", "__dirname", "__filename", "setImmediate"];
function restrictedGlobals({ allowBuffer }) {
  return [
    "error",
    ...PURITY_GLOBALS,
    ...NODE_GLOBALS.filter((name) => !(allowBuffer && name === "Buffer")).map((name) => ({
      name,
      message: `the Node global ${name} is forbidden in src/ (browser safety)`,
    })),
  ];
}

const GLOBAL_OBJECTS = ["globalThis", "window", "self", "global"];
const NODE_GLOBAL_PROPERTIES = GLOBAL_OBJECTS.flatMap((object) =>
  ["Buffer", "process", "require"].map((property) => ({
    object,
    property,
    message: `${object}.${property} is a Node global, forbidden in src/ (browser safety)`,
  })),
);
const NOBLE_PROPERTIES = ["sign", "keygen", "getPublicKey", "getSharedSecret", "randomSecretKey", "utils"].map((property) => ({
  property,
  message: `.${property} is a signing, key-generation or utility entry point, banned in src/ (verify-only, AGENTS rule 6)`,
}));

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "conformance/**", "test/**", "web/**", "browser/**", "site-dist/**", "build-*/**", ".kimosabe/**"],
  // web/** is the GitHub Pages site and browser/** the browser test page: DOM-context code, typechecked
  // by their own tsc configs, outside the library purity gate above.
  },
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts"],
    rules: {
      "no-restricted-globals": restrictedGlobals({ allowBuffer: false }),
      "no-restricted-imports": restrictedImports({ allowNodeCrypto: false, allowNoble: false }),
      "no-restricted-properties": ["error", ...NODE_GLOBAL_PROPERTIES, ...NOBLE_PROPERTIES],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-restricted-syntax": [
        "error",
        // Ban dynamic import(): every module is statically known (browser bundles, CSP).
        {
          selector: "ImportExpression",
          message: "dynamic import() forbidden in src/ (browser safety: every dependency is static)",
        },
        // Ban Date.now() / new Date() (clock).
        {
          selector: "MemberExpression[object.name='Date'][property.name='now']",
          message: "Date.now() forbidden in the verify path (AGENTS rule 2: no clock)",
        },
        {
          selector: "NewExpression[callee.name='Date']",
          message: "new Date() forbidden in the verify path (AGENTS rule 2: no clock)",
        },
        // Ban Math.random (RNG).
        {
          selector: "MemberExpression[object.name='Math'][property.name='random']",
          message: "Math.random() forbidden in the verify path (AGENTS rule 2: no RNG)",
        },
        // Ban crypto.random* (RNG).
        {
          selector: "CallExpression > MemberExpression[object.name='crypto'][property.name=/^random/]",
          message: "crypto.random* forbidden in the verify path (AGENTS rule 2: no RNG)",
        },
        // Ban process.env (env access).
        {
          selector: "MemberExpression[object.object.name='process'][object.property.name='env']",
          message: "process.env forbidden in the verify path (AGENTS rule 2: no env)",
        },
        // Ban require('fs'/'http'/...) style imports.
        {
          selector: "CallExpression[callee.name='require'] > Literal[value=/^(fs|http|https|net|child_process|os|worker_threads)$/]",
          message: "I/O module require forbidden in the verify path (AGENTS rule 2)",
        },
      ],
    },
  },
  {
    // The portable backend: noble's verification and hash entry points only.
    files: ["src/crypto/portable.ts"],
    rules: {
      "no-restricted-imports": restrictedImports({ allowNodeCrypto: false, allowNoble: true }),
    },
  },
  {
    // The node backend: node:crypto and Buffer, nothing else from Node, no noble.
    files: ["src/crypto/node.ts"],
    rules: {
      "no-restricted-imports": restrictedImports({ allowNodeCrypto: true, allowNoble: false }),
      "no-restricted-globals": restrictedGlobals({ allowBuffer: true }),
    },
  },
);
