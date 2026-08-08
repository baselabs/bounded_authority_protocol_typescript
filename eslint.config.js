// ESLint config for @bounded-authority/verifier — the library-path purity gate (ADR 0014 Decision 8).
// The verify path MUST be pure + deterministic (AGENTS rule 2): no filesystem, network, clock, RNG,
// env, or process access in src/. The conformance runner (conformance/) + tests (test/) are the I/O
// carve-out (they load the corpus), mirroring the Elixir CLI carve-out (ADR 0005). A stray
// Date.now() / fetch / fs / crypto.random* in src/ fails this gate.
//
// This is the TS analog of the Elixir tools/architecture_gate.exs purity rules for lib/. It does not
// reach the Elixir gate's full AST sophistication, but it covers the purity invariant (no I/O/clock/
// RNG/network in the verify path) that AGENTS rule 2 binds.
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "conformance/**", "test/**"],
  },
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts"],
    rules: {
      // The purity invariant: ban I/O / clock / RNG / network / fs / process in the library path.
      "no-restricted-globals": [
        "error",
        { name: "fetch", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
        { name: "XMLHttpRequest", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
        { name: "WebSocket", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
        { name: "setTimeout", message: "timers forbidden in the verify path (AGENTS rule 2)" },
        { name: "setInterval", message: "timers forbidden in the verify path (AGENTS rule 2)" },
      ],
      "no-restricted-imports": [
        "error",
        {
          paths: [
            { name: "fs", message: "filesystem I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:fs", message: "filesystem I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:fs/promises", message: "filesystem I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "http", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:http", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "https", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:https", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "net", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:net", message: "network I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "child_process", message: "subprocess I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:child_process", message: "subprocess I/O forbidden in the verify path (AGENTS rule 2)" },
            { name: "os", message: "env/host introspection forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:os", message: "env/host introspection forbidden in the verify path (AGENTS rule 2)" },
            { name: "worker_threads", message: "threading forbidden in the verify path (AGENTS rule 2)" },
            { name: "node:worker_threads", message: "threading forbidden in the verify path (AGENTS rule 2)" },
          ],
        },
      ],
      "no-restricted-syntax": [
        "error",
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
        // Ban crypto.random* (RNG) — node:crypto verify/digest are allowed, but randomBytes etc. are not.
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
);
