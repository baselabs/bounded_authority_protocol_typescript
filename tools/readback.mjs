#!/usr/bin/env node
// Post-publish read-back of one released version (pnpm readback; the release's read-back step, run
// once the staged publish is approved). Every check reads the public registry or runs the package
// installed from it, so it needs no credential and changes nothing. Each check is fatal.
//
//   node tools/readback.mjs <version> --sha256 <hex> [--commit <sha>] [--latest <version>]
//
//   --sha256  the tarball SHA-256 the release run verified (its verify job prints
//             "packed <file> sha256 <hex>", and its publish job "publishing <file> sha256 <hex>")
//   --commit  the commit the release tag names (default: git rev-parse v<version>^{commit})
//   --latest  the version npm's `latest` tag must name (default: <version>)
//
// 1. registry: `npm view` names <version>, and `latest` is --latest;
// 2. bytes: the registry tarball's SHA-512 equals its `dist.integrity`, and its SHA-256 equals
//    --sha256, so the published bytes are the bytes the release workflow verified;
// 3. provenance: the SLSA v1 attestation's subject is that tarball, built by this repository's
//    .github/workflows/release.yml from refs/tags/v<version> at --commit on a GitHub-hosted runner;
// 4. signatures: `npm audit signatures` in a fresh consumer verifies the registry signatures and the
//    attestation (this is the check of the attestation's signature; step 3 reads its content);
// 5. a fresh consumer: the README Quickstart on Node.js, and the Deno, Bun and browsers guide's
//    module on Node.js, Deno, Bun and in Chromium (bundled with esbuild, served under a strict CSP).
//    Deno, Bun and the Playwright Chromium build must be installed.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const NAME = "@bounded-authority-protocol/verifier";
const REPOSITORY = "https://github.com/baselabs/bounded_authority_protocol_typescript";
const WORKFLOW = ".github/workflows/release.yml";
const CSP = "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'";

class ReadbackError extends Error {}
const check = (condition, message) => {
  if (!condition) throw new ReadbackError(message);
};
const run = (cmd, args, cwd = ROOT) => execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

export function parseArgs(argv) {
  const [version, ...rest] = argv;
  check(/^\d+\.\d+\.\d+$/.test(version ?? ""), "usage: readback.mjs <version> --sha256 <hex> [--commit <sha>] [--latest <version>]");
  const options = { version, sha256: undefined, commit: undefined, latest: version };
  for (let i = 0; i < rest.length; i += 2) {
    const [flag, value] = [rest[i], rest[i + 1]];
    check(["--sha256", "--commit", "--latest"].includes(flag) && value !== undefined, `unknown or incomplete option ${flag}`);
    options[flag.slice(2)] = value;
  }
  check(/^[0-9a-f]{64}$/.test(options.sha256 ?? ""), "--sha256 <64 hex digits> is required: the tarball hash the release run verified");
  options.commit ??= run("git", ["rev-parse", `v${version}^{commit}`]).trim();
  check(/^[0-9a-f]{40}$/.test(options.commit), "--commit must be a 40-hex commit");
  return options;
}

const fenced = (markdown, tag) => [...markdown.matchAll(new RegExp("^```" + tag + "\\n([\\s\\S]*?)^```$", "gm"))].map((m) => m[1]);

export async function readback({ version, sha256, commit, latest }, log = console.log) {
  // 1. registry
  const view = JSON.parse(run("npm", ["view", `${NAME}@${version}`, "--json"]));
  check(view.version === version, `npm view ${NAME}@${version} names ${view.version}`);
  const tags = JSON.parse(run("npm", ["view", NAME, "dist-tags", "--json"]));
  check(tags.latest === latest, `latest is ${tags.latest}, expected ${latest}`);
  log(`ok registry: ${NAME}@${version} is published and latest is ${tags.latest}`);

  // 2. bytes
  const response = await fetch(view.dist.tarball);
  check(response.ok, `fetching ${view.dist.tarball}: HTTP ${response.status}`);
  const tarball = new Uint8Array(await response.arrayBuffer());
  const sha512 = createHash("sha512").update(tarball).digest();
  check(`sha512-${sha512.toString("base64")}` === view.dist.integrity, `the registry tarball does not match dist.integrity ${view.dist.integrity}`);
  const actual256 = createHash("sha256").update(tarball).digest("hex");
  check(actual256 === sha256, `the registry tarball's sha256 is ${actual256}, the release run verified ${sha256}`);
  log(`ok bytes: integrity ${view.dist.integrity}, sha256 ${sha256} (the verified tarball)`);

  // 3. provenance
  check(view.dist.attestations?.provenance?.predicateType === "https://slsa.dev/provenance/v1", "no SLSA v1 provenance on the registry");
  const attestations = await (await fetch(view.dist.attestations.url)).json();
  const slsa = attestations.attestations.find((a) => a.predicateType === "https://slsa.dev/provenance/v1");
  check(slsa !== undefined, "the attestation bundle has no SLSA v1 provenance");
  const statement = JSON.parse(Buffer.from(slsa.bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  const subject = statement.subject?.[0];
  check(statement.subject?.length === 1 && subject.name === `pkg:npm/${NAME.replace("@", "%40")}@${version}`, `provenance subject ${subject?.name}`);
  check(subject.digest?.sha512 === sha512.toString("hex"), "the provenance subject digest is not the registry tarball");
  const workflow = statement.predicate?.buildDefinition?.externalParameters?.workflow;
  check(workflow?.repository === REPOSITORY, `provenance repository ${workflow?.repository}`);
  check(workflow?.path === WORKFLOW, `provenance workflow ${workflow?.path}`);
  check(workflow?.ref === `refs/tags/v${version}`, `provenance ref ${workflow?.ref}`);
  const source = statement.predicate.buildDefinition.resolvedDependencies?.[0];
  check(source?.uri === `git+${REPOSITORY}@refs/tags/v${version}` && source?.digest?.gitCommit === commit,
    `provenance source ${source?.uri} at ${source?.digest?.gitCommit}, expected commit ${commit}`);
  check(statement.predicate.runDetails?.builder?.id === "https://github.com/actions/runner/github-hosted", "provenance builder is not a GitHub-hosted runner");
  log(`ok provenance: ${WORKFLOW} at refs/tags/v${version} (${commit}), GitHub-hosted`);

  const consumer = mkdtempSync(join(tmpdir(), "bap-readback-"));
  try {
    // 4. signatures
    writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "bap-readback", private: true, type: "module" }));
    run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error", `${NAME}@${version}`], consumer);
    const installed = JSON.parse(readFileSync(join(consumer, "node_modules", ...NAME.split("/"), "package.json"), "utf8"));
    check(installed.version === version, `the consumer installed ${installed.version}`);
    const audit = run("npm", ["audit", "signatures"], consumer);
    check(/verified registry signature/.test(audit) && /verified attestation/.test(audit), `npm audit signatures:\n${audit}`);
    log(`ok signatures: ${audit.split("\n").filter((l) => /verified/.test(l)).join("; ")}`);

    // 5. a fresh consumer
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    writeFileSync(join(consumer, "quickstart.ts"), fenced(readme, "ts")[0]);
    run("node", ["quickstart.ts"], consumer);
    log("ok quickstart: the README Quickstart runs on Node.js");
    const guide = readFileSync(join(ROOT, "docs/guides/runtimes.md"), "utf8");
    const [module] = fenced(guide, "ts");
    const [page] = fenced(guide, "html");
    writeFileSync(join(consumer, "verify-anywhere.ts"), module);
    for (const [label, cmd, args, backend] of [
      ["Node.js", "node", ["verify-anywhere.ts"], "node"],
      ["Deno", "deno", ["run", "verify-anywhere.ts"], "portable"],
      ["Bun", "bun", ["verify-anywhere.ts"], "portable"],
    ]) {
      const line = run(cmd, args, consumer).trim();
      check(line === `verified grant-gallery with the ${backend} backend`, `${label}: ${line}`);
      log(`ok ${label}: ${line}`);
    }
    log(`ok Chromium: ${await inChromium(consumer, page)}`);
  } finally {
    rmSync(consumer, { recursive: true, force: true });
  }
}

// The guide's module bundled from the consumer's installed package and loaded by the guide's page.
async function inChromium(consumer, page) {
  const { build } = await import("esbuild");
  const { chromium } = await import("playwright");
  const bundle = await build({
    entryPoints: [join(consumer, "verify-anywhere.ts")], absWorkingDir: consumer, bundle: true, format: "esm",
    platform: "browser", write: false, logLevel: "silent",
  });
  const app = bundle.outputFiles[0].text;
  const server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    const [status, type, body] = path === "/" ? [200, "text/html; charset=utf-8", page]
      : path === "/verify-anywhere.js" ? [200, "text/javascript; charset=utf-8", app] : [404, "text/plain", "not found"];
    res.writeHead(status, { "content-type": type, "content-security-policy": CSP });
    res.end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch();
  try {
    const tab = await browser.newPage();
    const errors = [];
    tab.on("pageerror", (e) => errors.push(String(e)));
    const verified = tab.waitForEvent("console", { predicate: (m) => m.text().startsWith("verified "), timeout: 30_000 });
    await tab.goto(`http://127.0.0.1:${server.address().port}/`);
    const line = (await verified).text();
    check(line === "verified grant-gallery with the portable backend" && errors.length === 0, `Chromium: ${line} ${errors.join(" ")}`);
    return line;
  } finally {
    await browser.close();
    server.close();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    await readback(parseArgs(process.argv.slice(2)));
    console.log("read-back passed");
  } catch (e) {
    console.error(`read-back FAILED: ${e instanceof ReadbackError ? e.message : (e?.stack ?? e)}`);
    process.exit(1);
  }
}
