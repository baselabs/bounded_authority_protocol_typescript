// Publish API declarations from the immutable tag matching npm's latest release. The site may
// run development source, but its API reference must describe the package readers can install.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const out = resolve(process.argv[2] ?? join(root, "site-dist/api"));
const run = (command, args, cwd = root) => execFileSync(command, args, {
  cwd, encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"],
}).trim();
const version = run("npm", ["view", `${pkg.name}@latest`, "version", "--fetch-retries=1", "--fetch-timeout=20000"]);
assert.match(version, /^\d+\.\d+\.\d+$/, "npm must identify a stable release; an outage fails closed");
const tag = `v${version}`;
const repository = pkg.repository.url.replace(/^git\+/, "");
const scratch = mkdtempSync(join(tmpdir(), "bap-released-api-"));
try {
  const release = join(scratch, "release");
  run("git", ["-c", "advice.detachedHead=false", "clone", "--quiet", "--depth=1", "--single-branch", "--branch", tag, repository, release]);
  const commit = run("git", ["rev-parse", "HEAD"], release);
  assert.equal(run("git", ["rev-parse", `${tag}^{commit}`], release), commit);
  const released = JSON.parse(readFileSync(join(release, "package.json"), "utf8"));
  assert.equal(released.name, pkg.name);
  assert.equal(released.version, version, "the release tag must match the npm version");
  // Resolve types against the tag's frozen dependency graph, never development dependencies.
  // Documentation needs no dependency install scripts. The caller supplies the pinned pnpm.
  run("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts"], release);
  const options = JSON.parse(readFileSync(join(root, "typedoc.json"), "utf8"));
  // Current-source CI enforces documentation coverage. Immutable releases can predate that gate;
  // render their actual comments without requiring undocumented types to become new exports.
  options.validation = { ...options.validation, notDocumented: false, notExported: false };
  options.disableSources = false;
  options.sourceLinkTemplate = `${repository.replace(/\.git$/, "")}/blob/${commit}/{path}#L{line}`;
  options.out = out;
  options.name = `${pkg.name} (released ${tag})`;
  writeFileSync(join(release, "typedoc.json"), JSON.stringify(options));
  console.log(run(process.execPath, [join(root, "node_modules/typedoc/bin/typedoc")], release));
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "release.json"), JSON.stringify({ package: pkg.name, version, tag, commit }, null, 2) + "\n");
  console.log(`Released API: ${pkg.name}@${version}, tag ${tag}, commit ${commit}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
