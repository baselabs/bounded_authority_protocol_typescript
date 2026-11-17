// Publish API declarations from the immutable tag matching npm's latest release. The site may
// run development source, but its API reference must describe the package readers can install.
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const out = resolve(process.argv[2] ?? join(root, "site-dist/api"));
const run = (command, args, cwd = root) => {
  // cross-spawn resolves Windows command shims and escapes arguments without shell: true.
  const result = spawn.sync(command, args, {
    cwd, encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${command} failed: ${result.stderr}`);
  return result.stdout.trim();
};
const version = run("npm", ["view", `${pkg.name}@latest`, "version", "--fetch-retries=1", "--fetch-timeout=20000"]);
assert.match(version, /^\d+\.\d+\.\d+$/, "npm must identify a stable release; an outage fails closed");
const tag = `v${version}`;
const repository = pkg.repository.url.replace(/^git\+/, "");
const scratch = mkdtempSync(join(tmpdir(), "bap-released-api-"));
try {
  const release = join(scratch, "release");
  run("git", ["-c", "advice.detachedHead=false", "clone", "--quiet", "--depth=1", "--single-branch", "--branch", tag, repository, release]);
  const commit = run("git", ["rev-parse", "HEAD"], release);
  const refs = new Map(run("git", ["ls-remote", "--exit-code", "--tags", repository,
    `refs/tags/${tag}`, `refs/tags/${tag}^{}`]).split("\n").map((line) => {
    const [sha, ref] = line.split("\t");
    return [ref, sha];
  }));
  const remoteCommit = refs.get(`refs/tags/${tag}^{}`) ?? refs.get(`refs/tags/${tag}`);
  assert.match(remoteCommit ?? "", /^[a-f0-9]{40}$/, "the remote must advertise the release tag");
  assert.equal(commit, remoteCommit, "the cloned commit must match the independently read remote tag");
  const released = JSON.parse(readFileSync(join(release, "package.json"), "utf8"));
  assert.equal(released.name, pkg.name);
  assert.equal(released.version, version, "the release tag must match the npm version");
  // Resolve types against the tag's frozen dependency graph, never development dependencies.
  // Documentation needs no dependency install scripts. Use the same pinned pnpm as CI.
  run("corepack", ["pnpm@10.20.0", "install", "--frozen-lockfile", "--ignore-scripts"], release);
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
