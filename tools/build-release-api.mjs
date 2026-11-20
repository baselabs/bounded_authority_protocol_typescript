// Render one API path from either the immutable npm-latest tag (Pages, the default)
// or a clean export of HEAD (qualification, with no owning-package registry or tag lookup).
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { writeDocumentationMetadata } from "./build-docs.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const { values, positionals } = parseArgs({
  options: { source: { type: "string", default: "release" } }, allowPositionals: true,
});
const source = values.source;
assert.ok(source === "release" || source === "commit", "source must be release or commit");
assert.ok(positionals.length <= 1, "expected at most one output directory");
const out = resolve(positionals[0] ?? join(root, "site-dist/api"));
const run = (command, args, cwd = root) => {
  // cross-spawn resolves Windows command shims and escapes arguments without shell: true.
  const result = spawn.sync(command, args, {
    cwd, encoding: "utf8", timeout: 120_000, stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${command} failed: ${result.stderr}`);
  return result.stdout.trim();
};
const repository = pkg.repository.url.replace(/^git\+/, "");
const scratch = mkdtempSync(join(tmpdir(), "bap-released-api-"));
try {
  const release = join(scratch, "release");
  let version, tag, commit;
  if (source === "commit") {
    commit = run("git", ["rev-parse", "HEAD"]);
    // A local clone preserves Git source discovery but excludes every working-tree edit,
    // untracked file and installed dependency. No remote or release tag participates.
    run("git", ["clone", "--quiet", "--no-hardlinks", "--no-tags", "--no-checkout", root, release]);
    run("git", ["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", commit], release);
    assert.equal(run("git", ["rev-parse", "HEAD"], release), commit);
  } else {
    version = run("npm", ["view", `${pkg.name}@latest`, "version", "--fetch-retries=1", "--fetch-timeout=20000"]);
    assert.match(version, /^\d+\.\d+\.\d+$/, "npm must identify a stable release; an outage fails closed");
    tag = `v${version}`;
    run("git", ["-c", "advice.detachedHead=false", "clone", "--quiet", "--depth=1", "--single-branch", "--branch", tag, repository, release]);
    commit = run("git", ["rev-parse", "HEAD"], release);
    const refs = new Map(run("git", ["ls-remote", "--exit-code", "--tags", repository,
      `refs/tags/${tag}`, `refs/tags/${tag}^{}`]).split("\n").map((line) => {
      const [sha, ref] = line.split("\t");
      return [ref, sha];
    }));
    const remoteCommit = refs.get(`refs/tags/${tag}^{}`) ?? refs.get(`refs/tags/${tag}`);
    assert.match(remoteCommit ?? "", /^[a-f0-9]{40}$/, "the remote must advertise the release tag");
    assert.equal(commit, remoteCommit, "the cloned commit must match the independently read remote tag");
  }
  const released = JSON.parse(readFileSync(join(release, "package.json"), "utf8"));
  assert.equal(released.name, pkg.name);
  if (source === "commit") version = released.version;
  else assert.equal(released.version, version, "the release tag must match the npm version");
  assert.match(commit, /^[a-f0-9]{40}$/, "the source must identify an exact commit");
  // Both sources run TypeDoc, its plugins and types from their own frozen dependency graph.
  // Documentation needs no dependency install scripts. Use the same pinned pnpm as CI.
  run("corepack", [released.packageManager, "install", "--frozen-lockfile", "--ignore-scripts"], release);
  const typedoc = join(release, "node_modules/typedoc/bin/typedoc");
  assert.ok(existsSync(typedoc), `Source ${tag ?? commit}'s frozen install has no TypeDoc; refusing to use the checkout's copy`);
  const options = JSON.parse(readFileSync(join(release, "typedoc.json"), "utf8"));
  // Current-source CI enforces documentation coverage. Immutable releases can predate that gate;
  // render their actual comments without requiring undocumented types to become new exports.
  options.validation = { ...options.validation, notDocumented: false, notExported: false };
  options.disableSources = false;
  options.sourceLinkTemplate = `${repository.replace(/\.git$/, "")}/blob/${commit}/{path}#L{line}`;
  options.out = out;
  options.name = source === "release" ? `${pkg.name} (released ${tag})` : `${pkg.name} (commit ${commit})`;
  writeFileSync(join(release, "typedoc.json"), JSON.stringify(options));
  console.log(run(process.execPath, [typedoc], release));
  mkdirSync(out, { recursive: true });
  // The version gate permits authored history only inside TypeDoc articles. Derive that
  // history from the selected source, so commit and release builds carry the same evidence.
  writeDocumentationMetadata(out, { version, channel: source,
    authored: (options.projectDocuments ?? []).map((path) => readFileSync(join(release, path), "utf8")) });
  writeFileSync(join(out, "release.json"), JSON.stringify({ package: pkg.name, version, source, ...(tag ? { tag } : {}), commit }, null, 2) + "\n");
  console.log(`${source === "release" ? "Released" : "Commit"} API: ${pkg.name}@${version}, ${tag ? `tag ${tag}, ` : ""}commit ${commit}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
