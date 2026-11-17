// npm staging finishes before human approval. Reconcile the deployed reference after approval.
import assert from "node:assert/strict";
import { appendFileSync, readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const registry = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/latest`, {
  signal: AbortSignal.timeout(30_000), cache: "no-store",
});
assert.equal(registry.status, 200, "npm latest must be available");
const { version } = await registry.json();
assert.match(version, /^\d+\.\d+\.\d+$/, "npm latest must be a stable release");
const repository = new URL(pkg.repository.url.replace(/^git\+/, "")).pathname.split("/").at(-1).replace(/\.git$/, "");
const response = await fetch(`https://baselabs.github.io/${repository}/api/release.json`, {
  signal: AbortSignal.timeout(30_000), cache: "no-store",
});
assert.ok(response.ok || response.status === 404, `Pages manifest returned ${response.status}`);
const deployed = response.ok ? await response.json() : undefined;
const rebuild = deployed?.package !== pkg.name || deployed?.version !== version;
console.log(`Pages API: npm latest ${version}; deployed ${deployed?.version ?? "missing"}; rebuild=${rebuild}`);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `rebuild=${rebuild}\n`);
