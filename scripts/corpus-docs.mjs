// Current corpus identity and counts have exactly one generated home in tracked prose.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import catalogue from "../conformance/catalogue.json" with {type: "json"};
const START = "<!-- corpus-source:start -->", END = "<!-- corpus-source:end -->";
const block = /<!-- corpus-source:start -->[\s\S]*?<!-- corpus-source:end -->/g;
export function corpusSummary(files, source) {
  const identity = source.candidate === undefined
    ? `Pinned Hex corpus: [bounded_authority_protocol ${source.version}](https://hex.pm/packages/bounded_authority_protocol/${source.version}).`
    : `Candidate corpus: monorepo commit \`${source.candidate}\`.`;
  const rows = Object.entries(catalogue).map(([name, path]) => {
    const i = JSON.parse(files.get(`${path}/index.json`));
    const total = i.total_cases ?? (i.verdict_sha256 ? i.files.reduce((sum, file) => sum + (file.cases ?? 0), 0) : undefined) ?? i.attestation_cases ?? (i.uri_cases !== undefined ? i.uri_cases + i.proof_cases : i.assertion_cases + i.digest_cases + i.successor_cases);
    return `| ${name} | ${total} |`;
  });
  return [START, identity, "", "| Corpus | Cases |", "|---|---|", ...rows, END].join("\n");
}
export function rewriteCorpusSummary(root, files, source) {
  const path = join(root, "README.md");
  if (!existsSync(path)) return;
  const text = readFileSync(path, "utf8");
  if ([...text.matchAll(block)].length !== 1) throw new Error("README.md: exactly one corpus summary block required");
  writeFileSync(path, text.replace(block, () => corpusSummary(files, source)));
}
export function assertDocumentation(root, files, source, paths) {
  paths ??= execFileSync("git", ["ls-files", "-z", "--", "*.md", "*.html", "*.yml", "*.yaml"], {cwd: root, encoding: "utf8"}).split("\0").filter(Boolean);
  for (const path of paths) {
    let text = readFileSync(join(root, path), "utf8");
    if (path === "CHANGELOG.md") text = text.split(/^## \[(?!Unreleased)/m)[0]; // Released history is historical, not a current claim.
    if (path === "README.md" && ([...text.matchAll(block)].length !== 1 || !text.includes(corpusSummary(files, source)))) throw new Error("README.md: corpus summary differs from SOURCE/snapshot");
    if (path !== "README.md" && block.test(text)) throw new Error(`${path}: corpus summary belongs only in README.md`);
    text = text.replace(block, "");
    // Ban copied release identities/counts outside the generated block; they silently stale on adoption.
    const release = /(?:Hex[^\n]{0,100}|bounded_authority_protocol[`\s\]]+|hex\.pm\/(?:api\/)?packages\/bounded_authority_protocol\/(?:releases\/)?)(?:\d+\.){2}\d+/i;
    const count = /\b\d[\d,]*(?:\/\d[\d,]*)?(?:\s*\+\s*\d[\d,]*)*\s+(?:cases|vectors|assertions|digests|successors|verdicts)\b|\b\d+\/\d+\b|\|\s*(?:v[123]|contract.major [123]|strict Ed25519|role.attestation|content.assertion|local.loopback[^|]*|producer canonicality|selector float.zero)\s*\|[^\n]*\d/i;
    if (release.test(text) || count.test(text)) throw new Error(`${path}: copied corpus version/count outside generated SOURCE summary`);
  }
}
