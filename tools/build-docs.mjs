// One ordered site: the API, guides, source recipes and notebook transcripts share a release label.
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// documentation.json for the site version gate: the version the site targets, and every version
// written in the authored documents, which the gate permits only inside generated articles.
export function writeDocumentationMetadata(out, { version, channel, authored }) {
  const historicalVersions = [...new Set(Array.from(authored.join("\n")
    .matchAll(/(?<![\w.])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?!\w|\.\d)/g), (match) => match[1]))];
  writeFileSync(join(out, "documentation.json"), JSON.stringify({ version, channel, historicalVersions }, null, 2) + "\n");
}

export function buildDocumentation({ source = root, out = join(root, "build-docs/api") } = {}) {
  const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
  const registry = JSON.parse(readFileSync(join(root, "docs/manifest.json"), "utf8"));
  assert.equal(registry.version, pkg.version, "guides and API must target the same version");
  const notebooks = JSON.parse(readFileSync(join(root, "docs/notebooks/registry.json"), "utf8"));
  assert.equal(notebooks.package, pkg.name); assert.equal(notebooks.version, pkg.version);
  const scratch = mkdtempSync(join(tmpdir(), "bap-documents-"));
  try {
    cpSync(join(root, "docs"), join(scratch, "docs"), { recursive: true });
    for (const name of ["README.md", "usage-rules.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "NOTICE"]) {
      cpSync(join(root, name), join(scratch, name));
    }
    const documents = [...registry.pages.map((page) => page.path), ...registry.extras];
    for (const item of notebooks.notebooks) {
      const path = `docs/notebooks/${item.file}`;
      const notebook = JSON.parse(readFileSync(join(root, path), "utf8"));
      const transcript = path.replace(/\.ipynb$/, ".md");
      const text = notebook.cells.map((cell) => {
        const content = Array.isArray(cell.source) ? cell.source.join("") : cell.source;
        if (cell.cell_type === "markdown") return content;
        const output = (cell.outputs ?? []).map((value) => {
          assert.notEqual(value.output_type, "error", `${path}: saved cell error`);
          if (value.output_type === "stream" && value.name === "stderr") return "";
          const text = value.output_type === "stream" ? value.text : value.data?.["text/plain"];
          assert.ok(text, `${path}: missing safe text output`);
          return Array.isArray(text) ? text.join("") : text;
        }).join("");
        assert.ok(output.trim(), `${path}: missing safe output`);
        // Use a longer fence than any backticks in the authored cell.
        const fence = "`".repeat(Math.max(3, ...[...content.matchAll(/`+/g)].map(([ticks]) => ticks.length + 1)));
        return `${fence}ts\n${content}\n${fence}\n\nExpected semantic output (checked by notebook qualification):\n\n${fence}text\n${output.trimEnd()}\n${fence}`;
      }).join("\n\n");
      writeFileSync(join(scratch, transcript), text + `\n\n[Download the Jupyter notebook](${item.file})\n`);
      documents.push(transcript);
    }
    // Site links open the interactive journey transcript; each transcript retains its download.
    for (const path of ["README.md", ...registry.pages.map((page) => page.path), ...registry.extras]) {
      const file = join(scratch, path);
      writeFileSync(file, readFileSync(file, "utf8").replace(/(\]\([^\s)#]+)\.ipynb(?=[)#])/g, "$1.md"));
    }
    const options = JSON.parse(readFileSync(join(root, "typedoc.json"), "utf8"));
    options.tsconfig = join(source, "tsconfig.build.json");
    options.out = resolve(out);
    options.projectDocuments = documents.map((path) => join(scratch, path));
    options.plugin = [join(root, "tools/docs-plugin.mjs")];
    options.name = `${pkg.name} (development; candidate ${pkg.version})`;
    options.readme = join(scratch, "README.md");
    const config = join(scratch, "typedoc.json");
    writeFileSync(config, JSON.stringify(options));
    const result = spawn.sync(process.execPath, [join(root, "node_modules/typedoc/bin/typedoc"), "--options", config], {
      cwd: source, encoding: "utf8", timeout: 180_000,
    });
    if (result.error) throw result.error;
    assert.equal(result.status, 0, result.stdout + result.stderr);
    console.log(result.stdout.trim());
    mkdirSync(out, { recursive: true });
    // The version gate still checks headers and arbitrary pages against npm. The documented
    // historical/dependency versions in each generated article must occur in authored sources.
    writeDocumentationMetadata(out, { version: pkg.version, channel: "development",
      authored: documents.map((path) => readFileSync(join(scratch, path), "utf8")) });
    return out;
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) buildDocumentation();
