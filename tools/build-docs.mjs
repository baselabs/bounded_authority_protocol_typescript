// One ordered site: the API, guides, source recipes and notebook transcripts share a release label.
import assert from "node:assert/strict";
import spawn from "cross-spawn";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

export function buildDocumentation({ source = root, out = join(root, "site-dist/api-development"), released, commit } = {}) {
  const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
  const registry = JSON.parse(readFileSync(join(root, "docs/manifest.json"), "utf8"));
  assert.equal(registry.version, pkg.version, "guides and API must target the same version");
  const scratch = mkdtempSync(join(tmpdir(), "bap-documents-"));
  try {
    cpSync(join(root, "docs"), join(scratch, "docs"), { recursive: true });
    for (const name of ["README.md", "usage-rules.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "LICENSE", "NOTICE"]) {
      cpSync(join(root, name), join(scratch, name));
    }
    const documents = [...registry.pages.map((page) => page.path), ...registry.extras];
    for (const item of registry.notebooks) {
      const notebook = JSON.parse(readFileSync(join(root, item.path), "utf8"));
      const transcript = item.path.replace(/\.ipynb$/, ".md");
      const text = notebook.cells.map((cell) => {
        const content = Array.isArray(cell.source) ? cell.source.join("") : cell.source;
        if (cell.cell_type === "markdown") return content;
        const output = cell.metadata.semantic_output;
        assert.ok(output, `${item.path}: missing safe output`);
        // Use a longer fence than any backticks in the authored cell.
        const fence = "`".repeat(Math.max(3, ...[...content.matchAll(/`+/g)].map(([ticks]) => ticks.length + 1)));
        return `${fence}ts\n${content}\n${fence}\n\nExpected semantic output (checked by notebook qualification):\n\n${fence}text\n${output}${fence}`;
      }).join("\n\n");
      writeFileSync(join(scratch, transcript), text + `\n\n[Download the Jupyter notebook](${item.path.split("/").at(-1)})\n`);
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
    options.name = `${pkg.name} (${released ? `released v${pkg.version}` : `development; candidate ${pkg.version}`})`;
    options.readme = join(scratch, "README.md");
    if (released) {
      // Historical releases cannot acquire new source comments. They still use their own types,
      // exact dependency lock and immutable source links. Current coverage is separately strict.
      options.validation = { ...options.validation, notDocumented: false, notExported: false };
      options.disableSources = false;
      options.sourceLinkTemplate = `${pkg.repository.url.replace(/^git\+/, "").replace(/\.git$/, "")}/blob/${commit}/{path}#L{line}`;
    }
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
    const authored = documents.map((path) => readFileSync(join(scratch, path), "utf8")).join("\n");
    const historicalVersions = [...new Set([...authored.matchAll(/(?<![\w.])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?!\w|\.\d)/g)].map((match) => match[1]))];
    writeFileSync(join(out, "documentation.json"), JSON.stringify({ version: pkg.version, channel: released ? "released" : "development", historicalVersions }, null, 2) + "\n");
    return out;
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) buildDocumentation();
