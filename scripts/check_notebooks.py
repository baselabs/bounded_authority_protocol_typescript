"""Run registered notebooks in fresh real Deno Jupyter kernels; never concatenate cells."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import nbformat
from nbclient import NotebookClient
from jupyter_client import AsyncKernelManager
from jupyter_client.kernelspec import KernelSpecManager

ROOT = Path(__file__).resolve().parent.parent


def run(*args, cwd=ROOT, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, check=True, text=True, capture_output=True, timeout=300)
    return result.stdout.strip()


def outputs(cell):
    text = ""
    for output in cell.get("outputs", []):
        if output.output_type == "stream" and output.name == "stdout":
            text += output.text
        elif output.output_type == "error":
            raise AssertionError("notebook cell failed")
        elif output.output_type == "stream" and output.name == "stderr":
            # Runtime warnings are not part of the stable semantic output.
            continue
        else:
            raise AssertionError("persist only explicit safe stdout, not implicit values")
    return text


def check(mode):
    manifest = json.loads((ROOT / "docs/manifest.json").read_text())
    package = json.loads((ROOT / "package.json").read_text())
    paths = [ROOT / item["path"] for item in manifest["notebooks"]]
    assert set(paths) == set((ROOT / "docs/notebooks").rglob("*.ipynb")), "notebook registry mismatch"
    assert paths, "empty notebook registry"
    pins = dict(line.split() for line in (ROOT / ".tool-versions").read_text().splitlines())
    assert run("deno", "--version").splitlines()[0].split()[1] == pins["deno"]
    assert run("python", "--version") == f"Python {pins['python']}"
    version = package["version"]
    specifier = f"npm:{package['name']}@{version}"
    with tempfile.TemporaryDirectory(prefix="bap-notebooks-") as temporary:
        scratch = Path(temporary)
        env = {**os.environ, "DENO_DIR": str(scratch / "cache"), "JUPYTER_DATA_DIR": str(scratch / "jupyter"),
               "JUPYTER_CONFIG_DIR": str(scratch / "config"), "JUPYTER_RUNTIME_DIR": str(scratch / "runtime"),
               "npm_config_cache": str(scratch / "npm-cache"), "TMPDIR": str(scratch),
               "TMP": str(scratch), "TEMP": str(scratch)}
        (scratch / "runtime").mkdir()
        # A kernel installed here belongs only to this run and is removed with its root.
        run("deno", "jupyter", "--install", cwd=scratch, env=env)
        consumer = scratch / "consumer"
        consumer.mkdir()
        if mode == "--local":
            packed = json.loads(run("node", str(ROOT / "tools/pack.mjs"), "--out", str(scratch / "pack"), env=env))
            (consumer / "package.json").write_text(json.dumps({"private": True, "type": "module", "dependencies": {package["name"]: f"file:{packed['file']}"}}))
            run("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", cwd=consumer, env=env)
            installed = consumer / "node_modules" / package["name"]
            assert json.loads((installed / "package.json").read_text())["version"] == version
            locked = json.loads((consumer / "package-lock.json").read_text())["packages"][f"node_modules/{package['name']}"]
            assert locked["resolved"].startswith("file:"), "local mode must use inspected tarball"
            entry = (installed / package["main"]).as_uri()
            metadata = (installed / "package.json").as_uri()
        else:
            registry = json.loads(run("npm", "view", f"{package['name']}@{version}", "--json", "--registry=https://registry.npmjs.org"))
            assert registry["name"] == package["name"] and registry["version"] == version
            assert registry["dist"]["tarball"].startswith("https://registry.npmjs.org/")
            # No package.json, imports map, node_modules or inherited config can substitute local code.
            (consumer / "deno.json").write_text('{"nodeModulesDir":"none","lock":false}\n')
            graph = json.loads(run("deno", "info", "--json", specifier, cwd=consumer, env=env))
            packages = graph.get("npmPackages", {})
            resolved = packages.get(f"{package['name']}@{version}")
            assert resolved and resolved["version"] == version, "resolved npm version differs"
            assert resolved["registryUrl"] == "https://registry.npmjs.org/", "resolved npm origin differs"
            cached = scratch / "cache/npm/registry.npmjs.org" / package["name"] / version / "package.json"
            assert cached.is_file(), "Deno must resolve the npm registry cache, not a local tree"
            assert json.loads(cached.read_text())["version"] == version
        for path in paths:
            notebook = nbformat.read(path, as_version=4)
            assert notebook.metadata.kernelspec.name == "deno", path
            assert notebook.metadata.bap.version == version, path
            code = [cell for cell in notebook.cells if cell.cell_type == "code"]
            assert code, f"{path}: no code cells"
            for cell in code:
                assert cell.source.strip(), f"{path}: empty code cell"
                assert outputs(cell) and outputs(cell) == cell.metadata.semantic_output, f"{path}: missing or inconsistent persisted output"
            candidate = copy.deepcopy(notebook)
            if mode == "--local":
                for cell in candidate.cells:
                    if cell.cell_type == "code":
                        cell.source = cell.source.replace(specifier + "/package.json", metadata).replace(specifier, entry)
            workspace = consumer / path.stem
            workspace.mkdir()
            # Published execution has no rewritten cells. Only the isolated resolver config is copied.
            # Local execution resolves the packed candidate's npm-installed dependency tree.
            resolution = "manual" if mode == "--local" else "none"
            (workspace / "deno.json").write_text(json.dumps({"nodeModulesDir": resolution, "lock": False}) + "\n")
            baseline = {p.relative_to(workspace) for p in workspace.rglob("*")}
            for cell in candidate.cells:
                if cell.cell_type == "code":
                    cell.outputs = []
                    cell.execution_count = None
            # jupyter_client passes env through to the actual kernel subprocess.
            kernel_env = {**env, "TMPDIR": str(workspace), "TMP": str(workspace), "TEMP": str(workspace)}
            manager = AsyncKernelManager(kernel_name="deno", connection_file=str(scratch / "runtime" / f"{path.stem}.json"), kernel_spec_manager=KernelSpecManager(
                kernel_dirs=[str(scratch / "jupyter/kernels")]))
            executed = NotebookClient(candidate, km=manager, timeout=180, kernel_name="deno", allow_errors=False,
                resources={"metadata": {"path": str(workspace)}}).execute(env=kernel_env, cleanup_kc=True)
            for saved, actual in zip(notebook.cells, executed.cells, strict=True):
                if saved.cell_type == "code":
                    assert actual.execution_count is not None, f"{path}: unexecuted cell"
                    assert outputs(actual) == saved.metadata.semantic_output, f"{path}: semantic output mismatch"
            assert {p.relative_to(workspace) for p in workspace.rglob("*")} == baseline, f"{path}: notebook left residue"
            print(f"notebook PASS {path.relative_to(ROOT)} {mode}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--local", action="store_true")
    group.add_argument("--published", action="store_true")
    arguments = parser.parse_args()
    check("--local" if arguments.local else "--published")
