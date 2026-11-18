"""Compare saved Jupyter outputs with fresh Deno kernels over inspected npm archives."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "https://registry.npmjs.org/"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(*args: str, cwd: Path, env: dict[str, str]) -> str:
    return subprocess.run(args, cwd=cwd, env=env, check=True, text=True,
                          capture_output=True, timeout=300).stdout.strip()


def normalize_outputs(cell: dict) -> list[tuple[str, str]]:
    """Ignore counts, rich MIME alternatives and ANSI color; preserve semantic text."""
    normalized: list[tuple[str, str]] = []
    for output in cell.get("outputs", []):
        kind = output["output_type"]
        require(kind != "error", "notebook cell failed")
        if kind == "stream":
            if output["name"] == "stderr":
                continue  # Runtime diagnostics are not semantic results.
            channel, value = "stdout", output["text"]
        else:
            require(kind in ("execute_result", "display_data"), "unknown output type")
            require("text/plain" in output["data"], "display needs a safe text/plain result")
            channel, value = "display", output["data"]["text/plain"]
        text = "".join(value) if isinstance(value, list) else value
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).replace("\r\n", "\n")
        if normalized and channel == "stdout" and normalized[-1][0] == channel:
            normalized[-1] = (channel, normalized[-1][1] + text)
        else:
            normalized.append((channel, text))
    return [(channel, text.rstrip()) for channel, text in normalized if text.strip()]


def verify_archive(data: bytes, integrity: str, installed: Path) -> None:
    digest = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    require(integrity == digest, "archive integrity mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            relative = Path(member.name).relative_to("package")
            require(".." not in relative.parts, "unsafe archive member")
            require((installed / relative).read_bytes() == archive.extractfile(member).read(),
                    f"installed bytes differ from archive: {relative}")


def snapshot(directory: Path) -> dict[str, str]:
    return {path.relative_to(directory).as_posix():
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "directory"
            for path in directory.rglob("*")}


def check(local: bool) -> None:
    import nbformat
    from nbclient import NotebookClient
    from jupyter_client import AsyncKernelManager
    from jupyter_client.kernelspec import KernelSpecManager

    tool_versions = str(ROOT / "scripts/tool-versions.sh")
    run(tool_versions, "check", "python", cwd=ROOT)
    package = json.loads((ROOT / "package.json").read_text())
    directory = ROOT / "docs/notebooks"
    registry = json.loads((directory / "registry.json").read_text())
    require(registry["schema"] == 1, "unknown notebook registry schema")
    require((registry["package"], registry["version"]) == (package["name"], package["version"]),
            "notebook registry identity mismatch")
    packages = registry["packages"]
    require(packages.get(package["name"]) == package["version"], "candidate pin missing")
    names = [entry["file"] for entry in registry["notebooks"]]
    require(bool(names) and len(names) == len(set(names)), "empty or duplicate notebook registry")
    require(sorted(names) == sorted(path.relative_to(directory).as_posix()
                                   for path in directory.rglob("*.ipynb")), "notebook registry mismatch")
    originals = []
    for name in names:
        notebook = nbformat.read(directory / name, as_version=4)
        nbformat.validate(notebook)
        require(notebook.metadata.kernelspec.name == "deno", f"{name}: not a Deno notebook")
        code = [cell for cell in notebook.cells if cell.cell_type == "code"]
        require(bool(code), f"{name}: no code cells")
        source = "\n".join(cell.source for cell in code)
        imports = re.findall(r"npm:(@bounded-authority-protocol/[\w-]+)@([^\s\"'/]+)", source)
        require((package["name"], package["version"]) in imports, f"{name}: candidate import missing")
        for dependency, version in imports:
            require(packages.get(dependency) == version, f"{name}: unregistered or stale npm pin")
        for index, cell in enumerate(code, 1):
            require(bool(cell.source.strip()) and bool(normalize_outputs(cell)),
                    f"{name}: cell {index} needs persisted semantic output")
            require("semantic_output" not in cell.metadata, "saved Jupyter output is the only golden")
        originals.append(notebook)

    with tempfile.TemporaryDirectory(prefix="bap-notebooks-") as temporary:
        scratch = Path(temporary)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("DENO_", "JUPYTER_", "NPM_CONFIG_", "npm_config_"))}
        env.update({"DENO_DIR": str(scratch / "deno"), "DENO_NO_UPDATE_CHECK": "1",
                    "JUPYTER_DATA_DIR": str(scratch / "jupyter"),
                    "JUPYTER_CONFIG_DIR": str(scratch / "config"),
                    "JUPYTER_RUNTIME_DIR": str(scratch / "runtime"),
                    "npm_config_cache": str(scratch / "npm-cache"),
                    "npm_config_userconfig": str(scratch / "npmrc"),
                    "npm_config_globalconfig": str(scratch / "global-npmrc"),
                    "NPM_CONFIG_REGISTRY": REGISTRY, "NO_COLOR": "1",
                    "TMPDIR": str(scratch), "TMP": str(scratch), "TEMP": str(scratch)})
        (scratch / "runtime").mkdir()
        (scratch / "npmrc").write_text("registry=" + REGISTRY + "\n")
        (scratch / "global-npmrc").write_text("")
        for tool in ("nodejs", "deno", "uv"):
            run(tool_versions, "check", tool, cwd=scratch, env=env)
        artifact = None
        if local:
            packed = json.loads(run("node", str(ROOT / "tools/pack.mjs"), "--out",
                                    str(scratch / "packed"), cwd=ROOT, env=env))
            artifact = Path(packed["file"])
            require(hashlib.sha256(artifact.read_bytes()).hexdigest() == packed["sha256"], "packer digest differs")
        run("deno", "jupyter", "--install", cwd=scratch, env=env)
        for name, original in zip(names, originals, strict=True):
            consumer = scratch / Path(name).stem
            consumer.mkdir()
            dependencies = dict(packages)
            if local:
                dependencies[package["name"]] = artifact.as_uri()
            (consumer / "package.json").write_text(json.dumps({"private": True, "type": "module", "dependencies": dependencies}))
            (consumer / "deno.json").write_text('{"nodeModulesDir":"manual","lock":false}\n')
            run("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund",
                "--registry=" + REGISTRY, cwd=consumer, env=env)
            lock = json.loads((consumer / "package-lock.json").read_text())["packages"]
            probes = []
            for dependency, version in packages.items():
                installed = consumer / "node_modules" / dependency
                metadata = json.loads((installed / "package.json").read_text())
                require((metadata["name"], metadata["version"]) == (dependency, version), "installed identity mismatch")
                locked = lock["node_modules/" + dependency]
                if local and dependency == package["name"]:
                    require(locked["resolved"].startswith("file:"), "candidate resolved outside packed archive")
                    archive = artifact.read_bytes()
                else:
                    published = json.loads(run("npm", "view", dependency + "@" + version, "--json",
                                               "--registry=" + REGISTRY, cwd=consumer, env=env))
                    require((published["name"], published["version"]) == (dependency, version), "registry identity mismatch")
                    dist = published["dist"]
                    url = urlparse(dist["tarball"])
                    require(url.scheme == "https" and url.netloc == "registry.npmjs.org", "tarball origin mismatch")
                    require(locked["resolved"] == dist["tarball"] and locked["integrity"] == dist["integrity"],
                            "resolved registry origin or integrity mismatch")
                    with urlopen(dist["tarball"], timeout=60) as response:
                        require(response.url == dist["tarball"], "tarball redirected outside asserted origin")
                        archive = response.read()
                verify_archive(archive, locked["integrity"], installed)
                # The kernel must resolve npm: to the inspected archive's actual exported objects.
                probes.append("{\n" +
                    f"const resolved = await import({json.dumps('npm:' + dependency + '@' + version)});\n" +
                    f"const inspected = await import({json.dumps((installed / metadata['main']).as_uri())});\n" +
                    "const names = Object.keys(inspected);\n" +
                    "if (!names.length || names.length !== Object.keys(resolved).length ||\n" +
                    "    !names.every(name => Object.is(resolved[name], inspected[name])))\n" +
                    '  throw new Error("kernel resolved an unexpected package origin");\n}\n')
            baseline = snapshot(consumer)
            candidate = copy.deepcopy(original)
            for cell in candidate.cells:
                if cell.cell_type == "code":
                    cell.outputs = []
                    cell.execution_count = None
            candidate.cells.insert(0, nbformat.v4.new_code_cell("\n".join(probes)))
            manager = AsyncKernelManager(kernel_name="deno",
                connection_file=str(scratch / "runtime" / (Path(name).stem + ".json")),
                kernel_spec_manager=KernelSpecManager(kernel_dirs=[str(scratch / "jupyter/kernels")]))
            kernel_env = {**env, "TMPDIR": str(consumer), "TMP": str(consumer), "TEMP": str(consumer)}
            executed = NotebookClient(candidate, km=manager, kernel_name="deno", timeout=180,
                allow_errors=False, resources={"metadata": {"path": str(consumer)}}).execute(
                    env=kernel_env, cleanup_kc=True)
            for index, (expected, actual) in enumerate(zip(original.cells, executed.cells[1:], strict=True), 1):
                require(expected.source == actual.source, f"{name}: execution changed cell source")
                if expected.cell_type == "code":
                    require(actual.execution_count is not None, f"{name}: cell {index} not executed")
                    require(normalize_outputs(expected) == normalize_outputs(actual),
                            f"{name}: cell {index} semantic output mismatch")
            require(snapshot(consumer) == baseline, f"{name}: notebook changed files or left residue")
            print(f"PASS {name} ({'local' if local else 'published'}): archives, kernel origin and saved outputs")
    require(not scratch.exists(), "runner left scratch files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--local", action="store_true")
    modes.add_argument("--published", action="store_true")
    check(parser.parse_args().local)
