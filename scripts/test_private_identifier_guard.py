#!/usr/bin/env python3
"""Real-Git acceptance tests for the local private-identifier guard."""

from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUARD = PROJECT_ROOT / "scripts" / "private_identifier_guard.py"
INSTALLER = PROJECT_ROOT / "scripts" / "install-hooks.sh"
MANIFEST_REL = Path("info/private-identifiers")
EXPECTATION_REL = Path(
    "info/private-identifier-guard/private-identifier-expectation.json"
)
ACTIVATION_REL = Path(
    "info/private-identifier-guard/private-identifier-active"
)
ACTIVATION_CONFIG_KEY = "bap.privateIdentifierGuard.active"
ZERO_OID = "0" * 40


def run(
    *args: str,
    cwd: Path,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    command_env = os.environ.copy()
    for name in tuple(command_env):
        if name.startswith("GIT_"):
            command_env.pop(name)
    command_env.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    if env:
        command_env.update(env)
    return subprocess.run(
        args,
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
        env=command_env,
        check=False,
    )


def git(repo: Path, *args: str, input_text: str | None = None) -> str:
    result = run("git", *args, cwd=repo, input_text=input_text)
    if result.returncode != 0:
        raise AssertionError("real git command failed")
    return result.stdout.strip()


# Every throwaway repository turns off git's automatic maintenance before any
# command that would start it. From git 2.54 the default maintenance strategy
# is "geometric", and commit, fetch, and a push into a local bare remote (its
# receive-pack) start `git maintenance run --auto --detach`: a repack that
# keeps writing packs into .git after the command returns. shutil.rmtree in
# tearDown then races it and fails intermittently with "directory not empty"
# (hosted CI runs git 2.55). With these two settings git starts no such process.
def init_scratch_repo(repo: Path, *init_args: str) -> None:
    git(repo, "init", *init_args)
    git(repo, "config", "maintenance.auto", "false")
    git(repo, "config", "gc.auto", "0")


class PrivateIdentifierGuardTest(unittest.TestCase):
    maxDiff = 1600

    def setUp(self) -> None:
        self.scratch = Path(tempfile.mkdtemp(prefix="bap-local-guard-test."))
        self.repo = self.scratch / "repo"
        self.repo.mkdir()
        init_scratch_repo(self.repo, "-q")
        self.common_dir = Path(
            git(self.repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
        )
        git(self.repo, "config", "user.email", "guard@example.invalid")
        git(self.repo, "config", "user.name", "Guard Test")
        self.pattern = "public-synthetic-orchid"
        self.other_pattern = "public-synthetic-cobalt"
        self.patterns = (
            self.pattern,
            self.other_pattern,
            "public-synthetic-amber",
            "public-synthetic-birch",
            "public-synthetic-coral",
            "public-synthetic-delta",
        )
        self.write_manifest(*self.patterns)
        self.initialize(len(self.patterns))
        (self.repo / "baseline.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "baseline.txt")
        git(self.repo, "commit", "-qm", "baseline")

    def tearDown(self) -> None:
        shutil.rmtree(self.scratch)

    def write_manifest(self, *patterns: str) -> None:
        manifest = self.common_dir / MANIFEST_REL
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("\n".join(patterns) + "\n", encoding="utf-8")

    def initialize(self, count: int) -> None:
        result = self.guard("initialize", "--expected-count", str(count))
        self.assertEqual(result.returncode, 0, "expectation initialization failed")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        expectation = self.common_dir / EXPECTATION_REL
        self.assertTrue(expectation.is_file())
        parsed = json.loads(expectation.read_text(encoding="utf-8"))
        self.assertEqual(parsed["entry_count"], count)
        self.assertEqual(set(parsed), {"entry_count", "manifest_sha256"})
        self.assertEqual((self.common_dir / ACTIVATION_REL).read_bytes(), b"enabled\n")
        self.assertEqual(
            git(self.repo, "config", "--local", "--bool", "--get", ACTIVATION_CONFIG_KEY),
            "true",
        )

    def copy_hook_sources(self) -> None:
        scripts = self.repo / "scripts"
        scripts.mkdir(exist_ok=True)
        shutil.copy2(GUARD, scripts / GUARD.name)
        shutil.copy2(INSTALLER, scripts / "install-hooks.sh")
        hooks = scripts / "hooks"
        hooks.mkdir()
        for name in ("pre-commit", "commit-msg", "pre-push"):
            shutil.copy2(PROJECT_ROOT / "scripts" / "hooks" / name, hooks / name)

    def install_real_hooks(self) -> None:
        self.write_manifest(*self.patterns)
        self.copy_hook_sources()
        (self.common_dir / EXPECTATION_REL).unlink()
        subdirectory = self.repo / "subdirectory"
        subdirectory.mkdir()
        result = run(
            "bash",
            "../scripts/install-hooks.sh",
            "--initialize-private-identifier-expectation",
            str(len(self.patterns)),
            cwd=subdirectory,
        )
        self.assertEqual(result.returncode, 0, "real hook installation failed")
        result = run("bash", "../scripts/install-hooks.sh", cwd=subdirectory)
        self.assertEqual(result.returncode, 0, "routine hook validation failed")

    def guard(
        self,
        mode: str,
        *args: str,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        repo: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        checkout = self.repo if repo is None else repo
        return run(
            sys.executable,
            str(GUARD),
            "--repo",
            str(checkout),
            mode,
            *args,
            cwd=checkout,
            input_text=input_text,
            env=env,
        )

    def assert_safe_output(self, result: subprocess.CompletedProcess[str]) -> None:
        output = (result.stdout + result.stderr).casefold()
        for pattern in self.patterns:
            self.assertNotIn(pattern.casefold(), output)
        self.assertNotIn("secret payload", output)
        self.assertNotIn("secret message", output)

    def test_manifest_state_fails_closed(self) -> None:
        manifest = self.common_dir / MANIFEST_REL
        expectation = self.common_dir / EXPECTATION_REL
        activation = self.common_dir / ACTIVATION_REL

        manifest.unlink()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(*self.patterns)
        manifest.chmod(0)
        result = self.guard("pre-commit")
        manifest.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(self.pattern)
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(
            self.pattern,
            self.other_pattern + "-changed",
            *self.patterns[2:],
        )
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.write_manifest(*self.patterns)
        expectation.unlink()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.initialize(len(self.patterns))
        activation.unlink()
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        self.initialize(len(self.patterns))
        activation.write_text("invalid\n", encoding="ascii")
        result = self.guard("pre-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

    def test_policy_parent_symlink_fails_closed(self) -> None:
        policy = self.common_dir / EXPECTATION_REL.parent
        held = policy.with_name("private-identifier-guard-held")
        policy.rename(held)
        policy.symlink_to(held.name, target_is_directory=True)
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

    def test_shared_info_parent_symlink_fails_closed(self) -> None:
        info = self.common_dir / "info"
        held = self.common_dir / "info-held"
        info.rename(held)
        info.symlink_to(held.name, target_is_directory=True)
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

    def test_policy_follows_separate_git_directory(self) -> None:
        separate = self.scratch / "metadata.git"
        git(self.repo, "init", "-q", "--separate-git-dir", str(separate))
        self.assertTrue((separate / MANIFEST_REL).is_file())
        self.assertFalse(self.common_dir.is_dir())
        result = self.guard("validate-policy")
        self.assertEqual(result.returncode, 0, result.stderr)

        path = self.repo / "content.txt"
        path.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        git(self.repo, "add", path.name)
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assert_safe_output(result)

    def test_persistent_activation_denies_removed_ignored_policy(self) -> None:
        (self.common_dir / MANIFEST_REL).unlink()
        shutil.rmtree(self.common_dir / EXPECTATION_REL.parent)
        self.assertEqual(
            git(self.repo, "config", "--local", "--bool", "--get", ACTIVATION_CONFIG_KEY),
            "true",
        )
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

    def test_pre_commit_scans_staged_blob_and_path_without_leaking(self) -> None:
        path = self.repo / "content.txt"
        path.write_text(f"secret payload {self.pattern.upper()}\n", encoding="utf-8")
        git(self.repo, "add", "content.txt")
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("pattern=1", result.stderr)
        self.assertIn("line=1", result.stderr)
        self.assert_safe_output(result)

        git(self.repo, "reset", "-q", "HEAD", "--", "content.txt")
        path.unlink()
        secret_path = f"notes-{self.other_pattern}.txt"
        (self.repo / secret_path).write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", secret_path)
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("pattern=2", result.stderr)
        self.assertIn("index-entry=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_commit_scans_symlink_blob_without_following_target(self) -> None:
        target = f"missing-{self.pattern}-target"
        os.symlink(target, self.repo / "link.txt")
        git(self.repo, "add", "link.txt")
        result = self.guard("pre-commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_commit_message_is_scanned_without_leaking(self) -> None:
        message = self.scratch / "COMMIT_EDITMSG"
        message.write_text(f"secret message {self.pattern}\n", encoding="utf-8")
        result = self.guard("commit-msg", str(message))
        self.assertEqual(result.returncode, 1)
        self.assertIn("message-file line=1 pattern=1", result.stderr)
        self.assert_safe_output(result)

    def make_remote(self) -> tuple[Path, str]:
        remote = self.scratch / "remote.git"
        remote.mkdir()
        init_scratch_repo(remote, "--bare", "-q")
        git(self.repo, "remote", "add", "origin", str(remote))
        head = git(self.repo, "rev-parse", "HEAD")
        result = self.guard(
            "pre-push",
            "origin",
            str(remote),
            input_text=f"refs/heads/main {head} refs/heads/main {ZERO_OID}\n",
        )
        self.assertEqual(result.returncode, 0)
        git(self.repo, "push", "-q", "origin", "HEAD:refs/heads/main")
        git(self.repo, "fetch", "-q", "origin")
        return remote, head

    def pre_push(
        self,
        remote: Path,
        local_ref: str,
        local_oid: str,
        remote_ref: str,
        remote_oid: str,
    ) -> subprocess.CompletedProcess[str]:
        return self.guard(
            "pre-push",
            "origin",
            str(remote),
            input_text=f"{local_ref} {local_oid} {remote_ref} {remote_oid}\n",
        )

    def rewind_main(self, oid: str) -> None:
        git(self.repo, "checkout", "-q", "--detach", oid)
        git(self.repo, "branch", "-f", "main", oid)
        git(self.repo, "checkout", "-q", "main")

    def test_pre_push_scans_outgoing_content_message_and_path(self) -> None:
        remote, remote_oid = self.make_remote()

        (self.repo / "outgoing.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "outgoing.txt")
        git(self.repo, "commit", "-qm", "content change")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

        self.rewind_main(remote_oid)
        (self.repo / "message.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "message.txt")
        git(self.repo, "commit", "-qm", f"secret message {self.pattern}")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("commit=", result.stderr)
        self.assert_safe_output(result)

        self.rewind_main(remote_oid)
        secret_path = f"outgoing-{self.other_pattern}.txt"
        (self.repo / secret_path).write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", secret_path)
        git(self.repo, "commit", "-qm", "path change")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("tree-entry=", result.stderr)
        self.assert_safe_output(result)

    def test_linked_worktree_reads_common_git_policy(self) -> None:
        remote, remote_oid = self.make_remote()
        linked = self.scratch / "linked"
        git(self.repo, "worktree", "add", "-q", "-b", "linked-fixture", str(linked))
        self.assertEqual(
            Path(git(linked, "rev-parse", "--path-format=absolute", "--git-common-dir")),
            self.common_dir,
        )
        linked_git_dir = Path(git(linked, "rev-parse", "--absolute-git-dir"))
        self.assertFalse((linked_git_dir / MANIFEST_REL).exists())

        def push(local_oid: str) -> subprocess.CompletedProcess[str]:
            return self.guard(
                "pre-push",
                "origin",
                str(remote),
                repo=linked,
                input_text=(
                    f"refs/heads/linked-fixture {local_oid} "
                    f"refs/heads/main {remote_oid}\n"
                ),
            )

        (linked / "linked.txt").write_text("clean\n", encoding="utf-8")
        git(linked, "add", "linked.txt")
        git(linked, "commit", "-qm", "linked clean")
        clean_oid = git(linked, "rev-parse", "HEAD")
        result = push(clean_oid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")

        (linked / "outgoing.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(linked, "add", "outgoing.txt")
        git(linked, "commit", "-qm", "linked content change")
        result = push(git(linked, "rev-parse", "HEAD"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

        # A per-worktree policy cannot replace missing clone-shared policy.
        (linked_git_dir / MANIFEST_REL.parent).mkdir(parents=True)
        shutil.copy2(self.common_dir / MANIFEST_REL, linked_git_dir / MANIFEST_REL)
        shutil.copytree(
            self.common_dir / EXPECTATION_REL.parent,
            linked_git_dir / EXPECTATION_REL.parent,
        )
        (self.common_dir / MANIFEST_REL).unlink()
        result = push(clean_oid)
        self.assertEqual(result.returncode, 2)
        self.assertIn("guard-state=manifest", result.stderr)
        self.assert_safe_output(result)

        bare = self.scratch / "bare.git"
        git(self.scratch, "clone", "--bare", "-q", str(self.repo), str(bare))
        git(bare, "config", "maintenance.auto", "false")
        git(bare, "config", "gc.auto", "0")
        bare_linked = self.scratch / "bare-linked"
        git(bare, "worktree", "add", "-q", "--detach", str(bare_linked), remote_oid)
        result = self.guard(
            "pre-push",
            "origin",
            str(remote),
            repo=bare_linked,
            input_text=f"refs/heads/main {remote_oid} refs/heads/main {remote_oid}\n",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("guard-state=policy-root-bare", result.stderr)

    def test_pre_push_scans_annotated_tag_message(self) -> None:
        remote, _remote_oid = self.make_remote()
        git(self.repo, "tag", "-a", "release-test", "-m", f"{self.pattern} tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/release-test")
        result = self.pre_push(
            remote,
            "refs/tags/release-test",
            tag_oid,
            "refs/tags/release-test",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("tag=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_git_invocation_count_is_independent_of_tree_size(self) -> None:
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        wrapper_dir = self.scratch / "bin"
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "git"
        wrapper.write_text(
            '#!/usr/bin/env bash\nset -euo pipefail\nprintf \'%s\\n\' "$*" >> "$GUARD_INVOCATION_LOG"\n'
            f'exec {shlex.quote(real_git)} "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        log = self.scratch / "git-invocations.log"
        env = {
            "PATH": str(wrapper_dir) + os.pathsep + os.environ["PATH"],
            "GUARD_INVOCATION_LOG": str(log),
        }

        def invocation_counts(local_oid: str, remote_oid: str) -> tuple[int, int]:
            log.write_text("", encoding="ascii")
            result = self.guard(
                "pre-push",
                "origin",
                "unused-remote",
                input_text=(
                    f"refs/heads/main {local_oid} refs/heads/main {remote_oid}\n"
                ),
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_safe_output(result)
            calls = log.read_text(encoding="utf-8").splitlines()
            return len(calls), sum(call.endswith(" cat-file --batch") for call in calls)

        base = git(self.repo, "rev-parse", "HEAD")
        for number in range(3):
            path = self.repo / "files" / f"dir-{number % 7}" / f"file-{number}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"clean content {number}\n", encoding="ascii")
        git(self.repo, "add", "files")
        git(self.repo, "commit", "-qm", "small tree")
        small = git(self.repo, "rev-parse", "HEAD")
        small_update, small_update_batches = invocation_counts(small, base)
        small_new, small_new_batches = invocation_counts(small, ZERO_OID)

        for number in range(3, 323):
            path = self.repo / "files" / f"dir-{number % 7}" / f"file-{number}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"clean content {number}\n", encoding="ascii")
        git(self.repo, "add", "files")
        git(self.repo, "commit", "-qm", "large tree")
        large = git(self.repo, "rev-parse", "HEAD")
        large_update, large_update_batches = invocation_counts(large, small)
        large_new, large_new_batches = invocation_counts(large, ZERO_OID)
        self.assertEqual(small_update, large_update)
        self.assertEqual(small_new, large_new)
        self.assertEqual(
            (small_update_batches, large_update_batches, small_new_batches, large_new_batches),
            (1, 1, 1, 1),
        )

    def test_pre_push_tree_entry_number_matches_recursive_ls_tree(self) -> None:
        for name in ("a/first.txt", "a/nested/second.txt", "m/before.txt", "z/last.txt"):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("clean\n", encoding="ascii")
        git(self.repo, "add", "a", "m", "z")
        git(self.repo, "commit", "-qm", "unchanged sibling trees")
        remote, remote_oid = self.make_remote()
        introduced = f"m/deep/nested/{self.pattern}.txt"
        path = self.repo / introduced
        path.parent.mkdir(parents=True)
        path.write_text("clean\n", encoding="ascii")
        git(self.repo, "add", introduced)
        git(self.repo, "commit", "-qm", "nested path")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        entries = git(self.repo, "ls-tree", "-r", "--full-tree", local_oid).splitlines()
        index = next(
            number
            for number, entry in enumerate(entries, start=1)
            if entry.endswith("\t" + introduced)
        )
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr,
            "private-identifier-guard: deny "
            f"source=commit={local_oid} tree-entry={index} line=0 pattern=1\n"
            "private-identifier-guard: deny findings=1\n",
        )
        self.assert_safe_output(result)

        tree_oid = git(self.repo, "rev-parse", f"{local_oid}^{{tree}}")
        result = self.pre_push(
            remote, tree_oid, tree_oid, "refs/tags/tree-numbering", ZERO_OID
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr,
            "private-identifier-guard: deny "
            f"source=push-object=1 tree-entry={index} line=0 pattern=1\n"
            "private-identifier-guard: deny findings=1\n",
        )
        self.assert_safe_output(result)

    def test_merge_scans_only_entries_differing_from_every_parent(self) -> None:
        remote, base = self.make_remote()
        shared = f"shared-{self.patterns[2]}.txt"
        left_path = f"left/{self.pattern}.txt"
        right_path = f"right/{self.other_pattern}.txt"
        (self.repo / "left").mkdir()
        (self.repo / left_path).write_text(self.pattern + "\n", encoding="ascii")
        (self.repo / shared).write_text("left version\n", encoding="ascii")
        git(self.repo, "add", "left", shared)
        git(self.repo, "commit", "-qm", "left parent")
        left = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "-qb", "right-parent", base)
        (self.repo / "right").mkdir()
        (self.repo / right_path).write_text(self.other_pattern + "\n", encoding="ascii")
        (self.repo / shared).write_text("right version\n", encoding="ascii")
        git(self.repo, "add", "right", shared)
        git(self.repo, "commit", "-qm", "right parent")
        right = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "left").mkdir()
        (self.repo / left_path).write_text(self.pattern + "\n", encoding="ascii")
        (self.repo / shared).write_text(self.patterns[3] + "\n", encoding="ascii")
        git(self.repo, "add", "left", shared)
        tree = git(self.repo, "write-tree")
        merge = git(self.repo, "commit-tree", tree, "-p", left, "-p", right, "-m", "merge")
        result = self.pre_push(
            remote, "refs/heads/main", merge, "refs/heads/main", base
        )
        self.assertEqual(result.returncode, 1)
        self.assertRegex(result.stderr, rf"commit={left} tree-entry=\d+ line=0 pattern=1")
        self.assertRegex(result.stderr, rf"commit={right} tree-entry=\d+ line=0 pattern=2")
        merge_lines = [line for line in result.stderr.splitlines() if f"commit={merge} " in line]
        self.assertEqual(len(merge_lines), 1)
        self.assertTrue(merge_lines[0].endswith("line=0 pattern=3"))
        merged_blob = git(self.repo, "rev-parse", f"{merge}:{shared}")
        self.assertIn(f"blob={merged_blob} line=1 pattern=4", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_denies_rename_of_remote_blob_to_confidential_path(self) -> None:
        remote, remote_oid = self.make_remote()
        original_blob = git(self.repo, "rev-parse", "HEAD:baseline.txt")
        renamed = f"renamed-{self.pattern}.txt"
        git(self.repo, "mv", "baseline.txt", renamed)
        git(self.repo, "commit", "-qm", "rename existing blob")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        self.assertEqual(git(self.repo, "rev-parse", f"HEAD:{renamed}"), original_blob)
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"commit={local_oid} tree-entry=1 line=0 pattern=1", result.stderr)
        self.assert_safe_output(result)

    def write_raw_tree(self, raw: bytes) -> str:
        source = self.scratch / "raw-tree"
        source.write_bytes(raw)
        return git(self.repo, "hash-object", "-w", "--literally", "-t", "tree", str(source))

    def test_tree_modes_are_canonicalized_before_comparing_parents(self) -> None:
        blob = bytes.fromhex(git(self.repo, "rev-parse", "HEAD:baseline.txt"))
        entry = self.pattern.encode("ascii") + b"\0" + blob
        parent_tree = self.write_raw_tree(b"100664 " + entry)
        parent = git(self.repo, "commit-tree", parent_tree, "-m", "parent")
        tree = self.write_raw_tree(b"100644 " + entry)
        child = git(self.repo, "commit-tree", tree, "-p", parent, "-m", "canonical mode")
        result = self.pre_push(
            self.scratch, "refs/heads/main", child, "refs/heads/main", parent
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_safe_output(result)

        tree = self.write_raw_tree(b"100744 " + entry)
        child = git(self.repo, "commit-tree", tree, "-p", parent, "-m", "executable mode")
        result = self.pre_push(
            self.scratch, "refs/heads/main", child, "refs/heads/main", parent
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"commit={child} tree-entry=1 line=0 pattern=1", result.stderr)
        self.assert_safe_output(result)

    def test_malformed_missing_and_wrong_type_tree_entries_fail_closed(self) -> None:
        blob = bytes.fromhex(git(self.repo, "rev-parse", "HEAD:baseline.txt"))
        commit = bytes.fromhex(git(self.repo, "rev-parse", "HEAD"))
        cases = (
            b"10x644 clean\0" + blob,
            b"100644 clean\0" + blob[:4],
            b"100644 \0" + blob,
            b"100644 clean\0" + bytes(20),
            b"100644 clean\0" + commit,
            b"40000 clean\0" + blob,
        )
        for raw in cases:
            with self.subTest(raw=raw[:6]):
                tree = self.write_raw_tree(raw)
                result = self.pre_push(
                    self.scratch, tree, tree, "refs/tags/tree-validation", ZERO_OID
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("guard-state=", result.stderr)
                self.assert_safe_output(result)

    def test_batch_process_is_reaped_on_every_context_exit(self) -> None:
        namespace = runpy.run_path(str(GUARD))
        guard_class = namespace["Guard"]
        guard_error = namespace["GuardError"]
        head = git(self.repo, "rev-parse", "HEAD").encode("ascii")
        for mode in ("normal", "guard-error", "unexpected-error", "process-death"):
            with self.subTest(mode=mode):
                guard = guard_class(self.repo)
                self.assertIsNone(guard._batch)
                try:
                    with guard:
                        guard.read_object(head, b"commit")
                        process = guard._batch
                        guard.object_type(head)
                        self.assertIs(guard._batch, process)
                        if mode == "guard-error":
                            guard.read_object(b"0" * guard.object_hex_length)
                        elif mode == "unexpected-error":
                            raise RuntimeError("synthetic unexpected exception")
                        elif mode == "process-death":
                            process.kill()
                            process.wait()
                            guard.read_object(head)
                except guard_error:
                    self.assertIn(mode, ("guard-error", "process-death"))
                except RuntimeError:
                    self.assertEqual(mode, "unexpected-error")
                else:
                    self.assertEqual(mode, "normal")
                self.assertIsNotNone(process.returncode)
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed)
                self.assertIsNone(guard._batch)

    def test_pre_push_scans_remote_ref_name_and_tag_object_from_oid(self) -> None:
        remote, remote_oid = self.make_remote()
        result = self.pre_push(
            remote,
            "HEAD",
            remote_oid,
            f"refs/heads/{self.pattern}",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("push-ref=", result.stderr)
        self.assert_safe_output(result)

        git(self.repo, "tag", "-a", "safe-tag", "-m", f"{self.pattern} tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/safe-tag")
        result = self.pre_push(
            remote,
            tag_oid,
            tag_oid,
            "refs/tags/safe-target",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("tag=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_scans_symlink_blob_without_following_target(self) -> None:
        remote, remote_oid = self.make_remote()
        target = f"missing-{self.pattern}-target"
        os.symlink(target, self.repo / "outgoing-link.txt")
        git(self.repo, "add", "outgoing-link.txt")
        git(self.repo, "commit", "-qm", "symlink target probe")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_new_ref_scans_history_present_only_under_remote_pull_ref(self) -> None:
        remote, _remote_oid = self.make_remote()
        (self.repo / "pull-only.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "pull-only.txt")
        git(self.repo, "commit", "-qm", "pull-only disclosure")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "push", "-q", "origin", "HEAD:refs/pull/1/head")

        result = self.pre_push(
            remote,
            "refs/heads/promoted",
            local_oid,
            "refs/heads/promoted",
            ZERO_OID,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_scans_direct_blob_tree_and_tag_terminals(self) -> None:
        remote, _remote_oid = self.make_remote()
        blob_oid = git(
            self.repo,
            "hash-object",
            "-w",
            "--stdin",
            input_text=f"secret payload {self.pattern}\n",
        )
        result = self.pre_push(
            remote, blob_oid, blob_oid, "refs/tags/blob-target", ZERO_OID
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

        tree_oid = git(
            self.repo,
            "mktree",
            input_text=f"100644 blob {blob_oid}\tclean.txt\n",
        )
        result = self.pre_push(
            remote, tree_oid, tree_oid, "refs/tags/tree-target", ZERO_OID
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

        git(self.repo, "tag", "-a", "blob-terminal", blob_oid, "-m", "clean tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/blob-terminal")
        result = self.pre_push(
            remote, tag_oid, tag_oid, "refs/tags/tagged-blob", ZERO_OID
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blob=", result.stderr)
        self.assert_safe_output(result)

    def test_pre_push_excludes_unrelated_local_ref(self) -> None:
        remote, remote_oid = self.make_remote()
        git(self.repo, "checkout", "-qb", "unrelated")
        (self.repo / "unrelated.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "unrelated.txt")
        git(self.repo, "commit", "-qm", "unrelated")
        git(self.repo, "checkout", "-q", "main")
        (self.repo / "clean-outgoing.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "clean-outgoing.txt")
        git(self.repo, "commit", "-qm", "clean outgoing")
        local_oid = git(self.repo, "rev-parse", "HEAD")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        self.assertEqual(result.returncode, 0)
        self.assert_safe_output(result)

    def test_pre_push_fails_closed_for_shallow_replace_and_grafts(self) -> None:
        remote, remote_oid = self.make_remote()
        (self.repo / "clean-outgoing.txt").write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "clean-outgoing.txt")
        git(self.repo, "commit", "-qm", "clean outgoing")
        local_oid = git(self.repo, "rev-parse", "HEAD")

        shallow = Path(git(self.repo, "rev-parse", "--git-path", "shallow"))
        if not shallow.is_absolute():
            shallow = self.repo / shallow
        shallow.write_text(remote_oid + "\n", encoding="ascii")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        shallow.unlink()
        self.assertNotEqual(result.returncode, 0)

        git(self.repo, "replace", remote_oid, local_oid)
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        git(self.repo, "replace", "-d", remote_oid)
        self.assertNotEqual(result.returncode, 0)

        grafts = Path(git(self.repo, "rev-parse", "--git-path", "info/grafts"))
        if not grafts.is_absolute():
            grafts = self.repo / grafts
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(local_oid + " " + remote_oid + "\n", encoding="ascii")
        result = self.pre_push(
            remote, "refs/heads/main", local_oid, "refs/heads/main", remote_oid
        )
        grafts.unlink()
        self.assertNotEqual(result.returncode, 0)

    def test_git_and_history_environment_failures_fail_closed(self) -> None:
        index = Path(git(self.repo, "rev-parse", "--git-path", "index"))
        if not index.is_absolute():
            index = self.repo / index
        held = index.with_name("index-held")
        index.rename(held)
        index.mkdir()
        result = self.guard("pre-commit")
        index.rmdir()
        held.rename(index)
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

        head = git(self.repo, "rev-parse", "HEAD")
        graft_file = self.scratch / "environment-graft"
        graft_file.write_text(head + "\n", encoding="ascii")
        remote = self.scratch / "environment-remote.git"
        remote.mkdir()
        init_scratch_repo(remote, "--bare", "-q")
        result = self.guard(
            "pre-push",
            "environment-origin",
            str(remote),
            input_text=f"refs/heads/main {head} refs/heads/main {ZERO_OID}\n",
            env={"GIT_GRAFT_FILE": str(graft_file)},
        )
        self.assertEqual(result.returncode, 2)
        self.assert_safe_output(result)

    def test_remote_audit_reports_counts_only(self) -> None:
        remote, _remote_oid = self.make_remote()
        git(self.repo, "checkout", "-qb", "audit-source")
        (self.repo / "audit.txt").write_text(
            f"secret payload {self.pattern}\n", encoding="utf-8"
        )
        git(self.repo, "add", "audit.txt")
        git(self.repo, "commit", "-qm", "audit")
        git(self.repo, "push", "-q", "origin", "HEAD:refs/heads/audit-source")
        git(
            self.repo,
            "push",
            "-q",
            "origin",
            f"HEAD:refs/heads/{self.other_pattern}",
        )
        git(self.repo, "fetch", "-q", "origin")
        result = self.guard("audit-remotes")
        self.assertEqual(result.returncode, 1)
        self.assertRegex(result.stdout, r"^findings=[1-9][0-9]* ")
        self.assert_safe_output(result)
        self.assertNotIn("audit-source", result.stdout + result.stderr)
        self.assertNotIn(str(remote), result.stdout + result.stderr)

    def test_real_git_commit_message_and_push_commands_are_guarded(self) -> None:
        self.install_real_hooks()

        staged = self.repo / "guarded.txt"
        staged.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        git(self.repo, "add", "guarded.txt")
        result = run("git", "commit", "-m", "clean message", cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        git(self.repo, "restore", "--staged", "guarded.txt")
        staged.unlink()
        staged.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "guarded.txt")
        result = run(
            "git", "commit", "-m", f"secret message {self.pattern}", cwd=self.repo
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)
        git(self.repo, "commit", "-qm", "clean message")

        remote = self.scratch / "command-remote.git"
        remote.mkdir()
        init_scratch_repo(remote, "--bare", "-q")
        git(self.repo, "remote", "add", "command-origin", str(remote))
        result = run(
            "git",
            "push",
            "-q",
            "command-origin",
            "HEAD:refs/heads/main",
            cwd=self.repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run(
            "git",
            "push",
            "command-origin",
            f"HEAD:refs/heads/{self.pattern}",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        git(self.repo, "tag", "-a", "safe-object-tag", "-m", f"{self.pattern} tag")
        tag_oid = git(self.repo, "rev-parse", "refs/tags/safe-object-tag")
        result = run(
            "git",
            "push",
            "command-origin",
            f"{tag_oid}:refs/tags/safe-target",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

        staged.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        git(self.repo, "add", "guarded.txt")
        git(self.repo, "commit", "--no-verify", "-qm", "synthetic push probe")
        result = run(
            "git",
            "push",
            "command-origin",
            "HEAD:refs/heads/main",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)

    def test_real_git_commit_a_and_pathspec_use_the_selected_index(self) -> None:
        self.install_real_hooks()
        tracked_a = self.repo / "tracked-a.txt"
        tracked_path = self.repo / "tracked-path.txt"
        unrelated = self.repo / "unrelated-staged.txt"
        for path in (tracked_a, tracked_path, unrelated):
            path.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", "tracked-a.txt", "tracked-path.txt", "unrelated-staged.txt")
        git(self.repo, "commit", "-qm", "tracked setup")

        tracked_a.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        result = run("git", "commit", "-am", "commit-a probe", cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)
        git(self.repo, "restore", "tracked-a.txt")

        tracked_path.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        result = run(
            "git",
            "commit",
            "-m",
            "pathspec deny probe",
            "--",
            "tracked-path.txt",
            cwd=self.repo,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assert_safe_output(result)
        git(self.repo, "restore", "tracked-path.txt")

        unrelated.write_text(f"secret payload {self.pattern}\n", encoding="utf-8")
        git(self.repo, "add", "unrelated-staged.txt")
        tracked_path.write_text("clean update\n", encoding="utf-8")
        result = run(
            "git",
            "commit",
            "-m",
            "pathspec allow probe",
            "--",
            "tracked-path.txt",
            cwd=self.repo,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            git(self.repo, "diff", "--cached", "--name-only"),
            "unrelated-staged.txt",
        )

    def test_real_git_commit_cleanup_and_retained_messages(self) -> None:
        removable = self.repo / f"remove-{self.pattern}.txt"
        verbose_removable = self.repo / f"verbose-{self.pattern}.txt"
        for path in (removable, verbose_removable):
            path.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", removable.name, verbose_removable.name)
        git(self.repo, "commit", "-qm", "seed cleanup paths")
        self.install_real_hooks()

        git(self.repo, "rm", "-q", removable.name)
        result = run(
            "git", "commit", "--cleanup=strip", "-m", "clean removal", cwd=self.repo
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        clean = self.repo / "clean-message-probe.txt"
        for cleanup in ("verbatim", "whitespace"):
            clean.write_text(f"clean {cleanup}\n", encoding="utf-8")
            git(self.repo, "add", clean.name)
            result = run(
                "git",
                "commit",
                f"--cleanup={cleanup}",
                "-m",
                f"# secret message {self.pattern}",
                cwd=self.repo,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assert_safe_output(result)
            git(self.repo, "restore", "--staged", clean.name)

        git(self.repo, "rm", "-q", verbose_removable.name)
        editor = self.scratch / "clean-editor.sh"
        editor.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'clean editor removal\\n' > \"$1\"\n",
            encoding="utf-8",
        )
        editor.chmod(0o700)
        result = run(
            "git",
            "commit",
            "-v",
            "--cleanup=strip",
            cwd=self.repo,
            env={"GIT_EDITOR": str(editor)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_routine_installer_does_not_repin_changed_manifest(self) -> None:
        self.install_real_hooks()
        expectation = self.common_dir / EXPECTATION_REL
        before = expectation.read_bytes()
        self.write_manifest(
            self.pattern,
            self.other_pattern + "-changed",
            *self.patterns[2:],
        )
        result = run("bash", "scripts/install-hooks.sh", cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(expectation.read_bytes(), before)

    def test_installer_refuses_unknown_hook_without_overwriting(self) -> None:
        self.write_manifest(*self.patterns)
        self.initialize(len(self.patterns))
        self.copy_hook_sources()
        scripts = self.repo / "scripts"
        hook = self.repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/usr/bin/env bash\nset -euo pipefail\necho preserved\n", encoding="utf-8")
        before = hook.read_bytes()
        result = run("bash", str(scripts / "install-hooks.sh"), cwd=self.repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing hook collision", result.stderr)
        self.assertEqual(hook.read_bytes(), before)

    def write_extension(self, name: str, body: str, mode: int = 0o700) -> Path:
        directory = self.repo / "scripts" / "hooks" / "pre-commit.d"
        directory.mkdir(exist_ok=True)
        extension = directory / name
        extension.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
        extension.chmod(mode)
        return extension

    def test_pre_commit_accepts_missing_and_empty_extension_directory(self) -> None:
        self.copy_hook_sources()
        directory = self.repo / "scripts" / "hooks" / "pre-commit.d"
        for present in (False, True):
            with self.subTest(present=present):
                if present:
                    directory.mkdir()
                result = run("bash", "scripts/hooks/pre-commit", cwd=self.repo)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_safe_output(result)

    def test_pre_commit_extensions_run_in_sorted_order_and_are_not_installed(self) -> None:
        self.copy_hook_sources()
        log = self.scratch / "extension-order"
        for name in ("z-last", "a-second", ".first"):
            self.write_extension(name, f'printf "%s\\n" {shlex.quote(name)} >> "$GUARD_EXTENSION_LOG"\n')
        result = run("bash", "scripts/install-hooks.sh", cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("3 hook(s) installed", result.stdout)
        self.assertFalse((self.common_dir / "hooks" / "pre-commit.d").exists())
        result = run(
            "git", "commit", "--allow-empty", "-m", "ordered extensions",
            cwd=self.repo, env={"GUARD_EXTENSION_LOG": str(log)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().splitlines(), [".first", "a-second", "z-last"])
        self.assert_safe_output(result)

    def test_pre_commit_propagates_extension_failure_and_stops(self) -> None:
        self.copy_hook_sources()
        log = self.scratch / "extension-order"
        self.write_extension("10-first", 'printf "first\\n" >> "$GUARD_EXTENSION_LOG"\n')
        self.write_extension("20-fail", 'printf "failed\\n" >> "$GUARD_EXTENSION_LOG"\nexit 23\n')
        self.write_extension("30-last", 'printf "last\\n" >> "$GUARD_EXTENSION_LOG"\n')
        result = run(
            "bash", "scripts/hooks/pre-commit", cwd=self.repo,
            env={"GUARD_EXTENSION_LOG": str(log)},
        )
        self.assertEqual(result.returncode, 23)
        self.assertEqual(log.read_text().splitlines(), ["first", "failed"])
        self.assert_safe_output(result)

    def test_pre_commit_rejects_nonexecutable_and_unreadable_extensions(self) -> None:
        self.copy_hook_sources()
        marker = self.repo / "extension-ran"
        extension = self.write_extension("check", 'touch extension-ran\n')
        for mode in (0o600, 0o111, 0o700):
            with self.subTest(mode=oct(mode)):
                extension.chmod(mode)
                result = run("bash", "scripts/hooks/pre-commit", cwd=self.repo)
                if mode == 0o700:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(marker.exists())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("extension unavailable; failing closed", result.stderr)
                    self.assertFalse(marker.exists())
                self.assert_safe_output(result)

    def test_pre_commit_rejects_nonregular_extension_entries(self) -> None:
        self.copy_hook_sources()
        target = self.write_extension("target", "exit 0\n")
        entry = target.with_name("00-entry")
        for kind in ("directory", "symlink", "broken-symlink"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    entry.mkdir()
                else:
                    entry.symlink_to(target.name if kind == "symlink" else "missing")
                try:
                    result = run("bash", "scripts/hooks/pre-commit", cwd=self.repo)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("extension unavailable; failing closed", result.stderr)
                    self.assert_safe_output(result)
                finally:
                    if kind == "directory":
                        entry.rmdir()
                    else:
                        entry.unlink()

    def test_pre_commit_guard_denial_prevents_extensions(self) -> None:
        self.copy_hook_sources()
        self.write_extension("check", "touch extension-ran\n")
        staged = self.repo / "guarded.txt"
        staged.write_text(self.pattern + "\n", encoding="utf-8")
        git(self.repo, "add", staged.name)
        result = run("bash", "scripts/hooks/pre-commit", cwd=self.repo)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.repo / "extension-ran").exists())
        self.assert_safe_output(result)

    def test_public_contributor_installs_hooks_without_private_state(self) -> None:
        (self.common_dir / MANIFEST_REL).unlink()
        shutil.rmtree(self.common_dir / EXPECTATION_REL.parent)
        git(self.repo, "config", "--local", "--unset-all", ACTIVATION_CONFIG_KEY)
        self.assertEqual(
            git(self.repo, "ls-files", "--", str(self.common_dir)).strip(), ""
        )
        self.copy_hook_sources()
        subdirectory = self.repo / "subdirectory"
        subdirectory.mkdir()
        result = run("bash", "../scripts/install-hooks.sh", cwd=subdirectory)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("pre-commit", "commit-msg", "pre-push"):
            self.assertTrue((self.repo / ".git" / "hooks" / name).is_symlink())

        path = self.repo / "public-clean.txt"
        path.write_text("clean\n", encoding="utf-8")
        git(self.repo, "add", path.name)
        result = run("git", "commit", "-m", "public clean", cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("owner policy is not configured", result.stderr)

    def test_installer_refuses_linked_worktree_before_writing(self) -> None:
        self.copy_hook_sources()
        git(self.repo, "add", "scripts")
        git(self.repo, "commit", "-qm", "fixture hook sources")
        git(self.repo, "config", "--local", "--unset-all", ACTIVATION_CONFIG_KEY)
        linked = self.scratch / "linked"
        git(self.repo, "worktree", "add", "-q", "-b", "linked-fixture", str(linked))
        destinations = [
            self.repo / ".git" / "hooks" / name
            for name in ("pre-commit", "commit-msg", "pre-push")
        ]
        self.assertTrue(all(not path.exists() for path in destinations))
        result = run("bash", "scripts/install-hooks.sh", cwd=linked)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("linked worktree detected", result.stderr)
        self.assertTrue(all(not path.exists() for path in destinations))

    def test_installer_refuses_global_hooks_path_before_writing(self) -> None:
        self.copy_hook_sources()
        subdirectory = self.repo / "subdirectory"
        subdirectory.mkdir()
        configured_hooks = self.scratch / "configured-hooks"
        global_config = self.scratch / "global-gitconfig"
        global_config.write_text(
            f"[core]\n\thooksPath = {configured_hooks}\n", encoding="utf-8"
        )
        destinations = [
            self.repo / ".git" / "hooks" / name
            for name in ("pre-commit", "commit-msg", "pre-push")
        ]
        self.assertTrue(all(not path.exists() for path in destinations))
        result = run(
            "bash",
            "../scripts/install-hooks.sh",
            cwd=subdirectory,
            env={"GIT_CONFIG_GLOBAL": str(global_config)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("core.hooksPath is configured", result.stderr)
        self.assertTrue(all(not path.exists() for path in destinations))
        self.assertFalse(configured_hooks.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
