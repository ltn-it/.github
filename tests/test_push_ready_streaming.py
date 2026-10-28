"""Core Push Ready must hash and scan complete content without RAM copies."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class PushReadyStreamingTests(unittest.TestCase):
    def setUp(self):
        self.ns = runpy.run_path(str(ROOT / "scripts/lit-push-ready.py"))

    def test_collaboration_fixture_retirement_binds_complete_blobs(self):
        from types import SimpleNamespace
        function = self.ns['retire_collaboration_fixture']
        path = 'tests/test_collaboration_content.py'
        before = '72b933b730b7b377a2496ec4fc6752f37de2a6d2'
        source = subprocess.check_output(['git', '-c', f'safe.directory={ROOT}', 'show', before], cwd=ROOT).decode()
        marker = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
        head = source.replace(marker, '-----BEGIN " + "RSA PRIVATE KEY-----', 1)
        change = SimpleNamespace(base_tip='a' * 40, base_commit='b' * 40, head_commit='c' * 40)

        def entry(commit, name):
            return f'100644 blob {before}\t{path}\0'

        def blob(commit, name, **kwargs):
            return head if commit == change.head_commit else source

        with mock.patch.dict(function.__globals__, git_tree_entry=entry, repository_blob_at_commit=blob):
            result = function(change)
            self.assertEqual({520}, set(result[path]))
            self.assertEqual(source.splitlines()[519], result[path][520][1])
        for invalid in (head + '\n# unrelated change\n', source):
            with self.subTest(invalid=invalid == source), mock.patch.dict(
                    function.__globals__, git_tree_entry=entry,
                    repository_blob_at_commit=lambda commit, name, **kwargs:
                    invalid if commit == change.head_commit else source):
                with self.assertRaisesRegex(RuntimeError, 'exact runtime composition'):
                    function(change)
        with mock.patch.dict(function.__globals__, git_tree_entry=lambda *args: '120000 blob bad'):
            with self.assertRaisesRegex(RuntimeError, 'regular source blobs'):
                function(change)
        with mock.patch.dict(function.__globals__, git_tree_entry=lambda *args: f'100644 blob {"d" * 40}\t{path}\0'):
            with self.assertRaisesRegex(RuntimeError, 'predecessor is not exact'):
                function(change)

    def test_regex_semantics_preserve_long_components_and_boundaries(self):
        patterns = (*self.ns["SECRET_CONTENT_PATTERNS"], self.ns["NPMRC_AUTH_PATTERN"])
        machine = self.ns["StreamingPatterns"](patterns)
        for value in (
            "password" + "\u2003" * 70000 + "='" + "A" * 16,
            "Bearer" + "\n" * 70000 + "A" * 20,
            "eyJ" + "x" * 70000 + "." + "x" * 70000 + "." + "x" * 70000,
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "xghp_" + "A" * 30,
            "ghp_" + "A" * 30,
            "UTF-8 ä𐍈\n ordinary content\n",
        ):
            expected = sum(
                1 << i for i, pattern in enumerate(patterns) if pattern.search(value)
            )
            scanner = machine.scanner()
            for start in range(0, len(value), 137):
                scanner.feed(value[start : start + 137])
            self.assertEqual(expected, scanner.finish())

    def test_private_spool_rejects_changed_bytes(self):
        spool = self.ns["PatchSpool"]()
        try:
            spool.write(b"original\n")
            spool.file.seek(0)
            spool.file.write(b"modified\n")
            with self.assertRaisesRegex(RuntimeError, "spool changed"):
                list(spool.chunks())
        finally:
            spool.close()

    def test_complete_patch_and_compatible_fingerprint_in_real_repository(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("GIT_")
            }
            env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, env=env)

            git("init", "-q", "-b", "develop")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            (root / "tracked.txt").write_text("base\n")
            git("add", ".")
            git("commit", "-qm", "fixture base")
            git("update-ref", "refs/remotes/origin/develop", "HEAD")
            (root / "tracked.txt").write_bytes(("complete ä𐍈\r\n" * 10000).encode())
            (root / "untracked.txt").write_bytes(b"x" * 65535 + b"\r\ny")
            function = self.ns["planned_change"]
            with mock.patch.dict(function.__globals__, {"ROOT": root}):
                old = {
                    "head": self.ns["git_output"]("rev-parse", "HEAD").strip(),
                    "status": self.ns["git_output"](
                        "status", "--porcelain=v1", "--untracked-files=all", "-z"
                    ),
                    "diff": self.ns["git_output"](
                        "diff",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--binary",
                        "HEAD",
                        "--",
                    ),
                    "untracked": self.ns["untracked_file_hashes"](),
                }
                wanted = hashlib.sha256(
                    json.dumps(
                        old, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    ).encode()
                ).hexdigest()
                self.assertEqual(wanted, self.ns["tree_fingerprint"]())
                with mock.patch.object(
                    self.ns["PatchSpool"],
                    "as_text",
                    side_effect=AssertionError("materialized"),
                ):
                    change = function(
                        {
                            "base_ref": "refs/remotes/origin/develop",
                            "review": {"warn_diff_bytes": None},
                        }
                    )
                    expected = git(
                        "diff",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--binary",
                        "--no-renames",
                        "--unified=40",
                        change.base_commit,
                        "--",
                    )
                    expected += self.ns["render_untracked_patch"](
                        "untracked.txt",
                        (root / "untracked.txt").read_bytes(),
                        (root / "untracked.txt").stat().st_mode,
                    ).encode()
                    self.assertEqual(len(expected), change.patch.size)
                    self.assertEqual(
                        hashlib.sha256(expected).hexdigest(), change.diff_sha256
                    )
                    self.assertEqual(expected, b"".join(change.patch.chunks()))
                    change.patch.close()
