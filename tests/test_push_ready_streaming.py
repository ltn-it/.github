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
        import base64
        import difflib
        import zlib
        from types import SimpleNamespace
        function = self.ns['retire_collaboration_fixture']
        fixture = json.loads((ROOT / 'tests/fixtures/push-ready-collaboration-predecessors.json').read_text())
        self.assertEqual(1, fixture['version'])
        snapshots = {item['path']: item for item in fixture['fixtures']}
        replacements = {
            'tests/test_collaboration_content.py': ('-----BEGIN ' + 'RSA PRIVATE KEY-----', '-----BEGIN " + "RSA PRIVATE KEY-----'),
            'tests/test_collaboration_private_evidence.py': ('ghp_' + 'a' * 24, "ghp_' + b'a' * 24 + b'"),
        }
        sources, heads, entries, successors, patch = {}, {}, {}, {}, ''
        def blob_hash(payload):
            return hashlib.sha1(b'blob ' + str(len(payload)).encode() + b'\0' + payload).hexdigest()
        for path, before, after, line_number, line_hex in self.ns['COLLABORATION_FIXTURES']:
            self.assertEqual(before, snapshots[path]['git_blob'])
            payload = zlib.decompress(base64.b64decode(snapshots[path]['zlib_base64'], validate=True))
            self.assertEqual(before, blob_hash(payload))
            source = payload.decode()
            marker, composed = replacements[path]
            head = source.replace(marker, composed, 1)
            self.assertEqual(after, blob_hash(head.encode()))
            self.assertEqual(source.splitlines()[line_number - 1].encode().hex(), line_hex)
            sources[path], heads[path], entries[path] = source, head, before
            successors[path] = after
            patch += f'diff --git a/{path} b/{path}\n' + ''.join(difflib.unified_diff(
                source.splitlines(keepends=True), head.splitlines(keepends=True),
                fromfile=f'a/{path}', tofile=f'b/{path}'))
        change = SimpleNamespace(base_tip='a' * 40, base_commit='b' * 40, head_commit='c' * 40,
                                 paths=tuple(sources), patch=patch)

        def entry(commit, name):
            selected = successors if commit == change.head_commit else entries
            return f'100644 blob {selected[name]}\t{name}\0'

        def index(*args):
            name = args[-1]
            return f'100644 {successors[name]} 0\t{name}\0'

        def workspace(name, **kwargs):
            return heads[name].encode(), 0o100644

        valid = dict(git_tree_entry=entry, git_output=index, read_repository_file=workspace,
                     secret_fixture_manifest_at_commit=lambda commit: {})
        with mock.patch.dict(function.__globals__, valid):
            selector = self.ns['secret_fixture_manifest_for_change']
            result = selector(change)
            self.assertEqual(set(sources), set(result))
            for path, _, _, line_number, *_ in self.ns['COLLABORATION_FIXTURES']:
                self.assertEqual(sources[path].splitlines()[line_number - 1], result[path][line_number][1])
            # Exercise the entire actual two-file diff, including the removed
            # dummy token. No historical Git objects are needed by this test.
            self.ns['streaming_review_safe'](change, result)
            with self.assertRaisesRegex(RuntimeError, 'secret-like content'):
                self.ns['streaming_review_safe'](change, {})
            added = SimpleNamespace(paths=change.paths, patch=patch + '+"ghp_' + 'a' * 24 + '"\n')
            with self.assertRaisesRegex(RuntimeError, 'secret-like content'):
                self.ns['streaming_review_safe'](added, result)
            for remaining in change.paths:
                incomplete = SimpleNamespace(**{**vars(change), 'paths': (remaining,)})
                with self.subTest(remaining=remaining), self.assertRaisesRegex(RuntimeError, 'complete migration'):
                    selector(incomplete)
        # Vary each trust binding independently, keeping all other files and
        # commits valid. In particular, a merge-base-only mismatch must fail.
        for target_path in change.paths:
            for target_commit in (change.base_tip, change.base_commit, change.head_commit):
                for invalid in ('', f'100644 blob {"d" * 40}\t{target_path}\0',
                                entry(target_commit, target_path).replace('100644', '100755', 1)):
                    def changed_binding(commit, name):
                        return invalid if (commit, name) == (target_commit, target_path) else entry(commit, name)
                    with self.subTest(path=target_path, commit=target_commit, invalid=invalid[:10]), mock.patch.dict(
                            function.__globals__, valid | {'git_tree_entry': changed_binding}):
                        with self.assertRaisesRegex(RuntimeError, 'exact regular source blobs'):
                            selector(change)
        with mock.patch.dict(function.__globals__, valid | {'git_tree_entry': lambda commit, name:
                             f'100644 blob {"d" * 40}\t{name}\0'}):
            no_exemption = selector(change)
            self.assertEqual({}, no_exemption)
            with self.assertRaisesRegex(RuntimeError, 'secret-like content'):
                self.ns['streaming_review_safe'](change, no_exemption)
        manifest = {'tests/other-fixture.py': {1: ('a' * 64, 'existing fixture')}}
        with mock.patch.dict(function.__globals__, valid | {'secret_fixture_manifest_at_commit': lambda commit: manifest}):
            self.assertIs(manifest, selector(change))
            with self.assertRaisesRegex(RuntimeError, 'secret-like content'):
                self.ns['streaming_review_safe'](change, manifest)
        for ending in ('\r\n', '\r'):
            def altered_entry(commit, name):
                if commit != change.head_commit:
                    return entry(commit, name)
                altered = blob_hash(heads[name].replace('\n', ending).encode())
                return f'100644 blob {altered}\t{name}\0'
            with self.subTest(ending=repr(ending)), mock.patch.dict(function.__globals__, valid | {'git_tree_entry': altered_entry}):
                with self.assertRaisesRegex(RuntimeError, 'exact regular source blobs'):
                    function(change)
        for target_path in change.paths:
            for invalid in ('', index(target_path).replace(' 0\t', ' 2\t'),
                            index(target_path).replace(successors[target_path], 'd' * 40),
                            index(target_path).replace('100644', '100755', 1), index(target_path) * 2):
                with self.subTest(path=target_path, index=invalid[:10]), mock.patch.dict(
                        function.__globals__, valid | {'git_output': lambda *args:
                        invalid if args[-1] == target_path else index(*args)}):
                    with self.assertRaisesRegex(RuntimeError, 'index drift'):
                        selector(change)
            for suffix, ending, mode in (('\n# unrelated change\n', '\n', 0o100644),
                                         ('', '\r\n', 0o100644), ('', '\r', 0o100644), ('', '\n', 0o100755)):
                with self.subTest(path=target_path, suffix=bool(suffix), ending=repr(ending), mode=mode), mock.patch.dict(
                        function.__globals__, valid | {'read_repository_file': lambda name, **kwargs:
                        ((heads[name] + suffix).replace('\n', ending).encode(), mode) if name == target_path else workspace(name)}):
                    with self.assertRaisesRegex(RuntimeError, 'workspace drift'):
                        selector(change)
        with mock.patch.dict(function.__globals__, git_tree_entry=lambda *args: '120000 blob bad'):
            with self.assertRaisesRegex(RuntimeError, 'exact regular source blobs'):
                function(change)
        with mock.patch.dict(function.__globals__, git_tree_entry=lambda commit, name: f'100644 blob {"d" * 40}\t{name}\0'):
            with self.assertRaisesRegex(RuntimeError, 'exact regular source blobs'):
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
