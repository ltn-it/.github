"""Copied historical bytes are not a native artifact or current acceptance."""
import copy
import hashlib
import io
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_review_restore as restore
from workflow_control import ControlError, binding, canonical


class NativeAPI:
    def __init__(self, fixture):
        self.fixture = fixture
        self.calls = []
        self.read_counts = {}
        self.drift = None

    def call(self, path):
        self.calls.append(("GET", path))
        self.read_counts[path] = self.read_counts.get(path, 0) + 1
        value = copy.deepcopy(self.fixture.responses[path])
        if self.drift == path and self.read_counts[path] > 1:
            value["updated_at"] = "changed"
            if "/pulls/" in path:
                value["body"] += "changed"
        return value

    def pages(self, path, key):
        self.calls.append(("GET", path))
        assert key == "jobs" and path.endswith("/attempts/1/jobs")
        return copy.deepcopy(self.fixture.jobs)

    def file(self, repository, path, revision):
        self.calls.append(("GET", (repository, path, revision)))
        assert repository == restore.SOURCE and revision == restore.ORIGINAL_SOURCE
        return self.fixture.files[path]

    def native_job_log(self, repository, job):
        self.calls.append(("GET", (repository, job, "logs")))
        assert repository == restore.REPOSITORY and job == 100
        return self.fixture.log


class ReviewCopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.repo = restore.REPOSITORY
        self.pull = {
            "number": 3, "state": "open", "draft": False, "title": "Release v1.2.0", "body": "Release metadata",
            "labels": [], "user": {"login": "lightning-it-release-automation[bot]", "id": 307565056, "type": "Bot"},
            "head": {"sha": "b" * 40, "ref": "release/v1.2.0",
                     "repo": {"full_name": self.repo, "id": restore.REPOSITORY_ID}},
            "base": {"sha": "a" * 40, "ref": "main",
                     "repo": {"full_name": self.repo, "id": restore.REPOSITORY_ID}},
        }
        self.run = {"id": 10, "run_attempt": 2, "workflow_id": 77, "head_sha": "b" * 40,
                    "event": "pull_request", "path": restore.WORKFLOW,
                    "workflow_url": f"https://api.github.com/repos/{self.repo}/actions/required_workflows/77",
                    "pull_requests": [{"number": 3, "head": {"sha": "b" * 40}, "base": {"sha": "a" * 40}}]}
        self.job = {"id": 100, "run_id": 10, "run_attempt": 1, "name": "Protected current revision",
                    "status": "completed", "conclusion": "success",
                    "steps": [{"name": n, "conclusion": "success"} for n in restore.REQUIRED_STEPS]}
        self.jobs = [self.job]
        self.files = {restore.WORKFLOW: b"original defining workflow", "scripts/workflow_subject.py": b"original subject",
                      ".github/codex/prompts/review-exact-head.md": b"original prompt",
                      ".github/codex/schemas/exact-head-review.schema.json": b"original schema"}
        self.workflow_patch = patch.object(restore, "ORIGINAL_WORKFLOW_SHA256", restore.sha256(self.files[restore.WORKFLOW]))
        self.workflow_patch.start()
        self.addCleanup(self.workflow_patch.stop)
        self.metadata = {
            "schema_version": 7, "repository": self.repo, "pull_request": 3,
            "central_source_sha": restore.ORIGINAL_SOURCE, "base_sha": "a" * 40, "head_sha": "b" * 40,
            "merge_base_sha": "a" * 40, "integration_tree_sha": "c" * 40, "diff_sha256": "d" * 64,
            "source_assets": {"workflow_subject.py": restore.sha256(self.files["scripts/workflow_subject.py"])},
            "prompt_sha256": restore.sha256(self.files[".github/codex/prompts/review-exact-head.md"]),
            "schema_sha256": restore.sha256(self.files[".github/codex/schemas/exact-head-review.schema.json"]),
        }
        agents = "Protected repository instructions\n"
        marker = "<!-- AGENTS_SHA256: " + restore.sha256(agents.encode()) + " -->\nReview the entire change.\n"
        instruction_files = []
        for path, content in ((".github/copilot-instructions.md", marker), ("AGENTS.md", agents)):
            raw = content.encode()
            instruction_files.append({"path": path, "content": content, "sha256": restore.sha256(raw),
                                      "blob_sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()})
        self.metadata["trusted_workflow_sha"] = self.metadata["base_sha"]
        self.metadata["review_instructions"] = {"version": 1, "source_sha": self.metadata["base_sha"],
                                                "files": instruction_files}
        self.metadata["instructions_sha256"] = restore.sha256(canonical(self.metadata["review_instructions"]))
        self.metadata["input_sha256"] = restore.sha256(canonical(self.metadata))
        self.result = {k: self.metadata[k] for k in restore.gateway.BINDINGS}
        self.result.update(verdict="PASS", findings=[], summary="No findings.")
        self.response = {
            "id": "resp_original", "status": "completed", "error": None,
            "model": restore.gateway.config.profile()["model"],
            "output": [{"type": "message", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": canonical(self.result).decode()}]}],
        }
        self.wire = canonical(self.response)
        self.record = {
            "version": 1, "source_sha": restore.ORIGINAL_SOURCE,
            "metadata_sha256": restore.sha256(canonical(self.metadata)), "response_sha256": restore.sha256(self.wire),
            "receipt": {"result": self.result, "response_sha256": restore.sha256(self.wire), "provider": {
                "request_count": 1, "request_sha256": ["e" * 64], "response_ids": ["resp_original"],
                "model": self.response["model"],
            }},
        }
        self.operation = {"version": 1, "source_sha": restore.ORIGINAL_SOURCE, "binding": binding(self.pull)}
        self.plan = {"schema": "native-review-copy/v1", "repository": self.repo,
                     "repository_id": restore.REPOSITORY_ID, "pull_request": 3, "run": 10, "attempt": 1,
                     "job": 100, "source_sha": restore.ORIGINAL_SOURCE, "artifacts": {}}
        tree = {"sha": "f" * 40, "truncated": False, "tree": [{"path": "scripts/workflow_subject.py",
                "mode": "100644", "type": "blob", "size": len(self.files["scripts/workflow_subject.py"])}]}
        self.responses = {
            f"repos/{self.repo}": {"full_name": self.repo, "id": restore.REPOSITORY_ID},
            f"repos/{self.repo}/pulls/3": self.pull, f"repos/{self.repo}/actions/runs/10": self.run,
            f"repos/{self.repo}/actions/jobs/100": self.job,
            f"repos/{restore.SOURCE}/git/commits/{restore.ORIGINAL_SOURCE}": {
                "sha": restore.ORIGINAL_SOURCE, "tree": {"sha": "f" * 40}},
            f"repos/{restore.SOURCE}/git/trees/{'f' * 40}?recursive=1": tree,
        }
        self.repack()

    def zip_bytes(self, files):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return output.getvalue()

    def repack(self, operation_files=None, receipt_files=None):
        payloads = {
            "operation": self.zip_bytes(operation_files or {"control-operation.json": canonical(self.operation)}),
            "receipt": self.zip_bytes(receipt_files or {
                "provider-native.json": canonical(self.record), "provider-response.bin": self.wire}),
        }
        for number, kind in enumerate(("operation", "receipt"), 200):
            payload = payloads[kind]
            (self.directory / f"{kind}.zip").write_bytes(payload)
            prefix = "control-operation" if kind == "operation" else "codex-receipt"
            self.plan["artifacts"][kind] = {"id": number, "name": prefix + "-1", "bytes": len(payload),
                                             "sha256": restore.sha256(payload)}
        self.refresh_log()

    def refresh_log(self):
        lines = [restore.INSTRUCTION_MARKER, canonical(self.metadata["review_instructions"]).decode(),
                 "Protected review-metadata.json:",
                 canonical({k: v for k, v in self.metadata.items() if k != "review_instructions"}).decode(),
                 "##[group]" + restore.EXPORT_COMMAND, "python3 -B scripts/workflow_control.py verify-codex",
                 "  NATIVE_JOB: {", *canonical_context(), "}", "##[endgroup]",
                 "Protected actual model response and complete native request receipt verified."]
        for item in self.plan["artifacts"].values():
            paths = (["  path: control-operation.json"] if item["name"].startswith("control-operation-") else
                     ["  path: exact-revision-review/provider-native.json", "exact-revision-review/provider-response.bin"])
            lines += ["##[group]Run " + restore.UPLOAD_ACTION, "with:", f"  name: {item['name']}",
                      *paths, "  overwrite: false", "  archive: true", "##[endgroup]",
                      f"Uploading artifact: {item['name']}.zip", f"Uploaded bytes {item['bytes']}",
                      "Finished uploading artifact content to blob storage!",
                      f"SHA256 digest of uploaded artifact is {item['sha256']}",
                      f"Artifact {item['name']} successfully finalized. Artifact ID {item['id']}",
                      f"Artifact {item['name']} has been successfully uploaded! Final size is {item['bytes']} bytes. Artifact ID is {item['id']}",
                      f"Artifact download URL: https://github.com/{self.repo}/actions/runs/10/artifacts/{item['id']}"]
        self.log = "\n".join("2026-10-30T02:34:29.4520448Z " + line for line in lines) + "\n"

    def authenticate(self, api=None):
        return restore.authenticate(api or NativeAPI(self), self.plan, self.directory)

    def assert_rejected(self, message):
        with self.assertRaisesRegex((ControlError, restore.gateway.review.ReviewError, ValueError), message):
            self.authenticate()

    def test_copy_retains_original_identity_without_current_acceptance_or_provider(self):
        api = NativeAPI(self)
        with patch.object(restore.transport, "run_worker") as provider:
            result = self.authenticate(api)
        provider.assert_not_called()
        self.assertEqual(self.plan, result["original"])
        self.assertFalse(result["current_gate_pass"])
        self.assertFalse(result["copy"]["native_artifact"])
        self.assertEqual("local-files", result["copy"]["transport"])
        self.assertEqual(0, result["provider_requests_performed"])
        self.assertEqual(restore.sha256(self.wire), result["response_sha256"])
        self.assertTrue(all(verb == "GET" for verb, _ in api.calls))

    def test_actual_sse_bytes_are_verified_without_normalization(self):
        created = {"type": "response.created", "sequence_number": 0,
                   "response": {"id": self.response["id"]}}
        completed = {"type": "response.completed", "sequence_number": 1, "response": self.response}
        self.wire = b"".join(b"event: " + event["type"].encode() + b"\ndata: " + canonical(event) + b"\n\n"
                             for event in (created, completed))
        self.record["response_sha256"] = self.record["receipt"]["response_sha256"] = restore.sha256(self.wire)
        self.repack()
        self.assertEqual(restore.sha256(self.wire), self.authenticate()["response_sha256"])

    def test_changed_copy_is_rejected_by_the_original_native_upload_digest(self):
        with (self.directory / "receipt.zip").open("ab") as stream:
            stream.write(b"changed")
        self.assert_rejected("restore-copy-zip-binding")

    def test_local_log_cannot_replace_a_missing_live_native_log(self):
        api = NativeAPI(self)
        api.native_job_log = lambda *_: (_ for _ in ()).throw(ControlError("native-log-unavailable"))
        (self.directory / "native.log").write_text(self.log)
        with self.assertRaisesRegex(ControlError, "native-log-unavailable"):
            self.authenticate(api)

    def test_manifest_cannot_choose_another_repository_source_or_attempt_type(self):
        for key, value in (("repository", "ltn-it/other"), ("repository_id", True), ("source_sha", "a" * 40),
                           ("attempt", True), ("job", 0), ("unknown", "ignored")):
            changed = self.plan | {key: value}
            with self.subTest(key=key), self.assertRaises(ControlError):
                restore.authenticate(NativeAPI(self), changed, self.directory)

    def test_native_source_context_and_upload_action_are_not_substitutable(self):
        original = self.log
        for before, after, error in ((restore.ORIGINAL_SOURCE, "a" * 40, "restore-native-source-binding"),
                                     (restore.UPLOAD_ACTION, "actions/upload-artifact@" + "a" * 40,
                                      "restore-native-upload-ambiguous")):
            self.log = original.replace(before, after)
            with self.subTest(error=error):
                self.assert_rejected(error)

    def test_native_shell_echo_color_does_not_normalize_upload_evidence(self):
        command = "python3 -B scripts/workflow_control.py verify-codex"
        self.log = self.log.replace(command, "\x1b[36;1m" + command + "\x1b[0m")
        self.assertFalse(self.authenticate()["current_gate_pass"])
        digest = "SHA256 digest of uploaded artifact is " + self.plan["artifacts"]["receipt"]["sha256"]
        self.log = self.log.replace(digest, "\x1b[36;1m" + digest + "\x1b[0m")
        self.assert_rejected("restore-native-upload-binding")

    def test_conflicting_duplicate_or_out_of_order_upload_claims_are_rejected(self):
        original = self.log
        digest_line = "SHA256 digest of uploaded artifact is " + self.plan["artifacts"]["receipt"]["sha256"]
        self.log = original.replace(digest_line, digest_line + "\nSHA256 digest of uploaded artifact is " + "f" * 64)
        self.assert_rejected("restore-native-upload-conflict")
        self.log = original + original[original.index("2026-10-30T02:34:29.4520448Z ##[group]Run " + restore.UPLOAD_ACTION):]
        self.assert_rejected("restore-native-upload-ambiguous")
        item = self.plan["artifacts"]["receipt"]
        size_line = f"Uploaded bytes {item['bytes']}"
        self.log = original.replace(size_line, "placeholder").replace(digest_line, size_line).replace("placeholder", digest_line)
        self.assert_rejected("restore-native-upload-order")

    def test_wrong_upload_size_id_or_url_is_not_hidden_by_matching_zip_contents(self):
        original = self.log
        item = self.plan["artifacts"]["receipt"]
        changes = ((f"Uploaded bytes {item['bytes']}", "Uploaded bytes 1"),
                   (f"Artifact ID {item['id']}", "Artifact ID 999"),
                   (f"/artifacts/{item['id']}", "/artifacts/999"))
        for before, after in changes:
            self.log = original.replace(before, after)
            with self.subTest(before=before):
                self.assert_rejected("restore-native-upload-binding")

    def test_failed_pending_wrong_attempt_and_duplicate_native_producers_fail_closed(self):
        original = copy.deepcopy(self.job)
        for change in ({"conclusion": "failure"}, {"status": "in_progress"}, {"run_attempt": 2}, {"run_id": 11}):
            self.job.clear(); self.job.update(original | change)
            with self.subTest(change=change):
                self.assert_rejected("restore-native-producer-success")
        self.job.clear(); self.job.update(original)
        self.jobs.append(copy.deepcopy(self.job))
        self.assert_rejected("restore-native-producer-ambiguous")

    def test_each_export_step_requires_one_actual_success(self):
        self.job["steps"].append({"name": restore.REQUIRED_STEPS[-1], "conclusion": "failure"})
        self.assert_rejected("restore-native-producer-steps")

    def test_ordinary_workflows_and_wrong_pr_associations_never_authenticate(self):
        self.run["workflow_url"] = f"https://api.github.com/repos/{self.repo}/actions/workflows/77"
        self.assert_rejected("restore-native-run")
        self.run["workflow_url"] = f"https://api.github.com/repos/{self.repo}/actions/required_workflows/77"
        self.run["pull_requests"].append(copy.deepcopy(self.run["pull_requests"][0]))
        self.assert_rejected("restore-native-association")

    def test_changed_current_body_or_base_cannot_relabel_old_operation(self):
        self.pull["body"] += "changed"
        self.assert_rejected("restore-original-operation-binding")
        self.pull["base"]["sha"] = "e" * 40
        self.run["pull_requests"][0]["base"]["sha"] = "e" * 40
        self.assert_rejected("restore-original-subject-binding")

    def test_source_tree_and_complete_source_assets_remain_original(self):
        key = f"repos/{restore.SOURCE}/git/trees/{'f' * 40}?recursive=1"
        self.responses[key]["truncated"] = True
        self.assert_rejected("restore-source-tree")
        self.responses[key]["truncated"] = False
        self.files["scripts/workflow_subject.py"] = b"X" * len(self.files["scripts/workflow_subject.py"])
        self.assert_rejected("restore-original-source-assets")

    def test_metadata_input_hash_is_not_recomputed_to_hide_changed_native_metadata(self):
        self.metadata["diff_sha256"] = "f" * 64
        self.refresh_log()
        self.assert_rejected("restore-original-input-digest")

    def test_full_protected_instruction_bundle_cannot_be_dropped_or_changed(self):
        original = self.log
        self.log = self.log.replace(restore.INSTRUCTION_MARKER, "Missing authoritative bundle")
        self.assert_rejected("restore-native-instructions-ambiguous")
        self.log = original.replace("Protected repository instructions", "Modified repository instructions")
        self.assert_rejected("single-instruction-drift")

    def test_native_metadata_record_and_wire_are_all_bound(self):
        self.record["metadata_sha256"] = "f" * 64
        self.repack()
        self.assert_rejected("codex-native-input-binding")

    def test_unchanged_wire_hash_does_not_allow_a_different_record_result(self):
        self.record["receipt"]["result"] = self.result | {"summary": "Changed result"}
        self.repack()
        self.assert_rejected("restore-original-response-binding")

    def test_zip_paths_and_extra_files_are_never_extracted(self):
        self.repack(receipt_files={"../provider-native.json": canonical(self.record), "provider-response.bin": self.wire})
        self.assert_rejected("restore-zip-exact-files")
        self.repack(receipt_files={"provider-native.json": canonical(self.record),
                                   "provider-response.bin": self.wire, "extra": b"data"})
        self.assert_rejected("restore-zip-exact-files")
        self.assertFalse((self.directory.parent / "provider-native.json").exists())

    def test_duplicate_zip_members_links_and_inflate_limits_fail_before_payload_decode(self):
        output = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr("control-operation.json", b"first")
                archive.writestr("control-operation.json", b"second")
        duplicate = output.getvalue()
        with self.assertRaisesRegex(ControlError, "restore-zip-exact-files"):
            restore.unpack(duplicate, {"bytes": len(duplicate), "sha256": restore.sha256(duplicate)},
                           {"control-operation.json": 100})
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755):
            info = zipfile.ZipInfo("control-operation.json"); info.external_attr = mode << 16
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr(info, b"target")
            item = {"bytes": len(output.getvalue()), "sha256": restore.sha256(output.getvalue())}
            with self.subTest(mode=mode), self.assertRaisesRegex(ControlError, "restore-zip-entry"):
                restore.unpack(output.getvalue(), item, {"control-operation.json": 100})
        payload = self.zip_bytes({"control-operation.json": b"x" * 101})
        with self.assertRaisesRegex(ControlError, "restore-zip-entry"):
            restore.unpack(payload, {"bytes": len(payload), "sha256": restore.sha256(payload)},
                           {"control-operation.json": 100})

    def test_expanded_zip_aggregate_obeys_the_actual_memory_admission(self):
        payload = self.zip_bytes({"one": b"x" * 50, "two": b"y" * 50})
        with patch.object(restore.resources, "wire_limit", return_value=75), \
             self.assertRaisesRegex(ControlError, "restore-zip-expanded-size"):
            restore.unpack(payload, {"bytes": len(payload), "sha256": restore.sha256(payload)}, {"one": 100, "two": 100})

    def test_symlinked_copy_is_not_opened_as_regular_data(self):
        path = self.directory / "receipt.zip"
        path.rename(self.directory / "other.zip")
        path.symlink_to("other.zip")
        with self.assertRaises(OSError):
            self.authenticate()

    def test_regular_file_and_json_resource_admission_precedes_decoding(self):
        with patch.object(restore.transport, "strict_json") as decoder, \
             self.assertRaisesRegex(ControlError, "restore-json-size"):
            restore.decode(b"{}", 1)
        decoder.assert_not_called()
        with self.assertRaisesRegex(ControlError, "restore-copy-file-size"):
            restore.regular_file(self.directory / "receipt.zip", 1)
        with self.assertRaises(restore.gateway.review.ReviewError):
            restore.decode(b'{"key":1,"key":2}', 100)

    def test_native_run_job_and_live_subject_are_reread_before_returning_copy_provenance(self):
        for path in (f"repos/{self.repo}/actions/runs/10", f"repos/{self.repo}/actions/jobs/100",
                     f"repos/{self.repo}/pulls/3"):
            api = NativeAPI(self); api.drift = path
            with self.subTest(path=path), self.assertRaisesRegex(ControlError, "drift"):
                self.authenticate(api)

    def test_no_automatic_cross_source_acceptance_or_hook_is_installed(self):
        self.plan["source_sha"] = "f" * 40
        self.assert_rejected("restore-scope")
        self.assertNotIn("workflow_review_restore", Path(restore.__file__).with_name("workflow_codex.py").read_text())


def canonical_context():
    value = {"check_run_id": 100, "workflow_repository": restore.SOURCE,
             "workflow_file_path": restore.WORKFLOW, "workflow_sha": restore.ORIGINAL_SOURCE,
             "status": "success"}
    return json.dumps(value, indent=2).splitlines()[1:-1]


if __name__ == "__main__":
    unittest.main()
