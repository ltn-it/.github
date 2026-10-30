"""Private copy custody is not a new review, approval or source selector."""
import base64
import copy as deepcopy_module
import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_review_copy as consumer
import workflow_review_copy_producer as producer
from workflow_control import ControlError, canonical, digest

try:
    from . import test_workflow_review_restore as archive_fixtures
except ImportError:
    import test_workflow_review_restore as archive_fixtures

clone = deepcopy_module.deepcopy
NEW_SOURCE = "9" * 40
OPERATOR = {"login": "litroc", "id": 76040632, "type": "User"}
BASE = "1" * 40
COMMIT = "2" * 40


class Custody:
    scope = consumer.PrivateReader.scope

    def __init__(self):
        self.tip = BASE
        self.closed = False
        self.calls = []
        self.private = True
        self.broad_token = False
        self.signed = True
        self.author = clone(OPERATOR)
        self.parents = [{"sha": BASE}]
        self.ancestry = True
        self.changes = []
        self.files = {}
        self.payloads = {}
        self.nodes = {"3" * 40: {"sha": "3" * 40, "truncated": False, "tree": []}}
        self.rule = {"id": consumer.CUSTODY_RULE, "enforcement": "active", "bypass_actors": [],
                     "conditions": {"ref_name": {"include": ["refs/heads/" + consumer.CUSTODY_REF], "exclude": []}},
                     "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]}

    def add(self, additions):
        self.tip = COMMIT
        self.changes = [{"filename": item["path"], "status": "added"} for item in additions]
        self.files = {item["path"]: base64.b64decode(item["contents"]) for item in additions}
        self.payloads = {path.rsplit("/", 1)[1]: data for path, data in self.files.items()}
        namespace = next(iter(self.files)).rsplit("/", 1)[0].split("/")
        for index, part in enumerate(namespace):
            oid, child = str(index + 4) * 40, str(index + 5) * 40
            self.nodes[oid] = {"sha": oid, "truncated": False,
                               "tree": [{"path": part, "mode": "040000", "type": "tree", "sha": child}]}
        self.nodes["7" * 40] = {"sha": "7" * 40, "truncated": False, "tree": []}
        for name, data in self.payloads.items():
            oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            self.nodes["7" * 40]["tree"].append({"path": name, "type": "blob", "mode": "100644",
                                                  "size": len(data), "sha": oid})
            self.nodes[oid] = {"sha": oid, "size": len(data), "encoding": "base64",
                               "content": base64.b64encode(data).decode()}

    def call(self, path):
        self.calls.append(path)
        prefix = f"repos/{consumer.CUSTODY}"
        if path == prefix:
            return {"id": consumer.CUSTODY_ID, "full_name": consumer.CUSTODY, "private": self.private, "archived": False}
        if path == "installation/repositories":
            rows = [{"id": consumer.CUSTODY_ID, "private": True}]
            if self.broad_token:
                rows.append({"id": 99, "private": True})
            return {"total_count": len(rows), "repositories": rows}
        if path == f"{prefix}/rulesets/{consumer.CUSTODY_RULE}":
            return clone(self.rule)
        if path == f"{prefix}/git/ref/heads/{consumer.CUSTODY_REF}":
            return {"ref": "refs/heads/" + consumer.CUSTODY_REF, "object": {"type": "commit", "sha": self.tip}}
        if path == f"{prefix}/git/commits/{BASE}":
            return {"sha": BASE, "tree": {"sha": "3" * 40}}
        if path == f"{prefix}/commits/{COMMIT}":
            return {"sha": COMMIT, "author": self.author, "committer": {"login": "web-flow", "id": 19864447, "type": "User"},
                    "parents": self.parents, "commit": {"tree": {"sha": "4" * 40},
                                                        "verification": {"verified": self.signed}}}
        if path.startswith(prefix + "/git/trees/") or path.startswith(prefix + "/git/blobs/"):
            return clone(self.nodes[path.rsplit("/", 1)[1]])
        if path == f"{prefix}/compare/{BASE}...{COMMIT}":
            return {"status": "ahead", "ahead_by": 1, "behind_by": 0, "total_commits": 1, "files": clone(self.changes)}
        if path.startswith(f"{prefix}/compare/{COMMIT}..."):
            return {"status": "identical" if self.ancestry else "diverged", "behind_by": 0 if self.ancestry else 1}
        raise AssertionError(path)

    def close(self):
        self.closed = True


class ProtocolAPI(archive_fixtures.NativeAPI):
    def __init__(self, fixture):
        super().__init__(fixture)
        self.custody = Custody()
        self.comments = []
        self.mutations = []
        self.program_drift = False
        self.after_cas_unknown = False
        self.graphql_errors = False
        self.root_main = NEW_SOURCE
        self.operator = clone(OPERATOR)
        self.native_run = {"id": 30, "run_attempt": 1, "workflow_id": 77,
                           "workflow_url": f"https://api.github.com/repos/{fixture.repo}/actions/required_workflows/77",
                           "path": consumer.WORKFLOW, "head_sha": fixture.pull["head"]["sha"],
                           "pull_requests": clone(fixture.run["pull_requests"])}
        self.native_job = {"id": 400, "run_id": 30, "run_attempt": 1, "name": "Protected current revision",
                           "status": "in_progress"}

    def call(self, path, **kwargs):
        if kwargs.get("method") == "POST":
            self.mutations.append((path, clone(kwargs)))
            if path == "graphql":
                request = kwargs["data"]["variables"]["input"]
                if self.graphql_errors:
                    return {"errors": [{"message": "fixture CAS conflict"}]}
                assert request["expectedHeadOid"] == BASE
                assert request["branch"] == {"repositoryNameWithOwner": consumer.CUSTODY,
                                              "branchName": consumer.CUSTODY_REF}
                assert set(request["fileChanges"]) == {"additions"}
                self.custody.add(request["fileChanges"]["additions"])
                if self.after_cas_unknown:
                    raise ControlError("fixture-native-unknown-write")
                return {"data": {"createCommitOnBranch": {"commit": {"oid": COMMIT, "parents": {"nodes": [{"oid": BASE}]}}}}}
            assert path == f"repos/{self.fixture.repo}/issues/3/comments"
            comment = {"id": 99, "body": kwargs["data"]["body"], "user": clone(self.operator),
                       "created_at": "2026-10-30T03:30:00Z", "updated_at": "2026-10-30T03:30:00Z"}
            self.comments.append(comment)
            return clone(comment)
        if path == "user":
            return clone(self.operator)
        if path == f"repos/{consumer.SOURCE}/git/ref/heads/main":
            return {"object": {"type": "commit", "sha": self.root_main}}
        if path.startswith(f"repos/{consumer.CUSTODY}/") or path == f"repos/{consumer.CUSTODY}":
            return self.custody.call(path)
        if path == f"repos/{self.fixture.repo}/issues/comments/99":
            return clone(self.comments[0])
        if path == f"repos/{self.fixture.repo}/actions/runs/30":
            return clone(self.native_run)
        if path == f"repos/{self.fixture.repo}/actions/jobs/400":
            return clone(self.native_job)
        return super().call(path)

    def pages(self, path, key=None):
        if path == f"repos/{self.fixture.repo}/issues/3/comments":
            return clone(self.comments)
        return super().pages(path, key)

    def file(self, repository, path, revision):
        if repository == consumer.CUSTODY:
            if path == "manifest.json" and revision == BASE:
                return canonical({"schema": 1, "repository": consumer.CUSTODY, "repository_id": consumer.CUSTODY_ID,
                                  "ref": "refs/heads/" + consumer.CUSTODY_REF})
            assert revision == COMMIT
            return self.custody.files[path]
        if revision == NEW_SOURCE:
            result = Path(consumer.__file__).with_name(Path(path).name).read_bytes()
            return result + b"changed" if self.program_drift else result
        return super().file(repository, path, revision)


class CopyProtocolTests(unittest.TestCase):
    def setUp(self):
        self.fixture = archive_fixtures.ReviewCopyTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.target_patch = patch.object(consumer, "TARGET", {"number": 3, "base": "a" * 40, "head": "b" * 40,
                                                             "run": 10, "attempt": 1, "job": 100})
        self.target_patch.start(); self.addCleanup(self.target_patch.stop)
        self.api = ProtocolAPI(self.fixture)
        self.context = {"workflow_repository": consumer.SOURCE, "workflow_file_path": consumer.WORKFLOW,
                        "workflow_sha": NEW_SOURCE, "check_run_id": 400}
        self.environment = patch.dict(os.environ, {"NATIVE_JOB": json.dumps(self.context), "GITHUB_RUN_ID": "30",
                                                   "GITHUB_RUN_ATTEMPT": "1", "GH_TOKEN": "public-native-token"})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def prepared(self):
        return producer.prepare(self.api, self.fixture.plan, self.fixture.directory, NEW_SOURCE, "2026-10-30T03:30:00Z")

    def produced(self):
        plan, report = self.prepared()
        result = producer.publish(self.api, plan, self.fixture.directory, digest(plan))
        return plan, report, result

    def materialized(self, source, destination):
        destination.mkdir()
        (destination / "change.patch").write_bytes(b"complete original candidate patch")
        metadata = clone(self.fixture.metadata)
        if source != consumer.archive.ORIGINAL_SOURCE:
            metadata["central_source_sha"] = source
            metadata["source_assets"] = consumer.program_hashes()
            metadata["input_sha256"] = digest({k: v for k, v in metadata.items() if k != "input_sha256"})
        return metadata

    def evidence(self):
        def old(_api, _repo, _pull, destination, *, public_token, expected_metadata_sha256):
            self.assertEqual("public-native-token", public_token)
            self.assertEqual(digest(self.fixture.metadata), expected_metadata_sha256)
            self.assertNotIn("REVIEW_COPY_TOKEN", os.environ)
            return self.materialized(consumer.archive.ORIGINAL_SOURCE, destination)
        def current(_api, _repo, _pull, source, destination):
            self.assertNotIn("REVIEW_COPY_TOKEN", os.environ)
            return self.materialized(source, destination)
        locator = consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
        with patch.object(consumer, "historical_subject", side_effect=old), \
             patch.object(consumer, "materialize", side_effect=current):
            return consumer.evidence(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE,
                                     locator, reader=self.api.custody)

    def test_prepare_is_read_only_and_exact_saved_plan_guards_one_cas_then_separate_locator(self):
        plan, _ = self.prepared()
        self.assertEqual([], self.api.mutations)
        with self.assertRaisesRegex(ControlError, "explicit-plan-binding"):
            producer.publish(self.api, plan, self.fixture.directory, "f" * 64)
        self.assertEqual([], self.api.mutations)
        result = producer.publish(self.api, plan, self.fixture.directory, digest(plan))
        self.assertEqual(["graphql", f"repos/{self.fixture.repo}/issues/3/comments"], [p for p, _ in self.api.mutations])
        self.assertEqual(COMMIT, result["custody_commit"])
        self.assertFalse(result["current_gate_pass"])
        self.assertFalse(result["original_artifacts_restored"])
        request = self.api.mutations[0][1]["data"]["variables"]["input"]
        self.assertTrue(all(x["path"].startswith("review-copies/cloud-276/" + digest(plan) + "/")
                            for x in request["fileChanges"]["additions"]))
        self.assertNotIn("provider-response.bin", self.api.comments[0]["body"])

    def test_unknown_cas_outcome_is_never_retried_or_followed_by_public_locator(self):
        plan, _ = self.prepared(); self.api.after_cas_unknown = True
        with self.assertRaisesRegex(ControlError, "unknown-write"):
            producer.publish(self.api, plan, self.fixture.directory, digest(plan))
        self.assertEqual(COMMIT, self.api.custody.tip)
        self.assertEqual(1, len(self.api.mutations))
        self.assertEqual([], self.api.comments)

    def test_graphql_partial_errors_and_concurrent_ref_change_do_not_trigger_retries(self):
        plan, _ = self.prepared(); self.api.graphql_errors = True
        with self.assertRaisesRegex(ControlError, "cas-outcome-unknown"):
            producer.publish(self.api, plan, self.fixture.directory, digest(plan))
        self.assertEqual(1, len(self.api.mutations))
        self.api.mutations.clear(); self.api.custody.tip = "e" * 40
        with self.assertRaisesRegex(ControlError, "stale-saved-plan"):
            producer.publish(self.api, plan, self.fixture.directory, digest(plan))
        self.assertEqual([], self.api.mutations)

    def test_private_scope_protection_operator_and_published_source_are_revalidated(self):
        changes = (
            (lambda: setattr(self.api.custody, "private", False), "private-repository"),
            (lambda: self.api.custody.rule.update(bypass_actors=[{"actor_type": "User"}]), "ref-protection"),
            (lambda: setattr(self.api, "operator", {"login": "other", "id": 99, "type": "User"}), "authorized-operator"),
            (lambda: setattr(self.api, "root_main", "e" * 40), "main-source"),
            (lambda: setattr(self.api, "program_drift", True), "program-drift"),
        )
        for change, message in changes:
            with self.subTest(message=message):
                self.api = ProtocolAPI(self.fixture); change()
                with self.assertRaisesRegex(ControlError, message): self.prepared()
                self.assertEqual([], self.api.mutations)

    def test_signed_producer_failure_keeps_copy_separate_without_false_acceptance(self):
        plan, _ = self.prepared(); self.api.custody.signed = False
        with self.assertRaisesRegex(ControlError, "native-signed-identity"):
            producer.publish(self.api, plan, self.fixture.directory, digest(plan))
        self.assertEqual(1, len(self.api.mutations)); self.assertEqual([], self.api.comments)

    def test_missing_or_malformed_locator_never_falls_through_to_codex(self):
        with self.assertRaisesRegex(ControlError, "locator-required"):
            consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
        self.produced(); self.api.comments[0]["body"] = consumer.MARKER + "{}"
        with self.assertRaisesRegex(ControlError, "locator-shape"):
            consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
        self.assertIsNone(consumer.locate(self.api, "ltn-it/other", self.fixture.pull, NEW_SOURCE))

    def test_operator_locator_cannot_change_subject_source_or_approved_generation(self):
        self.produced()
        self.api.comments[0]["updated_at"] = "2026-10-30T04:00:00Z"
        with self.assertRaisesRegex(ControlError, "edited-or-unknown"):
            consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
        self.api.comments[0]["updated_at"] = self.api.comments[0]["created_at"]
        with self.assertRaisesRegex(ControlError, "old-source-cannot"):
            consumer.locate(self.api, self.fixture.repo, self.fixture.pull, consumer.archive.ORIGINAL_SOURCE)
        self.fixture.pull["head"]["sha"] = "e" * 40
        with self.assertRaisesRegex(ControlError, "fixed-subject-drift"):
            consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)

    def test_explicit_dual_source_semantics_do_not_relabel_original_metadata(self):
        plan, report, _ = self.produced()
        with patch.object(consumer.archive.transport, "run_worker") as model, \
             patch.dict(os.environ, {"REVIEW_COPY_TOKEN": "private-token-never-forward"}):
            result = self.evidence()
        model.assert_not_called()
        self.assertEqual(consumer.archive.ORIGINAL_SOURCE, result["historical_review"]["source"])
        self.assertEqual(report["metadata_sha256"], result["historical_review"]["metadata_sha256"])
        self.assertEqual(NEW_SOURCE, result["current_verification"]["execution"]["source"])
        self.assertNotEqual(result["historical_review"]["metadata_sha256"], result["current_verification"]["metadata_sha256"])
        self.assertTrue(result["normal_current_approval_required"])
        self.assertEqual(0, result["provider_requests_performed"])
        self.assertNotIn("private-token-never-forward", json.dumps(result))
        self.assertNotIn(self.fixture.wire.decode(), json.dumps(result))
        self.assertTrue(self.api.custody.closed)

    def test_current_patch_instructions_schema_or_extra_semantics_must_match(self):
        self.produced()
        for key in ("prompt_sha256", "schema_sha256", "diff_sha256", "instructions_sha256", "new_policy_field"):
            original = self.materialized
            def changed(source, destination, key=key):
                value = original(source, destination)
                if source == NEW_SOURCE: value[key] = "changed"
                return value
            with self.subTest(key=key), patch.object(self, "materialized", side_effect=changed), \
                 self.assertRaisesRegex(ControlError, "semantic-subject-drift"):
                self.evidence()

    def test_copy_producer_repo_signed_identity_and_parent_must_match_private_manifest(self):
        self.produced()
        locator = consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
        self.api.custody.author = {"login": "other", "id": 99, "type": "User"}
        with self.assertRaisesRegex(ControlError, "signed-producer"):
            consumer.package(self.api, self.api.custody, self.fixture.pull, locator)
        self.api.custody.author = clone(OPERATOR); self.api.custody.parents = [{"sha": "f" * 40}]
        with self.assertRaisesRegex(ControlError, "custody-parent"):
            consumer.package(self.api, self.api.custody, self.fixture.pull, locator)

    def test_ref_ancestry_and_no_existing_ledger_rewrite_are_required(self):
        self.produced(); locator = consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
        self.api.custody.ancestry = False
        with self.assertRaisesRegex(ControlError, "custody-ancestry"):
            consumer.package(self.api, self.api.custody, self.fixture.pull, locator)
        self.api.custody.ancestry = True; self.api.custody.changes.append({"filename": "operations/old.json", "status": "modified"})
        with self.assertRaisesRegex(ControlError, "additions-only"):
            consumer.package(self.api, self.api.custody, self.fixture.pull, locator)

    def test_private_token_repository_subset_and_app_identity_fail_closed(self):
        self.api.custody.broad_token = True
        with self.assertRaisesRegex(ControlError, "token-repository-scope"):
            self.api.custody.scope()
        values = {"REVIEW_COPY_CLIENT_ID": consumer.CLIENT_ID, "REVIEW_COPY_APP_SLUG": "lightning-it-release-automation",
                  "REVIEW_COPY_INSTALLATION_ID": str(consumer.INSTALLATION_ID)}
        with patch.dict(os.environ, values):
            reader = consumer.PrivateReader("private-fixture-token")
            with patch.object(consumer, "capture") as native, self.assertRaisesRegex(ControlError, "endpoint-scope"):
                reader.call("repos/ltn-it/other/git/blobs/" + "a" * 40)
            native.assert_not_called()
            for key in values:
                with patch.dict(os.environ, {key: "wrong"}), self.assertRaisesRegex(ControlError, "app-installation"):
                    consumer.PrivateReader("private-fixture-token")

    def test_private_reader_sends_only_a_fixed_get_and_keeps_secret_out_of_argv(self):
        values = {"REVIEW_COPY_CLIENT_ID": consumer.CLIENT_ID, "REVIEW_COPY_APP_SLUG": "lightning-it-release-automation",
                  "REVIEW_COPY_INSTALLATION_ID": str(consumer.INSTALLATION_ID)}
        with patch.dict(os.environ, values), patch.object(consumer, "capture", return_value=b'{}') as native:
            reader = consumer.PrivateReader("private-fixture-token"); reader.call(f"repos/{consumer.CUSTODY}")
        args, kwargs = native.call_args
        self.assertNotIn("private-fixture-token", str(args))
        self.assertEqual("GET", args[0][args[0].index("--method") + 1])
        self.assertEqual("private-fixture-token", kwargs["environment"]["GH_TOKEN"])
        self.assertNotIn("OPENAI_API_KEY", kwargs["environment"])

    def test_historical_interpreter_receives_no_private_token_or_fake_native_job(self):
        with self.fixture.temporary as _unused:
            # Use an independent destination; historical files are synthetic,
            # and capture is replaced before any child or Git process starts.
            destination = self.fixture.directory / "old-context"
            with patch.dict(os.environ, {"REVIEW_COPY_TOKEN": "private-secret", "OPENAI_API_KEY": "model-secret"}), \
                 patch.object(consumer, "capture", return_value=canonical(self.fixture.metadata)) as child:
                result = consumer.historical_subject(self.api, self.fixture.repo, self.fixture.pull,
                                                     destination, public_token="public-native-token",
                                                     expected_metadata_sha256=digest(self.fixture.metadata))
            environment = child.call_args.kwargs["environment"]
            self.assertEqual("public-native-token", environment["GH_TOKEN"])
            self.assertNotIn("NATIVE_JOB", environment)
            self.assertNotIn("REVIEW_COPY_TOKEN", environment)
            self.assertNotIn("OPENAI_API_KEY", environment)
            self.assertEqual(consumer.archive.ORIGINAL_SOURCE, result["central_source_sha"])

    def test_current_native_source_job_attempt_and_association_are_checked(self):
        self.produced()
        for change in ({"run_attempt": 2}, {"run_id": 31}, {"id": 999}, {"status": "completed"}):
            self.api.native_job.update(change)
            with self.subTest(change=change), self.assertRaisesRegex(ControlError, "current-native-job"):
                consumer.native_context(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
            self.api.native_job = {"id": 400, "run_id": 30, "run_attempt": 1, "name": "Protected current revision",
                                   "status": "in_progress"}

    def test_original_source_job_and_native_log_drifts_cannot_use_a_local_copy_alone(self):
        self.produced(); self.fixture.job["conclusion"] = "failure"
        with self.assertRaisesRegex(ControlError, "producer-success"):
            self.evidence()
        self.fixture.job["conclusion"] = "success"; self.fixture.log += "\n" + self.fixture.log
        with self.assertRaisesRegex(ControlError, "export-ambiguous"):
            self.evidence()

    def test_both_named_owner_identities_can_produce_the_same_bounded_plan(self):
        self.api.operator = {"login": "litdeg", "id": 247824904, "type": "User"}
        self.api.custody.author = clone(self.api.operator)
        plan, _, result = self.produced()
        self.assertEqual(["litdeg", 247824904, "User"], plan["operator"])
        self.assertEqual(COMMIT, result["custody_commit"])

    def test_corrupt_private_blob_and_extra_namespace_file_are_rejected(self):
        self.produced(); locator = consumer.locate(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE)
        entry = self.api.custody.nodes["7" * 40]["tree"][0]
        blob = self.api.custody.nodes[entry["sha"]]
        original = blob["content"]
        blob["content"] = base64.b64encode(b"x" * entry["size"]).decode()
        with self.assertRaisesRegex(ControlError, "blob-digest"):
            consumer.package(self.api, self.api.custody, self.fixture.pull, locator)
        blob["content"] = original
        self.api.custody.nodes["7" * 40]["tree"].append(clone(entry))
        with self.assertRaisesRegex(ControlError, "exact-files"):
            consumer.package(self.api, self.api.custody, self.fixture.pull, locator)

    def test_preexisting_namespace_cannot_be_replaced(self):
        plan, _ = self.prepared()
        prefix = "review-copies/cloud-276/" + digest(plan)
        self.api.custody.add([{"path": prefix + "/operation.zip", "contents": "eA=="}])
        self.api.custody.nodes["3" * 40] = clone(self.api.custody.nodes["4" * 40])
        self.api.custody.nodes["3" * 40]["sha"] = "3" * 40
        self.api.custody.tip = BASE
        with self.assertRaisesRegex(ControlError, "namespace-already-exists"):
            producer.publish(self.api, plan, self.fixture.directory, digest(plan))
        self.assertEqual([], self.api.mutations)

    def test_old_code_is_authenticated_before_any_historical_execution(self):
        original = self.api.file
        def changed(repository, path, revision):
            data = original(repository, path, revision)
            return data + b"changed" if path.startswith("scripts/") and revision == consumer.archive.ORIGINAL_SOURCE else data
        with patch.object(self.api, "file", side_effect=changed), patch.object(consumer, "capture") as child, \
             self.assertRaisesRegex(ControlError, "historical-source-bytes"):
            consumer.historical_subject(self.api, self.fixture.repo, self.fixture.pull,
                                        self.fixture.directory / "historical-subject", public_token="",
                                        expected_metadata_sha256=digest(self.fixture.metadata))
        child.assert_not_called()

    def test_raw_patch_bytes_and_late_locator_are_rechecked(self):
        self.produced(); original = self.materialized
        def altered_patch(source, destination):
            value = original(source, destination)
            if source == NEW_SOURCE: (destination / "change.patch").write_bytes(b"changed despite metadata")
            return value
        with patch.object(self, "materialized", side_effect=altered_patch), \
             self.assertRaisesRegex(ControlError, "semantic-subject-drift"):
            self.evidence()
        def altered_locator(source, destination):
            value = original(source, destination)
            if source == NEW_SOURCE: self.api.comments[0]["updated_at"] = "2026-10-30T05:00:00Z"
            return value
        with patch.object(self, "materialized", side_effect=altered_locator), \
             self.assertRaisesRegex(ControlError, "locator-edited"):
            self.evidence()

    def test_route_is_fixed_to_the_incident_without_paid_fallback(self):
        with self.assertRaisesRegex(ControlError, "locator-required"):
            consumer.select_route(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE, "codex", None)
        self.produced()
        self.assertEqual("review-copy", consumer.select_route(
            self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE, "codex", None)[0])
        with self.assertRaisesRegex(ControlError, "normal-route-required"):
            consumer.select_route(self.api, self.fixture.repo, self.fixture.pull, NEW_SOURCE, "codex", object())
        self.assertEqual(("codex", None), consumer.select_route(
            self.api, "ltn-it/other", self.fixture.pull, NEW_SOURCE, "codex", None))

    def test_native_copy_proof_cannot_be_generalized_or_relabelled(self):
        self.produced(); evidence = self.evidence()
        run = {"id": 30, "run_attempt": 1}; gate = {"id": 400}
        record = {"route": "review-copy", "source_sha": NEW_SOURCE, "authorization": {"run": 30}, "evidence": evidence}
        consumer.validate_native_proof(self.fixture.repo, self.fixture.pull, record, run, gate)
        for alteration in (lambda v: v["authorization"].update(run=29),
                           lambda v: v["evidence"]["historical_review"].update(source=NEW_SOURCE),
                           lambda v: v["evidence"]["current_verification"]["execution"].update(attempt=2),
                           lambda v: v["evidence"].update(provider_requests_performed=1)):
            changed = clone(record); alteration(changed)
            with self.assertRaisesRegex(ControlError, "dual-source-proof"):
                consumer.validate_native_proof(self.fixture.repo, self.fixture.pull, changed, run, gate)
        with self.assertRaisesRegex(ControlError, "ingress-target"):
            consumer.validate_native_proof("ltn-it/other", self.fixture.pull, record, run, gate)


if __name__ == "__main__":
    unittest.main()
