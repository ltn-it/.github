"""Current GitHub names never substitute for immutable organization/repo IDs."""
import json
import importlib.util
import copy
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_control as control


class NamespaceIdentityTests(unittest.TestCase):
    def test_correction_preserves_the_independently_seeded_judge_in_proof_lineage(self):
        value = {"version": 1, "repository": "ltn-it/.github", "mode": "reference",
                 "quality": [{"workflow": ".github/workflows/repository-quality.yml", "job": "quality"}],
                 "accepted_sources": ["c292909ca4f90b79d2b2fef404f10d42c7184e00"]}
        result = control.policy_value(value, "ltn-it/.github", "a" * 40)
        self.assertIn("c292909ca4f90b79d2b2fef404f10d42c7184e00", result["accepted_sources"])

    def test_actual_frozen_delivery_helpers_admit_current_consumers(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / ".github/workflows/delivery-operations.yml").read_bytes())
        revisions = {workflow["jobs"][job]["steps"][0]["with"]["ref"] for job in ("refresh", "prepare")}
        for revision in revisions:
            source = "530b8fb175b7fccf238b03aab652bd5ee2ad2a41"
            changes = subprocess.check_output(["git", "-c", f"safe.directory={root}", "diff",
                "--name-only", source, revision], cwd=root, text=True).splitlines()
            self.assertEqual([".lit/promotion-event-targets.json", "scripts/workflow_promotion_event.py"], changes)
            subprocess.run(["git", "-c", f"safe.directory={root}", "merge-base",
                            "--is-ancestor", source, revision], cwd=root, check=True)
            payload = subprocess.check_output(["git", "-c", f"safe.directory={root}",
                "archive", revision, "scripts", ".lit"], cwd=root)
            with tempfile.TemporaryDirectory() as temp:
                with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                    archive.extractall(temp, filter="data")
                program = '''
import json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1] + "/scripts")
import workflow_events as events
import workflow_promotion_event as promotion
for repository in ("ltn-it/shared-assets-lit", "ltn-it/ansible-collection-supplementary"):
    assert promotion.target(repository)["repository"] == repository
    assert promotion.target(repository)["source_sha"] == sys.argv[3]
    event = Path(sys.argv[1]) / "event.json"
    event.write_text("{}")
    os.environ.update(GITHUB_REPOSITORY=repository, GITHUB_EVENT_NAME="pull_request_target",
        GITHUB_EVENT_PATH=str(event), NATIVE_JOB=json.dumps({"workflow_repository":"ltn-it/.github",
        "workflow_file_path":".github/workflows/delivery-operations.yml",
        "workflow_sha":sys.argv[2], "check_run_id":55}))
    with patch.object(events, "refresh") as refresh:
        events.main()
        assert refresh.call_args.args[1] == repository
'''
                subprocess.run([sys.executable, "-IB", "-c", program, temp, revision, source],
                               check=True, capture_output=True)

    def test_unchanged_historical_native_proof_survives_authenticated_rename(self):
        from test_workflow_control import pull, run, SOURCE, REPO
        value = pull(state="closed", merged=True, merge_commit_sha="d" * 40)
        for side in ("base", "head"):
            value[side]["repo"]["id"] = control.RENAMED_REPOSITORIES[".github"]
        record = {"version": 1, "source_sha": SOURCE, "route": "copilot",
                  "binding": control.binding(value) | {"head_repository": "lightning-it/.github"}}
        original = control.canonical(record)
        source_run = run() | {"status": "completed", "conclusion": "success"}
        api = Mock()
        api.pages.side_effect = [[source_run], [{"id": 100, "run_id": 10,
            "name": "Current revision review", "conclusion": "success"}], [source_run], [source_run]]
        api.call.side_effect = lambda path: (self.repository() if path == "repos/" + REPO else
            copy.deepcopy(value) if path.endswith("/pulls/3") else source_run)
        with patch.object(control, "artifact_record", return_value=record):
            result = control.check_native_control(api, REPO, value, {"accepted_sources": [SOURCE]})
        self.assertEqual(control.digest(record), result["proof_sha256"])
        self.assertEqual(original, control.canonical(record))
        for mutate in (lambda p: p.update(state="open", merged=False),
                       lambda p: p["head"]["repo"].update(id=1),
                       lambda p: p["base"]["repo"].update(id=True),
                       lambda p: p.update(title="changed"),
                       lambda p: p["head"]["repo"].update(full_name="ltn-it/other")):
            changed = copy.deepcopy(value)
            mutate(changed)
            self.assertFalse(control.historical_binding_matches(api, REPO, changed, record["binding"]))
        api.call.side_effect = None
        api.call.return_value = self.repository() | {"id": 1}
        with self.assertRaises(control.ControlError):
            control.historical_binding_matches(api, REPO, value, record["binding"])

    def test_archive_keys_preserve_old_namespace_and_reject_similar_foreign_names(self):
        spec = importlib.util.spec_from_file_location("namespace_archive", Path(__file__).resolve().parents[1]
                                                     / "scripts/lit-release-archive.py")
        archive = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = archive
        spec.loader.exec_module(archive)
        for repository in ("lightning-it/.github", "ltn-it/.github"):
            key = archive.object_key(repository, 3, "a" * 40, "b" * 64, "c" * 32)
            self.assertEqual(f"runs/github-release/v1/{repository}/3/"
                             + "a" * 40 + "/" + "c" * 32 + "/" + "b" * 64 + ".json", key)
        for repository in ("evil/ltn-it/.github", "ltn-it-evil/.github", "ltn-it/../.github"):
            with self.subTest(repository=repository), self.assertRaises(archive.ArchiveError):
                archive.object_key(repository, 3, "a" * 40, "b" * 64, "c" * 32)

    def repository(self, name=".github"):
        return {"id": control.RENAMED_REPOSITORIES[name], "full_name": f"ltn-it/{name}",
                "owner": {"login": "ltn-it", "id": 54334171},
                "archived": False, "disabled": False}

    def test_current_renamed_repositories_require_the_original_numeric_ids(self):
        for name, identifier in control.RENAMED_REPOSITORIES.items():
            api = Mock(); api.call.return_value = self.repository(name)
            with self.subTest(name=name):
                self.assertEqual(identifier, control.current_repository(api, f"ltn-it/{name}"))
            api.call.assert_called_once_with(f"repos/ltn-it/{name}")

    def test_prefix_alias_and_path_variants_fail_before_any_api_access(self):
        for name in ("lightning-it/.github", "ltn-it-evil/.github", "evil/ltn-it/.github",
                     "ltn-it/.github/extra", "ltn-it/.github?ref=main", "ltn-it/.github\n"):
            api = Mock()
            with self.subTest(name=name), self.assertRaises(control.ControlError):
                control.current_repository(api, name)
            api.call.assert_not_called()

    def invalid_repository_states(self, name=".github"):
        for field in ("archived", "disabled"):
            missing = self.repository(name)
            del missing[field]
            yield field, "missing", missing
            for invalid in (None, 0, "", [], {}, True, 1, "false"):
                yield field, repr(invalid), self.repository(name) | {field: invalid}

    def test_unknown_repository_state_is_rejected_for_every_fixed_identity(self):
        for name in control.RENAMED_REPOSITORIES:
            for field, invalid, value in self.invalid_repository_states(name):
                api = Mock(); api.call.return_value = value
                with self.subTest(name=name, field=field, invalid=invalid), \
                        self.assertRaisesRegex(control.ControlError, "current-repository-identity"):
                    control.current_repository(api, f"ltn-it/{name}")

    def test_unknown_repository_state_cannot_authenticate_a_historical_rename(self):
        from test_workflow_control import pull
        subject = pull(state="closed", merged=True, merge_commit_sha="d" * 40)
        for side in ("base", "head"):
            subject[side]["repo"]["id"] = control.RENAMED_REPOSITORIES[".github"]
        recorded = control.binding(subject) | {"head_repository": "lightning-it/.github"}
        original = control.canonical(recorded)
        for field, invalid, value in self.invalid_repository_states():
            api = Mock(); api.call.return_value = value
            with self.subTest(field=field, invalid=invalid), \
                    self.assertRaisesRegex(control.ControlError, "current-repository-identity"):
                control.historical_binding_matches(api, "ltn-it/.github", subject, recorded)
            self.assertEqual(original, control.canonical(recorded))

    def test_unknown_repository_state_blocks_protected_policy_rename(self):
        original = {"version": 1, "repository": "lightning-it/.github", "mode": "reference",
                    "quality": [{"workflow": ".github/workflows/quality.yml", "job": "quality"}],
                    "accepted_sources": []}
        raw = json.dumps(original).encode()
        for field, invalid, value in self.invalid_repository_states():
            api = Mock(); api.file.return_value = raw; api.call.return_value = value
            with self.subTest(field=field, invalid=invalid), \
                    self.assertRaisesRegex(control.ControlError, "current-repository-identity"):
                control.policy(api, "ltn-it/.github", "b" * 40, "a" * 40)
            self.assertEqual(raw, api.file.return_value)

    def test_unknown_repository_state_blocks_classification_before_event_or_funding(self):
        job = {"workflow_repository": "ltn-it/.github", "workflow_file_path": control.WORKFLOW,
               "workflow_sha": "a" * 40, "check_run_id": 123}
        for field, invalid, value in self.invalid_repository_states():
            api = Mock(); api.call.return_value = value
            with self.subTest(field=field, invalid=invalid), \
                    patch.dict(os.environ, {"GITHUB_REPOSITORY": "ltn-it/.github",
                        "NATIVE_JOB": json.dumps(job)}, clear=True), \
                    patch.object(sys, "argv", ["control", "classify"]), \
                    patch.object(control, "API", return_value=api), \
                    patch.object(control, "reserve_request") as reserve, \
                    self.assertRaisesRegex(control.ControlError, "current-repository-identity"):
                control.main()
            reserve.assert_not_called()
            api.call.assert_called_once_with("repos/ltn-it/.github")

    def test_recreated_repository_foreign_owner_boolean_and_disabled_targets_block(self):
        original = self.repository()
        variants = [original | {"id": value} for value in (True, 1, None)]
        variants += [original | {"full_name": "lightning-it/.github"},
                     original | {"owner": {"login": "ltn-it", "id": 1}},
                     original | {"owner": {"login": "other", "id": 54334171}},
                     original | {"owner": {"login": "ltn-it", "id": True}},
                     original | {"archived": True}, original | {"disabled": True}]
        for value in variants:
            api = Mock(); api.call.return_value = value
            with self.subTest(value=value), self.assertRaises(control.ControlError):
                control.current_repository(api, "ltn-it/.github")

    def test_identity_failure_blocks_the_real_entrypoint_before_event_or_funding(self):
        api = Mock(); api.call.return_value = self.repository() | {"id": 1}
        job = {"workflow_repository": "ltn-it/.github", "workflow_file_path": control.WORKFLOW,
               "workflow_sha": "a" * 40, "check_run_id": 123}
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "ltn-it/.github",
                                    "NATIVE_JOB": json.dumps(job)}, clear=True), \
                patch.object(sys, "argv", ["control", "classify"]), \
                patch.object(control, "API", return_value=api), \
                patch.object(control, "reserve_request") as reserve, \
                self.assertRaisesRegex(control.ControlError, "renamed-repository-id-drift"):
            control.main()
        reserve.assert_not_called()
        api.call.assert_called_once_with("repos/ltn-it/.github")

    def test_historical_source_admissions_and_app_identities_are_not_renamed(self):
        self.assertEqual("lightning-it/shared-assets-lit", control.SOURCE_GENERATED_SUBJECT["repository"])
        self.assertEqual(("lightning-it-release-automation[bot]", 307565056, "Bot"), control.RELEASE)
        self.assertEqual(("lightning-it-shared-assets-sync[bot]", 307342877, "Bot"), control.SYNC)

    def test_old_protected_base_needs_verified_numeric_identity_and_keeps_original_name(self):
        for name, identifier in control.RENAMED_REPOSITORIES.items():
            original = {"version": 1, "repository": f"lightning-it/{name}", "mode": "reference",
                        "quality": [{"workflow": ".github/workflows/quality.yml", "job": "quality"}],
                        "accepted_sources": []}
            raw = json.dumps(original).encode()
            api = Mock(); api.file.return_value = raw; api.call.return_value = self.repository(name)
            result = control.policy(api, f"ltn-it/{name}", "b" * 40, "a" * 40)
            self.assertEqual(f"lightning-it/{name}", result["repository"])
            self.assertEqual(raw, api.file.return_value)
            api.call.assert_called_once_with(f"repos/ltn-it/{name}")
            for actual in (None, True, identifier + 1):
                with self.subTest(name=name, identifier=actual), self.assertRaises(control.ControlError):
                    control.policy_value(json.loads(raw), f"ltn-it/{name}", "a" * 40,
                                         renamed_repository_id=actual)
            # Even a correctly authenticated rename never admits an unknown
            # source or refunds/changes any historical request record.
            changed = json.loads(raw) | {"accepted_sources": ["f" * 40]}
            with self.assertRaisesRegex(control.ControlError, "consumer-cannot-admit-central-source"):
                control.policy_value(changed, f"ltn-it/{name}", "a" * 40,
                                     renamed_repository_id=identifier)
