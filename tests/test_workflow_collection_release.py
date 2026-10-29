"""Normal stable releases keep their exact native review and Main approval."""
import copy
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, chdir
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_collection_release as collection
import workflow_control as control


def pull(repository, identifier):
    return {
        "number": 3, "title": "Release v1.38.0", "body": "", "labels": [], "draft": False,
        "user": dict(zip(("login", "id", "type"), collection.RELEASE)),
        "base": {"sha": "a" * 40, "ref": "main", "repo": {"full_name": repository, "id": identifier}},
        "head": {"sha": "b" * 40, "ref": "release/v1.38.0", "repo": {"full_name": repository, "id": identifier}},
    }


class CollectionReleaseTests(unittest.TestCase):
    def entry_context(self, directory, operation):
        repository, identifier = next(iter(collection.COLLECTIONS.items()))
        value = pull(repository, identifier)
        value.update(number=3, title="Release v1.38.0", body="", labels=[], draft=False)
        value["base"]["sha"], value["head"]["sha"] = "a" * 40, "b" * 40
        event = Path(directory) / "event.json"
        event.write_text(json.dumps({"pull_request": value}))
        environment = {"GITHUB_REPOSITORY": repository, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "NATIVE_JOB": "{}",
                       "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(Path(directory) / "output"),
                       "COMMON_QUALITY_RESULT": "success", "REVIEW_RESULT": "success",
                       "APPROVAL_RESULT": "skipped"}
        stack = ExitStack()
        stack.enter_context(chdir(directory))
        stack.enter_context(patch.dict(os.environ, environment, clear=True))
        stack.enter_context(patch.object(sys, "argv", ["control", operation]))
        api = Mock(); api.call.return_value = {"id": 10, "run_attempt": 1}
        stack.enter_context(patch.object(control, "API", return_value=api))
        stack.enter_context(patch.object(control, "current_repository", return_value=identifier))
        stack.enter_context(patch.object(control, "source_identity", return_value="c" * 40))
        stack.enter_context(patch.object(control, "native_required", return_value=True))
        stack.enter_context(patch.object(control, "live_pull", return_value=value))
        stack.enter_context(patch.object(control, "policy", return_value={}))
        stack.enter_context(patch.object(control, "operation_record", return_value={
            "version": 1, "source_sha": "c" * 40, "binding": control.binding(value)}))
        return stack, api, repository

    def test_real_classify_requires_normal_environment_before_any_funded_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, api, repository = self.entry_context(directory, "classify")
            with stack, patch.object(control, "normal_environment", side_effect=control.ControlError("missing-environment")), \
                 patch.object(control, "reserve_request") as funding, \
                 self.assertRaisesRegex(control.ControlError, "missing-environment"):
                control.main()
            funding.assert_not_called()
            self.assertTrue(all(call.kwargs.get("method", "GET") == "GET" for call in api.call.call_args_list))
        with tempfile.TemporaryDirectory() as directory:
            stack, _, repository = self.entry_context(directory, "classify")
            with stack, patch.object(control, "normal_environment") as environment, \
                 patch.object(control, "previous_approval", return_value=None), \
                 patch.object(control, "copilot_review") as copilot:
                control.main()
                output = (Path(directory) / "output").read_text()
                self.assertIn("route=codex\n", output)
                self.assertIn("approval_needed=true\n", output)
                self.assertIn("request_needed=false\n", output)
            environment.assert_called_once()
            copilot.assert_not_called()

    def test_real_finalize_blocks_without_actual_native_main_approval(self):
        for missing_history in (False, True):
            with self.subTest(missing_history=missing_history), tempfile.TemporaryDirectory() as directory:
                stack, _, _ = self.entry_context(directory, "finalize")
                with stack, patch.object(control, "normal_environment"), \
                     patch.object(control, "previous_approval", return_value=None), \
                     patch.object(collection, "native_approval", side_effect=control.ControlError("missing-native-history")) as approval, \
                     patch.object(control, "check_quality") as quality:
                    if missing_history:
                        os.environ["APPROVAL_RESULT"] = "success"
                    with self.assertRaisesRegex(control.ControlError, "missing-native-history|normal-main-approval-rejected-or-unavailable"):
                        control.main()
                    quality.assert_not_called()
                    self.assertEqual(int(missing_history), approval.call_count)
                    self.assertFalse((Path(directory) / "control-proof.json").exists())

    def test_real_finalize_retains_native_approval_and_current_codex_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, api, repository = self.entry_context(directory, "finalize")
            native = {"user": {"login": "litroc", "id": 76040632, "type": "User"}}
            evidence = {"kind": "test-double-for-authenticated-current-codex-evidence"}
            with stack, patch.object(control, "normal_environment"), \
                 patch.object(collection, "native_approval", return_value=native) as approval, \
                 patch.object(control, "check_quality", return_value=[]) as quality, \
                 patch.object(control, "validate_signal"), \
                 patch.object(control, "native_conversation_guard", return_value=[1]), \
                 patch.object(control, "verify_existing_route", return_value=evidence) as review:
                os.environ["APPROVAL_RESULT"] = "success"
                control.main()
                result = json.loads((Path(directory) / "control-proof.json").read_bytes())
                self.assertEqual({"run": 10, "approval": native}, result["authorization"])
                self.assertEqual("codex", result["route"])
                self.assertEqual(evidence, result["evidence"])
                self.assertEqual(2, approval.call_count)
                for call in approval.call_args_list:
                    self.assertEqual((api, repository, review.call_args.args[2], "c" * 40, 10), call.args)
                quality.assert_called_once()
                self.assertEqual("codex", review.call_args.args[-1])

    def test_failed_codex_job_cannot_reach_normal_approval_or_quality_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, _, _ = self.entry_context(directory, "finalize")
            with stack, patch.object(collection, "native_approval") as approval, \
                 patch.object(control, "check_quality") as quality:
                os.environ["REVIEW_RESULT"] = "failure"
                with self.assertRaisesRegex(control.ControlError, "codex-review-job-not-successful"):
                    control.main()
                approval.assert_not_called()
                quality.assert_not_called()
                self.assertFalse((Path(directory) / "control-proof.json").exists())

    def test_rejected_or_cancelled_main_job_never_falls_back_to_any_old_approval(self):
        for result in ("failure", "cancelled", "unavailable"):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                stack, _, _ = self.entry_context(directory, "finalize")
                with stack, patch.object(control, "normal_environment"), \
                     patch.object(control, "previous_approval", return_value=9) as previous, \
                     patch.object(collection, "native_approval") as approval, \
                     patch.object(control, "check_quality") as quality:
                    os.environ["APPROVAL_RESULT"] = result
                    with self.assertRaisesRegex(control.ControlError, "normal-main-approval-rejected-or-unavailable"):
                        control.main()
                    previous.assert_not_called()
                    approval.assert_not_called()
                    quality.assert_not_called()
                    self.assertFalse((Path(directory) / "control-proof.json").exists())

    def test_all_six_require_complete_codex_review_and_real_normal_approval(self):
        for repository, identifier in collection.COLLECTIONS.items():
            value = pull(repository, identifier)
            with self.subTest(repository=repository):
                self.assertTrue(collection.normal_release(value, repository))
                self.assertEqual("codex", control.classify(value, repository))
                self.assertTrue(control.normal_approval_required(value, repository, "codex"))
                self.assertFalse(control.normal_approval_required(value, repository, "copilot"))

    def test_each_numeric_repository_binding_is_independently_required(self):
        for repository, identifier in collection.COLLECTIONS.items():
            for side in ("base", "head"):
                for replacement in (None, True, str(identifier), identifier + 1):
                    value = pull(repository, identifier)
                    value[side]["repo"]["id"] = replacement
                    with self.subTest(repository=repository, side=side, replacement=replacement):
                        self.assertFalse(collection.normal_release(value, repository))
                        with self.assertRaises(control.ControlError):
                            control.classify(value, repository)

    def test_exact_app_identity_is_required(self):
        repository, identifier = next(iter(collection.COLLECTIONS.items()))
        for field, replacement in (("login", "unknown[bot]"), ("id", 1), ("type", "User")):
            value = pull(repository, identifier)
            value["user"][field] = replacement
            with self.subTest(field=field):
                self.assertFalse(collection.normal_release(value, repository))
                with self.assertRaises(control.ControlError):
                    control.classify(value, repository)

    def test_unknown_targets_and_forks_cannot_obtain_main_release_route(self):
        repository, identifier = next(iter(collection.COLLECTIONS.items()))
        for side in ("base", "head"):
            for replacement in (None, {"full_name": "attacker/fork", "id": identifier},
                                {"full_name": repository, "id": identifier + 1}):
                value = pull(repository, identifier)
                value[side]["repo"] = replacement
                with self.subTest(side=side, replacement=replacement):
                    self.assertFalse(collection.normal_release(value, repository))
                    with self.assertRaises(control.ControlError):
                        control.classify(value, repository)
        value = pull("ltn-it/unknown-collection", identifier)
        self.assertFalse(collection.normal_release(value, "ltn-it/unknown-collection"))
        with self.assertRaises(control.ControlError):
            control.classify(value, "ltn-it/unknown-collection")

    def test_only_canonical_stable_release_branches_are_recognized(self):
        repository, identifier = next(iter(collection.COLLECTIONS.items()))
        for branch in ("release/v1.2", "release/v01.2.3", "release/v1.2.3-rc.1",
                       "release/v1.2.3/other", "release/v1.2.3\n", "feature", "security-release/example"):
            value = pull(repository, identifier)
            value["head"]["ref"] = branch
            with self.subTest(branch=branch):
                self.assertFalse(collection.normal_release(value, repository))
                with self.assertRaises(control.ControlError):
                    control.classify(value, repository)

    def test_security_proof_and_ordinary_promotion_contracts_are_preserved(self):
        repository, identifier = next(iter(collection.COLLECTIONS.items()))
        value = pull(repository, identifier)
        self.assertFalse(control.normal_approval_required(value, repository, "codex", security=object()))
        promotion = copy.deepcopy(value)
        promotion["head"]["ref"] = "develop"
        self.assertEqual("promotion", control.classify(promotion, repository))
        self.assertTrue(control.normal_approval_required(promotion, repository, "promotion"))
        feature = copy.deepcopy(value)
        feature["base"]["ref"], feature["head"]["ref"] = "develop", "feature"
        self.assertEqual("codex", control.classify(feature, repository))
        self.assertFalse(control.normal_approval_required(feature, repository, "codex"))


if __name__ == "__main__":
    unittest.main()
