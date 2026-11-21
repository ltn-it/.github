"""Offline current-control hooks keep native approval and funding separate."""
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, chdir
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_collection_release as collection
import workflow_control as control
import workflow_review_copy as copy


class CopyControlTests(unittest.TestCase):
    def context(self, directory, operation):
        repo = copy.archive.REPOSITORY
        pull = {"number": 276, "state": "open", "title": "Release v1.2.0", "body": "", "labels": [], "draft": False,
                "user": dict(zip(("login", "id", "type"), control.RELEASE)),
                "base": {"sha": copy.TARGET["base"], "ref": "main", "repo": {"full_name": repo, "id": copy.archive.REPOSITORY_ID}},
                "head": {"sha": copy.TARGET["head"], "ref": "release/v1.2.0", "repo": {"full_name": repo, "id": copy.archive.REPOSITORY_ID}}}
        source = "9" * 40
        locator = {"comment": 99, "fixture": "isolated locator data"}
        record = {"version": 1, "source_sha": source, "binding": control.binding(pull), "review_copy": locator}
        root = Path(directory)
        (root / "event.json").write_text(json.dumps({"pull_request": pull}))
        (root / "control-operation.json").write_text(json.dumps(record))
        environment = {"GITHUB_REPOSITORY": repo, "GITHUB_RUN_ID": "30", "GITHUB_RUN_ATTEMPT": "1",
                       "NATIVE_JOB": "{}", "GITHUB_EVENT_PATH": str(root / "event.json"),
                       "GITHUB_OUTPUT": str(root / "output"), "COMMON_QUALITY_RESULT": "success",
                       "REVIEW_RESULT": "success", "APPROVAL_RESULT": "success", "REVIEW_COPY_TOKEN": "private-fixture-token"}
        stack = ExitStack()
        stack.enter_context(chdir(directory))
        stack.enter_context(patch.dict(os.environ, environment, clear=True))
        stack.enter_context(patch.object(sys, "argv", ["control", operation]))
        api = Mock(); api.call.return_value = {"id": 30, "run_attempt": 1}
        def construct():
            self.assertNotIn("REVIEW_COPY_TOKEN", os.environ)
            return api
        stack.enter_context(patch.object(control, "API", side_effect=construct))
        for name, result in (("current_repository", copy.archive.REPOSITORY_ID), ("source_identity", source),
                             ("native_required", True), ("live_pull", pull), ("policy", {}),
                             ("operation_record", record), ("previous_approval", None)):
            stack.enter_context(patch.object(control, name, return_value=result))
        stack.enter_context(patch.object(control, "normal_environment"))
        stack.enter_context(patch.object(copy, "locate", return_value=locator))
        return stack, api, record

    def test_actual_classify_records_locator_and_demands_fresh_normal_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, _, record = self.context(directory, "classify")
            with stack, patch.object(control, "reserve_request") as funding:
                control.main()
                output = (Path(directory) / "output").read_text()
                self.assertIn("route=review-copy\n", output)
                self.assertIn("approval_needed=true\n", output)
                self.assertIn("request_needed=false\n", output)
                self.assertEqual(record, json.loads((Path(directory) / "control-operation.json").read_text()))
                funding.assert_not_called()

    def test_missing_locator_blocks_before_any_funded_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, _, _ = self.context(directory, "classify")
            with stack, patch.object(copy, "locate", side_effect=control.ControlError("copy-locator-required")), \
                 patch.object(control, "reserve_request") as funding, \
                 self.assertRaisesRegex(control.ControlError, "locator-required"):
                control.main()
            funding.assert_not_called()

    def test_no_codex_entry_can_allocate_or_prepare_for_copy_route(self):
        for operation in ("prepare-codex", "reserve-codex", "verify-codex"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                stack, _, _ = self.context(directory, operation)
                with stack, patch.object(control, "reserve_request") as funding, \
                     self.assertRaisesRegex(control.ControlError, "codex-identity-required"):
                    control.main()
                funding.assert_not_called()

    def test_review_consumes_token_explicitly_with_no_ambient_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, api, record = self.context(directory, "review")
            with stack, patch.object(copy, "evidence", return_value={"fixture": "local test only"}) as verify:
                control.main()
                self.assertEqual("private-fixture-token", verify.call_args.kwargs["private_token"])
                self.assertEqual(record["review_copy"], verify.call_args.args[-1])
                self.assertNotIn("REVIEW_COPY_TOKEN", os.environ)

    def test_failed_or_skipped_current_review_never_reaches_approval_or_custody(self):
        for result in ("failure", "cancelled", "skipped"):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                stack, _, _ = self.context(directory, "finalize")
                with stack, patch.object(collection, "native_approval") as approve, \
                     patch.object(copy, "evidence") as verify, \
                     self.assertRaisesRegex(control.ControlError, "copy-current-review-job-not-successful"):
                    os.environ["REVIEW_RESULT"] = result
                    control.main()
                approve.assert_not_called(); verify.assert_not_called()

    def test_current_normal_approval_cannot_be_skipped_or_replaced_by_copy(self):
        for result in ("skipped", "failure", "cancelled"):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                stack, _, _ = self.context(directory, "finalize")
                with stack, patch.object(collection, "native_approval") as approve, \
                     patch.object(copy, "evidence") as verify, \
                     self.assertRaisesRegex(control.ControlError, "normal-main-approval-rejected-or-unavailable"):
                    os.environ["APPROVAL_RESULT"] = result
                    control.main()
                approve.assert_not_called(); verify.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            stack, _, _ = self.context(directory, "finalize")
            with stack, patch.object(collection, "native_approval", side_effect=control.ControlError("purpose-marker-missing")), \
                 patch.object(copy, "evidence") as verify, self.assertRaisesRegex(control.ControlError, "purpose-marker-missing"):
                control.main()
            verify.assert_not_called()

    def test_finalizer_rechecks_normal_decision_quality_conversations_and_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, _, _ = self.context(directory, "finalize")
            native = {"user": {"login": "litroc", "id": 76040632, "type": "User"}, "fixture": "not native acceptance"}
            with stack, patch.object(collection, "native_approval", return_value=native) as approve, \
                 patch.object(control, "check_quality", return_value=["quality"]) as quality, \
                 patch.object(control, "validate_signal"), \
                 patch.object(control, "native_conversation_guard", return_value=["conversation"]) as conversations, \
                 patch.object(copy, "evidence", return_value={"fixture": "local test only"}) as verify:
                control.main()
                proof = json.loads((Path(directory) / "control-proof.json").read_text())
                self.assertEqual("review-copy", proof["route"])
                self.assertEqual({"run": 30, "approval": native}, proof["authorization"])
                self.assertEqual(["conversation"], proof["native_conversation_guard"])
                self.assertEqual(2, approve.call_count)
                self.assertTrue(all(call.kwargs == {"expected_attempt": 1} for call in approve.call_args_list))
                quality.assert_called_once(); conversations.assert_called_once(); verify.assert_called_once()
                self.assertEqual("private-fixture-token", verify.call_args.kwargs["private_token"])

    def test_changed_locator_is_rejected_before_private_read(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, _, record = self.context(directory, "finalize")
            record["review_copy"] = {"comment": 98}
            with stack, patch.object(copy, "evidence") as verify, \
                 self.assertRaisesRegex(control.ControlError, "copy-operation-locator-drift"):
                control.main()
            verify.assert_not_called()

    def test_yaml_mints_only_fixed_private_read_tokens_and_keeps_model_conditions(self):
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / control.WORKFLOW).read_text())
        for key in ("review", "required"):
            steps = workflow["jobs"][key]["steps"]
            app = [s for s in steps if s.get("id") == "copy_token"]
            self.assertEqual(1, len(app))
            self.assertEqual("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", app[0]["uses"])
            self.assertEqual({"client-id", "private-key", "owner", "repositories", "permission-contents", "skip-token-revoke"}, set(app[0]["with"]))
            self.assertEqual("ltn-it", app[0]["with"]["owner"])
            self.assertEqual("shared-assets-lit", app[0]["with"]["repositories"])
            self.assertEqual("read", app[0]["with"]["permission-contents"])
            self.assertFalse(app[0]["with"]["skip-token-revoke"])
            self.assertEqual("--require=${{ github.workspace }}/scripts/workflow_review_copy_grant.cjs", app[0]["env"]["NODE_OPTIONS"])
            self.assertIn("route == 'review-copy'", app[0]["if"])
            if key == "required": self.assertIn("needs.review.result == 'success'", app[0]["if"])
        for step in workflow["jobs"]["review"]["steps"]:
            if step.get("id") in {"codex", "gateway", "reserve"} or "openai/codex-action@" in step.get("uses", ""):
                self.assertIn("steps.classify.outputs.route == 'codex'", step["if"])
        for key in ("review", "required"):
            for step in workflow["jobs"][key]["steps"]:
                if step.get("id") != "copy_token":
                    self.assertNotIn("NODE_OPTIONS", step.get("env", {}))


if __name__ == "__main__":
    unittest.main()
