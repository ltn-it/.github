"""Recovery budget approval never becomes normal Collection Main authority."""
import copy
import re
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workflow_collection_release as collection
import workflow_control as control

REPOSITORY = "ltn-it/ansible-collection-foundational"
SOURCE = "c" * 40


@contextmanager
def fixture():
    repository = {"full_name": REPOSITORY, "id": collection.COLLECTIONS[REPOSITORY]}
    pull = {"number": 3, "title": "Release v1.38.0", "body": "", "labels": [], "draft": False,
            "user": dict(zip(("login", "id", "type"), collection.RELEASE)),
            "base": {"ref": "main", "sha": "a" * 40, "repo": repository.copy()},
            "head": {"ref": "release/v1.38.0", "sha": "b" * 40, "repo": repository.copy()}}
    native = {"id": 10, "run_attempt": 1, "head_sha": pull["head"]["sha"], "path": control.WORKFLOW,
              "workflow_id": 77, "workflow_url": f"https://api.github.com/repos/{REPOSITORY}/actions/required_workflows/77",
              "pull_requests": [{"number": 3, "base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}}]}
    job = {"id": 100, "run_id": 10, "run_attempt": 1, "name": collection.APPROVAL_JOB,
           "status": "completed", "conclusion": "success", "created_at": "2026-10-28T00:01:00Z"}
    decision = {"state": "approved", "user": {"login": "litroc", "id": 76040632, "type": "User"},
                "comment": collection.approval_purpose(pull, REPOSITORY, 10, 1) + "\nExplicit normal release authorization.",
                "environments": [{"name": "normal-release-promotion-approval", "id": 50}]}
    state = {"runs": {10: native}, "jobs": {10: [job]}, "history": {10: [decision]},
             "operations": {(10, 1): {"version": 1, "source_sha": SOURCE, "binding": control.binding(pull)}},
             "reads": {}, "generation_drift": False, "job_drift": False, "advance_during_job_read": False}
    api = Mock()
    def call(path):
        match = re.fullmatch(rf"repos/{re.escape(REPOSITORY)}/actions/runs/([0-9]+)(/approvals)?", path)
        if match:
            identifier = int(match[1])
            if match[2]:
                return copy.deepcopy(state["history"][identifier])
            state["reads"][identifier] = state["reads"].get(identifier, 0) + 1
            result = copy.deepcopy(state["runs"][identifier])
            if state["generation_drift"] and state["reads"][identifier] >= 2:
                result["run_attempt"] += 1
            return result
        match = re.fullmatch(rf"repos/{re.escape(REPOSITORY)}/actions/jobs/([0-9]+)", path)
        if match:
            jobs = [job for jobs in state["jobs"].values() for job in jobs if job["id"] == int(match[1])]
            result = copy.deepcopy(jobs[0])
            if state["advance_during_job_read"]:
                state["runs"][result["run_id"]]["run_attempt"] += 1
            if state["job_drift"]:
                result["conclusion"] = "failure"
            return result
        raise AssertionError(path)
    def pages(path, key):
        current = re.fullmatch(rf"repos/{re.escape(REPOSITORY)}/actions/runs/([0-9]+)/attempts/([0-9]+)/jobs", path)
        if current:
            return copy.deepcopy([job for job in state["jobs"][int(current[1])]
                                  if job["run_attempt"] == int(current[2])])
        if path == f"repos/{REPOSITORY}/actions/runs?head_sha={pull['head']['sha']}":
            return copy.deepcopy(list(state["runs"].values()))
        match = re.fullmatch(rf"repos/{re.escape(REPOSITORY)}/actions/runs/([0-9]+)/(jobs\?filter=all|artifacts)", path)
        if match:
            identifier = int(match[1])
            if match[2] == "jobs?filter=all":
                return copy.deepcopy(state["jobs"][identifier])
            return [{"name": f"control-operation-{attempt}", "expired": False}
                    for run, attempt in state["operations"] if run == identifier]
        raise AssertionError((path, key))
    def operation(api, repository, run, source=None):
        attempts = [attempt for identifier, attempt in state["operations"]
                    if identifier == run["id"] and attempt <= run["run_attempt"]]
        control.require(attempts, "protected-operation-missing")
        result = copy.deepcopy(state["operations"][(run["id"], max(attempts))])
        control.require(source is None or result["source_sha"] == source, "protected-operation-source-drift")
        return result
    api.call.side_effect, api.pages.side_effect = call, pages
    with patch.object(control, "operation_record", side_effect=operation):
        yield api, state, pull


class CollectionApprovalTests(unittest.TestCase):
    def approve(self, api, pull, attempt=1):
        return collection.native_approval(api, REPOSITORY, pull, SOURCE, 10, expected_attempt=attempt)

    def test_fresh_current_job_and_native_decision_authorize(self):
        with fixture() as (api, state, pull):
            self.assertEqual(state["history"][10][0], self.approve(api, pull))

    def test_stable_route_never_reuses_historical_approval(self):
        with fixture() as (api, state, pull):
            self.assertIsNone(control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))
            api.call.assert_not_called()
            api.pages.assert_not_called()

    def test_budget_quoted_indented_and_other_attempt_decisions_do_not_authorize(self):
        for variant in ("budget", "quoted", "spaces", "tab", "other-attempt", "other-run", "old-binding"):
            with self.subTest(variant=variant), fixture() as (api, state, pull):
                marker = collection.approval_purpose(pull, REPOSITORY, 10, 1)
                choices = {"budget": "Review recovery only.", "quoted": "Budget only\n" + marker,
                           "spaces": "    " + marker, "tab": "\t" + marker,
                           "other-attempt": collection.approval_purpose(pull, REPOSITORY, 10, 2),
                           "other-run": collection.approval_purpose(pull, REPOSITORY, 9, 1),
                           "old-binding": "[collection-main-approval/v2 " + "d" * 64 + " 10/1]"}
                state["history"][10][0]["comment"] = choices[variant]
                with self.assertRaises(control.ControlError):
                    self.approve(api, pull)

    def test_failed_skipped_missing_or_pending_current_jobs_never_reuse_old_success(self):
        for outcome in ("failure", "cancelled", "pending", "skipped", "missing"):
            with self.subTest(outcome=outcome), fixture() as (api, state, pull):
                state["runs"][10]["run_attempt"] = 2
                state["operations"][(10, 2)] = copy.deepcopy(state["operations"][(10, 1)])
                if outcome != "missing":
                    state["jobs"][10].append(state["jobs"][10][0] | {
                        "id": 101, "run_attempt": 2, "status": "waiting" if outcome == "pending" else "completed",
                        "conclusion": None if outcome == "pending" else outcome})
                with self.assertRaises(control.ControlError):
                    self.approve(api, pull, 2)

    def test_verifier_only_rerun_has_no_fresh_operation_or_normal_gate(self):
        with fixture() as (api, state, pull):
            state["runs"][10]["run_attempt"] = 2
            with self.assertRaisesRegex(control.ControlError, "collection-current-operation-required"):
                self.approve(api, pull, 2)

    def test_complete_new_attempt_requires_and_accepts_its_own_explicit_approval(self):
        with fixture() as (api, state, pull):
            state["runs"][10]["run_attempt"] = 2
            state["operations"][(10, 2)] = copy.deepcopy(state["operations"][(10, 1)])
            state["jobs"][10].append(state["jobs"][10][0] | {"id": 101, "run_attempt": 2})
            with self.assertRaises(control.ControlError):
                self.approve(api, pull, 2)
            state["history"][10][0]["state"] = "rejected"
            state["history"][10].append(state["history"][10][0] | {
                "state": "approved", "comment": collection.approval_purpose(pull, REPOSITORY, 10, 2)})
            self.assertEqual(state["history"][10][1], self.approve(api, pull, 2))

    def test_rejection_bots_and_duplicate_current_decisions_fail_closed(self):
        for defect in ("rejected", "bot", "duplicate"):
            with self.subTest(defect=defect), fixture() as (api, state, pull):
                if defect == "rejected":
                    state["history"][10][0]["state"] = "rejected"
                elif defect == "bot":
                    state["history"][10][0]["user"]["type"] = "Bot"
                else:
                    state["history"][10].append(copy.deepcopy(state["history"][10][0]))
                with self.assertRaises(control.ControlError):
                    self.approve(api, pull)

    def test_operation_binding_source_and_current_artifact_are_required(self):
        for defect in ("metadata", "source", "missing-artifact"):
            with self.subTest(defect=defect), fixture() as (api, state, pull):
                if defect == "metadata":
                    pull["title"] = "Changed after approval"
                elif defect == "source":
                    state["operations"][(10, 1)]["source_sha"] = "d" * 40
                else:
                    state["operations"].clear()
                with self.assertRaises(control.ControlError):
                    self.approve(api, pull)

    def test_foreign_duplicate_or_missing_current_jobs_fail_closed(self):
        for defect in ("foreign", "duplicate", "missing"):
            with self.subTest(defect=defect), fixture() as (api, state, pull):
                if defect == "foreign":
                    state["jobs"][10][0]["run_id"] = 11
                elif defect == "duplicate":
                    state["jobs"][10].append(state["jobs"][10][0] | {"id": 101})
                else:
                    state["jobs"][10].clear()
                with self.assertRaises(control.ControlError):
                    self.approve(api, pull)

    def test_native_generation_and_job_drift_are_rejected(self):
        for defect in ("generation_drift", "job_drift", "advance_during_job_read"):
            with self.subTest(defect=defect), fixture() as (api, state, pull):
                state[defect] = True
                with self.assertRaises(control.ControlError):
                    self.approve(api, pull)

    def test_executing_attempt_is_independent_of_the_mutable_api_generation(self):
        with fixture() as (api, state, pull):
            with self.assertRaisesRegex(control.ControlError, "collection-approval-executing-attempt-drift"):
                self.approve(api, pull, 2)
