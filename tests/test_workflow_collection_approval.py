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
           "status": "completed", "conclusion": "success"}
    decision = {"state": "approved", "user": {"login": "litroc", "id": 76040632, "type": "User"},
                "comment": collection.approval_purpose(pull, REPOSITORY) + "\nExplicit normal release authorization.",
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
    def test_native_normal_job_and_scoped_user_decision_are_both_required(self):
        with fixture() as (api, state, pull):
            result = collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)
            self.assertEqual(state["history"][10][0], result)
            self.assertEqual(10, control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))

    def test_budget_only_history_never_authorizes_even_with_successful_recovery_job(self):
        for normal_job in (False, True):
            with self.subTest(normal_job=normal_job), fixture() as (api, state, pull):
                state["history"][10][0]["comment"] = "Approve one extra review budget; no release authority."
                if not normal_job:
                    state["jobs"][10][0]["name"] = "Protected current revision"
                self.assertIsNone(collection.native_approval(api, REPOSITORY, pull, SOURCE, 10, allow_missing=True))
                self.assertIsNone(control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))
                with self.assertRaises(control.ControlError):
                    collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)

    def test_scoped_decision_without_successful_normal_job_does_not_authorize(self):
        for conclusion in ("failure", "cancelled", "skipped"):
            with self.subTest(conclusion=conclusion), fixture() as (api, state, pull):
                state["jobs"][10][0]["conclusion"] = conclusion
                with self.assertRaises(control.ControlError):
                    collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)
                self.assertIsNone(control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))

    def test_explicit_main_decision_is_distinct_from_budget_in_the_same_run(self):
        with fixture() as (api, state, pull):
            budget = copy.deepcopy(state["history"][10][0])
            budget["comment"] = "Review recovery budget only."
            state["history"][10].insert(0, budget)
            result = collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)
            self.assertEqual(state["history"][10][1], result)

    def test_skipped_verifier_attempt_reuses_only_the_unchanged_actual_normal_decision(self):
        with fixture() as (api, state, pull):
            state["runs"][10]["run_attempt"] = 2
            state["jobs"][10].append(state["jobs"][10][0] | {"id": 101, "run_attempt": 2, "conclusion": "skipped"})
            self.assertEqual(10, control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))

    def test_later_rejection_does_not_fall_back_to_an_older_approved_job_or_run(self):
        with fixture() as (api, state, pull):
            state["runs"][9] = state["runs"][10] | {"id": 9}
            state["jobs"][9] = [state["jobs"][10][0] | {"id": 90, "run_id": 9}]
            state["history"][9] = copy.deepcopy(state["history"][10])
            state["operations"][(9, 1)] = copy.deepcopy(state["operations"][(10, 1)])
            state["runs"][10]["run_attempt"] = 2
            state["jobs"][10].append(state["jobs"][10][0] | {"id": 101, "run_attempt": 2, "conclusion": "failure"})
            self.assertIsNone(control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))
            self.assertNotIn(9, state["reads"])

    def test_another_attempts_binding_or_source_cannot_supply_the_approving_job(self):
        for defect in ("binding", "source"):
            with self.subTest(defect=defect), fixture() as (api, state, pull):
                if defect == "binding":
                    state["operations"][(10, 1)]["binding"]["base"] = "d" * 40
                    self.assertIsNone(collection.native_approval(api, REPOSITORY, pull, SOURCE, 10, allow_missing=True))
                else:
                    state["operations"][(10, 1)]["source_sha"] = "d" * 40
                    with self.assertRaisesRegex(control.ControlError, "protected-operation-source-drift"):
                        collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)

    def test_scope_marker_cannot_be_quoted_or_copied_from_another_binding(self):
        for comment in ("budget", "quoted", "old-binding"):
            with self.subTest(comment=comment), fixture() as (api, state, pull):
                marker = collection.approval_purpose(pull, REPOSITORY)
                state["history"][10][0]["comment"] = ("Budget only\n" + marker if comment == "quoted" else
                    "[collection-main-approval/v1 " + "d" * 64 + "]" if comment == "old-binding" else "Budget only")
                self.assertIsNone(collection.native_approval(api, REPOSITORY, pull, SOURCE, 10, allow_missing=True))

    def test_changed_metadata_invalidates_the_old_normal_scope(self):
        for field, replacement in (("title", "Another release"), ("body", "changed"), ("labels", [{"name": "changed"}])):
            with self.subTest(field=field), fixture() as (api, state, pull):
                pull[field] = replacement
                with self.assertRaisesRegex(control.ControlError, "collection-normal-approval-binding-changed"):
                    collection.native_approval(api, REPOSITORY, pull, SOURCE, 10, allow_missing=True)
                self.assertIsNone(control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))

    def test_ambiguous_decisions_bots_and_explicit_rejection_fail_closed(self):
        for defect in ("duplicate", "bot", "rejected"):
            with self.subTest(defect=defect), fixture() as (api, state, pull):
                if defect == "duplicate":
                    state["history"][10].append(copy.deepcopy(state["history"][10][0]))
                elif defect == "bot":
                    state["history"][10][0]["user"]["type"] = "Bot"
                else:
                    state["history"][10][0]["state"] = "rejected"
                with self.assertRaises(control.ControlError):
                    collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)

    def test_unmarked_native_rejection_cannot_reuse_an_older_scoped_approval(self):
        with fixture() as (api, state, pull):
            rejected = copy.deepcopy(state["history"][10][0])
            rejected.update(state="rejected", comment="")
            state["history"][10].append(rejected)
            self.assertIsNone(control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))
            with self.assertRaisesRegex(control.ControlError, "collection-main-approval-rejected"):
                collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)

    def test_native_generation_job_mutation_and_foreign_job_fail_closed(self):
        for defect in ("generation_drift", "job_drift", "foreign-job"):
            with self.subTest(defect=defect), fixture() as (api, state, pull):
                if defect == "foreign-job":
                    state["jobs"][10][0]["run_id"] = 11
                else:
                    state[defect] = True
                with self.assertRaises(control.ControlError):
                    collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)

    def test_rerun_during_selected_job_read_is_caught_by_the_final_generation_read(self):
        with fixture() as (api, state, pull):
            state["advance_during_job_read"] = True
            with self.assertRaisesRegex(control.ControlError, "collection-approval-generation-drift"):
                collection.native_approval(api, REPOSITORY, pull, SOURCE, 10)

    def test_restoring_metadata_never_bypasses_a_newer_rejection_or_pending_decision(self):
        for outcome in ("failure", "pending", "history-only"):
            with self.subTest(outcome=outcome), fixture() as (api, state, pull):
                state["runs"][9] = state["runs"][10] | {"id": 9}
                state["jobs"][9] = [state["jobs"][10][0] | {"id": 90, "run_id": 9}]
                state["history"][9] = copy.deepcopy(state["history"][10])
                state["operations"][(9, 1)] = copy.deepcopy(state["operations"][(10, 1)])
                # Run9 approved A. Run10 saw B at the same PR/base/head, and A is restored.
                state["operations"][(10, 1)]["binding"]["title"] = "Metadata B"
                if outcome == "pending":
                    state["jobs"][10][0].update(status="waiting", conclusion=None)
                    state["history"][10] = []
                else:
                    state["jobs"][10][0]["conclusion"] = "failure" if outcome == "failure" else "skipped"
                    state["history"][10][0].update(state="rejected", comment="")
                self.assertIsNone(control.previous_approval(api, REPOSITORY, pull, SOURCE, normal_collection=True))
                self.assertNotIn(9, state["reads"])

    def test_skipped_pre_classification_attempt_needs_no_missing_operation_artifact(self):
        with fixture() as (api, state, pull):
            state["runs"][10]["run_attempt"] = 2
            state["jobs"][10][0]["conclusion"] = "skipped"
            state["jobs"][10].append(state["jobs"][10][0] | {
                "id": 101, "run_attempt": 2, "conclusion": "success"})
            state["operations"][(10, 2)] = state["operations"].pop((10, 1))
            self.assertEqual(state["history"][10][0], collection.native_approval(api, REPOSITORY, pull, SOURCE, 10))
