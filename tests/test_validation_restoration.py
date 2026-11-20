"""A failed integration is accountable only after two ordinary reviewed inverses."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import release_package_ingress as archive
import workflow_control as control
import workflow_validation_restoration as rule


class RestorationTests(unittest.TestCase):
    def setUp(self):
        self.repo = {"id": rule.REPOSITORY_ID, "full_name": rule.REPOSITORY}
        self.merges = [rule.ORIGINAL, "a" * 40, "b" * 40]
        self.bases = [rule.PREVIOUS, *self.merges[:2]]
        self.heads = [rule.FEATURE, rule.INVERSE_HEAD, "c" * 40]
        self.pulls, self.rows, self.records, self.api_data = [], [], {}, {}
        self.trees, self.parents = {rule.PREVIOUS: "1" * 40}, {}
        for i, (merge, base, head) in enumerate(zip(self.merges, self.bases, self.heads)):
            number = 477 + i
            pull = {"id": 5408425625 + i, "number": number, "state": "closed", "merged": True,
                    "draft": False, "merged_at": "2026-11-20T07:01:00Z", "merge_commit_sha": merge,
                    "base": {"ref": "develop", "sha": base, "repo": self.repo},
                    "head": {"sha": head, "repo": self.repo}}
            self.pulls.append(pull)
            self.api_data[f"pulls/{number}"] = pull
            self.parents[merge] = (base, head)
            self.trees[merge] = self.trees[head] = ("1" if i == 1 else "2") * 40
            run, job = (rule.FAILED_RUN, rule.FAILED_JOB) if i == 0 else (100 + i, 200 + i)
            conclusion = "success" if i else "failure"
            native = {"id": run, "run_attempt": 1, "status": "completed", "conclusion": conclusion,
                      "head_sha": head, "repository": self.repo, "workflow_id": 388059047, "event": "pull_request",
                      "workflow_url": f"https://api.github.com/repos/{rule.REPOSITORY}/actions/required_workflows/388059047",
                      "path": control.WORKFLOW}
            self.api_data[f"actions/runs/{run}"] = self.api_data[f"actions/runs/{run}/attempts/1"] = native
            self.api_data[f"actions/jobs/{job}"] = {
                "id": job, "run_id": run, "run_attempt": 1, "head_sha": head, "name": "Current revision review",
                "status": "completed", "conclusion": conclusion,
                "completed_at": "2026-11-20T07:00:00Z" if i else "2026-11-20T07:01:05Z",
                "steps": [{"name": "Persist exact native acceptance proof", "conclusion": conclusion}]}
            if not i:
                self.api_data[f"actions/jobs/{job}"]["steps"] = [
                    {"name": rule.FINAL_STEP, "conclusion": "failure"},
                    {"name": "Persist exact native acceptance proof", "conclusion": "skipped"}]
            if i:
                record = {"version": 1, "source_sha": "3" * 40, "route": "copilot",
                          "binding": {"number": number, "base_ref": "develop", "head": head}}
                self.records[run] = record
                self.rows.append({"pull": number, "merge": merge,
                                  "control": {"run": run, "job": job, "attempt": 1, "route": "copilot",
                                              "artifact": "control-proof-1", "source_sha": record["source_sha"],
                                              "head": head, "proof_sha256": control.digest(record)}})
        self.api = Mock()
        self.api.call.side_effect = lambda path: self.api_data[path.removeprefix(f"repos/{rule.REPOSITORY}/")]
        self.promotion = {"base": {"ref": "main", "sha": rule.MAIN},
                          "head": {"ref": "develop", "sha": self.merges[-1], "repo": self.repo},
                          "user": dict(zip(("login", "id", "type"), control.RELEASE))}
        self.start = patch.object(rule, "git", side_effect=self.lookup)
        self.start.start()
        self.addCleanup(self.start.stop)

    def lookup(self, _, command, *args):
        if command == "rev-parse":
            return self.trees[args[0].removesuffix("^{tree}")]
        if command == "show":
            return " ".join(self.parents[args[-1]])
        if command == "merge-base":
            return args[-2]
        raise AssertionError(command)

    def verify(self):
        return rule.verify(self.api, self.promotion, None, self.merges, self.pulls[0], self.rows)

    def test_only_original_in_exact_repository_and_main_release(self):
        self.assertTrue(rule.applies(rule.REPOSITORY, self.promotion, rule.ORIGINAL))
        self.assertFalse(rule.applies("other/repo", self.promotion, rule.ORIGINAL))
        self.assertFalse(rule.applies(rule.REPOSITORY, self.promotion, self.merges[1]))
        self.assertFalse(rule.applies(rule.REPOSITORY, {"base": {"sha": self.heads[0]}}, rule.ORIGINAL))

    def test_archive_preserves_failure_and_two_separate_successes(self):
        incident = self.verify()
        self.assertEqual(("failure", 477, rule.FAILED_RUN), (incident["conclusion"], incident["pull"], incident["run"]))
        promotion = {"version": 1, "source_sha": "3" * 40, "route": "promotion",
                     "binding": {"number": 480, "head_repository": rule.REPOSITORY, "base_ref": "main", "head_ref": "develop",
                                 "base": rule.MAIN, "head": self.merges[-1]},
                     "evidence": {"base": rule.MAIN, "head": self.merges[-1], "integration_tree": "2"*40,
                                  "ingress": self.rows, "validation_477_restoration": incident}}
        self.api.pages.side_effect = lambda path, *unused: [
            self.api_data[f"actions/jobs/{201 if '/101/' in path else 202}"]]
        with tempfile.TemporaryDirectory() as tmp, patch.object(archive, "artifact_record",
                side_effect=lambda api, repo, run, *unused: self.records[run["id"]]):
            output = Path(tmp) / "archive.json"
            archive.assemble(self.api, rule.REPOSITORY, promotion, control.digest(promotion), output)
            saved = json.loads(output.read_bytes())
        self.assertEqual(saved["promotion"], promotion)
        self.assertEqual([r["reference"] for r in saved["ingress"]], self.rows)

    def test_real_promotion_loop_checks_both_later_integrations(self):
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.enterContext(patch.dict(os.environ, clean_env, clear=True))
        native = []
        def check(api, repo, pull, config):
            native.append(pull["number"])
            return self.rows[pull["number"] - 478]["control"]

        def graph(objects, command, *args, **kwargs):
            if command == "merge-base":
                return rule.MAIN
            if command == "rev-list":
                return "\n".join(self.merges)
            if command == "merge-tree":
                return self.trees[self.merges[-1]]
            if command == "diff":
                return b"reviewed patch"
            raise AssertionError(command)

        self.api.pages.side_effect = lambda url: [self.pulls[self.merges.index(url.split("/")[-2])]]
        with patch("workflow_subject.fetch_objects"), patch("workflow_subject.git", side_effect=graph), \
                patch("workflow_devtools_bootstrap.promotion_context", return_value=None), \
                patch.object(control, "check_native_control", side_effect=check):
            result = control.promotion_ingress(self.api, rule.REPOSITORY, self.promotion, {})
        self.assertEqual(native, [478, 479])
        self.assertEqual(result["ingress"], self.rows)
        self.assertEqual(result["validation_477_restoration"]["conclusion"], "failure")

    def test_drift_in_either_tree_or_merge_parents(self):
        for commit in (*self.merges, *self.heads):
            with self.subTest(commit=commit), patch.dict(self.trees, {commit: "d" * 40}):
                with self.assertRaises(control.ControlError):
                    self.verify()
        with patch.dict(self.parents, {self.merges[2]: (rule.ORIGINAL, self.heads[2])}):
            with self.assertRaises(control.ControlError):
                self.verify()

    def test_other_ingress_before_and_after_preserved_in_order(self):
        before = {"pull": 471, "merge": "4" * 40, "control": {"route": "copilot"}}
        after = {"pull": 481, "merge": "5" * 40, "control": {"route": "ancestry"}}
        commits = [before["merge"], *self.merges, after["merge"]]
        refs = [before, *self.rows, after]
        with patch.object(self, "merges", commits), patch.object(self, "rows", refs):
            self.assertEqual(self.verify()["reapplication"]["pull"], 479)
        for missing in (refs[1:], refs[:-1], [after, *self.rows, before]):
            with patch.object(self, "merges", commits), patch.object(self, "rows", missing):
                with self.assertRaises(control.ControlError):
                    self.verify()

    def test_missing_extra_or_out_of_order_proofs(self):
        for rows in [self.rows[:1], self.rows[::-1], self.rows + self.rows[:1]]:
            with patch.object(self, "rows", rows), self.assertRaises(control.ControlError):
                self.verify()
        with patch.object(self, "merges", self.merges[:2]), patch.object(self, "rows", self.rows[:1]):
            with self.assertRaises(control.ControlError):
                self.verify()

    def test_both_fresh_reviews_must_finish_before_merge(self):
        for row in self.rows:
            job = self.api_data[f"actions/jobs/{row['control']['job']}"]
            for change in ({"completed_at": self.pulls[1]["merged_at"]}, {"conclusion": "failure"},
                           {"steps": []}, {"head_sha": rule.FEATURE}):
                with patch.dict(job, change), self.assertRaises(control.ControlError):
                    self.verify()
            with patch.dict(row["control"], route="ancestry"), self.assertRaises(control.ControlError):
                self.verify()
        with patch.dict(self.rows[1]["control"], run=self.rows[0]["control"]["run"]):
            with self.assertRaises(control.ControlError):
                self.verify()

    def test_original_failure_and_identity_are_preserved(self):
        for obj, update in [(self.api_data[f"actions/runs/{rule.FAILED_RUN}"], {"run_attempt": 2}),
                            (self.api_data[f"actions/jobs/{rule.FAILED_JOB}"], {"conclusion": "success"}),
                            (self.pulls[0], {"id": 1}), (self.pulls[1], {"draft": True}),
                            (self.pulls[2]["head"], {"repo": {"id": 123, "full_name": "other/repo"}})]:
            with patch.dict(obj, update), self.assertRaises(control.ControlError):
                self.verify()
