"""Exercise actual result binding and credential-free final-byte preparation."""
import copy
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import collaboration_content as content
import collaboration_review_result as adapter
import exact_revision_gateway as gateway

NOW = datetime(2026, 10, 25, 20, 0, tzinfo=timezone.utc)


class ReviewResultAdapterTests(unittest.TestCase):
    def setUp(self):
        self.subject = {"repository": "ltn-it/.github", "repository_id": 1112629689,
                        "pull_request": 964, "head_sha": "a" * 40, "source_sha": "b" * 40}
        self.metadata = {key: "c" * (64 if key.endswith("sha256") else 40) for key in gateway.BINDINGS}
        self.metadata.update(repository=self.subject["repository"], pull_request=964,
                             head_sha=self.subject["head_sha"], central_source_sha=self.subject["source_sha"])
        self.result = {key: self.metadata[key] for key in gateway.BINDINGS}
        self.result.update(verdict="PASS", summary="No findings.", findings=[])
        self.inventory = {"version": 1, "organization": "ltn-it", "complete": True,
                          "started_at": "2026-10-25T19:59:00Z", "finished_at": "2026-10-25T19:59:10Z",
                          "repositories": [{"id": 1112629689, "full_name": "ltn-it/.github",
                                            "visibility": "public", "archived": False}]}
        self.policy = content.policy_from(ROOT / ".lit/collaboration-content-policy.json")
        self.lines = {"scripts/example.py": [2, 3]}
        self.sent = []

    def publish(self):
        wire = adapter.admitted_review_bytes(self.result, self.metadata, self.subject, self.lines,
                                             self.inventory, self.policy, now=NOW)
        self.sent.append(wire)
        return wire

    def finding(self, line=2):
        self.result.update(verdict="FAIL", findings=[{"severity": "high", "path": "scripts/example.py",
                           "line": line, "title": "Check missing state", "body": "Reject an unknown value."}])

    def rejected(self):
        with self.assertRaises(content.AdmissionError) as caught:
            self.publish()
        self.assertEqual([], self.sent)
        return str(caught.exception)

    def test_pass_sends_one_comment_not_an_approval(self):
        self.publish()
        self.assertEqual(1, len(self.sent))
        payload = json.loads(self.sent[0])
        self.assertEqual("COMMENT", payload["event"])
        self.assertEqual(self.subject["head_sha"], payload["commit_id"])
        self.assertNotIn("comments", payload)
        self.assertIn("Verdict: PASS", payload["body"])

    def test_fail_keeps_every_finding_and_valid_inline_position(self):
        self.finding()
        self.publish()
        payload = json.loads(self.sent[0])
        self.assertIn("Verdict: FAIL", payload["body"])
        self.assertIn("Reject an unknown value.", payload["body"])
        self.assertEqual(2, payload["comments"][0]["line"])
        self.assertEqual("RIGHT", payload["comments"][0]["side"])

    def test_noncommentable_or_null_line_stays_in_body_without_invented_inline(self):
        for line in (None, 99):
            with self.subTest(line=line):
                self.sent.clear()
                self.finding(line)
                self.publish()
                payload = json.loads(self.sent[0])
                self.assertNotIn("comments", payload)
                self.assertIn("Check missing state", payload["body"])

    def test_each_exact_revision_binding_mismatch_blocks_before_send(self):
        for key in gateway.BINDINGS:
            old = self.result[key]
            self.result[key] = "d" * len(old)
            with self.subTest(key=key):
                self.rejected()
            self.result[key] = old

    def test_wrong_repository_pr_source_or_id_blocks(self):
        for key, value in (("repository", "ltn-it/elsewhere"), ("pull_request", 965),
                           ("source_sha", "e" * 40), ("repository_id", 99)):
            old = self.subject[key]
            self.subject[key] = value
            with self.subTest(key=key):
                self.rejected()
            self.subject[key] = old

    def test_private_text_in_summary_or_each_finding_field_is_never_sent_or_echoed(self):
        for field in ("summary", "title", "body", "path"):
            with self.subTest(field=field):
                self.finding()
                self.result["summary"] = "No other findings."
                if field == "summary":
                    self.result[field] = "PRIVATE-123"
                else:
                    self.result["findings"][0][field] = "PRIVATE-123"
                    if field == "path":
                        self.lines["PRIVATE-123"] = [2]
                self.assertNotIn("PRIVATE-123", self.rejected())

    def test_unknown_provider_fields_and_false_pass_with_findings_fail_closed(self):
        self.result["extra"] = "PRIVATE-123"
        self.assertNotIn("PRIVATE-123", self.rejected())
        del self.result["extra"]
        self.finding()
        self.result["verdict"] = "PASS"
        self.rejected()

    def test_unknown_path_traversal_and_boolean_line_fail_closed(self):
        self.finding()
        for value in ("other.py", "../private.py", "/absolute.py"):
            self.result["findings"][0]["path"] = value
            self.rejected()
        self.result["findings"][0]["path"] = "scripts/example.py"
        self.result["findings"][0]["line"] = True
        self.rejected()

    def test_expired_incomplete_private_or_archived_inventory_blocks(self):
        for mutation in ("stale", "incomplete", "private", "archived"):
            old = copy.deepcopy(self.inventory)
            if mutation == "stale":
                self.inventory["started_at"] = "2026-10-24T19:59:00Z"
            elif mutation == "incomplete":
                self.inventory["complete"] = False
            elif mutation == "private":
                self.inventory["repositories"][0]["visibility"] = "private"
            else:
                self.inventory["repositories"][0]["archived"] = True
            with self.subTest(mutation=mutation):
                self.rejected()
            self.inventory = old

    def test_findings_limit_does_not_partially_publish(self):
        self.finding()
        self.result["findings"] *= 101
        self.rejected()

    def test_proposal_bytes_are_frozen_against_later_result_mutation(self):
        wire = self.publish()
        self.result["summary"] = "PRIVATE-123"
        self.assertNotIn("PRIVATE-123", wire.decode())
        self.assertEqual(self.sent[0], wire)

    def test_unrepresentable_text_fails_without_echo(self):
        self.result["summary"] = "\ud800PRIVATE-123"
        self.assertNotIn("PRIVATE-123", self.rejected())


if __name__ == "__main__":
    unittest.main()
