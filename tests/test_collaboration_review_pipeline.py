"""Actual adapter -> durable publisher chain; no provider or network traffic."""
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import collaboration_content as content
import collaboration_publisher as publisher
import collaboration_review_result as adapter
import exact_revision_gateway as gateway


class ReviewPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger = publisher.PrivateLedger(self.temporary.name)
        self.now = datetime(2026, 10, 25, 20, 0, tzinfo=timezone.utc)
        self.policy = content.policy_from(ROOT / ".lit/collaboration-content-policy.json")
        self.inventory = {"version": 1, "organization": "ltn-it", "complete": True,
                          "started_at": "2026-10-25T19:59:00Z", "finished_at": "2026-10-25T19:59:10Z",
                          "repositories": [{"id": publisher.ROOT_ID, "full_name": publisher.ROOT,
                                            "visibility": "public", "archived": False}]}
        self.subject = {"repository": publisher.ROOT, "repository_id": publisher.ROOT_ID,
                        "pull_request": 964, "head_sha": "b" * 40, "source_sha": "a" * 40}
        self.metadata = {key: "d" * (64 if key.endswith("sha256") else 40) for key in gateway.BINDINGS}
        self.metadata.update(repository=publisher.ROOT, pull_request=964,
                             head_sha=self.subject["head_sha"], central_source_sha=self.subject["source_sha"])
        self.result = {key: self.metadata[key] for key in gateway.BINDINGS}
        self.result.update(verdict="FAIL", summary="One finding.", findings=[{
            "severity": "high", "path": "scripts/example.py", "line": 2,
            "title": "Reject missing state", "body": "Unknown values must block."}])
        self.facts = publisher.Facts(publisher.ROOT, publisher.ROOT_ID, "public",
                                    42, "a" * 40, 84, "b" * 40, "c" * 64)
        self.calls = []
        self.reads = 0

    def prepare(self):
        return adapter.admitted_review_bytes(self.result, self.metadata, self.subject,
                                             {"scripts/example.py": [2]}, self.inventory, self.policy,
                                             now=self.now)

    def authorization(self, wire):
        return publisher.Authorization("e" * 64, "review.create", 964, None, "pull",
                                       publisher.digest(wire), publisher.digest(publisher.json_bytes(self.policy)),
                                       publisher.digest(publisher.json_bytes(self.inventory)), self.facts)

    def attest(self, auth):
        self.reads += 1
        return self.facts

    def sender(self, method, url, wire):
        self.calls.append((method, url, wire))
        return publisher.TransportResult(201, 123)

    def service(self, attest=None):
        return publisher.Publisher(admitted_bindings={(42, 84): "a" * 40},
                                   attest=attest or self.attest, ledger=self.ledger,
                                   serialize=self.ledger.serialize,
                                   transport=publisher.BoundedTransport(self.sender, publisher_actor_id=84),
                                   clock=lambda: self.now)

    def test_final_model_finding_bytes_reach_only_fixed_review_endpoint_once(self):
        wire = self.prepare()
        self.assertEqual(wire, publisher.json_bytes(json.loads(wire)))
        auth = self.authorization(wire)
        receipt = self.service().publish(auth, wire, self.inventory, self.policy)
        self.assertEqual("response-observed", receipt["disposition"])
        self.assertEqual([("POST", "https://api.github.com/repos/ltn-it/.github/pulls/964/reviews", wire)],
                         self.calls)
        self.assertEqual(2, self.reads)
        self.assertIn("Unknown values must block.", json.loads(wire)["body"])
        with self.assertRaises(content.AdmissionError):
            self.service().publish(auth, wire, self.inventory, self.policy)
        self.assertEqual(1, len(self.calls))

    def test_changed_provider_bytes_after_preparation_never_reach_transport(self):
        wire = self.prepare()
        auth = self.authorization(wire)
        payload = json.loads(wire)
        payload["comments"][0]["body"] = "PRIVATE-123"
        changed = publisher.json_bytes(payload)
        with self.assertRaises(content.AdmissionError) as caught:
            self.service().publish(auth, changed, self.inventory, self.policy)
        self.assertNotIn("PRIVATE-123", str(caught.exception))
        self.assertEqual([], self.calls)
        self.assertEqual(0, self.reads)

    def test_new_native_generation_at_final_read_burns_claim_without_publication(self):
        wire = self.prepare()
        auth = self.authorization(wire)
        def drift(current):
            self.reads += 1
            return self.facts if self.reads == 1 else replace(self.facts, generation="f" * 64)
        with self.assertRaises(content.AdmissionError):
            self.service(drift).publish(auth, wire, self.inventory, self.policy)
        self.assertEqual([], self.calls)
        self.assertEqual(2, self.reads)
        # An apparently restored snapshot cannot restore the consumed operation.
        with self.assertRaises(content.AdmissionError):
            self.service().publish(auth, wire, self.inventory, self.policy)
        self.assertEqual([], self.calls)


if __name__ == "__main__":
    unittest.main()
