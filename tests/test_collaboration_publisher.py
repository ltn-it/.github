"""Real final-wire boundary with a recorded, entirely offline transport."""
import copy
import json
import sys
import threading
import tempfile
import unittest
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collaboration_publisher as pub
from collaboration_content import AdmissionError


class Ledger:
    def __init__(self):
        self.claimed = {}

    def claim(self, key, fingerprint):
        if key in self.claimed:
            return False
        self.claimed[key] = fingerprint
        return True


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
        self.policy = json.loads((Path(__file__).resolve().parents[1]
                                  / ".lit/collaboration-content-policy.json").read_text())
        self.inventory = {"version": 1, "organization": "ltn-it", "complete": True,
                          "started_at": "2026-10-25T11:59:59Z", "finished_at": "2026-10-25T12:00:00Z",
                          "repositories": [{"id": pub.ROOT_ID, "full_name": pub.ROOT,
                                            "visibility": "public", "archived": False}]}
        self.facts = pub.Facts(pub.ROOT, pub.ROOT_ID, "public", 42, "a" * 40, 84, "b" * 40, "c" * 64)
        self.calls, self.attestations = [], []
        self.ledger = Ledger()
        self.lock = threading.Lock()
        self.publisher = pub.Publisher(admitted_bindings={(42, 84): "a" * 40, (43, 84): "f" * 40}, attest=self.attest,
                                       ledger=self.ledger, serialize=lambda: self.lock,
                                       transport=pub.BoundedTransport(self.send, publisher_actor_id=84), clock=lambda: self.now)

    def attest(self, auth):
        self.attestations.append(auth)
        return auth.facts

    def send(self, method, url, wire):
        self.assertTrue(self.lock.locked())
        self.assertEqual(2, len(self.attestations))
        self.calls.append((method, url, wire))
        return pub.TransportResult(201, 123)

    def subject(self, op):
        payloads = {
            "issue.create": {"title": "Public issue", "body": "Safe body"},
            "issue.edit": {"title": "Changed", "body": ""},
            "pull.create": {"title": "Public change", "body": "Safe body", "head": "feature/a",
                            "base": "develop", "draft": True},
            "pull.edit": {"body": "Changed"},
            "comment.create": {"body": "Safe comment"},
            "comment.edit": {"body": "Edited comment"},
            "inline.create": {"body": "Finding", "path": "scripts/example.py", "line": 2,
                              "side": "RIGHT", "commit_id": "b" * 40},
            "inline.reply": {"body": "Reply"},
            "inline.edit": {"body": "Edited finding"},
            "review.create": {"body": "Review", "commit_id": "b" * 40, "event": "COMMENT",
                              "comments": [{"body": "Inline finding", "path": "src/a.py", "line": 5,
                                            "side": "RIGHT", "start_line": 3, "start_side": "RIGHT"}]},
            "review.edit": {"body": "Edited review"},
        }
        method, suffix, _, edit, needs_object = pub.ROUTES[op]
        facts = replace(self.facts, owner_id=84, object_revision="d" * 64,
                        object_origin_producer_id=42, object_origin_source="a" * 40, object_origin_receipt="e" * 64) if edit else self.facts
        payload = payloads[op]
        wire = pub.json_bytes(payload)
        auth = pub.Authorization(pub.digest(op.encode()), op,
                                 None if op in {"issue.create", "pull.create"} else 7,
                                 11 if needs_object else None,
                                 "issue" if op.startswith(("issue.", "comment.")) else "pull",
                                 pub.digest(wire), pub.digest(pub.json_bytes(self.policy)),
                                 pub.digest(pub.json_bytes(self.inventory)), facts)
        return auth, wire

    def publish(self, auth, wire):
        return self.publisher.publish(auth, wire, self.inventory, self.policy)

    def assert_blocked(self, auth, wire):
        with self.assertRaises(AdmissionError) as error:
            self.publish(auth, wire)
        self.assertIn(str(error.exception), {"publisher-rejected", "publisher-unavailable"})
        self.assertEqual([], self.calls)

    def test_every_create_and_edit_route_sends_the_exact_validated_bytes_once(self):
        for op, (method, suffix, _, _, _) in pub.ROUTES.items():
            with self.subTest(op=op):
                self.setUp()
                auth, wire = self.subject(op)
                receipt = self.publish(auth, wire)
                self.assertEqual("response-observed", receipt["disposition"])
                self.assertEqual([(method, "https://api.github.com/repos/ltn-it/.github/"
                                   + suffix.format(number=7, object_id=11), wire)], self.calls)
                self.assertIs(wire, self.calls[0][2])
                with self.assertRaises(AdmissionError):
                    self.publish(auth, wire)
                self.assertEqual(1, len(self.calls))

    def test_pull_conversation_comments_have_the_same_bounded_issue_endpoint(self):
        auth, wire = self.subject("comment.create")
        self.publish(replace(auth, parent_kind="pull"), wire)
        self.assertTrue(self.calls[0][1].endswith("/issues/7/comments"))

    def test_rejects_private_content_on_every_surface_without_leaking_values(self):
        for op in pub.ROUTES:
            with self.subTest(op=op):
                self.setUp()
                auth, wire = self.subject(op)
                payload = json.loads(wire)
                payload["body"] = "Never publish https://secret.atlassian.net/hidden SAFE-7788"
                wire = pub.json_bytes(payload)
                self.assert_blocked(replace(auth, payload_sha256=pub.digest(wire)), wire)
                self.assertEqual({}, self.ledger.claimed)

    def test_private_titles_are_rejected_for_create_and_edit(self):
        for op in ("issue.create", "issue.edit", "pull.create", "pull.edit"):
            self.setUp()
            auth, wire = self.subject(op)
            payload = json.loads(wire)
            payload["title"] = "SAFE-7788"
            wire = pub.json_bytes(payload)
            self.assert_blocked(replace(auth, payload_sha256=pub.digest(wire)), wire)

    def test_native_generation_is_checked_after_final_content_validation(self):
        auth, wire = self.subject("review.create")
        original = pub.guarded_payload
        validated = []
        def validate(*args, **kwargs):
            validated.append(True)
            return original(*args, **kwargs)
        def attest(value):
            self.attestations.append(value)
            self.assertEqual(len(validated), len(self.attestations))
            return value.facts
        self.publisher.attest = attest
        with patch.object(pub, "guarded_payload", validate):
            self.publish(auth, wire)
        self.assertEqual(2, len(validated))

    def test_nested_inline_text_and_non_body_fields_are_validated(self):
        for field in ("body", "path"):
            self.setUp()
            auth, wire = self.subject("review.create")
            payload = json.loads(wire)
            payload["comments"][0][field] = "SAFE-7788"
            wire = pub.json_bytes(payload)
            self.assert_blocked(replace(auth, payload_sha256=pub.digest(wire)), wire)
        self.setUp()
        auth, wire = self.subject("pull.create")
        payload = json.loads(wire)
        payload["head"] = "SAFE-7788"
        wire = pub.json_bytes(payload)
        self.assert_blocked(replace(auth, payload_sha256=pub.digest(wire)), wire)

    def test_unknown_fields_on_every_route_cannot_create_an_alternate_write(self):
        for op in pub.ROUTES:
            self.setUp()
            auth, wire = self.subject(op)
            value = json.loads(wire)
            value["state"] = "closed"
            wire = pub.json_bytes(value)
            self.assert_blocked(replace(auth, payload_sha256=pub.digest(wire)), wire)

    def test_nested_unknown_fields_and_approval_or_pending_reviews_are_rejected(self):
        for event in ["APPROVE", "REQUEST_CHANGES", "PENDING", None]:
            self.setUp()
            auth, wire = self.subject("review.create")
            value = json.loads(wire)
            value["event"] = event
            wire = pub.json_bytes(value)
            self.assert_blocked(replace(auth, payload_sha256=pub.digest(wire)), wire)
        self.setUp()
        auth, wire = self.subject("review.create")
        value = json.loads(wire)
        value["comments"][0]["comments"] = [{"body": "hidden"}]
        wire = pub.json_bytes(value)
        self.assert_blocked(replace(auth, payload_sha256=pub.digest(wire)), wire)

    def test_foreign_repository_id_visibility_or_producer_and_source_are_denied(self):
        for field, value in [("repository", "ltn-it/other"), ("repository_id", pub.ROOT_ID + 1),
                             ("repository_id", True), ("visibility", "private"), ("origin_producer_id", 44),
                             ("origin_source", "f" * 40), ("head_sha", "no-head"),
                             ("generation", None), ("publisher_actor_id", 42)]:
            self.setUp()
            auth, wire = self.subject("issue.create")
            self.assert_blocked(replace(auth, facts=replace(auth.facts, **{field: value})), wire)

    def test_one_broker_can_publish_for_two_independently_admitted_origins(self):
        for origin, source in [(42, "a" * 40), (43, "f" * 40)]:
            self.setUp()
            auth, wire = self.subject("issue.create")
            auth = replace(auth, facts=replace(auth.facts, origin_producer_id=origin, origin_source=source))
            self.assertEqual("response-observed", self.publish(auth, wire)["disposition"])
            self.assertEqual(84, auth.facts.publisher_actor_id)

    def test_broker_edit_requires_original_origin_provenance_not_just_broker_owner(self):
        for op in ("issue.edit", "pull.edit", "comment.edit", "inline.edit", "review.edit"):
            for changes in ({"object_origin_producer_id": 43}, {"object_origin_source": "f" * 40},
                            {"object_origin_receipt": None}, {"object_origin_producer_id": None},
                            {"owner_id": 42}):
                self.setUp()
                auth, wire = self.subject(op)
                self.assert_blocked(replace(auth, facts=replace(auth.facts, **changes)), wire)
            self.setUp()
            auth, wire = self.subject(op)
            # Same admitted broker, different independently admitted origin: the
            # unchanged object's real provenance must still stop this edit.
            auth = replace(auth, facts=replace(auth.facts, origin_producer_id=43, origin_source="f" * 40))
            self.assert_blocked(auth, wire)

    def test_second_origin_can_edit_its_own_broker_published_object(self):
        auth, wire = self.subject("review.edit")
        auth = replace(auth, facts=replace(auth.facts, origin_producer_id=43, origin_source="f" * 40,
                       object_origin_producer_id=43, object_origin_source="f" * 40))
        self.assertEqual("response-observed", self.publish(auth, wire)["disposition"])

    def test_transport_rejects_actor_confusion_even_for_another_admitted_pair(self):
        self.publisher.bindings[(42, 85)] = "a" * 40
        auth, wire = self.subject("issue.create")
        auth = replace(auth, facts=replace(auth.facts, publisher_actor_id=85))
        self.assert_blocked(auth, wire)
        self.assertEqual({}, self.ledger.claimed)

    def test_wrong_edit_owner_or_missing_existing_object_revision_is_rejected(self):
        for op in ("issue.edit", "pull.edit", "comment.edit", "inline.edit", "review.edit"):
            for changes in ({"owner_id": 99}, {"owner_id": None}, {"object_revision": None}):
                self.setUp()
                auth, wire = self.subject(op)
                self.assert_blocked(replace(auth, facts=replace(auth.facts, **changes)), wire)

    def test_incomplete_stale_or_changed_inventory_and_policy_are_denied(self):
        for mutate in (lambda i: i.update(complete=False),
                       lambda i: i.update(started_at="2026-10-24T00:00:00Z"),
                       lambda i: i["repositories"][0].update(visibility="private"),
                       lambda i: i["repositories"][0].update(archived=True),
                       lambda i: i["repositories"][0].update(id=99)):
            self.setUp()
            auth, wire = self.subject("issue.create")
            mutate(self.inventory)
            # Even a correctly bound candidate digest cannot turn bad facts good.
            auth = replace(auth, inventory_sha256=pub.digest(pub.json_bytes(self.inventory)))
            self.assert_blocked(auth, wire)
        self.setUp()
        auth, wire = self.subject("issue.create")
        self.policy["max_text_bytes"] -= 1
        self.assert_blocked(auth, wire)

    def test_every_locator_and_parent_is_bound_before_attestation_or_effect(self):
        auth, wire = self.subject("review.edit")
        for changes in ({"number": True}, {"object_id": -1}, {"parent_kind": "issue"},
                        {"number": None}, {"object_id": "11"}):
            self.assert_blocked(replace(auth, **changes), wire)
        self.assertEqual([], self.attestations)

    def test_stale_generation_before_or_after_reservation_never_writes(self):
        for changed_at in [1, 2]:
            self.setUp()
            auth, wire = self.subject("review.create")
            reads = []
            def attest(value):
                reads.append(value)
                return replace(value.facts, generation="f" * 64) if len(reads) == changed_at else value.facts
            self.publisher.attest = attest
            self.assert_blocked(auth, wire)
            self.assertEqual(changed_at == 2, auth.operation_id in self.ledger.claimed)

    def test_concurrent_edit_or_head_change_during_read_is_rejected(self):
        for changes in ({"object_revision": "f" * 64}, {"owner_id": 9}, {"head_sha": "f" * 40}):
            self.setUp()
            auth, wire = self.subject("review.edit")
            self.publisher.attest = lambda value: replace(value.facts, **changes)
            self.assert_blocked(auth, wire)

    def test_noncanonical_duplicate_keys_malformed_or_changed_final_bytes_do_not_write(self):
        auth, wire = self.subject("issue.create")
        for malformed in (b'{"title":"A","title":"B","body":"ok"}', b'{"title":NaN}',
                          b'\xff', b'{}', b'[]', wire + b' '):
            with self.subTest(wire_hash=pub.digest(malformed)):
                self.assert_blocked(replace(auth, payload_sha256=pub.digest(malformed)), malformed)
        self.assert_blocked(auth, wire + b' ')
        self.assert_blocked(auth, wire.replace(b'Safe', b'Changed'))

    def test_transport_itself_denies_bytes_changed_after_validation(self):
        auth, wire = self.subject("issue.create")
        with self.assertRaises(AdmissionError):
            self.publisher.transport.send_once(auth, wire + b' ')
        self.assertEqual([], self.calls)

    def test_transport_has_no_arbitrary_route_delete_graphql_ready_or_merge(self):
        auth, wire = self.subject("issue.create")
        for operation in ["DELETE", "graphql", "pull.merge", "pull.ready", "review.approve",
                          "issue.close", "https://evil.invalid", "../issues"]:
            self.assert_blocked(replace(auth, operation=operation), wire)

    def test_all_transport_failures_are_consumed_and_never_retried(self):
        for result in [TimeoutError("PRIVATE-9911"), pub.TransportResult(500, None),
                       pub.TransportResult(302, 123), pub.TransportResult(201, True),
                       {"status": 201, "object_id": 123}, None]:
            self.setUp()
            auth, wire = self.subject("issue.create")
            def send(*args):
                self.calls.append(args)
                if isinstance(result, Exception):
                    raise result
                return result
            self.publisher.transport = pub.BoundedTransport(send, publisher_actor_id=84)
            receipt = self.publish(auth, wire)
            self.assertEqual("unknown-readback-required", receipt["disposition"])
            self.assertNotIn("PRIVATE", str(receipt))
            self.assert_blocked_after_effect(auth, wire)

    def assert_blocked_after_effect(self, auth, wire):
        with self.assertRaises(AdmissionError):
            self.publish(auth, wire)
        self.assertEqual(1, len(self.calls))

    def test_unknown_result_only_reconstructs_by_reads_without_another_send(self):
        auth, wire = self.subject("issue.create")
        self.publisher.transport = pub.BoundedTransport(lambda *args: None, publisher_actor_id=84)
        self.publish(auth, wire)
        seen = []
        def observe(value):
            seen.append(value)
            return {"operation_id": value.operation_id, "payload_sha256": value.payload_sha256,
                    "complete": True, "matches": [123]}
        self.assertEqual("effect-reconstructed", self.publisher.reconcile(auth, observe)["disposition"])
        self.assertEqual([auth], seen)
        for matches in [[], [123, 124], [True]]:
            self.assertEqual({"disposition": "unknown-readback-required"}, self.publisher.reconcile(
                auth, lambda value: {"operation_id": value.operation_id, "payload_sha256": value.payload_sha256,
                                     "complete": True, "matches": matches}))
        with self.assertRaises(AdmissionError):
            self.publish(auth, wire)

    def test_untrusted_callback_exceptions_never_disclose_rejected_input(self):
        auth, wire = self.subject("issue.create")
        for exception in [RuntimeError("PRIVATE-9911"), AdmissionError("PRIVATE-9911")]:
            self.publisher.attest = lambda value: (_ for _ in ()).throw(exception)
            with self.assertRaises(AdmissionError) as error:
                self.publish(auth, wire)
            self.assertNotIn("PRIVATE", str(error.exception))

    def test_inventory_expiry_during_second_attestation_burns_slot_and_cannot_retry(self):
        from datetime import timedelta
        auth, wire = self.subject("issue.create")
        current = [self.now]
        self.publisher.clock = lambda: current[0]
        def attest(value):
            self.attestations.append(value)
            if len(self.attestations) == 2:
                current[0] = self.now + timedelta(seconds=self.policy["inventory_max_age_seconds"])
            return value.facts
        self.publisher.attest = attest
        self.assert_blocked(auth, wire)
        self.assertEqual(2, len(self.attestations))
        self.assertIn(auth.operation_id, self.ledger.claimed)
        current[0] = self.now
        self.assert_blocked(auth, wire)

    def test_inventory_exact_deadline_after_second_attestation_preserves_one_effect(self):
        from datetime import timedelta
        auth, wire = self.subject("issue.create")
        current = [self.now]
        self.publisher.clock = lambda: current[0]
        def attest(value):
            self.attestations.append(value)
            if len(self.attestations) == 2:
                current[0] = self.now + timedelta(seconds=self.policy["inventory_max_age_seconds"] - 1)
            return value.facts
        self.publisher.attest = attest
        self.assertEqual("response-observed", self.publish(auth, wire)["disposition"])
        self.assertEqual(1, len(self.calls))
        self.assert_blocked_after_effect(auth, wire)

    def test_inventory_expiring_during_evidence_reads_burns_slot_without_send(self):
        auth, wire = self.subject("issue.create")
        times = iter([self.now, datetime(2026, 10, 25, 13, tzinfo=timezone.utc)])
        self.publisher.clock = lambda: next(times)
        self.assert_blocked(auth, wire)
        self.assertIn(auth.operation_id, self.ledger.claimed)

    def test_policy_or_inventory_changed_during_evidence_reads_never_writes(self):
        for field in ("policy", "inventory"):
            self.setUp()
            auth, wire = self.subject("issue.create")
            def attest(value):
                if field == "policy":
                    self.policy["approved_public_urls"].append("https://example.org/public")
                else:
                    self.inventory["complete"] = False
                return value.facts
            self.publisher.attest = attest
            self.assert_blocked(auth, wire)

    def test_durable_reservation_survives_restart_and_unknown_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            first = pub.PrivateLedger(directory)
            auth, wire = self.subject("issue.create")
            self.publisher.ledger, self.publisher.serialize = first, first.serialize
            self.publisher.transport = pub.BoundedTransport(lambda *args: None, publisher_actor_id=84)
            self.assertEqual("unknown-readback-required", self.publish(auth, wire)["disposition"])
            second = pub.PrivateLedger(directory)
            self.publisher.ledger, self.publisher.serialize = second, second.serialize
            with self.assertRaises(AdmissionError):
                self.publish(auth, wire)
            self.assertFalse(second.claim(auth.operation_id, "f" * 64))

    def test_two_publishers_share_one_durable_target_serialization(self):
        with tempfile.TemporaryDirectory() as directory:
            auth, wire = self.subject("issue.create")
            calls = []
            barrier = threading.Barrier(2)
            def attempt(_):
                ledger = pub.PrivateLedger(directory)
                publisher = pub.Publisher(admitted_bindings={(42, 84): "a" * 40, (43, 84): "f" * 40}, attest=lambda a: a.facts,
                    ledger=ledger, serialize=ledger.serialize, clock=lambda: self.now,
                    transport=pub.BoundedTransport(lambda *args: calls.append(args) or pub.TransportResult(201, 123), publisher_actor_id=84))
                barrier.wait(timeout=10)
                try:
                    return publisher.publish(auth, wire, self.inventory, self.policy)["disposition"]
                except AdmissionError:
                    return "consumed"
            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(attempt, range(2)))
            self.assertCountEqual(["response-observed", "consumed"], results)
            self.assertEqual(1, len(calls))

    def test_private_ledger_refuses_public_directory_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            with self.assertRaises(AdmissionError):
                pub.PrivateLedger(parent)
            parent.chmod(0o700)
            target = parent / "other"
            target.write_text("")
            (parent / "publisher.sqlite3").symlink_to(target)
            with self.assertRaises(OSError):
                pub.PrivateLedger(parent)

    def test_credentials_and_raw_payload_never_enter_validator_interface(self):
        auth, wire = self.subject("review.create")
        import collaboration_content
        original = collaboration_content.validate
        seen = []
        def validate(publication, inventory, policy, **kwargs):
            seen.append(copy.deepcopy(publication))
            self.assertEqual({"kind", "repository", "title", "body"}, set(publication))
            return original(publication, inventory, policy, **kwargs)
        with patch.object(collaboration_content, "validate", validate):
            self.publish(auth, wire)
        self.assertTrue(any(row["body"] == "Inline finding" for row in seen))


if __name__ == "__main__":
    unittest.main()
