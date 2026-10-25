"""Real RSA verification and actual native readers against offline API edges."""
import base64
import copy
import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collaboration_native_issuer as issuer
import workflow_control as control
from collaboration_content import AdmissionError, policy_from
from collaboration_publisher import digest, json_bytes
import collaboration_publisher as publisher
import tempfile


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


class NativeIssuerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.key.public_key().public_numbers()
        cls.jwks = {"keys": [{"kid": "offline-key", "alg": "RS256", "use": "sig", "kty": "RSA",
                             "n": encoded(numbers.n.to_bytes(256, "big")),
                             "e": encoded(numbers.e.to_bytes(3, "big"))}]}

    def setUp(self):
        self.source = "a" * 40
        self.head = "b" * 40
        self.base = "c" * 40
        self.now = 1800000000
        self.wire = json_bytes({"body": "Public result.", "event": "COMMENT", "commit_id": self.head})
        self.registry = {"version": 1, "repository_id": issuer.ROOT_ID, "principal_kind": "github-actions-job",
                         "origin_producer_id": 42, "publisher_actor_id": 84,
                         "subject": "repo:ltn-it@54334171/.github@1112629689:pull_request",
                         "workflow_ref": f"{issuer.ROOT}/{control.WORKFLOW}@refs/heads/main",
                         "operation": "review.create", "job": "Protected current revision"}
        self.rule = {"id": issuer.RULE, "enforcement": "active", "target": "branch",
                     "conditions": {"repository_id": {"repository_ids": [issuer.ROOT_ID]},
                                    "ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                     "rules": [{"type": "workflows", "parameters": {"workflows": [
                         {"path": control.WORKFLOW, "repository_id": issuer.ROOT_ID,
                          "ref": "refs/heads/main", "sha": self.source}]}}]}
        self.repo = {"id": issuer.ROOT_ID, "full_name": issuer.ROOT, "visibility": "public", "private": False,
                     "owner": {"login": "ltn-it", "id": control.ORGANIZATION_ID},
                     "archived": False, "disabled": False}
        self.pull = {"number": 964, "state": "open", "draft": False,
                     "base": {"sha": self.base, "ref": "develop", "repo": self.repo},
                     "head": {"sha": self.head, "ref": "feature", "repo": self.repo},
                     "title": "Public title", "body": "Public body", "labels": [],
                     "user": {"login": "author", "id": 15, "type": "User"}}
        self.run = {"id": 200, "run_attempt": 1, "head_sha": self.head,
                    "workflow_id": 500, "workflow_url": f"https://api.github.com/repos/{issuer.ROOT}/actions/required_workflows/500",
                    "path": control.WORKFLOW, "status": "in_progress", "conclusion": None,
                    "repository": self.repo, "pull_requests": [self.pull]}
        self.job = {"id": 300, "run_id": 200, "run_attempt": 1, "head_sha": self.head,
                    "check_run_url": f"https://api.github.com/repos/{issuer.ROOT}/check-runs/300",
                    "name": self.registry["job"], "status": "in_progress", "conclusion": None,
                    "steps": [{"name": "Request current Copilot review", "status": "completed", "conclusion": "skipped"},
                              {"name": "Reserve protected Codex request", "status": "completed", "conclusion": "success"}]}
        self.job["steps"].extend({"name": name, "status": "completed", "conclusion": "success"} for name in
                                ("Protected exact-revision Codex review", "Collect and verify the protected model receipt"))
        self.operation = {"version": 1, "source_sha": self.source, "binding": control.binding(self.pull)}
        self.calls, self.files = [], []
        self.run_lists = 0
        self.new_generation_on_final_list = False
        self.registration_changed = False
        self.api = SimpleNamespace(call=self.call, pages=self.pages, file=self.file)
        self.policy = policy_from(Path(__file__).resolve().parents[1] / ".lit/collaboration-content-policy.json")
        stamp = datetime.fromtimestamp(self.now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.inventory = {"version": 1, "organization": "ltn-it", "complete": True,
                          "started_at": stamp, "finished_at": stamp,
                          "repositories": [{k: self.repo[k] for k in ("id", "full_name", "visibility", "archived")}]}
        self.service = issuer.NativeReviewIssuer(self.api, "not-yet-signed", 964, self.wire, self.policy, self.inventory,
                                                 clock=lambda: self.now, keys=lambda: self.jwks)
        self.claims = {"iss": issuer.ISSUER, "aud": self.service.audience, "sub": self.registry["subject"],
                       "iat": self.now - 20, "nbf": self.now - 20, "exp": self.now + 280, "jti": "offline-jti",
                       "repository": issuer.ROOT, "repository_id": str(issuer.ROOT_ID),
                       "repository_owner": "ltn-it", "repository_owner_id": str(control.ORGANIZATION_ID),
                       "repository_visibility": "public", "event_name": "pull_request",
                       "workflow_ref": self.registry["workflow_ref"], "workflow_sha": self.source,
                       "run_id": "200", "run_attempt": "1", "check_run_id": "300"}
        self.service.token = self.sign(self.claims)
        self.download = patch.object(control.subprocess, "run", side_effect=self.native_download)
        self.download.start()
        self.addCleanup(self.download.stop)

    def sign(self, claims, header=None):
        header = header or {"alg": "RS256", "typ": "JWT", "kid": "offline-key"}
        unsigned = encoded(json_bytes(header)) + "." + encoded(json_bytes(claims))
        signature = self.key.sign(unsigned.encode(), padding.PKCS1v15(), hashes.SHA256())
        return unsigned + "." + encoded(signature)

    def call(self, path):
        self.calls.append(path)
        if path == "orgs/ltn-it":
            return {"id": control.ORGANIZATION_ID, "login": "ltn-it", "public_repos": 1, "owned_private_repos": 0}
        if path == "orgs/ltn-it/memberships/litroc":
            return {"state": "active", "role": "admin", "organization": {"login": "ltn-it"}}
        if path.startswith("orgs/ltn-it/repos?type=all"):
            return [copy.deepcopy(self.repo)] if path.endswith("page=1") else []
        if path == f"orgs/ltn-it/rulesets/{issuer.RULE}":
            result = copy.deepcopy(self.rule)
            if self.registration_changed and self.calls.count(path) > 1:
                result["enforcement"] = "disabled"
            return result
        if path == f"repos/{issuer.ROOT}":
            return copy.deepcopy(self.repo)
        if path == f"repos/{issuer.ROOT}/pulls/964":
            return copy.deepcopy(self.pull)
        if path == f"repos/{issuer.ROOT}/actions/runs/200":
            return copy.deepcopy(self.run)
        raise AssertionError("unexpected read")

    def file(self, repo, path, revision):
        self.files.append((repo, path, revision))
        self.assertEqual((issuer.ROOT, self.source), (repo, revision))
        if path == issuer.POLICY:
            return json_bytes(self.policy)
        self.assertEqual(issuer.REGISTRY, path)
        return json_bytes(self.registry)

    def pages(self, path, key):
        self.calls.append(path)
        if path.endswith(f"actions/runs?head_sha={self.head}"):
            self.run_lists += 1
            current = copy.deepcopy(self.run)
            if self.new_generation_on_final_list and self.run_lists >= 3:
                current["id"] = 201
            return [current]
        if path.endswith("actions/runs/200/attempts/1/jobs"):
            return [copy.deepcopy(self.job)]
        if path.endswith("actions/runs/200/artifacts"):
            return [{"id": 400, "name": "control-operation-1", "expired": False}]
        raise AssertionError("unexpected paginated read")

    def native_download(self, command, **kwargs):
        self.assertEqual(["gh", "run", "download", "200", "--repo", issuer.ROOT,
                          "--name", "control-operation-1", "--dir"], command[:-1])
        (Path(command[-1]) / "control-operation.json").write_bytes(json_bytes(self.operation))
        return SimpleNamespace(returncode=0)

    def rejected(self):
        with self.assertRaises(AdmissionError) as caught:
            self.service.issue()
        self.assertEqual("issuer-not-admitted-or-stale", str(caught.exception))

    def test_actual_rsa_and_native_artifact_budget_bind_exact_authorization(self):
        auth = self.service.issue()
        self.assertEqual(("review.create", 964, self.head, self.source, 42, 84),
                         (auth.operation, auth.number, auth.facts.head_sha, auth.facts.origin_source,
                          auth.facts.origin_producer_id, auth.facts.publisher_actor_id))
        self.assertEqual(digest(self.wire), auth.payload_sha256)
        self.assertEqual(f"repos/{issuer.ROOT}/actions/runs?head_sha={self.head}", self.calls[-1])
        self.assertEqual(auth.facts, self.service.attest(auth))

    def test_real_signature_is_required_not_merely_decoded_claims(self):
        for header in ({"alg": "none", "typ": "JWT", "kid": "offline-key"},
                       {"alg": "RS256", "typ": "JWT", "kid": "offline-key", "jku": "https://other.example"},
                       {"alg": "RS256", "typ": "JWT", "kid": "unknown"}):
            self.service.token = self.sign(self.claims, header)
            self.rejected()
        self.service.token = self.sign(self.claims)[:-10] + "a" * 10
        self.rejected()

    def test_wrong_claims_and_expired_token_never_read_native_evidence(self):
        for key, value in (("aud", "other"), ("sub", "other"), ("repository_id", "2"),
                           ("repository_owner_id", "3"), ("workflow_sha", "d" * 40),
                           ("workflow_ref", "candidate@branch"), ("check_run_id", True),
                           ("repository_visibility", "private"), ("exp", self.now),
                           ("nbf", self.now + 1), ("iat", True), ("event_name", "workflow_dispatch")):
            with self.subTest(key=key):
                self.calls.clear()
                self.service.token = self.sign(dict(self.claims, **{key: value}))
                self.rejected()
                self.assertEqual([f"orgs/ltn-it/rulesets/{issuer.RULE}"], self.calls)

    def test_unknown_or_candidate_registration_never_falls_back_to_head(self):
        self.api.file = lambda *args: (_ for _ in ()).throw(FileNotFoundError("private location"))
        self.rejected()
        self.assertEqual([f"orgs/ltn-it/rulesets/{issuer.RULE}"], self.calls)

    def test_consumed_budget_is_required_and_missing_state_does_not_mean_success(self):
        for status, conclusion in (("queued", None), ("completed", "failure"), ("completed", "skipped")):
            with self.subTest(status=status, conclusion=conclusion):
                self.job["steps"][1].update(status=status, conclusion=conclusion)
                self.rejected()
        self.job["steps"][1].update(status="completed", conclusion="success")
        del self.job["conclusion"]
        self.rejected()

    def test_new_generation_during_proof_reads_blocks_at_final_actual_common_reader(self):
        self.new_generation_on_final_list = True
        self.rejected()
        self.assertEqual(3, self.run_lists)
        self.assertEqual(f"repos/{issuer.ROOT}/actions/runs?head_sha={self.head}", self.calls[-1])

    def test_registration_change_during_artifact_reads_blocks_before_final_generation(self):
        self.registration_changed = True
        self.rejected()

    def test_operation_artifact_must_bind_current_subject_and_real_source(self):
        self.operation["binding"]["head"] = "e" * 40
        self.rejected()

    def test_new_jti_or_changed_bytes_cannot_allocate_another_operation_id(self):
        first = self.service.issue()
        self.claims["jti"] = "another-token"
        self.service.token = self.sign(self.claims)
        self.assertEqual(first.operation_id, self.service.issue().operation_id)
        other = issuer.NativeReviewIssuer(self.api, "pending", 964, b'{"body":"Changed"}', self.policy, self.inventory,
                                          clock=lambda: self.now, keys=lambda: self.jwks)
        claims = dict(self.claims, aud=other.audience)
        other.token = self.sign(claims)
        second = other.issue()
        self.assertEqual(first.operation_id, second.operation_id)
        self.assertNotEqual(first.payload_sha256, second.payload_sha256)

    def test_forged_facts_and_later_head_changes_fail_attestation(self):
        auth = self.service.issue()
        with self.assertRaises(AdmissionError):
            self.service.attest(replace(auth, facts=replace(auth.facts, publisher_actor_id=999)))
        self.pull["head"]["sha"] = "f" * 40
        with self.assertRaises(AdmissionError):
            self.service.attest(auth)

    def test_actual_issuer_attests_the_real_private_ledger_publication_chain(self):
        auth = self.service.issue()
        sent = []
        with tempfile.TemporaryDirectory() as directory:
            ledger = publisher.PrivateLedger(directory)
            service = publisher.Publisher(admitted_bindings={(42, 84): self.source}, attest=self.service.attest,
                ledger=ledger, serialize=ledger.serialize,
                transport=publisher.BoundedTransport(lambda method, url, wire: (
                    sent.append((method, url, wire)) or publisher.TransportResult(201, 123)), publisher_actor_id=84),
                clock=lambda: datetime.fromtimestamp(self.now, timezone.utc))
            result = service.publish(auth, self.wire, self.inventory, self.policy)
            self.assertEqual("response-observed", result["disposition"])
            self.assertEqual(1, len(sent))
            self.assertEqual(self.wire, sent[0][2])
            with self.assertRaises(AdmissionError):
                service.publish(auth, self.wire, self.inventory, self.policy)
            self.assertEqual(1, len(sent))

    def test_unknown_repository_state_and_partial_inventory_are_rejected(self):
        for key in ("disabled", "archived"):
            with self.subTest(key=key):
                original = self.repo.pop(key)
                self.rejected()
                self.repo[key] = original
        self.service.inventory["repositories"] = []
        self.rejected()

    def test_changed_source_policy_or_native_attempt_is_not_accepted(self):
        old = self.policy["version"]
        self.policy["version"] = 2
        self.rejected()
        self.policy["version"] = old
        self.run["run_attempt"] = True
        self.rejected()

    def test_expiry_during_actual_artifact_read_is_checked_after_final_generation(self):
        real_download = self.native_download
        def elapsed(*args, **kwargs):
            result = real_download(*args, **kwargs)
            self.now += 300
            return result
        with patch.object(control.subprocess, "run", side_effect=elapsed):
            self.rejected()
        self.assertEqual(3, self.run_lists)

    def test_token_cannot_be_reused_after_a_native_attempt_change(self):
        self.run["run_attempt"] = 2
        self.rejected()

    def test_budget_from_an_earlier_funded_generation_blocks_new_allocation(self):
        original_pages = self.api.pages
        def prior(path, key):
            if path.endswith(f"actions/runs?head_sha={self.head}"):
                current = original_pages(path, key)
                old = copy.deepcopy(self.run)
                old["id"] = 199
                return current + [old]
            if path.endswith("actions/runs/199/attempts/1/jobs"):
                job = copy.deepcopy(self.job)
                job["run_id"] = 199
                return [job]
            return original_pages(path, key)
        self.api.pages = prior
        self.rejected()

    def test_a_reservation_without_actual_verified_model_capture_is_not_a_proof(self):
        self.job["steps"][-1]["conclusion"] = "skipped"
        self.rejected()

    def test_real_jwks_fetch_is_bounded_and_does_not_follow_redirects(self):
        from unittest.mock import Mock
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = json_bytes(self.jwks)
        with patch.object(issuer.http.client, "HTTPSConnection", return_value=connection) as factory:
            self.assertEqual(self.jwks, issuer.signing_keys())
            self.assertEqual(("token.actions.githubusercontent.com",), factory.call_args.args)
            self.assertTrue(factory.call_args.kwargs["context"].check_hostname)
            connection.request.assert_called_once_with("GET", "/.well-known/jwks", headers={"Accept": "application/json"})
            response.read.assert_called_once_with(262145)
            connection.reset_mock()
            response.status = 302
            with self.assertRaises(AdmissionError):
                issuer.signing_keys()
            connection.request.assert_called_once()
            response.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
