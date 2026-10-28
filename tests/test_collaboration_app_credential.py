"""Credential-stage identity, narrowing and no-repeat tests; no live secrets."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collaboration_app_credential as credential
import collaboration_native_issuer as native
from collaboration_content import AdmissionError
from collaboration_publisher import Authorization, Facts, PrivateLedger, ROOT, ROOT_ID


class AppCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = PrivateLedger(self.temp.name)
        self.now = 1800000000
        self.identity = credential.AppIdentity(100, 200, 84)
        self.facts = Facts(ROOT, ROOT_ID, "public", 42, "a" * 40, 84, "b" * 40, "c" * 64)
        self.auth = Authorization("d" * 64, "review.create", 964, None, "pull", "e" * 64,
                                   "f" * 64, "0" * 64, self.facts)
        self.attest = Mock(return_value=self.facts)
        self.key_source = Mock(return_value=self.pem)
        self.service = credential.AppTokenPreparer(self.identity, self.key_source, self.attest,
                                                  self.ledger, clock=lambda: self.now)
        expires = datetime.fromtimestamp(self.now + 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.values = {"/app": {"id": 100, "slug": "offline-publisher"},
            "/app/installations/200": {"id": 200, "app_id": 100, "suspended_at": None,
                "account": {"id": 54334171, "login": "ltn-it", "type": "Organization"},
                "permissions": {"pull_requests": "write", "contents": "write"}},
            "/users/offline-publisher%5Bbot%5D": {"id": 84, "login": "offline-publisher[bot]", "type": "Bot"},
            "/app/installations/200/access_tokens": {"token": "ghs_100_" + "a" * 600 + ".signature-with_dashes",
                "expires_at": expires, "permissions": {"pull_requests": "write", "metadata": "read"}},
            "/installation/repositories?per_page=100&page=1": {"total_count": 1,
                "repositories": [{"id": ROOT_ID, "full_name": ROOT, "private": False}]}}
        self.connections, self.requests = [], []
        self.factory = patch.object(credential.http.client, "HTTPSConnection", side_effect=self.connect)
        self.factory.start()
        self.addCleanup(self.factory.stop)

    def connect(self, host, **kwargs):
        self.assertEqual("api.github.com", host)
        self.assertTrue(kwargs["context"].check_hostname)
        connection = Mock()
        self.connections.append(connection)
        def response():
            args, call = connection.request.call_args
            method, path = args
            self.requests.append((method, path, call))
            return Mock(status=201 if method == "POST" else 200,
                        read=Mock(return_value=json.dumps(self.values[path]).encode()))
        connection.getresponse.side_effect = response
        return connection

    def test_actual_jwt_identity_and_narrowed_scope_are_checked_before_use(self):
        prepared = self.service.prepare(self.auth)
        self.assertEqual(5, len(self.requests))
        jwt = self.requests[0][2]["headers"]["Authorization"].removeprefix("Bearer ")
        header, claims, signature = jwt.split(".")
        self.key.public_key().verify(native.decode64(signature), (header + "." + claims).encode(),
                                     padding.PKCS1v15(), hashes.SHA256())
        self.assertEqual({"iss": "100", "iat": self.now - 30, "exp": self.now + 300},
                         json.loads(native.decode64(claims)))
        mint = self.requests[3]
        self.assertEqual(("POST", "/app/installations/200/access_tokens"), mint[:2])
        self.assertEqual({"repository_ids": [ROOT_ID], "permissions": {"pull_requests": "write"}},
                         json.loads(mint[2]["body"]))
        self.assertEqual(84, prepared.receipt()["publisher_actor_id"])
        self.assertNotIn("token", prepared.receipt())
        self.assertNotIn("ghs_", repr(prepared))
        count = len(self.requests)
        self.assertTrue(prepared.credential().startswith("ghs_"))
        self.assertEqual(count, len(self.requests))
        self.assertEqual(2, self.attest.call_count)

    def test_native_rejection_precedes_key_read_and_every_mint(self):
        self.attest.side_effect = AdmissionError("private native detail")
        with self.assertRaises(AdmissionError) as caught:
            self.service.prepare(self.auth)
        self.assertEqual("publisher-credential-not-prepared", str(caught.exception))
        self.key_source.assert_not_called()
        self.assertFalse(self.requests)

    def test_actor_drift_is_not_inferred_from_app_slug_or_broker_claim(self):
        self.values["/users/offline-publisher%5Bbot%5D"]["id"] = 999
        with self.assertRaises(AdmissionError):
            self.service.prepare(self.auth)
        self.assertFalse(any(method == "POST" for method, _, _ in self.requests))

    def test_extra_token_permissions_or_foreign_repository_are_rejected(self):
        self.values["/app/installations/200/access_tokens"]["permissions"]["contents"] = "read"
        with self.assertRaises(AdmissionError):
            self.service.prepare(self.auth)

    def test_foreign_scope_response_is_not_used_even_after_successful_mint(self):
        self.values["/installation/repositories?per_page=100&page=1"]["total_count"] = 2
        with self.assertRaises(AdmissionError):
            self.service.prepare(self.auth)

    def test_unknown_post_outcome_consumes_preparation_without_mint_retry(self):
        real_connect = self.connect
        def unknown(host, **kwargs):
            connection = real_connect(host, **kwargs)
            real_response = connection.getresponse.side_effect
            def response():
                if connection.request.call_args.args[0] == "POST":
                    self.requests.append(("POST", "/app/installations/200/access_tokens", {}))
                    raise TimeoutError("private remote diagnostics")
                return real_response()
            connection.getresponse.side_effect = response
            return connection
        with patch.object(credential.http.client, "HTTPSConnection", side_effect=unknown):
            for _ in range(2):
                with self.assertRaises(AdmissionError):
                    self.service.prepare(self.auth)
        self.assertEqual(1, sum(method == "POST" for method, _, _ in self.requests))
        self.key_source.assert_called_once_with()

    def test_new_generation_before_mint_blocks_without_minting(self):
        self.attest.side_effect = [self.facts, AdmissionError("generation changed")]
        with self.assertRaises(AdmissionError):
            self.service.prepare(self.auth)
        self.assertFalse(any(method == "POST" for method, _, _ in self.requests))

    def test_prepared_expired_token_is_never_refreshed_by_getter(self):
        prepared = self.service.prepare(self.auth)
        self.now += 3600
        with self.assertRaises(AdmissionError):
            prepared.credential()
        self.assertEqual(1, sum(method == "POST" for method, _, _ in self.requests))

    def test_identity_stage_does_not_support_arbitrary_routes_or_broad_tokens(self):
        for method, path, payload in (("DELETE", "/installation/token", None),
                ("POST", "/app/installations/200/access_tokens", {"permissions": {"pull_requests": "write"}}),
                ("POST", "/graphql", {}), ("GET", "/repos/other/repository", None)):
            with self.subTest(path=path), self.assertRaises(AdmissionError):
                credential.github(method, path, "offline_bearer_only_for_tests", payload)
        self.assertFalse(self.connections)

    def test_unknown_installation_suspension_is_not_a_verified_active_state(self):
        del self.values["/app/installations/200"]["suspended_at"]
        with self.assertRaises(AdmissionError):
            self.service.prepare(self.auth)
        self.assertFalse(any(method == "POST" for method, _, _ in self.requests))


if __name__ == "__main__":
    unittest.main()
