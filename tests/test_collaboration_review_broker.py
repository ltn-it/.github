"""Whole broker chain with real native readers and recorded network edges."""
import copy
import http.client
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import test_collaboration_native_issuer as native_fixtures
import collaboration_review_broker as broker
from collaboration_app_credential import AppIdentity
from collaboration_native_issuer import NativeReviewIssuer
from collaboration_publisher import ROOT, ROOT_ID, json_bytes


class ReviewBrokerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native_fixtures.NativeIssuerTests.setUpClass()

    def setUp(self):
        self.native = native_fixtures.NativeIssuerTests()
        self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        self.native.pull.update(id=900, url=f"https://api.github.com/repos/{ROOT}/pulls/964")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.key_source = Mock(return_value=self.native.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.network = []
        self.readbacks = 0
        self.timeout_publication = False
        self.drift_after_mint = False
        self.drift_readback = False
        expires = datetime.fromtimestamp(self.native.now + 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.values = {"/app": {"id": 100, "slug": "offline-publisher"},
            "/app/installations/200": {"id": 200, "app_id": 100, "suspended_at": None,
                "account": {"id": 54334171, "login": "ltn-it", "type": "Organization"},
                "permissions": {"pull_requests": "write"}},
            "/users/offline-publisher%5Bbot%5D": {"id": 84, "login": "offline-publisher[bot]", "type": "Bot"},
            "/app/installations/200/access_tokens": {"token": "ghs_100_" + "a" * 600 + ".offline-signature",
                "expires_at": expires, "permissions": {"pull_requests": "write"}},
            "/installation/repositories?per_page=100&page=1": {"total_count": 1,
                "repositories": [{"id": ROOT_ID, "full_name": ROOT, "private": False}]},
            f"/repos/{ROOT}/pulls/964/reviews": {"id": 123}}
        self.review = {"id": 123, "pull_request_url": f"https://api.github.com/repos/{ROOT}/pulls/964",
                       "commit_id": self.native.head, "state": "COMMENTED", "user": {"id": 84},
                       "body": "Public result."}
        original = self.native.api.call
        def reader(path):
            if path == f"repos/{ROOT}/pulls/964/reviews/123":
                self.native.calls.append(path)
                self.readbacks += 1
                value = copy.deepcopy(self.review)
                if self.drift_readback and self.readbacks > 1:
                    value["body"] = "Different public result."
                return value
            if path.startswith(f"repos/{ROOT}/pulls/964/reviews/123/comments?"):
                self.native.calls.append(path)
                return []
            return original(path)
        self.native.api.call = reader
        self.factory = patch.object(http.client, "HTTPSConnection", side_effect=self.connection)
        self.factory.start()
        self.addCleanup(self.factory.stop)
        self.service = broker.ReviewBroker(self.native.api, self.temporary.name, AppIdentity(100, 200, 84),
            self.key_source, clock=lambda: self.native.now, oidc_keys=lambda: self.native.jwks)

    def connection(self, host, **kwargs):
        self.assertEqual("api.github.com", host)
        connection = Mock()
        def response():
            method, path = connection.request.call_args.args
            self.network.append((method, path, connection.request.call_args.kwargs.get('body')))
            self.native.calls.append("http:" + method + ":" + path)
            if path == f"/repos/{ROOT}/pulls/964/reviews" and self.timeout_publication:
                raise TimeoutError("private server detail")
            if path.startswith("/installation/repositories") and self.drift_after_mint:
                self.native.run_lists = 0
                self.native.new_generation_on_final_list = True
            return Mock(status=201 if method == "POST" else 200,
                        read=Mock(return_value=json_bytes(self.values[path])))
        connection.getresponse.side_effect = response
        return connection

    def execute(self, wire=None):
        return self.service.execute(self.native.service.token, 964, wire or self.native.wire,
                                    self.native.policy, self.native.inventory)

    def publication_count(self):
        return sum(path == f"/repos/{ROOT}/pulls/964/reviews" for _, path, _ in self.network)

    def test_oidc_custody_mint_final_native_guard_https_and_exact_readback_complete_once(self):
        result = self.execute()
        self.assertEqual('exact-known-effect-read-back', result['disposition'])
        self.assertEqual(1, self.publication_count())
        self.assertEqual(2, self.readbacks)
        self.assertEqual(f"repos/{ROOT}/actions/runs?head_sha={self.native.head}", self.native.calls[-1])
        self.assertEqual(self.native.wire, self.network[-1][2])
        self.assertEqual('blocked-before-publication', self.execute()['disposition'])
        self.assertEqual(1, self.publication_count())
        self.assertEqual(1, sum(method == 'POST' and path.endswith('/access_tokens') for method, path, _ in self.network))

    def test_unknown_http_response_never_searches_for_equal_text_or_retries(self):
        self.timeout_publication = True
        first = self.execute()
        self.assertEqual('unknown-readback-required', first['disposition'])
        self.assertNotIn('private server detail', str(first))
        self.assertEqual(0, self.readbacks)
        self.execute()
        self.assertEqual(1, self.publication_count())

    def test_changed_generation_after_mint_blocks_collaboration_effect(self):
        self.drift_after_mint = True
        self.assertEqual('blocked-before-publication', self.execute()['disposition'])
        self.assertEqual(0, self.publication_count())

    def test_private_final_body_rejected_before_key_access_or_custody(self):
        wire = json_bytes({"body": "PRIVATE-123", "event": "COMMENT", "commit_id": self.native.head})
        audience = NativeReviewIssuer(self.native.api, 'pending', 964, wire, self.native.policy,
                                      self.native.inventory).audience
        self.native.service.token = self.native.sign(dict(self.native.claims, aud=audience))
        self.assertEqual('blocked-before-publication', self.execute(wire)['disposition'])
        self.key_source.assert_not_called()
        self.assertFalse(self.network)
        self.assertFalse(list((Path(self.temporary.name)/'requests').iterdir()))

    def test_object_drift_after_successful_response_is_unknown_and_never_resent(self):
        self.drift_readback = True
        self.assertEqual('unknown-readback-required', self.execute()['disposition'])
        self.assertEqual(1, self.publication_count())
        self.execute()
        self.assertEqual(1, self.publication_count())

    def test_private_disk_receipts_do_not_contain_oidc_or_app_tokens_or_keys(self):
        self.execute()
        oidc = self.native.service.token.encode()
        app_token = self.values['/app/installations/200/access_tokens']['token'].encode()
        for path in Path(self.temporary.name).rglob('*'):
            if path.is_file():
                raw = path.read_bytes()
                self.assertNotIn(oidc, raw)
                self.assertNotIn(app_token, raw)
                self.assertNotIn(b'BEGIN PRIVATE KEY', raw)

    def test_failed_original_response_custody_stays_unknown_after_one_effect(self):
        with patch.object(self.service.responses, 'record', side_effect=OSError('private disk detail')):
            result = self.execute()
        self.assertEqual('unknown-readback-required', result['disposition'])
        self.assertEqual(1, self.publication_count())
        self.assertEqual(0, self.readbacks)
        self.execute()
        self.assertEqual(1, self.publication_count())


if __name__ == '__main__':
    unittest.main()
