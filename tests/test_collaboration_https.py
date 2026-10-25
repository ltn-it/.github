"""Exercise the actual HTTPS adapter with a replaced socket boundary only."""
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collaboration_https as https
from collaboration_content import AdmissionError
from collaboration_publisher import ROOT, ROOT_ID, Authorization, BoundedTransport, Facts, digest


class HTTPSOnceTests(unittest.TestCase):
    def setUp(self):
        self.credential = Mock(return_value="github_test_credential_for_offline_use_only")
        self.sender = https.HTTPSOnceSender(self.credential)
        self.connection = Mock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 201
        self.response.read.return_value = b'{"id":123}'
        self.factory = patch.object(https.http.client, "HTTPSConnection", return_value=self.connection)
        self.factory_mock = self.factory.start()
        self.addCleanup(self.factory.stop)
        self.wire = b'{"body":"A public result.","commit_id":"' + b"b" * 40 + b'","event":"COMMENT"}'
        facts = Facts(ROOT, ROOT_ID, "public", 42, "a" * 40, 84, "b" * 40, "c" * 64)
        self.auth = Authorization("d" * 64, "review.create", 964, None, "pull", digest(self.wire),
                                  "e" * 64, "f" * 64, facts)

    def send(self):
        return BoundedTransport(self.sender, publisher_actor_id=84).send_once(self.auth, self.wire)

    def test_real_transport_preserves_exact_bytes_and_verified_fixed_tls(self):
        result = self.send()
        self.assertEqual((201, 123), (result.status, result.object_id))
        self.factory_mock.assert_called_once()
        args, kwargs = self.factory_mock.call_args
        self.assertEqual(("api.github.com",), args)
        self.assertEqual(15, kwargs["timeout"])
        self.assertEqual(ssl.CERT_REQUIRED, kwargs["context"].verify_mode)
        self.assertTrue(kwargs["context"].check_hostname)
        args, kwargs = self.connection.request.call_args
        self.assertEqual(("POST", "/repos/ltn-it/.github/pulls/964/reviews"), args)
        self.assertIs(self.wire, kwargs["body"])
        self.assertEqual(str(len(self.wire)), kwargs["headers"]["Content-Length"])
        self.credential.assert_called_once_with()
        self.response.read.assert_called_once_with(https.MAX_RESPONSE + 1)
        self.connection.close.assert_called_once_with()

    def test_every_fixed_route_is_supported_without_caller_headers(self):
        from collaboration_publisher import ROUTES
        for method, suffix, _, _, _ in ROUTES.values():
            with self.subTest(suffix=suffix):
                url = https.PREFIX + suffix.format(number=964, object_id=123)
                result = self.sender(method, url, b'{}')
                self.assertEqual(123, result.object_id)

    def test_alternate_host_destructive_methods_and_url_tricks_fail_before_credentials(self):
        attempts = [("DELETE", https.PREFIX + "issues/1"), ("POST", "https://other.example/issues"),
                    ("POST", "https://api.github.com@other.example/repos/ltn-it/.github/issues"),
                    ("POST", https.PREFIX + "issues?redirect=1"), ("POST", https.PREFIX + "../issues"),
                    ("POST", https.PREFIX + "issues#fragment"), ("POST", https.PREFIX + "graphql"),
                    ("PATCH", https.PREFIX + "issues/0"), ("POST", https.PREFIX + "issues/01/comments"),
                    ("PUT", https.PREFIX + "pulls/964/merge")]
        for method, url in attempts:
            with self.subTest(url=url), self.assertRaises(AdmissionError):
                self.sender(method, url, self.wire)
        self.credential.assert_not_called()
        self.factory_mock.assert_not_called()

    def test_invalid_and_oversized_bytes_do_not_load_a_credential(self):
        for wire in ("text", bytearray(b"{}"), b"", b"x" * (https.MAX_REQUEST + 1)):
            with self.assertRaises(AdmissionError):
                self.sender("POST", https.PREFIX + "issues", wire)
        self.credential.assert_not_called()

    def test_redirect_and_error_responses_never_follow_or_repeat(self):
        for status in (301, 302, 307, 308, 401, 403, 429, 500, True):
            with self.subTest(status=status):
                self.connection.reset_mock()
                self.response.status = status
                result = self.send()
                self.assertEqual((0, None), (result.status, result.object_id))
                self.connection.request.assert_called_once()
                self.response.read.assert_not_called()

    def test_partial_write_and_read_failures_stay_unknown_without_secret_diagnostics(self):
        for boundary in (self.connection.request, self.connection.getresponse, self.response.read):
            with self.subTest(boundary=boundary):
                self.connection.reset_mock()
                boundary.side_effect = OSError("sensitive token or private response")
                result = self.send()
                self.assertEqual((0, None), (result.status, result.object_id))
                self.assertNotIn("sensitive", repr(result))
                self.connection.request.assert_called_once()
                boundary.side_effect = None

    def test_missing_boolean_duplicate_or_oversized_response_identity_is_unknown(self):
        for raw in (b"not json", b"null", b"[]", b"{}", b'{"id":true}', b'{"id":0}',
                    b'{"id":123,"id":456}',
                    b"x" * (https.MAX_RESPONSE + 1)):
            with self.subTest(raw_length=len(raw)):
                self.response.read.return_value = raw
                self.assertIsNone(self.send().object_id)

    def test_invalid_credential_never_opens_socket(self):
        for token in (None, "short", "bad\r\nheader" + "x" * 30):
            self.credential.return_value = token
            result = self.send()
            self.assertEqual((0, None), (result.status, result.object_id))
        self.factory_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
