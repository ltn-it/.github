"""Prepare one narrowly scoped App credential before final native attestation.

No key, token, installation or permission is read or changed on import. Live
use requires the concrete broker's independently admitted identity/key role.
This library has no CLI, environment credential lookup or automatic refresh.
"""
import base64
import http.client
import re
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from collaboration_content import AdmissionError, require
from collaboration_https import unique_object
from collaboration_publisher import Authorization, ROOT, ROOT_ID, digest, json_bytes, positive
from workflow_control import ORGANIZATION_ID
import json


@dataclass(frozen=True)
class AppIdentity:
    app_id: int
    installation_id: int
    actor_id: int


def base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def app_jwt(private_key, identity, now):
    require(type(private_key) is bytes and 0 < len(private_key) <= 32768, "publisher-app-key")
    key = serialization.load_pem_private_key(private_key, password=None)
    require(isinstance(key, rsa.RSAPrivateKey) and 2048 <= key.key_size <= 4096, "publisher-app-key")
    header = base64url(json_bytes({"alg": "RS256", "typ": "JWT"}))
    claims = base64url(json_bytes({"iat": int(now) - 30, "exp": int(now) + 300, "iss": str(identity.app_id)}))
    signing = (header + "." + claims).encode()
    return signing.decode() + "." + base64url(key.sign(signing, padding.PKCS1v15(), hashes.SHA256()))


def github(method, path, bearer, payload=None):
    """Private fixed credential API, never a producer-selectable HTTP proxy."""
    read = (path == "/app" or re.fullmatch(r"/app/installations/[1-9][0-9]*", path)
            or re.fullmatch(r"/users/[a-z0-9][a-z0-9-]{0,80}%5Bbot%5D", path)
            or path == "/installation/repositories?per_page=100&page=1")
    mint = re.fullmatch(r"/app/installations/[1-9][0-9]*/access_tokens", path)
    require((method == "GET" and read and payload is None) or (method == "POST" and mint
            and payload == {"repository_ids": [ROOT_ID], "permissions": {"pull_requests": "write"}}),
            "publisher-credential-route")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "ltn-it-publisher-credential-preparer", "Connection": "close"}
    if bearer is not None:
        require(type(bearer) is str and re.fullmatch(r"[A-Za-z0-9_.-]{20,8192}", bearer), "publisher-credential")
        headers["Authorization"] = "Bearer " + bearer
    wire = None if payload is None else json_bytes(payload)
    if wire is not None:
        headers.update({"Content-Type": "application/json", "Content-Length": str(len(wire))})
    connection = http.client.HTTPSConnection("api.github.com", timeout=15, context=ssl.create_default_context())
    try:
        connection.request(method, path, body=wire, headers=headers)
        response = connection.getresponse()
        require(response.status == (201 if method == "POST" else 200), "publisher-credential-response")
        raw = response.read(1048577)
        require(len(raw) <= 1048576, "publisher-credential-response-size")
        value = json.loads(raw, object_pairs_hook=unique_object)
        require(type(value) is dict, "publisher-credential-response-shape")
        return value
    finally:
        connection.close()


class PreparedCredential:
    """Memory-only trusted sender input; repr/receipts never contain its token."""
    __slots__ = ("_token", "_expires", "_clock", "_receipt")

    def __init__(self, token, expires, clock, receipt):
        self._token, self._expires, self._clock, self._receipt = token, expires, clock, receipt

    def __repr__(self):
        return "<PreparedCredential redacted>"

    def credential(self):
        require(self._clock() < self._expires, "publisher-credential-expired")
        return self._token

    def receipt(self):
        return dict(self._receipt)


class AppTokenPreparer:
    """Authenticates App/installation/bot; reserves one mint before POST.

    identity, key_source, attest, ledger and clock are trusted private broker
    construction inputs, never fields of a remote publication request. Prepare
    OUTSIDE Publisher.publish: only the already-prepared memory-only getter is
    passed to HTTPSOnceSender. Native attestation must follow all token I/O.
    """

    def __init__(self, identity, key_source, attest, ledger, *, clock=time.time, operation="review.create"):
        require(type(identity) is AppIdentity and all(positive(v) for v in asdict(identity).values())
                and callable(key_source) and callable(attest)
                and operation in {"review.create", "pull.create"}, "publisher-credential-config")
        self.identity, self.key_source, self.attest, self.ledger = identity, key_source, attest, ledger
        self.clock, self.operation = clock, operation

    def prepare(self, auth):
        try:
            return self._prepare(auth)
        except Exception:
            raise AdmissionError("publisher-credential-not-prepared") from None

    def _prepare(self, auth):
        expected = self.identity
        require(type(auth) is Authorization and auth.operation == self.operation
                and auth.facts.repository == ROOT and auth.facts.repository_id == ROOT_ID
                and auth.facts.publisher_actor_id == expected.actor_id, "publisher-credential-subject")
        with self.ledger.serialize():
            require(self.attest(auth) == auth.facts, "publisher-credential-authority")
            credential_id = digest(json_bytes({"stage": "credential-preparation/v1", "operation": auth.operation_id}))
            require(self.ledger.claim(credential_id, digest(json_bytes(asdict(auth)))) is True,
                    "publisher-credential-consumed")
            jwt = app_jwt(self.key_source(), expected, self.clock())
            app = github("GET", "/app", jwt)
            slug = app.get("slug")
            require(app.get("id") == expected.app_id and type(slug) is str
                    and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,80}", slug), "publisher-app-identity")
            installed = github("GET", f"/app/installations/{expected.installation_id}", jwt)
            account = installed.get("account") or {}
            require(installed.get("id") == expected.installation_id and installed.get("app_id") == expected.app_id
                    and "suspended_at" in installed and installed["suspended_at"] is None
                    and account.get("id") == ORGANIZATION_ID and account.get("login") == "ltn-it"
                    and account.get("type") == "Organization"
                    and (installed.get("permissions") or {}).get("pull_requests") == "write",
                    "publisher-installation-identity")
            actor = github("GET", f"/users/{slug}%5Bbot%5D", None)
            require(actor.get("id") == expected.actor_id and actor.get("login") == slug + "[bot]"
                    and actor.get("type") == "Bot", "publisher-app-actor")
            # The same independent native reader checks the unchanged exact
            # authorization again before the credential's only mutating call.
            require(self.attest(auth) == auth.facts, "publisher-credential-authority")
            token = github("POST", f"/app/installations/{expected.installation_id}/access_tokens", jwt,
                           {"repository_ids": [ROOT_ID], "permissions": {"pull_requests": "write"}})
            permissions = token.get("permissions")
            require(type(permissions) is dict and permissions.get("pull_requests") == "write"
                    and set(permissions) <= {"pull_requests", "metadata"}
                    and permissions.get("metadata", "read") == "read", "publisher-token-permissions")
            value = token.get("token")
            require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.-]{20,8192}", value), "publisher-token-shape")
            expiry = token.get("expires_at")
            require(type(expiry) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", expiry),
                    "publisher-token-expiry")
            expires = datetime.fromisoformat(expiry.replace("Z", "+00:00")).timestamp()
            require(0 < expires - self.clock() <= 3630, "publisher-token-expiry")
            scope = github("GET", "/installation/repositories?per_page=100&page=1", value)
            repositories = scope.get("repositories")
            require(type(scope.get("total_count")) is int and scope["total_count"] == 1
                    and type(repositories) is list and len(repositories) == 1
                    and repositories[0].get("id") == ROOT_ID and repositories[0].get("full_name") == ROOT
                    and repositories[0].get("private") is False, "publisher-token-scope")
            receipt = {"operation_id": auth.operation_id, "app_id": expected.app_id,
                       "installation_id": expected.installation_id, "publisher_actor_id": expected.actor_id,
                       "repository_id": ROOT_ID, "permissions": dict(permissions), "expires_at": expiry}
            return PreparedCredential(value, expires, self.clock, receipt)
