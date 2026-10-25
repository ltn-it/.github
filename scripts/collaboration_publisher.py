"""Offline-qualified final-byte publication seam; no network or credentials.

All authority objects, live facts, durable reservations, serialization and the
credential-isolated sender must come from independently trusted integration.
Calling Python in one process is NOT a credential boundary or source admission.
"""
from __future__ import annotations

import hashlib
import fcntl
import os
import sqlite3
import stat
from contextlib import contextmanager
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from collaboration_content import AdmissionError, guarded_payload, inventory_repositories, require


ROOT = "ltn-it/.github"
ROOT_ID = 1112629689


def digest(value):
    return hashlib.sha256(value).hexdigest()


def json_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise AdmissionError("publisher-json") from None


def positive(value):
    return type(value) is int and value > 0


def fixed_hash(value, length=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


@dataclass(frozen=True)
class Facts:
    """Independently authenticated snapshot, never a contributor assertion.

    generation binds actual workflow/run/attempt evidence. object_revision is
    a digest of the exact existing edit subject. Complete visibility belongs to
    the independently attested inventory, not a selected App's partial listing.
    """
    repository: str
    repository_id: int
    visibility: str
    producer_id: int
    producer_source: str
    head_sha: str
    generation: str
    owner_id: int | None = None
    object_revision: str | None = None


@dataclass(frozen=True)
class Authorization:
    operation_id: str
    operation: str
    number: int | None
    object_id: int | None
    parent_kind: str
    payload_sha256: str
    policy_sha256: str
    inventory_sha256: str
    facts: Facts


# Method and path are derived here, never supplied by the producer. No delete,
# approval, merge, ready, state transition, arbitrary route or GraphQL surface.
ROUTES = {
    "issue.create": ("POST", "issues", "issue", False, False),
    "issue.edit": ("PATCH", "issues/{number}", "issue", True, False),
    "pull.create": ("POST", "pulls", "pull_request", False, False),
    "pull.edit": ("PATCH", "pulls/{number}", "pull_request", True, False),
    "comment.create": ("POST", "issues/{number}/comments", "comment", False, False),
    "comment.edit": ("PATCH", "issues/comments/{object_id}", "comment", True, True),
    "inline.create": ("POST", "pulls/{number}/comments", "review_comment", False, False),
    "inline.reply": ("POST", "pulls/{number}/comments/{object_id}/replies", "comment", False, True),
    "inline.edit": ("PATCH", "pulls/comments/{object_id}", "review_comment", True, True),
    "review.create": ("POST", "pulls/{number}/reviews", "review", False, False),
    "review.edit": ("PUT", "pulls/{number}/reviews/{object_id}", "review", True, True),
}


def route(auth):
    require(type(auth) is Authorization and auth.operation in ROUTES, "publisher-operation")
    method, suffix, kind, edit, object_needed = ROUTES[auth.operation]
    numbered = auth.operation not in {"issue.create", "pull.create"}
    require((positive(auth.number) if numbered else auth.number is None)
            and (positive(auth.object_id) if object_needed else auth.object_id is None), "publisher-locator")
    require(auth.parent_kind in {"issue", "pull"}, "publisher-parent")
    if auth.operation.startswith("issue."):
        require(auth.parent_kind == "issue", "publisher-parent")
    if auth.operation.startswith(("pull.", "review.", "inline.")):
        require(auth.parent_kind == "pull", "publisher-parent")
    return method, f"https://api.github.com/repos/{ROOT}/" + suffix.format(
        number=auth.number, object_id=auth.object_id), kind, edit


def inline(value, *, commit=None):
    allowed = {"body", "path", "line", "side", "start_line", "start_side"}
    if commit is not None:
        allowed.add("commit_id")
    require(type(value) is dict and set(value) <= allowed
            and {"body", "path", "line", "side"} <= set(value), "publisher-inline-shape")
    require(type(value["body"]) is str and type(value["path"]) is str
            and value["path"] and not value["path"].startswith("/")
            and all(p not in {"", ".", ".."} for p in value["path"].split("/"))
            and "\\" not in value["path"] and positive(value["line"])
            and value["side"] in {"LEFT", "RIGHT"}, "publisher-inline-location")
    require(("start_line" in value) == ("start_side" in value), "publisher-inline-range")
    if "start_line" in value:
        require(positive(value["start_line"]) and value["start_line"] <= value["line"]
                and value["start_side"] == value["side"], "publisher-inline-range")
    if commit is not None:
        require(value.get("commit_id") == commit, "publisher-head")


def shape(auth, payload):
    op = auth.operation
    if op in {"issue.create", "issue.edit", "pull.edit"}:
        require(set(payload) <= {"title", "body"} and payload
                and all(type(v) is str for v in payload.values()), "publisher-content-shape")
        if op == "issue.create":
            require(set(payload) == {"title", "body"} and payload["title"], "publisher-title")
        if "title" in payload:
            require(bool(payload["title"]), "publisher-title")
    elif op == "pull.create":
        require(set(payload) == {"title", "body", "head", "base", "draft"}
                and all(type(payload[k]) is str and payload[k] for k in ("title", "head", "base"))
                and type(payload["body"]) is str and type(payload["draft"]) is bool,
                "publisher-pull-shape")
        require(all(re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", payload[k])
                    and ".." not in payload[k] for k in ("head", "base")), "publisher-branch")
    elif op == "inline.create":
        inline(payload, commit=auth.facts.head_sha)
    elif op == "review.create":
        require(set(payload) <= {"body", "commit_id", "event", "comments"}
                and {"body", "commit_id", "event"} <= set(payload)
                and type(payload["body"]) is str and payload["event"] == "COMMENT"
                and payload["commit_id"] == auth.facts.head_sha, "publisher-review-shape")
        if "comments" in payload:
            require(type(payload["comments"]) is list and len(payload["comments"]) <= 100,
                    "publisher-review-comments")
            for comment in payload["comments"]:
                inline(comment)
    else:
        require(set(payload) == {"body"} and type(payload["body"]) is str,
                "publisher-body-shape")


@dataclass(frozen=True)
class TransportResult:
    status: int
    object_id: int | None


class BoundedTransport:
    """Private sender seam. No actual HTTP client, token, redirects or retries.

    Deploy in a separate trusted process with fixed GitHub TLS egress. Its real
    sender must disable HTTP retries/redirects and never expose provider bodies.
    This endpoint restriction is not a GitHub permission-bucket guarantee.
    """
    def __init__(self, sender):
        self._sender = sender

    def send_once(self, auth, wire):
        method, url, _, _ = route(auth)
        require(type(wire) is bytes and digest(wire) == auth.payload_sha256, "publisher-final-byte-drift")
        return self._sender(method, url, wire)


class PrivateLedger:
    """Private local durable one-shot reservations and cross-process target lock.

    All publishers for the target MUST use this same ledger/lock. This does not
    serialize unrelated GitHub writers; deny those routes before live admission.
    Only hashes are stored. A reserved/unknown operation can never be reset here.
    The parent must be a pre-created, owned private directory, outside artifacts.
    """
    def __init__(self, directory):
        directory = Path(directory)
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0, "publisher-private-ledger")
        self.database = directory / "publisher.sqlite3"
        self.lock = directory / "publisher.lock"
        for path in (self.database, self.lock):
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                        and info.st_mode & 0o077 == 0 and info.st_nlink == 1, "publisher-private-ledger")
            finally:
                os.close(descriptor)
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE IF NOT EXISTS reservations "
                               "(operation_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)")

    @contextmanager
    def serialize(self):
        descriptor = os.open(self.lock, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def claim(self, operation_id, fingerprint):
        require(fixed_hash(operation_id) and fixed_hash(fingerprint), "publisher-reservation")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            cursor = connection.execute("INSERT OR IGNORE INTO reservations VALUES (?, ?)",
                                        (operation_id, fingerprint))
            return cursor.rowcount == 1


class Publisher:
    """Integration must supply a private atomic durable ledger and target lock.

    ledger.claim(id, fingerprint) MUST persist consumption before returning True;
    False blocks every later mutation including after crashes and unknown writes.
    serialize() MUST exclude all publishers of this target, across processes.
    attest(auth) independently reads current exact subject/owner/head/generation.
    It receives no payload and holds no publishing credential. Neither callback
    may be supplied by a contributor. Facts must bind the full operation incl.
    parent/object locators, and attest must recheck the producer's native source.
    """
    def __init__(self, *, admitted_producers, attest, ledger, serialize, transport, clock=None):
        self.producers = dict(admitted_producers)
        self.attest, self.ledger, self.serialize, self.transport = attest, ledger, serialize, transport
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def publish(self, auth, wire, inventory, policy):
        try:
            return self._publish(auth, wire, inventory, policy, now=self.clock())
        except AdmissionError:
            # Do not propagate callbacks' arbitrary exception text or rejected values.
            raise AdmissionError("publisher-rejected") from None
        except Exception:
            raise AdmissionError("publisher-unavailable") from None

    def _publish(self, auth, wire, inventory, policy, *, now):
        method, url, kind, edit = route(auth)
        facts = auth.facts
        require(type(facts) is Facts and facts.repository == ROOT and facts.repository_id == ROOT_ID
                and facts.visibility == "public" and positive(facts.producer_id)
                and fixed_hash(facts.producer_source, 40) and fixed_hash(facts.head_sha, 40)
                and fixed_hash(facts.generation)
                and self.producers.get(facts.producer_id) == facts.producer_source, "publisher-authority")
        require(fixed_hash(auth.operation_id) and fixed_hash(auth.payload_sha256)
                and auth.policy_sha256 == digest(json_bytes(policy))
                and auth.inventory_sha256 == digest(json_bytes(inventory)), "publisher-binding")
        require((positive(facts.owner_id) and facts.owner_id == facts.producer_id
                 and fixed_hash(facts.object_revision)) if edit
                else facts.owner_id is None and facts.object_revision is None, "publisher-ownership")
        require(type(wire) is bytes and len(wire) <= policy["max_text_bytes"]
                and digest(wire) == auth.payload_sha256, "publisher-final-byte-drift")
        try:
            payload = json.loads(wire)
        except (UnicodeError, ValueError):
            raise AdmissionError("publisher-json") from None
        require(type(payload) is dict and json_bytes(payload) == wire, "publisher-canonical-bytes")
        shape(auth, payload)
        # Existing credential-free validator inspects every final string, including
        # branch/path fields and all nested inline bodies. Its serializer must
        # produce exactly the already-frozen submitted bytes.
        validated = guarded_payload(kind, ROOT, payload, inventory, policy, lambda value: value, now=now)
        require(validated == wire, "publisher-final-byte-drift")
        repositories = inventory_repositories(inventory, policy, now)
        require(repositories[ROOT]["id"] == ROOT_ID and repositories[ROOT]["visibility"] == "public"
                and repositories[ROOT]["archived"] is False, "publisher-target")
        with self.serialize():
            require(self.attest(auth) == facts, "publisher-generation-drift")
            fingerprint = digest(json_bytes({"method": method, "url": url,
                                            "payload": auth.payload_sha256,
                                            "policy": auth.policy_sha256,
                                            "inventory": auth.inventory_sha256,
                                            "generation": facts.generation}))
            require(self.ledger.claim(auth.operation_id, fingerprint) is True, "publisher-consumed")
            # Recheck after the durable reservation, immediately before the one
            # effect. A failed recheck burns the reservation; never reset it.
            # Revalidate freshness and every final string after potentially slow
            # native evidence reads. Policy/inventory changes also burn the slot.
            require(auth.policy_sha256 == digest(json_bytes(policy))
                    and auth.inventory_sha256 == digest(json_bytes(inventory)), "publisher-input-drift")
            final = guarded_payload(kind, ROOT, payload, inventory, policy, lambda value: value,
                                    now=self.clock())
            require(final == wire, "publisher-final-byte-drift")
            # Native generation/ownership is the last potentially slow evidence
            # read. No content processing or other evidence read follows it.
            require(self.attest(auth) == facts, "publisher-generation-drift")
            require(auth.policy_sha256 == digest(json_bytes(policy))
                    and auth.inventory_sha256 == digest(json_bytes(inventory)), "publisher-input-drift")
            try:
                result = self.transport.send_once(auth, wire)
                confirmed = (type(result) is TransportResult and type(result.status) is int
                             and result.status in (200, 201) and positive(result.object_id))
            except Exception:
                confirmed, result = False, None
            return {"operation_id": auth.operation_id, "payload_sha256": auth.payload_sha256,
                    "disposition": "response-observed" if confirmed else "unknown-readback-required",
                    "object_id": result.object_id if confirmed else None}

    def reconcile(self, auth, observe):
        """Read-only reconstruction, never a retry or an authority to mutate.

        Trusted observer must identify exactly one effect bound to this operation,
        target, producer and byte hash using private retained request evidence.
        Merely finding equal content is insufficient; an ambiguous/absent result
        stays unknown. No uniqueness/idempotency property is invented for GitHub.
        """
        try:
            route(auth)
            result = observe(auth)
            require(type(result) is dict and set(result) == {"operation_id", "payload_sha256", "complete", "matches"}
                    and result["operation_id"] == auth.operation_id
                    and result["payload_sha256"] == auth.payload_sha256
                    and result["complete"] is True and type(result["matches"]) is list
                    and len(result["matches"]) == 1 and positive(result["matches"][0]), "publisher-readback")
            return {"operation_id": auth.operation_id, "payload_sha256": auth.payload_sha256,
                    "disposition": "effect-reconstructed", "object_id": result["matches"][0]}
        except Exception:
            return {"disposition": "unknown-readback-required"}
