"""Compose actual issuer, private custody, scoped credential and one HTTP write.

Library only: no daemon, workflow, credential, admission or remote call starts
on import. All constructor dependencies belong to the trusted private broker.
Remote producers provide only token/number/frozen wire/policy/inventory data.
"""
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from collaboration_app_credential import AppTokenPreparer
from collaboration_content import guarded_payload, require
from collaboration_https import HTTPSOnceSender
from collaboration_native_issuer import NativeReviewIssuer, signing_keys
from collaboration_private_evidence import (
    KnownResponse, NativeProof, PrivateEvidence, document, open_directory, read_file, write_file,
)
from collaboration_publisher import (
    BoundedTransport, PrivateLedger, Publisher, ROOT, ROOT_ID, digest, fixed_hash, json_bytes, positive, shape,
)


def private_child(parent, name):
    fd = open_directory(parent)
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=fd)
            os.fsync(fd)
        except FileExistsError:
            pass
        child = open_directory(name=name, parent=fd)
        os.close(child)
    finally:
        os.close(fd)
    return Path(parent) / name


class ResponseCustody:
    """Private original HTTP response provenance, never equal-text inference."""
    def __init__(self, directory):
        self.directory = directory

    def begin(self, auth):
        require(fixed_hash(auth.operation_id), "response-operation")
        root = open_directory(self.directory)
        try:
            os.mkdir(auth.operation_id, 0o700, dir_fd=root)
            os.fsync(root)
        finally:
            os.close(root)

    def record(self, auth, result):
        require(fixed_hash(auth.operation_id), "response-operation")
        if type(result.status) is not int or result.status not in (200, 201) or not positive(result.object_id):
            return
        require(positive(auth.number), "response-parent")
        record = {"version": 1, "authorization_sha256": digest(json_bytes(asdict(auth))),
                  "status": result.status, "object_id": result.object_id, "number": auth.number}
        wire = json_bytes(record)
        root = open_directory(self.directory)
        operation = None
        try:
            operation = open_directory(name=auth.operation_id, parent=root)
            write_file(operation, "response.json", wire)
            os.fsync(operation)
            write_file(operation, "complete.json", json_bytes({"response_sha256": digest(wire)}))
            os.fsync(operation)
            os.fsync(root)
        finally:
            if operation is not None:
                os.close(operation)
            os.close(root)

    def known(self, auth):
        root = operation = None
        try:
            require(fixed_hash(auth.operation_id), "response-operation")
            root = open_directory(self.directory)
            operation = open_directory(name=auth.operation_id, parent=root)
            wire = read_file(operation, "response.json", 4096)
            complete = document(read_file(operation, "complete.json", 256))
            record = document(wire)
            require(json_bytes(record) == wire and complete == {"response_sha256": digest(wire)}
                    and set(record) == {"version", "authorization_sha256", "status", "object_id", "number"}
                    and type(record["version"]) is int and record["version"] == 1
                    and record["authorization_sha256"] == digest(json_bytes(asdict(auth)))
                    and type(record["status"]) is int and record["status"] in (200, 201)
                    and positive(record["object_id"]) and positive(record["number"])
                    and record["number"] == auth.number, "response-private-provenance")
            facts = auth.facts
            return KnownResponse(auth.operation_id, auth.payload_sha256, ROOT_ID, facts.origin_producer_id,
                                 facts.publisher_actor_id, facts.origin_source, facts.generation,
                                 record["object_id"], record["number"], digest(wire))
        except Exception:
            return None
        finally:
            if operation is not None:
                os.close(operation)
            if root is not None:
                os.close(root)

    def verify(self, auth, response):
        return type(response) is KnownResponse and self.known(auth) == response


class ReviewBroker:
    """Root Develop review pilot, not an admitted service or universal guard.

    state_directory must already be privately owned0700. api is the real
    broker's authenticated read-only GitHub client. App identity/key supplier,
    clock and OIDC-key reader are fixed deployment inputs, never request fields.
    There is no retry, overwrite, repair, search or operation-ID allocator.
    """
    def __init__(self, api, state_directory, app_identity, key_source, *, clock=time.time, oidc_keys=signing_keys):
        self.api, self.clock, self.oidc_keys = api, clock, oidc_keys
        self.app_identity, self.key_source = app_identity, key_source
        self.requests = private_child(state_directory, "requests")
        self.responses = ResponseCustody(private_child(state_directory, "responses"))
        self.ledger = PrivateLedger(private_child(state_directory, "ledger"))

    def execute(self, token, number, wire, policy, inventory):
        publication_started = False
        auth = None
        try:
            issuer = NativeReviewIssuer(self.api, token, number, wire, policy, inventory,
                                       clock=self.clock, keys=self.oidc_keys)
            auth = issuer.issue()
            payload = document(wire)
            require(json_bytes(payload) == wire, "broker-canonical-payload")
            shape(auth, payload)
            admitted = guarded_payload("review", ROOT, payload, inventory, policy, lambda value: value,
                                       now=datetime.fromtimestamp(self.clock(), timezone.utc))
            require(admitted == wire, "broker-final-bytes")

            def verify_native(expected, proof):
                return type(proof) is NativeProof and asdict(proof) == issuer.evidence(expected)

            evidence = PrivateEvidence(self.requests, verify_native)
            evidence.write_once(auth, wire, NativeProof(**issuer.evidence(auth)))
            prepared = AppTokenPreparer(self.app_identity, self.key_source, issuer.attest, self.ledger,
                                       clock=self.clock).prepare(auth)
            https = HTTPSOnceSender(prepared.credential)

            def sender(method, url, final_wire):
                nonlocal publication_started
                self.responses.begin(auth)
                publication_started = True
                result = https(method, url, final_wire)
                self.responses.record(auth, result)
                return result

            # This map is interpreted from the independently authenticated
            # active-source registration, not a contributor's admission claim.
            facts = auth.facts
            publisher = Publisher(admitted_bindings={(facts.origin_producer_id, facts.publisher_actor_id): facts.origin_source},
                attest=issuer.attest, ledger=self.ledger, serialize=self.ledger.serialize,
                transport=BoundedTransport(sender, publisher_actor_id=self.app_identity.actor_id),
                clock=lambda: datetime.fromtimestamp(self.clock(), timezone.utc))
            result = publisher.publish(auth, wire, inventory, policy)
            if result["disposition"] != "response-observed":
                return result
            # A known original response must be durable before its ID can be
            # consumed as readback provenance. No body search fills this gap.
            response = self.responses.known(auth)
            class Reader:
                get = staticmethod(self.api.call)
            return evidence.exact_readback(auth, response, verify_response=self.responses.verify, reader=Reader())
        except Exception:
            result = {"disposition": "unknown-readback-required" if publication_started else "blocked-before-publication"}
            if auth is not None:
                result.update(operation_id=auth.operation_id, payload_sha256=auth.payload_sha256)
            return result
