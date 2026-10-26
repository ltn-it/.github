"""Private immutable request custody and bounded exact-effect GET readback.

No authentication secret/header, publication, retry or deletion API exists.
Proof/response authentication callbacks are independently trusted integration;
plain descriptors or this private filesystem do not manufacture native proof.
"""
from __future__ import annotations

import base64
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from collaboration_content import AdmissionError, GITHUB_TOKEN_PATTERN, require
from collaboration_https import unique_object
from collaboration_inventory import GitHubReadOnly, pages
from collaboration_publisher import Authorization, Facts, ROOT, ROOT_ID, digest, fixed_hash, json_bytes, positive, route, shape

MAX_WIRE = 262144
MAX_PROVIDER = 1048576
MAX_ENVELOPE = 2 * 1048576


@dataclass(frozen=True)
class NativeProof:
    repository_id: int
    origin_producer_id: int
    publisher_actor_id: int
    origin_source: str
    head_sha: str
    generation: str
    run_id: int
    run_attempt: int
    job_id: int
    authorization_sha256: str
    native_evidence_sha256: str
    # For edits, the authenticated pre-write field-hash map. Its canonical
    # digest must equal Facts.object_revision; no guessed previous text.
    before_fields: dict
    provider_response_sha256: str | None = None


@dataclass(frozen=True)
class KnownResponse:
    operation_id: str
    payload_sha256: str
    repository_id: int
    origin_producer_id: int
    publisher_actor_id: int
    origin_source: str
    generation: str
    object_id: int
    # Actual response.number for issue/PR creation, authenticated parent number
    # otherwise. A guessed number or equal-text search is not permitted.
    number: int
    response_evidence_sha256: str


def document(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def no_auth_material(raw):
    pattern = (r'(?i)\b(?:' + GITHUB_TOKEN_PATTERN + r'|sk-[a-z0-9_-]{20,})\b'
               r'|(?:authorization|proxy-authorization|set-cookie)\s*[:=]|\bBearer\s+[A-Za-z0-9_.-]{8,}')
    require(type(raw) is bytes and not re.search(pattern.encode("ascii"), raw), "custody-auth-material")
    value = document(raw)
    def inspect(node):
        if type(node) is dict:
            require(not any(key.casefold().replace('_', '-') in {
                'authorization', 'proxy-authorization', 'headers', 'request-headers', 'cookie', 'set-cookie',
                'token', 'access-token', 'refresh-token', 'api-key', 'client-secret', 'password', 'secret'}
                for key in node), "custody-auth-material")
            for key, child in node.items():
                inspect(key)
                inspect(child)
        elif type(node) is list:
            for child in node:
                inspect(child)
        elif type(node) is str:
            # JSON escape sequences are resolved only by the parser. Inspect
            # that representation as well as raw wire bytes before any write.
            require(not re.search(pattern, node), "custody-auth-material")
    inspect(value)
    return value


def private_stat(info, mode):
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == mode,
            "custody-private-mode")


def open_directory(path=None, *, name=None, parent=None):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path if path is not None else name, flags, dir_fd=parent)
    try:
        private_stat(os.fstat(fd), 0o700)
        return fd
    except Exception:
        os.close(fd)
        raise


def write_file(directory, name, wire):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        private_stat(os.fstat(fd), 0o600)
        # Handle short writes; they are file writes, never a provider retry.
        remaining = memoryview(wire)
        while remaining:
            count = os.write(fd, remaining)
            require(type(count) is int and count > 0, "custody-file-write")
            remaining = remaining[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def read_file(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        info = os.fstat(fd)
        private_stat(info, 0o600)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum,
                "custody-file-shape")
        pieces, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= maximum, "custody-file-size")
            pieces.append(block)
        require(size == info.st_size, "custody-file-drift")
        return b''.join(pieces)
    finally:
        os.close(fd)


def before_keys(operation):
    if operation in {'issue.edit', 'pull.edit'}:
        return {'title', 'body'}
    if operation == 'inline.edit':
        return {'body', 'path', 'line', 'side', 'start_line', 'start_side', 'commit_id',
                'in_reply_to_id', 'pull_request_review_id'}
    if operation == 'review.edit':
        return {'body', 'comments'}
    if operation == 'comment.edit':
        return {'body'}
    return set()


def bind(auth, wire, proof, provider):
    require(type(auth) is Authorization and type(auth.facts) is Facts and type(proof) is NativeProof,
            'custody-descriptor')
    route(auth)
    facts = auth.facts
    require(fixed_hash(auth.operation_id) and fixed_hash(auth.payload_sha256)
            and fixed_hash(auth.policy_sha256) and fixed_hash(auth.inventory_sha256)
            and facts.repository == ROOT and type(facts.repository_id) is int and facts.repository_id == ROOT_ID
            and facts.visibility == 'public' and positive(facts.origin_producer_id)
            and positive(facts.publisher_actor_id) and fixed_hash(facts.origin_source, 40)
            and fixed_hash(facts.head_sha, 40) and fixed_hash(facts.generation), 'custody-origin')
    require(type(wire) is bytes and 0 < len(wire) <= MAX_WIRE and digest(wire) == auth.payload_sha256,
            'custody-final-bytes')
    payload = no_auth_material(wire)
    require(type(payload) is dict and json_bytes(payload) == wire, 'custody-canonical-bytes')
    shape(auth, payload)
    require(type(proof.repository_id) is int and proof.repository_id == ROOT_ID
            and positive(proof.origin_producer_id) and proof.origin_producer_id == facts.origin_producer_id
            and positive(proof.publisher_actor_id) and proof.publisher_actor_id == facts.publisher_actor_id
            and proof.origin_source == facts.origin_source and proof.head_sha == facts.head_sha
            and proof.generation == facts.generation and positive(proof.run_id) and positive(proof.job_id)
            and positive(proof.run_attempt) and proof.run_attempt <= 100
            and proof.authorization_sha256 == digest(json_bytes(asdict(auth)))
            and fixed_hash(proof.native_evidence_sha256), 'custody-native-binding')
    require(type(proof.before_fields) is dict and set(proof.before_fields) == before_keys(auth.operation)
            and all(fixed_hash(value) for value in proof.before_fields.values()), 'custody-before-fields')
    if proof.before_fields:
        require(facts.owner_id == facts.publisher_actor_id and positive(facts.owner_id)
                and facts.object_origin_producer_id == facts.origin_producer_id
                and positive(facts.object_origin_producer_id)
                and facts.object_origin_source == facts.origin_source
                and fixed_hash(facts.object_origin_receipt)
                and facts.object_revision == digest(json_bytes(proof.before_fields)), 'custody-edit-origin')
    else:
        require(all(value is None for value in (facts.owner_id, facts.object_revision,
                facts.object_origin_producer_id, facts.object_origin_source, facts.object_origin_receipt)),
                'custody-create-origin')
    require((provider is None and proof.provider_response_sha256 is None)
            or (type(provider) is bytes and 0 < len(provider) <= MAX_PROVIDER
                and digest(provider) == proof.provider_response_sha256), 'custody-provider-binding')
    if provider is not None:
        no_auth_material(provider)
    return payload


class PrivateEvidence:
    """The directory must already exist, be privately owned, and not a symlink.

    verify_native(auth, proof) is the issuer's authenticated read-only verifier,
    never a producer-supplied authenticated flag. It must bind the real native
    run/attempt/job, producer/source, head, generation, assignment and descriptors.
    Failure after mkdir leaves a consumed incomplete operation; never resume it.
    """
    def __init__(self, directory, verify_native):
        self.directory = Path(directory)
        self.verify_native = verify_native

    def write_once(self, auth, wire, proof, provider_response=None):
        root = operation = None
        try:
            # Freeze nested proof data before callbacks or filesystem effects.
            proof = NativeProof(**document(json_bytes(asdict(proof))))
            bind(auth, wire, proof, provider_response)
            proof_bytes = json_bytes(asdict(proof))
            require(self.verify_native(auth, proof) is True
                    and json_bytes(asdict(proof)) == proof_bytes, 'custody-native-unverified')
            envelope = json_bytes({'version': 1, 'authorization': asdict(auth), 'native_proof': asdict(proof),
                'wire_base64': base64.b64encode(wire).decode('ascii'),
                'provider_base64': base64.b64encode(provider_response).decode('ascii')
                    if provider_response is not None else None})
            require(len(envelope) <= MAX_ENVELOPE, 'custody-envelope-size')
            root = open_directory(self.directory)
            os.mkdir(auth.operation_id, mode=0o700, dir_fd=root)
            os.fsync(root)  # Durable operation consumption before request bytes.
            operation = open_directory(name=auth.operation_id, parent=root)
            write_file(operation, 'request.json', envelope)
            os.fsync(operation)
            write_file(operation, 'complete.json', json_bytes({'version': 1,
                       'operation_id': auth.operation_id, 'request_sha256': digest(envelope)}))
            os.fsync(operation)
            os.fsync(root)
            return {'operation_id': auth.operation_id, 'payload_sha256': auth.payload_sha256,
                    'custody_sha256': digest(envelope), 'disposition': 'private-custody-durable'}
        except Exception:
            # No OS path, callback exception, rejected text or provider output.
            raise AdmissionError('private-custody-unavailable-or-consumed') from None
        finally:
            if operation is not None:
                os.close(operation)
            if root is not None:
                os.close(root)

    def _load(self, auth):
        require(type(auth) is Authorization and fixed_hash(auth.operation_id), 'custody-operation')
        root = open_directory(self.directory)
        operation = None
        try:
            operation = open_directory(name=auth.operation_id, parent=root)
            envelope = read_file(operation, 'request.json', MAX_ENVELOPE)
            commit = document(read_file(operation, 'complete.json', 1024))
            require(type(commit) is dict and type(commit.get('version')) is int
                    and commit == {'version': 1, 'operation_id': auth.operation_id,
                               'request_sha256': digest(envelope)}, 'custody-incomplete')
            value = document(envelope)
            require(type(value) is dict and set(value) == {'version', 'authorization', 'native_proof',
                    'wire_base64', 'provider_base64'} and type(value['version']) is int and value['version'] == 1
                    and json_bytes(value['authorization']) == json_bytes(asdict(auth))
                    and json_bytes(value) == envelope, 'custody-authorization-drift')
            wire = base64.b64decode(value['wire_base64'], validate=True)
            provider = base64.b64decode(value['provider_base64'], validate=True) if value['provider_base64'] is not None else None
            proof = NativeProof(**value['native_proof'])
            payload = bind(auth, wire, proof, provider)
            proof_bytes = json_bytes(asdict(proof))
            require(self.verify_native(auth, proof) is True
                    and json_bytes(asdict(proof)) == proof_bytes, 'custody-native-unverified')
            return payload, proof
        finally:
            if operation is not None:
                os.close(operation)
            os.close(root)

    def exact_readback(self, auth, response, *, verify_response, reader=None):
        """Read a confirmed response locator twice; unknown CREATE stays unknown.

        reader.get is a trusted read-only GitHub client (default existing
        GitHubReadOnly). verify_response authenticates the original transport
        receipt/custody; caller-asserted object IDs or matching text do not count.
        No mutation, search, retransmission or reservation reset is implemented.
        """
        try:
            payload, proof = self._load(auth)
            proof_bytes = json_bytes(asdict(proof))
            require(type(response) is KnownResponse and response.operation_id == auth.operation_id
                    and response.payload_sha256 == auth.payload_sha256
                    and type(response.repository_id) is int and response.repository_id == ROOT_ID
                    and positive(response.origin_producer_id) and response.origin_producer_id == auth.facts.origin_producer_id
                    and positive(response.publisher_actor_id) and response.publisher_actor_id == auth.facts.publisher_actor_id
                    and response.origin_source == auth.facts.origin_source and response.generation == auth.facts.generation
                    and positive(response.object_id) and positive(response.number)
                    and fixed_hash(response.response_evidence_sha256), 'custody-response-binding')
            require(auth.number is None or response.number == auth.number, 'custody-response-parent')
            if auth.operation.endswith('.edit') and auth.object_id is not None:
                require(response.object_id == auth.object_id, 'custody-response-object')
            require(verify_response(auth, response) is True, 'custody-response-unverified')
            reader = reader if reader is not None else GitHubReadOnly()
            first = observation(reader, auth, response, payload, proof)
            second = observation(reader, auth, response, payload, proof)
            require(first == second and self.verify_native(auth, proof) is True
                    and json_bytes(asdict(proof)) == proof_bytes, 'custody-readback-drift')
            return {'operation_id': auth.operation_id, 'payload_sha256': auth.payload_sha256,
                    'object_id': response.object_id, 'observation_sha256': digest(json_bytes(first)),
                    'disposition': 'exact-known-effect-read-back'}
        except Exception:
            return {'disposition': 'unknown-readback-required'}


def actor(value, auth):
    require(type(value.get('user')) is dict and positive(value['user'].get('id'))
            and value['user']['id'] == auth.facts.publisher_actor_id, 'custody-readback-actor')


def inline_projection(value):
    return {k: value.get(k) for k in before_keys('inline.edit')}


def observation(reader, auth, response, payload, proof):
    prefix = f'repos/{ROOT}'
    number = response.number
    family = 'pulls' if auth.parent_kind == 'pull' else 'issues'
    parent = reader.get(f'{prefix}/{family}/{number}')
    require(type(parent) is dict and positive(parent.get('id')) and parent.get('number') == number
            and type(parent.get('number')) is int
            and parent.get('url') == f'https://api.github.com/{prefix}/{family}/{number}', 'custody-readback-parent')
    if family == 'pulls':
        require(parent.get('head', {}).get('sha') == auth.facts.head_sha
                and type(parent.get('head', {}).get('repo', {}).get('id')) is int
                and parent.get('head', {}).get('repo', {}).get('id') == ROOT_ID
                and parent.get('base', {}).get('repo', {}).get('id') == ROOT_ID
                and type(parent.get('base', {}).get('repo', {}).get('id')) is int, 'custody-readback-head')
    op = auth.operation
    inline_ids = None
    if op.startswith(('issue.', 'pull.')):
        value = parent
        actor(value, auth)
        current = {'title': value.get('title'), 'body': value.get('body')}
        require(all(type(v) is str for v in current.values()), 'custody-readback-body')
        if op == 'pull.create':
            require(value.get('head', {}).get('ref') == payload['head'] and value.get('base', {}).get('ref') == payload['base']
                    and type(value.get('draft')) is bool and value['draft'] == payload['draft'], 'custody-readback-refs')
    elif op.startswith('comment.'):
        value = reader.get(f'{prefix}/issues/comments/{response.object_id}')
        actor(value, auth)
        require(value.get('issue_url') == f'https://api.github.com/{prefix}/issues/{number}', 'custody-readback-parent')
        current = {'body': value.get('body')}
    elif op.startswith('inline.'):
        value = reader.get(f'{prefix}/pulls/comments/{response.object_id}')
        actor(value, auth)
        require(value.get('pull_request_url') == f'https://api.github.com/{prefix}/pulls/{number}'
                and value.get('commit_id') == auth.facts.head_sha, 'custody-readback-parent')
        if op == 'inline.reply':
            require(value.get('in_reply_to_id') == auth.object_id and positive(value.get('in_reply_to_id')),
                    'custody-readback-reply')
            replied = reader.get(f'{prefix}/pulls/comments/{auth.object_id}')
            require(replied.get('id') == auth.object_id and positive(replied.get('id'))
                    and replied.get('pull_request_url') == value['pull_request_url']
                    and replied.get('commit_id') == auth.facts.head_sha, 'custody-readback-reply')
            current = {'body': value.get('body')}
        else:
            if op == 'inline.create':
                require(value.get('in_reply_to_id') is None, 'custody-readback-inline-kind')
                for key in ('start_line', 'start_side'):
                    require(key in payload or value.get(key) is None, 'custody-readback-inline-range')
            current = inline_projection(value)
    else:
        value = reader.get(f'{prefix}/pulls/{number}/reviews/{response.object_id}')
        actor(value, auth)
        require(value.get('pull_request_url') == f'https://api.github.com/{prefix}/pulls/{number}'
                and value.get('commit_id') == auth.facts.head_sha and value.get('state') == 'COMMENTED',
                'custody-readback-review')
        comments = pages(reader, f'{prefix}/pulls/{number}/reviews/{response.object_id}/comments', maximum=3)
        require(len(comments) <= 100, 'custody-readback-comments')
        projected = []
        inline_ids = sorted(comment['id'] for comment in comments)
        for comment in comments:
            actor(comment, auth)
            require(comment.get('pull_request_review_id') == response.object_id
                    and positive(comment.get('pull_request_review_id'))
                    and comment.get('pull_request_url') == f'https://api.github.com/{prefix}/pulls/{number}'
                    and comment.get('commit_id') == auth.facts.head_sha, 'custody-readback-inline-parent')
            item = {key: comment.get(key) for key in ('body', 'path', 'line', 'side')}
            if comment.get('start_line') is not None:
                item.update(start_line=comment['start_line'], start_side=comment.get('start_side'))
            projected.append(item)
        current = {'body': value.get('body'), 'comments': sorted(projected, key=json_bytes)}
    require(positive(value.get('id')) and value['id'] == response.object_id, 'custody-readback-object')
    require(len(json_bytes(current)) <= MAX_WIRE + 8192, 'custody-readback-size')
    expected = {k: v for k, v in payload.items() if k in current}
    if op == 'review.create':
        expected['comments'] = sorted(payload.get('comments', []), key=json_bytes)
    for field, value in current.items():
        if field in expected:
            require(type(value) is type(expected[field]) and value == expected[field], 'custody-readback-content')
        elif proof.before_fields:
            require(digest(json_bytes(value)) == proof.before_fields[field], 'custody-readback-unchanged')
        else:
            require(field not in {'body', 'title'}, 'custody-readback-content')
    return {'object_id': response.object_id, 'number': number, 'fields': current, 'inline_ids': inline_ids,
            'head': parent.get('head', {}).get('sha') if family == 'pulls' else None}
