"""Private filesystem, failure and exact GET readback without live credentials."""
import base64
import copy
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import collaboration_private_evidence as custody
from collaboration_content import AdmissionError
from collaboration_publisher import Authorization, Facts, ROOT, ROOT_ID, digest, json_bytes


class Reader:
    def __init__(self, values):
        self.values, self.calls = values, []

    def get(self, path):
        self.calls.append(path)
        if path not in self.values:
            raise RuntimeError('unregistered-private-path')
        value = self.values[path]
        return copy.deepcopy(value() if callable(value) else value)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.native_calls = []
        self.evidence = custody.PrivateEvidence(self.directory, self.verify)

    def verify(self, auth, proof):
        self.native_calls.append((auth, proof))
        return True

    def fixture(self, operation='review.create'):
        prefix = 'https://api.github.com/repos/' + ROOT
        parent_number, identifier = 7, 123
        head = 'b' * 40
        user = {'id': 84}
        inline = {'body': 'Finding', 'path': 'src/a.py', 'line': 3, 'side': 'RIGHT'}
        payloads = {
            'issue.create': {'title': 'Public title', 'body': 'Public body'},
            'issue.edit': {'title': 'Changed title'},
            'pull.create': {'title': 'Public title', 'body': 'Public body', 'head': 'feature/a', 'base': 'develop', 'draft': True},
            'pull.edit': {'body': 'Changed body'},
            'comment.create': {'body': 'Comment'}, 'comment.edit': {'body': 'Changed comment'},
            'inline.create': dict(inline, commit_id=head), 'inline.reply': {'body': 'Reply'},
            'inline.edit': {'body': 'Changed inline'},
            'review.create': {'body': 'Review', 'event': 'COMMENT', 'commit_id': head, 'comments': [inline]},
            'review.edit': {'body': 'Changed review'},
        }
        payload = payloads[operation]
        parent_kind = 'issue' if operation.startswith(('issue.', 'comment.')) else 'pull'
        parent = {'id': identifier if operation.startswith(('issue.', 'pull.')) else 70,
                  'number': parent_number, 'url': prefix + ('/issues/7' if parent_kind == 'issue' else '/pulls/7'),
                  'user': user, 'title': 'Old title', 'body': 'Old body', 'draft': True,
                  'head': {'sha': head, 'ref': 'feature/a', 'repo': {'id': ROOT_ID}}, 'base': {'ref': 'develop', 'repo': {'id': ROOT_ID}}}
        value = {'id': identifier, 'user': user, 'body': 'Old body', 'issue_url': prefix + '/issues/7',
                 'pull_request_url': prefix + '/pulls/7', 'commit_id': head, 'state': 'COMMENTED',
                 'path': 'src/a.py', 'line': 3, 'side': 'RIGHT', 'start_line': None, 'start_side': None,
                 'in_reply_to_id': 11 if operation == 'inline.reply' else None, 'pull_request_review_id': 33}
        comment = dict(inline, id=456, user=user, commit_id=head, pull_request_url=prefix + '/pulls/7',
                       pull_request_review_id=identifier)
        previous = {'title': parent['title'], 'body': parent['body']}
        if operation == 'inline.edit':
            previous = custody.inline_projection(value)
        elif operation == 'review.edit':
            previous = {'body': value['body'], 'comments': [inline]}
        elif operation == 'comment.edit':
            previous = {'body': value['body']}
        edit = operation.endswith('.edit')
        before = {key: digest(json_bytes(previous[key])) for key in custody.before_keys(operation)}
        facts = Facts(ROOT, ROOT_ID, 'public', 42, 'a' * 40, 84, head, 'c' * 64,
                      owner_id=84 if edit else None, object_revision=digest(json_bytes(before)) if edit else None,
                      object_origin_producer_id=42 if edit else None, object_origin_source='a' * 40 if edit else None,
                      object_origin_receipt='d' * 64 if edit else None)
        wire = json_bytes(payload)
        object_id = identifier if operation in {'comment.edit', 'inline.edit', 'review.edit'} else 11 if operation == 'inline.reply' else None
        auth = Authorization(digest(operation.encode()), operation, None if operation.endswith('.create') and operation.startswith(('issue.', 'pull.')) else parent_number,
                             object_id, parent_kind, digest(wire), 'e' * 64, 'f' * 64, facts)
        proof = custody.NativeProof(ROOT_ID, 42, 84, 'a' * 40, head, 'c' * 64, 100, 1, 200,
                                    digest(json_bytes(asdict(auth))), '0' * 64, before)
        response = custody.KnownResponse(auth.operation_id, auth.payload_sha256, ROOT_ID, 42, 84,
                                        'a' * 40, 'c' * 64, identifier, parent_number, '1' * 64)
        if operation.startswith(('issue.', 'pull.')):
            for key in ('title', 'body'):
                if key in payload:
                    parent[key] = payload[key]
        else:
            value['body'] = payload['body']
        base = 'repos/' + ROOT
        values = {base + ('/issues/7' if parent_kind == 'issue' else '/pulls/7'): parent,
                  base + '/issues/comments/123': value, base + '/pulls/comments/123': value,
                  base + '/pulls/7/reviews/123': value,
                  base + '/pulls/comments/11': {'id': 11, 'pull_request_url': prefix + '/pulls/7', 'commit_id': head},
                  base + '/pulls/7/reviews/123/comments?per_page=100&page=1': [comment],
                  base + '/pulls/7/reviews/123/comments?per_page=100&page=2': []}
        return auth, wire, proof, response, Reader(values)

    def readback(self, auth, response, reader):
        return self.evidence.exact_readback(auth, response, verify_response=lambda a, r: True, reader=reader)

    def test_every_supported_operation_persists_and_exactly_reads_back(self):
        operations = ['issue.create', 'issue.edit', 'pull.create', 'pull.edit', 'comment.create', 'comment.edit',
                      'inline.create', 'inline.reply', 'inline.edit', 'review.create', 'review.edit']
        for operation in operations:
            with self.subTest(operation=operation):
                auth, wire, proof, response, reader = self.fixture(operation)
                receipt = self.evidence.write_once(auth, wire, proof)
                self.assertEqual('private-custody-durable', receipt['disposition'])
                self.assertEqual('exact-known-effect-read-back', self.readback(auth, response, reader)['disposition'])
                self.assertTrue(all(path.startswith('repos/ltn-it/.github/') for path in reader.calls))
                # Reader has no send/mutation method. There is no search path.
                self.assertFalse(any('/search' in path for path in reader.calls))

    def test_default_client_uses_existing_get_only_reader(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        with patch.object(custody.GitHubReadOnly, 'get', autospec=True,
                          side_effect=lambda instance, path: reader.get(path)) as get:
            result = self.evidence.exact_readback(auth, response, verify_response=lambda a, r: True)
        self.assertEqual('exact-known-effect-read-back', result['disposition'])
        self.assertTrue(get.called)
        self.assertEqual(8, len(reader.calls))

    def test_short_file_writes_are_completed_without_new_operation(self):
        auth, wire, proof, response, reader = self.fixture()
        real_write = os.write
        def short(fd, data):
            return real_write(fd, data[:17])
        with patch.object(custody.os, 'write', short):
            self.evidence.write_once(auth, wire, proof)
        self.assertEqual('exact-known-effect-read-back', self.readback(auth, response, reader)['disposition'])

    def test_foreign_pr_head_repository_is_unknown_even_with_same_head_bytes(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        reader.values['repos/' + ROOT + '/pulls/7']['head']['repo']['id'] = ROOT_ID + 1
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_private_files_are_exclusive_owned_and_exact_with_durable_syncs(self):
        auth, wire, proof, _, _ = self.fixture()
        real_sync, syncs = os.fsync, []
        def fsync(fd):
            syncs.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            real_sync(fd)
        with patch.object(custody.os, 'fsync', fsync):
            self.evidence.write_once(auth, wire, proof)
        operation = self.directory / auth.operation_id
        self.assertEqual(0o700, stat.S_IMODE(operation.stat().st_mode))
        self.assertEqual([True, False, True, False, True, True], syncs)
        for name in ['request.json', 'complete.json']:
            self.assertEqual(0o600, stat.S_IMODE((operation / name).stat().st_mode))
        packet = json.loads((operation / 'request.json').read_bytes())
        self.assertEqual(wire, base64.b64decode(packet['wire_base64']))
        with self.assertRaises(AdmissionError):
            self.evidence.write_once(auth, wire, proof)
        self.assertEqual(packet, json.loads((operation / 'request.json').read_bytes()))

    def test_each_sync_failure_consumes_operation_without_automatic_resume(self):
        for fail_at in range(1, 7):
            with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as directory:
                evidence = custody.PrivateEvidence(directory, self.verify)
                auth, wire, proof, _, _ = self.fixture()
                real_sync, count = os.fsync, []
                def fsync(fd):
                    count.append(fd)
                    if len(count) == fail_at:
                        raise OSError('PRIVATE-9911')
                    real_sync(fd)
                with patch.object(custody.os, 'fsync', fsync), self.assertRaises(AdmissionError) as error:
                    evidence.write_once(auth, wire, proof)
                self.assertEqual('private-custody-unavailable-or-consumed', str(error.exception))
                self.assertTrue((Path(directory) / auth.operation_id).is_dir())
                with self.assertRaises(AdmissionError):
                    evidence.write_once(auth, wire, proof)

    def test_partial_write_and_missing_completion_are_unknown_after_restart(self):
        auth, wire, proof, response, reader = self.fixture()
        with patch.object(custody.os, 'write', return_value=0), self.assertRaises(AdmissionError):
            self.evidence.write_once(auth, wire, proof)
        restarted = custody.PrivateEvidence(self.directory, self.verify)
        result = restarted.exact_readback(auth, response, verify_response=lambda a, r: True, reader=reader)
        self.assertEqual({'disposition': 'unknown-readback-required'}, result)
        self.assertEqual([], reader.calls)

    def test_root_operation_and_file_symlinks_or_hardlinks_are_rejected(self):
        auth, wire, proof, response, reader = self.fixture()
        linked = self.directory / 'linked'
        real = self.directory / 'real'
        real.mkdir(mode=0o700)
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaises(AdmissionError):
            custody.PrivateEvidence(linked, self.verify).write_once(auth, wire, proof)
        operation = self.directory / auth.operation_id
        operation.symlink_to(real, target_is_directory=True)
        with self.assertRaises(AdmissionError):
            self.evidence.write_once(auth, wire, proof)
        operation.unlink()
        self.evidence.write_once(auth, wire, proof)
        request = operation / 'request.json'
        saved = request.read_bytes()
        request.unlink()
        outside = real / 'request'
        outside.write_bytes(saved)
        outside.chmod(0o600)
        request.symlink_to(outside)
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))
        request.unlink()
        os.link(outside, request)
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_public_modes_fail_closed(self):
        auth, wire, proof, response, reader = self.fixture()
        self.directory.chmod(0o755)
        with self.assertRaises(AdmissionError):
            self.evidence.write_once(auth, wire, proof)
        self.directory.chmod(0o700)
        self.evidence.write_once(auth, wire, proof)
        (self.directory / auth.operation_id / 'request.json').chmod(0o644)
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_foreign_origin_publisher_source_generation_or_authorization_is_rejected(self):
        for changes in [{'origin_producer_id': 43}, {'publisher_actor_id': 42}, {'origin_source': 'f' * 40},
                        {'generation': 'f' * 64}, {'head_sha': 'f' * 40}, {'repository_id': ROOT_ID + 1},
                        {'run_attempt': True}, {'authorization_sha256': 'f' * 64}]:
            with self.subTest(changes=changes):
                auth, wire, proof, _, _ = self.fixture()
                with self.assertRaises(AdmissionError):
                    self.evidence.write_once(auth, wire, replace(proof, **changes))
                self.assertFalse((self.directory / auth.operation_id).exists())

    def test_unverified_or_mutated_native_descriptor_never_creates_files(self):
        auth, wire, proof, _, _ = self.fixture()
        self.evidence.verify_native = lambda a, p: False
        with self.assertRaises(AdmissionError):
            self.evidence.write_once(auth, wire, proof)
        def mutate(a, p):
            p.before_fields['body'] = 'f' * 64
            return True
        self.evidence.verify_native = mutate
        with self.assertRaises(AdmissionError):
            self.evidence.write_once(auth, wire, proof)
        self.assertFalse((self.directory / auth.operation_id).exists())

    def test_changed_final_bytes_and_malformed_json_never_reach_custody(self):
        auth, wire, proof, _, _ = self.fixture()
        for bad in [wire + b' ', wire.replace(b'Review', b'Other'), b'[]', b'\xff']:
            with self.assertRaises(AdmissionError):
                self.evidence.write_once(auth, bad, proof)
        self.assertEqual([], list(self.directory.iterdir()))

    def test_provider_response_is_optional_bounded_bound_and_private(self):
        auth, wire, proof, _, _ = self.fixture()
        response = json_bytes({'summary': 'Private model result', 'count': 1})
        proof = replace(proof, provider_response_sha256=digest(response))
        self.evidence.write_once(auth, wire, proof, response)
        packet = json.loads((self.directory / auth.operation_id / 'request.json').read_bytes())
        self.assertEqual(response, base64.b64decode(packet['provider_base64']))
        self.assertNotIn('Private model result', str(self.evidence))

    def test_authentication_material_and_headers_cannot_be_inputs(self):
        for raw in [b'{"headers":{"Authorization":"Private"}}', b'{"access_token":"Private"}',
                    b'{"body":"Authorization: Private"}', b'{"body":"ghp_aaaaaaaaaaaaaaaaaaaaaaaa"}',
                    b'x' * (custody.MAX_PROVIDER + 1)]:
            auth, wire, proof, _, _ = self.fixture()
            with self.assertRaises(AdmissionError) as error:
                self.evidence.write_once(auth, wire, replace(proof, provider_response_sha256=digest(raw)), raw)
            self.assertNotIn('Private', str(error.exception))
            self.assertFalse((self.directory / auth.operation_id).exists())

    def test_unknown_create_response_never_searches_or_uses_equal_text_as_proof(self):
        for operation in ['issue.create', 'pull.create', 'review.create', 'comment.create', 'inline.create']:
            auth, wire, proof, _, reader = self.fixture(operation)
            self.evidence.write_once(auth, wire, proof)
            self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, None, reader))
            self.assertEqual([], reader.calls)

    def test_false_response_origin_locator_or_unverified_receipt_stays_unknown(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        for changes in [{'origin_producer_id': 43}, {'publisher_actor_id': 42}, {'generation': 'f' * 64},
                        {'payload_sha256': 'f' * 64}, {'number': 8}, {'operation_id': 'f' * 64},
                        {'response_evidence_sha256': None}]:
            self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, replace(response, **changes), reader))
        self.assertEqual([], reader.calls)
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.evidence.exact_readback(
            auth, response, verify_response=lambda a, r: False, reader=reader))
        self.assertEqual([], reader.calls)

    def test_parent_actor_head_body_or_inline_drift_prevents_exact_receipt(self):
        for area in ['parent', 'actor', 'head', 'body', 'inline', 'inline-actor', 'inline-review']:
            with tempfile.TemporaryDirectory() as directory:
                evidence = custody.PrivateEvidence(directory, self.verify)
                auth, wire, proof, response, reader = self.fixture()
                evidence.write_once(auth, wire, proof)
                parent = reader.values['repos/' + ROOT + '/pulls/7']
                value = reader.values['repos/' + ROOT + '/pulls/7/reviews/123']
                comment = reader.values['repos/' + ROOT + '/pulls/7/reviews/123/comments?per_page=100&page=1'][0]
                if area == 'parent': parent['url'] += '/foreign'
                if area == 'actor': value['user'] = {'id': 42}
                if area == 'head': parent['head']['sha'] = 'f' * 40
                if area == 'body': value['body'] = 'Different'
                if area == 'inline': comment['body'] = 'Different'
                if area == 'inline-actor': comment['user'] = {'id': 43}
                if area == 'inline-review': comment['pull_request_review_id'] = 99
                result = evidence.exact_readback(auth, response, verify_response=lambda a, r: True, reader=reader)
                self.assertEqual({'disposition': 'unknown-readback-required'}, result, area)

    def test_review_inline_pagination_must_finish_and_have_exact_members(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        key = 'repos/' + ROOT + '/pulls/7/reviews/123/comments?per_page=100&page=2'
        reader.values.pop(key)
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))
        reader.values[key] = [dict(reader.values[key.replace('page=2', 'page=1')][0], id=789)]
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_edit_must_preserve_original_origin_and_unedited_field_hashes(self):
        auth, wire, proof, response, reader = self.fixture('issue.edit')
        foreign = replace(auth, facts=replace(auth.facts, object_origin_producer_id=43))
        with self.assertRaises(AdmissionError):
            self.evidence.write_once(foreign, wire, replace(proof, authorization_sha256=digest(json_bytes(asdict(foreign)))))
        self.evidence.write_once(auth, wire, proof)
        reader.values['repos/' + ROOT + '/issues/7']['body'] = 'Unrequested edit'
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_native_proof_and_object_are_rechecked_after_reads(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        calls = []
        def native(a, p):
            calls.append(True)
            return len(calls) == 1
        self.evidence.verify_native = native
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))
        self.assertEqual(2, len(calls))
        self.evidence.verify_native = self.verify
        key = 'repos/' + ROOT + '/pulls/7/reviews/123'
        original = copy.deepcopy(reader.values[key])
        count = []
        def changed():
            count.append(True)
            return original if len(count) == 1 else dict(original, body='Later edit')
        reader.values[key] = changed
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_equal_inline_text_with_changed_object_ids_is_not_stable_readback(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        key = 'repos/' + ROOT + '/pulls/7/reviews/123/comments?per_page=100&page=1'
        original = copy.deepcopy(reader.values[key])
        calls = []
        def replacements():
            calls.append(True)
            return original if len(calls) == 1 else [dict(original[0], id=789)]
        reader.values[key] = replacements
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_nested_native_proof_mutation_during_gets_cannot_change_custody_binding(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        held = []
        def native(a, p):
            held.append(p)
            return True
        self.evidence.verify_native = native
        original_get = reader.get
        def get(path):
            held[0].before_fields['title'] = 'f' * 64
            return original_get(path)
        reader.get = get
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))

    def test_corruption_or_authorization_drift_cannot_reconstruct_effect(self):
        auth, wire, proof, response, reader = self.fixture()
        self.evidence.write_once(auth, wire, proof)
        changed = replace(auth, facts=replace(auth.facts, origin_producer_id=43))
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(changed, response, reader))
        request = self.directory / auth.operation_id / 'request.json'
        request.write_bytes(request.read_bytes() + b' ')
        self.assertEqual({'disposition': 'unknown-readback-required'}, self.readback(auth, response, reader))
        self.assertEqual([], reader.calls)


if __name__ == '__main__':
    unittest.main()
