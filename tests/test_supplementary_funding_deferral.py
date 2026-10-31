"""A late native follower cannot turn a known pre-sink abort into a claim."""
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import workflow_control as control
import workflow_supplementary_deferral as deferral
from test_workflow_control import pull as complete_pull

REPO, SOURCE = deferral.REPO, 'f' * 40


class SupplementaryFundingDeferralTests(unittest.TestCase):
    def fixture(self):
        pull = complete_pull()
        for role in ('base', 'head'):
            pull[role]['repo']['full_name'] = REPO
        head = pull['head']['sha']
        native = {'id': 20, 'head_sha': head, 'status': 'in_progress', 'run_attempt': 1, 'workflow_id': 77,
                  'workflow_url': f'https://api.github.com/repos/{REPO}/actions/required_workflows/77',
                  'path': control.WORKFLOW, 'pull_requests': [copy.deepcopy(pull)]}
        pending = native | {'id': 21, 'status': 'pending'}
        operation = {'version': 1, 'source_sha': SOURCE, 'binding': control.binding(pull)}
        job_context = {'check_run_id': 501, 'workflow_sha': SOURCE,
                       'workflow_repository': control.SOURCE, 'workflow_file_path': control.WORKFLOW}
        proof = {'version': 1, 'repository': REPO, 'repository_id': 1103407173,
                 'source_sha': SOURCE, 'run': 20, 'attempt': 1, 'job': 501,
                 'binding': operation['binding'], 'operation_sha256': control.digest(operation),
                 'step': 'Reserve protected Codex request', 'generation': {'current': native, 'later': [pending]},
                 'outcome': 'guarded-before-request', 'provider_request': False, 'reservation_created': False}
        steps = [{'name': name, 'status': 'completed', 'conclusion': 'skipped'}
                 for name in sorted(control.FUNDING_STEPS | deferral.MODEL_STEPS)]
        for step in steps:
            if step['name'] == proof['step']: step['conclusion'] = 'success'
        steps += [{'name': deferral.UPLOAD, 'status': 'completed', 'conclusion': 'success'},
                  {'name': deferral.STOP, 'status': 'completed', 'conclusion': 'failure'}]
        job = {'id': 501, 'run_id': 20, 'run_attempt': 1, 'head_sha': head, 'status': 'completed',
               'name': 'Protected current revision', 'conclusion': 'failure', 'steps': steps}
        api = Mock()
        api.native_job_log.return_value = json.dumps(job_context, indent=2)
        return api, pull, native, pending, operation, job_context, proof, job

    def records(self, operation, proof):
        def record(_api, repo, owner, name, filename):
            self.assertEqual(REPO, repo)
            self.assertEqual(20, owner['id'])
            self.assertEqual(1, int(name.rsplit('-', 1)[1]))
            self.assertIn(filename, {'control-operation.json', 'control-funding-deferred.json'})
            return copy.deepcopy(operation if filename == 'control-operation.json' else proof)
        return patch.object(control, 'artifact_record', side_effect=record)

    def test_follower_arriving_after_preflight_or_at_final_fence_emits_no_effect(self):
        for arrival in (2, 3):
            api, pull, native, pending, operation, context, _, _ = self.fixture()
            reads = 0
            def pages(path, key):
                nonlocal reads
                if key == 'check_runs' or '/workflows/332570404/' in path: return []
                self.assertEqual('workflow_runs', key)
                reads += 1
                return [native, pending] if reads >= arrival else [native]
            api.pages.side_effect = pages
            api.call.side_effect = lambda path: native if path.endswith('/20') else pending
            self.assertFalse(control.supplementary_defer_generation(api, REPO, pull, native))
            previous = Path.cwd()
            with tempfile.TemporaryDirectory() as temp:
                try:
                    os.chdir(temp)
                    output = Path(temp) / 'output'
                    with (self.subTest(arrival=arrival),
                          patch.dict(os.environ, {'NATIVE_JOB': json.dumps(context), 'GITHUB_OUTPUT': str(output)}),
                          patch.object(control, 'supplementary_qualification_genesis'),
                          patch.object(control, 'supplementary_live_funding_bases')):
                        self.assertFalse(control.reserve_or_defer(api, REPO, pull, SOURCE, native, operation,
                                                                 'Reserve protected Codex request'))
                    saved = json.loads(Path('control-funding-deferred.json').read_bytes())
                    self.assertEqual(False, saved['provider_request'])
                    self.assertEqual(False, saved['reservation_created'])
                    self.assertEqual('deferred=true\n', output.read_text())
                    self.assertEqual({key: pending[key] for key in ('id', 'run_attempt', 'head_sha', 'status',
                                                                  'workflow_id', 'workflow_url', 'path')},
                                     saved['generation']['later'][0])
                finally:
                    os.chdir(previous)
            self.assertTrue(all(not call.kwargs for call in api.call.call_args_list))

    def test_exact_native_no_effect_proof_is_readonly_and_not_a_review(self):
        api, _, native, _, operation, _, proof, job = self.fixture()
        owner = native | {'status': 'completed', 'conclusion': 'failure'}
        with self.records(operation, proof):
            self.assertEqual(proof, deferral.verify(api, REPO, owner, 1, job, SOURCE))
        api.call.assert_not_called()
        self.assertEqual('failure', job['conclusion'])

    def test_missing_changed_or_consumed_proof_never_grants_an_unspent_slot(self):
        for changes in ({'source_sha': 'e' * 40}, {'run': 21}, {'attempt': 2}, {'job': 502},
                        {'provider_request': True}, {'reservation_created': True}, {'outcome': 'unknown'},
                        {'operation_sha256': 'e' * 64}, {'binding': {}}, {'generation': {}}, {'version': True}):
            api, _, native, _, operation, _, proof, job = self.fixture()
            with (self.subTest(changes=changes), self.records(operation, proof | changes),
                  self.assertRaises(control.ControlError)):
                deferral.verify(api, REPO, native | {'status': 'completed'}, 1, job, SOURCE)
        api, _, native, _, operation, _, proof, job = self.fixture()
        with patch.object(control, 'artifact_record', side_effect=control.ControlError('missing-artifact')):
            with self.assertRaisesRegex(control.ControlError, 'missing-artifact'):
                deferral.verify(api, REPO, native, 1, job, SOURCE)
        for name in deferral.MODEL_STEPS | {deferral.UPLOAD, deferral.STOP}:
            changed = copy.deepcopy(job)
            for step in changed['steps']:
                if step['name'] == name: step['conclusion'] = 'success' if name != deferral.UPLOAD else 'failure'
            with (self.subTest(step=name), self.records(operation, proof), self.assertRaises(control.ControlError)):
                deferral.verify(api, REPO, native, 1, changed, SOURCE)

    def test_actual_defining_source_log_is_mandatory(self):
        api, _, native, _, operation, _, proof, job = self.fixture()
        api.native_job_log.return_value = 'unknown or expired source'
        with self.records(operation, proof), self.assertRaisesRegex(control.ControlError, 'actual-defining-source'):
            deferral.verify(api, REPO, native, 1, job, SOURCE)

    def test_real_deferral_with_one_hundred_megabyte_metadata_followers_is_bounded(self):
        self.large_deferral(100)

    def test_one_hundred_one_later_witnesses_remain_bounded_without_truncating_history(self):
        self.large_deferral(101)

    def test_unselected_malformed_or_foreign_follower_cannot_hide_behind_max_witness(self):
        for change in ({'run_attempt': None}, {'run_attempt': True}, {'workflow_url': 'https://untrusted.invalid'},
                       {'path': control.WORKFLOW + '@' + 'x' * 600}):
            with self.subTest(change=change), self.assertRaises(control.ControlError):
                self.large_deferral(101, corrupt=change)

    def test_even_unselected_full_native_metadata_drift_still_denies_before_projection(self):
        with self.assertRaisesRegex(control.ControlError, 'follower-drift'):
            self.large_deferral(101, drift=True)

    def large_deferral(self, count, corrupt=None, drift=False):
        api, pull, native, _, operation, context, _, job = self.fixture()
        message = 'large irrelevant native commit message' + 'x' * (1024 * 1024)
        native['head_commit'] = {'message': message}
        followers = [native | {'id': identifier, 'status': 'pending'} for identifier in range(21, 21 + count)]
        if corrupt:
            followers[1] = followers[1] | corrupt
        rows = [native, *followers]
        by_id = {row['id']: row for row in rows}
        api.call.side_effect = lambda path: (by_id[22] | {'head_commit': {'message': 'changed after inventory'}}
                                           if drift and path.endswith('/22') else by_id[int(path.rsplit('/', 1)[1])])
        api.pages.side_effect = lambda path, key: [] if key == 'check_runs' or '/workflows/332570404/' in path else rows
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            try:
                os.chdir(temporary)
                with patch.dict(os.environ, {'NATIVE_JOB': json.dumps(context),
                                             'GITHUB_OUTPUT': str(Path(temporary) / 'output')}):
                    self.assertFalse(control.reserve_or_defer(api, REPO, pull, SOURCE, native, operation,
                                                             'Reserve protected Codex request'))
                raw = Path('control-funding-deferred.json').read_bytes()
                self.assertLess(len(raw), 8192)
                saved = json.loads(raw)
                self.assertFalse(saved['provider_request'])
                self.assertFalse(saved['reservation_created'])
                self.assertNotIn('head_commit', saved['generation']['current'])
                self.assertEqual(20 + count, saved['generation']['later'][0]['id'])
                self.assertEqual(1, len(saved['generation']['later']))
                # The compact proof remains usable by the real native-history
                # verifier, without reclassifying it as a successful review.
                owner = native | {'status': 'completed', 'conclusion': 'failure'}
                final = job | {'id': 502, 'name': 'Current revision review', 'steps': []}
                def record(_api, repo, run, name, filename):
                    return saved if filename == 'control-funding-deferred.json' else operation
                with (patch.object(control, 'artifact_record', side_effect=record),
                      patch.object(api, 'pages', return_value=[job, final])):
                    control.supplementary_unfunded_common(api, REPO, owner, native['head_sha'], source=SOURCE)
            finally:
                os.chdir(previous)
        # Every full native follower was authenticated BEFORE projection.
        self.assertTrue({f'repos/{REPO}/actions/runs/{identifier}' for identifier in range(21, 21 + count)}
                        <= {call.args[0] for call in api.call.call_args_list})
        self.assertTrue(all(not call.kwargs for call in api.call.call_args_list))

    def test_near_limit_unicode_operation_does_not_duplicate_binding_in_receipt(self):
        api, pull, native, pending, operation, context, _, job = self.fixture()
        low, high = 0, 65536
        while low < high:
            middle = (low + high + 1) // 2
            candidate = operation | {'binding': control.binding(pull | {'body': '\u0800' * middle})}
            if len(control.canonical(candidate)) <= control.MAX_OPERATION_BYTES:
                low = middle
            else:
                high = middle - 1
        pull['body'] = '\u0800' * low
        operation['binding'] = control.binding(pull)
        self.assertLessEqual(len(control.canonical(operation)), control.MAX_OPERATION_BYTES)
        self.assertGreater(len(control.canonical(operation)), control.MAX_OPERATION_BYTES - 6)
        original_operation = control.canonical(operation)
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            try:
                os.chdir(temporary)
                with patch.dict(os.environ, {'NATIVE_JOB': json.dumps(context),
                                             'GITHUB_OUTPUT': str(Path(temporary) / 'output')}):
                    deferral.emit(REPO, pull, SOURCE, operation, native, 'Reserve protected Codex request',
                                  control.SupplementaryDeferred({'current': native, 'later': [pending]}))
                raw = Path('control-funding-deferred.json').read_bytes()
                self.assertLess(len(raw), 8192)
                saved = json.loads(raw)
                self.assertEqual(2, saved['version'])
                self.assertNotIn('binding', saved)
                self.assertEqual({'number': pull['number'], 'base': pull['base']['sha'],
                                  'head': pull['head']['sha']}, saved['subject'])
                self.assertEqual(control.digest(operation), saved['operation_sha256'])
                self.assertEqual(original_operation, control.canonical(operation))
                with self.records(operation, saved):
                    self.assertEqual(saved, deferral.verify(api, REPO,
                        native | {'status': 'completed', 'conclusion': 'failure'}, 1, job, SOURCE))
                for changed in (saved | {'subject': saved['subject'] | {'body': ''}},
                                saved | {'subject': saved['subject'] | {'head': 'e' * 40}},
                                saved | {'operation_sha256': 'e' * 64}):
                    with (self.records(operation, changed), self.assertRaises(control.ControlError)):
                        deferral.verify(api, REPO, native | {'status': 'completed'}, 1, job, SOURCE)
                tampered_operation = operation | {'binding': operation['binding'] | {'body': 'tampered'}}
                with (self.records(tampered_operation, saved), self.assertRaises(control.ControlError)):
                    deferral.verify(api, REPO, native | {'status': 'completed'}, 1, job, SOURCE)
            finally:
                os.chdir(previous)

    def test_complete_history_accepts_only_proven_no_effect_original(self):
        api, pull, native, _, operation, _, proof, job = self.fixture()
        final = job | {'id': 502, 'name': 'Current revision review', 'steps': []}
        api.pages.return_value = [job, final]
        with self.records(operation, proof):
            control.supplementary_unfunded_common(api, REPO, native | {'status': 'completed'},
                                                 pull['head']['sha'], source=SOURCE)
        with self.assertRaises(control.ControlError):
            control.supplementary_unfunded_common(api, REPO, native | {'status': 'completed'}, pull['head']['sha'])

    def test_deferred_copilot_invocation_never_reuses_evidence_to_write_acceptance(self):
        api, pull, native, _, operation, context, _, _ = self.fixture()
        pull['user'] = {'login': 'litroc', 'id': 76040632, 'type': 'User'}
        operation['binding'] = control.binding(pull)
        api.call.side_effect = lambda path: native if '/actions/runs/' in path else pull
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temp:
            try:
                os.chdir(temp)
                event = Path(temp) / 'event.json'
                event.write_text(json.dumps({'pull_request': pull}))
                environment = {'GITHUB_REPOSITORY': REPO, 'GITHUB_RUN_ID': '20', 'GITHUB_RUN_ATTEMPT': '1',
                               'GITHUB_EVENT_PATH': str(event), 'NATIVE_JOB': json.dumps(context),
                               'COMMON_QUALITY_RESULT': 'success', 'REVIEW_RESULT': 'failure', 'REVIEW_DEFERRED': 'true'}
                with (patch.dict(os.environ, environment), patch.object(sys, 'argv', ['control', 'finalize']),
                      patch.object(control, 'API', return_value=api),
                      patch.object(control, 'current_repository', return_value=1103407173),
                      patch.object(control, 'operation_record', return_value=operation),
                      patch.object(control, 'policy', return_value={'mode': 'reference'}),
                      patch.object(control, 'check_quality', return_value={}),
                      patch.object(control, 'validate_signal'), patch.object(control, 'native_conversation_guard', return_value={}),
                      patch.object(control, 'complete_generated_lock_quality'),
                      patch.object(control, 'verify_existing_route', return_value={'review': 9}) as evidence):
                    with self.assertRaisesRegex(control.ControlError, 'deferred-invocation'):
                        control.main()
                    evidence.assert_not_called()
                self.assertFalse(Path('control-proof.json').exists())
            finally:
                os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
