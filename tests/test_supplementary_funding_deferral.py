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
                    self.assertEqual(pending, saved['generation']['later'][0])
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

    def test_complete_history_accepts_only_proven_no_effect_original(self):
        api, pull, native, _, operation, _, proof, job = self.fixture()
        final = job | {'id': 502, 'name': 'Current revision review', 'steps': []}
        api.pages.return_value = [job, final]
        with self.records(operation, proof):
            control.supplementary_unfunded_common(api, REPO, native | {'status': 'completed'},
                                                 pull['head']['sha'], source=SOURCE)
        with self.assertRaises(control.ControlError):
            control.supplementary_unfunded_common(api, REPO, native | {'status': 'completed'}, pull['head']['sha'])


if __name__ == '__main__':
    unittest.main()
