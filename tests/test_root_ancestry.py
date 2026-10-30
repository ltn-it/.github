"""Original public Native captures; no network, issuer, or activation claim."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import workflow_control as control
import workflow_root_ancestry as ancestry

FIXTURE = Path(__file__).with_name('fixtures') / 'root-ancestry-985-986.json'
CONFIG = {'accepted_sources': [ancestry.SOURCE]}
PROMOTION = {'base': {'sha': ancestry.MAIN}, 'head': {'sha': '84aec48f715a93d2e1e4e819aa16f5a591d79e29'}}
PREFIX = f'repos/{ancestry.ROOT}'


class NativeCapture:
    def __init__(self):
        self.value = json.loads(FIXTURE.read_text())
        self.records = self.value['records']
        self.calls = []

    def call(self, path, *, method='GET', data=None):
        if method != 'GET' or data is not None:
            raise AssertionError('No write is allowed in this reader.')
        self.calls.append(path)
        return copy.deepcopy(self.records[path])

    def pages(self, path, key=None):
        value = self.call(path)
        if key is None:
            return value
        if value['total_count'] != len(value[key]):
            raise AssertionError('Captured page is not complete.')
        return value[key]

    def native_job_log(self, repo, job):
        if repo != ancestry.ROOT:
            raise AssertionError('Foreign log.')
        return self.value['job_logs'][str(job)]['projection']

    def artifact(self, api, repo, run, name, filename):
        if api is not self or repo != ancestry.ROOT or run['id'] not in {
                ancestry.MAIN_RUN, ancestry.FAILED_RUN, 41018682524}:
            raise AssertionError('Unknown captured artifact origin.')
        expected = 'control-operation.json' if name.startswith('control-operation') else 'control-proof.json'
        if filename != expected:
            raise AssertionError('Foreign artifact file.')
        return copy.deepcopy(self.value['decoded_artifacts'][name])


class RootAncestryTests(unittest.TestCase):
    def verify(self, api):
        with patch.object(control, 'artifact_record', side_effect=api.artifact):
            return ancestry.control_for_ingress(api, ancestry.ROOT, PROMOTION,
                                               api.call(f'{PREFIX}/pulls/986'), CONFIG)

    def test_original_reader_reproduces_the_actual_failure_without_retrying(self):
        api = NativeCapture()
        with patch.object(control, 'artifact_record', side_effect=api.artifact):
            with self.assertRaisesRegex(control.ControlError, 'ingress-protected-run-not-successful'):
                control.check_native_control(api, ancestry.ROOT, api.call(f'{PREFIX}/pulls/986'), CONFIG)

    def test_only_the_already_accepted_main_tree_supplies_the_new_typed_baseline(self):
        api = NativeCapture()
        result = self.verify(api)
        self.assertEqual('protected-main-ancestry-baseline/v1', result['kind'])
        self.assertEqual('failure', result['historical_failure']['conclusion'])
        self.assertEqual('unchanged', result['historical_failure']['budget_disposition'])
        self.assertEqual(ancestry.MAIN_PROOF, result['accepted_main']['proof_artifact'])
        self.assertEqual(ancestry.TREE, result['tree'])
        self.assertFalse(result['source_admission_granted'])
        self.assertFalse(result['model_funding_granted'])
        self.assertNotIn('proof_artifact', result['historical_failure'])

    def test_real_product_ingress_987_still_uses_the_ordinary_complete_native_reader(self):
        api = NativeCapture()
        with patch.object(control, 'artifact_record', side_effect=api.artifact):
            result = ancestry.control_for_ingress(api, ancestry.ROOT, PROMOTION,
                                                api.call(f'{PREFIX}/pulls/987'), CONFIG)
        self.assertEqual((41018682524, 3, 'copilot'), (result['run'], result['attempt'], result['route']))
        self.assertEqual(ancestry.SOURCE, result['source_sha'])

    def test_identity_refs_parents_trees_and_original_native_generation_must_all_match(self):
        changes = [
            (f'{PREFIX}', lambda x: x.update(id=1)),
            (f'{PREFIX}/branches/main', lambda x: x.update(protected=False)),
            (f'{PREFIX}/git/ref/heads/develop', lambda x: x['object'].update(sha='f' * 40)),
            (f'{PREFIX}/git/commits/{ancestry.MERGE}', lambda x: x['tree'].update(sha='f' * 40)),
            (f'{PREFIX}/git/commits/{ancestry.MERGE}', lambda x: x['parents'].reverse()),
            (f'{PREFIX}/git/commits/{ancestry.MAIN}', lambda x: x['parents'].pop()),
            (f'{PREFIX}/pulls/985', lambda x: x.update(merged=False)),
            (f'{PREFIX}/pulls/986', lambda x: x['user'].update(id=1)),
            (f'{PREFIX}/pulls/986', lambda x: x.update(created_at='2026-10-29T13:00:00Z')),
            (f'{PREFIX}/actions/runs/{ancestry.MAIN_RUN}', lambda x: x.update(conclusion='failure')),
            (f'{PREFIX}/actions/runs/{ancestry.MAIN_RUN}', lambda x: x.update(run_attempt=True)),
            (f'{PREFIX}/actions/runs/{ancestry.FAILED_RUN}', lambda x: x.update(run_attempt=2)),
            (f'{PREFIX}/actions/runs/{ancestry.FAILED_RUN}', lambda x: x.update(conclusion='success')),
            (f'{PREFIX}/actions/runs/{ancestry.MAIN_RUN}/artifacts', lambda x: x['artifacts'][0].update(expired=True)),
        ]
        for path, change in changes:
            api = NativeCapture()
            change(api.records[path])
            with self.subTest(path=path), self.assertRaises(control.ControlError):
                self.verify(api)

    def test_forged_main_proof_approval_or_failed_operation_cannot_supply_authority(self):
        for target, change in [
            ('control-proof-1', lambda x: x.update(source_sha='f' * 40)),
            ('control-proof-1', lambda x: x['binding'].update(head='f' * 40)),
            ('control-proof-1', lambda x: x['evidence'].update(integration_tree='f' * 40)),
            ('control-operation-1', lambda x: x['binding'].update(number=123)),
        ]:
            api = NativeCapture()
            change(api.value['decoded_artifacts'][target])
            with self.subTest(target=target), self.assertRaises(control.ControlError):
                self.verify(api)
        api = NativeCapture()
        api.records[f'{PREFIX}/actions/runs/{ancestry.MAIN_RUN}/approvals'][0]['user']['id'] = 1
        with self.assertRaises(control.ControlError):
            self.verify(api)

    def test_a_semantic_failure_or_premerge_closure_is_never_the_ancestry_case(self):
        for error in ['ControlError: actual-review-finding', 'ControlError: pull-not-reviewable']:
            api = NativeCapture()
            for job in api.value['job_logs'].values():
                value = job['projection']
                if error == 'ControlError: actual-review-finding':
                    value = value.replace('ControlError: pull-not-reviewable', error)
                else:
                    value = value.replace('2026-10-29T15:00:57.6072205Z', '2026-10-29T14:59:00Z')
                job['projection'] = value
            with self.subTest(error=error), self.assertRaises(control.ControlError):
                self.verify(api)

    def test_changed_product_acceptance_remains_blocking(self):
        api = NativeCapture()
        api.value['decoded_artifacts']['control-proof-3']['binding']['head'] = 'f' * 40
        with patch.object(control, 'artifact_record', side_effect=api.artifact):
            with self.assertRaises(control.ControlError):
                ancestry.control_for_ingress(api, ancestry.ROOT, PROMOTION,
                    api.call(f'{PREFIX}/pulls/987'), CONFIG)

    def test_a_new_generation_during_the_native_reads_invalidates_the_disposition(self):
        api = NativeCapture()
        original = api.call
        count = 0
        def changed(path, **kwargs):
            nonlocal count
            value = original(path, **kwargs)
            if path == f'{PREFIX}/actions/runs/{ancestry.FAILED_RUN}':
                count += 1
                if count > 1:
                    value['run_attempt'] = 2
            return value
        api.call = changed
        with self.assertRaisesRegex(control.ControlError, 'native-generation-drift'):
            self.verify(api)

    def test_original_artifact_expiry_during_reads_is_not_hidden_by_a_cached_result(self):
        api = NativeCapture()
        original = api.pages
        count = 0
        def changed(path, key=None):
            nonlocal count
            value = original(path, key)
            if path == f'{PREFIX}/actions/runs/{ancestry.MAIN_RUN}/artifacts':
                count += 1
                if count > 1:
                    next(row for row in value if row['id'] == ancestry.MAIN_PROOF)['expired'] = True
            return value
        api.pages = changed
        with self.assertRaisesRegex(control.ControlError, 'native-generation-drift'):
            self.verify(api)


if __name__ == '__main__':
    unittest.main()
