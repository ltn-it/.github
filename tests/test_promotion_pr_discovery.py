"""Actual provider discovery regression; native proof readers remain mandatory."""
import copy
import json
import os
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import workflow_control as control

FIXTURE = json.loads((Path(__file__).parent / 'fixtures/ubuntu607-promotion-discovery.json').read_text())
REPO = FIXTURE['repo']
PREFIX = f'repos/{REPO}'
CLOSED = PREFIX + '/pulls?state=closed&base=develop'


class Provider(control.API):
    """Production pagination over projected provider DTOs, with modeled filler."""
    def __init__(self):
        self.fixture = copy.deepcopy(FIXTURE)
        self.reads = []
        self.incomplete = False
        self.inventory = copy.deepcopy(FIXTURE['closed'])

    def call(self, path, *, method='GET', data=None):
        if method != 'GET' or data is not None:
            raise AssertionError('Read-only producer.')
        self.reads.append(path)
        if path == PREFIX:
            return {'id': 1268102957, 'full_name': REPO, 'owner': {'login': 'ltn-it', 'id': 54334171},
                    'archived': False, 'disabled': False}
        if path.startswith(CLOSED + '&per_page=100&page='):
            page = int(path.rsplit('=', 1)[1])
            if self.incomplete:
                return [copy.deepcopy(self.inventory[0])] * 100
            return copy.deepcopy(self.inventory[(page - 1) * 100:page * 100])
        if '/commits/' in path and '/pulls?' in path:
            merge = path.split('/commits/')[1].split('/')[0]
            page = int(path.rsplit('=', 1)[1])
            return copy.deepcopy(self.fixture['associations'][merge]) if page == 1 else []
        if path.startswith(PREFIX + '/pulls/'):
            return copy.deepcopy(self.fixture['direct'][path.rsplit('/', 1)[1]])
        raise AssertionError(path)

    def git(self, _objects, *args, binary=False):
        if args[0] == 'merge-base':
            return self.fixture['base']
        if args[0] == 'rev-list':
            return '\n'.join(self.fixture['commits'])
        if args[:3] == ('show', '-s', '--format=%P'):
            return ' '.join(self.fixture['parents'][args[3]])
        if args[0] == 'merge-tree':
            return 'b403215513fff93bd23be7400b128d26870e1688'
        if args[0] == 'diff' and binary:
            return b'reviewed integration payload transport'
        raise AssertionError(args)


class PromotionDiscoveryTests(unittest.TestCase):
    def setUp(self):
        # The wrapper's linked-worktree Git variables must not redirect the
        # temporary bare repository used by the real promotion producer.
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        clean = patch.dict(os.environ, environment, clear=True)
        clean.start()
        self.addCleanup(clean.stop)

    def ingress(self, api, commit=None, fallback=None):
        with patch('workflow_subject.git', side_effect=api.git):
            return control.promotion_ingress_pull(api, REPO, commit or FIXTURE['commits'][0],
                                                  Path('/unused'), fallback if fallback is not None else {})

    def promotion(self, api):
        return control.promotion_ingress(api, REPO,
            {'base': {'sha': FIXTURE['base']}, 'head': {'sha': FIXTURE['head']}},
            {'accepted_sources': ['015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f']})

    def test_successor_policy_retains_both_genuine_previous_sources(self):
        policy = json.loads((Path(__file__).resolve().parents[1] / '.lit/workflow-control.json').read_text())
        result = control.policy_value(policy, 'ltn-it/.github', 'f' * 40)
        for source in ('015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f',
                       '498ad94e16dc852672c671e89f0c7acc7db57bc3'):
            self.assertIn(source, result['accepted_sources'])
        self.assertEqual(30, len(result['accepted_sources']))

    def test_actual_missing_association_consumes_closed_provider_and_all_native_proofs(self):
        api, observed = Provider(), []
        def native(_api, repo, ingress, config):
            self.assertIs(_api, api)
            self.assertEqual(repo, REPO)
            self.assertEqual(config['accepted_sources'], ['015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f'])
            observed.append(ingress['number'])
            return {'route': 'ancestry' if ingress['number'] == 605 else 'copilot', 'run': ingress['number']}
        with patch('workflow_subject.fetch_objects'), patch('workflow_subject.git', side_effect=api.git), \
                patch('workflow_devtools_bootstrap.promotion_context', return_value=None), \
                patch('workflow_validation_transition.prepare', return_value=None), \
                patch.object(control, 'check_native_control', side_effect=native):
            result = self.promotion(api)
        self.assertEqual([604, 605, 606], observed)
        self.assertEqual(observed, [entry['pull'] for entry in result['ingress']])
        self.assertEqual(1, sum(path.startswith(CLOSED) for path in api.reads))
        self.assertEqual({'base', 'head', 'integration_tree', 'diff_sha256', 'ingress'}, set(result))

    def test_second_missing_merge_reuses_one_complete_snapshot(self):
        api, cache = Provider(), {}
        api.fixture['associations'][FIXTURE['commits'][1]] = []
        self.assertEqual(604, self.ingress(api, fallback=cache)['number'])
        self.assertEqual(605, self.ingress(api, FIXTURE['commits'][1], cache)['number'])
        self.assertEqual(1, sum(path.startswith(CLOSED) for path in api.reads))

    def test_normal_nonempty_association_does_not_read_inventory_or_parents(self):
        api = Provider()
        with patch('workflow_subject.git', side_effect=AssertionError('No fallback parent read.')):
            result = control.promotion_ingress_pull(api, REPO, FIXTURE['commits'][1], Path('/unused'), {})
        self.assertEqual(605, result['number'])
        self.assertFalse(any(path.startswith(CLOSED) for path in api.reads))

    def test_nonempty_contradictory_or_ambiguous_association_never_falls_back(self):
        for rows in ([FIXTURE['direct']['605']], [FIXTURE['direct']['604']] * 2):
            with self.subTest(rows=len(rows)):
                api = Provider()
                api.fixture['associations'][FIXTURE['commits'][0]] = copy.deepcopy(rows)
                with self.assertRaisesRegex(control.ControlError, 'promotion-unattributed-ingress'):
                    self.ingress(api)
                self.assertFalse(any(path.startswith(CLOSED) for path in api.reads))

    def test_missing_or_ambiguous_inventory_match_is_denied(self):
        for ambiguous in (False, True):
            api = Provider()
            if ambiguous:
                row = copy.deepcopy(FIXTURE['direct']['604'])
                row.update(id=999999, number=999)
                api.inventory.append(row)
            else:
                api.inventory = [p for p in api.inventory if p['number'] != 604]
            with self.subTest(ambiguous=ambiguous), self.assertRaisesRegex(
                    control.ControlError, 'promotion-unattributed-ingress'):
                self.ingress(api)

    def test_wrong_parent_repository_state_or_head_denies_direct_binding(self):
        for field in ('parent', 'first-parent', 'base', 'inventory-base', 'repository', 'state', 'merged', 'head', 'number'):
            api = Provider()
            direct = api.fixture['direct']['604']
            if field == 'parent':
                api.fixture['parents'][FIXTURE['commits'][0]][1] = 'f' * 40
            elif field == 'first-parent':
                api.fixture['parents'][FIXTURE['commits'][0]][0] = 'f' * 40
            elif field == 'base':
                direct['base']['sha'] = 'f' * 40
            elif field == 'inventory-base':
                next(p for p in api.inventory if p['number'] == 604)['base']['sha'] = 'f' * 40
            elif field == 'repository':
                direct['base']['repo']['id'] = 1
            elif field == 'state':
                direct['state'] = 'open'
            elif field == 'merged':
                direct['merged'] = False
            elif field == 'head':
                direct['head']['sha'] = 'f' * 40
            else:
                direct['number'] = 999
            with self.subTest(field=field), self.assertRaisesRegex(
                    control.ControlError, 'promotion-fallback-parent-or-identity-drift'):
                self.ingress(api)

    def test_inventory_duplicates_wrong_repository_or_open_row_deny(self):
        for field in ('duplicate', 'repository', 'state'):
            api = Provider()
            if field == 'duplicate':
                api.inventory.append(copy.deepcopy(api.inventory[0]))
            elif field == 'repository':
                api.inventory[0]['base']['repo']['id'] = 1
            else:
                api.inventory[0]['state'] = 'open'
            with self.subTest(field=field), self.assertRaisesRegex(
                    control.ControlError, 'promotion-pull-inventory-shape'):
                self.ingress(api)

    def test_oversized_inventory_and_invalid_merge_shape_deny(self):
        api = Provider()
        with patch.object(control, 'MAX_PROOF_BYTES', 1), self.assertRaisesRegex(
                control.ControlError, 'promotion-pull-inventory-size'):
            self.ingress(api)
        for parents in ([FIXTURE['base']], ['f' * 40] * 3):
            api = Provider()
            api.fixture['parents'][FIXTURE['commits'][0]] = parents
            with self.subTest(parents=len(parents)), self.assertRaisesRegex(
                    control.ControlError, 'promotion-fallback-parent-or-identity-drift'):
                self.ingress(api)

    def test_matching_first_page_does_not_accept_unfinished_inventory(self):
        api = Provider()
        api.incomplete = True
        with self.assertRaisesRegex(control.ControlError, 'native-pagination-incomplete'):
            self.ingress(api)
        self.assertEqual(100, sum(path.startswith(CLOSED) for path in api.reads))
        self.assertNotIn(PREFIX + '/pulls/604', api.reads)

    def test_complete_multiple_pages_are_read_before_unique_match_acceptance(self):
        api = Provider()
        filler = copy.deepcopy(api.inventory[1])
        filler.update(merge_commit_sha='e' * 40)
        for number in range(1000, 1200):
            row = copy.deepcopy(filler)
            row.update(number=number, id=number)
            api.inventory.append(row)
        self.assertEqual(604, self.ingress(api)['number'])
        self.assertEqual(3, sum(path.startswith(CLOSED) for path in api.reads))

    def test_native_proof_failure_is_not_reclassified_or_skipped(self):
        api = Provider()
        with patch('workflow_subject.fetch_objects'), patch('workflow_subject.git', side_effect=api.git), \
                patch('workflow_devtools_bootstrap.promotion_context', return_value=None), \
                patch('workflow_validation_transition.prepare', return_value=None), \
                patch.object(control, 'check_native_control', side_effect=control.ControlError('real-native-proof-denied')):
            with self.assertRaisesRegex(control.ControlError, 'real-native-proof-denied'):
                self.promotion(api)


if __name__ == '__main__':
    unittest.main()
