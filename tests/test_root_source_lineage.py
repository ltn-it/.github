"""Actual central policy composed with original public ingress captures.

Git responses below are transport projections, not native admission evidence.
The policy, ancestry reader and ordinary ingress reader remain unmodified.
"""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from test_root_ancestry import NativeCapture, PREFIX
import workflow_control as control
import workflow_root_ancestry as ancestry

SOURCE = '198f11c00825a52c0ebc53d3a5e4ff0bb4b4b9a4'
ROOT = Path(__file__).resolve().parents[1]


def installed_policy():
    return control.policy_value(json.loads((ROOT / '.lit/workflow-control.json').read_bytes()),
                                ancestry.ROOT, SOURCE)


class CompleteCapture(NativeCapture):
    def __init__(self):
        super().__init__()
        self.extra = json.loads((ROOT / 'tests/fixtures/root-ancestry-989-quality.json').read_bytes())
        self.records.update(self.extra['records'])
        self.records[PREFIX + '/branches/develop']['commit']['sha'] = SOURCE
        self.records[PREFIX + '/git/ref/heads/develop']['object']['sha'] = SOURCE
        for number in (986, 987, 989):
            pull = self.records[f'{PREFIX}/pulls/{number}']
            self.records[f'{PREFIX}/commits/{pull["merge_commit_sha"]}/pulls'] = [copy.deepcopy(pull)]

    def artifact(self, api, repo, run, name, filename):
        if run['id'] == 41031455732:
            if getattr(api, 'delegate', api) is not self or repo != ancestry.ROOT:
                raise AssertionError('Wrong original 989 producer.')
            expected = 'control-proof.json' if name == 'control-proof-5' else 'control-operation.json'
            if filename != expected:
                raise AssertionError('Wrong original 989 file.')
            return copy.deepcopy(self.extra['decoded_artifacts'][name])
        return super().artifact(api, repo, run, name, filename)


class SourceLineageTests(unittest.TestCase):
    def test_real_policy_reaches_original_baseline_and_all_ordinary_ingress(self):
        api = CompleteCapture()
        policy = installed_policy()
        promotion = {'base': {'sha': ancestry.MAIN}, 'head': {'sha': SOURCE}}
        with patch.object(control, 'artifact_record', side_effect=api.artifact):
            results = [ancestry.control_for_ingress(api, ancestry.ROOT, promotion,
                api.call(f'{PREFIX}/pulls/{number}'), policy) for number in (986, 987, 989)]
        self.assertEqual(['ancestry', 'copilot', 'copilot'], [row['route'] for row in results])
        self.assertEqual([ancestry.SOURCE] * 3, [row['source_sha'] for row in results])
        self.assertEqual('failure', results[0]['historical_failure']['conclusion'])
        self.assertEqual((41031455732, 5, 123985218006),
                         tuple(results[2][key] for key in ('run', 'attempt', 'job')))

    def test_full_normal_promotion_consumes_policy_without_injected_accepted_sources(self):
        api = CompleteCapture()
        merges = [api.records[f'{PREFIX}/pulls/{number}']['merge_commit_sha'] for number in (986, 987, 989)]
        tree = self.extra_tree(api)
        def git(_objects, *args, binary=False):
            if args[0] == 'merge-base':
                return ancestry.MAIN
            if args[0] == 'rev-list':
                return '\n'.join(merges)
            if args[0] == 'merge-tree':
                return tree
            if args[0] == 'diff' and binary:
                return b'captured nonempty integration transport'
            raise AssertionError(args)
        clean_git_environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        with patch.dict(os.environ, clean_git_environment, clear=True), \
                patch.object(control, 'artifact_record', side_effect=api.artifact), \
                patch('workflow_subject.fetch_objects'), patch('workflow_subject.git', side_effect=git):
            value = control.promotion_ingress(api, ancestry.ROOT,
                {'base': {'sha': ancestry.MAIN}, 'head': {'sha': SOURCE}}, installed_policy())
        self.assertEqual([986, 987, 989], [row['pull'] for row in value['ingress']])
        self.assertEqual(tree, value['integration_tree'])

    @staticmethod
    def extra_tree(api):
        return api.records[f'{PREFIX}/git/commits/{SOURCE}']['tree']['sha']

    def test_missing015_and_unknown_sources_still_fail_closed(self):
        api = CompleteCapture()
        policy = installed_policy()
        policy['accepted_sources'] = [item for item in policy['accepted_sources'] if item != ancestry.SOURCE]
        with self.assertRaisesRegex(control.ControlError, 'root-ancestry-fixed-baseline-required'):
            ancestry.control_for_ingress(api, ancestry.ROOT,
                {'base': {'sha': ancestry.MAIN}, 'head': {'sha': SOURCE}},
                api.call(PREFIX + '/pulls/986'), policy)
        for repo in (ancestry.ROOT, 'ltn-it/ansible-collection-foundational'):
            value = {'version': 1, 'repository': repo, 'mode': 'enforce',
                     'quality': [{'workflow': '.github/workflows/product.yml', 'job': 'product'}],
                     'accepted_sources': ['f' * 40]}
            with self.subTest(repo=repo), self.assertRaisesRegex(control.ControlError, 'consumer-cannot-admit'):
                control.policy_value(value, repo, SOURCE)


if __name__ == '__main__':
    unittest.main()
