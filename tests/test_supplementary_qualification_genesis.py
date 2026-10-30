"""Sup-native pre-funding proof; no private Management artifact or host clock."""
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import workflow_control as control

REPO = 'ltn-it/ansible-collection-supplementary'
PARENT, HEAD, BASE, FEATURE, SOURCE = (char * 40 for char in 'abcde')
ACTOR = {'login': 'litroc', 'id': 76040632, 'type': 'User'}


class SupplementaryQualificationGenesisTests(unittest.TestCase):
    def test_new_funder_requires_actual_both_protected_v2_bases(self):
        api = Mock()
        repo = {'id': 1103407173, 'full_name': REPO}
        records = {f'repos/{REPO}': repo,
                   f'repos/{REPO}/branches/main': {'protected': True, 'commit': {'sha': BASE}},
                   f'repos/{REPO}/branches/develop': {'protected': True, 'commit': {'sha': PARENT}},
                   f'repos/{REPO}/git/ref/heads/main': {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': BASE}},
                   f'repos/{REPO}/git/ref/heads/develop': {'ref': 'refs/heads/develop', 'object': {'type': 'commit', 'sha': PARENT}}}
        versions = {BASE: 2, PARENT: 2, HEAD: 2}
        api.call.side_effect = lambda path: records[path]
        api.file.side_effect = lambda repo, path, revision: json.dumps({
            'version': versions[revision], 'repository': REPO}).encode()
        pull = {'base': {'ref': 'develop', 'sha': PARENT}, 'head': {'sha': HEAD}}
        control.supplementary_live_funding_bases(api, REPO, pull)
        for branch in (BASE, PARENT):
            versions[branch] = 1
            with self.subTest(branch=branch), self.assertRaisesRegex(control.ControlError, 'both-live-v2'):
                control.supplementary_live_funding_bases(api, REPO, pull)
            versions[branch] = 2
        with self.assertRaisesRegex(control.ControlError, 'live-base-drift'):
            control.supplementary_live_funding_bases(api, REPO, {'base': {'ref': 'develop', 'sha': HEAD}})
        versions[HEAD] = 1
        with self.assertRaisesRegex(control.ControlError, 'candidate-must-include-v2'):
            control.supplementary_live_funding_bases(api, REPO, pull)

    def fixture(self):
        bot = dict(zip(('login', 'id', 'type'), control.RELEASE))
        pull = {'user': bot, 'base': {'ref': 'develop', 'sha': PARENT},
                'head': {'ref': 'qualification/supplementary-funding-v2', 'sha': HEAD}}
        merged = {'number': 7, 'state': 'closed', 'merged': True, 'merge_commit_sha': PARENT,
                  'merged_at': '2026-10-29T01:44:39Z', 'merged_by': ACTOR,
                  'base': {'ref': 'develop', 'sha': BASE, 'repo': {'id': 1103407173}},
                  'head': {'sha': FEATURE, 'repo': {'id': 1103407173}}}
        events = [{'id': 90, 'event': 'merged', 'created_at': merged['merged_at'],
                   'commit_id': PARENT, 'actor': ACTOR},
                  {'id': 91, 'event': 'closed', 'created_at': merged['merged_at'], 'actor': ACTOR}]
        retired = {'id': 30336823454, 'repository': {'id': 1103407173}, 'workflow_id': 299841777,
                   'path': '.github/workflows/release-prepare.yml', 'event': 'push', 'head_branch': 'main',
                   'head_sha': 'f43f74c6904397af7ab48bacf13e6f8519d354d5', 'run_attempt': 1,
                   'status': 'completed', 'conclusion': 'failure', 'updated_at': '2026-07-28T07:01:39Z'}
        original = {'version': 1, 'repository': REPO, 'mode': 'reference', 'quality': ['fixture']}
        expected = original | {'supplementary_funding_contract': {
            'version': 2, 'candidate_scope': 'repository-head', 'legacy_claims': 'consumed',
            'unknown_outcomes': 'consumed_uncertain'}}
        content = (json.dumps(expected, indent=2, ensure_ascii=True) + '\n').encode()
        changed = {'status': 'ahead', 'total_commits': 1, 'files': [{
            'filename': '.lit/workflow-control.json', 'status': 'modified',
            'sha': hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()}]}
        records = {f'repos/{REPO}': {'id': 1103407173, 'full_name': REPO},
                   f'repos/{REPO}/branches/main': {'protected': True, 'commit': {'sha': BASE}},
                   f'repos/{REPO}/branches/develop': {'protected': True, 'commit': {'sha': PARENT}},
                   f'repos/{REPO}/git/ref/heads/main': {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': BASE}},
                   f'repos/{REPO}/git/ref/heads/develop': {'ref': 'refs/heads/develop', 'object': {'type': 'commit', 'sha': PARENT}},
                   f'repos/{REPO}/git/commits/{HEAD}': {'sha': HEAD, 'parents': [{'sha': PARENT}]},
                   f'repos/{REPO}/git/commits/{PARENT}': {'sha': PARENT, 'parents': [{'sha': BASE}, {'sha': FEATURE}]},
                   f'repos/{REPO}/pulls/7': merged,
                   f'repos/{REPO}/actions/runs/30336823454': retired,
                   f'repos/{REPO}/actions/runs/30336823454/attempts/1': copy.deepcopy(retired),
                   f'repos/{REPO}/compare/{PARENT}...{HEAD}': changed}
        api = Mock()
        api.call.side_effect = lambda path: copy.deepcopy(records[path])
        api.pages.side_effect = lambda path: copy.deepcopy(events if path.endswith('/events') else [merged])
        api.file.side_effect = lambda repo, path, revision: content if revision == HEAD else json.dumps(original).encode()
        return api, pull, records, events, content

    def test_current_parent_and_native_merge_exclude_old_unknown_without_knowing_its_candidate(self):
        api, pull, _, _, _ = self.fixture()
        proof = control.supplementary_qualification_genesis(api, REPO, pull, SOURCE)
        self.assertEqual('UNKNOWN', proof['provider_outcome'])
        self.assertEqual('CONSUMED_UNCERTAIN', proof['disposition'])
        self.assertIsNone(proof['candidate_sha'])
        self.assertEqual(PARENT, proof['parent'])
        self.assertTrue(all(not call.kwargs for call in api.call.call_args_list))

    def test_another_qualification_branch_cannot_recreate_the_canonical_genesis(self):
        for branch in ('qualification/funding-v2', 'qualification/supplementary-funding-v2-copy'):
            api, pull, _, _, _ = self.fixture()
            pull['head']['ref'] = branch
            with self.subTest(branch=branch), self.assertRaisesRegex(control.ControlError, 'single-canonical-genesis'):
                control.supplementary_qualification_genesis(api, REPO, pull, SOURCE)
            api.call.assert_not_called()
            api.pages.assert_not_called()
            api.file.assert_not_called()

    def test_commit_dates_are_never_used_instead_of_native_merge(self):
        api, pull, records, _, _ = self.fixture()
        records[f'repos/{REPO}/pulls/7']['merged_at'] = '2026-07-27T01:00:00Z'
        with self.assertRaises(control.ControlError):
            control.supplementary_qualification_genesis(api, REPO, pull, SOURCE)

    def test_only_exact_single_current_parent_and_governance_diff_are_allowed(self):
        for problem in ('parents', 'file', 'sha', 'count', 'protected', 'branch', 'author'):
            api, pull, records, _, _ = self.fixture()
            if problem == 'parents': records[f'repos/{REPO}/git/commits/{HEAD}']['parents'].append({'sha': BASE})
            elif problem == 'file': records[f'repos/{REPO}/compare/{PARENT}...{HEAD}']['files'][0]['filename'] = 'README.md'
            elif problem == 'sha': records[f'repos/{REPO}/compare/{PARENT}...{HEAD}']['files'][0]['sha'] = BASE
            elif problem == 'count': records[f'repos/{REPO}/compare/{PARENT}...{HEAD}']['total_commits'] = 2
            elif problem == 'protected': records[f'repos/{REPO}/branches/develop']['protected'] = False
            elif problem == 'branch': pull['base']['ref'] = 'main'
            elif problem == 'author': pull['user'] = ACTOR
            with self.subTest(problem=problem), self.assertRaises(control.ControlError):
                control.supplementary_qualification_genesis(api, REPO, pull, SOURCE)

    def test_forged_native_merge_actor_and_squash_rebase_locator_drift_fail(self):
        for problem in ('actor', 'head', 'base', 'parents', 'merge'):
            api, pull, records, events, _ = self.fixture()
            if problem == 'actor': events[0]['actor'] = ACTOR | {'id': 1}
            elif problem == 'head': records[f'repos/{REPO}/pulls/7']['head']['sha'] = HEAD
            elif problem == 'base': records[f'repos/{REPO}/pulls/7']['base']['sha'] = HEAD
            elif problem == 'parents': records[f'repos/{REPO}/git/commits/{PARENT}']['parents'].pop()
            elif problem == 'merge': events[0]['commit_id'] = HEAD
            with self.subTest(problem=problem), self.assertRaises(control.ControlError):
                control.supplementary_qualification_genesis(api, REPO, pull, SOURCE)

    def test_recent_unknown_attempt_cannot_be_excluded_by_original_old_timestamp(self):
        api, pull, records, _, _ = self.fixture()
        retired = records[f'repos/{REPO}/actions/runs/30336823454']
        retired['run_attempt'] = 2
        records[f'repos/{REPO}/actions/runs/30336823454/attempts/2'] = retired | {
            'updated_at': '2026-10-30T01:00:00Z'}
        with self.assertRaisesRegex(control.ControlError, 'must-follow-retired-unknown'):
            control.supplementary_qualification_genesis(api, REPO, pull, SOURCE)

    def test_no_private_management_artifact_query_is_needed_or_allowed(self):
        api, pull, _, _, _ = self.fixture()
        control.supplementary_qualification_genesis(api, REPO, pull, SOURCE)
        for method in (api.call, api.pages, api.file):
            for call in method.call_args_list:
                self.assertNotIn('github-management-lit', str(call))
                self.assertNotIn('/artifacts', str(call))


if __name__ == '__main__':
    unittest.main()
