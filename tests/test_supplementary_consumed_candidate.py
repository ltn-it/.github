"""Sup candidate funding survives PR, input, base, source and recovery drift."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import workflow_control as control

REPO = 'ltn-it/ansible-collection-supplementary'
HEAD, OLD_BASE = 'd' * 40, 'b' * 40


def legacy_claim():
    return {'id': 41, 'name': 'Protected Exact-Revision Codex result',
            'app': {'id': 15368, 'slug': 'github-actions'}, 'head_sha': HEAD,
            'external_id': 'mlx90-exact-revision:v5:' + 'b' * 64 + ':10',
            'status': 'completed', 'conclusion': 'neutral'}


def producer():
    return {'id': 10, 'repository': {'id': 1103407173}, 'workflow_id': 332570404,
            'path': '.github/workflows/release-bot-exact-head-review.yml',
            'event': 'workflow_dispatch', 'head_branch': 'main', 'head_sha': OLD_BASE,
            'display_title': f'Exact-Revision Codex PR #7 {OLD_BASE}..{HEAD}',
            'actor': dict(zip(('login', 'id', 'type'), control.RELEASE)),
            'triggering_actor': dict(zip(('login', 'id', 'type'), control.RELEASE))}


class SupplementaryConsumedCandidateTests(unittest.TestCase):
    def api(self, checks=(), runs=()):
        api = Mock()
        def pages(path, key):
            if key == 'check_runs': return list(checks)
            if key == 'workflow_runs': return list(runs)
            if key == 'jobs':
                return [{'run_id': 12, 'name': 'Protected current revision',
                         'steps': [{'name': 'Reserve protected Codex request', 'status': 'completed',
                                    'conclusion': 'failure'}]}]
            raise AssertionError(path)
        api.pages.side_effect = pages
        api.call.return_value = producer()
        return api

    def test_fresh_candidate_has_no_claim_and_does_not_write(self):
        api = self.api()
        control.supplementary_consumed_candidate(api, REPO, HEAD, 20)
        api.call.assert_not_called()

    def test_neutral_failed_and_unknown_legacy_results_are_consumed_across_input_drift(self):
        for conclusion in ('neutral', 'failure', None, 'success'):
            api = self.api([legacy_claim() | {'conclusion': conclusion}])
            with self.subTest(conclusion=conclusion), self.assertRaisesRegex(
                    control.ControlError, 'consumed-legacy'):
                control.supplementary_consumed_candidate(api, REPO, HEAD, 20)
            self.assertTrue(all(not call.kwargs for call in api.call.call_args_list))

    def test_foreign_app_marker_does_not_consume_a_fresh_candidate(self):
        api = self.api([legacy_claim() | {'app': {'id': 1, 'slug': 'other'}}])
        control.supplementary_consumed_candidate(api, REPO, HEAD, 20)

    def test_unknown_marker_or_producer_does_not_grant_a_slot(self):
        for fields in ({'repository': {'id': 1}}, {'head_sha': 'a' * 40}, {'actor': {}},
                       {'workflow_id': 1}, {'display_title': 'missing candidate'}):
            api = self.api([legacy_claim()])
            api.call.return_value = producer() | fields
            with self.subTest(fields=fields), self.assertRaisesRegex(control.ControlError, 'origin-unknown'):
                control.supplementary_consumed_candidate(api, REPO, HEAD, 20)
        with self.assertRaisesRegex(control.ControlError, 'claim-unknown'):
            control.supplementary_consumed_candidate(self.api([legacy_claim() | {'external_id': 'bad'}]),
                                                     REPO, HEAD, 20)

    def test_common_consumption_does_not_depend_on_same_pr_or_base(self):
        owner = {'id': 12, 'head_sha': HEAD, 'run_attempt': 1, 'workflow_id': 77, 'status': 'completed',
                 'workflow_url': f'https://api.github.com/repos/{REPO}/actions/required_workflows/77',
                 'path': control.WORKFLOW, 'pull_requests': []}
        with self.assertRaisesRegex(control.ControlError, 'consumed-native'):
            control.supplementary_consumed_candidate(self.api(runs=[owner]), REPO, HEAD, 20)

    def test_recovery_locator_does_not_bypass_legacy_consumption(self):
        api = self.api([legacy_claim()])
        native = {'id': 20, 'head_sha': HEAD, 'run_attempt': 1, 'workflow_id': 77,
                  'workflow_url': f'https://api.github.com/repos/{REPO}/actions/required_workflows/77',
                  'path': control.WORKFLOW}
        api.call.side_effect = lambda path: native if path.endswith('/20') else producer()
        with patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': 'e' * 64}), self.assertRaisesRegex(
                control.ControlError, 'consumed-legacy'):
            control.reserve_request(api, REPO, {'head': {'sha': HEAD}}, 'f' * 40, 20, 1)

    def test_other_five_and_modulix_do_not_change(self):
        for name in ('foundational', 'rhel', 'ubuntu', 'ocp', 'cloud'):
            api = Mock()
            control.supplementary_consumed_candidate(api, 'ltn-it/ansible-collection-' + name, HEAD, 20)
            self.assertEqual([], api.mock_calls)
        api = Mock()
        control.supplementary_consumed_candidate(api, 'ltn-it/modulix-validation', HEAD, 20)
        self.assertEqual([], api.mock_calls)


if __name__ == '__main__':
    unittest.main()
