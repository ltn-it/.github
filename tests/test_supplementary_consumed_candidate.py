"""Sup candidate funding survives PR, input, base, source and recovery drift."""
import copy
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
    def test_native_mutex_is_candidate_scoped_for_sup_and_preserves_other_pr_keys(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/change-control-required.yml').read_text()
        self.assertIn("github.repository_id == '1103407173'", workflow)
        self.assertIn("format('sup-funded-review-{0}-{1}', github.repository_id, github.event.pull_request.head.sha)", workflow)
        self.assertIn("format('protected-control-{0}-{1}', github.repository_id, github.event.pull_request.number)", workflow)
        self.assertIn("cancel-in-progress: ${{ github.repository_id != '1103407173' }}", workflow)

    def test_funding_contract_is_typed_and_cannot_be_declared_for_another_target(self):
        contract = {'version': 2, 'candidate_scope': 'repository-head', 'legacy_claims': 'consumed',
                    'unknown_outcomes': 'consumed_uncertain'}
        policy = {'version': 1, 'repository': REPO, 'mode': 'reference',
                  'quality': [{'workflow': '.github/workflows/collection-ci.yml', 'job': 'Collection / Fast'}],
                  'accepted_sources': [], 'supplementary_funding_contract': contract}
        result = control.policy_value(copy.deepcopy(policy), REPO, 'f' * 40)
        self.assertEqual(contract, result['supplementary_funding_contract'])
        for malformed in (None, [], contract | {'version': 2.0}, contract | {'unknown_outcomes': 'clean'},
                          contract | {'legacy_claims': 'retry'}):
            with self.subTest(malformed=malformed), self.assertRaisesRegex(control.ControlError, 'contract-shape'):
                control.policy_value(copy.deepcopy(policy) | {'supplementary_funding_contract': malformed}, REPO, 'f' * 40)
        foreign = 'ltn-it/modulix-validation'
        with self.assertRaisesRegex(control.ControlError, 'contract-shape'):
            control.policy_value(copy.deepcopy(policy) | {'repository': foreign}, foreign, 'f' * 40)

    def api(self, checks=(), runs=(), jobs=None, legacy_runs=(), legacy_jobs=None):
        api = Mock()
        def pages(path, key):
            if key == 'check_runs': return list(checks)
            if '/actions/workflows/332570404/runs' in path: return list(legacy_runs)
            if key == 'workflow_runs': return list(runs)
            if key == 'jobs':
                if '/runs/10/' in path and legacy_jobs is not None: return legacy_jobs
                if isinstance(jobs, dict): return jobs[int(path.split('/attempts/')[1].split('/')[0])]
                if jobs is not None: return jobs
                return [{'id': 101, 'run_id': 12, 'run_attempt': 1, 'head_sha': HEAD,
                         'status': 'completed', 'name': 'Protected current revision',
                         'steps': [{'name': 'Reserve protected Codex request', 'status': 'completed',
                                    'conclusion': 'failure'},
                                   {'name': 'Request current Copilot review', 'status': 'completed',
                                    'conclusion': 'skipped'}]},
                        {'id': 102, 'run_id': 12, 'run_attempt': 1, 'head_sha': HEAD,
                         'status': 'completed', 'name': 'Current revision review'}]
            raise AssertionError(path)
        api.pages.side_effect = pages
        api.call.return_value = producer()
        return api

    def test_fresh_candidate_has_no_claim_and_does_not_write(self):
        api = self.api()
        control.supplementary_consumed_candidate(api, REPO, HEAD, 20)
        api.call.assert_not_called()

    def test_hidden_custom_check_does_not_hide_durable_old_base_legacy_funding(self):
        native = producer() | {'status': 'completed', 'run_attempt': 1}
        jobs = [{'id': 111, 'run_id': 10, 'run_attempt': 1, 'head_sha': OLD_BASE, 'status': 'completed',
                 'conclusion': 'failure', 'name': 'Current revision review', 'steps': [
                     {'name': name, 'status': 'completed', 'conclusion': 'success'} for name in (
                         'Reserve one immutable review input or reuse its protected PASS',
                         'Run protected history-free Exact-Revision Codex review')]}]
        api = self.api(legacy_runs=[native], legacy_jobs=jobs)
        api.call.return_value = native
        with self.assertRaisesRegex(control.ControlError, 'durable-candidate-consumed'):
            control.supplementary_consumed_candidate(api, REPO, HEAD, 20)
        self.assertTrue(all(not call.kwargs for call in api.call.call_args_list))

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

    def common(self):
        return {'id': 12, 'head_sha': HEAD, 'run_attempt': 1, 'workflow_id': 77, 'status': 'completed',
                'workflow_url': f'https://api.github.com/repos/{REPO}/actions/required_workflows/77',
                'path': control.WORKFLOW, 'pull_requests': []}

    def overlapping(self, **changes):
        pull = {'number': 7, 'base': {'sha': OLD_BASE}, 'head': {'sha': HEAD}}
        active = self.common() | {'id': 20, 'status': 'in_progress', 'pull_requests': [pull]}
        pending = active | {'id': 21, 'status': 'pending', 'conclusion': None} | changes
        api = self.api(runs=[active, pending], jobs=[])
        api.call.side_effect = lambda path: active if path.endswith('/20') else pending
        return api, pull, active, pending

    def test_overlap_yields_unfunded_then_newest_generation_reserves_once(self):
        api, pull, active, pending = self.overlapping()
        self.assertTrue(control.supplementary_defer_generation(api, REPO, pull, active))
        self.assertTrue(all(not call.kwargs for call in api.call.call_args_list))
        old = active | {'status': 'completed', 'conclusion': 'failure'}
        current = pending | {'status': 'in_progress'}
        protected = {'id': 101, 'run_id': 20, 'run_attempt': 1, 'head_sha': HEAD,
                     'status': 'completed', 'conclusion': 'failure', 'name': 'Protected current revision',
                     'steps': [{'name': name, 'status': 'completed', 'conclusion': 'skipped'}
                               for name in control.FUNDING_STEPS]}
        final = protected | {'id': 102, 'name': 'Current revision review', 'steps': []}
        api = self.api(runs=[old, current], jobs=[protected, final])
        api.call.return_value = current
        self.assertFalse(control.supplementary_defer_generation(api, REPO, pull, current))
        with (patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': ''}),
              patch.object(control, 'supplementary_qualification_genesis'),
              patch.object(control, 'supplementary_live_funding_bases')):
            self.assertEqual(21, control.reserve_request(api, REPO, pull, 'f' * 40, 21, 1))
        consumed = protected | {'steps': [
            {'name': name, 'status': 'completed', 'conclusion': 'success'}
            for name in control.FUNDING_STEPS]}
        api = self.api(runs=[old], jobs=[consumed, final])
        with self.assertRaisesRegex(control.ControlError, 'consumed-native'):
            control.supplementary_consumed_candidate(api, REPO, HEAD, 22)

    def test_yield_does_not_assert_follower_source_mutex_or_provider_state(self):
        for changes in ({'status': 'queued'}, {'status': 'waiting'}, {'status': 'in_progress'},
                        {'run_attempt': 2}, {'status': 'completed', 'conclusion': 'failure'}):
            api, pull, active, _ = self.overlapping(**changes)
            with self.subTest(changes=changes):
                self.assertTrue(control.supplementary_defer_generation(api, REPO, pull, active))
        api, pull, active, _ = self.overlapping(id=19)
        self.assertFalse(control.supplementary_defer_generation(api, REPO, pull, active))
        self.assertFalse(control.supplementary_defer_generation(Mock(), 'ltn-it/modulix-validation', {}, {}))

    def test_yield_rejects_native_drift_and_unassignable_common_generation(self):
        api, pull, active, pending = self.overlapping()
        api.call.side_effect = lambda path: active if path.endswith('/20') else pending | {'status': 'in_progress'}
        with self.assertRaisesRegex(control.ControlError, 'follower-drift'):
            control.supplementary_defer_generation(api, REPO, pull, active)
        api, pull, active, _ = self.overlapping(workflow_url='https://example.invalid/unknown')
        with self.assertRaisesRegex(control.ControlError, 'source-unassignable'):
            control.supplementary_defer_generation(api, REPO, pull, active)

    def test_workflow_skips_both_funding_boundaries_and_model_then_fails_deferred_run(self):
        import yaml
        workflow = yaml.safe_load((Path(__file__).resolve().parents[1]
                                   / '.github/workflows/change-control-required.yml').read_text())
        steps = workflow['jobs']['review']['steps']
        generation = next(index for index, step in enumerate(steps) if step.get('id') == 'generation')
        guarded = control.FUNDING_STEPS | {
            'Protected exact-revision Codex review', 'Install complete-request budget gateway',
            'Export protected native Codex evidence', 'Persist protected Codex receipt',
            'Verify applicable native review or governed exemption'}
        selected = {step['name']: (index, step) for index, step in enumerate(steps) if step['name'] in guarded}
        self.assertEqual(guarded, set(selected))
        for name, (index, step) in selected.items():
            with self.subTest(step=name):
                self.assertGreater(index, generation)
                self.assertIn("steps.generation.outputs.deferred != 'true'", step['if'])
        deferred = next(step for step in steps if step['name'].startswith('Leave deferred invocation'))
        self.assertIn("steps.generation.outputs.deferred == 'true'", deferred['if'])
        self.assertIn("steps.request.outputs.deferred == 'true'", deferred['if'])
        self.assertIn("steps.reserve.outputs.deferred == 'true'", deferred['if'])
        self.assertIn('exit 1', deferred['run'])
        self.assertNotIn('upload-artifact', deferred.get('uses', ''))

    def test_recovery_locator_without_authenticated_slot_cannot_bypass_common_consumption(self):
        api, pull, active, _ = self.overlapping()
        consumed = self.common()
        api = self.api(runs=[active, consumed])
        with self.assertRaisesRegex(control.ControlError, 'authenticated-exact-slot'):
            control.supplementary_consumed_candidate(api, REPO, HEAD, 20, pull=pull,
                                                     source='f' * 40, recovery={})

    def test_missing_or_partial_original_funding_job_is_unknown_not_unspent(self):
        job = {'id': 101, 'run_id': 12, 'run_attempt': 1, 'head_sha': HEAD,
               'status': 'completed', 'name': 'Protected current revision',
               'steps': [{'name': 'Reserve protected Codex request', 'status': 'completed', 'conclusion': 'skipped'}]}
        for jobs in ([], [job], [job | {'name': 'Current revision review'}]):
            with self.subTest(jobs=jobs), self.assertRaises(control.ControlError):
                control.supplementary_consumed_candidate(self.api(runs=[self.common()], jobs=jobs), REPO, HEAD, 20)

    def test_duplicate_or_malformed_native_inventory_cannot_hide_a_claim(self):
        foreign = legacy_claim() | {'app': {'id': 1, 'slug': 'other'}}
        for checks in ([foreign, foreign], [foreign | {'id': False}]):
            with self.subTest(checks=checks), self.assertRaises(control.ControlError):
                control.supplementary_consumed_candidate(self.api(checks=checks), REPO, HEAD, 20)
        with self.assertRaises(control.ControlError):
            control.supplementary_consumed_candidate(self.api(runs=[self.common(), self.common()]), REPO, HEAD, 20)

    def test_real_pagination_rejects_overlapping_pages_and_total_drift_sup_only(self):
        for problem in ('overlap', 'total'):
            api = control.API()
            first = [{'id': index + 1} for index in range(100)]
            second = [{'id': 100 if problem == 'overlap' else 101}]
            api.call = Mock(side_effect=[{'total_count': 101, 'check_runs': first},
                                        {'total_count': 102 if problem == 'total' else 101, 'check_runs': second}])
            with self.subTest(problem=problem), self.assertRaises(control.ControlError):
                api.pages(f'repos/{REPO}/commits/{HEAD}/check-runs', 'check_runs')
        api = control.API()
        api.call = Mock(return_value={'total_count': 2, 'check_runs': [{'id': 1}, {'id': 1}]})
        self.assertEqual(2, len(api.pages('repos/ltn-it/modulix-validation/commits/' + HEAD + '/check-runs', 'check_runs')))

    def test_unassignable_common_source_is_not_ignored(self):
        owner = self.common() | {'workflow_url': 'https://example.invalid/unknown'}
        with self.assertRaises(control.ControlError):
            control.supplementary_consumed_candidate(self.api(runs=[owner]), REPO, HEAD, 20)

    def test_verifier_only_attempt_requires_a_complete_original_no_funding_observation(self):
        original = {'id': 101, 'run_id': 12, 'run_attempt': 1, 'head_sha': HEAD, 'status': 'completed',
                    'name': 'Protected current revision', 'steps': [
                        {'name': name, 'status': 'completed', 'conclusion': 'skipped'}
                        for name in control.FUNDING_STEPS]}
        final = {'id': 102, 'run_id': 12, 'run_attempt': 1, 'head_sha': HEAD, 'status': 'completed',
                 'name': 'Current revision review'}
        verifier = final | {'id': 103, 'run_attempt': 2}
        owner = self.common() | {'run_attempt': 2}
        control.supplementary_consumed_candidate(self.api(runs=[owner], jobs={
            1: [original, final], 2: [verifier]}), REPO, HEAD, 20)
        with self.assertRaises(control.ControlError):
            control.supplementary_consumed_candidate(self.api(runs=[owner], jobs={
                1: [final], 2: [verifier]}), REPO, HEAD, 20)

    def test_recovery_locator_does_not_bypass_legacy_consumption(self):
        api = self.api([legacy_claim()])
        native = {'id': 20, 'head_sha': HEAD, 'run_attempt': 1, 'workflow_id': 77,
                  'workflow_url': f'https://api.github.com/repos/{REPO}/actions/required_workflows/77',
                  'path': control.WORKFLOW}
        api.call.side_effect = lambda path: native if path.endswith('/20') else producer()
        with patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': 'e' * 64}), self.assertRaisesRegex(
                control.ControlError, 'consumed-legacy'):
            control.reserve_request(api, REPO, {'head': {'sha': HEAD}}, 'f' * 40, 20, 1)

    def test_own_prior_attempt_must_prove_both_boundaries_before_normal_or_recovery(self):
        native = {'id': 20, 'head_sha': HEAD, 'run_attempt': 2, 'status': 'in_progress', 'workflow_id': 77,
                  'workflow_url': f'https://api.github.com/repos/{REPO}/actions/required_workflows/77',
                  'path': control.WORKFLOW, 'pull_requests': [
                      {'number': 7, 'base': {'sha': OLD_BASE}, 'head': {'sha': HEAD}}]}
        pull = {'number': 7, 'base': {'sha': OLD_BASE}, 'head': {'sha': HEAD}}
        final = {'id': 101, 'run_id': 20, 'run_attempt': 1, 'head_sha': HEAD, 'status': 'completed',
                 'name': 'Current revision review'}
        partial = final | {'id': 102, 'name': 'Protected current revision', 'steps': [
            {'name': 'Reserve protected Codex request', 'status': 'completed', 'conclusion': 'skipped'}]}
        for recovery in ('', 'e' * 64):
            for jobs in ([final], [partial, final]):
                api = self.api(runs=[native], jobs=jobs)
                api.call.return_value = native
                with (self.subTest(recovery=bool(recovery), jobs=jobs),
                      patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': recovery}),
                      patch.object(control, 'supplementary_consumed_candidate'),
                      patch.object(control, 'supplementary_qualification_genesis'),
                      patch.object(control, 'supplementary_live_funding_bases'),
                      patch('workflow_recovery.authorize') as authorize,
                      self.assertRaises(control.ControlError)):
                    control.reserve_request(api, REPO, pull, 'f' * 40, 20, 2)
                authorize.assert_not_called()
        complete = partial | {'steps': [
            {'name': name, 'status': 'completed', 'conclusion': 'skipped'} for name in control.FUNDING_STEPS]}
        api = self.api(runs=[native], jobs=[complete, final])
        api.call.return_value = native
        with (patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': ''}),
              patch.object(control, 'supplementary_consumed_candidate'),
              patch.object(control, 'supplementary_qualification_genesis'),
              patch.object(control, 'supplementary_live_funding_bases')):
            self.assertEqual(20, control.reserve_request(api, REPO, pull, 'f' * 40, 20, 2))


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
