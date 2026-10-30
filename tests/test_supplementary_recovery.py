"""Preserve the genuine one-extra-attempt contract inside Sup's full ledger."""
import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import workflow_control as control
import workflow_recovery as recovery
import test_workflow_recovery as recovery_fixtures

REPO = 'ltn-it/ansible-collection-supplementary'
ORIGINAL_REPO, SOURCE = recovery_fixtures.REPO, recovery_fixtures.SOURCE


class SupplementaryRecoveryTests(unittest.TestCase):
    def setUp(self):
        fixture = recovery_fixtures.RecoveryTests('test_one_failed_reservation_is_a_plan_not_authority')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        for name in ('pull', 'failed', 'native', 'job', 'record', 'value', 'comment', 'outcome'):
            setattr(self, name, getattr(fixture, name))
        self.api = fixture.api
        for ref in ('base', 'head'):
            self.pull[ref]['repo']['full_name'] = REPO
        for run in (self.failed, self.native):
            run['workflow_url'] = run['workflow_url'].replace(ORIGINAL_REPO, REPO)
        self.record['binding'] = control.binding(self.pull)
        self.value['repository'] = REPO
        self.comment['body'] = recovery.MARKER + json.dumps(self.value) + ' -->'
        self.outcome['binding']['repository'] = REPO
        self.job.update(run_attempt=1, head_sha=self.pull['head']['sha'])
        self.job['steps'].append({'name': 'Request current Copilot review', 'status': 'completed', 'conclusion': 'skipped'})
        pages = self.api.pages.side_effect
        self.extra = []
        def native_pages(path, key=None):
            if key == 'check_runs' or '/workflows/332570404/' in path: return []
            if '/runs?head_sha=' in path: return fixture.runs + self.extra
            if path.endswith('/runs/10/attempts/1/jobs'):
                return [self.job, self.job | {'id': 31, 'name': 'Current revision review', 'steps': []}]
            if path.endswith('/runs/15/attempts/1/jobs'):
                return [self.job | {'id': 35, 'run_id': 15},
                        self.job | {'id': 36, 'run_id': 15, 'name': 'Current revision review', 'steps': []}]
            return pages(path, key)
        self.api.pages.side_effect = native_pages
        self.approved = {'state': 'approved', 'user': {'id': 76040632, 'type': 'User'},
                         'environments': [{'id': 50, 'name': 'normal-release-promotion-approval'}]}
        def native_call(path):
            if path.endswith('/approvals'): return [self.approved] if self.approved else []
            if path.endswith('/pulls/9'): return self.pull
            if path.endswith('/runs/20'): return self.native
            if path.endswith('/runs/10'): return self.failed
            raise AssertionError(path)
        self.api.call.side_effect = native_call

    def plan(self):
        return recovery.plan(self.api, REPO, self.pull, SOURCE, self.native)

    def reserve(self, digest):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temp:
            try:
                os.chdir(temp)
                with (patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': digest}),
                      patch.object(control, 'supplementary_qualification_genesis'),
                      patch.object(control, 'supplementary_live_funding_bases')):
                    result = control.reserve_request(self.api, REPO, self.pull, SOURCE, 20, 1)
                return result, json.loads(Path('control-recovery.json').read_bytes())
            finally:
                os.chdir(previous)

    def test_real_plan_and_native_authorize_preserve_exactly_one_extra_attempt(self):
        plan = self.plan()
        result, receipt = self.reserve(control.digest(plan))
        self.assertEqual(20, result)
        self.assertEqual(10, receipt['request']['failed_run'])
        self.assertEqual(1, receipt['request']['failed_attempt'])
        self.assertEqual(30, receipt['failed_job'])
        self.assertEqual(1, receipt['additional_attempts'])
        self.assertEqual('unknown', receipt['original_provider_outcome'])
        self.assertEqual(76040632, receipt['approval']['user']['id'])
        self.assertFalse(receipt['release_authorized'])
        self.assertEqual('failure', self.failed['conclusion'])

    def test_owner_locator_without_genuine_native_approval_never_reserves(self):
        digest = control.digest(self.plan())
        self.approved = None
        with self.assertRaises(control.ControlError):
            self.reserve(digest)

    def test_unrelated_consumed_candidate_slot_blocks_even_if_normal_recovery_history_ignores_it(self):
        digest = control.digest(self.plan())
        self.extra.append(self.failed | {'id': 15, 'pull_requests': [{'number': 99}]})
        self.assertEqual(digest, control.digest(self.plan()))
        with self.assertRaisesRegex(control.ControlError, 'consumed-native'):
            self.reserve(digest)

    def test_second_reserved_slot_missing_service_outcome_or_changed_plan_blocks(self):
        digest = control.digest(self.plan())
        self.extra.append(self.failed | {'id': 15})
        with self.assertRaisesRegex(control.ControlError, 'one-previous-reservation'):
            self.reserve(digest)
        self.extra.clear()
        self.outcome['result_produced'] = True
        with self.assertRaisesRegex(control.ControlError, 'service-failure-without-result'):
            self.reserve(digest)
        self.outcome['result_produced'] = False
        self.comment['updated_at'] = '2026-10-16T10:05:00Z'
        with self.assertRaisesRegex(control.ControlError, 'plan-drift'):
            self.reserve(digest)

    def test_unknown_or_legacy_head_claim_cannot_use_common_recovery_authority(self):
        digest = control.digest(self.plan())
        pages = self.api.pages.side_effect
        self.api.pages.side_effect = lambda path, key=None: [
            {'id': 50, 'head_sha': self.pull['head']['sha'], 'name': 'Protected Exact-Revision Codex result',
             'app': {'id': 15368, 'slug': 'github-actions'}, 'external_id': 'unknown'}
        ] if key == 'check_runs' else pages(path, key)
        with self.assertRaisesRegex(control.ControlError, 'legacy-claim-unknown'):
            self.reserve(digest)

    def test_late_recovery_follower_also_aborts_before_additional_allocation(self):
        digest = control.digest(self.plan())
        pending = self.native | {'id': 21, 'status': 'pending'}
        self.extra.append(pending)
        native_call = self.api.call.side_effect
        self.api.call.side_effect = lambda path: pending if path.endswith('/runs/21') else native_call(path)
        context = {'check_run_id': 80, 'workflow_sha': SOURCE,
                   'workflow_repository': control.SOURCE, 'workflow_file_path': control.WORKFLOW}
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temp:
            try:
                os.chdir(temp)
                with patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': digest,
                                             'NATIVE_JOB': json.dumps(context), 'GITHUB_OUTPUT': str(Path(temp) / 'output')}):
                    self.assertFalse(control.reserve_or_defer(self.api, REPO, self.pull, SOURCE,
                                                             self.native, self.record, 'Reserve protected Codex request'))
                self.assertFalse(Path('control-recovery.json').exists())
                evidence = json.loads(Path('control-funding-deferred.json').read_bytes())
                self.assertFalse(evidence['provider_request'])
                self.assertFalse(evidence['reservation_created'])
            finally:
                os.chdir(previous)

    def test_recovery_follower_after_candidate_audit_aborts_at_last_receipt_fence(self):
        digest = control.digest(self.plan())
        pending = self.native | {'id': 21, 'status': 'pending'}
        native_call = self.api.call.side_effect
        self.api.call.side_effect = lambda path: pending if path.endswith('/runs/21') else native_call(path)
        context = {'check_run_id': 80, 'workflow_sha': SOURCE,
                   'workflow_repository': control.SOURCE, 'workflow_file_path': control.WORKFLOW}
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temp:
            try:
                os.chdir(temp)
                with (patch.dict(os.environ, {'REVIEW_RECOVERY_PLAN_SHA256': digest,
                                              'NATIVE_JOB': json.dumps(context), 'GITHUB_OUTPUT': str(Path(temp) / 'output')}),
                      patch.object(control, 'supplementary_qualification_genesis', side_effect=lambda *_: self.extra.append(pending)),
                      patch.object(control, 'supplementary_live_funding_bases')):
                    self.assertFalse(control.reserve_or_defer(self.api, REPO, self.pull, SOURCE,
                                                             self.native, self.record, 'Reserve protected Codex request'))
                self.assertFalse(Path('control-recovery.json').exists())
                evidence = json.loads(Path('control-funding-deferred.json').read_bytes())
                self.assertFalse(evidence['provider_request'])
            finally:
                os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
