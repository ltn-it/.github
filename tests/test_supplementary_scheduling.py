"""Real pre-funding entry points for three retained native invocations."""
import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import test_supplementary_funding_deferral as funding_fixture
REPO, SOURCE = funding_fixture.REPO, funding_fixture.SOURCE
import workflow_control as control

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('queue_policy', ROOT / 'scripts/validate-actionlint-queue-policy.py')
QUEUE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUEUE)


class SupplementarySchedulingTests(unittest.TestCase):
    def test_actual_workflow_matches_typed_queue_policy_and_other_repos_keep_single(self):
        QUEUE.validate(ROOT)
        actual = yaml.safe_load((ROOT / control.WORKFLOW).read_text())['concurrency']
        self.assertEqual(QUEUE.SOURCE_SUP_QUEUE, {key: str(value) for key, value in actual.items()})
        for identifier in ('1103407173', '1269461997', '1103405635'):
            queue = actual['queue'].removeprefix('${{').removesuffix('}}').replace('&&', ' and ').replace('||', ' or ')
            queue = queue.replace('github.repository_id', repr(identifier))
            cancel = actual['cancel-in-progress'].removeprefix('${{').removesuffix('}}').replace('github.repository_id', repr(identifier))
            self.assertEqual('max' if identifier == '1103407173' else 'single', eval(queue, {'__builtins__': {}}))
            self.assertEqual(identifier != '1103407173', eval(cancel, {'__builtins__': {}}))
        profile = (ROOT / 'scripts/lit-ci-profile.sh').read_text()
        self.assertLess(profile.index('python3 scripts/validate-actionlint-queue-policy.py'), profile.index('actionlint_args=(-ignore'))

    def exercise_three(self, *, missing_middle=False):
        fixture = funding_fixture.SupplementaryFundingDeferralTests()
        api, pull, native, _, operation, context, _, job = fixture.fixture()
        rows = {identifier: native | {'id': identifier, 'status': 'pending'} for identifier in (20, 21, 22)}
        proofs, operations, jobs, logs = {}, {}, {}, {}

        def read(path):
            return rows[int(path.rsplit('/', 1)[-1])]

        def pages(path, key):
            if key == 'check_runs' or '/workflows/332570404/' in path:
                return []
            if key == 'jobs':
                identifier = int(path.split('/runs/')[1].split('/')[0])
                return [] if missing_middle and identifier == 21 else jobs[identifier]
            self.assertEqual('workflow_runs', key)
            return list(rows.values())

        def artifact(_api, repo, owner, name, filename):
            self.assertEqual(REPO, repo)
            identifier = owner['id']
            return copy.deepcopy(proofs[identifier] if filename == 'control-funding-deferred.json' else operations[identifier])

        api.call.side_effect = read
        api.pages.side_effect = pages
        api.native_job_log.side_effect = lambda repo, identifier: logs[identifier]
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            try:
                for identifier in (20, 21, 22):
                    directory = Path(temporary) / str(identifier)
                    directory.mkdir()
                    os.chdir(directory)
                    rows[identifier] = rows[identifier] | {'status': 'in_progress'}
                    current = rows[identifier]
                    current_context = context | {'check_run_id': 501 + identifier - 20}
                    operations[identifier] = copy.deepcopy(operation)
                    with (patch.dict(os.environ, {'NATIVE_JOB': json.dumps(current_context),
                                                  'GITHUB_OUTPUT': str(directory / 'output')}),
                          patch.object(control, 'supplementary_qualification_genesis'),
                          patch.object(control, 'supplementary_live_funding_bases'),
                          patch.object(control, 'artifact_record', side_effect=artifact)):
                        result = control.reserve_or_defer(api, REPO, pull, SOURCE, current, operation,
                                                          'Reserve protected Codex request')
                    if identifier == 22:
                        self.assertTrue(result)
                        self.assertFalse(Path('control-funding-deferred.json').exists())
                        continue
                    self.assertFalse(result)
                    proofs[identifier] = json.loads(Path('control-funding-deferred.json').read_bytes())
                    rows[identifier] = current | {'status': 'completed', 'conclusion': 'failure'}
                    protected = job | {'id': current_context['check_run_id'], 'run_id': identifier}
                    jobs[identifier] = [protected, protected | {'id': identifier + 1000,
                                        'name': 'Current revision review', 'steps': []}]
                    logs[protected['id']] = json.dumps(current_context, indent=2)
            finally:
                os.chdir(previous)
        api.call.assert_called()
        self.assertTrue(all(not call.kwargs for call in api.call.call_args_list))
        self.assertEqual({20, 21}, set(proofs))
        self.assertTrue(all(value['provider_request'] is False and value['reservation_created'] is False
                            for value in proofs.values()))

    def test_a_and_b_defer_with_proof_and_c_checks_complete_history_before_its_only_slot(self):
        self.exercise_three()

    def test_jobless_cancellation_stays_unknown_including_manual_or_queue_overflow(self):
        # GitHub max retains <=100 pending entries. A manually canceled or
        # overflowed jobless run is NOT reclassified as free by this change.
        with self.assertRaisesRegex(control.ControlError, 'original-or-verifier-history'):
            self.exercise_three(missing_middle=True)


if __name__ == '__main__':
    unittest.main()
