"""One historical Root ancestry baseline; never a failed-review fallback.

This reader authenticates already accepted Main bytes. It does not relabel the
failed PR 986 run, fund a model, admit this source, or mutate GitHub. Source 015
does not consume it: a separately qualified Root migration is still necessary.
"""
from __future__ import annotations

import re
from datetime import timedelta

ROOT = 'ltn-it/.github'
IDENTIFIER = 1112629689
SOURCE = '015233f4dfe0f95a6df0ea8a9e4ef8150dadc19f'
MAIN = 'c353913fc261e193b60876219820e9714b0122b9'
PREVIOUS_MAIN = '97fb1c61a1753eac3fc126e2ba7cac33ec463f3e'
DEVELOP = '000ed477a7af21e0accec549531966f095523bc2'
MERGE = '1d19405fefd66e5f1b007bddcd1920e3a1287866'
TREE = '0e3abaf9c461bdbe01bd3be383058038d0f711b1'
MAIN_RUN = 40885286707
FAILED_RUN = 40895680515
MAIN_PROOF = 12903126597
MAIN_PROOF_DIGEST = 'aa123ea71359ab434c0401f43a38a1c719fc813ebfb22021c9eb1d9d5992cbf8'


def control_for_ingress(api, repo, promotion, ingress, config):
    from workflow_control import check_native_control
    result = baseline(api, repo, promotion, ingress, config)
    return result if result is not None else check_native_control(api, repo, ingress, config)


def baseline(api, repo, promotion, ingress, config):
    """Return one typed ancestry disposition, only for this exact old merge.

    All other ingress must use the ordinary native review reader. A changed
    historical generation or a missing original artifact still blocks.
    """
    if repo != ROOT or ingress.get('number') != 986:
        return None
    from workflow_control import (
        RELEASE, artifact_record, digest, historical_binding_matches, identity,
        native_approval, native_jobs, native_required, operation_record, require,
    )
    from workflow_ingress import instant

    require(promotion.get('base', {}).get('sha') == MAIN
            and type(config.get('accepted_sources')) is list
            and SOURCE in config['accepted_sources'], 'root-ancestry-fixed-baseline-required')
    repository = api.call(f'repos/{ROOT}')
    require(repository.get('id') == IDENTIFIER and repository.get('full_name') == ROOT
            and repository.get('visibility') == 'public' and not repository.get('archived')
            and not repository.get('disabled'), 'root-ancestry-repository-identity')

    def refs():
        result = {}
        for branch in ('main', 'develop'):
            native = api.call(f'repos/{ROOT}/branches/{branch}')
            reference = api.call(f'repos/{ROOT}/git/ref/heads/{branch}')
            require(native.get('protected') is True and reference.get('ref') == f'refs/heads/{branch}'
                    and reference.get('object', {}).get('type') == 'commit'
                    and reference['object'].get('sha') == native.get('commit', {}).get('sha'),
                    'root-ancestry-protected-ref-required')
            result[branch] = reference['object']['sha']
        return result

    observed_refs = refs()
    require(observed_refs == {'main': MAIN, 'develop': promotion.get('head', {}).get('sha')},
            'root-ancestry-current-promotion-drift')
    accepted = api.call(f'repos/{ROOT}/pulls/985')
    historical = api.call(f'repos/{ROOT}/pulls/986')
    require(historical == ingress, 'root-ancestry-historical-pr-drift')
    for pull, number, merge, parents, branches, author in (
        (accepted, 985, MAIN, [PREVIOUS_MAIN, DEVELOP], ['main', 'develop'], RELEASE),
        (historical, 986, MERGE, [DEVELOP, MAIN], ['develop', 'main'], ('litroc', 76040632, 'User')),
    ):
        require(pull.get('number') == number and pull.get('merged') is True and pull.get('state') == 'closed'
                and pull.get('draft') is False and pull.get('merge_commit_sha') == merge
                and [pull.get(side, {}).get('sha') for side in ('base', 'head')] == parents
                and [pull.get(side, {}).get('ref') for side in ('base', 'head')] == branches
                and all(pull.get(side, {}).get('repo', {}).get('id') == IDENTIFIER
                        and pull[side]['repo'].get('full_name') == ROOT for side in ('base', 'head'))
                and identity(pull.get('user', {})) == author, 'root-ancestry-exact-pr-lineage')
        commit = api.call(f'repos/{ROOT}/git/commits/{merge}')
        require(commit.get('sha') == merge and commit.get('tree', {}).get('sha') == TREE
                and [row.get('sha') for row in commit.get('parents', [])] == parents,
                'root-ancestry-identical-main-tree-required')
    require(instant(accepted['merged_at']) < instant(historical['created_at']) < instant(historical['merged_at']),
            'root-ancestry-main-must-be-accepted-first')

    original = api.call(f'repos/{ROOT}/actions/runs/{MAIN_RUN}')
    failed = api.call(f'repos/{ROOT}/actions/runs/{FAILED_RUN}')
    for run, identifier, head, conclusion in (
        (original, MAIN_RUN, DEVELOP, 'success'), (failed, FAILED_RUN, MAIN, 'failure')
    ):
        require(type(run.get('id')) is int and run.get('id') == identifier
                and type(run.get('run_attempt')) is int and run.get('run_attempt') == 1
                and run.get('repository', {}).get('id') == IDENTIFIER and native_required(run, ROOT)
                and run.get('workflow_id') == 385148697 and run.get('head_sha') == head
                and run.get('event') == 'pull_request' and run.get('status') == 'completed'
                and run.get('conclusion') == conclusion, 'root-ancestry-original-native-generation-required')
    require(instant(original['updated_at']) < instant(accepted['merged_at']),
            'root-ancestry-main-review-before-merge-required')
    jobs = native_jobs(api, ROOT, original)
    expected = {'Source common quality': 123487224718, 'Protected current revision': 123487730389,
                'Approve exact main promotion': 123487921318, 'Current revision review': 123493489393}
    require(len(jobs) == 4 and {row.get('name'): row.get('id') for row in jobs} == expected
            and all(row.get('status') == 'completed' and row.get('conclusion') == 'success'
                    and row.get('head_sha') == DEVELOP and type(row.get('run_attempt')) is int
                    and row.get('run_attempt') == 1
                    and instant(row['completed_at']) < instant(accepted['merged_at']) for row in jobs),
            'root-ancestry-original-main-checks-required')
    artifacts = api.pages(f'repos/{ROOT}/actions/runs/{MAIN_RUN}/artifacts', 'artifacts')
    proofs = [row for row in artifacts if row.get('name') == 'control-proof-1']
    require(len(proofs) == 1 and proofs[0].get('id') == MAIN_PROOF and proofs[0].get('expired') is False,
            'root-ancestry-original-main-proof-required')
    proof = artifact_record(api, ROOT, original, 'control-proof-1', 'control-proof.json')
    require(digest(proof) == MAIN_PROOF_DIGEST and proof.get('version') == 1
            and proof.get('source_sha') == SOURCE and proof.get('route') == 'promotion'
            and historical_binding_matches(api, ROOT, accepted, proof.get('binding'))
            and proof.get('evidence', {}).get('integration_tree') == TREE,
            'root-ancestry-original-main-proof-binding')
    approval = native_approval(api, ROOT, MAIN_RUN)
    recorded = proof.get('authorization', {})
    require(recorded.get('run') == MAIN_RUN
            and identity(approval.get('user', {})) == identity(recorded.get('approval', {}).get('user', {}))
            == ('litroc', 76040632, 'User')
            and any(row.get('id') == 24378530648 and row.get('name') == 'normal-release-promotion-approval'
                    and row.get('can_admins_bypass') is False for row in approval.get('environments', [])),
            'root-ancestry-genuine-original-main-approval-required')
    failed_artifacts = api.pages(f'repos/{ROOT}/actions/runs/{FAILED_RUN}/artifacts', 'artifacts')
    require(len(failed_artifacts) == 1 and failed_artifacts[0].get('id') == 12906667243
            and failed_artifacts[0].get('name') == 'control-operation-1'
            and failed_artifacts[0].get('expired') is False, 'root-ancestry-failed-history-changed')
    operation = operation_record(api, ROOT, failed, SOURCE)
    require(historical_binding_matches(api, ROOT, historical, operation.get('binding')),
            'root-ancestry-original-failed-operation-binding')
    failed_jobs = native_jobs(api, ROOT, failed)
    expected_failed = {
        'Source common quality': (123523997408, 'success'),
        'Protected current revision': (123524593901, 'failure'),
        'Current revision review': (123529611190, 'failure'),
        'Approve exact main promotion': (123529612270, 'skipped'),
    }
    require(len(failed_jobs) == 4 and {
        row.get('name'): (row.get('id'), row.get('conclusion')) for row in failed_jobs
    } == expected_failed, 'root-ancestry-exact-failed-topology-required')
    for job in failed_jobs:
        require(job.get('head_sha') == MAIN and type(job.get('run_attempt')) is int and job.get('run_attempt') == 1
                and job.get('status') == 'completed', 'root-ancestry-failed-job-generation')
        if job['conclusion'] != 'failure':
            continue
        steps = [row for row in job.get('steps', []) if row.get('conclusion') == 'failure']
        expected_step = ('Verify applicable native review or governed exemption'
                         if job['name'] == 'Protected current revision' else
                         'Enforce native review and quality on the still-current tuple')
        require(len(steps) == 1 and steps[0].get('name') == expected_step,
                'root-ancestry-only-closed-subject-failure-required')
        log = api.native_job_log(ROOT, job['id'])
        require(f'"workflow_sha": "{SOURCE}"' in log and f'"workflow_repository": "{ROOT}"' in log
                and f'"check_run_id": {job["id"]}' in log
                and '"workflow_file_path": ".github/workflows/change-control-required.yml"' in log,
                'root-ancestry-native-failed-source-required')
        errors = [line for line in log.splitlines() if 'Protected control blocked:' in line]
        match = re.fullmatch(r'(\S+Z) Protected control blocked: ControlError: pull-not-reviewable',
                             errors[0]) if len(errors) == 1 else None
        require(match is not None and instant(match[1]) > instant(historical['merged_at']) + timedelta(seconds=1),
                'root-ancestry-only-post-merge-closure-required')
    require(api.call(f'repos/{ROOT}/actions/runs/{MAIN_RUN}') == original
            and api.call(f'repos/{ROOT}/actions/runs/{FAILED_RUN}') == failed
            and api.call(f'repos/{ROOT}/pulls/985') == accepted
            and api.call(f'repos/{ROOT}/pulls/986') == historical
            and api.pages(f'repos/{ROOT}/actions/runs/{MAIN_RUN}/artifacts', 'artifacts') == artifacts
            and api.pages(f'repos/{ROOT}/actions/runs/{FAILED_RUN}/artifacts', 'artifacts') == failed_artifacts
            and native_approval(api, ROOT, MAIN_RUN) == approval, 'root-ancestry-native-generation-drift')
    # The mutable protected tips are the final I/O, after all historical reads.
    require(refs() == observed_refs, 'root-ancestry-current-promotion-drift')
    return {'kind': 'protected-main-ancestry-baseline/v1', 'route': 'ancestry', 'source_sha': SOURCE,
            'merge': MERGE, 'tree': TREE,
            'accepted_main': {'pull': 985, 'merge': MAIN, 'run': MAIN_RUN, 'attempt': 1,
                              'proof_artifact': MAIN_PROOF, 'proof_sha256': MAIN_PROOF_DIGEST},
            'historical_failure': {'pull': 986, 'run': FAILED_RUN, 'attempt': 1, 'conclusion': 'failure',
                                   'budget_disposition': 'unchanged'},
            'model_funding_granted': False, 'source_admission_granted': False}
