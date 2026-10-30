"""Native proof of a Supplementary read-only abort before a funding sink.

This is not a reservation, review result, retry permit or historical refund.
Only the exact defining Source can attest its own guarded no-effect path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import workflow_control as control

UPLOAD = "Preserve Supplementary pre-funding deferral"
STOP = "Leave deferred invocation unsuccessful without review acceptance"
REPO = "ltn-it/ansible-collection-supplementary"
MODEL_STEPS = {"Protected exact-revision Codex review", "Collect and verify the protected model receipt",
               "Export protected native Codex evidence", "Persist protected Codex receipt",
               "Verify applicable native review or governed exemption"}


def subject_binding(binding):
    control.require(type(binding) is dict and type(binding.get('number')) is int
                    and 0 < binding['number'] < 2**63, 'supplementary-no-effect-binding-number')
    return {'number': binding['number'], 'base': control.sha(binding.get('base')),
            'head': control.sha(binding.get('head'))}


def generation_projection(generation, binding):
    """Retain one source-authenticated later witness, never a history/budget grant.

    supplementary_defer_generation has already authenticated the COMPLETE native
    inventory and re-read every full follower record. This projection cannot
    omit a malformed unselected follower; it checks all rows before choosing the
    deterministic maximum ID. The complete funding ledger remains separate.
    """
    require = control.require
    require(type(generation) is dict and set(generation) == {"current", "later"},
            "supplementary-no-effect-generation")
    current = generation['current']
    require(type(current) is dict and current.get('status') == 'in_progress',
            'supplementary-no-effect-current-origin')
    binding = subject_binding(binding)
    head = binding['head']

    def project(row):
        require(type(row) is dict and type(row.get('path')) is str
                and control.native_required(row, REPO) and row.get('head_sha') == head,
                'supplementary-no-effect-projection-origin')
        require(all(type(row.get(key)) is int and 0 < row[key] < 2**63
                    for key in ('id', 'workflow_id'))
                and type(row.get('run_attempt')) is int and 1 <= row['run_attempt'] <= 32
                and row.get('status') in {'queued', 'pending', 'waiting', 'requested', 'in_progress', 'completed'}
                and type(row.get('path')) is str and 0 < len(row['path']) <= 512,
                'supplementary-no-effect-projection-fields')
        return {key: row[key] for key in ('id', 'run_attempt', 'head_sha', 'status',
                                         'workflow_id', 'workflow_url', 'path')}

    projected = project(current)
    associations = current.get('pull_requests')
    require(type(associations) is list, 'supplementary-no-effect-current-association')
    matches = [pr for pr in associations if type(pr) is dict and pr.get('number') == binding['number']
               and pr.get('base', {}).get('sha') == binding['base']
               and pr.get('head', {}).get('sha') == head]
    require(len(matches) == 1 and type(matches[0].get('number')) is int,
            'supplementary-no-effect-current-association')
    projected['pull_requests'] = [{'number': binding['number'], 'base': {'sha': binding['base']},
                                   'head': {'sha': head}}]
    later = control.supplementary_inventory(generation['later'], head)
    require(later, 'supplementary-no-effect-newer-native-generation')
    witness = None
    for row in later:
        compact = project(row)
        require(compact['id'] > projected['id'], 'supplementary-no-effect-newer-native-generation')
        if witness is None or compact['id'] > witness['id']:
            witness = compact
    return {'current': projected, 'later': [witness]}


def emit(repo, pull, source, operation, native, step, deferred):
    require = control.require
    job = json.loads(os.environ["NATIVE_JOB"])
    require(repo == REPO and control.source_identity(job) == source
            and step in control.FUNDING_STEPS and native == deferred.generation["current"],
            "supplementary-no-effect-emitter-origin")
    subject = subject_binding(control.binding(pull))
    generation = generation_projection(deferred.generation, subject)
    value = {"version": 2, "repository": repo, "repository_id": 1103407173, "source_sha": source,
             "run": native["id"], "attempt": native["run_attempt"], "job": job["check_run_id"],
             "subject": subject, "operation_sha256": control.digest(operation),
             "step": step, "generation": generation,
             "outcome": "guarded-before-request", "provider_request": False, "reservation_created": False}
    payload = control.canonical(value)
    require(len(payload) <= control.MAX_OPERATION_BYTES, "supplementary-no-effect-size")
    with Path("control-funding-deferred.json").open("xb") as stream:
        stream.write(payload)
    control.output("deferred", "true")


def verify(api, repo, owner, attempt, job, source):
    require = control.require
    require(repo == REPO and control.native_required(owner, repo) and job.get("conclusion") == "failure"
            and job.get("status") == "completed" and job.get("run_id") == owner.get("id")
            and type(job.get("run_attempt")) is int and job["run_attempt"] == attempt
            and job.get("head_sha") == owner.get("head_sha") and type(job.get("id")) is int and job["id"] > 0,
            "supplementary-no-effect-native-origin")
    steps = job.get("steps")
    require(type(steps) is list, "supplementary-no-effect-native-steps")

    def step(name, outcome):
        selected = [row for row in steps if row.get("name") == name]
        return len(selected) == 1 and selected[0].get("status") == "completed" \
            and selected[0].get("conclusion") == outcome

    require(step(UPLOAD, "success") and step(STOP, "failure")
            and all(step(name, "skipped") for name in MODEL_STEPS),
            "supplementary-no-effect-native-boundaries")
    value = control.artifact_record(api, repo, owner, f"control-funding-deferred-{attempt}",
                                    "control-funding-deferred.json")
    operation = control.artifact_record(api, repo, owner, f"control-operation-{attempt}", "control-operation.json")
    require(type(value) is dict and type(operation) is dict, "supplementary-no-effect-record-shape")
    reached = value.get("step")
    version = value.get('version')
    require(type(version) is int and version in {1, 2}, 'supplementary-no-effect-version')
    subject = subject_binding(operation.get('binding'))
    subject_key = 'binding' if version == 1 else 'subject'
    bound = (value.get('binding') == operation.get('binding') if version == 1 else
             type(value.get('subject')) is dict and set(value['subject']) == {'number', 'base', 'head'}
             and type(value['subject'].get('number')) is int and value['subject'] == subject)
    # v1 read compatibility never turns an invalid/oversized old receipt into
    # authority. New v2 emission binds the full untruncated operation by digest,
    # retaining only constant-size subject coordinates in the abort receipt.
    require(set(value) == {"version", "repository", "repository_id", "source_sha", "run", "attempt", "job",
                           subject_key, "operation_sha256", "step", "generation", "outcome", "provider_request",
                           "reservation_created"}
            and bound
            and value.get("repository") == repo and type(value.get("repository_id")) is int
            and value["repository_id"] == 1103407173 and value.get("source_sha") == source
            and type(operation.get("version")) is int and operation["version"] == 1 and operation.get("source_sha") == source
            and value.get("run") == owner["id"] and type(value.get("run")) is int
            and value.get("attempt") == attempt and type(value.get("attempt")) is int
            and value.get("job") == job["id"] and type(value.get("job")) is int
            and subject["head"] == owner["head_sha"]
            and value.get("operation_sha256") == control.digest(operation)
            and value.get("outcome") == "guarded-before-request"
            and value.get("provider_request") is False and value.get("reservation_created") is False
            and reached in control.FUNDING_STEPS and step(reached, "success")
            and all(step(name, "skipped") for name in control.FUNDING_STEPS - {reached}),
            "supplementary-no-effect-record-binding")
    generation = value.get("generation")
    require(type(generation) is dict and set(generation) == {"current", "later"},
            "supplementary-no-effect-generation")
    current = generation["current"]
    require(type(current) is dict and control.native_required(current, repo)
            and current.get("id") == owner["id"] and current.get("run_attempt") == attempt
            and current.get("head_sha") == owner["head_sha"] and current.get("status") == "in_progress"
            and current.get("workflow_id") == owner.get("workflow_id") and current.get("path") == owner.get("path")
            and any(pr.get("number") == subject["number"]
                    and pr.get("base", {}).get("sha") == subject["base"]
                    and pr.get("head", {}).get("sha") == subject["head"]
                    for pr in current.get("pull_requests", [])),
            "supplementary-no-effect-original-generation")
    later = control.supplementary_inventory(generation["later"], owner["head_sha"])
    require(later and all(control.native_required(row, repo) and row["id"] > owner["id"] for row in later),
            "supplementary-no-effect-newer-native-generation")
    log = api.native_job_log(repo, job["id"])
    require(f'"workflow_sha": "{source}"' in log
            and f'"workflow_repository": "{control.SOURCE}"' in log
            and f'"workflow_file_path": "{control.WORKFLOW}"' in log
            and f'"check_run_id": {job["id"]}' in log,
            "supplementary-no-effect-actual-defining-source")
    return value
