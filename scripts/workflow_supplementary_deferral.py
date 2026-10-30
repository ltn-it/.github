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


def emit(repo, pull, source, operation, native, step, deferred):
    require = control.require
    job = json.loads(os.environ["NATIVE_JOB"])
    require(repo == REPO and control.source_identity(job) == source
            and step in control.FUNDING_STEPS and native == deferred.generation["current"],
            "supplementary-no-effect-emitter-origin")
    value = {"version": 1, "repository": repo, "repository_id": 1103407173, "source_sha": source,
             "run": native["id"], "attempt": native["run_attempt"], "job": job["check_run_id"],
             "binding": control.binding(pull), "operation_sha256": control.digest(operation),
             "step": step, "generation": deferred.generation,
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
    require(set(value) == {"version", "repository", "repository_id", "source_sha", "run", "attempt", "job",
                           "binding", "operation_sha256", "step", "generation", "outcome", "provider_request",
                           "reservation_created"}
            and type(value.get("version")) is int and value["version"] == 1
            and value.get("repository") == repo and type(value.get("repository_id")) is int
            and value["repository_id"] == 1103407173 and value.get("source_sha") == source
            and operation.get("version") == 1 and operation.get("source_sha") == source
            and value.get("run") == owner["id"] and type(value.get("run")) is int
            and value.get("attempt") == attempt and type(value.get("attempt")) is int
            and value.get("job") == job["id"] and type(value.get("job")) is int
            and type(value.get("binding")) is dict
            and value.get("binding") == operation.get("binding")
            and value["binding"].get("head") == owner["head_sha"]
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
            and any(pr.get("number") == value["binding"].get("number")
                    and pr.get("base", {}).get("sha") == value["binding"].get("base")
                    and pr.get("head", {}).get("sha") == value["binding"].get("head")
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
